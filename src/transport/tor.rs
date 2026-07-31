//! The Tor control plane: publish murmure's onion service, and dial another one.
//!
//! This module opens streams and hands them over; what travels on them is
//! `proto`'s business and the loop above them is `chat`'s. There is no
//! `Transport` trait yet (see `transport/mod.rs`) and no reconnection policy:
//! a dropped conversation ends the program, and the operator dials again.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use arti_client::config::Reconfigure;
use arti_client::{KeystoreSelector, TorClient};
use futures::{Stream, StreamExt as _};
use safelog::DisplayRedacted as _;
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::{HsClientDescEncKey, HsClientDescEncSecretKey, HsId, HsIdKeypair};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::config::restricted_discovery::HsClientNickname;
use tor_hsservice::{
    HsNickname, OnionServiceConfig, RendRequest, RunningOnionService, handle_rend_requests,
};
use tor_rtcompat::PreferredRuntime;

/// The virtual port murmure listens on inside its onion service.
pub const SERVICE_PORT: u16 = 7777;

/// A bootstrapped Tor client, plus the directories it owns.
pub type Client = Arc<TorClient<PreferredRuntime>>;

/// The stream of incoming rendezvous requests for a launched onion service.
pub type RendRequests = std::pin::Pin<Box<dyn Stream<Item = RendRequest> + Send>>;

/// Build and bootstrap a Tor client on a dedicated pair of directories.
///
/// The two clients in this milestone must never share a state or a cache
/// directory: arti stores the keystore and the guard state under `state_dir`,
/// and two clients writing the same files corrupt each other in ways that have
/// nothing to do with what we are testing.
///
/// `progress` is called with a fraction from 0.0 to 1.0 and, when arti thinks it
/// is stuck, the reason. This is not decoration: a first bootstrap downloads the
/// whole consensus and its microdescriptors cold, which takes **minutes**, not
/// the tens of seconds a warm cache takes. Without a number on screen there is
/// no way to tell that wait from a hang — and `blocked()` is what turns "it is
/// frozen" into "your clock is two hours off".
pub async fn bootstrap_client(
    state_dir: &Path,
    cache_dir: &Path,
    mut progress: impl FnMut(f32, Option<String>),
) -> Result<Client> {
    create_private_dir(state_dir)?;
    create_private_dir(cache_dir)?;

    let config = arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .with_context(|| {
            format!(
                "building a Tor client config on {} / {}",
                state_dir.display(),
                cache_dir.display()
            )
        })?;

    // Split what `create_bootstrapped` does in one call: the event stream only
    // exists once the client does, so subscribing has to happen between
    // construction and bootstrap or the early progress is lost.
    let client = TorClient::builder()
        .config(config)
        .create_unbootstrapped_async()
        .await
        .map_err(|e| describe(e, "creating the Tor client"))?;

    // Scoped: the bootstrap future borrows `client`, and returning it moves.
    {
        let mut events = client.bootstrap_events();
        let booting = client.bootstrap();
        futures::pin_mut!(booting);
        loop {
            tokio::select! {
                outcome = &mut booting => {
                    outcome.map_err(|e| describe(e, "bootstrapping the Tor client"))?;
                    break;
                }
                // arti reports a blockage as a best-effort guess, so it reaches
                // the operator as a symptom, never as a diagnosis.
                Some(status) = events.next() => progress(
                    status.as_frac(),
                    status.blocked().map(|b| b.message().to_string()),
                ),
            }
        }
    }
    Ok(client)
}

/// Create a directory `fs-mistrust` will accept: owner-only, 0700.
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 700 {}", path.display()))?;
    }
    Ok(())
}

/// The outcome of handing our identity key to arti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyHandover {
    /// The keystore was empty for this nickname; arti accepted our keypair.
    Inserted,
    /// The keystore already held an identity for this nickname, so arti refused
    /// to overwrite it and we launched against whatever was already there.
    ///
    /// This is *not* a success on its own — the caller must still prove the
    /// published address is the one derived from our seed.
    Reused,
}

/// Launch the onion service under **our** identity key.
///
/// # Route A / route B swap point
///
/// This is the single function that decides how murmure's key reaches arti's
/// keystore. Nothing else in the codebase touches `tor-keymgr`, so swapping the
/// route is a local edit here.
///
/// **Route A (in use).** `TorClient::launch_onion_service_with_hsid`
/// (`arti-client-0.44.0/src/client.rs:1998`, gated `onion-service-service` +
/// `experimental-api`). It calls
/// `KeyMgr::insert::<HsIdKeypair>(kp, &HsIdKeypairSpecifier::new(nickname),
/// KeystoreSelector::Primary, /* overwrite = */ false)` and then delegates to
/// the ordinary `launch_onion_service`.
///
/// **Route B (fallback, no experimental feature).** Build an
/// `ArtiNativeKeystore::from_path_and_mistrust(state_dir.join("keystore"),
/// permissions)` plus a `KeyMgrBuilder`, insert under `HsIdKeypairSpecifier`,
/// then call the non-experimental `launch_onion_service`. arti-client builds
/// its own keystore at exactly `<state_dir>/keystore`
/// (`arti-client-0.44.0/src/client.rs:320-350`), so the two agree on disk.
/// Replacing the body of this function is the whole migration.
///
/// # Why a second run is not an error
///
/// `KeyMgr::insert` with `overwrite = false` returns `KeyAlreadyExists` whenever
/// the keystore already holds an `HsIdKeypair` for the nickname — including when
/// it holds *our own* key from a previous run. Refusing to overwrite is exactly
/// the behaviour murmure wants, so the failure is caught here and we launch
/// against the stored key instead. Which key that actually is gets settled by
/// the caller's byte comparison against the locally derived address, never by
/// trusting this call.
pub fn launch_with_identity(
    client: &Client,
    nickname: &HsNickname,
    keypair: HsIdKeypair,
    authorized: &[(HsClientNickname, HsClientDescEncKey)],
) -> Result<(KeyHandover, Arc<RunningOnionService>, RendRequests)> {
    let config = service_config(nickname, authorized)?;

    match client.launch_onion_service_with_hsid(config.clone(), keypair) {
        // The two arms return two distinct opaque `impl Stream` types, so they
        // are boxed into one nameable type.
        Ok(Some((svc, requests))) => Ok((KeyHandover::Inserted, svc, Box::pin(requests))),
        Ok(None) => bail!("the onion service is disabled in its own configuration"),
        Err(e) if is_key_already_exists(&e) => {
            let (svc, requests) = client
                .launch_onion_service(config)
                .map_err(|e| describe(e, "launching the onion service"))?
                .ok_or_else(|| anyhow!("the onion service is disabled in its own configuration"))?;
            Ok((KeyHandover::Reused, svc, Box::pin(requests)))
        }
        Err(e) => Err(describe(e, "handing our identity key to arti")),
    }
}

/// The onion service config for a given set of authorised clients.
///
/// # Why the empty case is not restricted
///
/// Restricted discovery encrypts the descriptor's introduction points for a
/// named list of clients, so a service with an empty list is one nobody can
/// reach — and arti refuses to build that config at all
/// (`RestrictedDiscoveryConfigBuilder::post_build_validate`: "restricted mode
/// is enabled but no client key providers are configured"). So a murmure with
/// no contacts publishes an ordinary descriptor, and goes dark on the first
/// `/add`. That transition is visible to the operator, because it changes what
/// the world can learn about them.
fn service_config(
    nickname: &HsNickname,
    authorized: &[(HsClientNickname, HsClientDescEncKey)],
) -> Result<OnionServiceConfig> {
    let mut builder = OnionServiceConfigBuilder::default();
    builder.nickname(nickname.clone());

    if !authorized.is_empty() {
        let restricted = builder.restricted_discovery();
        restricted.enabled(true);
        // `key_dirs` is the other provider arti offers, and it is the one that
        // supports live reload by watching a directory. murmure does not use
        // it: it would mean one plaintext `<nickname>.auth` file per contact,
        // next to a contacts book that is sealed precisely so that reading the
        // disk does not reveal who you talk to. Passing the keys in memory and
        // calling `reconfigure` (see [`authorize`]) gets the same live update
        // without the leak.
        let keys = restricted.static_keys().access();
        keys.extend(authorized.iter().cloned());
    }

    builder
        .build()
        .map_err(|e| anyhow!("building the onion service config: {e}"))
}

/// Replace the set of clients allowed to discover the running service.
///
/// This takes effect without a restart: the publisher's config handler re-reads
/// the authorised clients, marks every descriptor dirty and schedules an upload
/// (`tor-hsservice-0.44.0/src/publish/reactor.rs:1203`). The new descriptor
/// still has to propagate to the HSDirs, so a friend added this second may need
/// a minute before they can find us.
pub fn authorize(
    service: &Arc<RunningOnionService>,
    nickname: &HsNickname,
    authorized: &[(HsClientNickname, HsClientDescEncKey)],
) -> Result<()> {
    let config = service_config(nickname, authorized)?;
    service
        .reconfigure(config, Reconfigure::AllOrNothing)
        .map_err(|e| anyhow!("updating the authorised clients: {e}"))
}

/// Store our own discovery key in the keystore, filed under a peer's address.
///
/// arti looks the key up by the `HsId` it is about to dial
/// (`HsClientDescEncKeypairSpecifier::new(hsid)`), so reaching a restricted
/// service means having deposited a key under *that* service's address first.
/// murmure presents the same secret to everyone — see
/// [`crate::identity::Identity::discovery_secret`] for why — so this is a pure
/// bookkeeping step, and doing it twice is not an error.
pub fn present_to(client: &Client, peer: HsId, secret: HsClientDescEncSecretKey) -> Result<()> {
    match client.insert_service_discovery_key(KeystoreSelector::Primary, peer, secret) {
        Ok(_) => Ok(()),
        // Already deposited on an earlier run. Since the secret is a pure
        // function of our seed, what is stored is what we would have written.
        Err(e) if is_key_already_exists(&e) => Ok(()),
        Err(e) => Err(describe(e, "storing our discovery key for a contact")),
    }
}

/// The name arti files a contact's discovery key under.
///
/// arti wants a `Slug` — lowercase ASCII, digits, `_` and `-`. A contact's
/// local name is none of those things reliably ("Alice", "mon pote"), and it is
/// private besides. The head of their onion address is already lowercase
/// base32, so it is a valid slug by construction, unique across contacts, and
/// tells arti nothing the caller did not already hand it.
pub fn client_nickname(address: &str) -> Result<HsClientNickname> {
    /// Base32 characters taken from the address. 16 of them is 80 bits — this
    /// only has to separate a handful of contacts, not resist collision search.
    const LEN: usize = 16;

    let base32 = address.strip_suffix(".onion").unwrap_or(address);
    let head: String = base32.chars().take(LEN).collect();
    head.parse()
        .map_err(|e| anyhow!("{address} does not yield a usable client nickname: {e}"))
}

/// Recognise `tor_keymgr::Error::KeyAlreadyExists` through arti-client's opaque
/// error type.
///
/// `arti_client::ErrorDetail` is only public behind the `error_detail`
/// experimental feature, and `KeyAlreadyExists` reports the very generic
/// `ErrorKind::BadApiUsage` (`tor-keymgr-0.44.0/src/err.rs:71`), so neither
/// discriminant is enough on its own. Walking the source chain for the
/// variant's own `#[error("Key already exists")]` message is.
fn is_key_already_exists(err: &arti_client::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = source {
        if e.to_string().contains("Key already exists") {
            return true;
        }
        source = e.source();
    }
    false
}

/// Flatten an arti error into something an operator can act on, keeping the
/// `ErrorKind` — the part of arti's error surface that is stable and
/// classifiable — and the full source chain.
pub fn describe(err: arti_client::Error, doing: &str) -> anyhow::Error {
    use arti_client::HasKind as _;
    let kind = err.kind();
    let mut chain = vec![err.to_string()];
    let mut source = std::error::Error::source(&err);
    while let Some(e) = source {
        chain.push(e.to_string());
        source = e.source();
    }
    anyhow!("{doing} failed [{kind:?}]: {}", chain.join(": "))
}

/// Block until the service believes it is reachable, or until `timeout`.
///
/// # This is a hint, not a gate
///
/// `State::Running` requires *both* the IPT manager and the descriptor
/// publisher to report `Running`; `Bootstrapping` in either one masks
/// everything else (`tor-hsservice-0.44.0/src/status.rs:232`). Observed in
/// practice: the descriptor uploads successfully and the service answers dials
/// while the aggregate status is still `Bootstrapping`. So a timeout here means
/// "not confirmed", never "unreachable" — the caller should log it and dial
/// anyway. [`dial_and_echo_retrying`] is the authoritative test.
pub async fn wait_until_reachable(svc: &Arc<RunningOnionService>, timeout: Duration) -> Result<()> {
    if svc.status().state().is_fully_reachable() {
        return Ok(());
    }
    let mut events = svc.status_events();
    let wait = async {
        while let Some(status) = events.next().await {
            let state = status.state();
            tracing::info!("onion service state: {state:?}");
            if state.is_fully_reachable() {
                return Ok(());
            }
        }
        Err(anyhow!("the onion service status stream ended unexpectedly"))
    };
    tokio::time::timeout(timeout, wait)
        .await
        .map_err(|_| anyhow!("the onion service was still not reachable after {timeout:?}"))?
}

/// Every incoming stream, accepted, as they arrive.
///
/// A stream that fails to accept is logged and skipped rather than ending the
/// service: one bad rendezvous must not take the listener down.
///
/// The caller decides what to do with each one. v1 holds a single conversation
/// at a time, so a second caller waits in the queue until the first hangs up —
/// which is what a phone does, and what the brainstorm asked for.
pub fn incoming(
    requests: impl Stream<Item = RendRequest>,
) -> impl Stream<Item = arti_client::DataStream> {
    handle_rend_requests(requests).filter_map(|request| async move {
        tracing::info!("incoming stream: {:?}", request.request());
        match request.accept(Connected::new_empty()).await {
            Ok(stream) => Some(stream),
            Err(e) => {
                tracing::warn!("accepting an incoming stream failed: {e}");
                None
            }
        }
    })
}

/// Dial a `.onion` on [`SERVICE_PORT`] and hand back the open stream.
pub async fn dial(client: &Client, address: HsId) -> Result<arti_client::DataStream> {
    let host = address.display_unredacted().to_string();
    client
        .connect((host.as_str(), SERVICE_PORT))
        .await
        .map_err(|e| describe(e, &format!("dialling {host}:{SERVICE_PORT}")))
}

/// Dial until it works or `deadline` runs out.
///
/// A first dial that lands before the descriptor has propagated to the HSDirs
/// fails with `OnionServiceNotFound` / `OnionServiceDescriptorValidationFailed`
/// — a timing artefact, not a verdict. Retrying is the only honest way to tell
/// "not published yet" from "not reachable".
pub async fn dial_retrying(
    client: &Client,
    address: HsId,
    deadline: Duration,
    mut on_attempt: impl FnMut(u32, &str),
) -> Result<arti_client::DataStream> {
    /// Gap between two dials. A rendezvous is 7-50 s, so retrying faster than
    /// this just piles up circuits.
    const BACKOFF: Duration = Duration::from_secs(10);

    let start = Instant::now();
    let mut attempt = 0u32;
    let mut last: Option<anyhow::Error> = None;

    while start.elapsed() < deadline {
        attempt += 1;
        let remaining = deadline.saturating_sub(start.elapsed());
        match tokio::time::timeout(remaining, dial(client, address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                on_attempt(attempt, &format!("{e:#}"));
                last = Some(e);
            }
            Err(_) => break,
        }
        tokio::time::sleep(BACKOFF.min(deadline.saturating_sub(start.elapsed()))).await;
    }

    Err(match last {
        Some(e) => e.context(format!("giving up after {attempt} dial attempts in {deadline:?}")),
        None => anyhow!("no dial attempt completed within {deadline:?}"),
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
    const KEY: &str = "descriptor:x25519:ZPRRMIV6DV6SJFL7SFBSVLJ5VUNPGCDFEVZ7M23LTLVTCCXJQBKA";

    fn nickname() -> HsNickname {
        "murmure".to_owned().try_into().unwrap()
    }

    #[test]
    fn a_contact_address_yields_a_usable_client_nickname() {
        let nick = client_nickname(ADDR).expect("slug");
        assert_eq!(nick.to_string(), "haticvmas7sfodco");
        // With or without the suffix, and stable across calls.
        assert_eq!(
            client_nickname(ADDR.trim_end_matches(".onion"))
                .unwrap()
                .to_string(),
            nick.to_string()
        );
    }

    /// arti rejects "restricted, but nobody is authorised" at build time, so
    /// both ends of that branch have to build.
    #[test]
    fn the_service_config_builds_with_and_without_authorised_clients() {
        service_config(&nickname(), &[]).expect("an empty book is not restricted");
        let clients = vec![(client_nickname(ADDR).unwrap(), KEY.parse().unwrap())];
        service_config(&nickname(), &clients).expect("one contact is enough to restrict");
    }

    /// Does Tor work at all from this machine?
    ///
    /// Ignored by default: it needs the network and a cold cache takes minutes.
    /// Run it when a bootstrap misbehaves and you want arti on its own, with no
    /// interface in the way:
    ///
    /// ```text
    /// cargo test --release -- --ignored --nocapture reaches_the_tor_network
    /// ```
    ///
    /// It prints arti's own progress, so a slow run and a stuck one look
    /// different from the first minute.
    /// Arti's own logs go to stdout here, unlike in the binary where they go to
    /// a file so the TUI can own the screen. `RUST_LOG` selects them:
    ///
    /// ```text
    /// RUST_LOG=tor_proto=trace,tor_circmgr=debug,tor_chanmgr=debug
    /// ```
    ///
    /// Without this the test says "15%" and nothing else, which is exactly the
    /// blindness it exists to remove.
    #[tokio::test]
    #[ignore = "needs the network; minutes on a cold cache"]
    async fn reaches_the_tor_network() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();

        let dir = std::env::temp_dir().join("murmure-bootstrap-test");
        // A cold cache on purpose: that is the case that goes wrong.
        let _ = std::fs::remove_dir_all(&dir);

        let started = Instant::now();
        let mut last = String::new();
        let client = bootstrap_client(&dir.join("state"), &dir.join("cache"), |frac, blocked| {
            let line = match blocked {
                Some(why) => format!("stuck: {why}"),
                None => format!("{:.0}%", frac * 100.0),
            };
            // One line per change, not per event: arti emits many identical ones.
            if line != last {
                println!("[{:>6.1}s] {line}", started.elapsed().as_secs_f32());
                last = line;
            }
        })
        .await
        .expect("bootstrap failed");

        println!("bootstrapped in {:.1}s", started.elapsed().as_secs_f32());
        drop(client);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
