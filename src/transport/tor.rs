//! The Tor control plane: publish murmure's onion service, and dial another one.
//!
//! Everything here is scoped to the keystore milestone. There is no `Transport`
//! trait yet (see `transport/mod.rs`), no reconnection policy, and no framing —
//! only the two halves the milestone has to prove: *we publish under our own
//! key*, and *we can reach that address through Tor*.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use arti_client::TorClient;
use futures::{Stream, StreamExt as _};
use safelog::DisplayRedacted as _;
use tor_cell::relaycell::msg::Connected;
use tor_hscrypto::pk::{HsId, HsIdKeypair};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{HsNickname, RendRequest, RunningOnionService, handle_rend_requests};
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
pub async fn bootstrap_client(state_dir: &Path, cache_dir: &Path) -> Result<Client> {
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
    let client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| describe(e, "bootstrapping the Tor client"))?;
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
) -> Result<(KeyHandover, Arc<RunningOnionService>, RendRequests)> {
    let config = OnionServiceConfigBuilder::default()
        .nickname(nickname.clone())
        .build()
        .map_err(|e| anyhow!("building the onion service config: {e}"))?;

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

/// Answer every incoming stream by echoing back whatever bytes arrive.
///
/// Runs until the request stream ends, i.e. until the service is dropped.
pub async fn serve_echo(requests: impl Stream<Item = RendRequest>) {
    let streams = handle_rend_requests(requests);
    futures::pin_mut!(streams);
    while let Some(request) = streams.next().await {
        tokio::spawn(async move {
            if let Err(e) = echo_once(request).await {
                tracing::warn!("echo failed: {e:#}");
            }
        });
    }
}

/// Accept one stream, read one chunk, write it straight back.
///
/// Neither side waits for end-of-stream; see [`dial_and_echo`] for why.
async fn echo_once(request: tor_hsservice::StreamRequest) -> Result<()> {
    use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};

    tracing::info!("incoming stream: {:?}", request.request());
    let mut stream = request
        .accept(Connected::new_empty())
        .await
        .context("accepting the incoming stream")?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.context("reading the probe")?;
    stream
        .write_all(&buf[..n])
        .await
        .context("writing the echo")?;
    stream.flush().await.context("flushing the echo")?;
    stream.close().await.context("closing the echo stream")?;
    Ok(())
}

/// Dial a `.onion` on [`SERVICE_PORT`], send `payload`, and read back exactly as
/// many bytes.
///
/// # Why not `read_to_end`
///
/// Closing a Tor stream is not a clean EOF. `DataWriter::poll_close` hands the
/// reactor a `CloseStreamBehavior::SendEnd(End::new_misc())`
/// (`tor-proto-0.44.0/src/stream.rs:82`), i.e. an END cell with reason `MISC`.
/// The reading side turns `EndReceived(DONE)` into EOF but every other reason
/// into an error (`tor-proto-0.44.0/src/client/stream/data.rs:503`), so
/// `read_to_end` against a peer that closed its stream fails with
/// "Received an END cell with reason MISC" *after* having received all the
/// data. Reading a known length sidesteps the question entirely, which is all
/// this echo protocol needs.
pub async fn dial_and_echo(client: &Client, address: HsId, payload: &[u8]) -> Result<Vec<u8>> {
    use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let host = address.display_unredacted().to_string();
    let mut stream = client
        .connect((host.as_str(), SERVICE_PORT))
        .await
        .map_err(|e| describe(e, &format!("dialling {host}:{SERVICE_PORT}")))?;

    stream
        .write_all(payload)
        .await
        .context("writing the probe")?;
    // Arti buffers: without an explicit flush the probe never leaves.
    stream.flush().await.context("flushing the probe")?;

    let mut reply = vec![0u8; payload.len()];
    stream
        .read_exact(&mut reply)
        .await
        .context("reading the echo")?;
    Ok(reply)
}

/// Dial until it works or `deadline` runs out.
///
/// A first dial that lands before the descriptor has propagated to the HSDirs
/// fails with `OnionServiceNotFound` / `OnionServiceDescriptorValidationFailed`
/// — a timing artefact, not a verdict. Retrying is the only honest way to tell
/// "not published yet" from "not reachable".
pub async fn dial_and_echo_retrying(
    client: &Client,
    address: HsId,
    payload: &[u8],
    deadline: Duration,
    mut on_attempt: impl FnMut(u32, &str),
) -> Result<Vec<u8>> {
    /// Gap between two dials. A rendezvous is 7-50 s, so retrying faster than
    /// this just piles up circuits.
    const BACKOFF: Duration = Duration::from_secs(10);

    let start = Instant::now();
    let mut attempt = 0u32;
    let mut last: Option<anyhow::Error> = None;

    while start.elapsed() < deadline {
        attempt += 1;
        let remaining = deadline.saturating_sub(start.elapsed());
        match tokio::time::timeout(remaining, dial_and_echo(client, address, payload)).await {
            Ok(Ok(reply)) => return Ok(reply),
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
