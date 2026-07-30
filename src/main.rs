//! murmure — peer-to-peer terminal messaging over Tor onion services.
//!
//! ```text
//! murmure                      publish our address and wait for a friend
//! murmure <address>.onion      call a friend
//! ```
//!
//! Both sides need to be online at the same time. It is a phone call, not a
//! text message.
//!
//! The identity is a 32-byte seed murmure owns; the `.onion` address is derived
//! from it, so the address survives restarts and is unforgeable without the
//! seed. Delete the seed and you are someone else.

mod chat;
mod identity;
mod proto;
mod transport;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use safelog::DisplayRedacted as _;

use crate::identity::Identity;
use crate::transport::tor::{self, KeyHandover};

/// Nickname arti files this service's keys and state under. Fixed: changing it
/// would look like a brand new service to the keystore.
const NICKNAME: &str = "murmure";

/// How long to wait for the service to *confirm* it is reachable before
/// announcing it as ready. Advisory only — see `tor::wait_until_reachable`,
/// which under-reports on a service that already answers.
const REACHABLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Total budget for reaching a friend's service. A rendezvous is 7-50 s per
/// PETS 2025, and a first dial can land before the descriptor has propagated,
/// so this covers several attempts.
const DIAL_TIMEOUT: Duration = Duration::from_secs(240);

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // Arti is chatty at info. Quiet by default so the conversation
                // is readable; `RUST_LOG=info` brings the detail back.
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("murmure: could not start the tokio runtime: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("murmure: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let started = Instant::now();
    let run_dir = run_dir();
    std::fs::create_dir_all(&run_dir).with_context(|| format!("creating {}", run_dir.display()))?;

    match parse_args()? {
        Mode::Listen => listen(started, &run_dir).await,
        Mode::Call { address } => call(started, &run_dir, &address).await,
    }
}

/// What the operator asked for.
enum Mode {
    /// Publish our own service and wait.
    Listen,
    /// Dial someone else's.
    Call { address: String },
}

fn parse_args() -> Result<Mode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok(Mode::Listen),
        [one] if !one.starts_with('-') => Ok(Mode::Call {
            address: one.clone(),
        }),
        _ => bail!(
            "usage:\n  murmure                    publish and wait\n  \
             murmure <address>.onion    call a friend"
        ),
    }
}

/// Publish our onion service and hold a conversation with whoever connects.
async fn listen(started: Instant, run_dir: &std::path::Path) -> Result<()> {
    let seed_path = run_dir.join("identity.seed");
    let existed = seed_path.exists();
    let identity = Identity::load_or_create(&seed_path)?;
    identity.check_permissions()?;
    let expected = identity.onion_address();

    stage(
        started,
        &format!(
            "identity {} at {}",
            if existed { "loaded" } else { "generated" },
            identity.path().display()
        ),
    );

    let nickname = NICKNAME
        .to_owned()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid onion service nickname {NICKNAME:?}: {e}"))?;

    stage(started, "bootstrapping Tor");
    let client = tor::bootstrap_client(
        &run_dir.join("service/state"),
        &run_dir.join("service/cache"),
    )
    .await?;

    stage(started, "publishing the service");
    let (handover, service, requests) =
        tor::launch_with_identity(&client, &nickname, identity.hs_id_keypair())?;
    if handover == KeyHandover::Reused {
        tracing::debug!("the keystore already held this identity; arti did not overwrite it");
    }

    // The address we publish must be the one our seed derives, never one arti
    // generated. A byte comparison, not a log check.
    let published = service
        .onion_address()
        .context("arti published the service but reported no onion address")?;
    if published != expected {
        bail!(
            "IDENTITY MISMATCH — arti published {published} but our seed derives {expected}.\n\
             The keystore at {}/service/state/keystore holds a different key than the seed at {}.\n\
             Nothing was overwritten: delete that keystore directory to republish under our \
             seed, or delete the seed to adopt the stored identity.",
            run_dir.display(),
            seed_path.display(),
            published = published.display_unredacted(),
            expected = expected.display_unredacted(),
        );
    }

    let address = published.display_unredacted().to_string();
    assert_well_formed(&address)?;

    println!();
    println!("your address — give it to your friend, and compare it out loud:");
    println!("  {address}");
    println!("  fingerprint: {}", fingerprint(&address));
    println!();

    match tor::wait_until_reachable(&service, REACHABLE_TIMEOUT).await {
        Ok(()) => stage(started, "reachable; waiting for a connection"),
        // Under-reports; the incoming connection is the real test.
        Err(_) => stage(
            started,
            "reachability not confirmed (arti under-reports); waiting anyway",
        ),
    }

    let stream = tor::accept_one(requests).await?;
    stage(started, "connected");
    println!("(type to send, Ctrl-D to hang up)");
    println!();

    let (reader, writer) = stream.split();
    chat::run(reader, writer, "them").await
}

/// Dial a friend's address and hold a conversation.
async fn call(started: Instant, run_dir: &std::path::Path, address: &str) -> Result<()> {
    let address = address.trim().trim_end_matches('/');
    assert_well_formed(address)?;
    let hs_id: tor_hscrypto::pk::HsId = address
        .parse()
        .map_err(|e| anyhow::anyhow!("{address} is not a valid onion address: {e}"))?;

    println!();
    println!("calling:");
    println!("  {address}");
    println!("  fingerprint: {}", fingerprint(address));
    println!("  -> compare that fingerprint out loud before you say anything private.");
    println!();

    stage(started, "bootstrapping Tor");
    let client =
        tor::bootstrap_client(&run_dir.join("client/state"), &run_dir.join("client/cache")).await?;

    stage(started, "dialling (7-50 s is normal)");
    let stream = tor::dial_retrying(&client, hs_id, DIAL_TIMEOUT, |attempt, err| {
        stage(started, &format!("attempt {attempt} failed: {err}"))
    })
    .await?;

    stage(started, "connected");
    println!("(type to send, Ctrl-D to hang up)");
    println!();

    let (reader, writer) = stream.split();
    chat::run(reader, writer, "them").await
}

/// Where this run keeps its seed and its Tor directories.
///
/// Overridable with `MURMURE_DIR`, which is also how two instances share one
/// machine without colliding.
fn run_dir() -> PathBuf {
    match std::env::var_os("MURMURE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(".murmure"),
    }
}

/// A short, speakable digest of an address, for comparing out loud.
///
/// The address itself is 56 characters — nobody reads that over the phone
/// correctly. These are the first and last four, which is what the human check
/// in `aidd_docs/brainstorm` actually needs: an attacker who substituted the
/// address has to match both ends.
fn fingerprint(address: &str) -> String {
    let base32 = address.strip_suffix(".onion").unwrap_or(address);
    let head: String = base32.chars().take(4).collect();
    let tail: String = base32
        .chars()
        .skip(base32.chars().count().saturating_sub(4))
        .collect();
    format!("{head} … {tail}")
}

/// A v3 onion address is 56 base32 characters plus `.onion`.
fn assert_well_formed(address: &str) -> Result<()> {
    let Some(base32) = address.strip_suffix(".onion") else {
        bail!("{address} does not end in .onion");
    };
    if base32.len() != 56 {
        bail!(
            "{address} has {} characters before .onion, expected 56 (v3)",
            base32.len()
        );
    }
    if !base32
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        bail!("{address} is not lowercase base32");
    }
    Ok(())
}

/// Print a timestamped stage marker, so a 90-second wait never looks frozen.
fn stage(started: Instant, what: &str) {
    println!("[{:>5.1}s] {what}", started.elapsed().as_secs_f32());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_takes_both_ends() {
        let addr = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
        assert_eq!(fingerprint(addr), "hati … 7ryd");
    }

    #[test]
    fn well_formed_rejects_the_wrong_shapes() {
        let ok = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
        assert!(assert_well_formed(ok).is_ok());
        // v2 length
        assert!(assert_well_formed("abcdefghij234567.onion").is_err());
        // no suffix
        assert!(assert_well_formed("haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd").is_err());
        // '1' and '8' are not in base32
        assert!(assert_well_formed("1aticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ry8.onion").is_err());
    }
}
