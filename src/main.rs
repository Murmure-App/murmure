//! murmure — keystore milestone.
//!
//! One executable proof, and nothing else:
//!
//! 1. murmure generates and owns a 32-byte ed25519 seed;
//! 2. it hands the derived keypair to arti as the onion service identity;
//! 3. it publishes the service and prints the resulting `.onion` address,
//!    after checking byte-for-byte that the address arti published is the one
//!    derived from *our* seed;
//! 4. a second, independent `TorClient` on the same machine dials that address
//!    through Tor and gets its probe echoed back.
//!
//! Run it twice: the address is the same, because murmure owns the seed. Delete
//! the seed and the run directory, and the address changes.

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

/// How long to wait for the service to *confirm* it is reachable before dialling
/// anyway. Short on purpose, and overlapped with the client bootstrap: the
/// confirmation is advisory (see `transport::tor::wait_until_reachable`) and
/// often never arrives even on a service that answers. The dial is the real
/// test.
const REACHABLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Total budget for reaching our own service. A rendezvous is 7-50 s per
/// PETS 2025 and the first dial can land before the descriptor has propagated,
/// so this covers several attempts. Generous on purpose: a tight timeout would
/// fail the milestone for the wrong reason.
const DIAL_TIMEOUT: Duration = Duration::from_secs(240);

/// What the client sends and expects back verbatim.
const PROBE: &[u8] = b"murmure milestone probe";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
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
        Ok(()) => {
            println!("[ok] milestone crossed");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("murmure: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let started = Instant::now();
    let run_dir = run_dir();
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("creating {}", run_dir.display()))?;

    // ---- phase 2: our own identity -------------------------------------
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
    println!("expected address (derived locally from our seed):");
    println!("  {}", expected.display_unredacted());

    // ---- phase 3: publish under that identity --------------------------
    let nickname = NICKNAME
        .to_owned()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid onion service nickname {NICKNAME:?}: {e}"))?;

    stage(started, "bootstrapping the service-side Tor client");
    let service_client = tor::bootstrap_client(
        &run_dir.join("service/state"),
        &run_dir.join("service/cache"),
    )
    .await?;

    stage(started, "launching the onion service under our key");
    let (handover, service, requests) =
        tor::launch_with_identity(&service_client, &nickname, identity.hs_id_keypair())?;
    match handover {
        KeyHandover::Inserted => stage(started, "arti accepted our keypair into an empty keystore"),
        KeyHandover::Reused => stage(
            started,
            "the keystore already held an identity for this nickname; \
             arti refused to overwrite it (this is the wanted behaviour)",
        ),
    }

    // The whole point of the milestone: the published address must be the one
    // we derived locally, not one arti generated. A byte comparison, not a log
    // check.
    let published = service
        .onion_address()
        .context("arti published the service but reported no onion address")?;
    if published != expected {
        bail!(
            "IDENTITY MISMATCH — arti published {published} but our seed derives {expected}.\n\
             The keystore at {}/service/state/keystore holds a different key than the seed at {}.\n\
             arti was not allowed to overwrite it, so nothing was lost: either delete that \
             keystore directory to republish under our seed, or delete the seed to adopt the \
             stored identity.",
            run_dir.display(),
            seed_path.display(),
            published = published.display_unredacted(),
            expected = expected.display_unredacted(),
        );
    }

    let address_text = published.display_unredacted().to_string();
    assert_well_formed(&address_text)?;
    println!("published address (reported by arti):");
    println!("  {address_text}");
    println!("  -> matches the address derived from our seed");

    stage(
        started,
        "serving; publishing the descriptor and bootstrapping the client in parallel",
    );
    tokio::spawn(tor::serve_echo(requests));

    // ---- phase 4: reach it from a second client ------------------------
    //
    // The two are independent, so they run concurrently: the second client owns
    // its own state and cache directories and shares nothing with the service.
    let client_state = run_dir.join("client/state");
    let client_cache = run_dir.join("client/cache");
    let (reachable, dial_client) = tokio::join!(
        tor::wait_until_reachable(&service, REACHABLE_TIMEOUT),
        tor::bootstrap_client(&client_state, &client_cache),
    );
    let dial_client = dial_client?;
    match reachable {
        Ok(()) => stage(started, "onion service reports itself reachable"),
        // Advisory only — see `wait_until_reachable`. The dial below decides.
        Err(e) => stage(
            started,
            &format!("reachability not confirmed ({e:#}); dialling anyway"),
        ),
    }

    stage(
        started,
        &format!("dialling {address_text}:{}", tor::SERVICE_PORT),
    );
    let echoed = tor::dial_and_echo_retrying(
        &dial_client,
        published,
        PROBE,
        DIAL_TIMEOUT,
        |attempt, err| stage(started, &format!("dial attempt {attempt} failed: {err}")),
    )
    .await?;

    if echoed != PROBE {
        bail!(
            "echo mismatch: sent {:?}, received {:?}",
            String::from_utf8_lossy(PROBE),
            String::from_utf8_lossy(&echoed)
        );
    }
    stage(started, "echo received and identical");

    println!();
    println!("murmure reached its own onion service through Tor, under a key it generated itself.");
    println!("run it again: the address will be identical, because the seed is ours.");
    Ok(())
}

/// Where this run keeps its seed and its two client directory pairs.
///
/// Overridable with `MURMURE_DIR` so a test can point at a scratch directory.
fn run_dir() -> PathBuf {
    match std::env::var_os("MURMURE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(".murmure"),
    }
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

/// Print a timestamped stage marker, so a 90-second run never looks frozen.
fn stage(started: Instant, what: &str) {
    println!("[{:>5.1}s] {what}", started.elapsed().as_secs_f32());
}
