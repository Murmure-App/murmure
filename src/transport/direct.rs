//! The direct data plane: a QUIC link that does not go through Tor.
//!
//! # What this is for, and what it costs
//!
//! Tor carries everything in murmure, and for text that is free — a message is
//! a few hundred bytes, so even a poor circuit passes a thousand a second. For
//! a file it is not free: onion-to-onion traffic crosses **six** relays, and
//! measured throughput sits at 0,1-0,25 MB/s. A 2 MB PDF takes half a minute.
//!
//! This module is the escape hatch, and it is deliberately not automatic.
//! A direct connection tells the other peer our IP address, and tells both
//! ISPs that these two addresses exchanged data at this moment — which is
//! precisely the metadata the whole project exists to hide. So the operator
//! asks for it by name, per transfer, and the recipient is told what it
//! reveals before anything is sent. An automatic fast path with a silent
//! fallback, which is what the original plan called for, would leak the
//! relationship without anyone noticing.
//!
//! # Why there is no certificate authority
//!
//! There is nothing for a CA to attest. The two peers have already
//! authenticated each other over an onion circuit, against an address the
//! operators compared out loud. So the certificate here is a carrier for a
//! public key and nothing else: it is generated fresh per connection, and the
//! dialling side checks it against a fingerprint handed to it over that
//! already-authenticated Tor channel. That is strictly stronger than the web
//! PKI for this case — no third party is trusted at all.
//!
//! # What it does not do
//!
//! No NAT traversal, and — as built — **no way to be reached from outside the
//! local network at all**. [`candidates`] advertises only what this machine can
//! see about itself, which is a private address and loopback; discovering the
//! public one needs STUN or another third party, and there is none. The port is
//! ephemeral too, so there is nothing fixed for an operator to forward even if
//! they wanted to.
//!
//! So this reaches a peer on the same network, and otherwise fails and falls
//! back to Tor. Making a forwarded port usable would take two things that are
//! not here: a fixed port, and a way for the operator to declare their public
//! address. Hole punching is a later step again, and a much harder one; see
//! `aidd_docs/INSTALL.md`.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow};
use quinn::{Endpoint, RecvStream, SendStream};

/// Application-layer protocol name. QUIC requires one, and naming it keeps a
/// stray connection from another program from getting as far as a stream.
const ALPN: &[u8] = b"murmure-file/1";

/// How long a dial may spend on one candidate before the next is tried.
///
/// Short on purpose: the whole point of the direct path is that it is fast, and
/// a candidate that has not answered in this long is almost always one that
/// never will — a private address on a network we are not on. Tor is waiting
/// underneath, so giving up early costs a fallback, not a failure.
pub const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// A listener waiting for the peer to connect, and what the peer needs to
/// reach it.
pub struct Listener {
    endpoint: Endpoint,
    /// BLAKE3 of the certificate, sent over Tor for the dialler to pin.
    pub fingerprint: [u8; 32],
    /// Every address this machine believes it can be reached on.
    pub candidates: Vec<SocketAddr>,
}

/// Bind a QUIC endpoint on an ephemeral port and describe how to reach it.
pub fn listen() -> Result<Listener> {
    let (chain, key) = self_signed()?;
    let fingerprint = *blake3::hash(&chain).as_bytes();

    // Built by hand rather than with `ServerConfig::with_single_cert`, which
    // sets no ALPN: the handshake then fails with "peer doesn't support any
    // known protocol", because the dialling side does announce one.
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("selecting TLS versions")?
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(chain.clone())],
        rustls::pki_types::PrivateKeyDer::try_from(key)
            .map_err(|e| anyhow!("the generated private key is unusable: {e}"))?,
    )
    .context("loading the generated certificate")?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let suite = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .context("adapting the TLS config for QUIC")?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(suite));
    Arc::get_mut(&mut server.transport)
        .expect("freshly built, so not yet shared")
        .max_concurrent_uni_streams(1u8.into());

    // Any interface: which one the peer can actually reach is what the
    // candidate list is for.
    let endpoint = Endpoint::server(server, "0.0.0.0:0".parse().expect("literal"))
        .context("binding the QUIC endpoint")?;
    let port = endpoint
        .local_addr()
        .context("reading the bound port")?
        .port();

    Ok(Listener {
        endpoint,
        fingerprint,
        candidates: candidates(port),
    })
}

/// An open direct link, and everything that has to stay alive for it to work.
///
/// quinn closes a connection as soon as its `Connection` is dropped, and tears
/// the whole thing down when the last `Endpoint` goes — so handing back a bare
/// stream would give the caller something that dies the moment this function
/// returns. Small payloads survive that by winning the race against the close;
/// large ones do not, which is a bug that only shows up on real files.
pub struct Link<S> {
    _endpoint: Option<Endpoint>,
    _connection: quinn::Connection,
    stream: S,
}

impl<S> std::ops::Deref for Link<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.stream
    }
}

impl<S> std::ops::DerefMut for Link<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl Listener {
    /// Wait for the peer, and hand back the stream they open.
    pub async fn accept(&self) -> Result<Link<RecvStream>> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow!("the QUIC endpoint closed before anyone connected"))?;
        let connection = incoming.await.context("completing the QUIC handshake")?;
        let stream = connection
            .accept_uni()
            .await
            .context("accepting the file stream")?;
        Ok(Link {
            // Ours is owned by the `Listener`, which the caller keeps.
            _endpoint: None,
            _connection: connection,
            stream,
        })
    }
}

/// Try each candidate in turn; the first one that completes wins.
///
/// `fingerprint` is what makes this safe: it arrived over the Tor channel, and
/// a connection whose certificate does not hash to it is refused during the
/// handshake, before a byte of the file moves.
pub async fn dial(candidates: &[SocketAddr], fingerprint: [u8; 32]) -> Result<Link<SendStream>> {
    let mut endpoint =
        Endpoint::client("0.0.0.0:0".parse().expect("literal")).context("binding a QUIC client")?;
    endpoint.set_default_client_config(client_config(fingerprint)?);

    let mut last: Option<anyhow::Error> = None;
    for address in candidates {
        let attempt = async {
            let connecting = endpoint
                .connect(*address, "murmure")
                .with_context(|| format!("starting a QUIC connection to {address}"))?;
            let connection = connecting
                .await
                .with_context(|| format!("connecting to {address}"))?;
            let stream = connection
                .open_uni()
                .await
                .context("opening the file stream")?;
            Ok::<_, anyhow::Error>(Link {
                _endpoint: Some(endpoint.clone()),
                _connection: connection,
                stream,
            })
        };
        match tokio::time::timeout(DIAL_TIMEOUT, attempt).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = Some(e),
            Err(_) => last = Some(anyhow!("{address} did not answer within {DIAL_TIMEOUT:?}")),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("the peer offered no address to try")))
}

/// A fresh certificate and its key, both DER.
fn self_signed() -> Result<(Vec<u8>, Vec<u8>)> {
    let signed = rcgen::generate_simple_self_signed(vec!["murmure".to_owned()])
        .context("generating a certificate for the direct link")?;
    Ok((
        signed.cert.der().to_vec(),
        signed.signing_key.serialize_der(),
    ))
}

/// Where this machine thinks it can be reached, on `port`.
///
/// The address is found by opening a UDP socket and pointing it at an address
/// that is never routed. No packet is sent — `connect` on UDP only fixes the
/// default destination — but it makes the operating system choose the source
/// address it *would* use, which is the one on the interface that carries the
/// default route. That is the answer we want, and it costs no dependency and
/// no platform-specific code.
///
/// Loopback is included last so that two instances on one machine can reach
/// each other, which is what the tests do.
fn candidates(port: u16) -> Vec<SocketAddr> {
    let mut found = Vec::new();
    if let Some(ip) = default_route_address() {
        found.push(SocketAddr::new(ip, port));
    }
    found.push(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port));
    found
}

fn default_route_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // TEST-NET-1: reserved for documentation, so it is never actually routed.
    socket.connect("192.0.2.1:9").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// A client config that trusts exactly one certificate: the one whose BLAKE3
/// hash matches what came over Tor.
fn client_config(fingerprint: [u8; 32]) -> Result<quinn::ClientConfig> {
    let crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("selecting TLS versions")?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(Pinned { fingerprint }))
    .with_no_client_auth();

    let mut crypto = crypto;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let suite = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("adapting the TLS config for QUIC")?;
    Ok(quinn::ClientConfig::new(Arc::new(suite)))
}

/// Accept one certificate and no other.
///
/// This replaces the web PKI rather than adding to it. Refusing everything
/// except a known hash is the whole check — there is no name to validate, no
/// expiry that means anything on a certificate made seconds ago, and no
/// authority whose opinion we would want.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let got = *blake3::hash(end_entity).as_bytes();
        // Constant-time: the fingerprint is public, but comparing secrets and
        // near-secrets in constant time by habit is cheaper than deciding case
        // by case which ones deserve it.
        if got.ct_eq(&self.fingerprint) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the peer's certificate does not match the fingerprint sent over Tor".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only, so this is unreachable rather than permissive.
        Err(rustls::Error::General(
            "TLS 1.2 is not used on a QUIC link".to_owned(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Constant-time equality for a 32-byte hash.
trait ConstantTimeEq {
    fn ct_eq(&self, other: &Self) -> bool;
}

impl ConstantTimeEq for [u8; 32] {
    fn ct_eq(&self, other: &Self) -> bool {
        self.iter()
            .zip(other.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole path, on one machine: bind, hand the fingerprint over as Tor
    /// would, connect, and move bytes.
    #[tokio::test]
    async fn a_file_crosses_a_direct_link() {
        let listener = listen().expect("bind");
        let fingerprint = listener.fingerprint;
        let candidates = listener.candidates.clone();

        let receiving = tokio::spawn(async move {
            let mut stream = listener.accept().await.expect("accept");
            stream.read_to_end(1024 * 1024).await.expect("read")
        });

        // Big enough to lose the race against a connection closing early.
        // With a few bytes this test passed even while `dial` dropped the
        // connection on the way out, which is the bug it now catches.
        let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let mut out = dial(&candidates, fingerprint).await.expect("dial");
        out.write_all(&payload).await.expect("write");
        out.finish().expect("finish");
        out.stopped().await.ok();

        assert_eq!(receiving.await.unwrap(), payload);
    }

    /// The fingerprint is the only thing standing between a direct link and
    /// whoever answers on that port, so a wrong one must stop the handshake.
    #[tokio::test]
    async fn a_wrong_fingerprint_is_refused() {
        let listener = listen().expect("bind");
        // One candidate, and the loopback one: with several, a refusal on the
        // first is followed by a timeout on the rest, and the timeout is what
        // the assertion would see.
        let only = *listener
            .candidates
            .iter()
            .find(|a| a.ip().is_loopback())
            .expect("loopback is always offered");

        // Joined rather than spawned, so the listener outlives the handshake:
        // dropping it closes the endpoint, and the dial would then time out
        // instead of being refused.
        let one = [only];
        let (_, dialled) = tokio::join!(listener.accept(), dial(&one, [0u8; 32]));

        let text = match dialled {
            Ok(_) => panic!("a wrong fingerprint must not connect"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            text.contains("fingerprint") || text.contains("crypto") || text.contains("certificate"),
            "expected a certificate refusal, got: {text}"
        );
    }

    /// A peer that offers nothing reachable has to fail promptly rather than
    /// hang, because Tor is waiting underneath.
    #[tokio::test]
    async fn an_unreachable_candidate_gives_up() {
        // TEST-NET-1 again: routed nowhere, so nothing can answer.
        let nowhere: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let started = std::time::Instant::now();
        assert!(dial(&[nowhere], [0u8; 32]).await.is_err());
        assert!(
            started.elapsed() < DIAL_TIMEOUT * 2,
            "gave up after {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn candidates_always_include_a_way_back_to_this_machine() {
        let found = candidates(4242);
        assert!(found.iter().all(|a| a.port() == 4242));
        assert!(
            found.iter().any(|a| a.ip().is_loopback()),
            "two instances on one machine must be able to meet: {found:?}"
        );
    }
}
