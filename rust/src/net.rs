//! Transport plumbing: TCP connect (direct or via a front SOCKS5 proxy)
//! and a minimal HTTPS GET client.
//!
//! Two TLS modes exist on purpose:
//! * **Verified** for `vpngate.net` and DoH endpoints. On Windows the
//!   handshake goes through the OS TLS stack (SChannel, via
//!   native-tls / tokio-native-tls), so the ClientHello matches the
//!   browser's — rustls' ClientHello was getting a fatal
//!   HandshakeFailure from a middlebox on Leo's network path while
//!   Chrome through the same front proxy opened the same URLs fine.
//!   On other platforms verified TLS is rustls with Mozilla roots
//!   **plus the OS system certificate store** (see
//!   `verified_tls_config`).
//! * **Accept-any** for VPNGate nodes: SoftEther nodes use self-signed
//!   certificates, so verification would always fail (the Python reference
//!   probe also disables verification). This is documented in the README.
//!   On Windows accept-any goes through SChannel too
//!   (`accept_any_tls_connect`, verification disabled in native-tls),
//!   because rustls' ClientHello was getting its handshake killed
//!   mid-flight (EOF) by a middlebox on Leo's network path while
//!   SChannel HTTPS through the same front proxy worked — the
//!   difference is the TLS stack, not the proxy. Other platforms keep
//!   rustls accept-any.

use crate::config::FrontProxy;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ClientConfig;
#[cfg(not(windows))]
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::TlsConnector;

/// A TCP connector that optionally routes through a front SOCKS5 proxy.
#[derive(Clone, Debug)]
pub struct Connector {
    pub front: Option<FrontProxy>,
}

impl Connector {
    #[allow(dead_code)]
    pub fn new(front: Option<FrontProxy>) -> Self {
        Self { front }
    }

    pub fn from_config(cfg: &crate::config::Config) -> Self {
        if cfg.front_proxy.enabled {
            Self {
                front: Some(cfg.front_proxy.clone()),
            }
        } else {
            Self { front: None }
        }
    }

    /// TCP connect to `host:port`, direct or via the front SOCKS5 proxy.
    pub async fn connect_tcp(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        match &self.front {
            Some(fp) => {
                crate::socks5::socks5_connect(
                    &fp.addr,
                    host,
                    port,
                    fp.username.as_deref(),
                    fp.password.as_deref(),
                )
                .await
            }
            None => TcpStream::connect((host, port)).await,
        }
    }
}

/// Build a verified rustls client config (non-Windows only): Mozilla
/// roots **plus** the OS system certificate store (Linux/macOS: the
/// usual system bundle, when one exists).
///
/// Why the system store: Leo's network path intercepts TLS with a CA
/// that is trusted by the OS — Chrome trusts it because browsers read
/// the system store — while Mozilla-roots-only verification rejected
/// it, so both refresh tiers failed even though the same URLs open
/// fine in the browser through the same front proxy. Adding the
/// system store makes the program trust what the browser trusts.
/// When no system store is available (or it loads nothing), the
/// Mozilla roots still apply, so verification is never weakened — it
/// only gains roots the OS already trusts. The accept-any config used
/// for VPNGate nodes is untouched by this change.
///
/// On Windows this function is not used: verified HTTPS goes through
/// SChannel (`tls_connect_verified`), which reads the Windows store
/// natively and — more importantly — sends a browser-like handshake.
#[cfg(not(windows))]
pub fn verified_tls_config() -> Arc<ClientConfig> {
    // v3.14 (diagnosis §6 item 8): one shared config, built once.
    // Every verified handshake used to rebuild the whole root store
    // (Mozilla roots + system store, hundreds of certs) from scratch
    // — pure per-handshake allocation/CPU, not RSS, but free to save.
    static CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(verified_roots())
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// The root store behind [`verified_tls_config`]: the Mozilla roots,
/// then every certificate the OS system store provides. Duplicates
/// (a root in both sets) are ignored — `add` fails on them and the
/// error is dropped on purpose.
#[cfg(not(windows))]
fn verified_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // load_native_certs() never fails outright: it returns whatever
    // the store gave plus a list of per-cert errors (empty store →
    // empty list, and the Mozilla roots above still apply).
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    roots
}

/// A TLS stream from a verified handshake. The concrete type differs
/// per platform (SChannel on Windows, rustls elsewhere), so callers
/// only see this boxed trait. A combined supertrait is needed because
/// a trait object can only name one non-auto trait directly.
pub trait TlsStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TlsStream for T {}

/// One shared SChannel connector for verified HTTPS (Windows),
/// built once and cloned per handshake (`native_tls::TlsConnector`
/// is a cheap `Arc` clone). v3.14 (diagnosis §6 item 8): every
/// handshake used to build a fresh connector. If the build ever
/// fails, the caller gets the error and the next handshake retries
/// the build — nothing is cached on failure.
#[cfg(windows)]
fn shared_verified_tls_connector() -> Result<native_tls::TlsConnector, String> {
    static CONNECTOR: std::sync::OnceLock<native_tls::TlsConnector> =
        std::sync::OnceLock::new();
    if let Some(c) = CONNECTOR.get() {
        return Ok(c.clone());
    }
    let fresh = native_tls::TlsConnector::new().map_err(|e| e.to_string())?;
    Ok(CONNECTOR.get_or_init(|| fresh).clone())
}

/// One shared SChannel connector for accept-any SSTP (Windows),
/// same pattern as `shared_verified_tls_connector`.
#[cfg(windows)]
fn shared_accept_any_tls_connector() -> Result<native_tls::TlsConnector, String> {
    static CONNECTOR: std::sync::OnceLock<native_tls::TlsConnector> =
        std::sync::OnceLock::new();
    if let Some(c) = CONNECTOR.get() {
        return Ok(c.clone());
    }
    let fresh = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(CONNECTOR.get_or_init(|| fresh).clone())
}

/// Verified TLS handshake over an already-connected stream: the
/// Google check inside an established tunnel, and the verified leg of
/// `https_get`. Windows: SChannel (native-tls) — the handshake
/// (ClientHello, cipher suites, extensions) matches the browser's,
/// and the Windows certificate store is used, so trust matches the
/// browser too. Other platforms: rustls with Mozilla roots plus the
/// system store (see `verified_tls_config`). The returned error is
/// already worded; callers prefix it with the host.
pub async fn verified_tls_connect<S>(
    stream: S,
    host: &str,
) -> Result<Box<dyn TlsStream>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[cfg(windows)]
    {
        let connector =
            tokio_native_tls::TlsConnector::from(shared_verified_tls_connector()?);
        let stream = connector
            .connect(host, stream)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Box::new(stream))
    }
    #[cfg(not(windows))]
    {
        let cfg = verified_tls_config();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("bad server name {}: {}", host, e))?;
        let stream = TlsConnector::from(cfg)
            .connect(server_name, stream)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Box::new(stream))
    }
}

/// TLS handshake for `https_get`. `verify = false` (accept-any) stays
/// rustls on every platform; `verify = true` uses the platform's
/// verified stack via `verified_tls_connect`.
async fn tls_connect(tcp: TcpStream, host: &str, verify: bool) -> Result<Box<dyn TlsStream>, String> {
    if !verify {
        let cfg = accept_any_tls_config();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("bad server name {}: {}", host, e))?;
        let stream = TlsConnector::from(cfg)
            .connect(server_name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(Box::new(stream));
    }
    verified_tls_connect(tcp, host).await
}

/// Build an accept-any rustls client config (self-signed VPNGate nodes).
/// Only used for the SSTP TLS layer, never for vpngate.net / DoH.
/// v3.14: built once and shared (see `verified_tls_config`).
pub fn accept_any_tls_config() -> Arc<ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            Arc::new(
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// Accept-any TLS handshake over an already-connected stream, for
/// VPNGate nodes (self-signed certs — verification is off by design).
/// Windows: SChannel via native-tls with both verification switches
/// disabled, so the handshake (ClientHello, cipher suites, extensions)
/// matches the browser's; SNI is still the target hostname. Other
/// platforms: rustls accept-any (same as before). The returned error
/// is already worded; callers prefix it with the host.
pub async fn accept_any_tls_connect<S>(
    stream: S,
    host: &str,
) -> Result<Box<dyn TlsStream>, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    #[cfg(windows)]
    {
        let connector =
            tokio_native_tls::TlsConnector::from(shared_accept_any_tls_connector()?);
        let stream = connector
            .connect(host, stream)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Box::new(stream))
    }
    #[cfg(not(windows))]
    {
        let cfg = accept_any_tls_config();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| format!("bad server name {}: {}", host, e))?;
        let stream = TlsConnector::from(cfg)
            .connect(server_name, stream)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Box::new(stream))
    }
}

#[derive(Debug)]
struct AcceptAnyVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Minimal HTTPS GET. `url` must be https://host[:port]/path.
/// Returns (status_code, body). Follows no redirects.
pub async fn https_get(
    connector: &Connector,
    url: &str,
    extra_headers: &[(&str, &str)],
    verify: bool,
) -> Result<(u16, Vec<u8>), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("https_get: only https:// URLs supported")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) if authority[i + 1..].chars().all(|c| c.is_ascii_digit()) => (
            &authority[..i],
            authority[i + 1..]
                .parse::<u16>()
                .map_err(|_| "bad port in URL")?,
        ),
        _ => (authority, 443),
    };
    let tcp = connector
        .connect_tcp(host, port)
        .await
        .map_err(|e| format!("TCP connect to {}:{} failed: {}", host, port, e))?;
    let mut tls = tls_connect(tcp, host, verify)
        .await
        .map_err(|e| format!("TLS handshake to {} failed: {}", host, e))?;
    let mut req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: vpngate-client/{}\r\n",
        path,
        authority,
        env!("CARGO_PKG_VERSION")
    );
    for (k, v) in extra_headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("HTTPS write failed: {}", e))?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw)
        .await
        .map_err(|e| format!("HTTPS read failed: {}", e))?;
    // Split headers / body.
    let split =
        find_subslice(&raw, b"\r\n\r\n").ok_or("HTTPS response has no header terminator")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("cannot parse HTTP status line")?;
    let mut body = raw[split + 4..].to_vec();
    // Handle chunked transfer encoding (vpngate.net / DoH may use it).
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body)?;
    }
    Ok((status, body))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Front-proxy diagnostics: is the proxy itself up, and can the target
// be reached through it? The two questions have different fixes, so the
// test reports them separately instead of one generic "failed".
// ---------------------------------------------------------------------------

/// Outcome of testing one HTTPS URL through the (optional) front proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontProxyCheck {
    /// The URL answered (HTTP status + round-trip time).
    Reachable { status: u16, ms: u128 },
    /// The front proxy itself is unreachable (its port does not answer,
    /// or the SOCKS5 handshake / auth was rejected). `String` is the
    /// underlying error, already worded for the log.
    ProxyUnreachable(String),
    /// The proxy is up, but the target did not answer through it.
    TargetUnreachable(String),
}

/// Direct TCP connect to the front proxy (no SOCKS5 handshake): proves
/// the proxy port is listening. Returns `None` when no front proxy is
/// configured, `Some(true)` when the port answers, `Some(false)` when
/// it does not (down, wrong address, LAN not reachable).
pub async fn check_front_proxy_tcp(connector: &Connector, timeout: Duration) -> Option<bool> {
    let fp = connector.front.as_ref()?;
    let res = tokio::time::timeout(timeout, TcpStream::connect(&fp.addr)).await;
    Some(matches!(res, Ok(Ok(_))))
}

/// Classify an `https_get` failure. `proxy_tcp` is the result of
/// `check_front_proxy_tcp`: `None` when no front proxy is configured
/// (then every failure is the target's), `Some(true/false)` when one
/// is configured and its port did/did not answer.
pub fn classify_https_get_error(err: &str, proxy_tcp: Option<bool>) -> FrontProxyCheck {
    // The proxy answered and tried, but could not reach the target
    // (connection refused / host unreachable / network unreachable
    // on the proxy's side): the proxy is up, the target is the problem.
    if err.contains("SOCKS5 proxy CONNECT failed") {
        return FrontProxyCheck::TargetUnreachable(format!(
            "代理已接受请求，但连不上目标站：{}",
            err
        ));
    }
    // Auth / method rejection happens at the proxy itself.
    if err.contains("SOCKS5 proxy rejected") || err.contains("SOCKS5 proxy authentication failed") {
        return FrontProxyCheck::ProxyUnreachable(format!(
            "代理拒绝了连接（认证/方式不对）：{}",
            err
        ));
    }
    if err.starts_with("TCP connect to ") {
        return match proxy_tcp {
            // No proxy configured: the direct connect to the target failed.
            None => FrontProxyCheck::TargetUnreachable(format!("直连目标站失败：{}", err)),
            // Proxy port answers, but the SOCKS5 handshake broke
            // mid-flight: the proxy is the problem, not the target.
            Some(true) => FrontProxyCheck::ProxyUnreachable(format!(
                "代理端口能连上，但 SOCKS5 握手失败：{}",
                err
            )),
            // Proxy port does not answer at all.
            Some(false) => {
                FrontProxyCheck::ProxyUnreachable(format!("连前置代理端口失败：{}", err))
            }
        };
    }
    // TLS handshake / HTTP write / read / parse: the TCP pipe through
    // the proxy was established, so the target is at fault.
    FrontProxyCheck::TargetUnreachable(format!("代理建好连接后目标站无响应：{}", err))
}

/// How much of a front-proxy test's total budget the TCP pre-check
/// may consume: at most 5 s, so a dead proxy address cannot eat the
/// whole budget before the HTTPS leg even starts. Pure, so the cap is
/// unit-testable without network timing.
fn front_proxy_precheck_budget(total: Duration) -> Duration {
    total.min(Duration::from_secs(5))
}

/// Test one HTTPS URL through `connector`, distinguishing "the front
/// proxy itself is down" from "the proxy is up but the target does not
/// answer through it". This is SOCKS5-proxy connectivity, not ICMP ping.
///
/// `timeout` is the TOTAL budget for this one site (pre-check +
/// HTTPS together, not one budget each): the TCP pre-check gets at
/// most 5 s of it, the HTTPS leg gets whatever is left. Two sites
/// tested in series therefore take at most 2 × `timeout` overall,
/// and the caller can report progress between them instead of going
/// silent for 40 s.
pub async fn test_url_through_proxy(
    connector: &Connector,
    url: &str,
    timeout: Duration,
) -> FrontProxyCheck {
    let start = Instant::now();
    let deadline = start + timeout;
    let proxy_tcp =
        check_front_proxy_tcp(connector, front_proxy_precheck_budget(timeout)).await;
    let remaining = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout(remaining, https_get(connector, url, &[], true)).await {
        Ok(Ok((status, _))) => FrontProxyCheck::Reachable {
            status,
            ms: start.elapsed().as_millis(),
        },
        Ok(Err(e)) => classify_https_get_error(&e, proxy_tcp),
        Err(_) => {
            // The whole request timed out: blame the proxy only when a
            // direct TCP connect to it also failed/timed out; otherwise
            // the target (or the proxy's path to it) is slow/dead.
            if proxy_tcp == Some(false) {
                FrontProxyCheck::ProxyUnreachable("连接前置代理超时".to_string())
            } else {
                FrontProxyCheck::TargetUnreachable("请求超时，目标站无响应".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn connector_with_proxy(addr: &str) -> Connector {
        let mut fp = FrontProxy::default();
        fp.enabled = true;
        fp.addr = addr.to_string();
        Connector::new(Some(fp))
    }

    /// v3.14 (diagnosis §6 item 8): the TLS configs are built once
    /// and shared — two calls return the very same `Arc`, not two
    /// separately built root stores.
    #[test]
    fn tls_configs_are_shared_singletons() {
        assert!(
            std::sync::Arc::ptr_eq(&accept_any_tls_config(), &accept_any_tls_config()),
            "accept-any config must be a single shared instance"
        );
        #[cfg(not(windows))]
        assert!(
            std::sync::Arc::ptr_eq(&verified_tls_config(), &verified_tls_config()),
            "verified config must be a single shared instance"
        );
    }

    /// A port that (almost certainly) has nothing listening: bind an
    /// ephemeral port, then drop the listener.
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// Fake SOCKS5 proxy: accepts connections (a real proxy serves many;
    /// the test below also opens a TCP pre-check connection first), then
    /// per connection either refuses the CONNECT (`"refuse"`), drops
    /// the connection mid-handshake (`"hangup"`), or completes the
    /// SOCKS5 handshake and then never answers again (`"blackhole"`).
    /// Returns its port.
    async fn fake_socks5(mode: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(handle_fake_conn(s, mode));
            }
        });
        port
    }

    async fn handle_fake_conn(mut s: tokio::net::TcpStream, mode: &'static str) {
        if mode == "hangup" {
            return; // drop: the client's handshake read fails
        }
        let mut g = [0u8; 3];
        if s.read_exact(&mut g).await.is_err() {
            return;
        }
        if s.write_all(&[0x05, 0x00]).await.is_err() {
            return;
        }
        let mut h = [0u8; 4];
        if s.read_exact(&mut h).await.is_err() {
            return;
        }
        let skip = match h[3] {
            0x01 => 4,
            0x03 => {
                let mut l = [0u8; 1];
                if s.read_exact(&mut l).await.is_err() {
                    return;
                }
                l[0] as usize
            }
            0x04 => 16,
            _ => return,
        };
        let mut rest = vec![0u8; skip + 2];
        if s.read_exact(&mut rest).await.is_err() {
            return;
        }
        if mode == "blackhole" {
            // CONNECT accepted, then silence: the client's TLS
            // handshake (and everything after it) gets no answer.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            return;
        }
        // CONNECT refused (0x05): the proxy is up, the target is not.
        let _ = s
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[test]
    #[cfg(not(windows))]
    fn verified_roots_add_system_store_on_top_of_mozilla() {
        let mozilla = webpki_roots::TLS_SERVER_ROOTS.len();
        let roots = verified_roots();
        // Never fewer than the Mozilla set: a missing/empty system
        // store must fall back to Mozilla roots only, not break the
        // verified config.
        assert!(
            roots.len() >= mozilla,
            "verified roots {} < Mozilla roots {}",
            roots.len(),
            mozilla
        );
        // Report the split for diagnosis; the system store usually
        // overlaps the Mozilla set, so no assertion on the extra count.
        let native = rustls_native_certs::load_native_certs();
        eprintln!(
            "Mozilla roots: {}, system certs: {} ({} load errors), verified roots total: {}",
            mozilla,
            native.certs.len(),
            native.errors.len(),
            roots.len()
        );
    }

    #[test]
    fn classify_https_errors_split_proxy_from_target() {
        // No proxy configured: a TCP failure is the target's fault.
        assert!(matches!(
            classify_https_get_error(
                "TCP connect to www.google.com:443 failed: connection refused",
                None
            ),
            FrontProxyCheck::TargetUnreachable(_)
        ));
        // Proxy port does not answer: the proxy is the problem.
        assert!(matches!(
            classify_https_get_error(
                "TCP connect to www.google.com:443 failed: connection refused",
                Some(false)
            ),
            FrontProxyCheck::ProxyUnreachable(_)
        ));
        // Proxy port answers but the SOCKS5 handshake breaks: proxy-side.
        assert!(matches!(
            classify_https_get_error(
                "TCP connect to www.google.com:443 failed: unexpected end of file",
                Some(true)
            ),
            FrontProxyCheck::ProxyUnreachable(_)
        ));
        // Proxy refused the CONNECT: proxy up, target down.
        assert!(matches!(
            classify_https_get_error(
                "TCP connect to www.google.com:443 failed: SOCKS5 proxy CONNECT failed, reply code 0x05",
                Some(true)
            ),
            FrontProxyCheck::TargetUnreachable(_)
        ));
        // Auth rejected at the proxy: proxy-side.
        assert!(matches!(
            classify_https_get_error(
                "TCP connect to www.google.com:443 failed: SOCKS5 proxy authentication failed",
                Some(true)
            ),
            FrontProxyCheck::ProxyUnreachable(_)
        ));
        // TLS / HTTP stages: the pipe through the proxy was up.
        assert!(matches!(
            classify_https_get_error(
                "TLS handshake to www.google.com failed: bad cert",
                Some(true)
            ),
            FrontProxyCheck::TargetUnreachable(_)
        ));
        assert!(matches!(
            classify_https_get_error("HTTPS read failed: connection reset", Some(true)),
            FrontProxyCheck::TargetUnreachable(_)
        ));
    }

    #[tokio::test]
    async fn check_front_proxy_tcp_detects_dead_and_live_ports() {
        let dead = connector_with_proxy(&format!("127.0.0.1:{}", closed_port()));
        assert_eq!(
            check_front_proxy_tcp(&dead, Duration::from_secs(3)).await,
            Some(false),
            "nothing listens on the dead port"
        );
        let live_port = fake_socks5("hangup").await;
        let live = connector_with_proxy(&format!("127.0.0.1:{}", live_port));
        assert_eq!(
            check_front_proxy_tcp(&live, Duration::from_secs(3)).await,
            Some(true),
            "the fake proxy accepts TCP"
        );
        assert_eq!(
            check_front_proxy_tcp(&Connector::new(None), Duration::from_secs(3)).await,
            None,
            "no proxy configured"
        );
    }

    #[tokio::test]
    async fn test_url_through_proxy_classifies_mock_proxies() {
        let timeout = Duration::from_secs(5);
        // Dead proxy: proxy itself unreachable.
        let dead = connector_with_proxy(&format!("127.0.0.1:{}", closed_port()));
        assert!(matches!(
            test_url_through_proxy(&dead, "https://www.google.com", timeout).await,
            FrontProxyCheck::ProxyUnreachable(_)
        ));
        // Proxy accepts TCP but hangs up mid-handshake: proxy-side.
        let hangup = connector_with_proxy(&format!("127.0.0.1:{}", fake_socks5("hangup").await));
        assert!(matches!(
            test_url_through_proxy(&hangup, "https://www.google.com", timeout).await,
            FrontProxyCheck::ProxyUnreachable(_)
        ));
        // Proxy refuses the CONNECT: proxy up, target unreachable.
        let refusing = connector_with_proxy(&format!("127.0.0.1:{}", fake_socks5("refuse").await));
        assert!(matches!(
            test_url_through_proxy(&refusing, "https://www.google.com", timeout).await,
            FrontProxyCheck::TargetUnreachable(_)
        ));
    }

    #[test]
    fn front_proxy_precheck_budget_caps_at_five_seconds() {
        assert_eq!(
            front_proxy_precheck_budget(Duration::from_secs(2)),
            Duration::from_secs(2),
            "a short total budget is used as-is"
        );
        assert_eq!(
            front_proxy_precheck_budget(Duration::from_secs(10)),
            Duration::from_secs(5),
            "a 10 s total budget gives the pre-check 5 s, not 10"
        );
        assert_eq!(
            front_proxy_precheck_budget(Duration::from_secs(30)),
            Duration::from_secs(5),
            "the pre-check never takes more than 5 s"
        );
    }

    #[tokio::test]
    async fn test_url_through_proxy_total_budget_is_shared() {
        // Blackhole proxy: the TCP pre-check answers instantly, the
        // SOCKS5 CONNECT is accepted, then nothing ever comes back.
        // The whole site must finish within its total budget (not
        // pre-check budget + HTTPS budget), classified as the target
        // not answering — Leo's v3.1 test sat silent for 40 s because
        // each leg had its own 10 s timeout, twice over, for two sites.
        let blackhole =
            connector_with_proxy(&format!("127.0.0.1:{}", fake_socks5("blackhole").await));
        let total = Duration::from_secs(3);
        let start = Instant::now();
        let res = test_url_through_proxy(&blackhole, "https://www.google.com", total).await;
        let elapsed = start.elapsed();
        assert!(
            matches!(
                res,
                FrontProxyCheck::TargetUnreachable(ref d)
                    if d.contains("请求超时，目标站无响应")
            ),
            "blackhole proxy must time out as target-unreachable, got {:?}",
            res
        );
        assert!(
            elapsed < total + Duration::from_secs(2),
            "one site must finish within its total budget, took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_url_through_proxy_silent_proxy_address_times_out() {
        // An address that never answers TCP at all (SYN dropped, or
        // rejected outright in this sandbox): the pre-check may take
        // at most 5 s of the total budget, and the result blames the
        // proxy with a timeout, within the total budget.
        let silent = connector_with_proxy("10.255.255.1:80");
        let total = Duration::from_secs(8);
        let start = Instant::now();
        let res = test_url_through_proxy(&silent, "https://www.google.com", total).await;
        let elapsed = start.elapsed();
        assert!(
            matches!(res, FrontProxyCheck::ProxyUnreachable(_)),
            "silent proxy address must be proxy-unreachable, got {:?}",
            res
        );
        assert!(
            elapsed < total + Duration::from_secs(2),
            "must finish within the total budget, took {:?}",
            elapsed
        );
    }
}

fn dechunk(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let end = find_subslice(&body[pos..], b"\r\n").ok_or("bad chunked body")? + pos;
        let size_str = String::from_utf8_lossy(&body[pos..end]).trim().to_string();
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or(""), 16)
            .map_err(|_| "bad chunk size")?;
        if size == 0 {
            break;
        }
        let start = end + 2;
        if start + size > body.len() {
            return Err("chunk overruns body".to_string());
        }
        out.extend_from_slice(&body[start..start + size]);
        pos = start + size + 2;
    }
    Ok(out)
}
