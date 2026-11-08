//! Headless end-to-end test of the flow the GUI drives: connect a tunnel
//! to the mock SSTP server, run generate_204 through it, and serve a
//! local SOCKS5 port through it. No window, no GPU.
//!
//! The mock server is tests/mock_sstp.py (stdlib Python + a self-signed
//! cert at /tmp/mock_sstp_cert.pem, generated with openssl if missing).
//! If python3 or openssl is unavailable the test prints a skip note and
//! passes, instead of failing on a missing tool.

use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpngate_client::net::Connector;
use vpngate_client::sstp::SstpTunnel;

struct MockServer(Option<Child>);

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn tool_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn ensure_cert() {
    let cert = "/tmp/mock_sstp_cert.pem";
    let key = "/tmp/mock_sstp_key.pem";
    if std::path::Path::new(cert).exists() && std::path::Path::new(key).exists() {
        return;
    }
    let _ = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn start_mock() -> Option<MockServer> {
    // Reuse a mock that is already listening (another test in this
    // binary may have started it; pkill would break it mid-test).
    if std::net::TcpStream::connect_timeout(
        &"127.0.0.1:8443".parse().unwrap(),
        Duration::from_millis(300),
    )
    .is_ok()
    {
        return Some(MockServer(None));
    }
    // Clear any stale mock from an earlier run (pkill's own cmdline does
    // not contain "mock_sstp", so it cannot match itself here).
    let _ = Command::new("pkill").args(["-f", "mock_sstp.py"]).output();
    std::thread::sleep(Duration::from_millis(300));
    ensure_cert();
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = format!("{}/tests/mock_sstp.py", manifest);
    let child = Command::new("python3")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(MockServer(Some(child)))
}

async fn wait_for_port() -> bool {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect("127.0.0.1:8443")
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// The mock SSTP server is shared by the tests in this binary, but
/// its lifetime is tied to one test's `MockServer` handle: if the
/// owner finishes first, its Drop kills the mock under the other
/// test, and a parallel `start_mock` can pkill a mock that is just
/// starting (or already in use). Serialize the mock-using tests
/// instead — each holds this lock for its whole body, so the mock is
/// never started twice at once and never killed mid-test.
static MOCK_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn gui_connect_flow_against_mock() {
    if !tool_exists("python3") || !tool_exists("openssl") {
        eprintln!("SKIP: python3/openssl not available; mock SSTP server cannot run");
        return;
    }
    let _mock_guard = MOCK_LOCK.lock().await;
    let _mock = match start_mock() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: could not start mock SSTP server");
            return;
        }
    };
    assert!(
        wait_for_port().await,
        "mock SSTP server did not listen on 8443"
    );

    let connector = Connector::new(None);
    let timeout = Duration::from_secs(10);
    let tunnel = SstpTunnel::connect(&connector, "127.0.0.1", 8443, timeout)
        .await
        .expect("tunnel connect to mock");
    assert_eq!(tunnel.vip.to_string(), "10.0.0.2", "mock assigns 10.0.0.2");

    // generate_204 through the tunnel (the same check the CLI `test`
    // subcommand runs; the GUI's own tunnel-test button was removed
    // in v3.13).
    let mut s = tunnel
        .open_stream("www.gstatic.com", 80, timeout)
        .await
        .expect("open stream");
    s.write_all(b"GET http://www.gstatic.com/generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, s.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        head.contains("204"),
        "generate_204 should return 204, got: {}",
        head
    );

    // Local mixed proxy server through the tunnel (the GUI's connect
    // path): SOCKS5 still works through the mixed port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(vpngate_client::socks5::serve_mixed(
        listener,
        tunnel.clone(),
        timeout,
        None,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // no-auth
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);
    // CONNECT example.com:80 (domain form).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
    req.extend_from_slice(b"example.com");
    req.extend_from_slice(&80u16.to_be_bytes());
    client.write_all(&req).await.unwrap();
    let mut conn_resp = [0u8; 10];
    client.read_exact(&mut conn_resp).await.unwrap();
    assert_eq!(conn_resp[1], 0x00, "SOCKS5 CONNECT should succeed");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf2 = vec![0u8; 4096];
    let n2 = tokio::time::timeout(timeout, client.read(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    let body = String::from_utf8_lossy(&buf2[..n2]).to_string();
    assert!(
        body.contains("204"),
        "SOCKS5-through-tunnel should return the mock 204, got: {}",
        body
    );

    serve.abort();
    drop(tunnel); // last tunnel ref: writer task shuts TLS down
}

/// Shared mock setup for the mixed-proxy tests: lock the mock for
/// the whole test, start it if needed, and open one tunnel to it.
/// Returns the lock guard first so the caller keeps it alive — the
/// mock is shared, and dropping the guard early would let another
/// test kill the mock mid-test.
async fn setup_mock_tunnel() -> Option<(
    tokio::sync::MutexGuard<'static, ()>,
    MockServer,
    std::sync::Arc<SstpTunnel>,
)> {
    if !tool_exists("python3") || !tool_exists("openssl") {
        eprintln!("SKIP: python3/openssl not available; mock SSTP server cannot run");
        return None;
    }
    let guard = MOCK_LOCK.lock().await;
    let mock = match start_mock() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: could not start mock SSTP server");
            return None;
        }
    };
    if !wait_for_port().await {
        eprintln!("SKIP: mock SSTP server did not listen on 8443");
        return None;
    }
    let connector = Connector::new(None);
    let timeout = Duration::from_secs(10);
    let tunnel = SstpTunnel::connect(&connector, "127.0.0.1", 8443, timeout)
        .await
        .ok()?;
    Some((guard, mock, tunnel))
}

/// Read from `client` until `needle` appears or the timeout elapses;
/// returns everything read so far.
async fn read_until(
    client: &mut tokio::net::TcpStream,
    needle: &str,
    timeout: Duration,
) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, client.read(&mut buf)).await {
            Ok(Ok(0)) => break, // peer closed
            Ok(Ok(n)) => {
                out.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&out).contains(needle) {
                    break;
                }
            }
            _ => break, // timeout or read error
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// The mixed port speaks HTTP as well as SOCKS5: an HTTP CONNECT
/// builds a tunnel and passes raw bytes through it, a plain
/// absolute-form GET returns the response through the tunnel, and a
/// POST with a Content-Length body forwards the body too. The mock
/// answers every tunnel stream with a canned 204.
#[tokio::test]
async fn mixed_proxy_http_methods_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let timeout = Duration::from_secs(10);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(vpngate_client::socks5::serve_mixed(
        listener,
        tunnel.clone(),
        timeout,
        None,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // CONNECT: 200, then raw bytes pass through the tunnel and the
    // mock's 204 comes back.
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let head = read_until(&mut c, "\r\n\r\n", timeout).await;
    assert!(
        head.contains("200"),
        "CONNECT should answer 200, got: {}",
        head
    );
    c.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let body = read_until(&mut c, "204", timeout).await;
    assert!(
        body.contains("204"),
        "bytes through the CONNECT tunnel should return the mock 204, got: {}",
        body
    );
    drop(c);

    // Plain absolute-form GET: the response comes back through the
    // tunnel (and the connection then closes — a fresh connection is
    // needed for the next request).
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let body = read_until(&mut c, "204", timeout).await;
    assert!(
        body.contains("204"),
        "plain HTTP GET through the tunnel should return the mock 204, got: {}",
        body
    );
    drop(c);

    // POST with a Content-Length body: the body is forwarded through
    // the tunnel, and the mock's 204 comes back.
    let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
    c.write_all(b"POST http://example.com/post HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        .await
        .unwrap();
    let body = read_until(&mut c, "204", timeout).await;
    assert!(
        body.contains("204"),
        "POST with a body through the tunnel should return the mock 204, got: {}",
        body
    );
    drop(c);

    serve.abort();
    drop(tunnel);
}

/// HTTP CONNECT really is a byte pipe after the 200 — not just for
/// ASCII: a binary TLS ClientHello (0x00 bytes included) sent through
/// a CONNECT tunnel comes back byte-for-byte from the mock's echo
/// mode, which is what a TLS handshake inside the tunnel needs. The
/// server is bound the LAN way (0.0.0.0:0, reached via 127.0.0.1),
/// so the wildcard-bind path is covered too, and the connection log
/// lines name the peer and the CONNECT target host.
#[tokio::test]
async fn connect_relay_carries_tls_client_hello_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let timeout = Duration::from_secs(10);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel::<String>(vpngate_client::socks5::CONN_LOG_CAPACITY);
    let serve = tokio::spawn(vpngate_client::socks5::serve_mixed(
        listener,
        tunnel.clone(),
        timeout,
        Some(log_tx),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A minimal (fake) TLS 1.2 ClientHello record: 5-byte record
    // header + 4-byte handshake header + version + 32 random bytes
    // + session/cipher/compression/extensions. Binary on purpose,
    // so any text-oriented handling in the relay would corrupt it.
    let client_hello: [u8; 52] = [
        0x16, 0x03, 0x01, 0x00, 0x2f, // record: handshake, TLS 1.0, len 47
        0x01, 0x00, 0x00, 0x2b, // handshake: client_hello, len 43
        0x03, 0x03, // client version TLS 1.2
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // 32 random bytes
        0x00, // session id length 0
        0x00, 0x02, 0x13, 0x01, // cipher suites: len 2, TLS_AES_128_GCM_SHA256
        0x01, 0x00, // compression methods: len 1, null
        0x00, 0x00, // extensions length 0
    ];

    // SOCKS5 through the wildcard bind: greeting, CONNECT
    // example.com:443, then ECHO bytes come back verbatim.
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    tokio::time::timeout(timeout, c.read_exact(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 greeting must be accepted");
    let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
    req.extend_from_slice(b"example.com");
    req.extend_from_slice(&443u16.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(timeout, c.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &rep[..2],
        &[0x05, 0x00],
        "SOCKS5 CONNECT must succeed, got: {:?}",
        rep
    );
    c.write_all(b"ECHO:socks5-echo").await.unwrap();
    let mut echo = [0u8; 11];
    tokio::time::timeout(timeout, c.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &echo, b"socks5-echo",
        "bytes through the SOCKS5 tunnel must come back verbatim"
    );
    drop(c);

    // HTTP CONNECT: 200, then the ClientHello goes through the
    // tunnel and comes back byte-for-byte.
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let head = read_until(&mut c, "\r\n\r\n", timeout).await;
    assert!(
        head.contains("200"),
        "CONNECT should answer 200, got: {}",
        head
    );
    let mut payload = b"ECHO:".to_vec();
    payload.extend_from_slice(&client_hello);
    c.write_all(&payload).await.unwrap();
    let mut back = [0u8; 52];
    tokio::time::timeout(timeout, c.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        back, client_hello,
        "the ClientHello must survive the CONNECT relay byte-for-byte"
    );
    drop(c);

    // A raw TLS byte (0x16) sent straight at the proxy port, with no
    // CONNECT: not a protocol we serve, closed silently.
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(&[0x16]).await.unwrap();
    let mut one = [0u8; 1];
    // The server peeked the byte (peek does not consume it) and then
    // closed with it still unread in the receive buffer, so the
    // kernel answers with RST rather than a clean FIN — either way
    // the connection is dead, which is the point.
    match tokio::time::timeout(timeout, c.read(&mut one)).await {
        Ok(Ok(0)) => {}
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!(
            "an unknown first byte must close the connection, got: {:?}",
            other
        ),
    }
    drop(c);

    // Drain the connection log: the SOCKS5 + CONNECT lines name the
    // peer (127.0.0.1 — this connection came from loopback, not LAN)
    // and the target host, and the unknown byte is logged too.
    let mut lines = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), log_rx.recv()).await {
            Ok(Some(line)) => lines.push(line),
            _ => break,
        }
    }
    assert!(
        lines
            .iter()
            .any(|l| l.contains("127.0.0.1") && l.contains("SOCKS5 → example.com:443")),
        "the SOCKS5 connection line must name the peer and target, got: {:?}",
        lines
    );
    assert!(
        lines.iter().any(|l| l.contains("127.0.0.1")
            && l.contains("HTTP CONNECT → example.com:443")),
        "the CONNECT line must name the peer and target host, got: {:?}",
        lines
    );
    assert!(
        lines.iter().any(|l| l.contains("未知协议")),
        "the unknown first byte must be logged, got: {:?}",
        lines
    );

    serve.abort();
    drop(tunnel);
}

/// LAN sharing binds the same mixed port on all interfaces: one
/// 0.0.0.0 bind serves loopback too, so a client connecting via
/// 127.0.0.1 reaches the mixed server (SOCKS5 greeting answered).
#[tokio::test]
async fn wildcard_bind_serves_loopback_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let timeout = Duration::from_secs(10);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let serve = tokio::spawn(vpngate_client::socks5::serve_mixed(
        listener,
        tunnel.clone(),
        timeout,
        None,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // no-auth
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(
        resp,
        [0x05, 0x00],
        "a wildcard bind must answer loopback SOCKS5 clients"
    );

    serve.abort();
    drop(tunnel);
}

/// A TCP listener that accepts and holds connections forever, never
/// sending a byte — a hanging candidate port (a dead node whose TLS
/// handshake never answers).
fn black_hole_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || loop {
        let Ok((s, _)) = listener.accept() else {
            break;
        };
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3600));
            drop(s);
        });
    });
    port
}

/// One candidate port answers (the mock SSTP server), the others hang:
/// the parallel race must return the good one fast — a serial walk
/// would burn the whole timeout on the hanging port listed first.
/// Regression test for Leo's v3.2 log (dead-node probe ~20 s).
#[tokio::test]
async fn parallel_candidate_race_is_fast() {
    if !tool_exists("python3") || !tool_exists("openssl") {
        eprintln!("SKIP: python3/openssl not available; mock SSTP server cannot run");
        return;
    }
    let _mock_guard = MOCK_LOCK.lock().await;
    let _mock = match start_mock() {
        Some(m) => m,
        None => {
            eprintln!("SKIP: could not start mock SSTP server");
            return;
        }
    };
    assert!(
        wait_for_port().await,
        "mock SSTP server did not listen on 8443"
    );

    let connector = Connector::new(None);
    let timeout = Duration::from_secs(5);
    // Hanging ports first: serial order would hang on them before
    // ever reaching the mock.
    let candidates = vec![
        ("127.0.0.1".to_string(), black_hole_port()),
        ("127.0.0.1".to_string(), black_hole_port()),
        ("127.0.0.1".to_string(), 8443),
    ];
    let start = std::time::Instant::now();
    let (vip, ms) = SstpTunnel::probe_any(&connector, &candidates, timeout)
        .await
        .expect("race must find the live mock port");
    let elapsed = start.elapsed();
    assert_eq!(vip.to_string(), "10.0.0.2", "mock assigns 10.0.0.2");
    assert!(
        elapsed < Duration::from_secs(3),
        "parallel race must beat the 5 s timeout, took {:?} (probe said {} ms)",
        elapsed,
        ms.as_millis()
    );
}

/// Every candidate hangs: the race must still return, within about
/// one total timeout — not one timeout per candidate.
#[tokio::test]
async fn parallel_candidate_race_all_hanging_returns_within_timeout() {
    let connector = Connector::new(None);
    let timeout = Duration::from_secs(3);
    let candidates = vec![
        ("127.0.0.1".to_string(), black_hole_port()),
        ("127.0.0.1".to_string(), black_hole_port()),
        ("127.0.0.1".to_string(), black_hole_port()),
    ];
    let start = std::time::Instant::now();
    let res = SstpTunnel::probe_any(&connector, &candidates, timeout).await;
    let elapsed = start.elapsed();
    assert!(res.is_err(), "all-hanging race must fail");
    assert!(
        elapsed < Duration::from_secs(5),
        "three hanging candidates must cost about one 3 s timeout, took {:?}",
        elapsed
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "the race must actually wait out the deadline, took {:?}",
        elapsed
    );
}

/// SOCKS5 UDP ASSOCIATE through the mock tunnel, with the mock's UDP
/// ECHO mode: a datagram sent to the relay comes back byte-for-byte,
/// proving the whole path (SOCKS UDP header → tunnel UDP → mock →
/// tunnel UDP → SOCKS UDP reply). The mock only proves the path —
/// real DNS/QUIC still need Leo's phone test (see the docs).
#[tokio::test]
async fn socks5_udp_associate_echo_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let timeout = Duration::from_secs(10);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (log_tx, mut log_rx) = tokio::sync::mpsc::channel::<String>(vpngate_client::socks5::CONN_LOG_CAPACITY);
    let serve = tokio::spawn(vpngate_client::socks5::serve_mixed(
        listener,
        tunnel.clone(),
        timeout,
        Some(log_tx),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // UDP ASSOCIATE over TCP: greeting, then command 0x03 with a
    // 0.0.0.0:0 address (the usual "any" request).
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    tokio::time::timeout(timeout, c.read_exact(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resp, [0x05, 0x00], "SOCKS5 greeting must be accepted");
    c.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(timeout, c.read_exact(&mut rep))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &rep[..2],
        &[0x05, 0x00],
        "UDP ASSOCIATE must succeed, got: {:?}",
        rep
    );
    assert_eq!(rep[3], 0x01, "relay address must be IPv4, got: {:?}", rep);
    let relay_ip = std::net::Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    assert_eq!(
        relay_ip.to_string(),
        "127.0.0.1",
        "relay must answer on loopback"
    );
    assert_eq!(
        relay_port, port,
        "UDP relay must share the TCP listener's port"
    );

    // The datagram round-trip needs a machine that can actually
    // send UDP. This VM's sandbox blocks UDP sendto with EPERM even
    // to 127.0.0.1, so the round-trip part skips here — the TCP
    // handshake above already ran, and the tunnel-level echo test
    // covers the UDP path itself.
    if !udp_available().await {
        eprintln!("SKIP: this machine cannot send UDP datagrams (sandbox blocks sendto); datagram round-trip skipped, ASSOCIATE handshake above still ran");
    } else {
    // One datagram to an IPv4 target: SOCKS UDP header + payload.
    // The mock echoes the payload back through the tunnel.
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut dgram = vec![0, 0, 0, 0x01, 127, 0, 0, 1];
    dgram.extend_from_slice(&80u16.to_be_bytes());
    dgram.extend_from_slice(b"UDP-ECHO-HELLO");
    udp.send_to(&dgram, (relay_ip, relay_port)).await.unwrap();
    let mut buf = [0u8; 2048];
    let (n, _from) = tokio::time::timeout(timeout, udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let back = &buf[..n];
    // Reply header: RSV 0, FRAG 0, ATYP 1, source 127.0.0.1:80.
    assert!(n >= 10, "UDP reply too short: {:?}", back);
    assert_eq!(&back[..4], &[0, 0, 0, 0x01], "reply header: {:?}", back);
    assert_eq!(&back[4..8], &[127, 0, 0, 1], "reply source IP: {:?}", back);
    assert_eq!(
        u16::from_be_bytes([back[8], back[9]]),
        80,
        "reply source port"
    );
    assert_eq!(
        &back[10..],
        b"UDP-ECHO-HELLO",
        "payload must echo byte-for-byte"
    );

    // A domain target goes through DoH resolution, then the same echo.
    let mut dgram = vec![0, 0, 0, 0x03, 11];
    dgram.extend_from_slice(b"example.com");
    dgram.extend_from_slice(&80u16.to_be_bytes());
    dgram.extend_from_slice(b"UDP-ECHO-DOMAIN");
    udp.send_to(&dgram, (relay_ip, relay_port)).await.unwrap();
    let (n, _) = tokio::time::timeout(timeout, udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &buf[10..n],
        b"UDP-ECHO-DOMAIN",
        "domain-target payload must echo"
    );

    // A fragmented datagram (FRAG 1) is dropped, never answered.
    let mut dgram = vec![0, 0, 1, 0x01, 127, 0, 0, 1];
    dgram.extend_from_slice(&80u16.to_be_bytes());
    dgram.extend_from_slice(b"FRAG-DROPPED");
    udp.send_to(&dgram, (relay_ip, relay_port)).await.unwrap();
    let res = tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut buf)).await;
    assert!(
        res.is_err(),
        "a fragmented datagram must get no reply, got: {:?}",
        res
    );
    }

    // The connection log names the UDP ASSOCIATE line.
    drop(c); // close the ASSOCIATE TCP connection
    let mut lines = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), log_rx.recv()).await {
            Ok(Some(line)) => lines.push(line),
            _ => break,
        }
    }
    assert!(
        lines.iter().any(|l| l.contains("UDP ASSOCIATE")),
        "the log must carry a UDP ASSOCIATE line, got: {:?}",
        lines
    );

    serve.abort();
    drop(tunnel);
}

/// Tunnel-level UDP: a `UdpFlow` through the mock tunnel, echoed by
/// the mock's UDP mode. This needs no real UDP socket at all (the
/// datagrams travel inside the SSTP stream), so it runs even where
/// the sandbox blocks UDP — it proves the frame builder, the IP
/// demuxer, and the flow table end to end.
#[tokio::test]
async fn udp_flow_echo_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let timeout = Duration::from_secs(10);

    // One flow, two datagrams: both echo back with the target as
    // their source (127.0.0.1:80), as a real NAT would.
    let mut flow = tunnel
        .open_udp_flow("127.0.0.1", 80)
        .await
        .expect("open UDP flow to the mock");
    flow.send(b"UDP-FLOW-ONE").unwrap();
    let (ip, port, payload) = tokio::time::timeout(timeout, flow.recv())
        .await
        .unwrap()
        .expect("first UDP echo must arrive");
    assert_eq!(ip.to_string(), "127.0.0.1");
    assert_eq!(port, 80);
    assert_eq!(payload, b"UDP-FLOW-ONE");
    flow.send(b"UDP-FLOW-TWO").unwrap();
    let (ip, port, payload) = tokio::time::timeout(timeout, flow.recv())
        .await
        .unwrap()
        .expect("second UDP echo must arrive");
    assert_eq!(ip.to_string(), "127.0.0.1");
    assert_eq!(port, 80);
    assert_eq!(payload, b"UDP-FLOW-TWO");

    // A domain target resolves (DoH) and echoes the same way.
    let mut flow2 = tunnel
        .open_udp_flow("example.com", 80)
        .await
        .expect("open UDP flow to a domain");
    flow2.send(b"UDP-FLOW-DOMAIN").unwrap();
    let (_ip, port, payload) = tokio::time::timeout(timeout, flow2.recv())
        .await
        .unwrap()
        .expect("domain UDP echo must arrive");
    assert_eq!(port, 80);
    assert_eq!(payload, b"UDP-FLOW-DOMAIN");

    // An oversize datagram is refused, not fragmented.
    let big = vec![0u8; 2000];
    assert!(
        flow.send(&big).is_err(),
        "a 2000-byte datagram must not fit the tunnel MTU"
    );

    drop(tunnel);
}

/// True when this machine can actually send a UDP datagram (bind +
/// sendto to loopback). This VM's sandbox blocks UDP sendto with
/// EPERM even to 127.0.0.1, so the full ASSOCIATE test skips here
/// instead of failing on the sandbox — same pattern as the
/// python3/openssl skips above.
async fn udp_available() -> bool {
    let Ok(s) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    let addr = match s.local_addr() {
        Ok(a) => a,
        Err(_) => return false,
    };
    s.send_to(b"probe", addr).await.is_ok()
}

// --- v3.14 ------------------------------------------------------------

/// v3.14, diagnosis §3 item 1: a stream opened through the mock
/// tunnel registers one session, and dropping the stream removes
/// it — the end-to-end form of the lib unit test, over a real
/// (mock) SSTP tunnel. Pre-fix this failed: normal-close sessions
/// were only removed when the whole tunnel dropped, so the count
/// stayed 1 after the drop.
#[tokio::test]
async fn tunnel_stream_drop_removes_session_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let timeout = Duration::from_secs(10);
    assert_eq!(tunnel.session_count(), 0, "no sessions before opening");
    let s = tunnel
        .open_stream("www.gstatic.com", 80, timeout)
        .await
        .expect("open stream through the mock tunnel");
    assert_eq!(tunnel.session_count(), 1, "one live session while open");
    drop(s);
    assert_eq!(
        tunnel.session_count(),
        0,
        "dropping the stream must remove its session immediately"
    );
}

/// v3.14, diagnosis §3 item 2: the mixed server's accepted
/// connections belong to its JoinSet, so aborting the server (what
/// `disconnect()` does) closes even a connection that never sent
/// a byte and would otherwise sit stalled forever. Pre-fix this
/// failed: the accepted task was a detached `tokio::spawn`, the
/// abort left it alive, and the client read timed out instead of
/// returning EOF.
#[tokio::test]
async fn disconnect_aborts_stalled_connection_against_mock() {
    let Some((_guard, _mock, tunnel)) = setup_mock_tunnel().await else {
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve = tokio::spawn(vpngate_client::socks5::serve_mixed(
        listener,
        tunnel.clone(),
        Duration::from_secs(10),
        None,
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A client that connects and then never sends anything —
    // the worst case for the old code: no byte, no timeout, the
    // handler blocks in its first read forever.
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    serve.abort();
    let mut buf = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
    assert!(
        matches!(res, Ok(Ok(0))),
        "aborting the mixed server must close stalled connections (EOF), got {:?}",
        res
    );
    drop(tunnel);
}
