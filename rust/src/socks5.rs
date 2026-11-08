//! SOCKS5, both directions, plus the mixed local proxy:
//! * **Client** (`socks5_connect`): used when a front SOCKS5 proxy is
//!   configured — the TCP connection to the VPNGate node (and to
//!   vpngate.net / DoH) goes through it.
//! * **Server** (`serve_mixed`): after the tunnel is up, a local
//!   proxy listener (default 127.0.0.1:10818) that sniffs the first
//!   byte of each connection — 0x05 goes to the SOCKS5 handler, an
//!   ASCII letter goes to the HTTP proxy handler, anything else is
//!   closed silently. Both forward through the tunnel as their own
//!   userspace TCP sessions, so one port serves SOCKS5 and HTTP
//!   (NekoBox-style "Mixed (SOCKS+HTTP)") and LAN sharing needs no
//!   second port.
//! * **UDP relay** (v3.9, `UdpRelay`): the same port number on UDP
//!   serves SOCKS5 UDP ASSOCIATE (RFC 1928). Datagrams from a client
//!   are stripped of their SOCKS UDP header and sent through the
//!   tunnel as UDP flows (`SstpTunnel::open_udp_flow`); replies come
//!   back the same way. This is what makes a phone behind v2rayNG
//!   browse: its DNS lookups and QUIC are UDP, and a TCP-only proxy
//!   drops them silently. HTTP has no UDP, so only SOCKS5 gets it.
//!   TCP and UDP port numbers do not collide, so one port number
//!   serves both.
//!
//! The HTTP proxy supports CONNECT (tunnel mode: 200, then raw bytes
//! both ways — HTTPS goes this way) and plain HTTP requests in
//! absolute form (`GET http://host:port/path ...`) or origin form
//! with a Host header (rewritten to origin-form and forwarded; the
//! response is streamed back and the connection closed — no
//! keep-alive reuse). No HTTP authentication: `Proxy-Authorization`
//! is ignored. The tunnel is IPv4-only, so IPv6 targets are refused,
//! same as the SOCKS5 path.
//!
//! Every accepted connection is logged once (`ConnLog`): source
//! address (127.0.0.1 vs a LAN address), sniffed protocol, and the
//! CONNECT / SOCKS5 target host — never a path, a body, or
//! credentials — plus a failure line when the connection dies. The
//! GUI feeds these lines into its log panel + `vpngate-gui.log`, so
//! a LAN device that cannot reach the proxy leaves no line at all
//! (blocked before us, e.g. by the Windows firewall), while a
//! connection that arrives but fails names the step it died on.

use crate::sstp::{SstpTunnel, UdpFlow};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

/// Connect to `host:port` through a SOCKS5 proxy at `proxy_addr`.
/// Supports no-auth and username/password auth.
pub async fn socks5_connect(
    proxy_addr: &str,
    host: &str,
    port: u16,
    username: Option<&str>,
    password: Option<&str>,
) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy_addr).await?;
    if let (Some(u), Some(p)) = (username, password) {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        if resp != [0x05, 0x02] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "SOCKS5 proxy rejected username/password auth",
            ));
        }
        let mut auth = vec![0x01, u.len() as u8];
        auth.extend_from_slice(u.as_bytes());
        auth.push(p.len() as u8);
        auth.extend_from_slice(p.as_bytes());
        s.write_all(&auth).await?;
        let mut aresp = [0u8; 2];
        s.read_exact(&mut aresp).await?;
        if aresp != [0x01, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy authentication failed",
            ));
        }
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        if resp != [0x05, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "SOCKS5 proxy rejected no-auth",
            ));
        }
    }
    // CONNECT, address type 3 (domain).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 proxy CONNECT failed, reply code {:#04x}", hdr[1]),
        ));
    }
    let skip = match hdr[3] {
        0x01 => 4,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        0x04 => 16,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad SOCKS5 reply address type",
            ));
        }
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

/// Serve the local mixed proxy (SOCKS5 + HTTP) on `listener`,
/// forwarding connections through `tunnel`. Runs until the listener
/// errors or the task is aborted. Each connection gets its own
/// userspace TCP session.
/// Where per-connection lines from the mixed proxy go. The GUI
/// passes a sender that feeds its log panel + file log
/// (`GuiEvent::ConnLog`); `None` logs to stderr (the CLI). One line
/// per accepted connection — source address, sniffed protocol, and
/// the CONNECT / SOCKS5 target host — plus a second line only when
/// the connection fails, carrying the reason. Never a path, a body,
/// or credentials: a CONNECT line names the host, nothing else.
///
/// v3.14 (diagnosis §4.2): BOUNDED (512 lines). The old unbounded
/// channel could pile log lines up while the UI frame was stalled —
/// the producer (one line per accepted connection) never blocks,
/// but a stalled consumer lets the queue grow without limit. A log
/// line is droppable by design (the on-screen log only keeps 100
/// lines anyway): when the channel is full the line is dropped and
/// `CONN_LOG_DROPPED` counts it, so a burst is visible in the RSS
/// log instead of silently eating memory.
pub type ConnLog = tokio::sync::mpsc::Sender<String>;

/// Capacity of the `ConnLog` channel (see above).
pub const CONN_LOG_CAPACITY: usize = 512;

/// Log lines dropped because the `ConnLog` channel was full (or its
/// receiver was gone). Read by the GUI's RSS log line; a rising
/// count under load is expected behaviour, not a bug.
pub static CONN_LOG_DROPPED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// How many `ConnLog` lines have been dropped so far.
pub fn conn_log_dropped() -> usize {
    CONN_LOG_DROPPED.load(std::sync::atomic::Ordering::Relaxed)
}

fn emit_conn_log(sink: &Option<ConnLog>, line: String) {
    match sink {
        Some(tx) => {
            if tx.try_send(line).is_err() {
                CONN_LOG_DROPPED
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        None => eprintln!("{}", line),
    }
}

fn peer_of(socket: &TcpStream) -> String {
    socket
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string())
}

pub async fn serve_mixed(
    listener: TcpListener,
    tunnel: Arc<SstpTunnel>,
    timeout: Duration,
    conn_log: Option<ConnLog>,
) {
    println!(
        "混合代理（SOCKS5+HTTP）listening on {}",
        listener.local_addr().unwrap()
    );
    println!("Configure your apps / browser to use this proxy (SOCKS5 or HTTP). Ctrl-C to stop.");
    // UDP relay on the same address (same port number) as the TCP
    // listener — TCP and UDP port numbers do not collide. When the
    // UDP bind fails (the port is already taken by another program's
    // UDP socket), the TCP proxy keeps working and UDP ASSOCIATE is
    // refused with a clear error; nothing else changes.
    let udp_socket: Option<Arc<UdpSocket>> = match listener.local_addr() {
        Ok(a) => match UdpSocket::bind(a).await {
            Ok(s) => {
                println!("UDP 中继（SOCKS5 UDP ASSOCIATE）listening on {} (UDP)", a);
                Some(Arc::new(s))
            }
            Err(e) => {
                eprintln!(
                    "UDP 中继绑定 {} 失败：{}（UDP 不可用，SOCKS5 UDP ASSOCIATE 会被拒绝；TCP 代理不受影响）",
                    a, e
                );
                None
            }
        },
        Err(_) => None,
    };
    let relay: Option<Arc<UdpRelay>> = udp_socket.as_ref().map(|s| {
        Arc::new(UdpRelay::new(
            tunnel.clone(),
            s.clone(),
            conn_log.clone(),
        ))
    });
    // Reply-forwarding tasks live in this JoinSet, owned by this
    // task's stack: aborting the mixed server (disconnect) drops the
    // set, which aborts every forwarder and frees the UDP socket —
    // no leaked relay, no leaked port.
    let mut forwarders: JoinSet<()> = JoinSet::new();
    // Accepted TCP connections live in this JoinSet too (v3.14,
    // diagnosis §4.1): each accepted connection used to be a
    // detached `tokio::spawn` whose handle was thrown away, so
    // aborting the mixed server did NOT stop them — a stalled
    // long-lived connection kept its `Arc<SstpTunnel>` alive and
    // "disconnect" never released the tunnel. JoinSet-owned tasks
    // are aborted when this set is dropped, i.e. when the mixed
    // server itself is aborted on disconnect. (A connection that is
    // mid-transfer when the user disconnects is cut immediately —
    // that is what disconnect means.)
    let mut conns: JoinSet<()> = JoinSet::new();
    let mut sweep = tokio::time::interval(UDP_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            res = listener.accept() => {
                let (socket, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("mixed proxy accept error: {}", e);
                        continue;
                    }
                };
                let t = tunnel.clone();
                let log = conn_log.clone();
                let relay_addr = relay.as_ref().map(|r| r.socket_addr());
                let relay_for_assoc = relay.clone();
                conns.spawn(async move {
                    if let Err(e) =
                        handle_mixed_conn(socket, t, timeout, &log, relay_addr, relay_for_assoc).await
                    {
                        emit_conn_log(&log, format!("混合代理连接 {} 失败：{}", peer, e));
                    }
                });
            }
            datagram = recv_udp_datagram(&udp_socket) => {
                let (data, src) = datagram;
                if let Some(r) = &relay {
                    r.handle_datagram(&mut forwarders, src, &data).await;
                }
            }
            _ = sweep.tick() => {
                if let Some(r) = &relay {
                    let n = r.sweep_idle();
                    if n > 0 {
                        emit_conn_log(&conn_log, format!("UDP 中继：清理 {} 条空闲超时的流", n));
                    }
                }
            }
            Some(_done) = forwarders.join_next(), if !forwarders.is_empty() => {
                // Reap a finished reply-forwarder (its flow closed).
            }
            Some(_done) = conns.join_next(), if !conns.is_empty() => {
                // Reap a finished accepted connection.
            }
        }
    }
}

/// Receive one datagram from the relay socket; parks forever when
/// there is no relay (UDP bind failed) or the socket errors, so the
/// select loop never spins.
async fn recv_udp_datagram(socket: &Option<Arc<UdpSocket>>) -> (Vec<u8>, SocketAddr) {
    match socket {
        Some(s) => {
            let mut buf = [0u8; UDP_RELAY_BUF];
            match s.recv_from(&mut buf).await {
                Ok((n, src)) => (buf[..n].to_vec(), src),
                Err(_) => std::future::pending().await,
            }
        }
        None => std::future::pending().await,
    }
}

/// What the first byte of a local-proxy connection means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstByte {
    /// 0x05: a SOCKS5 greeting.
    Socks5,
    /// An ASCII letter: an HTTP request line (CONNECT, GET, ...).
    Http,
    /// Anything else: not a protocol we serve; close silently.
    Unknown,
}

/// Classify the first byte of a connection to the local proxy.
fn classify_first_byte(b: u8) -> FirstByte {
    if b == 0x05 {
        FirstByte::Socks5
    } else if b.is_ascii_alphabetic() {
        FirstByte::Http
    } else {
        FirstByte::Unknown
    }
}

/// One accepted connection: sniff the first byte (`peek`, so the
/// chosen handler still sees the whole stream) and dispatch.
/// `relay_addr` is the UDP relay's address for SOCKS5 UDP ASSOCIATE
/// replies (None when the UDP bind failed); `relay` is the shared
/// relay state for per-client cleanup when an ASSOCIATE connection
/// closes.
async fn handle_mixed_conn(
    local: TcpStream,
    tunnel: Arc<SstpTunnel>,
    timeout: Duration,
    conn_log: &Option<ConnLog>,
    relay_addr: Option<SocketAddr>,
    relay: Option<Arc<UdpRelay>>,
) -> Result<(), String> {
    let peer = peer_of(&local);
    let mut first = [0u8; 1];
    let n = local.peek(&mut first).await.map_err(|e| e.to_string())?;
    if n == 0 {
        emit_conn_log(
            conn_log,
            format!("混合代理连接 {}：未发送数据，已关闭", peer),
        );
        return Ok(()); // client closed immediately
    }
    match classify_first_byte(first[0]) {
        FirstByte::Socks5 => {
            handle_socks5_conn(local, tunnel, timeout, conn_log, relay_addr, relay).await
        }
        FirstByte::Http => handle_http_conn(local, tunnel, timeout, conn_log).await,
        FirstByte::Unknown => {
            emit_conn_log(
                conn_log,
                format!(
                    "混合代理连接 {}：未知协议（首字节 0x{:02x}），已关闭",
                    peer, first[0]
                ),
            );
            Ok(())
        }
    }
}

async fn handle_socks5_conn(
    mut local: TcpStream,
    tunnel: Arc<SstpTunnel>,
    timeout: Duration,
    conn_log: &Option<ConnLog>,
    relay_addr: Option<SocketAddr>,
    relay: Option<Arc<UdpRelay>>,
) -> Result<(), String> {
    // Greeting.
    let mut hdr = [0u8; 2];
    local
        .read_exact(&mut hdr)
        .await
        .map_err(|e| e.to_string())?;
    if hdr[0] != 0x05 {
        return Err("not a SOCKS5 client".to_string());
    }
    let n = hdr[1] as usize;
    let mut methods = vec![0u8; n];
    local
        .read_exact(&mut methods)
        .await
        .map_err(|e| e.to_string())?;
    if !methods.contains(&0x00) {
        local
            .write_all(&[0x05, 0xFF])
            .await
            .map_err(|e| e.to_string())?;
        return Err("SOCKS5 client offered no no-auth method".to_string());
    }
    local
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    // Request.
    let mut rhdr = [0u8; 4];
    local
        .read_exact(&mut rhdr)
        .await
        .map_err(|e| e.to_string())?;
    if rhdr[0] != 0x05 {
        let _ = local
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("not a SOCKS5 client".to_string());
    }
    let (host, port) = match rhdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            local.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            (
                format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
                u16::from_be_bytes([b[4], b[5]]),
            )
        }
        0x03 => {
            let mut l = [0u8; 1];
            local.read_exact(&mut l).await.map_err(|e| e.to_string())?;
            let mut b = vec![0u8; l[0] as usize + 2];
            local.read_exact(&mut b).await.map_err(|e| e.to_string())?;
            let name = String::from_utf8_lossy(&b[..l[0] as usize]).to_string();
            let p = u16::from_be_bytes([b[l[0] as usize], b[l[0] as usize + 1]]);
            (name, p)
        }
        0x04 => {
            let _ = local
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err("IPv6 targets are not supported by the tunnel (IPv4 only)".to_string());
        }
        t => {
            let _ = local
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(format!("unsupported SOCKS5 address type {}", t));
        }
    };
    match rhdr[1] {
        0x03 => {
            // UDP ASSOCIATE: the address just parsed is the client's
            // "expected" address (usually 0.0.0.0:0) and is ignored —
            // datagrams are keyed by their actual source instead.
            return handle_socks5_udp_associate(local, relay_addr, relay, conn_log).await;
        }
        0x01 => {} // CONNECT: fall through to the body below.
        cmd => {
            let _ = local
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(format!("unsupported SOCKS5 command {}", cmd));
        }
    }
    emit_conn_log(
        conn_log,
        format!(
            "混合代理连接 {}：SOCKS5 → {}:{}",
            peer_of(&local),
            host,
            port
        ),
    );
    if tunnel.is_dead() {
        let _ = local
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("tunnel is dead".to_string());
    }
    let mut remote = match tunnel.open_stream(&host, port, timeout).await {
        Ok(s) => s,
        Err(e) => {
            let _ = local
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(format!("tunnel TCP to {}:{} failed: {}", host, port, e));
        }
    };
    local
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| e.to_string())?;
    let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// SOCKS5 UDP relay (UDP ASSOCIATE, RFC 1928) — v3.9
// ---------------------------------------------------------------------------

/// Max UDP datagram (including the SOCKS header) we read from a client.
const UDP_RELAY_BUF: usize = 2048;
/// Max payload bytes in one tunnelled UDP datagram (1500-byte PPP MRU
/// minus the 20-byte IP and 8-byte UDP headers). Larger payloads are
/// dropped, never fragmented.
const UDP_RELAY_MAX_PAYLOAD: usize = 1472;
/// Max concurrent UDP flows through one relay.
const UDP_RELAY_MAX_FLOWS: usize = 1024;
/// A flow with no traffic for this long is dropped.
const UDP_FLOW_IDLE: Duration = Duration::from_secs(60);
/// How often the relay sweeps idle flows.
const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Parse a SOCKS5 UDP datagram (RFC 1928): RSV(2) FRAG(1) ATYP(1)
/// ADDR PORT(2) DATA. Returns (frag, host, port, payload) — host is
/// a dotted IPv4 string for ATYP 1, a domain for ATYP 3. None when
/// malformed (short, non-zero RSV, IPv6, unknown ATYP).
fn parse_socks_udp(data: &[u8]) -> Option<(u8, String, u16, &[u8])> {
    if data.len() < 4 || data[0] != 0 || data[1] != 0 {
        return None;
    }
    let frag = data[2];
    match data[3] {
        0x01 => {
            if data.len() < 10 {
                return None;
            }
            let host = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            let port = u16::from_be_bytes([data[8], data[9]]);
            Some((frag, host, port, &data[10..]))
        }
        0x03 => {
            let n = data[4] as usize;
            if data.len() < 5 + n + 2 {
                return None;
            }
            let host = String::from_utf8_lossy(&data[5..5 + n]).into_owned();
            let port = u16::from_be_bytes([data[5 + n], data[5 + n + 1]]);
            Some((frag, host, port, &data[5 + n + 2..]))
        }
        _ => None, // IPv6 (0x04) and anything else: unsupported
    }
}

/// Build a SOCKS5 UDP datagram reply: RSV 0, FRAG 0, ATYP 1 with the
/// packet's source address, then the payload.
fn build_socks_udp(src_ip: Ipv4Addr, src_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len());
    out.extend_from_slice(&[0, 0, 0, 0x01]);
    out.extend_from_slice(&src_ip.octets());
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// One UDP flow, keyed by the client's UDP socket address and the
/// target as asked (host string, so a domain target resolves once
/// per flow instead of once per datagram). The client's TCP
/// ASSOCIATE connection may use a different port, so the key is the
/// datagram source, not the TCP peer.
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct UdpFlowKey {
    client: SocketAddr,
    host: String,
    port: u16,
}

struct UdpFlowEntry {
    key: UdpFlowKey,
    /// Source port of the tunnel flow (replies are demuxed on it).
    src_port: u16,
    /// Resolved destination (for `send_udp`).
    dst_ip: Ipv4Addr,
    dst_port: u16,
    /// "host:port" as the client asked, for the log line.
    dst_display: String,
    last_active: std::sync::Mutex<Instant>,
}

impl UdpFlowEntry {
    fn new(key: UdpFlowKey, src_port: u16, dst: (Ipv4Addr, u16), dst_display: String) -> Self {
        Self {
            key,
            src_port,
            dst_ip: dst.0,
            dst_port: dst.1,
            dst_display,
            last_active: std::sync::Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        if let Ok(mut g) = self.last_active.lock() {
            *g = Instant::now();
        }
    }

    fn last_active(&self) -> Instant {
        self.last_active
            .lock()
            .map(|g| *g)
            .unwrap_or_else(|_| Instant::now())
    }

    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_active())
    }
}

/// The UDP flow table: bounded, with idle expiry. Pure bookkeeping —
/// no tunnel, no sockets — so it is unit-testable on its own. The
/// relay owns one behind a mutex; the tunnel flows themselves are
/// closed by the relay, not by the table.
struct UdpFlowTable {
    flows: HashMap<UdpFlowKey, Arc<UdpFlowEntry>>,
    max_flows: usize,
}

impl UdpFlowTable {
    fn new(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
        }
    }

    fn get(&self, key: &UdpFlowKey) -> Option<Arc<UdpFlowEntry>> {
        self.flows.get(key).cloned()
    }

    fn insert(&mut self, entry: Arc<UdpFlowEntry>) {
        self.flows.insert(entry.key.clone(), entry);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.flows.len()
    }

    /// Remove `entry` only if it is still the entry stored under its
    /// key (a newer flow for the same key must survive).
    fn remove_if_same(&mut self, entry: &Arc<UdpFlowEntry>) {
        if let Some(cur) = self.flows.get(&entry.key) {
            if Arc::ptr_eq(cur, entry) {
                self.flows.remove(&entry.key);
            }
        }
    }

    /// Drop every flow from one client IP (ASSOCIATE TCP close).
    /// Returns the dropped entries so the caller can close their
    /// tunnel flows.
    fn remove_client(&mut self, ip: IpAddr) -> Vec<Arc<UdpFlowEntry>> {
        let keys: Vec<UdpFlowKey> = self
            .flows
            .keys()
            .filter(|k| k.client.ip() == ip)
            .cloned()
            .collect();
        keys.iter()
            .filter_map(|k| self.flows.remove(k))
            .collect()
    }

    /// When the table is full, evict the least-recently-active flow
    /// so a new one can be created (bounded memory under a flood).
    /// Returns the evicted entry so the caller can close its tunnel
    /// flow. None when there is room.
    fn evict_oldest_if_full(&mut self) -> Option<Arc<UdpFlowEntry>> {
        if self.flows.len() < self.max_flows {
            return None;
        }
        let oldest = self
            .flows
            .values()
            .min_by_key(|e| e.last_active())
            .cloned()?;
        self.flows.remove(&oldest.key);
        Some(oldest)
    }

    /// Drop flows idle longer than `idle`. Returns the dropped
    /// entries so the caller can close their tunnel flows.
    fn sweep_idle(&mut self, now: Instant, idle: Duration) -> Vec<Arc<UdpFlowEntry>> {
        let keys: Vec<UdpFlowKey> = self
            .flows
            .iter()
            .filter(|(_, e)| e.idle_for(now) > idle)
            .map(|(k, _)| k.clone())
            .collect();
        keys.iter()
            .filter_map(|k| self.flows.remove(k))
            .collect()
    }
}

/// The UDP relay shared by one mixed-proxy listener: one UDP socket
/// bound to the same port as the TCP listener, a flow table, and the
/// tunnel. Datagrams are handled inline in `serve_mixed`'s select
/// loop; replies are forwarded by per-flow tasks owned by that same
/// loop's JoinSet, so aborting the mixed server (disconnect) aborts
/// the relay and its forwarders too — no leaked UDP socket.
struct UdpRelay {
    tunnel: Arc<SstpTunnel>,
    socket: Arc<UdpSocket>,
    flows: std::sync::Mutex<UdpFlowTable>,
    conn_log: Option<ConnLog>,
}

impl UdpRelay {
    fn new(tunnel: Arc<SstpTunnel>, socket: Arc<UdpSocket>, conn_log: Option<ConnLog>) -> Self {
        Self {
            tunnel,
            socket,
            flows: std::sync::Mutex::new(UdpFlowTable::new(UDP_RELAY_MAX_FLOWS)),
            conn_log,
        }
    }

    fn socket_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap())
    }

    /// Handle one datagram received on the relay socket: parse the
    /// SOCKS UDP header, find or open the tunnel flow for
    /// (client, target), and send the payload through the tunnel.
    /// `forwarders` is the JoinSet the reply-forwarding task is
    /// spawned into (owned by `serve_mixed`, so it dies with it).
    /// Malformed datagrams, fragmented ones (FRAG > 0, unsupported)
    /// and oversize payloads are dropped silently — UDP is lossy
    /// anyway, and answering garbage would only help a scanner.
    async fn handle_datagram(
        self: &Arc<Self>,
        forwarders: &mut JoinSet<()>,
        src: SocketAddr,
        data: &[u8],
    ) {
        let Some((frag, host, port, payload)) = parse_socks_udp(data) else {
            return;
        };
        if frag != 0 {
            return;
        }
        if payload.len() > UDP_RELAY_MAX_PAYLOAD {
            return;
        }
        let key = UdpFlowKey {
            client: src,
            host: host.clone(),
            port,
        };
        let entry = {
            let table = self.flows.lock().unwrap();
            table.get(&key)
        };
        let entry = match entry {
            Some(e) => e,
            None => {
                if self.tunnel.is_dead() {
                    return;
                }
                if let Some(old) = {
                    let mut table = self.flows.lock().unwrap();
                    table.evict_oldest_if_full()
                } {
                    self.tunnel.close_udp_flow(old.src_port);
                }
                let flow = match self.tunnel.open_udp_flow(&host, port).await {
                    Ok(f) => f,
                    Err(e) => {
                        emit_conn_log(
                            &self.conn_log,
                            format!(
                                "混合代理 UDP {}：打通 {}:{} 失败：{}",
                                src, host, port, e
                            ),
                        );
                        return;
                    }
                };
                let entry = Arc::new(UdpFlowEntry::new(
                    key.clone(),
                    flow.src_port(),
                    flow.dst(),
                    format!("{}:{}", host, port),
                ));
                {
                    let mut table = self.flows.lock().unwrap();
                    table.insert(entry.clone());
                }
                forwarders.spawn(udp_reply_forwarder(self.clone(), entry.clone(), flow));
                // One line per flow, not per datagram (DNS does
                // dozens a second): source, target host:port, and
                // the first packet's byte count. Never any content.
                emit_conn_log(
                    &self.conn_log,
                    format!(
                        "混合代理 UDP {}：新建流 → {}（首包 {} 字节）",
                        src,
                        entry.dst_display,
                        payload.len()
                    ),
                );
                entry
            }
        };
        entry.touch();
        if self
            .tunnel
            .send_udp(entry.src_port, entry.dst_ip, entry.dst_port, payload)
            .is_err()
        {
            // The flow went away between lookup and send (swept, or
            // the tunnel died): drop the entry so the next datagram
            // opens a fresh flow instead of black-holing.
            self.tunnel.close_udp_flow(entry.src_port);
            let mut table = self.flows.lock().unwrap();
            table.remove_if_same(&entry);
        }
    }

    /// Drop flows idle longer than `UDP_FLOW_IDLE`: close the tunnel
    /// flow (the forwarder's recv then returns None and it exits)
    /// and remove the entry. Returns how many were dropped.
    fn sweep_idle(&self) -> usize {
        let expired = {
            let mut table = self.flows.lock().unwrap();
            table.sweep_idle(Instant::now(), UDP_FLOW_IDLE)
        };
        for e in &expired {
            self.tunnel.close_udp_flow(e.src_port);
        }
        expired.len()
    }

    /// Remove `entry` only if it is still the entry stored under its
    /// key (a newer flow for the same key must survive).
    fn remove_if_same(&self, entry: &Arc<UdpFlowEntry>) {
        let mut table = self.flows.lock().unwrap();
        table.remove_if_same(entry);
    }

    /// Drop every flow from one client IP (called when its UDP
    /// ASSOCIATE TCP connection closes). The 60 s idle sweep is the
    /// backstop for clients that never close cleanly.
    fn remove_client_flows(&self, client_ip: IpAddr) {
        let victims = {
            let mut table = self.flows.lock().unwrap();
            table.remove_client(client_ip)
        };
        for e in &victims {
            self.tunnel.close_udp_flow(e.src_port);
        }
    }
}

/// One flow's reply pump: tunnel replies → SOCKS UDP datagrams back
/// to the client. Ends when the tunnel flow closes (idle sweep,
/// client disconnect, or tunnel death); the entry is removed from
/// the table on exit (only if it is still the same entry).
async fn udp_reply_forwarder(relay: Arc<UdpRelay>, entry: Arc<UdpFlowEntry>, mut flow: UdpFlow) {
    let client = entry.key.client;
    loop {
        match flow.recv().await {
            Some((src_ip, src_port, payload)) => {
                entry.touch();
                let reply = build_socks_udp(src_ip, src_port, &payload);
                if relay.socket.send_to(&reply, client).await.is_err() {
                    break;
                }
            }
            None => break, // flow closed (sweep / tunnel death)
        }
    }
    relay.remove_if_same(&entry);
    // Dropping `flow` removes it from the tunnel's udp_flows table.
}

/// SOCKS5 UDP ASSOCIATE (RFC 1928): reply with the relay's UDP
/// address, then hold the TCP connection open — the association
/// lives as long as this connection. When it closes, drop this
/// client's flows (the 60 s idle sweep is the backstop).
async fn handle_socks5_udp_associate(
    mut local: TcpStream,
    relay_addr: Option<SocketAddr>,
    relay: Option<Arc<UdpRelay>>,
    conn_log: &Option<ConnLog>,
) -> Result<(), String> {
    let Some(relay_addr) = relay_addr else {
        let _ = local
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        return Err("SOCKS5 UDP ASSOCIATE 被拒绝：UDP 中继不可用".to_string());
    };
    let peer_ip = local.peer_addr().map(|a| a.ip()).ok();
    // If the relay is bound to 0.0.0.0, the client needs the concrete
    // IP it connected to (a 0.0.0.0 reply address is unusable).
    let reply_ip = if relay_addr.ip().is_unspecified() {
        local
            .local_addr()
            .map(|a| a.ip())
            .unwrap_or(relay_addr.ip())
    } else {
        relay_addr.ip()
    };
    let mut rep = vec![0x05, 0x00, 0x00, 0x01];
    match reply_ip {
        IpAddr::V4(v4) => rep.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => {
            // Our binds are IPv4-only; this cannot happen, but refuse
            // cleanly rather than sending a malformed reply.
            let _ = local
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err("SOCKS5 UDP ASSOCIATE 被拒绝：中继地址不是 IPv4".to_string());
        }
    }
    rep.extend_from_slice(&relay_addr.port().to_be_bytes());
    local.write_all(&rep).await.map_err(|e| e.to_string())?;
    emit_conn_log(
        conn_log,
        format!(
            "混合代理连接 {}：SOCKS5 UDP ASSOCIATE → 中继 {}:{}",
            peer_of(&local),
            reply_ip,
            relay_addr.port()
        ),
    );
    // Hold the association open until the client closes the TCP
    // connection; ASSOCIATE carries no TCP data.
    let mut buf = [0u8; 512];
    loop {
        match local.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    if let (Some(r), Some(ip)) = (relay, peer_ip) {
        r.remove_client_flows(ip);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP proxy (one half of the mixed local server)
// ---------------------------------------------------------------------------

/// Max HTTP header block we will read (64 KiB); larger → close.
/// Max request body we will forward (64 MiB); larger → 413/close.
const HTTP_MAX_HEADERS: usize = 64 * 1024;
const HTTP_MAX_BODY: usize = 64 * 1024 * 1024;

/// Split an HTTP request line into (method, request-uri). `None`
/// when the line is not `METHOD SP URI SP HTTP/x.y`.
fn parse_http_request_line(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let uri = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return None;
    }
    Some((method.to_string(), uri.to_string()))
}

/// Parse `host`, `host:port`, or `user@host:port` (userinfo stripped).
/// IPv6 literals are refused — the tunnel is IPv4-only, same as the
/// SOCKS5 path. Returns None on garbage.
fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() || authority.starts_with('[') {
        return None;
    }
    // A bare host or host:port has at most one ':'.
    if authority.matches(':').count() > 1 {
        return None;
    }
    match authority.split_once(':') {
        Some((host, p)) => {
            if host.is_empty() {
                return None;
            }
            Some((host.to_string(), p.parse::<u16>().ok()?))
        }
        None => Some((authority.to_string(), default_port)),
    }
}

/// Resolve an HTTP proxy target to (host, port):
/// * CONNECT → the authority itself (default port 443).
/// * Absolute-form `http://host[:port]/...` → that host (default 80).
/// * Origin-form (`/path...`) → the Host header (default 80).
/// Anything else (other schemes, missing Host) → None.
fn http_target(method: &str, uri: &str, host_header: Option<&str>) -> Option<(String, u16)> {
    if method.eq_ignore_ascii_case("CONNECT") {
        return parse_authority(uri, 443);
    }
    if let Some(rest) = uri.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or("");
        return parse_authority(authority, 80);
    }
    if uri.starts_with('/') {
        let authority = host_header?;
        return parse_authority(authority, 80);
    }
    None
}

/// Origin-form path for a forwarded request: absolute-form
/// `http://host[:port]/path...` → `/path...` ("/" when empty);
/// origin-form URIs pass through unchanged.
fn origin_form_path(uri: &str) -> String {
    if let Some(rest) = uri.strip_prefix("http://") {
        match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".to_string(),
        }
    } else {
        uri.to_string()
    }
}

/// Parsed HTTP request head: the request line plus (name, value)
/// pairs (names lowercased for matching, values trimmed).
struct HttpRequestHead {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
}

impl HttpRequestHead {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse a header block (request line + `Name: value` lines) into a
/// head. `None` on a malformed request line or a header line without
/// a colon.
fn parse_http_head(block: &[u8]) -> Option<HttpRequestHead> {
    let text = String::from_utf8_lossy(block);
    let mut lines = text.lines();
    let request_line = lines.next()?;
    let (method, uri) = parse_http_request_line(request_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((
            name.trim().to_ascii_lowercase(),
            value.trim().to_string(),
        ));
    }
    Some(HttpRequestHead {
        method,
        uri,
        headers,
    })
}

/// Rebuild the header block for the origin server: request line in
/// origin-form, all headers except Proxy-Authorization,
/// Proxy-Connection and Connection (replaced with
/// `Connection: close`), and any Keep-Alive dropped.
fn build_forward_head(req: &HttpRequestHead, origin_path: &str) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, origin_path);
    for (name, value) in &req.headers {
        match name.as_str() {
            "proxy-authorization" | "proxy-connection" | "connection" | "keep-alive" => {}
            _ => out.push_str(&format!("{}: {}\r\n", name, value)),
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// First index of `needle` in `hay`, if present.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Read one HTTP header block (up to and including the first blank
/// line). Returns (header_bytes, leftover_bytes): leftover is
/// whatever was already read past the header terminator (start of
/// the body / TLS handshake) and must be forwarded, never dropped.
/// Errors on EOF before the terminator or an oversized block.
async fn read_http_headers<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_subslice(&buf, b"\r\n\r\n") {
            let headers = buf[..end + 4].to_vec();
            let leftover = buf[end + 4..].to_vec();
            return Ok((headers, leftover));
        }
        if buf.len() > HTTP_MAX_HEADERS {
            return Err("HTTP header block too large".to_string());
        }
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before HTTP headers finished".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A byte source that first drains a leftover prefix, then reads
/// from the socket. Lets the chunked-body reader reuse bytes that
/// were already read past the header block.
struct PrefixedReader<'a, R: AsyncRead + Unpin> {
    prefix: Vec<u8>,
    pos: usize,
    stream: &'a mut R,
}

impl<'a, R: AsyncRead + Unpin> PrefixedReader<'a, R> {
    async fn read_line(&mut self) -> Result<Vec<u8>, String> {
        let mut line = Vec::new();
        loop {
            while self.pos < self.prefix.len() {
                let b = self.prefix[self.pos];
                self.pos += 1;
                line.push(b);
                if b == b'\n' {
                    return Ok(line);
                }
            }
            let mut one = [0u8; 1];
            let n = self
                .stream
                .read(&mut one)
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("connection closed mid-chunk".to_string());
            }
            line.push(one[0]);
            if one[0] == b'\n' {
                return Ok(line);
            }
            if line.len() > 8192 {
                return Err("chunk-size line too long".to_string());
            }
        }
    }

    async fn read_exact_into(&mut self, buf: &mut [u8]) -> Result<(), String> {
        let mut filled = 0;
        while filled < buf.len() {
            if self.pos < self.prefix.len() {
                let take = (self.prefix.len() - self.pos).min(buf.len() - filled);
                buf[filled..filled + take]
                    .copy_from_slice(&self.prefix[self.pos..self.pos + take]);
                self.pos += take;
                filled += take;
                continue;
            }
            let n = self
                .stream
                .read(&mut buf[filled..])
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("connection closed mid-chunk".to_string());
            }
            filled += n;
        }
        Ok(())
    }
}

/// Forward a chunked request body (framing preserved verbatim),
/// reading from `local` (with `leftover` bytes first) to `remote`.
async fn forward_chunked_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    local: &mut R,
    remote: &mut W,
    leftover: Vec<u8>,
) -> Result<(), String> {
    let mut r = PrefixedReader {
        prefix: leftover,
        pos: 0,
        stream: local,
    };
    let mut total: usize = 0;
    loop {
        let line = r.read_line().await?;
        // Chunk-size line may carry extensions after ';'.
        let size_str = String::from_utf8_lossy(&line)
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let size = usize::from_str_radix(&size_str, 16)
            .map_err(|_| "bad chunk size".to_string())?;
        remote
            .write_all(&line)
            .await
            .map_err(|e| e.to_string())?;
        total = total
            .checked_add(size)
            .ok_or("chunked body too large")?;
        if total > HTTP_MAX_BODY {
            return Err("HTTP request body too large".to_string());
        }
        if size == 0 {
            // Trailers: forward lines until the blank line.
            loop {
                let tline = r.read_line().await?;
                let done = tline == b"\r\n" || tline == b"\n";
                remote
                    .write_all(&tline)
                    .await
                    .map_err(|e| e.to_string())?;
                if done {
                    return Ok(());
                }
            }
        }
        let mut buf = vec![0u8; size];
        r.read_exact_into(&mut buf).await?;
        remote
            .write_all(&buf)
            .await
            .map_err(|e| e.to_string())?;
        // Trailing CRLF after the chunk data.
        let mut crlf = [0u8; 2];
        r.read_exact_into(&mut crlf).await?;
        remote
            .write_all(&crlf)
            .await
            .map_err(|e| e.to_string())?;
    }
}

/// Forward a request body from `local` to `remote`, honouring
/// Content-Length or chunked framing. `leftover` is bytes already
/// read past the headers. No body declared → nothing to forward.
async fn forward_http_body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    local: &mut R,
    remote: &mut W,
    req: &HttpRequestHead,
    leftover: Vec<u8>,
) -> Result<(), String> {
    if let Some(len) = req
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        if len > HTTP_MAX_BODY {
            return Err("HTTP request body too large".to_string());
        }
        let mut remaining = len;
        // First the bytes we already hold.
        let take = remaining.min(leftover.len());
        if take > 0 {
            remote
                .write_all(&leftover[..take])
                .await
                .map_err(|e| e.to_string())?;
            remaining -= take;
        }
        let mut chunk = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            let n = local
                .read(&mut chunk[..want])
                .await
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("connection closed mid-body".to_string());
            }
            remote
                .write_all(&chunk[..n])
                .await
                .map_err(|e| e.to_string())?;
            remaining -= n;
        }
        return Ok(());
    }
    if req
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        return forward_chunked_body(local, remote, leftover).await;
    }
    // No body declared; bytes already read past the headers (if any)
    // have no framing to honour, so they are dropped.
    Ok(())
}

async fn handle_http_conn(
    mut local: TcpStream,
    tunnel: Arc<SstpTunnel>,
    timeout: Duration,
    conn_log: &Option<ConnLog>,
) -> Result<(), String> {
    let peer = peer_of(&local);
    let (head_bytes, leftover) = match read_http_headers(&mut local).await {
        Ok(v) => v,
        Err(_) => {
            // Malformed / empty request: close without a reply.
            emit_conn_log(
                conn_log,
                format!("混合代理连接 {}：HTTP 请求头未读完，已关闭", peer),
            );
            return Ok(());
        }
    };
    let Some(req) = parse_http_head(&head_bytes) else {
        let _ = local
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        emit_conn_log(
            conn_log,
            format!("混合代理连接 {}：HTTP 请求行畸形，已回 400", peer),
        );
        return Ok(());
    };
    let host_header = req.get("host").map(|s| s.to_string());
    let Some((host, port)) = http_target(&req.method, &req.uri, host_header.as_deref()) else {
        let _ = local
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        emit_conn_log(
            conn_log,
            format!("混合代理连接 {}：HTTP 请求目标无法解析，已回 400", peer),
        );
        return Ok(());
    };
    // The connection line: source, protocol, target host only —
    // never the path or the body (see `ConnLog`).
    if req.method.eq_ignore_ascii_case("CONNECT") {
        emit_conn_log(
            conn_log,
            format!("混合代理连接 {}：HTTP CONNECT → {}:{}", peer, host, port),
        );
    } else {
        emit_conn_log(
            conn_log,
            format!(
                "混合代理连接 {}：HTTP {} → {}:{}",
                peer,
                req.method.to_ascii_uppercase(),
                host,
                port
            ),
        );
    }
    let mut remote = match tunnel.open_stream(&host, port, timeout).await {
        Ok(s) => s,
        Err(e) => {
            let _ = local
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Err(format!("tunnel TCP to {}:{} failed: {}", host, port, e));
        }
    };
    if req.method.eq_ignore_ascii_case("CONNECT") {
        // Tunnel mode: 200, then raw bytes both ways (TLS inside).
        local
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        if !leftover.is_empty() {
            remote
                .write_all(&leftover)
                .await
                .map_err(|e| e.to_string())?;
        }
        let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
        return Ok(());
    }
    // Plain HTTP: rewrite to origin-form, forward, then stream the
    // response back and close (no keep-alive reuse).
    let origin_path = origin_form_path(&req.uri);
    let forward = build_forward_head(&req, &origin_path);
    remote
        .write_all(&forward)
        .await
        .map_err(|e| e.to_string())?;
    if let Err(e) = forward_http_body(&mut local, &mut remote, &req, leftover).await {
        return Err(e);
    }
    // One-way copy: the origin server closes after the response (we
    // sent Connection: close), then the client side is closed.
    let _ = tokio::io::copy(&mut remote, &mut local).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn classify_first_byte_routes_protocols() {
        assert_eq!(classify_first_byte(0x05), FirstByte::Socks5);
        for m in [b'C', b'G', b'P', b'H', b'D', b'O', b'T', b'c', b'g'] {
            assert_eq!(classify_first_byte(m), FirstByte::Http, "byte {:#04x}", m);
        }
        for b in [0x00, 0x01, 0x04, 0x16, 0xFF] {
            assert_eq!(classify_first_byte(b), FirstByte::Unknown, "byte {:#04x}", b);
        }
    }

    #[test]
    fn parse_http_request_line_edges() {
        assert_eq!(
            parse_http_request_line("GET http://example.com/ HTTP/1.1"),
            Some(("GET".to_string(), "http://example.com/".to_string()))
        );
        assert_eq!(
            parse_http_request_line("CONNECT example.com:443 HTTP/1.1"),
            Some(("CONNECT".to_string(), "example.com:443".to_string()))
        );
        assert_eq!(
            parse_http_request_line("GET / HTTP/1.0"),
            Some(("GET".to_string(), "/".to_string()))
        );
        assert!(parse_http_request_line("GET").is_none());
        assert!(parse_http_request_line("FOO BAR").is_none());
        assert!(parse_http_request_line("GET / HTTP/1.1 EXTRA").is_none());
        assert!(parse_http_request_line("").is_none());
    }

    #[test]
    fn parse_authority_edges() {
        assert_eq!(
            parse_authority("example.com", 80),
            Some(("example.com".to_string(), 80))
        );
        assert_eq!(
            parse_authority("example.com:443", 80),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_authority("user@example.com:8080", 80),
            Some(("example.com".to_string(), 8080))
        );
        assert!(parse_authority("[::1]:8080", 80).is_none(), "IPv6 refused");
        assert!(parse_authority("a:b:c", 80).is_none());
        assert!(parse_authority(":80", 80).is_none());
        assert!(parse_authority("", 80).is_none());
        assert!(parse_authority("example.com:0", 80).is_some(), "port 0 parses");
    }

    #[test]
    fn http_target_edges() {
        assert_eq!(
            http_target("CONNECT", "example.com:443", None),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            http_target("CONNECT", "example.com", None),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            http_target("GET", "http://example.com:8080/a?b=c", None),
            Some(("example.com".to_string(), 8080))
        );
        assert_eq!(
            http_target("GET", "http://example.com/a", None),
            Some(("example.com".to_string(), 80))
        );
        assert_eq!(
            http_target("GET", "http://example.com", None),
            Some(("example.com".to_string(), 80))
        );
        assert_eq!(
            http_target("GET", "/a", Some("example.com:81")),
            Some(("example.com".to_string(), 81))
        );
        assert_eq!(http_target("GET", "/a", None), None);
        assert_eq!(http_target("GET", "https://example.com/a", None), None);
        assert_eq!(http_target("GET", "ftp://example.com/", None), None);
    }

    #[test]
    fn origin_form_path_edges() {
        assert_eq!(origin_form_path("http://h:80/a?b"), "/a?b");
        assert_eq!(origin_form_path("http://h"), "/");
        assert_eq!(origin_form_path("http://h/"), "/");
        assert_eq!(origin_form_path("/a"), "/a");
    }

    #[test]
    fn build_forward_head_drops_proxy_headers() {
        let req = HttpRequestHead {
            method: "GET".to_string(),
            uri: "http://example.com/a".to_string(),
            headers: vec![
                ("host".to_string(), "example.com".to_string()),
                (
                    "proxy-authorization".to_string(),
                    "Basic eA==".to_string(),
                ),
                ("proxy-connection".to_string(), "keep-alive".to_string()),
                ("connection".to_string(), "keep-alive".to_string()),
                ("accept".to_string(), "*/*".to_string()),
            ],
        };
        let out = String::from_utf8(build_forward_head(&req, "/a")).unwrap();
        assert!(out.starts_with("GET /a HTTP/1.1\r\n"), "request line: {}", out);
        assert!(out.contains("host: example.com\r\n"), "keeps Host: {}", out);
        assert!(out.contains("accept: */*\r\n"), "keeps Accept: {}", out);
        assert!(!out.contains("proxy-authorization"), "drops auth: {}", out);
        assert!(!out.contains("proxy-connection"), "drops proxy-connection: {}", out);
        assert!(out.contains("Connection: close\r\n"), "forces close: {}", out);
        assert_eq!(out.matches("Connection: close").count(), 1, "one close: {}", out);
    }

    #[tokio::test]
    async fn read_http_headers_splits_leftover() {
        let (mut a, mut b) = duplex(65536);
        a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODYPART")
            .await
            .unwrap();
        drop(a);
        let (head, leftover) = read_http_headers(&mut b).await.unwrap();
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(leftover, b"BODYPART");
    }

    #[tokio::test]
    async fn read_http_headers_errors_on_eof() {
        let (mut a, mut b) = duplex(65536);
        a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        drop(a);
        assert!(read_http_headers(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn forward_http_body_content_length() {
        let (mut client, mut server) = duplex(65536);
        let (mut sink_a, mut sink_b) = duplex(65536);
        let req = HttpRequestHead {
            method: "POST".to_string(),
            uri: "http://example.com/a".to_string(),
            headers: vec![("content-length".to_string(), "5".to_string())],
        };
        // Body arrives split: "HE" already past the headers (leftover),
        // "LLO" still in the stream.
        client.write_all(b"LLO").await.unwrap();
        drop(client);
        forward_http_body(&mut server, &mut sink_a, &req, b"HE".to_vec())
            .await
            .unwrap();
        drop(sink_a);
        let mut got = Vec::new();
        sink_b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"HELLO");
    }

    #[tokio::test]
    async fn forward_http_body_chunked() {
        let (mut client, mut server) = duplex(65536);
        let (mut sink_a, mut sink_b) = duplex(65536);
        let req = HttpRequestHead {
            method: "POST".to_string(),
            uri: "http://example.com/a".to_string(),
            headers: vec![("transfer-encoding".to_string(), "chunked".to_string())],
        };
        // "5\r\nHELLO\r\n0\r\n\r\n" split across writes.
        client.write_all(b"5\r\nHE").await.unwrap();
        client.write_all(b"LLO\r\n0\r\n\r\n").await.unwrap();
        drop(client);
        forward_http_body(&mut server, &mut sink_a, &req, Vec::new())
            .await
            .unwrap();
        drop(sink_a);
        let mut got = Vec::new();
        sink_b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"5\r\nHELLO\r\n0\r\n\r\n");
    }

    #[test]
    fn parse_socks_udp_edges() {
        // IPv4 target.
        let mut d = vec![0, 0, 0, 0x01, 1, 2, 3, 4];
        d.extend_from_slice(&53u16.to_be_bytes());
        d.extend_from_slice(b"QUERY");
        let (frag, host, port, payload) = parse_socks_udp(&d).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 53);
        assert_eq!(payload, b"QUERY");
        // Domain target, FRAG preserved for the caller to drop.
        let mut d = vec![0, 0, 2, 0x03, 11];
        d.extend_from_slice(b"example.com");
        d.extend_from_slice(&443u16.to_be_bytes());
        d.extend_from_slice(b"QUIC");
        let (frag, host, port, payload) = parse_socks_udp(&d).unwrap();
        assert_eq!(frag, 2);
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(payload, b"QUIC");
        // IPv6, bad RSV, short, and unknown ATYP are all refused.
        assert!(parse_socks_udp(&[0, 0, 0, 0x04, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(parse_socks_udp(&[0, 1, 0, 0x01, 1, 2, 3, 4, 0, 53]).is_none());
        assert!(parse_socks_udp(&[0, 0, 0]).is_none());
        assert!(parse_socks_udp(&[0, 0, 0, 0x09, 1, 2, 3, 4, 0, 53]).is_none());
        // Truncated domain: length byte promises more than present.
        assert!(parse_socks_udp(&[0, 0, 0, 0x03, 11, b'e', b'x']).is_none());
    }

    #[test]
    fn build_socks_udp_roundtrip() {
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let built = build_socks_udp(ip, 53, b"DNS-REPLY");
        let (frag, host, port, payload) = parse_socks_udp(&built).unwrap();
        assert_eq!(frag, 0);
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 53);
        assert_eq!(payload, b"DNS-REPLY");
        assert_eq!(&built[..4], &[0, 0, 0, 0x01], "header bytes");
    }

    fn udp_test_entry(client_port: u16, host: &str, port: u16) -> Arc<UdpFlowEntry> {
        Arc::new(UdpFlowEntry::new(
            UdpFlowKey {
                client: SocketAddr::from(([127, 0, 0, 1], client_port)),
                host: host.to_string(),
                port,
            },
            20000 + client_port,
            (Ipv4Addr::new(8, 8, 8, 8), port),
            format!("{}:{}", host, port),
        ))
    }

    #[test]
    fn udp_flow_table_sweep_drops_idle_only() {
        let mut table = UdpFlowTable::new(1024);
        let now = Instant::now();
        let idle = udp_test_entry(1001, "a.example", 53);
        let recent = udp_test_entry(1002, "b.example", 53);
        let fresh = udp_test_entry(1003, "c.example", 53);
        *idle.last_active.lock().unwrap() = now - Duration::from_secs(120);
        *recent.last_active.lock().unwrap() = now - Duration::from_secs(10);
        table.insert(idle.clone());
        table.insert(recent.clone());
        table.insert(fresh.clone());
        let dropped = table.sweep_idle(now, UDP_FLOW_IDLE);
        assert_eq!(dropped.len(), 1, "only the 120 s-idle flow goes");
        assert!(Arc::ptr_eq(&dropped[0], &idle));
        assert_eq!(table.len(), 2);
        assert!(table.get(&recent.key).is_some());
        assert!(table.get(&fresh.key).is_some());
    }

    #[test]
    fn udp_flow_table_evicts_oldest_when_full() {
        let mut table = UdpFlowTable::new(3);
        let now = Instant::now();
        let e1 = udp_test_entry(1001, "a.example", 53);
        let e2 = udp_test_entry(1002, "b.example", 53);
        let e3 = udp_test_entry(1003, "c.example", 53);
        *e1.last_active.lock().unwrap() = now - Duration::from_secs(30);
        *e2.last_active.lock().unwrap() = now - Duration::from_secs(20);
        *e3.last_active.lock().unwrap() = now - Duration::from_secs(10);
        table.insert(e1.clone());
        table.insert(e2.clone());
        table.insert(e3.clone());
        // Full (3 of 3): the least-recently-active flow is evicted.
        let evicted = table.evict_oldest_if_full().unwrap();
        assert!(
            Arc::ptr_eq(&evicted, &e1),
            "the least-recently-active flow is evicted"
        );
        assert_eq!(table.len(), 2);
        assert!(table.get(&e1.key).is_none());
        // Room again: nothing to evict.
        assert!(table.evict_oldest_if_full().is_none());
        table.insert(udp_test_entry(1004, "d.example", 53));
        let evicted = table.evict_oldest_if_full().unwrap();
        assert!(
            Arc::ptr_eq(&evicted, &e2),
            "after refill, the next-oldest flow is evicted"
        );
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn udp_flow_table_remove_client() {
        let mut table = UdpFlowTable::new(1024);
        let phone = udp_test_entry(1001, "a.example", 53);
        // Same client IP as `phone`, different UDP source port.
        let phone2 = Arc::new(UdpFlowEntry::new(
            UdpFlowKey {
                client: SocketAddr::from(([127, 0, 0, 1], 1002)),
                host: "b.example".to_string(),
                port: 443,
            },
            21002,
            (Ipv4Addr::new(1, 1, 1, 1), 443),
            "b.example:443".to_string(),
        ));
        let other = Arc::new(UdpFlowEntry::new(
            UdpFlowKey {
                client: SocketAddr::from(([192, 168, 1, 5], 1003)),
                host: "c.example".to_string(),
                port: 53,
            },
            21003,
            (Ipv4Addr::new(8, 8, 4, 4), 53),
            "c.example:53".to_string(),
        ));
        table.insert(phone.clone());
        table.insert(phone2.clone());
        table.insert(other.clone());
        let removed = table.remove_client("127.0.0.1".parse().unwrap());
        assert_eq!(removed.len(), 2, "both flows from that IP go");
        assert_eq!(table.len(), 1);
        assert!(table.get(&other.key).is_some());
    }

    /// v3.14 (diagnosis §4.2): `ConnLog` is a BOUNDED channel
    /// (512). A full channel drops the line and counts it instead
    /// of queueing without limit while the UI is stalled — the
    /// first line still gets through, the overflow is counted.
    #[test]
    fn conn_log_bounded_drops_when_full_and_counts() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1);
        let sink = Some(tx);
        let before = conn_log_dropped();
        emit_conn_log(&sink, "first".to_string());
        emit_conn_log(&sink, "second".to_string()); // full -> dropped
        emit_conn_log(&sink, "third".to_string()); // dropped too
        assert_eq!(rx.try_recv().unwrap(), "first");
        assert_eq!(
            conn_log_dropped() - before,
            2,
            "two overflow lines must be counted as dropped"
        );
        assert!(rx.try_recv().is_err(), "nothing else queued");
    }
}
