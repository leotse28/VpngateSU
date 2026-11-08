//! vpngate-gui — desktop GUI for the VPNGate Rust client (egui/eframe 0.36).
//!
//! Same tunnel code as the CLI (`vpngate_client` lib); this binary only
//! adds a window around it. Long work (fetch / probe / connect)
//! runs on tokio tasks; the UI polls them through a channel and never
//! blocks.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vpngate_client::config::Config;
use vpngate_client::filelog::{self, FileLogger, LogLevel};
use vpngate_client::net::{self, Connector};
use vpngate_client::sstp::SstpTunnel;
use vpngate_client::sysproxy::SystemProxyGuard;
use vpngate_client::tray;
use vpngate_client::vpngate::{self, Node};

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

/// What the UI is waiting for right now (at most one job at a time).
#[derive(Clone, Copy, PartialEq, Eq)]
#[derive(Debug)]
enum Busy {
    Fetching,
    Probing,
    ProbingAll,
    Connecting,
    TestingFrontProxy,
}

/// Which node-list column the list is sorted by. Only the country,
/// sessions (当前人数）, line-quality （线路质量）, per-capita
/// bandwidth （人均带宽） and latency/status （延迟/状态） columns are
/// sortable; the status (∞), ISP and host:port columns are not. One
/// column at a time: clicking a header sorts by that column and
/// clears the previous column's arrow; clicking the same column
/// again reverses the direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SortCol {
    Country,
    Sessions,
    Quality,
    PerCapita,
    Latency,
}

impl SortCol {
    /// First-click direction for the column — the most useful order:
    /// countries A-Z, fewest sessions first (lightest load), fastest
    /// line first (speed primary, ping secondary), highest
    /// per-capita bandwidth first (most headroom per user), and for
    /// latency the available nodes by ms ascending, unprobed in the
    /// middle, failed last (see `latency_key`).
    fn default_dir(self) -> SortDir {
        match self {
            SortCol::Country => SortDir::Asc,
            SortCol::Sessions => SortDir::Asc,
            SortCol::Quality => SortDir::Desc,
            SortCol::PerCapita => SortDir::Desc,
            SortCol::Latency => SortDir::Asc,
        }
    }
}

/// Country-column sort direction, toggled by clicking a sortable
/// header. Chinese country names sort by string (Unicode code-point)
/// order — deterministic, and same-country rows stay grouped — with
/// the hostname as the tie-breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    /// Arrow shown in the sorted column's header for the current
    /// direction: ▲ = the column's first-click order, ▼ = reversed.
    fn arrow(self) -> &'static str {
        match self {
            SortDir::Asc => "▲",
            SortDir::Desc => "▼",
        }
    }
}

/// One rendered node-list row: (node index, status icon, country,
/// ISP, sessions cell, quality cell, per-capita cell, host:port
/// shown, latency/status, host:port full). v3.14 caches the whole
/// built list (`GuiApp::rows_cache`) keyed by `list_fingerprint`,
/// so the ~1100 per-frame `String` allocations of the old build
/// happen only when the list actually changed.
type NodeRow = (
    usize,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// Sort key for the 线路质量 column: (has data, speed, ping
/// reversed). No-data nodes (sessions, speed and ping all zero —
/// the curated 28) count as smallest, so they sort first in
/// ascending order and last in descending order, never mixed in
/// with nodes that have data. Speed is primary, ping secondary:
/// in the ascending key a larger ping sorts later (Reverse), so
/// reversing the whole key (descending, the first click) is
/// fastest-first with smaller ping first on ties, and ascending is
/// slowest-first with larger ping first.
fn quality_key(n: &vpngate::Node) -> (bool, u64, std::cmp::Reverse<u64>) {
    let has_data = n.sessions != 0 || n.speed_mbps != 0 || n.ping_ms != 0;
    (
        has_data,
        n.speed_mbps,
        std::cmp::Reverse(n.ping_ms),
    )
}

/// Does this node carry listed stats (sessions / speed / ping)?
/// The curated 28 have all three zero — no data, not "zero
/// sessions" or "zero speed".
fn has_listed_stats(n: &vpngate::Node) -> bool {
    n.sessions != 0 || n.speed_mbps != 0 || n.ping_ms != 0
}

/// 当前人数 cell: "47人" ("0人" for a node with data but zero
/// sessions); "—" when the node carries no listed stats at all.
fn sessions_cell(n: &vpngate::Node) -> String {
    if has_listed_stats(n) {
        format!("{}人", n.sessions)
    } else {
        "—".to_string()
    }
}

/// 线路质量 cell: "572M@3ms" (speed Mbps @ ping ms); "—" with no data.
fn quality_cell(n: &vpngate::Node) -> String {
    if has_listed_stats(n) {
        format!("{}M@{}ms", n.speed_mbps, n.ping_ms)
    } else {
        "—".to_string()
    }
}

/// Sort key for the 人均带宽 column: (has data, per-capita speed in
/// tenths of a Mbps). Integer tenths — no float comparison — so the
/// order is exact and deterministic: `speed * 10 / sessions`
/// (integer division), or `speed * 10` when sessions is zero (one
/// user alone gets the whole line, so per-capita is the total
/// speed). No-data nodes count as smallest, like `quality_key`, so
/// they sort first in ascending order and last in descending order.
fn per_capita_key(n: &vpngate::Node) -> (bool, u64) {
    let has_data = has_listed_stats(n);
    let tenths = if n.sessions == 0 {
        n.speed_mbps.saturating_mul(10)
    } else {
        n.speed_mbps.saturating_mul(10) / n.sessions
    };
    (has_data, tenths)
}

/// 人均带宽 cell: total speed divided by current sessions, one
/// decimal, e.g. "12.2M/人" for 572 Mbps shared by 47 users.
/// "—" with no data; a node with data but zero sessions shows the
/// total speed itself ("100.0M/人" — one user alone); speed zero
/// with sessions present shows "0.0M/人", not "—".
fn per_capita_cell(n: &vpngate::Node) -> String {
    if !has_listed_stats(n) {
        return "—".to_string();
    }
    if n.sessions == 0 {
        format!("{:.1}M/人", n.speed_mbps as f64)
    } else {
        format!("{:.1}M/人", n.speed_mbps as f64 / n.sessions as f64)
    }
}

impl Busy {
    fn label(self) -> &'static str {
        match self {
            Busy::Fetching => "正在拉取节点列表…",
            Busy::Probing => "正在探测节点…",
            Busy::ProbingAll => "正在探测全部节点…",
            Busy::Connecting => "正在连接…",
            Busy::TestingFrontProxy => "正在测试前置代理…",
        }
    }
}

/// Why a probe failed: the front proxy itself is down, or the proxy
/// is up but the node did not answer. The distinction matters because
/// refresh / probe / connect all share the front proxy — when the
/// proxy is down they fail together for one reason, and swapping
/// nodes will not help.
#[derive(Debug, Clone)]
enum ProbeFailure {
    ProxyDown(String),
    NodeDown(String),
}

/// A live connection: tunnel + the mixed proxy server task(s) + the optional
/// system-proxy guard. Dropping the tunnel Arc closes the TLS stream
/// (the lib's writer task sends close_notify when its channel closes).
/// With LAN sharing on, the one server binds the wildcard address
/// (0.0.0.0:local_port) instead of a second port; the task is
/// aborted on disconnect.
struct ActiveConnection {
    /// Held for ownership: dropping the last tunnel Arc closes the
    /// TLS stream. Nothing in the GUI reads it any more (the
    /// tunnel-test button that did was removed in v3.13) — the
    /// field is the connection, not a lookup.
    #[allow(dead_code)]
    tunnel: Arc<SstpTunnel>,
    serve: Vec<tokio::task::JoinHandle<()>>,
    proxy_guard: Option<SystemProxyGuard>,
    /// Display label, e.g. "127.0.0.1:10818" or
    /// "127.0.0.1:10818 ＋ 0.0.0.0:10818".
    listen_addr: String,
    node_label: String,
    vip: Ipv4Addr,
}

enum GuiEvent {
    Nodes(vpngate::NodeListUpdate),
    /// v3.15 "从API刷新节点" failed: the official API could not be
    /// reached. The reason is the API error verbatim; the list and
    /// the blocklist stay exactly as they were — this event carries
    /// no nodes, so there is nothing to fall back to.
    ApiRefreshFailed { reason: String },
    Probe {
        host: String,
        result: Result<(Ipv4Addr, Duration), ProbeFailure>,
    },
    /// Probe-all sweep: the task is about to probe `current` (the
    /// (done+1)-th of `total`). The row shows "探测中…" and the
    /// status line names it; the outcome still arrives as
    /// `ProbeAllResult` below.
    ProbeAllProgress {
        current: String,
        done: usize,
        total: usize,
    },
    /// Probe-all sweep: one node's outcome. `done` counts this node.
    ProbeAllResult {
        host: String,
        result: Result<(Ipv4Addr, Duration), ProbeFailure>,
        done: usize,
        total: usize,
    },
    /// Probe-all sweep finished: `stopped` means the user pressed
    /// 停止 (or the front proxy went down, see `proxy_down`)
    /// before the queue ran out; `ok`/`failed` count the nodes
    /// actually probed.
    ProbeAllDone {
        total: usize,
        ok: usize,
        failed: usize,
        stopped: bool,
        proxy_down: bool,
    },
    Connected(Box<ActiveConnection>),
    ConnectFailed(String),
    /// One line from the mixed proxy about an accepted connection
    /// (source address, protocol, target host — see `ConnLog` in
    /// `socks5.rs`). The UI writes it to the log panel + file log,
    /// so a LAN device that never reaches the proxy leaves no line.
    ConnLog(String),
    FrontProxyTest {
        /// Front-proxy address snapshotted when the test was clicked
        /// (the live field may have changed by the time the result
        /// arrives — Leo once typed 12.0.0.1, fixed it mid-test to
        /// 127.0.0.1, and the start line and the result line named
        /// different addresses).
        addr: String,
        google: net::FrontProxyCheck,
        vpngate: net::FrontProxyCheck,
    },
    /// Progress of a running front-proxy test: which site is being
    /// tested right now ("Google" / "vpngate.net"). Updates the
    /// status line only; the full result still comes as
    /// `FrontProxyTest`.
    FrontProxyTestProgress { site: String },
}

/// Build a Connector from the current settings.
fn connector_for(front_enabled: bool, front_addr: &str, user: &str, pass: &str) -> Connector {
    if front_enabled {
        let mut fp = vpngate_client::config::FrontProxy::default();
        fp.enabled = true;
        fp.addr = front_addr.to_string();
        fp.username = if user.is_empty() {
            None
        } else {
            Some(user.to_string())
        };
        fp.password = if pass.is_empty() {
            None
        } else {
            Some(pass.to_string())
        };
        Connector::new(Some(fp))
    } else {
        Connector::new(None)
    }
}

async fn fetch_flow(connector: &Connector) -> vpngate::NodeListUpdate {
    vpngate::fetch_nodes_with_fallback(connector).await
}

/// v3.15: API-only refresh — the official API (CSV) and nothing
/// else. Any failure is an `Err`; the caller reports it plainly
/// instead of falling back to the scrape.
async fn fetch_api_flow(connector: &Connector) -> Result<Vec<vpngate::Node>, String> {
    vpngate::fetch_api_only(connector).await
}

async fn probe_flow(
    connector: &Connector,
    target: &str,
    timeout: Duration,
) -> Result<(Ipv4Addr, Duration), ProbeFailure> {
    let candidates = vpngate::resolve_target(target);
    // One race over all candidate ports (first success wins); a dead
    // node costs about one timeout, not one per port in series.
    let last_err = match SstpTunnel::probe_any(connector, &candidates, timeout).await {
        Ok(v) => return Ok(v),
        Err(e) => e,
    };
    // All candidates failed. If a front proxy is configured, find out
    // whether the proxy itself is the problem: a direct TCP connect to
    // the proxy separates "proxy down" from "node down".
    let proxy_tcp = net::check_front_proxy_tcp(connector, Duration::from_secs(3)).await;
    Err(classify_probe_failure(last_err, proxy_tcp))
}

/// Pure half of `probe_flow`'s failure handling, so the split is
/// unit-testable: only a failed direct TCP connect to a configured
/// front proxy blames the proxy; anything else blames the node.
fn classify_probe_failure(last_err: String, proxy_tcp: Option<bool>) -> ProbeFailure {
    match proxy_tcp {
        Some(false) => ProbeFailure::ProxyDown(last_err),
        _ => ProbeFailure::NodeDown(last_err),
    }
}

/// Probe every node in `targets` in order, one at a time (never in
/// parallel — a dead node costs about one timeout, and 95 parallel
/// handshakes would flood the front proxy). `targets` is the
/// (raw host, dialled target) snapshot `probe_all_targets` took at
/// click time. Sends a progress event before each probe and a
/// result event after it, then a done event with the counts. Stops
/// early when `stop` is set — checked before each probe and after
/// each result, so a 停止 click lands after the node in flight —
/// or when a probe fails because the front proxy is down (the rest
/// would fail identically, one timeout each).
async fn probe_all_flow(
    connector: &Connector,
    targets: Vec<(String, String)>,
    timeout: Duration,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<GuiEvent>,
    ctx: egui::Context,
) {
    let total = targets.len();
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut stopped = false;
    let mut proxy_down = false;
    for (i, (host, target)) in targets.into_iter().enumerate() {
        if stop.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
        let _ = tx.send(GuiEvent::ProbeAllProgress {
            current: host.clone(),
            done: i,
            total,
        });
        ctx.request_repaint();
        let res = probe_flow(connector, &target, timeout).await;
        match &res {
            Ok(_) => ok += 1,
            Err(ProbeFailure::ProxyDown(_)) => {
                failed += 1;
                proxy_down = true;
            }
            Err(ProbeFailure::NodeDown(_)) => failed += 1,
        }
        let _ = tx.send(GuiEvent::ProbeAllResult {
            host,
            result: res,
            done: i + 1,
            total,
        });
        ctx.request_repaint();
        if proxy_down {
            break;
        }
        if stop.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
    }
    let _ = tx.send(GuiEvent::ProbeAllDone {
        total,
        ok,
        failed,
        stopped,
        proxy_down,
    });
    ctx.request_repaint();
}

/// Test the front proxy itself: HTTPS GET to Google and to vpngate.net
/// through it (SOCKS5 connectivity, not ICMP ping). Runs on a
/// background task; the result distinguishes "the proxy is down" from
/// "the proxy is up but the target does not answer through it".
///
/// `timeout` is the TOTAL budget per site (see
/// `net::test_url_through_proxy`): pre-check + HTTPS together, so two
/// sites take at most 2 × `timeout`. A progress event is sent before
/// each site so the status line shows which one is being tested
/// instead of going silent for the whole run.
async fn front_proxy_test_flow(
    connector: &Connector,
    timeout: Duration,
    tx: &std::sync::mpsc::Sender<GuiEvent>,
) -> (net::FrontProxyCheck, net::FrontProxyCheck) {
    let _ = tx.send(GuiEvent::FrontProxyTestProgress {
        site: "Google".to_string(),
    });
    let google = net::test_url_through_proxy(connector, "https://www.google.com", timeout).await;
    let _ = tx.send(GuiEvent::FrontProxyTestProgress {
        site: "vpngate.net".to_string(),
    });
    let vpngate = net::test_url_through_proxy(connector, "https://www.vpngate.net", timeout).await;
    (google, vpngate)
}

/// Dedicated per-site budget for the front-proxy test (10 s total per
/// site: TCP pre-check at most 5 s, HTTPS gets the rest). This is NOT
/// the tunnel timeout: the tunnel timeout is for SSTP/PPP establish,
/// and a proxy test must not inherit a long one (or a short one) —
/// Leo's v3.1 test once sat silent for 40 s because each leg had its
/// own 10 s timeout, twice over, for two sites.
const FRONT_PROXY_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect the tunnel, start the local mixed proxy server(s),
/// optionally set the system proxy. Runs on a background task;
/// returns the live connection. `listen_addrs` is the address(es)
/// to actually bind (one mixed server per address); `listen_display`
/// is what the user sees (loopback always, plus the LAN address
/// when sharing is on — a single wildcard bind under the hood).
/// Both servers share the one tunnel, and the system proxy (if on)
/// points at the loopback address, never 0.0.0.0.
async fn connect_flow(
    connector: Connector,
    target: String,
    listen_addrs: Vec<String>,
    listen_display: String,
    timeout: Duration,
    system_proxy: bool,
    service: Option<String>,
    conn_log: Option<vpngate_client::socks5::ConnLog>,
) -> Result<ActiveConnection, String> {
    let candidates = vpngate::resolve_target(&target);
    // One race over all candidate ports (first success wins); a dead
    // node costs about one timeout, not one per port in series.
    let tunnel = SstpTunnel::connect_any(&connector, &candidates, timeout)
        .await
        .map_err(|e| format!("{} 个候选均失败；最后一次：{}", candidates.len(), e))?;
    let vip = tunnel.vip;
    let mut listeners = Vec::new();
    for addr in &listen_addrs {
        // Bind the local mixed-proxy port. v3.14: one retry after a
        // short wait when the address is in use — a restart starts
        // the new instance BEFORE the old one exits, so the first
        // bind of a restart-resume connect can still hit the old
        // process's listener; the old process is gone within a
        // second or two, so one 2 s retry covers it. A manual
        // connect that hits a genuinely busy port fails after the
        // same single retry, with the retry named in the error.
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                tokio::net::TcpListener::bind(addr).await.map_err(|e2| {
                    format!(
                        "本地混合代理无法监听 {}：{}（已重试一次，端口仍被占用，换一个端口再试）",
                        addr, e2
                    )
                })?
            }
            Err(e) => {
                return Err(format!(
                    "本地混合代理无法监听 {}：{}（端口可能被占用，换一个端口再试）",
                    addr, e
                ));
            }
        };
        listeners.push(listener);
    }
    let mut serve = Vec::new();
    for listener in listeners {
        serve.push(tokio::spawn(vpngate_client::socks5::serve_mixed(
            listener,
            tunnel.clone(),
            timeout,
            conn_log.clone(),
        )));
    }
    let listen_addr = listen_display;
    let mut guard = None;
    if system_proxy {
        // System proxy always points at the loopback address (a
        // 0.0.0.0 bind is not a usable proxy address).
        let sysproxy_addr = vpngate_client::config::loopback_of(&listen_addrs[0]);
        match SystemProxyGuard::set(&sysproxy_addr, service.as_deref()) {
            Ok(g) => guard = Some(g),
            Err(e) => {
                for s in &serve {
                    s.abort();
                }
                return Err(format!("系统代理设置失败：{}（隧道已断开）", e));
            }
        }
    }
    Ok(ActiveConnection {
        tunnel,
        serve,
        proxy_guard: guard,
        listen_addr,
        node_label: target,
        vip,
    })
}


/// Place a truncating label at the left of an exact cell rect.
/// (`Ui::put` centres the widget, which would centre every column's
/// text; a node list reads better left-aligned, like the old Grid.)
fn put_cell_label(ui: &mut egui::Ui, rect: egui::Rect, text: impl Into<egui::WidgetText>) {
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(rect)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
        |ui| {
            ui.add(egui::Label::new(text).truncate());
        },
    );
}

/// Scroll-bar style for every ScrollArea in the GUI (v3.13): the old
/// `ScrollStyle::solid()` was only 6 px wide with the handle in the
/// widgets' `bg_fill` (light theme: grey 230 on a warm-white panel —
/// nearly invisible at rest). This keeps solid (non-floating, so the
/// bars always occupy space and, per egui 0.36's scroll_area.rs, the
/// handle/background opacity is 1.0 at rest — no hover needed) but
/// widens the bar to 12 px, narrows the inner margin so the strip
/// costs 14 px total, lengthens the minimum handle to 24 px, and
/// switches the handle to the `foreground_color` (`fg_stroke`:
/// grey 60 light / grey 180 dark) so it reads in both themes.
/// Verified against egui 0.36.2 source (`style.rs` `ScrollStyle`,
/// `scroll_area.rs` opacity branches) — the field names are
/// `bar_width` / `bar_inner_margin` / `handle_min_length` /
/// `foreground_color`, not the `scroll_bar_width` guesses.
fn thick_scroll_style() -> egui::style::ScrollStyle {
    let mut s = egui::style::ScrollStyle::solid();
    s.bar_width = 12.0;
    s.bar_inner_margin = 2.0;
    s.handle_min_length = 24.0;
    s.foreground_color = true;
    s
}

/// A horizontal resize handle between two stacked boxes (v3.13):
/// an 8 px tall grab strip spanning the available width. Dragging
/// vertically moves `height` by the drag delta, clamped to
/// `min..=max` (the caller passes the clamped bounds for the
/// current panel). Returns the strip rect so tests can grab it.
/// Paint: a faint strip in both themes, with a centred grip pill
/// that turns indigo (the selection colour) on hover/drag, and a
/// vertical-resize cursor. Same drag pattern as the column
/// separators (apply the delta on `dragged()` and on
/// `drag_stopped()`, so a kittest teleport-drag still lands).
fn height_drag_handle(
    ui: &mut egui::Ui,
    id: impl Into<egui::Id>,
    height: &mut f32,
    min: f32,
    max: f32,
    hover_text: &str,
) -> egui::Rect {
    // Reserve the strip, then interact with a stable id (same
    // pattern as the column separators: an auto id would work while
    // the layout order is stable, but an explicit one survives
    // reordering).
    let (_alloc_id, rect) = ui.allocate_space(egui::vec2(ui.available_width(), 8.0));
    let resp = ui
        .interact(rect, id.into(), egui::Sense::drag())
        .on_hover_cursor(egui::CursorIcon::ResizeRow)
        .on_hover_text(hover_text);
    if resp.dragged() || resp.drag_stopped() {
        *height = (*height + resp.drag_delta().y).clamp(min, max);
    }
    let active = resp.hovered() || resp.dragged();
    let visuals = ui.visuals();
    ui.painter().rect_filled(
        rect,
        4.0,
        visuals.widgets.inactive.bg_fill,
    );
    let pill_color = if active {
        visuals.selection.bg_fill
    } else {
        visuals.text_color().gamma_multiply(0.35)
    };
    let pill = egui::Rect::from_center_size(rect.center(), egui::vec2(48.0, 3.0));
    ui.painter().rect_filled(pill, 1.5, pill_color);
    rect
}

/// One line for one front-proxy test target: reachable + ms, or which
/// side failed (proxy down vs target unreachable through a working proxy).
fn front_proxy_check_line(label: &str, check: &net::FrontProxyCheck) -> String {
    match check {
        net::FrontProxyCheck::Reachable { status, ms } => {
            format!("{}：通（HTTP {}，{} ms）", label, status, ms)
        }
        net::FrontProxyCheck::ProxyUnreachable(detail) => {
            format!("{}：前置代理连不上（{}）", label, detail)
        }
        net::FrontProxyCheck::TargetUnreachable(detail) => {
            format!("{}：代理通、目标站不通（{}）", label, detail)
        }
    }
}

/// Parse a manual node entry: "host:port", a bare hostname, or an index
/// into the curated list. Returns the canonical target string for
/// `resolve_target`, or a validation error to show next to the field.
fn parse_manual_target(text: &str, curated_len: usize) -> Result<String, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("请输入节点，例如 kanratown.opengw.net:992".to_string());
    }
    if let Some((h, p)) = t.rsplit_once(':') {
        if !h.is_empty() {
            match p.parse::<u16>() {
                Ok(port) if port > 0 => return Ok(t.to_string()),
                _ => return Err("端口必须是 1–65535 的数字".to_string()),
            }
        }
    }
    if let Ok(idx) = t.parse::<usize>() {
        if idx < curated_len {
            return Ok(t.to_string());
        }
        return Err(format!("序号超出范围（内嵌列表共 {} 个）", curated_len));
    }
    // Bare hostname: resolve_target will try the candidate SSTP ports.
    if t.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && t.contains('.')
    {
        return Ok(t.to_string());
    }
    Err("格式不对：主机名:端口，例如 kanratown.opengw.net:992".to_string())
}

/// Build the node a manual add creates. No literal placeholder
/// values: country/operator stay empty (the table shows "—") and
/// `name` stays empty so the operator cell cannot fall back to a
/// "host:port" string. v3.11 wrote "手动" / "手动添加" here — the
/// same class of bug as the import path's "导入" (v3.12 removes
/// every such placeholder; see also the scrape path in vpngate.rs).
fn manual_node(host: String, port: Option<u16>) -> Node {
    Node {
        host,
        port,
        country: String::new(),
        country_code: String::new(),
        isp: String::new(),
        name: String::new(),
        score: 0,
        ping_ms: 0,
        speed_mbps: 0,
        sessions: 0,
        ip: String::new(),
        backups: Vec::new(),
        port_source: "manual".to_string(),
        source: "manual".to_string(),
    }
}

/// One line per node, in the given (display) order: `host:port`
/// first, then the five metadata columns tab-separated — country,
/// operator, user count, line quality in Mbps, and (v3.16) the
/// last probed latency in ms:
/// `vpn547433109.opengw.net:995\t日本\tIIJ\t47\t572\t42`.
/// The sixth column is the probe latency from `probe_ms` (the
/// 延迟/状态 column's number, up to thousands of ms) — empty when
/// the node was never probed. It is NOT the API ping (`Node.ping_ms`,
/// the @xxms inside the line-quality column, tens of ms): that one
/// comes back from the API on refresh and is never exported.
/// The host is the completed DDNS hostname — the same target a
/// connect dials (a bare API label like "public-vpn-192" becomes
/// "public-vpn-192.opengw.net"). A node with no known port exports
/// as a bare host: the app never invents a port (API nodes arrive
/// port-less and connect tries 443/992/995 in parallel, so no
/// single port is "the" port for them). Empty fields
/// mean unknown (sessions/speed are 0 when the node carries no
/// stats); country/operator are sanitized so a stray tab or newline
/// in the data can never break the line format. The first field
/// stays a plain `host:port`, so the text is still usable as a bare
/// host list by anything that only reads the first field.
fn export_nodes_text(nodes: &[Node], probe_ms: &HashMap<String, u64>) -> String {
    nodes
        .iter()
        .map(|n| {
            let hostport = match n.port {
                Some(p) => format!("{}:{}", vpngate::complete_ddns_host(&n.host), p),
                None => vpngate::complete_ddns_host(&n.host),
            };
            let field = |s: &str| s.replace(['\t', '\n', '\r'], " ");
            let sessions = if n.sessions == 0 {
                String::new()
            } else {
                n.sessions.to_string()
            };
            let speed = if n.speed_mbps == 0 {
                String::new()
            } else {
                n.speed_mbps.to_string()
            };
            let latency = probe_ms
                .get(&vpngate::complete_ddns_host(&n.host))
                .or_else(|| probe_ms.get(&n.host))
                .map(|ms| ms.to_string())
                .unwrap_or_default();
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                hostport,
                field(&n.country),
                field(&n.isp),
                sessions,
                speed,
                latency
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One line of an import text (clipboard or node-list file).
enum ImportLine {
    /// Empty line or `#` comment: ignored, not an error.
    Skip,
    /// Not a `host[:port]` line: counted, never fails the import.
    Malformed,
    /// A node to add (`port` is `None` for a bare hostname — the
    /// connect path then tries the candidate ports). `host` is
    /// already completed (a bare label gains `.opengw.net`).
    /// `country` / `isp` are empty when the line carries no metadata
    /// (old plain `host:port` lines); `sessions` and `speed_mbps`
    /// are 0 then — unknown, shown as "—". Never a literal
    /// placeholder value: v3.11 stamped "导入" here, v3.12 removes it.
    /// `probe_ms` (v3.16) is the last probed latency in ms from the
    /// sixth column — `None` when the line carries no sixth column
    /// or it is empty (never probed); the import restores it into
    /// the app's in-memory `probe_ms` plus its display string.
    Node {
        host: String,
        port: Option<u16>,
        country: String,
        isp: String,
        sessions: u64,
        speed_mbps: u64,
        probe_ms: Option<u64>,
    },
}

/// Parse one import line. Three formats, all accepted:
/// * new (v3.16 export): `host:port\tcountry\tisp\tsessions\tspeed\tprobe_ms`
///   — the five metadata columns are restored; empty fields mean
///   unknown; the sixth column is the last probed latency in ms
///   (empty = never probed, non-numeric = Malformed);
/// * v3.12–v3.15 export: `host:port\tcountry\tisp\tsessions\tspeed`
///   — the four metadata columns are restored, no latency;
/// * old (v3.11 and earlier): a plain `host:port` or bare hostname
///   — metadata stays empty.
/// A hostname is ASCII letters/digits, `.` and `-` (the same
/// alphabet `parse_manual_target` accepts for a bare host); a port,
/// when present, must be 1–65535; sessions/speed/probe_ms, when present,
/// must be numbers. A bare VPNGate label without a dot
/// ("public-vpn-192") is accepted and completed to `.opengw.net`
/// here, so the stored host is always the full FQDN.
fn parse_import_line(line: &str) -> ImportLine {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return ImportLine::Skip;
    }
    let parts: Vec<&str> = t.split('\t').collect();
    if parts.len() > 6 {
        return ImportLine::Malformed;
    }
    let valid_host = |h: &str| {
        !h.is_empty()
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    };
    let (host, port) = match parts[0].rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => {
            let Ok(port) = p.parse::<u16>() else {
                return ImportLine::Malformed;
            };
            if port == 0 || !valid_host(h) {
                return ImportLine::Malformed;
            }
            (h.to_string(), Some(port))
        }
        Some(_) => return ImportLine::Malformed,
        None => {
            if valid_host(parts[0]) {
                (parts[0].to_string(), None)
            } else {
                return ImportLine::Malformed;
            }
        }
    };
    let field = |i: usize| parts.get(i).map(|s| s.trim()).unwrap_or("");
    let number = |i: usize| -> Option<u64> {
        let s = field(i);
        if s.is_empty() {
            Some(0)
        } else {
            s.parse::<u64>().ok()
        }
    };
    let Some(sessions) = number(3) else {
        return ImportLine::Malformed;
    };
    let Some(speed_mbps) = number(4) else {
        return ImportLine::Malformed;
    };
    // Sixth column (v3.16): empty = never probed, a number =
    // the last probed latency in ms, anything else = Malformed.
    let probe_ms = match field(5) {
        "" => None,
        s => match s.parse::<u64>() {
            Ok(ms) => Some(ms),
            Err(_) => return ImportLine::Malformed,
        },
    };
    ImportLine::Node {
        host: vpngate::complete_ddns_host(&host),
        port,
        country: field(1).to_string(),
        isp: field(2).to_string(),
        sessions,
        speed_mbps,
        probe_ms,
    }
}

/// What one import run did (see `import_nodes_text`).
#[derive(Debug, Default, PartialEq, Eq)]
struct ImportReport {
    added: usize,
    duplicates: usize,
    malformed: usize,
    /// Blocked hosts the import unblocked (completed hostnames).
    unblocked: Vec<String>,
}

/// One-line refresh summary, logged for every refresh so a small
/// list is diagnosable at a glance: which source served the list,
/// how many hosts the refresh cleared from the blocklist first, how
/// many manual/imported nodes the merge kept (v3.12), and how many
/// nodes the list finally holds.
///
/// v3.11 semantics (Leo's call, 2026-11-08): delete is session-only
/// hiding — a refresh clears the blocklist before fetching, so the
/// incoming list is shown in full and a refresh always brings the
/// many nodes back. The old line ("返回 N 个、屏蔽滤掉 M 个") no
/// longer applies: there is no filtering left to count, only the
/// cleared count and the final count. (Before v3.11 only the final
/// count was logged, so "refresh shows 8 nodes" could mean a
/// failing API or a big blocklist — indistinguishable from the log.)
fn refresh_summary_line(
    source: vpngate::NodeListSource,
    cleared: usize,
    final_count: usize,
    retained: usize,
) -> String {
    let name = match source {
        vpngate::NodeListSource::Api => "官方 API",
        vpngate::NodeListSource::WebScrape => "网页抓取",
        vpngate::NodeListSource::Cache => "缓存",
        vpngate::NodeListSource::Curated => "内嵌列表",
    };
    if retained == 0 {
        format!(
            "刷新完成（{}）：已清空屏蔽 {} 个，获取到 {} 个。",
            name, cleared, final_count
        )
    } else {
        format!(
            "刷新完成（{}）：已清空屏蔽 {} 个，获取到 {} 个（含手动/导入保留 {} 个）。",
            name, cleared, final_count, retained
        )
    }
}

/// The shared refresh-failure notice (Leo's exact wording,
/// 2026-11-08): both refresh buttons write this sentence VERBATIM
/// — in the log AND in the status bar — when their refresh fails,
/// with the way + reason appended in parentheses. Never reword it,
/// never split it into two sentences: the sentence is the prefix of
/// the returned line, so `contains` on the exact sentence always
/// matches.
fn refresh_failure_line(way: &str, reason: &str) -> String {
    format!(
        "当前方式刷新节点失败，请用另一种方式刷新（方式：{}；原因：{}）。",
        way, reason
    )
}

/// Read the system clipboard as text (`arboard`). Used by the
/// Ctrl+V keypress path and the File menu's clipboard import — the
/// `Event::Paste` path needs no read (eframe already read it).
fn read_clipboard_text() -> Result<String, String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard.get_text().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// CJK font: egui's default fonts have no Chinese glyphs, so load one from
// the OS in the constructor. Tries system paths in order; returns the
// first readable file. Prefers .ttf (single-face) over .ttc collections.
// ---------------------------------------------------------------------------

fn find_cjk_font() -> Option<Vec<u8>> {
    let mut candidates: Vec<std::path::PathBuf> = vec![
        // Windows (target platform: Windows 10 x64 — tried first)
        "C:\\Windows\\Fonts\\msyh.ttc".into(),
        "C:\\Windows\\Fonts\\msyhbd.ttc".into(),
        "C:\\Windows\\Fonts\\simsun.ttc".into(),
        "C:\\Windows\\Fonts\\simhei.ttf".into(),
        // macOS
        "/System/Library/Fonts/PingFang.ttc".into(),
        // Linux (this VM and most distros)
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc".into(),
        "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.ttc".into(),
    ];
    // Walk /usr/share/fonts for any NotoSansCJK* file (depth-limited).
    if let Ok(top) = std::fs::read_dir("/usr/share/fonts") {
        let mut stack: Vec<(std::path::PathBuf, usize)> =
            top.filter_map(|e| e.ok()).map(|e| (e.path(), 1)).collect();
        while let Some((dir, depth)) = stack.pop() {
            if depth > 3 {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        stack.push((path, depth + 1));
                    } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.contains("NotoSansCJK")
                            && name.contains("Regular")
                            && (name.ends_with(".ttf") || name.ends_with(".ttc"))
                        {
                            candidates.push(path);
                        }
                    }
                }
            }
        }
    }
    // Prefer .ttf over .ttc (single-face files parse everywhere).
    candidates.sort_by_key(|p| p.extension().map(|e| e != "ttf").unwrap_or(true));
    for path in candidates {
        if let Ok(bytes) = std::fs::read(&path) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct GuiApp {
    config: Config,
    /// Where the config was loaded from (`config.toml` next to the exe
    /// in portable mode); `None` when running on defaults.
    config_path: Option<std::path::PathBuf>,
    nodes: Vec<Node>,
    nodes_source: String,
    /// Anchor row: the last clicked row (an index into `self.nodes`,
    /// not a display position). Enter / Ctrl+R / the 探测 and 连接
    /// buttons act on this row; `None` means nothing is current and
    /// those actions are unavailable, as before.
    selected: Option<usize>,
    /// Multi-select set: node indices selected by click / Ctrl+click
    /// / Shift+click (see `click_row`). This is what 删除选中
    /// deletes, and the row highlight follows this set — not the
    /// anchor alone. The anchor is not necessarily in the set
    /// (Ctrl+click can toggle it out).
    selected_set: BTreeSet<usize>,
    /// Hostnames deleted from the list, kept out of every list load
    /// until unblocked. Mirrors `Config::blocked_hosts` (canonical
    /// completed hostnames — see `blocked_key`); persisted via
    /// auto-save. There is no restore button (v3.10): a host comes
    /// back by importing it (import unblocks it), by clearing the
    /// whole list with the File menu's 清空屏蔽列表 (v3.11), or by
    /// deleting it from `blocked_hosts` in config.toml.
    blocked_hosts: BTreeSet<String>,
    probes: HashMap<String, String>,
    /// Last successful probe latency per host (ms), parallel to
    /// `probes`: the 延迟/状态 sort reads this number, never
    /// re-parses the "N ms" display string. Set when a probe
    /// succeeds, cleared when a probe starts (the row shows
    /// "探测中…" then) or fails, so it never goes stale.
    probe_ms: HashMap<String, u64>,
    busy: Option<Busy>,
    /// Probe-all sweep state: the shared stop flag the 停止 button
    /// sets (the background task checks it before/after each probe),
    /// and the running counts shown in the progress line. `busy ==
    /// ProbingAll` is the sweep-active flag; the counters are only
    /// meaningful while it is set.
    probe_all_stop: Arc<AtomicBool>,
    probe_all_total: usize,
    probe_all_done: usize,
    probe_all_ok: usize,
    probe_all_failed: usize,
    status: String,
    error: String,
    log: Vec<String>,
    conn: Option<ActiveConnection>,
    // Settings (editable in the advanced section; start from config).
    front_enabled: bool,
    front_addr: String,
    front_user: String,
    front_pass: String,
    local_port: u16,
    allow_lan: bool,
    system_proxy: bool,
    /// Node-list column widths in pixels, in display order: country,
    /// ISP, 当前人数， 线路质量， 人均带宽， host:port, latency/status.
    /// Draggable at the header separators (every resizable column
    /// but the last has one); persisted to config.toml with the
    /// rest of the settings via auto-save. The status column (∞ for
    /// the connected node) is a fixed 28 px and is NOT in this
    /// array — it has no separator and is not resizable. Pre-v3.7
    /// configs stored only 4 widths and v3.12 configs 6; those
    /// migrate on load (see `de_col_widths` in config.rs), so old
    /// config files keep loading as-is.
    col_widths: [u16; 7],
    /// Node-list box height the user dragged to (v3.13 resize
    /// handle). `None` = never dragged: the list uses its formula
    /// height (`panel_h - 250`, at least 120 px) — see
    /// `effective_list_height`. Persisted as whole pixels in
    /// `config.ui.list_height`; `None` stays `None` on save, so a
    /// user who never drags keeps the formula behaviour.
    list_height: Option<f32>,
    /// Advanced-settings box height in pixels (v3.13 resize handle):
    /// the CollapsingHeader body scrolls inside it. Default 240 px.
    advanced_height: f32,
    /// Log box height in pixels (v3.13 resize handle). Default
    /// 90 px (the old hard-coded value).
    log_height: f32,
    /// Last frame's resize-handle rects, for the kittest drag tests
    /// (they need something to grab — the handles have no label).
    /// Test-only: never read in production.
    #[cfg(test)]
    list_handle_rect: Option<egui::Rect>,
    #[cfg(test)]
    advanced_handle_rect: Option<egui::Rect>,
    #[cfg(test)]
    log_handle_rect: Option<egui::Rect>,
    /// List sort: `None` = fetch order (startup default), `Some`
    /// = (column, direction) the user picked by clicking a
    /// sortable header （国家/地区 / 当前人数 / 线路质量 / 人均带宽 /
    /// 延迟/状态）. Clicking a different column restarts at that
    /// column's first-click direction (see `SortCol::default_dir`). Kept
    /// across refreshes; session-only, not persisted to config.toml.
    sort: Option<(SortCol, SortDir)>,
    /// Where the mouse was pressed while selecting a row (`None` when
    /// no press is in flight). egui only counts a click when the
    /// pointer moves under `max_click_dist` (6 px); a real mouse
    /// drifts past that while clicking a row, and the ScrollArea
    /// turns the gesture into a scroll drag — so the row loop also
    /// accepts a press-and-release on the same row within 12 px.
    row_press_pos: Option<egui::Pos2>,
    /// The modifier keys held when the row press started, latched
    /// next to `row_press_pos`. The row click reads its modifiers
    /// on the *release* frame (see `effective_click_mods`), and a
    /// user who lets go of Shift/Ctrl a beat before the mouse
    /// button would lose the gesture there — the press-time latch
    /// is what makes Shift+click select a range reliably.
    row_press_mods: Option<egui::Modifiers>,
    /// Which node the row press started on (`None` when no press is
    /// in flight, or when the press was not on a row at all). The
    /// tolerant-click path used to key off the rows' CURRENT rects
    /// on the release frame, which mis-selected whenever the rows
    /// moved between press and release — the list scrolling under
    /// the cursor, or a plain click on the vertical scrollbar
    /// (row rects span the full list width, including the
    /// scrollbar strip, so the track click selected whatever row
    /// sat at that height and the next delete removed THAT row
    /// while the one Leo meant stayed; the v3.9 delete bug). The
    /// tolerant path now fires only for the node recorded here.
    /// Recorded only when the press lands inside the list's clip
    /// rect, which excludes the scrollbar strips, so a scrollbar
    /// press records no row at all.
    row_press_node: Option<usize>,
    /// One-shot request from the arrow keys: after ↑/↓ moves the
    /// selection, the row loop scrolls the selected row into view
    /// (see the row loop). Only set when the selection actually
    /// changes; cleared when the row loop consumes it. Mouse clicks
    /// never set it — a clicked row is already visible.
    scroll_to_selected: bool,
    /// The node list's current vertical scroll offset (pixels, from
    /// the ScrollArea output each frame). The arrow-key test reads
    /// it to prove the list actually scrolled.
    node_list_scroll_y: f32,
    /// Whether the selected row is fully inside the node list's
    /// visible area vertically this frame (recomputed in the row
    /// loop from the clip rect; `false` when nothing is selected).
    /// The arrow-key test reads it to prove the follow-scroll works.
    selected_row_in_view: bool,
    /// Drop the `Event::Paste` eframe sends one frame after a Ctrl+V
    /// we already handled via the direct clipboard read (see
    /// `handle_clipboard_events`): without this the same paste would
    /// import twice. Set on the keypress frame, consumed (cleared)
    /// on the next frame whether or not a Paste event shows up.
    drop_next_paste: bool,
    /// How many hosts the in-flight refresh cleared from the
    /// blocklist when it started (see `start_fetch`). The Nodes
    /// handler consumes it for the refresh summary line, then
    /// resets it to 0. Always 0 outside a refresh.
    refresh_cleared_blocked: usize,
    /// Whether 高级设置 starts open. Production default is closed;
    /// the render test opens it so the review screenshots show the
    /// front-proxy section and the log.
    advanced_open: bool,
    /// Render-test aid: start the outer scroll area at the bottom, so
    /// the review screenshots show the log instead of the node list.
    render_scroll_bottom: bool,
    manual_host: String,
    manual_error: String,
    show_about: bool,
    /// System tray (v3.12, Windows only): the live tray icon.
    /// `None` on Linux and when tray creation failed on Windows —
    /// then X quits as before. Dropping the handle removes the icon,
    /// so the quit path `take()`s it.
    #[cfg(windows)]
    tray: Option<vpngate_client::tray::TrayHandle>,
    /// A second launch asked this instance to come forward
    /// (v3.15 single-instance): set by the watcher thread
    /// (`single_instance::spawn_show_watcher`, started in `new()`),
    /// consumed in `ui()` — the same effect as a tray double-click
    /// (`show_main_window`).
    show_requested: Arc<AtomicBool>,
    /// An explicit quit was requested (File menu 退出 / tray menu
    /// 退出): the next close request really quits instead of hiding
    /// to the tray. Set just before sending `ViewportCommand::Close`.
    quit_requested: bool,
    /// The main window is currently hidden in the tray.
    hidden_to_tray: bool,
    /// The one-time "已最小化到托盘…" hint has been shown.
    tray_hint_shown: bool,
    font_ok: bool,
    /// Last auto-save failure message (to show a repeated failure once).
    last_save_error: String,
    /// File logger (`vpngate-gui.log` next to the exe). `None` until
    /// `init_file_log` runs in `new()`; the logger itself no-ops when
    /// its file could not be opened. `for_tests` apps have none.
    file_logger: Option<FileLogger>,
    /// The log file's path (shown in the UI log at startup and next to
    /// the save button). `Some` even when the file could not be opened.
    log_path: Option<std::path::PathBuf>,
    /// RSS sampling (v3.14, diagnosis §7): when the app started
    /// (all RSS `t=` values are relative to this), which one-shot
    /// samples have fired, and the last periodic sample. The
    /// one-shot tags: T0 (first frame), T+5min (quiet baseline),
    /// C0 (connected), C+30min, D0 (disconnected) + D+10s, P0
    /// (probe-all done); plus one sample every 30 minutes. The
    /// three pass/fail tiers (Tier A/B/C, diagnosis §7.3) are
    /// judged from the log lines Leo sends back — the VM cannot
    /// produce Windows RSS numbers.
    started_at: Instant,
    rss_t0_done: bool,
    rss_t5_done: bool,
    rss_last_periodic: Instant,
    rss_connected_since: Option<Instant>,
    rss_conn30_done: bool,
    rss_disconnected_at: Option<Instant>,
    rss_disconnect_10s_done: bool,
    /// Last read of `font_atlas_fill_ratio()` (updated once per
    /// frame in `ui()`; the RSS log lines read this field, so
    /// `sample_rss` needs no `egui::Context` and stays callable
    /// from `apply_event` / `disconnect`). 0.0 before the first
    /// frame.
    last_atlas_fill: f32,
    /// Cached `log.join("\n")` for the log panel (v3.14, diagnosis
    /// §3 item 4): the old code re-joined up to 100 lines every
    /// frame. Rebuilt only when `log_text_dirty` (set by the only
    /// log writer, `log_line_at`).
    log_text_cache: String,
    log_text_dirty: bool,
    /// Cached display order + built rows (v3.14, diagnosis §3 item
    /// 7), both keyed by `list_fingerprint()`: (fingerprint,
    /// order) / (fingerprint, rows). A fingerprint change rebuilds;
    /// anything else reuses the cached values with no per-frame
    /// `String` allocation. The fingerprint hashes every field the
    /// rows or the order read (node display fields, `probes`,
    /// `probe_ms`, `sort`, connected node) — a missed input would
    /// show a stale list, so the hash inputs are the contract.
    order_cache: Option<(u64, Vec<usize>)>,
    rows_cache: Option<(u64, Vec<NodeRow>)>,
    /// How many times `build_rows` ran (test-only: the cache tests
    /// assert a second frame with an unchanged list does NOT
    /// rebuild). Never read in production.
    #[cfg(test)]
    rows_built: usize,
    /// True while this instance is exiting because the user chose
    /// 重启客户端 (v3.14): `perform_quit` then keeps the resume
    /// marker the restart just wrote; a manual quit
    /// (`restarting == false`) deletes it, so a later manual open
    /// never auto-connects.
    restarting: bool,
    /// A restart-resume auto-connect is in flight (v3.14): set by
    /// `try_resume` when it starts the connect, cleared by the
    /// `Connected` / `ConnectFailed` event — so those handlers can
    /// log the resume outcome explicitly ("已连回…" /
    /// "自动连接失败…，保持断开，不再重试").
    resume_pending: bool,
    event_tx: mpsc::Sender<GuiEvent>,
    event_rx: Option<mpsc::Receiver<GuiEvent>>,
}

impl Default for GuiApp {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            config: Config::default(),
            config_path: None,
            nodes: vpngate::curated_nodes(),
            nodes_source: "内嵌列表（28 个已知节点）".to_string(),
            selected: None,
            selected_set: BTreeSet::new(),
            blocked_hosts: BTreeSet::new(),
            probes: HashMap::new(),
            probe_ms: HashMap::new(),
            busy: None,
            probe_all_stop: Arc::new(AtomicBool::new(false)),
            probe_all_total: 0,
            probe_all_done: 0,
            probe_all_ok: 0,
            probe_all_failed: 0,
            status: "未连接".to_string(),
            error: String::new(),
            log: vec!["就绪。".to_string()],
            conn: None,
            front_enabled: false,
            front_addr: "127.0.0.1:1080".to_string(),
            front_user: String::new(),
            front_pass: String::new(),
            local_port: 10818,
            allow_lan: false,
            system_proxy: false,
            col_widths: vpngate_client::config::UiSettings::default().node_col_widths,
            list_height: None,
            advanced_height: vpngate_client::config::UiSettings::default().advanced_height
                as f32,
            log_height: vpngate_client::config::UiSettings::default().log_height as f32,
            #[cfg(test)]
            list_handle_rect: None,
            #[cfg(test)]
            advanced_handle_rect: None,
            #[cfg(test)]
            log_handle_rect: None,
            sort: None,
            row_press_pos: None,
            row_press_mods: None,
            row_press_node: None,
            scroll_to_selected: false,
            node_list_scroll_y: 0.0,
            selected_row_in_view: false,
            drop_next_paste: false,
            refresh_cleared_blocked: 0,
            advanced_open: false,
            render_scroll_bottom: false,
            manual_host: String::new(),
            manual_error: String::new(),
            show_about: false,
            #[cfg(windows)]
            tray: None,
            // A second launch asked this instance to come forward
            // (v3.15 single-instance): set by the watcher thread
            // in `single_instance::spawn_show_watcher`, consumed
            // in `ui()` — the same effect as a tray double-click.
            show_requested: Arc::new(AtomicBool::new(false)),
            quit_requested: false,
            hidden_to_tray: false,
            tray_hint_shown: false,
            font_ok: false,
            last_save_error: String::new(),
            file_logger: None,
            log_path: None,
            started_at: Instant::now(),
            rss_t0_done: false,
            rss_t5_done: false,
            rss_last_periodic: Instant::now(),
            rss_connected_since: None,
            rss_conn30_done: false,
            rss_disconnected_at: None,
            rss_disconnect_10s_done: false,
            last_atlas_fill: 0.0,
            log_text_cache: String::new(),
            log_text_dirty: true,
            order_cache: None,
            rows_cache: None,
            #[cfg(test)]
            rows_built: 0,
            restarting: false,
            resume_pending: false,
            event_tx: tx,
            event_rx: Some(rx),
        }
    }
}

/// Brand palette, coordinated with the app icon (solid indigo #1E40AF
/// + bold white ring since v3.15; a bold white shield in v3.14, a bold white V in v3.13, an indigo
/// → cyan gradient before that). Restrained on purpose: one accent (indigo), one
/// success accent (cyan/teal, used for the ∞ connected-node mark),
/// muted amber for warnings, soft red for errors — no multi-colour
/// mixing. Both themes follow the OS setting; these are per-theme
/// overrides on egui's defaults. Contrast checked (WCAG):
/// * light ink #1F2937 on warm off-white #F7F6F3 ≈ 13:1
/// * dark warm-white #F1F5F9 on deep slate #0F172A ≈ 15:1
/// * white on indigo selection #1E40AF ≈ 8.7:1, on #2563EB ≈ 5.1:1
/// * cyan ∞ #0E7490 on #F7F6F3 ≈ 4.9:1, #22D3EE on #0F172A ≈ 10:1
/// * error #B91C1C on #F7F6F3 ≈ 5.9:1, warn #B45309 ≈ 4.6:1
fn branded_visuals(theme: egui::Theme) -> egui::Visuals {
    use egui::Color32;
    let mut v = match theme {
        egui::Theme::Dark => egui::Visuals::dark(),
        egui::Theme::Light => egui::Visuals::light(),
    };
    match theme {
        egui::Theme::Dark => {
            v.override_text_color = Some(Color32::from_rgb(0xF1, 0xF5, 0xF9));
            v.panel_fill = Color32::from_rgb(0x0F, 0x17, 0x2A); // deep slate
            v.window_fill = Color32::from_rgb(0x1E, 0x29, 0x3B); // slate-800
            v.extreme_bg_color = Color32::from_rgb(0x0B, 0x12, 0x20);
            v.faint_bg_color = Color32::from_rgb(0x1E, 0x29, 0x3B);
            v.selection.bg_fill = Color32::from_rgb(0x25, 0x63, 0xEB);
            v.selection.stroke = egui::Stroke::new(1.0, Color32::WHITE);
            v.hyperlink_color = Color32::from_rgb(0x93, 0xC5, 0xFD);
            v.error_fg_color = Color32::from_rgb(0xFC, 0xA5, 0xA5);
            v.warn_fg_color = Color32::from_rgb(0xFC, 0xD3, 0x4D);
            v.widgets.hovered.bg_fill = Color32::from_rgb(0x1E, 0x3A, 0x8A);
            v.widgets.active.bg_fill = Color32::from_rgb(0x1E, 0x40, 0xAF);
            v.widgets.inactive.bg_fill = Color32::from_rgb(0x1E, 0x29, 0x3B);
        }
        egui::Theme::Light => {
            v.override_text_color = Some(Color32::from_rgb(0x1F, 0x29, 0x37)); // ink
            v.panel_fill = Color32::from_rgb(0xF7, 0xF6, 0xF3); // warm off-white
            v.window_fill = Color32::WHITE;
            v.extreme_bg_color = Color32::from_rgb(0xF8, 0xFA, 0xFC);
            v.faint_bg_color = Color32::from_rgb(0xF1, 0xF5, 0xF9);
            v.selection.bg_fill = Color32::from_rgb(0x1E, 0x40, 0xAF);
            v.selection.stroke = egui::Stroke::new(1.0, Color32::WHITE);
            v.hyperlink_color = Color32::from_rgb(0x1E, 0x40, 0xAF);
            v.error_fg_color = Color32::from_rgb(0xB9, 0x1C, 0x1C);
            v.warn_fg_color = Color32::from_rgb(0xB4, 0x53, 0x09);
            v.widgets.hovered.bg_fill = Color32::from_rgb(0xE0, 0xE7, 0xFF);
            v.widgets.active.bg_fill = Color32::from_rgb(0xC7, 0xD2, 0xFE);
            v.widgets.inactive.bg_fill = Color32::WHITE;
        }
    }
    v
}

/// Accent colour for the ∞ connected-node mark (not the only signal —
/// the glyph itself marks the row). Darker cyan on light so the
/// contrast stays above 4.5:1; bright cyan on dark.
fn infinity_accent(dark_mode: bool) -> egui::Color32 {
    if dark_mode {
        egui::Color32::from_rgb(0x22, 0xD3, 0xEE)
    } else {
        egui::Color32::from_rgb(0x0E, 0x74, 0x90)
    }
}

impl GuiApp {
    /// Fonts + text sizes + theme, set up once. Returns whether a CJK
    /// font was found. Shared by `new` and the render test constructor.
    fn setup_visuals(cc: &eframe::CreationContext<'_>) -> bool {
        cc.egui_ctx.set_theme(egui::ThemePreference::System);
        cc.egui_ctx
            .set_visuals_of(egui::Theme::Dark, branded_visuals(egui::Theme::Dark));
        cc.egui_ctx
            .set_visuals_of(egui::Theme::Light, branded_visuals(egui::Theme::Light));
        cc.egui_ctx.all_styles_mut(|style| {
            style.text_styles = [
                (
                    egui::TextStyle::Heading,
                    egui::FontId::new(20.0, egui::FontFamily::Proportional),
                ),
                (
                    egui::TextStyle::Body,
                    egui::FontId::new(15.0, egui::FontFamily::Proportional),
                ),
                (
                    egui::TextStyle::Button,
                    egui::FontId::new(15.0, egui::FontFamily::Proportional),
                ),
                (
                    egui::TextStyle::Monospace,
                    egui::FontId::new(13.0, egui::FontFamily::Monospace),
                ),
                (
                    egui::TextStyle::Small,
                    egui::FontId::new(12.0, egui::FontFamily::Proportional),
                ),
            ]
            .into();
            // Roomier controls: the default 8x4 spacing makes the
            // action buttons look cramped at 15 pt text.
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 6.0);
        });
        if let Some(bytes) = find_cjk_font() {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "cjk".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(bytes)),
            );
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                fam.insert(0, "cjk".to_owned());
            }
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                fam.insert(0, "cjk".to_owned());
            }
            cc.egui_ctx.set_fonts(fonts);
            true
        } else {
            false
        }
    }

    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        app.font_ok = Self::setup_visuals(cc);
        // Portable config first: the session header in the file log
        // records the config path and the front-proxy setting it loaded.
        // Nothing is read from or written to the user profile.
        let cfg_path = Config::resolve_config_path(None);
        if let Some(p) = &cfg_path {
            if let Ok(cfg) = Config::load(Some(p)) {
                app.apply_config(&cfg);
            }
        }
        app.config_path = cfg_path;
        // File log: from here on every log_line / log_warn / log_error
        // (and every set_error) is also appended to vpngate-gui.log.
        app.init_file_log();
        // System tray (v3.12, Windows only): X hides to the tray.
        // A failure here is not fatal — log it and run without a
        // tray, so X quits as before.
        #[cfg(windows)]
        match vpngate_client::tray::TrayHandle::new() {
            Ok(t) => app.tray = Some(t),
            Err(e) => app.log_warn(format!("托盘创建失败：{e}，点 X 会直接退出。")),
        }
        // v3.15 single-instance: a second launch signals this
        // instance (named event on Windows) instead of opening
        // another window. The watcher thread raises
        // `show_requested` and asks for a repaint; `ui()` shows
        // the window — the same effect as a tray double-click.
        // Only the primary instance ever reaches `new()` (a second
        // launch exits in `main()`), so the watcher always belongs
        // to the lock owner.
        let show_flag = app.show_requested.clone();
        let show_ctx = cc.egui_ctx.clone();
        vpngate_client::single_instance::spawn_show_watcher(show_flag, move || {
            show_ctx.request_repaint();
        });
        if !app.font_ok {
            app.log_warn("未找到系统里的中文字体，中文可能显示为方框。".to_string());
        }
        // No config file at all (fresh folder, e.g. a new portable
        // version unzipped next to the old one): say so once, and tell
        // the user how to carry their settings over. The portable
        // storage design is unchanged — config stays next to the exe.
        if app.config_path.is_none() {
            app.log_line(
                "未找到 config.toml：如从旧版升级，把旧文件夹里的 config.toml 与 nodes_cache.json 复制到新版 exe 旁边即可保留设置。"
                    .to_string(),
            );
        }
        // No auto-refresh on startup: a refresh with the front proxy
        // off once hung for 85 s (direct fetch to vpngate.net, no
        // timeout). Load the cached list if there is one, else the
        // bundled 28 — no network at all — and let the user refresh
        // manually. `start_fetch` is still what the 刷新节点 button
        // runs; only the startup call is gone.
        let (nodes, cache_age) = vpngate::fallback_nodes();
        let source = if cache_age.is_some() {
            vpngate::NodeListSource::Cache
        } else {
            vpngate::NodeListSource::Curated
        };
        // The blocklist (loaded from config.toml just above) filters
        // the startup list too, like every other load.
        let nodes = app.apply_blocklist(nodes);
        let n = nodes.len();
        app.nodes = nodes;
        app.nodes_source = source.label(n, cache_age);
        let loaded = format!(
            "已加载{}。点右上角“刷新节点”获取最新。",
            app.nodes_source
        );
        app.status = loaded.clone();
        app.log_line(loaded);
        // v3.14 restart-resume: a marker written by the instance
        // that restarted into this one auto-connects to the same
        // node once, via the normal start_connect path. No marker
        // (a manual open) → nothing happens here.
        app.try_resume(cc.egui_ctx.clone());
        app
    }

    /// Test-only constructor: no font loading, no config file, no network.
    #[cfg(test)]
    fn for_tests() -> Self {
        Self::default()
    }

    /// Render-test constructor: real fonts and styles, but no config
    /// file and no network fetch (no tokio runtime in the harness).
    #[cfg(test)]
    fn for_render_tests(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        app.font_ok = Self::setup_visuals(cc);
        // 高级设置 open: the review shots must show the front-proxy
        // section and its test button, not just the collapsed header.
        app.advanced_open = true;
        // No fetch runs in the harness; don't claim one is starting.
        app.log = vec!["就绪。".to_string()];
        app
    }

    /// Render-test constructor with the outer scroll area at the bottom
    /// (shows the end of 高级设置 and the log).
    #[cfg(test)]
    fn for_render_tests_scrolled(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::for_render_tests(cc);
        app.render_scroll_bottom = true;
        app
    }

    /// Effective node-list box height for this frame (v3.13): the
    /// user's dragged value wins (clamped to the current panel), and
    /// until the first drag the old formula (`panel_h - 250`, at
    /// least 120 px) is the default — so a fresh install and an old
    /// config look exactly as before.
    fn effective_list_height(&self, panel_h: f32) -> f32 {
        match self.list_height {
            Some(h) => {
                vpngate_client::config::clamp_list_height(h, panel_h)
            }
            None => (panel_h - 250.0).max(120.0),
        }
    }

    fn apply_config(&mut self, cfg: &Config) {
        self.config = cfg.clone();
        self.front_enabled = cfg.front_proxy.enabled;
        self.front_addr = cfg.front_proxy.addr.clone();
        self.front_user = cfg.front_proxy.username.clone().unwrap_or_default();
        self.front_pass = cfg.front_proxy.password.clone().unwrap_or_default();
        self.local_port = cfg.listen.local_port;
        self.allow_lan = cfg.listen.allow_lan;
        self.system_proxy = cfg.system_proxy.enabled;
        self.col_widths = cfg.ui.node_col_widths;
        self.list_height = cfg.ui.list_height.map(|h| h as f32);
        // Clamp hand-edited values into range on load (a config
        // file may carry anything); the list height is clamped per
        // frame instead, since its ceiling depends on the panel.
        self.advanced_height = vpngate_client::config::clamp_advanced_height(
            cfg.ui.advanced_height as f32,
        );
        self.log_height =
            vpngate_client::config::clamp_log_height(cfg.ui.log_height as f32);
        self.blocked_hosts = cfg.blocked_hosts.iter().cloned().collect();
    }

    /// Build the current settings as a Config (for saving).
    fn current_config(&self) -> Config {
        let mut cfg = self.config.clone();
        cfg.front_proxy.enabled = self.front_enabled;
        cfg.front_proxy.addr = self.front_addr.clone();
        cfg.front_proxy.username = if self.front_user.is_empty() {
            None
        } else {
            Some(self.front_user.clone())
        };
        cfg.front_proxy.password = if self.front_pass.is_empty() {
            None
        } else {
            Some(self.front_pass.clone())
        };
        cfg.listen.local_port = self.local_port;
        cfg.listen.allow_lan = self.allow_lan;
        cfg.system_proxy.enabled = self.system_proxy;
        cfg.ui.node_col_widths = self.col_widths;
        // Whole pixels on save (config stores u16); `None` stays
        // `None`, so the formula default survives until a drag.
        cfg.ui.list_height = self.list_height.map(|h| h.round() as u16);
        cfg.ui.advanced_height = self.advanced_height.round() as u16;
        cfg.ui.log_height = self.log_height.round() as u16;
        // BTreeSet iteration is sorted, so the saved list is in a
        // stable order across runs.
        cfg.blocked_hosts = self.blocked_hosts.iter().cloned().collect();
        cfg
    }

    /// Save the current settings to `config.toml` next to the exe
    /// (portable mode). Reports the result in the log and status line.
    /// With auto-save on, this is normally already done — the button is
    /// an explicit "save again now" that confirms it.
    fn save_settings(&mut self) {
        let Some(path) = Config::portable_config_path() else {
            self.set_error("保存失败：找不到程序所在目录。".to_string());
            return;
        };
        match self.current_config().save(&path) {
            Ok(()) => {
                self.config = self.current_config();
                self.config_path = Some(path.clone());
                self.error.clear();
                self.status = "设置已保存到程序目录下的 config.toml。".to_string();
                self.log_line(format!("设置已保存到 {}。", path.display()));
            }
            Err(e) => {
                self.set_error(format!("保存设置失败：{}。程序目录可能不可写。", e));
            }
        }
    }

    /// Quiet save used by auto-save: writes the file without touching
    /// the status line or log (a save per keystroke would spam both).
    /// A failure is shown once per distinct error message.
    fn save_settings_quiet(&mut self) {
        let Some(path) = Config::portable_config_path() else {
            return;
        };
        match self.current_config().save(&path) {
            Ok(()) => {
                self.config_path = Some(path);
                if !self.last_save_error.is_empty() {
                    self.last_save_error.clear();
                    self.error.clear();
                }
            }
            Err(e) => {
                let msg = format!("自动保存设置失败：{}。程序目录可能不可写。", e);
                if msg != self.last_save_error {
                    self.last_save_error = msg.clone();
                    self.set_error(msg);
                }
            }
        }
    }

    /// If any setting differs from the last saved/loaded config, persist
    /// it now — so closing the app without clicking 保存设置 loses
    /// nothing (front proxy, LAN sharing, system proxy, local port).
    /// Called at the end of every frame and on exit.
    fn auto_save_if_dirty(&mut self) {
        let cfg = self.current_config();
        if cfg != self.config {
            self.config = cfg;
            self.save_settings_quiet();
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.config.tunnel.timeout_secs.max(1))
    }

    fn connector(&self) -> Connector {
        connector_for(
            self.front_enabled,
            &self.front_addr,
            &self.front_user,
            &self.front_pass,
        )
    }

    /// Start the file log (`vpngate-gui.log` next to the exe, same
    /// portable dir as config.toml; `./vpngate-gui.log` when the exe
    /// dir is unknown). Writes the session header (start time,
    /// version, exe path, config path, front proxy enabled + address —
    /// never the password) and replays the lines already on screen, so
    /// the file covers the whole run from startup. A file that cannot
    /// be opened warns once in the on-screen log and disables file
    /// logging for this run; the GUI never crashes over it.
    fn init_file_log(&mut self) {
        let path = Config::portable_dir()
            .map(|d| filelog::log_path_for_dir(&d))
            .unwrap_or_else(|| std::path::PathBuf::from("vpngate-gui.log"));
        self.log_path = Some(path.clone());
        let mut logger = FileLogger::new(&path);
        let exe = std::env::current_exe().ok();
        logger.write_header(&self.config, exe.as_deref(), self.config_path.as_deref());
        // Replay what is already on screen (the "就绪…" startup line),
        // so the file covers the run from the start.
        for line in self.log.clone() {
            logger.log(LogLevel::Info, &line);
        }
        if logger.open_failed {
            let err = logger.open_error.clone().unwrap_or_default();
            self.file_logger = Some(logger);
            self.log_warn(format!(
                "日志文件打不开（{}）：{}。本次运行不写文件日志，界面日志不受影响。",
                path.display(),
                err
            ));
        } else {
            self.file_logger = Some(logger);
            self.log_line(format!("日志文件：{}。报问题时请附上它。", path.display()));
        }
    }

    /// Info: on-screen log + file log at [INFO].
    fn log_line(&mut self, line: String) {
        self.log_line_at(LogLevel::Info, line);
    }

    /// Write Leo's verbatim refresh-failure notice (see
    /// `refresh_failure_line`) to the status bar AND the log.
    /// Both refresh buttons use this when their refresh fails.
    fn report_refresh_failure(&mut self, way: &str, reason: &str) {
        let line = refresh_failure_line(way, reason);
        self.status = line.clone();
        self.log_line(line);
    }

    /// Warning: on-screen log + file log at [WARN].
    fn log_warn(&mut self, line: String) {
        self.log_line_at(LogLevel::Warn, line);
    }

    /// Error: on-screen log + file log at [ERROR].
    fn log_error(&mut self, line: String) {
        self.log_line_at(LogLevel::Error, line);
    }

    fn log_line_at(&mut self, level: LogLevel, line: String) {
        if let Some(fl) = self.file_logger.as_mut() {
            fl.log(level, &line);
        }
        self.log.push(line);
        if self.log.len() > 100 {
            let excess = self.log.len() - 100;
            self.log.drain(..excess);
        }
        // The log panel's cached join is stale now (v3.14 §3 item 4).
        self.log_text_dirty = true;
    }

    /// The log panel's text: `log.join("\n")`, cached and rebuilt
    /// only when a line was added since the last call (v3.14,
    /// diagnosis §3 item 4 — the old code re-joined up to 100 lines
    /// every frame). The `TextEdit` shows it read-only.
    fn cached_log_text(&mut self) -> &str {
        if self.log_text_dirty {
            self.log_text_cache = self.log.join("\n");
            self.log_text_dirty = false;
        }
        &self.log_text_cache
    }

    // --- RSS sampling (v3.14, diagnosis §7) -------------------------

    /// This process's working set + pagefile usage, in bytes.
    /// Windows: `GetProcessMemoryInfo` via a direct `psapi` extern
    /// — zero new dependencies, no `Cargo.toml` change. The task
    /// manager's "内存" column is the PRIVATE working set while
    /// `WorkingSetSize` includes shared pages, so the absolute
    /// numbers differ by a few MB; the log lines are for the
    /// longitudinal growth curve (same口径, deltas), not for
    /// matching a screenshot. `None` on Linux (the VM build logs
    /// the line with `n/a` so the plumbing is still verifiable).
    #[cfg(windows)]
    fn read_working_set() -> Option<(u64, u64)> {
        use std::ffi::c_void;
        #[repr(C)]
        #[allow(non_snake_case)]
        struct ProcessMemoryCounters {
            cb: u32,
            PageFaultCount: u32,
            PeakWorkingSetSize: usize,
            WorkingSetSize: usize,
            QuotaPeakPagedPoolUsage: usize,
            QuotaPagedPoolUsage: usize,
            QuotaPeakNonPagedPoolUsage: usize,
            QuotaNonPagedPoolUsage: usize,
            PagefileUsage: usize,
            PeakPagefileUsage: usize,
        }
        #[link(name = "psapi")]
        extern "system" {
            fn GetCurrentProcess() -> *mut c_void;
            fn GetProcessMemoryInfo(
                h_process: *mut c_void,
                ppsmem_counters: *mut ProcessMemoryCounters,
                cb: u32,
            ) -> i32;
        }
        let mut counters = ProcessMemoryCounters {
            cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };
        let ok = unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut counters,
                counters.cb,
            )
        };
        if ok == 0 {
            return None;
        }
        Some((counters.WorkingSetSize as u64, counters.PagefileUsage as u64))
    }

    #[cfg(not(windows))]
    fn read_working_set() -> Option<(u64, u64)> {
        None
    }

    /// Write one `[RSS]` line to the on-screen + file log (diagnosis
    /// §7.2): `t` (elapsed since startup), `tag` (the event),
    /// working set + pagefile, font-atlas fill ratio, live tunnel
    /// sessions, connected?, node count, dropped `ConnLog` lines.
    /// Leo sends `vpngate-gui.log` back and the curve is read off
    /// these lines; the three tiers (diagnosis §7.3) are judged
    /// from them, not from a screenshot.
    fn sample_rss(&mut self, tag: &str) {
        let elapsed = self.started_at.elapsed();
        let t = format!(
            "+{:03}:{:02}",
            elapsed.as_secs() / 3600,
            (elapsed.as_secs() % 3600) / 60
        );
        let sessions = self
            .conn
            .as_ref()
            .map(|c| c.tunnel.session_count())
            .unwrap_or(0);
        let (ws, pf) = match Self::read_working_set() {
            Some((w, p)) => (
                format!("{:.1}MB", w as f64 / 1_048_576.0),
                format!("{:.1}MB", p as f64 / 1_048_576.0),
            ),
            None => ("n/a".to_string(), "n/a".to_string()),
        };
        self.log_line(format!(
            "[RSS] t={} tag={} working_set={} pagefile={} atlas_fill={:.2} sessions={} conn={} nodes={} conn_log_dropped={}",
            t,
            tag,
            ws,
            pf,
            self.last_atlas_fill,
            sessions,
            self.conn.is_some(),
            self.nodes.len(),
            vpngate_client::socks5::conn_log_dropped()
        ));
    }

    /// Which timed RSS samples are due at `now` (pure: takes the
    /// clock so tests can drive it without waiting). One-shot tags
    /// fire once; `periodic` fires every 30 minutes from startup.
    fn rss_timer_tags(&self, now: Instant) -> Vec<&'static str> {
        let mut tags = Vec::new();
        if !self.rss_t0_done {
            tags.push("startup");
        }
        if !self.rss_t5_done
            && now.duration_since(self.started_at) >= Duration::from_secs(5 * 60)
        {
            tags.push("startup_plus_5min");
        }
        if !self.rss_conn30_done {
            if let Some(since) = self.rss_connected_since {
                if now.duration_since(since) >= Duration::from_secs(30 * 60) {
                    tags.push("connected_plus_30min");
                }
            }
        }
        if !self.rss_disconnect_10s_done {
            if let Some(at) = self.rss_disconnected_at {
                if now.duration_since(at) >= Duration::from_secs(10) {
                    tags.push("disconnected_plus_10s");
                }
            }
        }
        if now.duration_since(self.rss_last_periodic) >= Duration::from_secs(30 * 60) {
            tags.push("periodic");
        }
        tags
    }

    /// Sample every RSS tag due now (called once per frame from
    /// `ui()`). Marks one-shot tags done as they fire.
    fn check_rss_timers(&mut self) {
        let now = Instant::now();
        for tag in self.rss_timer_tags(now) {
            match tag {
                "startup" => self.rss_t0_done = true,
                "startup_plus_5min" => self.rss_t5_done = true,
                "connected_plus_30min" => self.rss_conn30_done = true,
                "disconnected_plus_10s" => self.rss_disconnect_10s_done = true,
                "periodic" => self.rss_last_periodic = now,
                _ => {}
            }
            self.sample_rss(tag);
        }
    }

    /// Set the error banner AND log it at [ERROR] (both logs). Use
    /// this instead of assigning `self.error` directly — a bare
    /// assignment is invisible in the file log, which is exactly how
    /// a failure ends up with no trace to debug from.
    fn set_error(&mut self, msg: String) {
        self.error = msg.clone();
        self.log_error(msg);
    }

    fn start_fetch(&mut self, ctx: egui::Context) {
        if self.busy.is_some() {
            return;
        }
        // v3.11 (Leo's call): a refresh always brings the full list
        // back. Delete is session-only hiding from here on — the
        // blocklist is cleared (in memory AND in config.toml, so a
        // restart does not resurrect it) BEFORE fetching, and the
        // incoming list is shown unfiltered. The cleared count is
        // stashed for the Nodes handler's summary line. Startup
        // loads do NOT clear: only an explicit refresh does.
        self.refresh_cleared_blocked = self.clear_blocklist();
        self.busy = Some(Busy::Fetching);
        self.status = "正在拉取节点列表…".to_string();
        let tx = self.event_tx.clone();
        let connector = self.connector();
        // spawn_task (not raw tokio::spawn): no-ops when there is no
        // runtime, so the kittest harness can click 刷新节点 and
        // observe the busy flag + the cleared blocklist, then drive
        // the Nodes event by hand.
        Self::spawn_task(async move {
            let res = fetch_flow(&connector).await;
            let _ = tx.send(GuiEvent::Nodes(res));
            ctx.request_repaint();
        });
    }

    /// v3.15 "从API刷新节点": refresh from the official API (CSV)
    /// ONLY — no web scrape, no cache, no curated list. Unlike
    /// `start_fetch` it does NOT clear the blocklist first: the
    /// blocklist keeps filtering as usual (deleted nodes stay
    /// hidden), and a failed API fetch changes nothing at all — the
    /// list and the blocklist stay exactly as they were. Success
    /// goes through the same `Nodes` path as a normal refresh
    /// (merge, cache, summary); failure arrives as
    /// `ApiRefreshFailed` and is reported in Leo's exact words
    /// instead of falling back silently.
    fn start_fetch_api_only(&mut self, ctx: egui::Context) {
        if self.busy.is_some() {
            return;
        }
        self.busy = Some(Busy::Fetching);
        self.status = "正在从官方 API 拉取节点列表…".to_string();
        let tx = self.event_tx.clone();
        let connector = self.connector();
        // spawn_task no-ops without a runtime (kittest): the busy
        // flag stays set and the caller drives the result by hand,
        // same as `start_fetch`.
        Self::spawn_task(async move {
            match fetch_api_flow(&connector).await {
                Ok(nodes) => {
                    let _ = tx.send(GuiEvent::Nodes(vpngate::NodeListUpdate {
                        nodes,
                        source: vpngate::NodeListSource::Api,
                        cache_age_secs: None,
                        api_error: None,
                        web_error: None,
                    }));
                }
                Err(reason) => {
                    let _ = tx.send(GuiEvent::ApiRefreshFailed { reason });
                }
            }
            ctx.request_repaint();
        });
    }

    /// Spawn a background task. No-ops when there is no tokio runtime
    /// (the kittest harness has none): the busy flag stays set and the
    /// caller observes it, which is exactly what the shortcut tests
    /// assert. Production always runs inside the runtime `main`
    /// creates (`rt.enter()`), so this never skips there.
    fn spawn_task<F>(f: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(f);
        }
    }

    fn start_probe(&mut self, ctx: egui::Context) {
        let Some(i) = self.selected else { return };
        let Some(node) = self.nodes.get(i) else {
            return;
        };
        if self.busy.is_some() {
            return;
        }
        let target = node.host.clone();
        let port = node.port;
        // The dialled target (and the start line) uses the completed
        // hostname: a bare DDNS label from the node list
        // ("public-vpn-192") becomes its full FQDN, so the log shows
        // exactly which host:port is being dialled. `target` itself
        // stays raw: it is the probes-map key and the table looks the
        // status up by the node's stored host.
        let target_str = match port {
            Some(p) => format!("{}:{}", vpngate::complete_ddns_host(&target), p),
            None => vpngate::complete_ddns_host(&target),
        };
        self.busy = Some(Busy::Probing);
        // Probing goes through the front proxy when it is on (same
        // chain as refresh/connect), so say so: when the proxy is down,
        // the probe fails for the proxy's sake, not the node's.
        if self.front_enabled {
            self.status = format!("正在探测 {}（经前置代理 {}）…", target_str, self.front_addr);
            self.log_line(format!(
                "开始探测 {}（经前置代理 {}）。",
                target_str, self.front_addr
            ));
        } else {
            self.status = format!("正在探测 {}…", target_str);
        }
        self.probes.insert(target.clone(), "探测中…".to_string());
        // A re-probe must not keep the old latency: until this probe
        // finishes, the node sorts with the unprobed group.
        self.probe_ms.remove(&target);
        let tx = self.event_tx.clone();
        let connector = self.connector();
        let timeout = self.timeout();
        Self::spawn_task(async move {
            let res = probe_flow(&connector, &target_str, timeout).await;
            let _ = tx.send(GuiEvent::Probe {
                host: target,
                result: res,
            });
            ctx.request_repaint();
        });
    }

    /// Snapshot of the nodes to probe, in display order (see
    /// `display_indices`, so a sorted list sweeps in the shown
    /// order): (raw host — the probes-map key — and the dialled
    /// target string, host:port with the DDNS suffix completed, like
    /// `start_probe` builds it). A snapshot, not indices: the list
    /// can gain a manually-added node mid-sweep, which would shift
    /// indices under a stored queue.
    fn probe_all_targets(&mut self) -> Vec<(String, String)> {
        self.display_indices()
            .into_iter()
            .filter_map(|i| {
                let n = self.nodes.get(i)?;
                let target = match n.port {
                    Some(p) => format!("{}:{}", vpngate::complete_ddns_host(&n.host), p),
                    None => vpngate::complete_ddns_host(&n.host),
                };
                Some((n.host.clone(), target))
            })
            .collect()
    }

    /// Start a probe-all sweep: every node in the list, in display
    /// order, one at a time. Blocked when another job is running or
    /// the list is empty (the button is disabled then too).
    fn start_probe_all(&mut self, ctx: egui::Context) {
        if self.busy.is_some() || self.nodes.is_empty() {
            return;
        }
        let targets = self.probe_all_targets();
        if targets.is_empty() {
            return;
        }
        let total = targets.len();
        self.probe_all_stop.store(false, Ordering::Relaxed);
        self.probe_all_total = total;
        self.probe_all_done = 0;
        self.probe_all_ok = 0;
        self.probe_all_failed = 0;
        self.busy = Some(Busy::ProbingAll);
        self.status = format!("正在探测全部：0/{}…", total);
        self.log_line(format!(
            "开始探测全部：{} 个节点（按当前显示顺序，一个一个探测）。",
            total
        ));
        // The first row shows "探测中…" right away; later rows get
        // it from the ProbeAllProgress event before their probe.
        if let Some((first, _)) = targets.first() {
            self.probes.insert(first.clone(), "探测中…".to_string());
            self.probe_ms.remove(first);
        }
        let tx = self.event_tx.clone();
        let connector = self.connector();
        let timeout = self.timeout();
        let stop = self.probe_all_stop.clone();
        Self::spawn_task(async move {
            probe_all_flow(&connector, targets, timeout, stop, tx, ctx).await;
        });
    }

    /// Ask the running sweep to stop after the node in flight
    /// finishes. The busy flag stays set until the ProbeAllDone
    /// event arrives; results already out are kept.
    fn stop_probe_all(&mut self) {
        if self.busy != Some(Busy::ProbingAll) {
            return;
        }
        self.probe_all_stop.store(true, Ordering::Relaxed);
        self.status = format!(
            "正在停止探测全部（等当前节点测完，已测 {}/{}）…",
            self.probe_all_done, self.probe_all_total
        );
        self.log_line("已请求停止探测全部，当前节点测完后停下。".to_string());
    }

    /// Addresses to actually bind for the next connection, from the
    /// live UI fields: the local port, or the same port on all
    /// interfaces when LAN sharing is on (one mixed server).
    fn listen_addrs(&self) -> Vec<String> {
        self.current_config().listen.listen_addrs()
    }

    /// What the user sees for the next connection's local proxy.
    fn listen_display(&self) -> String {
        self.current_config().listen.display_addrs()
    }

    fn start_connect(&mut self, ctx: egui::Context) {
        let Some(i) = self.selected else { return };
        let Some(node) = self.nodes.get(i) else {
            return;
        };
        if self.busy.is_some() {
            return;
        }
        let target = match node.port {
            // Complete a bare DDNS label, like start_probe does, so
            // the start line and the connection label show the full
            // host:port actually dialled.
            Some(p) => format!("{}:{}", vpngate::complete_ddns_host(&node.host), p),
            None => vpngate::complete_ddns_host(&node.host),
        };
        // v3.13 switch: already connected to another node? Disconnect
        // first (sync: aborts the serve tasks, restores the system
        // proxy, logs the 已断开 line), then fall through to the
        // normal connect flow below, which logs the 开始连接 line.
        // Connected to this very node: no-op — never a pointless
        // disconnect-and-reconnect of the same node.
        if self.conn.is_some() {
            if self.selected_is_connected() {
                return;
            }
            self.disconnect();
        }
        let listen_addrs = self.listen_addrs();
        let listen_display = self.listen_display();
        self.busy = Some(Busy::Connecting);
        self.status = format!("正在连接 {}…", target);
        self.error.clear();
        // Log the start line with the full target (host:port when the
        // port is known, bare host otherwise — the candidates are
        // resolved inside connect_flow). The probe start line already
        // logs its target; the connect had none, so a failed connect
        // left no trace of which host:port it actually dialled.
        if self.front_enabled {
            self.log_line(format!(
                "开始连接 {}（经前置代理 {}）。",
                target, self.front_addr
            ));
        } else {
            self.log_line(format!("开始连接 {}。", target));
        }
        let tx = self.event_tx.clone();
        let connector = self.connector();
        let timeout = self.timeout();
        let system_proxy = self.system_proxy;
        let service = self.config.system_proxy.service.clone();
        Self::spawn_task(async move {
            // Per-connection lines from the mixed proxy go through
            // this channel into the GUI log (GuiEvent::ConnLog);
            // the forwarder joins the connection's serve tasks, so
            // disconnecting aborts it too. v3.14: BOUNDED (512,
            // `CONN_LOG_CAPACITY`) — the old unbounded channel could
            // queue log lines without limit while the UI was stalled;
            // overflow lines are now dropped + counted (see
            // `emit_conn_log`), never queued.
            let (conn_tx, mut conn_rx) =
                tokio::sync::mpsc::channel::<String>(
                    vpngate_client::socks5::CONN_LOG_CAPACITY,
                );
            let tx2 = tx.clone();
            match connect_flow(
                connector,
                target.clone(),
                listen_addrs,
                listen_display,
                timeout,
                system_proxy,
                service,
                Some(conn_tx),
            )
            .await
            {
                Ok(mut c) => {
                    c.serve.push(tokio::spawn(async move {
                        while let Some(line) = conn_rx.recv().await {
                            let _ = tx2.send(GuiEvent::ConnLog(line));
                        }
                    }));
                    let _ = tx.send(GuiEvent::Connected(Box::new(c)));
                }
                Err(e) => {
                    let _ = tx.send(GuiEvent::ConnectFailed(e));
                }
            }
            ctx.request_repaint();
        });
    }

    /// Test the front proxy (button next to the front-proxy settings).
    /// Only runs when the front proxy is on — with it off there is
    /// nothing to test and a "direct" result would be misleading.
    /// The address is snapshotted at click time: the start line, the
    /// progress and the result must all name the address the test
    /// actually used, even if the field is edited mid-test.
    fn start_test_front_proxy(&mut self, ctx: egui::Context) {
        if !self.front_enabled || self.busy.is_some() {
            return;
        }
        let addr = self.front_addr.clone();
        self.busy = Some(Busy::TestingFrontProxy);
        self.status = format!("正在测试前置代理 {}…", addr);
        self.log_line(format!(
            "开始测试前置代理 {}（到 Google 与 vpngate.net，每站最多 10 秒）。",
            addr
        ));
        let tx = self.event_tx.clone();
        let connector = self.connector();
        tokio::spawn(async move {
            let (google, vpngate) =
                front_proxy_test_flow(&connector, FRONT_PROXY_TEST_TIMEOUT, &tx).await;
            let _ = tx.send(GuiEvent::FrontProxyTest {
                addr,
                google,
                vpngate,
            });
            ctx.request_repaint();
        });
    }

    fn disconnect(&mut self) {
        if let Some(c) = self.conn.take() {
            for s in c.serve {
                s.abort();
            }
            if let Some(g) = c.proxy_guard {
                g.unset();
            }
            // Dropping the last tunnel Arc closes the TLS stream.
            self.log_line(format!("已断开 {}（虚拟 IP {}）。", c.node_label, c.vip));
        }
        self.status = "未连接".to_string();
        self.error.clear();
        // v3.14 RSS: disconnect sample now + another 10 s later
        // (whether the disconnect actually released the tunnel is
        // the §4.1 evidence — see `check_rss_timers`).
        self.rss_connected_since = None;
        self.rss_disconnected_at = Some(Instant::now());
        self.rss_disconnect_10s_done = false;
        self.sample_rss("disconnected");
    }

    /// Whether a live tray icon exists (Windows only; always false
    /// on Linux, where there is no tray).
    fn tray_active(&self) -> bool {
        #[cfg(windows)]
        {
            self.tray.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Apply the state half of a close decision: hiding sets the
    /// flag and, the first time, the status/log hint. The caller
    /// sends the matching viewport commands (CancelClose +
    /// Visible(false) for HideToTray); Quit needs no state here —
    /// `perform_quit` does the work.
    fn apply_close(&mut self, decision: tray::CloseDecision) {
        if decision == tray::CloseDecision::HideToTray {
            self.hidden_to_tray = true;
            if !self.tray_hint_shown {
                self.tray_hint_shown = true;
                self.status = tray::TRAY_HINT.to_string();
                self.log_line(tray::TRAY_HINT.to_string());
            }
        }
    }

    /// The real-quit path, shared by the File-menu 退出, the tray
    /// 退出, and (via close_requested) the X button when there is no
    /// tray: disconnect first, persist settings, drop the tray icon
    /// (dropping the handle removes it from the tray). A manual quit
    /// also deletes any resume marker (v3.14): a later manual open
    /// must never auto-connect. A restart (`restarting == true`)
    /// keeps the marker the restart just wrote.
    fn perform_quit(&mut self) {
        self.disconnect();
        self.auto_save_if_dirty();
        if !self.restarting {
            if let Some(path) = tray::resume_file_path() {
                tray::clear_resume_target(&path);
            }
        }
        #[cfg(windows)]
        {
            self.tray.take();
        }
    }

    /// Show the main window again after hiding to the tray
    /// (Windows only — only the tray calls it).
    fn show_main_window(&mut self, ctx: &egui::Context) {
        self.hidden_to_tray = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// The restart itself, in Leo's order (v3.15 — "断开 → 退出 →
    /// 重启 → 连回"): disconnect FIRST, then write the resume
    /// marker, then hand back the command that launches the
    /// successor. The caller (`restart_client`, Windows only)
    /// spawns it and quits; the successor waits for this process
    /// to exit (`--restart-wait-pid`, see `single_instance`) before
    /// it binds the port or connects, so the v3.14 race — the new
    /// instance binding 10818 while the old one still held it,
    /// retrying once after 2 s, giving up with the marker already
    /// consumed — cannot happen any more.
    ///
    /// Returns the exe + arguments for the successor: the current
    /// arguments (any stale `--restart-wait-pid` pair dropped)
    /// plus a fresh `--restart-wait-pid <this pid>`.
    fn prepare_restart(&mut self) -> Result<(std::path::PathBuf, Vec<String>), String> {
        // (a) Disconnect first, while this instance still owns the
        // tunnel: the tunnel closes, the 10818 listeners are
        // aborted, the system proxy is restored. `disconnect`
        // logs "已断开 …", so the log reads断开 → 正在重启 → …
        let target = self.conn.as_ref().map(|c| c.node_label.clone());
        if target.is_some() {
            self.disconnect();
        }
        // (b) Resume marker — only when a node was connected, so
        // a disconnected restart still starts disconnected.
        // Written AFTER the disconnect, and `perform_quit` keeps
        // it when `restarting` is set (a manual quit deletes it).
        if let Some(target) = &target {
            match tray::resume_file_path() {
                Some(path) => {
                    match tray::write_resume_target(&path, target, target) {
                        Ok(()) => {
                            self.log_line(format!(
                                "正在重启客户端，重启后自动连回 {}……",
                                target
                            ));
                        }
                        Err(e) => {
                            self.log_line(format!(
                                "正在重启客户端（恢复标记写不进 {}：{}，重启后需手动再连）……",
                                path.display(),
                                e
                            ));
                        }
                    }
                }
                None => {
                    self.log_line(
                        "正在重启客户端（找不到程序目录，写不了恢复标记，重启后需手动再连）……"
                            .to_string(),
                    );
                }
            }
        } else {
            self.log_line("正在重启客户端……".to_string());
        }
        // (c) Successor command: this exe + current arguments,
        // with the old pid attached so the successor waits for
        // this process to exit before it takes the lock, binds
        // 10818, or connects.
        let (exe, args) = tray::restart_command().map_err(|e| {
            format!("重启失败：找不到当前程序路径：{}", e)
        })?;
        let mut args =
            vpngate_client::single_instance::restart_args_without_wait_pid(&args);
        args.push(
            vpngate_client::single_instance::RESTART_WAIT_PID_ARG.to_string(),
        );
        args.push(std::process::id().to_string());
        Ok((exe, args))
    }

    /// Restart the client: launch a fresh instance of this exe
    /// (same arguments) and quit this one. v3.15: the order is
    /// Leo's — disconnect, then exit, then the successor starts
    /// and connects back (`prepare_restart` does the disconnect +
    /// marker + successor command; the successor itself waits for
    /// this process to exit before binding or connecting). A
    /// marker that cannot be written only loses the resume — the
    /// restart itself still happens, and the user reconnects by hand.
    /// (Windows only — only the tray calls it.)
    #[cfg(windows)]
    fn restart_client(&mut self, ctx: &egui::Context) {
        match self.prepare_restart() {
            Ok((exe, args)) => {
                match std::process::Command::new(&exe).args(&args).spawn() {
                    Ok(_) => {
                        self.restarting = true;
                        self.quit_requested = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    Err(e) => {
                        self.error = format!("重启失败：{e}");
                        self.log_line(format!("重启客户端失败：{e}。"));
                    }
                }
            }
            Err(e) => {
                self.error = format!("重启失败：{e}");
                self.log_line(format!("重启客户端失败：{e}。"));
            }
        }
    }

    /// Consume a restart-resume marker, if one was written by the
    /// instance that restarted into this one (v3.14, Leo 11:37 —
    /// "重启后自动连回原来那个节点"). Called once from `new()`,
    /// after the node list is loaded. Rules:
    /// * No marker → nothing happens (a manual open never
    ///   auto-connects — only a restart writes a marker, and
    ///   `perform_quit` deletes any stale one on a manual quit).
    /// * Marker + target in the list → select it and `start_connect`
    ///   (the normal path, one attempt, `resume_pending` set so the
    ///   Connected / ConnectFailed handlers log the outcome).
    /// * Marker + target NOT in the list → log why and stay
    ///   disconnected, no retry.
    /// * The marker is deleted by the read itself
    ///   (`take_resume_target`), before connecting — it can only
    ///   ever fire once, even if this connect fails or the app
    ///   crashes mid-connect. A stale marker (> 10 min, the new
    ///   instance crashed before consuming it) is ignored the same
    ///   way.
    /// * Port race: the old instance may still hold the local
    ///   listen port when this connect binds — `connect_flow`
    ///   retries the bind once after 2 s.
    fn try_resume(&mut self, ctx: egui::Context) {
        let Some(path) = tray::resume_file_path() else {
            return;
        };
        let Some(rt) = tray::take_resume_target(&path) else {
            return;
        };
        let idx = self.nodes.iter().position(|n| {
            let t = match n.port {
                Some(p) => format!(
                    "{}:{}",
                    vpngate::complete_ddns_host(&n.host),
                    p
                ),
                None => vpngate::complete_ddns_host(&n.host),
            };
            t == rt.target
        });
        match idx {
            Some(i) => {
                self.selected = Some(i);
                self.selected_set = BTreeSet::from([i]);
                self.log_line(format!(
                    "重启恢复：上次连接的是 {}，自动连回它……",
                    rt.label
                ));
                self.resume_pending = true;
                self.start_connect(ctx);
            }
            None => {
                self.log_line(format!(
                    "重启恢复：节点 {} 不在列表里，不自动连接。",
                    rt.label
                ));
            }
        }
    }

    /// Drain tray-icon and menu events (Windows only) and act on
    /// them. Runs every frame from `update`.
    #[cfg(windows)]
    fn poll_tray_events(&mut self, ctx: &egui::Context) {
        let requests = match &self.tray {
            Some(t) => t.drain_requests(),
            None => return,
        };
        for req in requests {
            match req {
                tray::TrayRequest::Show => self.show_main_window(ctx),
                tray::TrayRequest::Restart => self.restart_client(ctx),
                tray::TrayRequest::Quit => {
                    self.quit_requested = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    /// Apply one background-task result. Pure state update, no egui calls,
    /// so headless tests can drive it.
    fn apply_event(&mut self, ev: GuiEvent) {
        match ev {
            GuiEvent::Nodes(upd) => {
                self.busy = None;
                // Merge first (v3.12): manual/imported nodes the
                // fresh list lacks are kept, appended at the end, so
                // a refresh no longer drops them. The cache stores
                // the merged list, so they survive a restart too.
                let (merged, retained) = self.merge_refresh_nodes(upd.nodes);
                // A fresh list from the API or the web scrape is worth
                // caching, so the next failed refresh still has a recent
                // list to show.
                if matches!(
                    upd.source,
                    vpngate::NodeListSource::Api | vpngate::NodeListSource::WebScrape
                ) {
                    let _ = vpngate::save_cached_nodes(&merged);
                }
                // The blocklist was cleared when this refresh started
                // (see `start_fetch`), so the incoming list is shown
                // in full: delete only hides nodes until the next
                // refresh. `apply_blocklist` stays as the guard for
                // a node deleted mid-fetch — it filters that one host
                // out — and for the startup load path, which still
                // filters (only an explicit refresh clears).
                // (The cache above still stores the full list.)
                let cleared = std::mem::take(&mut self.refresh_cleared_blocked);
                self.nodes = self.apply_blocklist(merged);
                let n = self.nodes.len();
                // One explicit line for every refresh — source, how
                // many blocked hosts the refresh cleared first, how
                // many manual/imported nodes it kept, and the final
                // count — so a small list is diagnosable at a glance.
                self.log_line(refresh_summary_line(upd.source, cleared, n, retained));
                self.nodes_source = upd.source.label(n, upd.cache_age_secs);
                self.clear_selection();
                match upd.source {
                    vpngate::NodeListSource::Api => {
                        self.status = format!("节点列表已更新：{} 个节点。", n);
                        self.log_line(format!("节点列表已更新：{} 个节点。", n));
                    }
                    vpngate::NodeListSource::WebScrape => {
                        self.status = format!("官方 API 不可用，已从网页抓取 {} 个节点。", n);
                        self.log_line(format!(
                            "官方 API 拉取失败：{}；已改用网页抓取（{} 个节点）。",
                            upd.api_error.as_deref().unwrap_or("未知原因"),
                            n
                        ));
                    }
                    vpngate::NodeListSource::Cache => {
                        self.status =
                            format!("官方 API 与网页都不可用，已显示缓存列表（{} 个）。", n);
                        self.log_line(format!(
                            "官方 API 拉取失败：{}；网页抓取失败：{}；已改用缓存列表（{} 个）。",
                            upd.api_error.as_deref().unwrap_or("未知原因"),
                            upd.web_error.as_deref().unwrap_or("未知原因"),
                            n
                        ));
                        // v3.15: the whole fallback chain failed —
                        // say so in Leo's exact words, in the log
                        // AND the status bar, so the user knows to
                        // try the other button.
                        self.report_refresh_failure(
                            "官方 API 与网页抓取",
                            &format!(
                                "{}；{}",
                                upd.api_error.as_deref().unwrap_or("未知原因"),
                                upd.web_error.as_deref().unwrap_or("未知原因")
                            ),
                        );
                    }
                    vpngate::NodeListSource::Curated => {
                        self.status = format!(
                            "官方 API 与网页都不可用，显示内嵌列表（{} 个）。",
                            n
                        );
                        self.log_line(format!(
                            "官方 API 拉取失败：{}；网页抓取失败：{}；已改用内嵌列表。",
                            upd.api_error.as_deref().unwrap_or("未知原因"),
                            upd.web_error.as_deref().unwrap_or("未知原因")
                        ));
                        // v3.15: same as the Cache arm — the whole
                        // fallback chain failed, say so in Leo's
                        // exact words (log AND status bar).
                        self.report_refresh_failure(
                            "官方 API 与网页抓取",
                            &format!(
                                "{}；{}",
                                upd.api_error.as_deref().unwrap_or("未知原因"),
                                upd.web_error.as_deref().unwrap_or("未知原因")
                            ),
                        );
                    }
                }
            }
            GuiEvent::ApiRefreshFailed { reason } => {
                self.busy = None;
                // v3.15: the API-only button failed. The list and
                // the blocklist stay exactly as they were — this
                // event carries no nodes — and the failure is
                // reported plainly, in Leo's exact words, instead
                // of silently falling back to the scrape.
                self.report_refresh_failure("官方 API", &reason);
            }
            GuiEvent::Probe { host, result } => {
                self.busy = None;
                match result {
                    Ok((vip, ms)) => {
                        self.probes
                            .insert(host.clone(), format!("{} ms", ms.as_millis()));
                        self.probe_ms
                            .insert(host.clone(), ms.as_millis() as u64);
                        self.status =
                            format!("{} 可用：虚拟 IP {}，{} ms。", host, vip, ms.as_millis());
                        self.log_line(format!(
                            "探测 {}：可用，虚拟 IP {}，{} ms。",
                            host,
                            vip,
                            ms.as_millis()
                        ));
                    }
                    Err(ProbeFailure::ProxyDown(e)) => {
                        self.probes.insert(host.clone(), "代理不通".to_string());
                        self.probe_ms.remove(&host);
                        self.status = "探测失败：前置代理连不上。".to_string();
                        self.set_error(format!(
                            "探测 {} 失败：前置代理 {} 连不上（{}）。节点还没连上——问题在代理不在节点：刷新、探测、连接都走这条代理，代理不通时会一起失败，换节点没用。先点高级设置里的“测试前置代理”确认。",
                            host, self.front_addr, e
                        ));
                        self.log_line(format!(
                            "探测 {}：失败：前置代理 {} 连不上（{}）。提示：刷新节点、探测、连接都走前置代理，代理不通时它们会一起失败。",
                            host, self.front_addr, e
                        ));
                    }
                    Err(ProbeFailure::NodeDown(e)) => {
                        self.probes.insert(host.clone(), "失败".to_string());
                        self.probe_ms.remove(&host);
                        self.status = format!("{} 探测失败。", host);
                        if self.front_enabled {
                            self.set_error(format!(
                                "探测 {} 失败：前置代理 {} 能连上，但节点不通（{}）。换一个节点再试。",
                                host, self.front_addr, e
                            ));
                            self.log_line(format!(
                                "探测 {}：失败：前置代理 {} 能连上，节点不通（{}）。",
                                host, self.front_addr, e
                            ));
                        } else {
                            self.set_error(format!("探测 {} 失败：{}。换一个节点再试。", host, e));
                        }
                    }
                }
            }
            GuiEvent::ProbeAllProgress {
                current,
                done,
                total,
            } => {
                // A sweep in flight: the row being probed shows
                // "探测中…" (same cell text as a single probe) and
                // the status line names it. A stray progress event
                // with no sweep running is ignored.
                if self.busy != Some(Busy::ProbingAll) {
                    return;
                }
                self.probe_all_done = done;
                self.probe_all_total = total;
                self.probes.insert(current.clone(), "探测中…".to_string());
                self.probe_ms.remove(&current);
                self.status = format!("正在探测全部：{}/{}（{}）…", done, total, current);
            }
            GuiEvent::ProbeAllResult {
                host,
                result,
                done,
                total,
            } => {
                // Same cell updates as a single probe, but no
                // per-node error banner: 83 failures would spam the
                // banner and the file log with the long advisory
                // text, and the summary at the end is the right
                // place for the outcome. One concise log line per
                // node keeps the trace without the noise.
                if self.busy != Some(Busy::ProbingAll) {
                    return;
                }
                self.probe_all_done = done;
                self.probe_all_total = total;
                match result {
                    Ok((vip, ms)) => {
                        self.probe_all_ok += 1;
                        self.probes
                            .insert(host.clone(), format!("{} ms", ms.as_millis()));
                        self.probe_ms
                            .insert(host.clone(), ms.as_millis() as u64);
                        self.status = format!(
                            "正在探测全部：{}/{}（{} 可用，{} ms）…",
                            done, total, host, ms.as_millis()
                        );
                        self.log_line(format!(
                            "探测全部 {}/{}：{} 可用，虚拟 IP {}，{} ms。",
                            done, total, host, vip, ms.as_millis()
                        ));
                    }
                    Err(ProbeFailure::ProxyDown(e)) => {
                        self.probe_all_failed += 1;
                        self.probes.insert(host.clone(), "代理不通".to_string());
                        self.probe_ms.remove(&host);
                        self.status = format!(
                            "正在探测全部：{}/{}（{} 代理不通）…",
                            done, total, host
                        );
                        self.log_line(format!(
                            "探测全部 {}/{}：{} 失败：前置代理不通（{}）。",
                            done, total, host, e
                        ));
                    }
                    Err(ProbeFailure::NodeDown(e)) => {
                        self.probe_all_failed += 1;
                        self.probes.insert(host.clone(), "失败".to_string());
                        self.probe_ms.remove(&host);
                        self.status = format!(
                            "正在探测全部：{}/{}（{} 失败）…",
                            done, total, host
                        );
                        self.log_line(format!(
                            "探测全部 {}/{}：{} 失败（{}）。",
                            done, total, host, e
                        ));
                    }
                }
            }
            GuiEvent::ProbeAllDone {
                total,
                ok,
                failed,
                stopped,
                proxy_down,
            } => {
                self.busy = None;
                self.probe_all_ok = ok;
                self.probe_all_failed = failed;
                self.probe_all_done = ok + failed;
                self.probe_all_total = total;
                let skipped = total.saturating_sub(ok + failed);
                if proxy_down {
                    self.status = format!(
                        "探测全部已停止：前置代理不通，已测 {}/{}，{} 个可用，{} 个失败。",
                        ok + failed, total, ok, failed
                    );
                    self.set_error(format!(
                        "探测全部已停止：前置代理 {} 不通，剩下的 {} 个节点没测（已测 {}/{}，{} 个可用）。先点高级设置里的“测试前置代理”确认。",
                        self.front_addr, skipped, ok + failed, total, ok
                    ));
                    self.log_line(format!(
                        "探测全部已停止：前置代理不通。已测 {}/{}，{} 个可用，{} 个失败，{} 个未测。",
                        ok + failed, total, ok, failed, skipped
                    ));
                } else if stopped {
                    self.status = format!(
                        "探测全部已停止：已测 {}/{}，{} 个可用，{} 个失败。",
                        ok + failed, total, ok, failed
                    );
                    self.log_line(format!(
                        "探测全部已停止：已测 {}/{}，{} 个可用，{} 个失败，{} 个未测。",
                        ok + failed, total, ok, failed, skipped
                    ));
                } else {
                    self.status = format!(
                        "探测全部完成：{} 个节点，{} 个可用，{} 个失败。",
                        total, ok, failed
                    );
                    self.log_line(format!(
                        "探测全部完成：{} 个节点，{} 个可用，{} 个失败。",
                        total, ok, failed
                    ));
                }
                // v3.14 RSS: probe-all-done sample (Tier C).
                self.sample_rss("probe_all_done");
            }
            GuiEvent::Connected(c) => {
                self.busy = None;
                self.status = format!("已连接 {}，虚拟 IP {}。", c.node_label, c.vip);
                self.error.clear();
                self.log_line(format!(
                    "已连接 {}，虚拟 IP {}，本地混合代理（SOCKS5+HTTP）{}。浏览器/应用连这个端口即可上网。",
                    c.node_label, c.vip, c.listen_addr
                ));
                if self.resume_pending {
                    self.resume_pending = false;
                    self.log_line(format!(
                        "重启恢复：已自动连回 {}。",
                        c.node_label
                    ));
                }
                self.conn = Some(*c);
                // v3.14 RSS: connection-start sample + 30-min timer.
                self.rss_connected_since = Some(Instant::now());
                self.rss_conn30_done = false;
                self.sample_rss("connected");
            }
            GuiEvent::ConnectFailed(e) => {
                self.busy = None;
                self.status = "连接失败。".to_string();
                self.set_error(format!("连接失败：{}。换一个节点，或检查前置 SOCKS5 设置。", e));
                if self.resume_pending {
                    self.resume_pending = false;
                    self.log_line(
                        "重启恢复：自动连接失败，保持断开，不再重试。".to_string(),
                    );
                }
            }
            GuiEvent::ConnLog(line) => {
                self.log_line(line);
            }
            GuiEvent::FrontProxyTestProgress { site } => {
                // Which site is being tested right now; the busy flag
                // stays set until the FrontProxyTest result arrives.
                self.status = format!("正在测试前置代理… {}", site);
            }
            GuiEvent::FrontProxyTest {
                addr,
                google,
                vpngate,
            } => {
                self.busy = None;
                let g = front_proxy_check_line("Google", &google);
                let v = front_proxy_check_line("vpngate.net", &vpngate);
                self.log_line(format!("前置代理测试：{}；{}。", g, v));
                let proxy_detail = match &google {
                    net::FrontProxyCheck::ProxyUnreachable(d) => Some(d.clone()),
                    _ => match &vpngate {
                        net::FrontProxyCheck::ProxyUnreachable(d) => Some(d.clone()),
                        _ => None,
                    },
                };
                let mut target_down: Vec<(&str, String)> = Vec::new();
                if let net::FrontProxyCheck::TargetUnreachable(d) = &google {
                    target_down.push(("Google", d.clone()));
                }
                if let net::FrontProxyCheck::TargetUnreachable(d) = &vpngate {
                    target_down.push(("vpngate.net", d.clone()));
                }
                if let Some(d) = proxy_detail {
                    self.status = "前置代理测试：前置代理连不上。".to_string();
                    self.set_error(format!(
                        "前置代理 {} 连不上（{}）。刷新、探测、连接都走这条代理，代理不通时会一起失败：检查前置代理（NekoBox）开没开、地址对不对。",
                        addr, d
                    ));
                } else if target_down.is_empty() {
                    self.status = format!("前置代理测试：{}；{}。", g, v);
                    self.error.clear();
                } else {
                    let labels: Vec<&str> = target_down.iter().map(|(l, _)| *l).collect();
                    self.status = format!("前置代理测试：前置代理通，{}不通。", labels.join("、"));
                    self.set_error(format!(
                        "前置代理能连上，但 {} 通过它打不开（{}）。刷新节点要走 vpngate.net，这个不通就拉不到新节点；Google 不通则是出口的问题。",
                        labels.join("、"),
                        target_down[0].1
                    ));
                }
            }
        }
    }

    fn drain_events(&mut self) {
        let mut events = Vec::new();
        if let Some(rx) = &self.event_rx {
            while let Ok(ev) = rx.try_recv() {
                events.push(ev);
            }
        }
        for ev in events {
            self.apply_event(ev);
        }
    }

    fn selected_node_label(&self) -> Option<String> {
        self.nodes.get(self.selected?).map(|n| match n.port {
            Some(p) => format!("{}:{}", n.host, p),
            None => n.host.clone(),
        })
    }

    /// The rows for this frame, from the cache when
    /// `list_fingerprint()` is unchanged, freshly built otherwise.
    /// Takes the cache out (the caller puts it back after the
    /// frame — see `ui()`); returns the fingerprint alongside, so
    /// the caller can store the pair back. The build counter
    /// (`rows_built`, test-only) is what the cache tests assert on.
    fn cached_rows(&mut self) -> (u64, Vec<NodeRow>) {
        let fp = self.list_fingerprint();
        let rows = match self.rows_cache.take() {
            Some((cached_fp, cached)) if cached_fp == fp => cached,
            _ => self.build_rows(),
        };
        (fp, rows)
    }

    /// Build the rendered node-list rows in display order (see
    /// `display_indices`). Pure construction — the caller
    /// (`ui()`) caches the result in `rows_cache` and only calls
    /// this when `list_fingerprint()` changed.
    fn build_rows(&mut self) -> Vec<NodeRow> {
        #[cfg(test)]
        {
            self.rows_built += 1;
        }
        let connected_host = self.connected_node_host();
        self.display_indices()
            .into_iter()
            .map(|idx| {
                let n = &self.nodes[idx];
                let status = self
                    .probes
                    .get(&n.host)
                    .cloned()
                    .unwrap_or_else(|| "未探测".to_string());
                let full = match n.port {
                    Some(p) => format!("{}:{}", n.host, p),
                    None => n.host.clone(),
                };
                let status_icon =
                    if connected_host.as_deref().is_some_and(|h| {
                        vpngate::complete_ddns_host(&n.host) == h
                    }) {
                        "∞".to_string()
                    } else {
                        String::new()
                    };
                (
                    idx,
                    status_icon,
                    // Full text here: the cells truncate with "…"
                    // to the current column width (see below), so
                    // widening a column shows more instead of a
                    // fixed 12/14-character cut. Empty
                    // country/operator shows "—": no literal
                    // placeholder value ("导入", "手动", "未知")
                    // is ever stored in these fields (v3.12).
                    if n.country.is_empty() {
                        "—".to_string()
                    } else {
                        n.country.clone()
                    },
                    if !n.isp.is_empty() {
                        n.isp.clone()
                    } else if !n.name.is_empty() {
                        n.name.clone()
                    } else {
                        "—".to_string()
                    },
                    sessions_cell(n),
                    quality_cell(n),
                    per_capita_cell(n),
                    // All curated hosts end in .opengw.net; drop
                    // the suffix for display (full host is in
                    // the tooltip).
                    match n.port {
                        Some(p) => format!(
                            "{}:{}",
                            n.host.strip_suffix(".opengw.net").unwrap_or(&n.host),
                            p
                        ),
                        None => n
                            .host
                            .strip_suffix(".opengw.net")
                            .unwrap_or(&n.host)
                            .to_string(),
                    },
                    status,
                    full,
                )
            })
            .collect()
    }

    /// Fingerprint of everything the node list's display order and
    /// built rows read (v3.14, diagnosis §3 item 7): every displayed
    /// node field, `probes`, `probe_ms`, `sort`, and the connected
    /// node's label (the ∞ mark). The `order_cache` / `rows_cache`
    /// rebuild only when this changes; any input missed here would
    /// show a stale list, so the hashed inputs ARE the contract.
    /// `HashMap` iteration order is stable within a run (it only
    /// changes when the map rehashes, which also changes content),
    /// so no sorting allocation is needed — a different order with
    /// the same content can only cause a spurious rebuild, never a
    /// stale read.
    fn list_fingerprint(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut h = DefaultHasher::new();
        self.nodes.len().hash(&mut h);
        for n in &self.nodes {
            n.host.hash(&mut h);
            n.port.hash(&mut h);
            n.country.hash(&mut h);
            n.country_code.hash(&mut h);
            n.isp.hash(&mut h);
            n.name.hash(&mut h);
            n.score.hash(&mut h);
            n.ping_ms.hash(&mut h);
            n.speed_mbps.hash(&mut h);
            n.sessions.hash(&mut h);
            n.ip.hash(&mut h);
        }
        for (k, v) in &self.probes {
            k.hash(&mut h);
            v.hash(&mut h);
        }
        for (k, v) in &self.probe_ms {
            k.hash(&mut h);
            v.hash(&mut h);
        }
        self.sort.hash(&mut h);
        self.conn.as_ref().map(|c| &c.node_label).hash(&mut h);
        h.finish()
    }

    /// Node indices in display order: fetch order by default, or
    /// sorted by the column the user picked (see `sort`) — the
    /// whole row follows the sort key, and `selected` still stores
    /// a node index, so sorting never misaligns the selection. A
    /// refresh replaces `self.nodes` and the sort re-applies
    /// automatically, since the order is computed here, not stored.
    /// v3.14: cached by `list_fingerprint()` — the sort over ~125
    /// rows is re-run only when the list actually changed.
    fn display_indices(&mut self) -> Vec<usize> {
        let fp = self.list_fingerprint();
        if let Some((cached_fp, cached)) = &self.order_cache {
            if *cached_fp == fp {
                return cached.clone();
            }
        }
        let order = self.compute_display_indices();
        self.order_cache = Some((fp, order.clone()));
        order
    }

    /// The uncached sort (see `display_indices`).
    fn compute_display_indices(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.nodes.len()).collect();
        if let Some((col, dir)) = self.sort {
            idx.sort_by(|&a, &b| {
                let (na, nb) = (&self.nodes[a], &self.nodes[b]);
                let ord = match col {
                    SortCol::Country => na
                        .country
                        .cmp(&nb.country)
                        .then_with(|| na.host.cmp(&nb.host)),
                    SortCol::Sessions => na
                        .sessions
                        .cmp(&nb.sessions)
                        .then_with(|| na.host.cmp(&nb.host)),
                    SortCol::Quality => quality_key(na)
                        .cmp(&quality_key(nb))
                        .then_with(|| na.host.cmp(&nb.host)),
                    SortCol::PerCapita => per_capita_key(na)
                        .cmp(&per_capita_key(nb))
                        .then_with(|| na.host.cmp(&nb.host)),
                    SortCol::Latency => self
                        .latency_key(na)
                        .cmp(&self.latency_key(nb))
                        .then_with(|| na.host.cmp(&nb.host)),
                };
                match dir {
                    SortDir::Asc => ord,
                    SortDir::Desc => ord.reverse(),
                }
            });
        }
        idx
    }

    /// Click a sortable column header: the same column again
    /// reverses the direction; a different column starts at that
    /// column's first-click direction (see `SortCol::default_dir`).
    fn toggle_sort(&mut self, col: SortCol) {
        self.sort = Some(match self.sort {
            Some((c, dir)) if c == col => (
                col,
                match dir {
                    SortDir::Asc => SortDir::Desc,
                    SortDir::Desc => SortDir::Asc,
                },
            ),
            _ => (col, col.default_dir()),
        });
    }

    /// Sort key for the 延迟/状态 column: (group, ms). Group 0 =
    /// probed and available, ordered by latency ms ascending;
    /// group 1 = unprobed ("未探测" — no entry — or "探测中…");
    /// group 2 = failed ("失败" / "代理不通"). Reversing the whole
    /// key (second click) puts failures first, unprobed in the
    /// middle, available by ms descending last. The ms comes from
    /// `probe_ms`, stored when a probe succeeds — never re-parsed
    /// from the display string.
    fn latency_key(&self, n: &vpngate::Node) -> (u8, u64) {
        // A node being probed right now sorts with the unprobed
        // group even if an earlier probe left a ms behind (the
        // start path clears `probe_ms`, so this is belt-and-braces).
        if self.probes.get(&n.host).map(|s| s.as_str()) == Some("探测中…") {
            return (1, 0);
        }
        match self.probe_ms.get(&n.host) {
            Some(&ms) => (0, ms),
            None => match self.probes.get(&n.host) {
                None => (1, 0),
                Some(_) => (2, 0),
            },
        }
    }

    /// Canonical key for the blocklist: the completed DDNS hostname
    /// (a bare API label like "public-vpn-192" becomes
    /// "public-vpn-192.opengw.net"), so a node matches its block
    /// entry no matter which source listed it — and so the
    /// connected-node check compares like with like.
    fn blocked_key(host: &str) -> String {
        vpngate::complete_ddns_host(host)
    }

    /// Target string for the selected row, built exactly like
    /// `start_connect` builds it (completed host + `:port` when the
    /// port is known, bare completed host otherwise). `None` when
    /// nothing is selected.
    fn selected_target(&self) -> Option<String> {
        let n = self.nodes.get(self.selected?)?;
        Some(match n.port {
            Some(p) => format!("{}:{}", vpngate::complete_ddns_host(&n.host), p),
            None => vpngate::complete_ddns_host(&n.host),
        })
    }

    /// Whether the selected row is the node already connected (same
    /// target string as `conn.node_label`). Enter / the 连接 button
    /// on it must be a no-op — never disconnect-and-reconnect the
    /// same node for nothing (v3.13 switch rule).
    fn selected_is_connected(&self) -> bool {
        match (&self.conn, self.selected_target()) {
            (Some(c), Some(t)) => t == c.node_label,
            _ => false,
        }
    }

    /// Host of the currently connected node, if any (the `node_label`
    /// is the target string, "host" or "host:port", with the DDNS
    /// suffix already completed). The status column shows ∞ for the
    /// node whose completed host matches this.
    fn connected_node_host(&self) -> Option<String> {
        let label = self.conn.as_ref()?.node_label.clone();
        let host = match label.rsplit_once(':') {
            Some((h, p))
                if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) =>
            {
                h.to_string()
            }
            _ => label,
        };
        Some(host)
    }

    /// Move the selection one row up (`delta < 0`) or down
    /// (`delta > 0`) in display order (see `display_indices`, so a
    /// sorted list moves in the shown order). Stops at the ends —
    /// no wrap-around. With no selection yet, ↓ picks the first row
    /// and ↑ picks the last. Sets `scroll_to_selected` when the
    /// selection actually changes, so the row loop scrolls it into
    /// view; pressing ↑ at the top (or ↓ at the bottom) changes
    /// nothing and requests no scroll. Moving the selection starts
    /// nothing, so callers may move it while busy or connected.
    fn move_selection(&mut self, delta: isize) {
        let order = self.display_indices();
        if order.is_empty() {
            return;
        }
        let pos = self
            .selected
            .and_then(|s| order.iter().position(|&i| i == s));
        let new_pos = match pos {
            Some(p) => (p as isize + delta).clamp(0, order.len() as isize - 1) as usize,
            None => {
                if delta > 0 {
                    0
                } else {
                    order.len() - 1
                }
            }
        };
        if Some(order[new_pos]) != self.selected {
            self.selected = Some(order[new_pos]);
            // Arrow keys keep the v3.4 behaviour: the multi-select
            // collapses to just the row the anchor moved to.
            self.selected_set = BTreeSet::from([order[new_pos]]);
            self.scroll_to_selected = true;
        }
    }

    /// Select every currently displayed node (v3.15, Ctrl+A):
    /// the display order from `display_indices` — the sorted
    /// order, with blocked hosts already excluded at load — so
    /// this is exactly the set "导出选中" / Ctrl+C exports (see
    /// `selected_nodes_in_display_order`). The anchor moves to
    /// the first displayed row, so Enter / Ctrl+R after a Ctrl+A
    /// act on it. An empty list is a no-op.
    fn select_all(&mut self) {
        let order = self.display_indices();
        if order.is_empty() {
            return;
        }
        self.selected = Some(order[0]);
        self.selected_set = order.into_iter().collect();
    }

    /// Clear both halves of the selection: the anchor and the
    /// multi-select set (used after a delete, a restore, and a list
    /// reload — indices from the old list are meaningless there).
    fn clear_selection(&mut self) {
        self.selected = None;
        self.selected_set.clear();
    }

    /// The modifiers a row click counts with: the ones held when
    /// the press started (`press_mods`, latched in `row_press_mods`)
    /// OR the ones held now (the release frame). A press and a
    /// release usually land in different frames, and a user who
    /// lets go of Shift/Ctrl a beat before the mouse button would
    /// lose the gesture if only the release frame were read — that
    /// is exactly the v3.7 Shift+click failure (the range came out
    /// as a plain single-row click). The OR also covers Shift
    /// pressed mid-click and a press+release that land in one
    /// frame. `command` counts as Ctrl (Cmd on macOS, Ctrl
    /// elsewhere), like the row code before it.
    fn effective_click_mods(
        press_mods: Option<egui::Modifiers>,
        current: egui::Modifiers,
    ) -> (bool, bool) {
        let press = press_mods.unwrap_or_default();
        let ctrl = press.ctrl || press.command || current.ctrl || current.command;
        let shift = press.shift || current.shift;
        (ctrl, shift)
    }

    /// Click selection for a row (`node_idx` is an index into
    /// `self.nodes`, not a display position). Plain click selects
    /// only that row; Ctrl/Cmd+click toggles it in or out of the
    /// multi-select set; Shift+click selects the whole range from
    /// the anchor to this row in display order. Every click moves
    /// the anchor to the clicked row — the anchor is the row Enter /
    /// Ctrl+R / 探测 / 连接 act on, while 删除选中 deletes the set.
    fn click_row(&mut self, node_idx: usize, ctrl: bool, shift: bool) {
        if shift {
            if let Some(anchor) = self.selected {
                let order = self.display_indices();
                match (
                    order.iter().position(|&i| i == anchor),
                    order.iter().position(|&i| i == node_idx),
                ) {
                    (Some(a), Some(b)) => {
                        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                        self.selected_set =
                            order[lo..=hi].iter().copied().collect();
                    }
                    // Anchor or clicked row is gone (the list was
                    // reloaded between clicks): fall back to
                    // selecting just this row.
                    _ => self.selected_set = BTreeSet::from([node_idx]),
                }
            } else {
                self.selected_set = BTreeSet::from([node_idx]);
            }
        } else if ctrl {
            if !self.selected_set.remove(&node_idx) {
                self.selected_set.insert(node_idx);
            }
        } else {
            self.selected_set = BTreeSet::from([node_idx]);
        }
        self.selected = Some(node_idx);
    }

    /// Whether 删除选中 may run: a non-empty selection and no job
    /// running (probe / connect / refresh / probe-all all set
    /// `busy` — the same guard as the 刷新节点 button). Deleting
    /// mid-sweep would change the list under the running probe-all.
    fn can_delete(&self) -> bool {
        !self.selected_set.is_empty() && self.busy.is_none()
    }

    /// Delete the multi-selected nodes. The connected node is never
    /// deleted — if it is selected it is skipped and logged.
    /// Deleted hosts go on the blocklist, which only hides them for
    /// this session: the next refresh clears the blocklist and
    /// brings the full list back (v3.11, Leo's call). Probe results
    /// for deleted hosts are cleaned up, and the selection is
    /// cleared.
    fn delete_selected(&mut self) {
        if !self.can_delete() {
            return;
        }
        let connected = self.connected_node_host();
        self.delete_selected_with_connected(connected.as_deref());
    }

    /// `delete_selected` with the connected host supplied directly
    /// (the live path passes `connected_node_host()`): the list
    /// mutation plus the status/log reporting, so the connected-node
    /// skip wording is unit-testable without a live tunnel.
    fn delete_selected_with_connected(&mut self, connected_host: Option<&str>) {
        let (removed, skipped) = self.delete_selected_except(connected_host);
        self.clear_selection();
        if skipped > 0 {
            self.log_line(format!("已连接的节点不能删除，已跳过 {}。", skipped));
        }
        if removed > 0 {
            self.status = format!(
                "已删除 {} 个节点（本次会话里隐藏，刷新后会带回来）。",
                removed
            );
            self.log_line(format!(
                "已删除 {} 个节点：屏蔽列表现在有 {} 个主机。",
                removed,
                self.blocked_hosts.len()
            ));
        }
    }

    /// Core of `delete_selected`, split out so the connected-node
    /// skip is unit-testable without a live tunnel:
    /// `connected_host` is the completed hostname of the connected
    /// node, if any. Returns (removed, skipped).
    fn delete_selected_except(&mut self, connected_host: Option<&str>) -> (usize, usize) {
        let mut removed = 0usize;
        let mut skipped = 0usize;
        // Remove highest index first so earlier indices stay valid.
        let mut idxs: Vec<usize> = self.selected_set.iter().copied().collect();
        idxs.sort_unstable_by(|a, b| b.cmp(a));
        for i in idxs {
            let Some(node) = self.nodes.get(i) else {
                continue;
            };
            let key = Self::blocked_key(&node.host);
            if connected_host == Some(key.as_str()) {
                skipped += 1;
                continue;
            }
            let node = self.nodes.remove(i);
            self.probes.remove(&node.host);
            self.probe_ms.remove(&node.host);
            self.blocked_hosts.insert(key);
            removed += 1;
        }
        (removed, skipped)
    }

    /// Drop the blocked hosts from a freshly loaded list. Applied on
    /// every list load — API refresh, web scrape, cache, embedded
    /// fallback — so a deleted node never comes back until its host
    /// is removed from `blocked_hosts` in config.toml.
    fn apply_blocklist(&self, nodes: Vec<Node>) -> Vec<Node> {
        if self.blocked_hosts.is_empty() {
            return nodes;
        }
        nodes
            .into_iter()
            .filter(|n| !self.blocked_hosts.contains(&Self::blocked_key(&n.host)))
            .collect()
    }

    /// Merge a fresh list with the manual/imported nodes a refresh
    /// must not drop (v3.12 — before this, a refresh replaced the
    /// whole list, so a manually added or imported node vanished at
    /// the next refresh). Nodes whose `source` is "manual" or
    /// "import" and whose completed host is absent from the incoming
    /// list are appended at the end, in their current order; the
    /// count of kept nodes is returned alongside the merged list.
    /// When the incoming list has the same completed host, the
    /// incoming row wins for metadata (country/operator/users/
    /// quality) and the manual copy is dropped — except its port:
    /// the API never carries an SSTP port, so a manual port survives
    /// when the incoming row has none.
    fn merge_refresh_nodes(&self, incoming: Vec<Node>) -> (Vec<Node>, usize) {
        let mut merged = incoming;
        let mut index_by_host: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (i, n) in merged.iter().enumerate() {
            index_by_host
                .entry(Self::blocked_key(&n.host))
                .or_insert(i);
        }
        let mut retained = 0usize;
        for n in &self.nodes {
            if n.source != "manual" && n.source != "import" {
                continue;
            }
            let key = Self::blocked_key(&n.host);
            match index_by_host.get(&key) {
                Some(&i) => {
                    if merged[i].port.is_none() {
                        if let Some(p) = n.port {
                            merged[i].port = Some(p);
                            merged[i].port_source = n.port_source.clone();
                        }
                    }
                }
                None => {
                    index_by_host.insert(key, merged.len());
                    merged.push(n.clone());
                    retained += 1;
                }
            }
        }
        (merged, retained)
    }

    /// The selected nodes in display order (see `display_indices`,
    /// so a sorted list exports in the shown order). Cloned: the
    /// export text is built from this snapshot.
    fn selected_nodes_in_display_order(&mut self) -> Vec<Node> {
        self.display_indices()
            .into_iter()
            .filter(|i| self.selected_set.contains(i))
            .filter_map(|i| self.nodes.get(i).cloned())
            .collect()
    }

    /// Copy the selected nodes to the system clipboard, one
    /// `host:port` line per node (see `export_nodes_text`). Same
    /// guard as the delete button — a non-empty selection and no job
    /// running — so the button, the Ctrl+C shortcut and the File menu
    /// item all share this one path. The clipboard write itself is
    /// egui's fire-and-forget `copy_text` (the OS call happens in
    /// the eframe backend, which reports no result back to the app);
    /// the only failure the app can see is an empty selection, and
    /// that is reported as such instead of claiming success.
    fn export_selected(&mut self, ctx: &egui::Context) {
        if !self.can_delete() {
            return;
        }
        let nodes = self.selected_nodes_in_display_order();
        let text = export_nodes_text(&nodes, &self.probe_ms);
        if text.is_empty() {
            self.status = "没有选中的节点可导出。".to_string();
            self.log_line("导出选中：没有选中的节点，未写入剪贴板。".to_string());
            return;
        }
        let n = nodes.len();
        ctx.copy_text(text);
        self.status = format!("已导出 {} 个节点到剪贴板。", n);
        self.log_line(format!("已导出 {} 个节点到剪贴板。", n));
    }

    /// Write the selected nodes to a plain-text node-list file
    /// (same `host:port` lines as the clipboard export) through a
    /// native save dialog (`rfd`, default name `nodes_export.txt`).
    /// Same guard as the delete button. A cancelled dialog is not
    /// an error — it just says so.
    fn export_selected_to_file(&mut self) {
        if !self.can_delete() {
            return;
        }
        let nodes = self.selected_nodes_in_display_order();
        let text = export_nodes_text(&nodes, &self.probe_ms);
        if text.is_empty() {
            self.status = "没有选中的节点可导出。".to_string();
            self.log_line("导出到文件：没有选中的节点，未写文件。".to_string());
            return;
        }
        let n = nodes.len();
        let picked = rfd::FileDialog::new()
            .set_file_name("nodes_export.txt")
            .add_filter("文本文件", &["txt"])
            .save_file();
        match picked {
            Some(path) => match std::fs::write(&path, &text) {
                Ok(()) => {
                    self.status = format!("已导出 {} 个节点到 {}。", n, path.display());
                    self.log_line(format!("已导出 {} 个节点到 {}。", n, path.display()));
                }
                Err(e) => {
                    self.status = format!("写文件失败：{}。", e);
                    self.log_line(format!(
                        "导出到文件失败：写 {} 失败：{}。",
                        path.display(),
                        e
                    ));
                }
            },
            None => {
                self.status = "已取消保存文件。".to_string();
                self.log_line("导出到文件：用户取消了保存对话框。".to_string());
            }
        }
    }

    /// Import nodes from text (clipboard or file — one shared path).
    /// `source` is the short noun used in the messages ("剪贴板" /
    /// "文件"). Does nothing while a job is running: a fetch that
    /// finishes mid-import would replace the list and silently drop
    /// the imported nodes. After a successful import the node cache
    /// is rewritten so the nodes survive a restart, and a blocklist
    /// change (imported hosts are unblocked) is auto-saved.
    fn import_from_text(&mut self, text: &str, source: &str) {
        if self.busy.is_some() {
            self.status = "正在忙，请稍后再导入。".to_string();
            self.log_line(format!("从{}导入：正在忙，未导入。", source));
            return;
        }
        let report = self.import_nodes_text(text);
        if report.added > 0 {
            if let Err(e) = vpngate::save_cached_nodes(&self.nodes) {
                self.log_warn(format!("导入后写节点缓存失败：{}。", e));
            }
            self.auto_save_if_dirty();
        }
        for host in &report.unblocked {
            self.log_line(format!("已从屏蔽列表里拿掉 {}（导入把它要回来了）。", host));
        }
        if report.added == 0 && report.duplicates == 0 && report.malformed == 0 {
            self.status = format!("{}里没有可导入的节点。", source);
            self.log_line(format!("从{}导入：没有可解析的行，未导入任何节点。", source));
        } else {
            self.status = format!(
                "已导入 {} 个节点（跳过重复 {} 个，格式不对 {} 个）。",
                report.added, report.duplicates, report.malformed
            );
            self.log_line(format!(
                "从{}导入：成功 {} 个，跳过重复 {} 个，格式不对 {} 个。",
                source, report.added, report.duplicates, report.malformed
            ));
        }
    }

    /// The mutation core of `import_from_text`, split out so the
    /// parse/insert/count logic is unit-testable without status/log
    /// side effects (and without touching the cache or the config).
    /// Nodes are appended at the end, in the file's order; the
    /// selection is left untouched. A host already in the list (by
    /// completed hostname) is a duplicate — the whole line is
    /// skipped, including any probe latency it carries (v3.16:
    /// the existing row's live probe_ms is authoritative); a host
    /// on the blocklist is unblocked — importing it is an explicit
    /// request to have it back — and reported in `unblocked`.
    /// A sixth column (v3.16) restores the last probed latency
    /// into `probe_ms` plus its "N ms" display string. The export
    /// text is the latency's only persistence: the node cache
    /// stores `Node` only, so an imported latency survives only
    /// until the program exits (a refresh/re-probe overwrites or
    /// clears it by the existing probe rules).
    fn import_nodes_text(&mut self, text: &str) -> ImportReport {
        let mut report = ImportReport::default();
        for line in text.lines() {
            match parse_import_line(line) {
                ImportLine::Skip => {}
                ImportLine::Malformed => report.malformed += 1,
                ImportLine::Node {
                    host,
                    port,
                    country,
                    isp,
                    sessions,
                    speed_mbps,
                    probe_ms,
                } => {
                    let key = Self::blocked_key(&host);
                    if self
                        .nodes
                        .iter()
                        .any(|n| Self::blocked_key(&n.host) == key)
                    {
                        // Duplicate host: the whole line is skipped
                        // — including its probe latency. The existing
                        // row's probe_ms is live state; an imported
                        // stale value must not overwrite it.
                        report.duplicates += 1;
                        continue;
                    }
                    if self.blocked_hosts.remove(&key) {
                        report.unblocked.push(key);
                    }
                    // No literal placeholder values: country/isp
                    // stay empty when the line carries no metadata
                    // (the table shows "—" for them), and `name`
                    // stays empty so the operator cell cannot fall
                    // back to a "host:port" string. v3.11 stamped
                    // "导入" into both fields here — that is the
                    // bug Leo's screenshot shows.
                    self.nodes.push(Node {
                        host: host.clone(),
                        port,
                        country,
                        country_code: String::new(),
                        isp,
                        name: String::new(),
                        score: 0,
                        ping_ms: 0,
                        speed_mbps,
                        sessions,
                        ip: String::new(),
                        backups: Vec::new(),
                        port_source: "import".to_string(),
                        source: "import".to_string(),
                    });
                    // v3.16: restore the last probed latency (the
                    // export text is its only persistence — the
                    // node cache stores Node only, never probe_ms).
                    // The restored value is "last measured", not a
                    // fresh probe: it shows as "N ms" and sorts
                    // like a real probe result, until a re-probe
                    // overwrites/clears it by the existing rules.
                    if let Some(ms) = probe_ms {
                        self.probes.insert(host.clone(), format!("{} ms", ms));
                        self.probe_ms.insert(host, ms);
                    }
                    report.added += 1;
                }
            }
        }
        report
    }

    /// Import from the system clipboard, read directly (`arboard`) —
    /// the File menu item's path (a menu click carries no Paste
    /// event). Ctrl+V instead goes through `handle_clipboard_events`
    /// (Paste event first, keypress + direct read as fallback).
    fn import_from_clipboard(&mut self) {
        if self.busy.is_some() {
            self.status = "正在忙，请稍后再导入。".to_string();
            self.log_line("从剪切板导入：正在忙，未导入。".to_string());
            return;
        }
        match read_clipboard_text() {
            Ok(text) => self.import_from_text(&text, "剪贴板"),
            Err(e) => {
                self.status = format!("读剪贴板失败：{}。", e);
                self.log_line(format!("从剪切板导入失败：读剪贴板失败：{}。", e));
            }
        }
    }

    /// Import from a plain-text node-list file through a native open
    /// dialog (`rfd`). Same line format as the clipboard import.
    fn import_from_file_dialog(&mut self) {
        if self.busy.is_some() {
            self.status = "正在忙，请稍后再导入。".to_string();
            self.log_line("从文件导入：正在忙，未导入。".to_string());
            return;
        }
        let picked = rfd::FileDialog::new()
            .add_filter("文本文件", &["txt"])
            .add_filter("全部文件", &["*"])
            .pick_file();
        match picked {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(text) => {
                    self.log_line(format!("正在从文件 {} 导入…", path.display()));
                    self.import_from_text(&text, "文件");
                }
                Err(e) => {
                    self.status = format!("读文件失败：{}。", e);
                    self.log_line(format!(
                        "从文件导入失败：读 {} 失败：{}。",
                        path.display(),
                        e
                    ));
                }
            },
            None => {
                self.status = "已取消选择文件。".to_string();
                self.log_line("从文件导入：用户取消了打开对话框。".to_string());
            }
        }
    }

    /// Clear the blocklist (in memory and in config.toml) and return
    /// how many hosts were cleared. The caller owns the messaging:
    /// `start_fetch` calls this before fetching, and the Nodes
    /// handler logs the cleared count in the refresh summary line.
    /// This is NOT the v3.10-removed "恢复已删除" button — nothing
    /// is put back into the current list here; the hosts come back
    /// with the fresh list the refresh fetches.
    fn clear_blocklist(&mut self) -> usize {
        let n = self.blocked_hosts.len();
        if n == 0 {
            return 0;
        }
        self.blocked_hosts.clear();
        self.auto_save_if_dirty();
        n
    }

    /// Ctrl+C / Ctrl+V on the node list, called once per frame from
    /// `ui()` (after the Enter/Ctrl+R shortcuts). The caller guards
    /// it with the same focus rule — no text field focused and the
    /// About window closed — so a focused text field keeps its own
    /// copy/paste.
    ///
    /// Ctrl+C arrives as `Event::Copy` (eframe translates the
    /// keypress) and exports the selection, exactly like the
    /// 导出选中 button. Ctrl+V arrives as `Event::Paste` — but one
    /// frame AFTER the keypress (eframe reads the clipboard after
    /// rendering and pushes the event for the next frame), and an
    /// empty clipboard sends no event at all. So the keypress itself
    /// is the trigger: `consume_shortcut` (Ctrl+V) + a direct
    /// `arboard` read, which reports an empty clipboard instead of
    /// staying silent. The Paste event that follows the same
    /// keypress is dropped (`drop_next_paste`, lives exactly one
    /// frame) so the import does not run twice; a Paste event with
    /// no preceding keypress imports directly.
    fn handle_clipboard_events(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| {
            i.events.iter().any(|e| matches!(e, egui::Event::Copy))
        }) {
            self.export_selected(ctx);
        }
        let pasted = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Paste(t) => Some(t.clone()),
                _ => None,
            })
        });
        if self.drop_next_paste {
            self.drop_next_paste = false;
        } else if let Some(text) = pasted {
            self.import_from_text(&text, "剪贴板");
        } else if ctx.input_mut(|i| {
            i.consume_shortcut(&egui::KeyboardShortcut::new(
                egui::Modifiers::COMMAND,
                egui::Key::V,
            ))
        }) {
            match read_clipboard_text() {
                Ok(text) => {
                    if !text.trim().is_empty() {
                        self.drop_next_paste = true;
                    }
                    self.import_from_text(&text, "剪贴板");
                }
                Err(e) => {
                    self.status = format!("读剪贴板失败：{}。", e);
                    self.log_line(format!("从剪贴板导入失败：读剪贴板失败：{}。", e));
                }
            }
        }
    }

    /// Keyboard shortcuts (Enter = connect, Ctrl+R = probe): the pure
    /// guard half, unit-testable. `enter` / `ctrl_r` are whether the
    /// key was pressed this frame; `text_edit_focused` is whether a
    /// text field (manual-add, port, front-proxy address…) has focus
    /// — typing there must never trigger a connect or a probe.
    fn shortcut_action(
        &self,
        enter: bool,
        ctrl_r: bool,
        text_edit_focused: bool,
    ) -> Option<ShortcutAction> {
        if text_edit_focused
            || self.show_about
            || self.busy.is_some()
            || self.selected.is_none()
        {
            return None;
        }
        if enter {
            // v3.13: Enter while connected switches to another
            // selected node (start_connect disconnects first) — but
            // Enter on the already-connected node is a no-op, never
            // a reconnect.
            if self.selected_is_connected() {
                None
            } else {
                Some(ShortcutAction::Connect)
            }
        } else if ctrl_r {
            // Ctrl+R while connected stays blocked, as before — a
            // probe opens a second tunnel, and the shortcut never
            // did that (the 探测 button path is unchanged).
            if self.conn.is_some() {
                None
            } else {
                Some(ShortcutAction::Probe)
            }
        } else {
            None
        }
    }
}

/// What a keyboard shortcut asks for (see `shortcut_action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShortcutAction {
    Connect,
    Probe,
}

// ---------------------------------------------------------------------------
// eframe App
// ---------------------------------------------------------------------------

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Background results first.
        self.drain_events();

        // v3.14 RSS sampling: atlas fill is read once per frame
        // (cheap float read) so the RSS log lines — including the
        // ones written from apply_event/disconnect, which have no
        // Context — always carry a fresh value; the timers fire the
        // one-shot + periodic samples.
        self.last_atlas_fill = ui.ctx().fonts(|f| f.font_atlas_fill_ratio());
        self.check_rss_timers();

        // Escape closes the About window.
        if self.show_about && ui.ctx().input(|i| i.key_pressed(egui::Key::Escape)) {
            self.show_about = false;
        }
        // Keyboard shortcuts on the node list: Enter connects the
        // selected node, Ctrl+R probes it (same flows as the buttons).
        // `text_edit_focused` covers the manual-add, port and
        // front-proxy fields — typing there must not trigger anything.
        // A focused row also fires its own `clicked()` on Enter (egui
        // activates focused click widgets with Enter/Space); that only
        // re-selects the same row, and the busy guard below blocks a
        // second connect/probe from a focused button in the same frame.
        let ctx = ui.ctx().clone();
        let enter = ctx.input(|i| i.key_pressed(egui::Key::Enter));
        let ctrl_r = ctx.input_mut(|i| {
            i.consume_shortcut(&egui::KeyboardShortcut::new(
                egui::Modifiers::COMMAND,
                egui::Key::R,
            ))
        });
        let text_focused = ctx.text_edit_focused();
        match self.shortcut_action(enter, ctrl_r, text_focused) {
            Some(ShortcutAction::Connect) => self.start_connect(ctx.clone()),
            Some(ShortcutAction::Probe) => self.start_probe(ctx.clone()),
            None => {}
        }
        // Arrow keys move the selection in the node list (same guard
        // family as the shortcuts above: no text field focused —
        // ↑/↓ there move the cursor — and the About window closed).
        // Unlike Enter/Ctrl+R, moving the selection is allowed while
        // busy or connected: it only changes which row is selected,
        // it starts nothing. Holding a key repeats (egui
        // `key_pressed` includes repeat events). The row loop
        // scrolls the newly selected row into view (one-shot
        // `scroll_to_selected`).
        if !text_focused && !self.show_about {
            if ctx.input(|i| i.key_pressed(egui::Key::ArrowUp)) {
                self.move_selection(-1);
            } else if ctx.input(|i| i.key_pressed(egui::Key::ArrowDown)) {
                self.move_selection(1);
            }
        }
        // Del deletes the selected nodes — the same path (and the
        // same guards) as the 删除选中 button: nothing selected or
        // a job running means nothing happens, a connected node is
        // skipped and logged. Same focus guard as the shortcuts
        // above: in a text field Del deletes a character, never a
        // node; with the About window open it does nothing.
        if !text_focused
            && !self.show_about
            && ctx.input(|i| i.key_pressed(egui::Key::Delete))
        {
            self.delete_selected();
        }
        // Ctrl+A selects all displayed nodes (v3.15) — same focus
        // guard as the shortcuts above: in a text field Ctrl+A
        // stays the field's own select-all-text, never a node
        // selection; with the About window open it does nothing.
        if !text_focused
            && !self.show_about
            && ctx.input_mut(|i| {
                i.consume_shortcut(&egui::KeyboardShortcut::new(
                    egui::Modifiers::COMMAND,
                    egui::Key::A,
                ))
            })
        {
            self.select_all();
        }
        // Ctrl+C exports the selection, Ctrl+V imports from the
        // clipboard (see `handle_clipboard_events`): same focus
        // guard as the shortcuts above — a focused text field owns
        // its own copy/paste, and stealing it would break typing in
        // the manual-add / port / front-proxy fields.
        if !text_focused && !self.show_about {
            self.handle_clipboard_events(&ctx);
        }
        // Tray (Windows): drain tray-icon + menu events first, so a
        // tray click can show the window on this very frame.
        #[cfg(windows)]
        self.poll_tray_events(&ctx);
        // v3.15 single-instance: a second launch asked this
        // instance to come forward — same effect as a tray
        // double-click (`show_main_window`).
        if self.show_requested.swap(false, Ordering::SeqCst) {
            self.show_main_window(&ctx);
        }
        // While hidden in the tray the window gets no input, so keep
        // the event loop ticking — otherwise the tray poll above
        // would never run and a tray click could not bring the
        // window back.
        if self.hidden_to_tray {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        // Quitting while connected disconnects first (no confirm
        // needed). With a live tray (Windows) an X click hides the
        // window to the tray instead of quitting — only an explicit
        // quit (File menu 退出 / tray menu 退出, which set
        // `quit_requested` first) really exits. The close-requested
        // check is the eframe 0.36 mechanism (see epi.rs:
        // `close_requested()` + `ViewportCommand::CancelClose`).
        if ui.ctx().input(|i| i.viewport().close_requested()) {
            match tray::decide_close(self.tray_active(), self.quit_requested) {
                tray::CloseDecision::HideToTray => {
                    self.apply_close(tray::CloseDecision::HideToTray);
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
                tray::CloseDecision::Quit => self.perform_quit(),
            }
        }

        egui::Panel::top("menu_bar").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button("文件", |ui| {
                    // Export / import share the button and shortcut
                    // paths — no second implementation of either.
                    let can_export = self.can_delete();
                    let export_disabled_hint = if self.selected_set.is_empty() {
                        "请先选择要导出的节点（单击选一行，Ctrl+单击多选，或按 Ctrl+A 全选）"
                    } else {
                        "正在忙，请稍候"
                    };
                    if ui
                        .add_enabled(
                            can_export,
                            egui::Button::new("导出到剪切板").shortcut_text("Ctrl+C"),
                        )
                        .on_hover_text("把选中的节点按显示顺序导出到剪贴板（每行 主机:端口）")
                        .on_disabled_hover_text(export_disabled_hint)
                        .clicked()
                    {
                        let ctx = ui.ctx().clone();
                        self.export_selected(&ctx);
                        ui.close();
                    }
                    if ui
                        .add_enabled(can_export, egui::Button::new("导出到config"))
                        .on_hover_text("把选中的节点写进一个节点清单文件（默认 nodes_export.txt，每行 主机:端口）")
                        .on_disabled_hover_text(export_disabled_hint)
                        .clicked()
                    {
                        self.export_selected_to_file();
                        ui.close();
                    }
                    ui.separator();
                    let can_import = self.busy.is_none();
                    if ui
                        .add_enabled(
                            can_import,
                            egui::Button::new("从剪切板导入").shortcut_text("Ctrl+V"),
                        )
                        .on_hover_text("读剪贴板里的节点清单（每行 主机:端口），加进列表")
                        .on_disabled_hover_text("正在忙，请稍候")
                        .clicked()
                    {
                        self.import_from_clipboard();
                        ui.close();
                    }
                    if ui
                        .add_enabled(can_import, egui::Button::new("从文件config导入"))
                        .on_hover_text("从一个节点清单文件导入（每行 主机:端口）")
                        .on_disabled_hover_text("正在忙，请稍候")
                        .clicked()
                    {
                        self.import_from_file_dialog();
                        ui.close();
                    }
                    ui.separator();
                    // Select-all (v3.15): same action as the Ctrl+A
                    // shortcut — every displayed row, in display
                    // order. Always enabled: on an empty list it is
                    // a no-op, and it never needs a prior selection.
                    if ui
                        .add_enabled(
                            self.busy.is_none(),
                            egui::Button::new("全选").shortcut_text("Ctrl+A"),
                        )
                        .on_hover_text("选中当前显示的全部节点（按显示顺序；文本框里按 Ctrl+A 仍是选中文字）")
                        .on_disabled_hover_text("正在忙，请稍候")
                        .clicked()
                    {
                        self.select_all();
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("退出").clicked() {
                        // An explicit quit, not an X click: mark it
                        // so the close-requested handler really quits
                        // instead of hiding to the tray.
                        self.quit_requested = true;
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("帮助", |ui| {
                    if ui.button("关于").clicked() {
                        self.show_about = true;
                        ui.close();
                    }
                });
            });
        });

        egui::Panel::bottom("status_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                if let Some(c) = &self.conn {
                    ui.separator();
                    ui.label(format!("虚拟 IP {} · 本地 {}", c.vip, c.listen_addr));
                }
            });
            if !self.error.is_empty() {
                ui.label(egui::RichText::new(&self.error).color(ui.visuals().error_fg_color));
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            // egui's default scroll style is "floating": the bar is fully
            // transparent (dormant opacity 0) until the mouse hovers the
            // list, so "always visible" alone still shows nothing at rest.
            // v3.13 uses thick_scroll_style() instead of solid(): solid
            // bars are always drawn at rest, but only 6 px wide with a
            // low-contrast handle — the thick style is 12 px with a
            // foreground-colour handle, visible in both themes without
            // hovering. Set once here; every ScrollArea below (outer,
            // node list, advanced, log) inherits it.
            ui.style_mut().spacing.scroll = thick_scroll_style();
            // The panel is only 420 px tall at minimum size while the
            // content below the node list (advanced settings, log) needs
            // more room: one outer vertical scroll area wraps everything
            // so nothing is cut off without a way to reach it. The node
            // list and the log keep their own fixed-height scroll areas
            // inside it. `panel_h` is captured before entering the
            // scroll area (inside it the available height is unbounded).
            let panel_h = ui.available_height();
            // Test-only: pin the scroll to the bottom so the render test
            // can screenshot the end of 高级设置 and the log. (An
            // explicit scroll_offset(1e6) does NOT clamp — egui applies
            // it raw and the content scrolls out of view entirely, so
            // stick_to_bottom is the right tool here.)
            let outer = egui::ScrollArea::vertical()
                .id_salt("central")
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .stick_to_bottom(self.render_scroll_bottom);
            outer.show(ui, |ui| {
            if !self.font_ok {
                ui.label(
                    egui::RichText::new("未找到系统里的中文字体，中文可能显示为方框。")
                        .color(ui.visuals().warn_fg_color),
                );
            }
            // Toolbar: heading, source, refresh.
            ui.horizontal(|ui| {
                ui.heading("节点");
                ui.label(egui::RichText::new(&self.nodes_source).small());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let can_refresh = self.busy.is_none();
                    if ui
                        .add_enabled(
                            can_refresh,
                            egui::Button::new("刷新节点").min_size(egui::vec2(92.0, 32.0)),
                        )
                        .on_disabled_hover_text("正在忙，请稍候")
                        .clicked()
                    {
                        self.start_fetch(ui.ctx().clone());
                    }
                    // v3.15: API-only refresh, immediately left of
                    // "刷新节点" (right_to_left layout: added after
                    // it, so it lands on its left). Official API
                    // (CSV) only — no web scrape, no cache, no
                    // curated list; a failure is reported plainly
                    // and the list stays as it was.
                    if ui
                        .add_enabled(
                            can_refresh,
                            egui::Button::new("从API刷新节点")
                                .min_size(egui::vec2(124.0, 32.0)),
                        )
                        .on_disabled_hover_text("正在忙，请稍候")
                        .on_hover_text("只从官方 API（CSV）刷新，不含网页抓取备用；失败时明着失败，不会悄悄退到网页抓取。")
                        .clicked()
                    {
                        self.start_fetch_api_only(ui.ctx().clone());
                    }
                    if let Some(b) = self.busy {
                        ui.spinner();
                        if b == Busy::ProbingAll {
                            ui.label(format!(
                                "正在探测全部：{}/{}…",
                                self.probe_all_done, self.probe_all_total
                            ));
                        } else {
                            ui.label(b.label());
                        }
                    }
                });
            });
            ui.separator();

            // Node list (8 columns: a fixed 28 px status column with ∞
            // for the connected node, then country / ISP / 当前人数 /
            // 线路质量 / 人均带宽 / host:port / latency-status;
            // host:port merged so the grid fits a 560 px window —
            // hostnames alone are ~200 px wide).
            // Each row: (node index, status icon, country, isp,
            // sessions cell, quality cell, per-capita cell, host:port
            // shown, status, host:port full). Rows are built in display
            // order (see display_indices): fetch order by default, or
            // sorted by the column the user clicked. `selected` still
            // stores a node index.
            // v3.14 rows cache (diagnosis §3 item 7): the built rows
            // are reused while `list_fingerprint()` is unchanged, so
            // the ~1100 per-frame `String` allocations happen only
            // when the list actually changed. Taken out of the cache
            // for this frame (the row loop below still mutates
            // `self`) and put back after the outer scroll area.
            let (rows_fp, rows) = self.cached_rows();
            // v3.13: the dragged height wins; until the first drag the
            // old formula is the default (see effective_list_height).
            let list_h = self.effective_list_height(panel_h);
            // Recomputed in the row loop below; false when there is
            // no list or no selection (see the row loop).
            self.selected_row_in_view = false;
            if rows.is_empty() {
                ui.label("还没有节点。点右上角“刷新节点”，或在下面“高级设置”里手动添加。");
            } else {
                let list_out = egui::ScrollArea::both()
                    .id_salt("node_list")
                    .max_height(list_h)
                    .auto_shrink([false, false])
                    // Always show the scroll bars: with 28+ nodes the
                    // list overflows at 560x420, and a bar that only
                    // appears while scrolling is easy to miss entirely.
                    .scroll_bar_visibility(
                        egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                    )
                    .show(ui, |ui| {
                        // Tighter gaps so the columns fit a 560 px
                        // window at the default widths.
                        ui.spacing_mut().item_spacing = egui::vec2(6.0, 4.0);
                        // Status column (∞) is fixed 28 px and never
                        // resizable; the other seven columns （国家/地
                        // 区、运营商、当前人数、线路质量、人均带宽、
                        // 主机:端口、延迟/状态） all come from
                        // `col_widths` (config `node_col_widths`,
                        // 7 elements).
                        const STATUS_COL_W: f32 = 28.0;
                        let widths: [f32; 8] = [
                            STATUS_COL_W,
                            self.col_widths[0] as f32,
                            self.col_widths[1] as f32,
                            self.col_widths[2] as f32,
                            self.col_widths[3] as f32,
                            self.col_widths[4] as f32,
                            self.col_widths[5] as f32,
                            self.col_widths[6] as f32,
                        ];
                        // 30 px rows: 22 px was easy to miss, and a
                        // click that drifts a few pixels is lost to the
                        // scroll drag (see the tolerant-click note in
                        // the row loop below).
                        let row_h = 30.0;
                        // One row is 8 cells + 7 six-pixel separators +
                        // the 14 gaps between the 15 items. The status
                        // column has no separator (its gap is the same
                        // width, so the columns stay aligned).
                        let handle_w = 6.0f32;
                        let gap = ui.spacing().item_spacing.x;
                        let total_w =
                            widths.iter().sum::<f32>() + 7.0 * handle_w + 14.0 * gap;
                        // Rows span the full available width, not just
                        // the columns: at 800 px the old 554 px rows
                        // left ~200 px of dead space on the right of
                        // every row, and clicks there selected nothing.
                        let row_w = total_w.max(ui.available_width());
                        // Manual click tolerance: record the press
                        // position (frame-level) so the row loop can
                        // accept a press-and-release on the same row
                        // within 12 px — egui's own click needs under
                        // 6 px of movement (max_click_dist), and a real
                        // mouse easily drifts past that.
                        let (pressed, released, ptr_pos) = ui.input(|i| {
                            (
                                i.pointer.any_pressed(),
                                i.pointer.any_released(),
                                i.pointer.interact_pos(),
                            )
                        });
                        // Modifier keys for the row clicks below:
                        // Ctrl/Cmd+click toggles a row in the
                        // multi-select set, Shift+click selects a
                        // range from the anchor. `command` is Cmd on
                        // macOS and Ctrl elsewhere, so Ctrl+click works
                        // on both. The press-time modifiers are latched
                        // next to the press position (see
                        // `row_press_mods`): the click is completed on
                        // the release frame, and reading the modifiers
                        // only there loses the gesture when the user
                        // lets go of Shift/Ctrl a beat before the mouse
                        // button (the v3.7 Shift+click failure).
                        let click_mods = ui.input(|i| i.modifiers);
                        if pressed {
                            self.row_press_pos = ptr_pos;
                            self.row_press_mods = Some(click_mods);
                            // Clear first: the row loop below records
                            // the pressed row (if the press is on one);
                            // a stale value from an earlier gesture
                            // must not survive a press elsewhere.
                            self.row_press_node = None;
                        }
                        let (click_ctrl, click_shift) = Self::effective_click_mods(
                            self.row_press_mods,
                            click_mods,
                        );
                        if pressed {
                            self.row_press_pos = ptr_pos;
                        }
                        // Header row: labels plus a draggable separator
                        // after each resizable column but the last.
                        // Dragging resizes that column (40–400 px); the
                        // width is remembered in the settings and
                        // auto-saved to config.toml. The status column
                        // (index 0) has an empty header and no
                        // separator; the country （当前人数 / 线路质量 /
                        // 人均带宽 / 延迟/状态） columns (indices 1, 3,
                        // 4, 5, 7) are clickable to sort (see below).
                        // NOTE: the cells are placed at exact rects (like
                        // the data rows below), not via
                        // allocate_ui_with_layout: that advances the parent
                        // by the child's *content* size, so a short label
                        // would pull the separator and the next column left
                        // of its intended position, and the header would
                        // drift out of line with the data columns.
                        // Handles get explicit stable ids (not auto ids).
                        let (header_rect, _) = ui.allocate_exact_size(
                            egui::vec2(row_w, row_h),
                            egui::Sense::hover(),
                        );
                        // The arrow sits on the one column currently
                        // sorted (see `sort`); the other sortable
                        // headers show their bare label.
                        let sort_arrow = |col: SortCol| match self.sort {
                            Some((c, dir)) if c == col => format!(" {}", dir.arrow()),
                            _ => String::new(),
                        };
                        let country_label = format!("国家/地区{}", sort_arrow(SortCol::Country));
                        let sessions_label =
                            format!("当前人数{}", sort_arrow(SortCol::Sessions));
                        let quality_label =
                            format!("线路质量{}", sort_arrow(SortCol::Quality));
                        let per_capita_label =
                            format!("人均带宽{}", sort_arrow(SortCol::PerCapita));
                        let latency_label =
                            format!("延迟/状态{}", sort_arrow(SortCol::Latency));
                        let header_labels = [
                            "",
                            country_label.as_str(),
                            "运营商",
                            sessions_label.as_str(),
                            quality_label.as_str(),
                            per_capita_label.as_str(),
                            "主机:端口",
                            latency_label.as_str(),
                        ];
                        let mut x = header_rect.left();
                        for (i, label) in header_labels.iter().enumerate() {
                            let cell_rect = egui::Rect::from_min_size(
                                egui::pos2(x, header_rect.top()),
                                egui::vec2(widths[i], row_h),
                            );
                            put_cell_label(
                                ui,
                                cell_rect,
                                egui::RichText::new(*label).strong(),
                            );
                            // Sortable headers: country (1), 当前人数
                            // (3), 线路质量 (4), 人均带宽 (5), 延迟/状态
                            // (7). The label is drawn first and the
                            // interact sits on top of it (a Label has
                            // no sense, so it cannot eat the click).
                            // Clicking a header sorts by that column
                            // (first click = that column's most useful
                            // order); clicking it again reverses.
                            let sort_col = match i {
                                1 => Some(SortCol::Country),
                                3 => Some(SortCol::Sessions),
                                4 => Some(SortCol::Quality),
                                5 => Some(SortCol::PerCapita),
                                7 => Some(SortCol::Latency),
                                _ => None,
                            };
                            if let Some(col) = sort_col {
                                let tip = match col {
                                    SortCol::Country => {
                                        "点击按国家排序（A-Z / Z-A 切换）"
                                    }
                                    SortCol::Sessions => "点击按连接人数排序",
                                    SortCol::Quality => {
                                        "点击按线路质量排序（速度优先）"
                                    }
                                    SortCol::PerCapita => {
                                        "点击按人均带宽排序（人均速度从高到低）"
                                    }
                                    SortCol::Latency => {
                                        "点击按延迟排序：已测的按毫秒从小到大，未测的居中，失败的最后"
                                    }
                                };
                                let resp = ui
                                    .interact(
                                        cell_rect,
                                        egui::Id::new(("sort_col", i)),
                                        egui::Sense::click(),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(tip);
                                if resp.clicked() {
                                    self.toggle_sort(col);
                                }
                            }
                            x += widths[i];
                            if i < 7 {
                                x += gap;
                                // Separator after a resizable column
                                // only, and it resizes that column:
                                // country (1) -> col_widths[0], ISP
                                // (2) -> col_widths[1], 当前人数
                                // (3) -> col_widths[2], 线路质量
                                // (4) -> col_widths[3], 人均带宽
                                // (5) -> col_widths[4], host:port
                                // (6) -> col_widths[5]. The status
                                // column keeps the same gap but no
                                // handle, and the last column
                                // (延迟/状态， 7) has none — so it is
                                // the one resizable column that cannot
                                // be dragged (its width is still
                                // stored in col_widths[6]).
                                let sep_col = match i {
                                    1 => Some(0usize),
                                    2 => Some(1usize),
                                    3 => Some(2usize),
                                    4 => Some(3usize),
                                    5 => Some(4usize),
                                    6 => Some(5usize),
                                    _ => None,
                                };
                                if let Some(wi) = sep_col {
                                    let handle_rect = egui::Rect::from_min_size(
                                        egui::pos2(x, header_rect.top()),
                                        egui::vec2(handle_w, row_h),
                                    );
                                    let resp = ui.interact(
                                        handle_rect,
                                        egui::Id::new(("node_col_sep", wi)),
                                        egui::Sense::drag(),
                                    );
                                    let active = resp.hovered() || resp.dragged();
                                    // Apply the per-frame delta while
                                    // dragging, and also on release: a
                                    // drag whose pointer only moved in the
                                    // release event still carries its delta
                                    // then (kittest teleports this way).
                                    if resp.dragged() || resp.drag_stopped() {
                                        self.col_widths[wi] =
                                            (self.col_widths[wi] as f32
                                                + resp.drag_delta().x)
                                                .clamp(40.0, 400.0)
                                                as u16;
                                    }
                                    let stroke = if active {
                                        ui.visuals().widgets.active.bg_stroke
                                    } else {
                                        ui.visuals().widgets.noninteractive.bg_stroke
                                    };
                                    ui.painter().vline(
                                        handle_rect.center().x,
                                        handle_rect.y_range(),
                                        stroke,
                                    );
                                    resp.on_hover_cursor(egui::CursorIcon::ResizeColumn);
                                }
                                x += handle_w + gap;
                            }
                        }
                        // Data rows: whole-row click selects; text
                        // truncates with "…" to the current column width,
                        // and widening a column shows more of it (the
                        // horizontal scroll bar reveals the rest).
                        // The row rect spans the full available width
                        // (row_w, not just total_w) so clicks on the
                        // empty right part of a row still select it.
                        // Frame-level flag for the click mutual
                        // exclusion below: `clicked()` and the
                        // tolerant path must not both fire in one
                        // frame (they can land on different rows
                        // once the list has moved).
                        let mut row_clicked = false;
                        for (
                            display_i,
                            (node_idx, status_icon, country, isp, sessions, quality, per_capita, hostport, status, full),
                        ) in rows.iter().enumerate()
                        {
                            let (row_rect, row_resp) = ui.allocate_exact_size(
                                egui::vec2(row_w, row_h),
                                egui::Sense::click(),
                            );
                            // Record which row the press started on
                            // (v3.10 delete fix): the tolerant-click
                            // path below must fire for the PRESSED row,
                            // not for whatever row the release point
                            // happens to sit on after the list moved.
                            // Only a press inside the list's clip rect
                            // counts — the clip rect excludes the
                            // scrollbar strips, so a scrollbar press
                            // records no row and selects nothing.
                            if pressed {
                                if let Some(p) = self.row_press_pos {
                                    if row_rect.contains(p)
                                        && ui.clip_rect().contains(p)
                                    {
                                        self.row_press_node = Some(*node_idx);
                                    }
                                }
                            }
                            // Highlight follows the multi-select set
                            // (see `click_row`): every row in the set
                            // gets the indigo fill and white text.
                            // The arrow-key follow-scroll and the
                            // visibility bookkeeping below still track
                            // the anchor row only (`self.selected`).
                            let selected = self.selected_set.contains(node_idx);
                            let is_anchor = self.selected == Some(*node_idx);
                            // Arrow-key follow-scroll: a one-shot
                            // request from move_selection. Align None
                            // scrolls only as far as needed to bring
                            // the row into view (already-visible rows
                            // don't move the list). The target is
                            // consumed by this (innermost) ScrollArea.
                            if self.scroll_to_selected && is_anchor {
                                ui.scroll_to_rect(row_rect, None);
                                self.scroll_to_selected = false;
                            }
                            // Visibility bookkeeping for the arrow-key
                            // test: the clip rect is this list's
                            // viewport. Vertical only — rows span the
                            // full width and can run past the clip
                            // rect horizontally (the list scrolls
                            // sideways at 560 px), which says nothing
                            // about whether the row is on screen.
                            // Recomputed every frame (the scroll
                            // target above only takes effect after
                            // this frame's show).
                            if is_anchor {
                                let clip = ui.clip_rect();
                                self.selected_row_in_view = row_rect.top() >= clip.top()
                                    && row_rect.bottom() <= clip.bottom();
                            }
                            let fill = if selected {
                                ui.visuals().selection.bg_fill
                            } else if row_resp.hovered() {
                                ui.visuals().widgets.hovered.bg_fill
                            } else if display_i % 2 == 0 {
                                ui.visuals().faint_bg_color
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            ui.painter().rect_filled(row_rect, 0.0, fill);
                            // Selected-row text goes white (the indigo
                            // fill would swallow the default ink text).
                            let sel_text = ui.visuals().selection.stroke.color;
                            let cell_text = |t: &str| {
                                if selected {
                                    egui::RichText::new(t).color(sel_text)
                                } else {
                                    egui::RichText::new(t)
                                }
                            };
                            // Place each cell label at its exact rect
                            // (egui 0.36 has no allocate_ui_at_rect).
                            let cells = [
                                status_icon, country, isp, sessions, quality, per_capita,
                                hostport, status,
                            ];
                            let mut x = row_rect.left();
                            for (j, text) in cells.iter().enumerate() {
                                let cell_rect = egui::Rect::from_min_size(
                                    egui::pos2(x, row_rect.top()),
                                    egui::vec2(widths[j], row_h),
                                );
                                if j == 0 {
                                    // Status column: the ∞ mark for the
                                    // connected node, centred in the
                                    // 28 px cell, slightly larger than
                                    // body text so the glyph reads at
                                    // 30 px row height. (The glyph's
                                    // rendering is verified by the
                                    // render_infinity_glyph test — the
                                    // system CJK font must carry U+221E.)
                                    let accent =
                                        infinity_accent(ui.visuals().dark_mode);
                                    let color = if selected { sel_text } else { accent };
                                    ui.put(
                                        cell_rect,
                                        egui::Label::new(
                                            egui::RichText::new(text.as_str())
                                                .size(17.0)
                                                .color(color),
                                        )
                                        .halign(egui::Align::Center),
                                    );
                                } else {
                                    put_cell_label(ui, cell_rect, cell_text(text));
                                }
                                x += widths[j];
                                if j < 7 {
                                    // Gap, separator, gap — the same
                                    // symmetric spacing as the header row.
                                    x += gap + handle_w + gap;
                                }
                            }
                            // Full host:port on hover (the column shows it
                            // without the .opengw.net suffix).
                            let row_resp = row_resp
                                .on_hover_text(full)
                                .on_hover_cursor(egui::CursorIcon::PointingHand);
                            // Click selection (see `click_row`): plain
                            // click selects only this row, Ctrl/Cmd
                            // toggles it in the multi-select set,
                            // Shift selects a range from the anchor.
                            // The two paths below are exclusive: egui's
                            // own click and the tolerant click below
                            // both fire on the release frame for a
                            // press that barely moved, and calling
                            // `click_row` twice would undo the gesture
                            // (a Shift range would collapse back to the
                            // clicked row, a Ctrl toggle would toggle
                            // back out). `clicked()` wins when it fires;
                            // the tolerant path covers the 6–12 px drift
                            // egui's click misses. The exclusion is
                            // frame-level (`row_clicked`), not per-row:
                            // once the list has moved, the two paths
                            // can land on different rows. And the
                            // tolerant path fires only for the row the
                            // press started on (`row_press_node`) —
                            // never for the row the release point sits
                            // on now (the v3.9 delete bug: a press on
                            // a row, the list scrolling under the
                            // cursor, and the delete removing the
                            // wrong row).
                            let clicked = row_resp.clicked();
                            if clicked {
                                row_clicked = true;
                                self.click_row(*node_idx, click_ctrl, click_shift);
                            } else if released && !row_clicked {
                                if let (Some(origin), Some(pos)) =
                                    (self.row_press_pos, ptr_pos)
                                {
                                    // The 12 px budget still separates
                                    // a click from a real scroll drag.
                                    if origin.distance(pos) < 12.0
                                        && self.row_press_node == Some(*node_idx)
                                    {
                                        self.click_row(*node_idx, click_ctrl, click_shift);
                                    }
                                }
                            }
                        }
                        if released {
                            self.row_press_pos = None;
                            self.row_press_mods = None;
                            self.row_press_node = None;
                        }
                    });
                // The list's current scroll offset (the arrow-key
                // test reads it to prove the list actually scrolled).
                self.node_list_scroll_y = list_out.state.offset.y;
                // v3.13 resize handle: drag to change the list height
                // (120 px to panel minus 150 px). The dragged value
                // is stored and auto-saved; until the first drag the
                // formula height above is used.
                let mut list_h_drag = list_h;
                let list_rect = height_drag_handle(
                    ui,
                    "list_height_handle",
                    &mut list_h_drag,
                    120.0,
                    (panel_h - 150.0).max(120.0),
                    "拖动调整节点列表高度",
                );
                #[cfg(test)]
                {
                    self.list_handle_rect = Some(list_rect);
                }
                #[cfg(not(test))]
                let _ = list_rect;
                if list_h_drag != list_h {
                    self.list_height = Some(list_h_drag);
                }
            }

            // Primary action row (roomy buttons: 96x34).
            ui.horizontal(|ui| {
                let connected = self.conn.is_some();
                let can_act = self.busy.is_none() && self.selected.is_some();
                let btn_size = egui::vec2(96.0, 34.0);
                if connected {
                    if ui
                        .add(egui::Button::new("断开连接").min_size(btn_size))
                        .clicked()
                    {
                        self.disconnect();
                    }
                    // v3.13: the same switch path as Enter — disconnect
                    // the current node and connect the selected one
                    // (one start_connect call does both). Only when
                    // another node is selected; on the connected row
                    // itself it is disabled, like Enter is a no-op
                    // there. Before v3.13 this branch showed only
                    // 断开连接, so switching needed a manual
                    // disconnect first.
                    let can_switch = self.busy.is_none()
                        && self.selected.is_some()
                        && !self.selected_is_connected();
                    if ui
                        .add_enabled(
                            can_switch,
                            egui::Button::new("连接").min_size(btn_size),
                        )
                        .on_hover_text("断开当前节点并连接选中节点（回车）")
                        .on_disabled_hover_text(if self.selected.is_none() {
                            "请先在上面选择一个节点"
                        } else if self.selected_is_connected() {
                            "已连接的就是选中节点"
                        } else {
                            "正在忙，请稍候"
                        })
                        .clicked()
                    {
                        self.start_connect(ui.ctx().clone());
                    }
                } else {
                    let selection = ui.visuals().selection;
                    let connect = egui::Button::new(
                        egui::RichText::new("连接").color(selection.stroke.color),
                    )
                    .fill(selection.bg_fill)
                    .min_size(btn_size);
                    if ui
                        .add_enabled(can_act, connect)
                        .on_hover_text("连接选中节点（回车）")
                        .on_disabled_hover_text(if self.selected.is_none() {
                            "请先在上面选择一个节点"
                        } else {
                            "正在忙，请稍候"
                        })
                        .clicked()
                    {
                        self.start_connect(ui.ctx().clone());
                    }
                }
                if ui
                    .add_enabled(can_act, egui::Button::new("探测").min_size(btn_size))
                    .on_hover_text("探测选中节点（Ctrl+R）")
                    .on_disabled_hover_text(if self.selected.is_none() {
                        "请先在上面选择一个节点"
                    } else {
                        "正在忙，请稍候"
                    })
                    .clicked()
                {
                    self.start_probe(ui.ctx().clone());
                }
                // Probe-all: sweeps the whole list in display order,
                // one node at a time. While a sweep runs the same
                // button becomes 停止 (the sweep stops after the
                // node in flight; results already out are kept).
                // No selection needed — it probes everything.
                if self.busy == Some(Busy::ProbingAll) {
                    let stop_requested = self.probe_all_stop.load(Ordering::Relaxed);
                    if ui
                        .add_enabled(
                            !stop_requested,
                            egui::Button::new("停止").min_size(btn_size),
                        )
                        .on_hover_text("在当前节点探测结束后停下，已出的结果保留")
                        .on_disabled_hover_text("正在停止，等当前节点测完…")
                        .clicked()
                    {
                        self.stop_probe_all();
                    }
                } else {
                    let can_probe_all = self.busy.is_none() && !self.nodes.is_empty();
                    if ui
                        .add_enabled(
                            can_probe_all,
                            egui::Button::new("探测全部").min_size(btn_size),
                        )
                        .on_hover_text("按当前显示顺序，一个一个探测全部节点")
                        .on_disabled_hover_text(if self.nodes.is_empty() {
                            "列表里还没有节点"
                        } else {
                            "正在忙，请稍候"
                        })
                        .clicked()
                    {
                        self.start_probe_all(ui.ctx().clone());
                    }
                }
                match self.selected_node_label() {
                    Some(label) => ui.label(format!("已选：{}", label)),
                    None => ui.label("未选择节点"),
                };
            });
            // Batch delete: removes the multi-selected rows from the
            // list and records their hostnames on the persistent
            // blocklist, so a refresh never brings them back. Busy
            // jobs (probe / connect / refresh / probe-all) disable
            // it — same guard as 刷新节点. The restore button only
            // shows while the blocklist is non-empty.
            ui.horizontal(|ui| {
                let btn_size = egui::vec2(96.0, 34.0);
                let n_sel = self.selected_set.len();
                let delete_label = if n_sel > 0 {
                    format!("删除选中 ({})", n_sel)
                } else {
                    "删除选中".to_string()
                };
                if ui
                    .add_enabled(
                        self.can_delete(),
                        egui::Button::new(delete_label).min_size(btn_size),
                    )
                    .on_hover_text("删除选中的节点，并记入屏蔽列表（本次会话里隐藏，刷新后会带回来；或按 Del 键）")
                    .on_disabled_hover_text(if n_sel == 0 {
                        "请先选择要删除的节点（单击选一行，Ctrl+单击多选，或按 Ctrl+A 全选）"
                    } else {
                        "正在忙，请稍候"
                    })
                    .clicked()
                {
                    self.delete_selected();
                }
                // Export the selection to the clipboard (same guard
                // as delete): one `host:port` line per node, in
                // display order. Ctrl+C and the File menu use the
                // same `export_selected` path.
                let export_label = if n_sel > 0 {
                    format!("导出选中 ({})", n_sel)
                } else {
                    "导出选中".to_string()
                };
                if ui
                    .add_enabled(
                        self.can_delete(),
                        egui::Button::new(export_label).min_size(btn_size),
                    )
                    .on_hover_text("把选中的节点按显示顺序导出到剪贴板（每行 主机:端口）")
                    .on_disabled_hover_text(if n_sel == 0 {
                        "请先选择要导出的节点（单击选一行，Ctrl+单击多选，或按 Ctrl+A 全选）"
                    } else {
                        "正在忙，请稍候"
                    })
                    .clicked()
                {
                    let ctx = ui.ctx().clone();
                    self.export_selected(&ctx);
                }
                ui.label("Ctrl+单击多选，Shift+单击选一个范围，Ctrl+A 全选。");
            });
            // 常用开关和端口放主面板上，不用展开高级设置也能看到；改动会自动保存。
            // 本地端口只在连接时生效，连接中锁住；局域网分享用同一个
            // 混合端口（SOCKS5+HTTP），不再另开端口。
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.allow_lan, "允许局域网分享（混合端口同时监听 0.0.0.0）")
                    .on_hover_text("开启后，局域网里的其他设备也能连这个本地混合代理端口——同一个端口，不用再多占一个");
                ui.checkbox(&mut self.system_proxy, "设置系统代理（断开/退出时还原）")
                    .on_hover_text("开启后，系统代理会指到本地端口；关闭或退出时自动还原。");
            });
            ui.horizontal(|ui| {
                let connected = self.conn.is_some();
                ui.label("本地端口：");
                ui.add_enabled(
                    !connected,
                    egui::DragValue::new(&mut self.local_port).range(1..=65535),
                )
                .on_disabled_hover_text("连接中，断开后才能改端口");
                if connected {
                    ui.label("连接中，断开后才能改。");
                } else if self.allow_lan {
                    ui.label(format!(
                        "局域网设备连本机 IP:{}（同一混合端口）。",
                        self.local_port
                    ));
                } else {
                    ui.label("（勾选局域网分享后，局域网设备连本机 IP 用同一端口）");
                }
            });
            ui.separator();

            // Advanced settings.
            egui::CollapsingHeader::new("高级设置")
                .default_open(self.advanced_open)
                .show(ui, |ui| {
                    // v3.13: the body scrolls inside its own box, so a
                    // tall advanced section never pushes the log off
                    // the panel. Height = advanced_height (default
                    // 240 px, draggable via the handle below, which
                    // sits inside the header so it only shows while
                    // open). The body keeps its original indentation.
                    egui::ScrollArea::vertical()
                        .id_salt("advanced")
                        .max_height(self.advanced_height)
                        .auto_shrink([false, false])
                        .scroll_bar_visibility(
                            egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                        )
                        .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("手动添加节点：");
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.manual_host)
                                .hint_text("主机名:端口，例如 kanratown.opengw.net:992")
                                .desired_width(280.0),
                        );
                        if ui.button("添加").clicked() || resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            match parse_manual_target(&self.manual_host, vpngate::curated_nodes().len()) {
                                Ok(target) => {
                                    self.manual_error.clear();
                                    let (host, port) = match target.rsplit_once(':') {
                                        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
                                        None => (target.clone(), None),
                                    };
                                    // The node itself is built by
                                    // `manual_node` (no placeholders).
                                    let node = manual_node(host, port);
                                    self.nodes.insert(0, node);
                                    // The insert shifts every old index
                                    // by one, so the old multi-select
                                    // would point at the wrong rows:
                                    // replace it with just the new row,
                                    // like the anchor.
                                    self.selected = Some(0);
                                    self.selected_set = BTreeSet::from([0]);
                                    self.log_line(format!("手动添加节点：{}。", target));
                                    // The node must survive a restart
                                    // (and a restart-resume must find
                                    // it in the startup list): rewrite
                                    // the node cache, like an import
                                    // does — v3.15: without this, a
                                    // manually added node that was
                                    // connected and then restarted
                                    // came back as "不在列表里" and
                                    // never reconnected.
                                    if let Err(e) =
                                        vpngate::save_cached_nodes(&self.nodes)
                                    {
                                        self.log_warn(format!(
                                            "手动添加后写节点缓存失败：{}。",
                                            e
                                        ));
                                    }
                                    self.manual_host.clear();
                                }
                                Err(e) => {
                                    self.log_warn(format!("手动添加节点失败：{}。", e));
                                    self.manual_error = e;
                                }
                            }
                        }
                    });
                    if !self.manual_error.is_empty() {
                        ui.label(
                            egui::RichText::new(&self.manual_error)
                                .color(ui.visuals().error_fg_color),
                        );
                    }
                    ui.separator();
                    ui.checkbox(&mut self.front_enabled, "使用前置 SOCKS5 代理（连节点前先走它）");
                    ui.add_enabled_ui(self.front_enabled, |ui| {
                        egui::Grid::new("front_proxy_grid")
                            .num_columns(2)
                            .show(ui, |ui| {
                                ui.label("代理地址：");
                                ui.text_edit_singleline(&mut self.front_addr);
                                ui.end_row();
                                ui.label("用户名：");
                                ui.text_edit_singleline(&mut self.front_user);
                                ui.end_row();
                                ui.label("密码：");
                                ui.add(egui::TextEdit::singleline(&mut self.front_pass).password(true));
                                ui.end_row();
                            });
                    });
                    // Test the front proxy itself: with it off there is
                    // nothing to test, so the button stays disabled with
                    // a hint instead of running a misleading "direct" test.
                    ui.horizontal(|ui| {
                        let can_test = self.front_enabled
                            && !self.front_addr.trim().is_empty()
                            && self.busy.is_none();
                        if ui
                            .add_enabled(
                                can_test,
                                egui::Button::new("测试前置代理").min_size(egui::vec2(96.0, 32.0)),
                            )
                            .on_disabled_hover_text(if !self.front_enabled {
                                "先勾选“使用前置 SOCKS5 代理”，这个测试需要前置代理开着"
                            } else if self.front_addr.trim().is_empty() {
                                "先填代理地址"
                            } else {
                                "正在忙，请稍候"
                            })
                            .clicked()
                        {
                            self.start_test_front_proxy(ui.ctx().clone());
                        }
                        ui.label("测代理到 Google、vpngate.net（走 SOCKS5）。");
                    });
                    ui.separator();
                    ui.separator();
                    // Portable save: settings go to config.toml next to
                    // the exe, so the folder stays self-contained.
                    ui.horizontal(|ui| {
                        if ui
                            .add(
                                egui::Button::new("保存设置").min_size(egui::vec2(96.0, 32.0)),
                            )
                            .on_hover_text("设置改动会自动保存到程序目录下的 config.toml；点一下是手动再存一次")
                            .clicked()
                        {
                            self.save_settings();
                        }
                        match &self.config_path {
                            Some(p) => ui.label(
                                egui::RichText::new(format!("配置文件：{}", p.display())).small(),
                            ),
                            None => ui.label(
                                egui::RichText::new("配置文件：未保存（当前是默认设置）").small(),
                            ),
                        };
                    });
                    // Log file location: next to the exe, same folder as
                    // config.toml. Shown here so Leo can find it when
                    // reporting a problem (startup also logs the path).
                    match &self.log_path {
                        Some(p) => ui.label(
                            egui::RichText::new(format!("日志文件：{}", p.display())).small(),
                        ),
                        None => ui.label(
                            egui::RichText::new("日志文件：未开启").small(),
                        ),
                    };
                        });
                    // v3.13 resize handle for the advanced box
                    // (120–600 px). Inside the header, after the
                    // scroll area.
                    let mut adv_h = self.advanced_height;
                    let adv_rect = height_drag_handle(
                        ui,
                        "advanced_height_handle",
                        &mut adv_h,
                        120.0,
                        600.0,
                        "拖动调整高级设置高度",
                    );
                    #[cfg(test)]
                    {
                        self.advanced_handle_rect = Some(adv_rect);
                    }
                    #[cfg(not(test))]
                    let _ = adv_rect;
                    self.advanced_height =
                        vpngate_client::config::clamp_advanced_height(adv_h);
                });
            ui.separator();

            // Log.
            ui.label("日志");
            // v3.14: cached join (see cached_log_text) — the old
            // `self.log.join("\n")` re-allocated up to 100 lines
            // every frame. The height is read into a local first:
            // `log_view` borrows `self`, so no `self.*` field may
            // be touched while it lives.
            let log_height = self.log_height;
            let mut log_view = self.cached_log_text();
            egui::ScrollArea::vertical()
                .id_salt("log")
                .max_height(log_height)
                .auto_shrink([false, false])
                // v3.13: the log bar is always visible too (it was the
                // only one left on the default floating style).
                .scroll_bar_visibility(
                    egui::scroll_area::ScrollBarVisibility::AlwaysVisible,
                )
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut log_view)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                });
            // v3.13 resize handle for the log box (60–400 px).
            let mut log_h = log_height;
            let log_rect = height_drag_handle(
                ui,
                "log_height_handle",
                &mut log_h,
                60.0,
                400.0,
                "拖动调整日志高度",
            );
            #[cfg(test)]
            {
                self.log_handle_rect = Some(log_rect);
            }
            #[cfg(not(test))]
            let _ = log_rect;
            self.log_height = vpngate_client::config::clamp_log_height(log_h);
            // v3.14: put the rows back in the cache for the next frame.
            self.rows_cache = Some((rows_fp, rows));
            });
        });

        // Settings auto-save: any change made this frame (front proxy,
        // LAN sharing, system proxy, local port) is persisted now, so
        // closing without clicking 保存设置 loses nothing.
        self.auto_save_if_dirty();

        if self.show_about {
            egui::Window::new("关于 VPNGate 客户端")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label(format!(
                        "VPNGate 客户端 {}（Rust / egui）",
                        env!("CARGO_PKG_VERSION")
                    ));
                    ui.label("连 VPNGate 志愿者节点（MS-SSTP + PPP），本地开一个 SOCKS5 端口。");
                    ui.label("没有虚拟网卡，不改系统路由；系统代理默认关闭。");
                    ui.label("节点是陌生人家的宽带，随时可能下线，仅供试用。");
                    if ui.button("关闭").clicked() {
                        self.show_about = false;
                    }
                });
        }
    }
}

fn main() -> eframe::Result {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = rt.enter(); // lets tokio::spawn find the runtime
    // v3.15 single-instance (GUI only — the CLI is exempt): a
    // second launch signals the running instance to show its
    // window and exits, instead of opening a second window. A
    // restart successor (spawned with `--restart-wait-pid <old
    // pid>`) is NOT a duplicate: it waits for the old process to
    // exit first, then takes the lock — the two waits share one
    // policy in `single_instance::acquire_startup`. The guard
    // lives on this stack until the process exits; dropping it
    // would release the lock.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let wait_pid =
        vpngate_client::single_instance::parse_restart_wait_pid(&args);
    let _single_instance_guard =
        match vpngate_client::single_instance::acquire_startup(wait_pid) {
            vpngate_client::single_instance::StartupOutcome::Primary(guard) => {
                guard
            }
            vpngate_client::single_instance::StartupOutcome::SecondInstance => {
                std::process::exit(0);
            }
        };
    // v3.14: the window/taskbar icon is set explicitly from the
    // 32 px entry of the same assets/icon.ico the tray and the exe
    // use (decoded, never a loose PNG — icon-256.png is gitignored).
    // Without it the window fell back to the exe default.
    // v3.15: the lib returns a plain RGBA tuple
    // (`decode_window_icon_rgba`) and the GUI wraps it in
    // `egui::IconData` here, so the shared module no longer
    // references eframe — the CLI binary stops linking it.
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("VPNGate 客户端")
        .with_inner_size([800.0, 600.0])
        .with_min_inner_size([560.0, 420.0]);
    if let Some((rgba, width, height)) =
        vpngate_client::tray::decode_window_icon_rgba(include_bytes!(
            "../../assets/icon.ico"
        ))
    {
        viewport = viewport.with_icon(egui::IconData {
            rgba,
            width,
            height,
        });
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "vpngate-gui",
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
}

// ---------------------------------------------------------------------------
// Tests (headless; no window, no GPU)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Both tests that touch the shared portable config path
    /// (`config.toml` next to the test exe) must serialize: parallel
    /// writes to one path tear each other's files (a v3.11 run
    /// produced a half-written `node_col_widths` line) and a
    /// `remove_file` in one test can delete the other's file
    /// mid-assert. Hold this for the whole test body.
    static PORTABLE_CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn node(host: &str) -> Node {
        Node {
            host: host.to_string(),
            port: Some(992),
            country: "日本".to_string(),
            country_code: "JP".to_string(),
            isp: "NTT".to_string(),
            name: host.to_string(),
            score: 100,
            ping_ms: 10,
            speed_mbps: 50,
            sessions: 1,
            ip: "1.2.3.4".to_string(),
            backups: vec![],
            port_source: "curated".to_string(),
            source: "curated".to_string(),
        }
    }

    #[test]
    fn manual_target_parsing() {
        assert_eq!(
            parse_manual_target("kanratown.opengw.net:992", 28).unwrap(),
            "kanratown.opengw.net:992"
        );
        assert_eq!(
            parse_manual_target("  vpn1.opengw.net:443  ", 28).unwrap(),
            "vpn1.opengw.net:443"
        );
        assert_eq!(parse_manual_target("3", 28).unwrap(), "3");
        assert_eq!(
            parse_manual_target("kanratown.opengw.net", 28).unwrap(),
            "kanratown.opengw.net"
        );
        assert!(parse_manual_target("", 28).is_err());
        assert!(parse_manual_target("host:0", 28).is_err());
        assert!(parse_manual_target("host:70000", 28).is_err());
        assert!(parse_manual_target("host:notaport", 28).is_err());
        assert!(parse_manual_target("99", 28).is_err());
    }

    fn node_in(host: &str, country: &str) -> Node {
        let mut n = node(host);
        n.country = country.to_string();
        n
    }

    /// Plain-click a row by its cell label in a kittest harness.
    fn click_row_label(harness: &mut egui_kittest::Harness<'_, GuiApp>, label: &str) {
        use egui_kittest::kittest::Queryable;
        let cell = harness.get_by_label(label);
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
    }

    /// Shift+click a row by its cell label in a kittest harness:
    /// ModifiersChanged(shift) before the press and again before the
    /// release (egui only tracks modifiers from ModifiersChanged
    /// events; the row code latches them at press time).
    fn shift_click_row_label(
        harness: &mut egui_kittest::Harness<'_, GuiApp>,
        label: &str,
    ) {
        use egui_kittest::kittest::Queryable;
        let shift = egui::Modifiers {
            shift: true,
            ..Default::default()
        };
        let cell = harness.get_by_label(label);
        let center = cell.rect().center();
        harness.event(egui::Event::ModifiersChanged(shift));
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(shift));
        harness.drop_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
        harness.run();
    }

    /// Shift+click a row by its cell label, releasing Shift before
    /// the mouse button — the exact gesture Leo reported as broken
    /// (the modifiers must be latched at press time, or the range
    /// is lost and delete has nothing to remove).
    fn shift_click_row_label_early_release(
        harness: &mut egui_kittest::Harness<'_, GuiApp>,
        label: &str,
    ) {
        use egui_kittest::kittest::Queryable;
        let shift = egui::Modifiers {
            shift: true,
            ..Default::default()
        };
        let cell = harness.get_by_label(label);
        let center = cell.rect().center();
        harness.event(egui::Event::ModifiersChanged(shift));
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
        harness.drop_at(center);
        harness.run();
    }

    /// Click a button by its label in a kittest harness.
    fn click_button_label(harness: &mut egui_kittest::Harness<'_, GuiApp>, label: &str) {
        use egui_kittest::kittest::Queryable;
        let btn = harness.get_by_label(label);
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
    }

    /// Node with explicit listed stats (sessions / speed / ping).
    /// All three zero = no data (the curated 28); any nonzero =
    /// has data.
    fn node_stats(host: &str, country: &str, sessions: u64, speed_mbps: u64, ping_ms: u64) -> Node {
        let mut n = node_in(host, country);
        n.sessions = sessions;
        n.speed_mbps = speed_mbps;
        n.ping_ms = ping_ms;
        n
    }

    #[test]
    fn country_sort_orders_by_country_then_host() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("b.opengw.net", "美国"),
            node_in("a.opengw.net", "日本"),
            node_in("c.opengw.net", "日本"),
            node_in("d.opengw.net", "德国"),
        ];
        // Default: fetch order, no sorting.
        assert_eq!(app.display_indices(), vec![0, 1, 2, 3]);
        app.sort = Some((SortCol::Country, SortDir::Asc));
        // Chinese names sort by string (Unicode code-point) order:
        // 德国 U+5FB7 < 日本 U+65E5 < 美国 U+7F8E; same-country rows
        // break ties by hostname (a before c).
        assert_eq!(app.display_indices(), vec![3, 1, 2, 0]);
        app.sort = Some((SortCol::Country, SortDir::Desc));
        assert_eq!(app.display_indices(), vec![0, 2, 1, 3]);
    }

    #[test]
    fn country_sort_survives_refresh() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("b.opengw.net", "美国"),
            node_in("a.opengw.net", "日本"),
        ];
        app.sort = Some((SortCol::Country, SortDir::Asc));
        assert_eq!(app.display_indices(), vec![1, 0]);
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![
                node_in("z.opengw.net", "美国"),
                node_in("y.opengw.net", "德国"),
            ],
            source: vpngate::NodeListSource::Api,
            cache_age_secs: None,
            api_error: None,
            web_error: None,
        }));
        // New list, same chosen direction (德国 < 美国).
        assert_eq!(app.sort, Some((SortCol::Country, SortDir::Asc)));
        assert_eq!(app.display_indices(), vec![1, 0]);
    }

    #[test]
    fn sessions_sort_orders_few_first_then_many() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_stats("b.opengw.net", "日本", 47, 500, 10),
            node_stats("a.opengw.net", "日本", 0, 0, 0),
            node_stats("c.opengw.net", "日本", 301, 100, 5),
            node_stats("d.opengw.net", "日本", 5, 200, 20),
        ];
        assert_eq!(app.display_indices(), vec![0, 1, 2, 3]);
        app.sort = Some((SortCol::Sessions, SortDir::Asc));
        // Fewest first: 0, 5, 47, 301 (a no-data node has 0 sessions).
        assert_eq!(app.display_indices(), vec![1, 3, 0, 2]);
        app.sort = Some((SortCol::Sessions, SortDir::Desc));
        assert_eq!(app.display_indices(), vec![2, 0, 3, 1]);
    }

    #[test]
    fn quality_sort_orders_by_speed_then_ping_with_no_data_at_the_ends() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_stats("a.opengw.net", "日本", 10, 500, 30),
            node_stats("b.opengw.net", "日本", 10, 500, 10),
            node_stats("c.opengw.net", "日本", 10, 100, 5),
            node_stats("d.opengw.net", "日本", 0, 0, 0),
        ];
        app.sort = Some((SortCol::Quality, SortDir::Desc));
        // First click: fastest first; same speed -> smaller ping
        // first; the no-data node last.
        assert_eq!(app.display_indices(), vec![1, 0, 2, 3]);
        app.sort = Some((SortCol::Quality, SortDir::Asc));
        // Reversed: no-data first, slowest first; same speed ->
        // larger ping first.
        assert_eq!(app.display_indices(), vec![3, 2, 0, 1]);
    }

    #[test]
    fn api_speed_bps_converts_to_mbps_in_quality_cell() {
        // Leo's v3.6 report: 线路质量 showed "77570260M" — the API
        // Speed column is bits per second, not Mbps. Parse the
        // real-magnitude row and check the cell the GUI shows.
        let csv = "# comment\n* vpn_servers\nHostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\nvpn267947139.opengw.net,1.2.3.4,1000000,12,77570260,Japan,JP,47,1000,2000,3000,0,SoftBank BB,,AAAA\n";
        let nodes = vpngate::parse_api_csv(csv);
        assert_eq!(nodes.len(), 1);
        assert_eq!(quality_cell(&nodes[0]), "78M@12ms");
        assert_eq!(sessions_cell(&nodes[0]), "47人");
    }

    #[test]
    fn quality_sort_compares_api_and_scrape_speeds_like_for_like() {
        // Before the v3.7 fix, API nodes stored raw bps in
        // speed_mbps, so an API node at 77.6 Mbps sorted as
        // 77,570,260 and always beat scrape nodes (whole Mbps) in
        // the quality sort. After the fix both are Mbps.
        let csv = "# comment\n* vpn_servers\nHostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\nvpn267947139.opengw.net,1.2.3.4,1000000,12,77570260,Japan,JP,47,1000,2000,3000,0,SoftBank BB,,AAAA\n";
        let api = vpngate::parse_api_csv(csv).into_iter().next().unwrap();
        assert_eq!(api.speed_mbps, 78);
        // Scrape node: "261.83 Mbps" from the page → 262 Mbps.
        let scrape = node_stats("s.opengw.net", "日本", 70, 262, 8);
        let mut app = GuiApp::for_tests();
        app.nodes = vec![api, scrape];
        app.sort = Some((SortCol::Quality, SortDir::Desc));
        // Fastest first: 262 Mbps scrape node before 78 Mbps API node.
        assert_eq!(app.display_indices(), vec![1, 0]);
        app.sort = Some((SortCol::Quality, SortDir::Asc));
        assert_eq!(app.display_indices(), vec![0, 1]);
    }

    #[test]
    fn toggle_sort_resets_direction_when_switching_columns() {
        let mut app = GuiApp::for_tests();
        app.sort = Some((SortCol::Country, SortDir::Desc));
        app.toggle_sort(SortCol::Sessions);
        assert_eq!(
            app.sort,
            Some((SortCol::Sessions, SortDir::Asc)),
            "switching to sessions starts few-first"
        );
        app.toggle_sort(SortCol::Sessions);
        assert_eq!(
            app.sort,
            Some((SortCol::Sessions, SortDir::Desc)),
            "same column again reverses"
        );
        app.toggle_sort(SortCol::Quality);
        assert_eq!(
            app.sort,
            Some((SortCol::Quality, SortDir::Desc)),
            "switching to quality starts fastest-first"
        );
        app.toggle_sort(SortCol::PerCapita);
        assert_eq!(
            app.sort,
            Some((SortCol::PerCapita, SortDir::Desc)),
            "switching to per-capita starts highest-first"
        );
        app.toggle_sort(SortCol::PerCapita);
        assert_eq!(
            app.sort,
            Some((SortCol::PerCapita, SortDir::Asc)),
            "same column again reverses"
        );
        app.toggle_sort(SortCol::Latency);
        assert_eq!(
            app.sort,
            Some((SortCol::Latency, SortDir::Asc)),
            "switching to latency starts available-first by ms"
        );
        app.toggle_sort(SortCol::Country);
        assert_eq!(
            app.sort,
            Some((SortCol::Country, SortDir::Asc)),
            "switching back to country starts A-Z"
        );
    }

    #[test]
    fn sessions_and_quality_cells_format() {
        // API node with data: "47人" / "572M@3ms".
        let n = node_stats("a.opengw.net", "日本", 47, 572, 3);
        assert_eq!(sessions_cell(&n), "47人");
        assert_eq!(quality_cell(&n), "572M@3ms");
        // Curated node: all three zero -> "—" in both cells.
        let n = node_stats("b.opengw.net", "日本", 0, 0, 0);
        assert_eq!(sessions_cell(&n), "—");
        assert_eq!(quality_cell(&n), "—");
        // Data but zero sessions: "0人", not "—".
        let n = node_stats("c.opengw.net", "日本", 0, 100, 5);
        assert_eq!(sessions_cell(&n), "0人");
        assert_eq!(quality_cell(&n), "100M@5ms");
    }

    #[test]
    fn per_capita_cell_formats() {
        // 572 / 47 = 12.17… -> "12.2M/人" (one decimal, rounded).
        let n = node_stats("a.opengw.net", "日本", 47, 572, 3);
        assert_eq!(per_capita_cell(&n), "12.2M/人");
        // Zero sessions but data: one user alone gets the whole
        // line — the total speed itself.
        let n = node_stats("b.opengw.net", "日本", 0, 100, 5);
        assert_eq!(per_capita_cell(&n), "100.0M/人");
        // Curated node: all three zero -> "—".
        let n = node_stats("c.opengw.net", "日本", 0, 0, 0);
        assert_eq!(per_capita_cell(&n), "—");
        // Speed zero but sessions present: "0.0M/人", not "—".
        let n = node_stats("d.opengw.net", "日本", 10, 0, 5);
        assert_eq!(per_capita_cell(&n), "0.0M/人");
        // Exact division keeps one decimal: 100 / 4 = 25.0.
        let n = node_stats("e.opengw.net", "日本", 4, 100, 5);
        assert_eq!(per_capita_cell(&n), "25.0M/人");
    }

    #[test]
    fn per_capita_sort_orders_high_first_with_no_data_last() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            // a: 500/10 = 50.0, b: 100/5 = 20.0, c: 200/1 = 200.0
            // (few sessions, huge share), d: no data, e: 0/100 = 0.0
            // (alone on the line — the whole 100 Mbps is theirs).
            node_stats("a.opengw.net", "日本", 10, 500, 10),
            node_stats("b.opengw.net", "日本", 5, 100, 5),
            node_stats("c.opengw.net", "日本", 1, 200, 20),
            node_stats("d.opengw.net", "日本", 0, 0, 0),
            node_stats("e.opengw.net", "日本", 0, 100, 5),
        ];
        app.sort = Some((SortCol::PerCapita, SortDir::Desc));
        // First click: highest per-capita first (c 200.0, e 100.0,
        // a 50.0, b 20.0); the no-data node last.
        assert_eq!(app.display_indices(), vec![2, 4, 0, 1, 3]);
        app.sort = Some((SortCol::PerCapita, SortDir::Asc));
        // Reversed: no-data first, then lowest first.
        assert_eq!(app.display_indices(), vec![3, 1, 0, 4, 2]);
    }

    #[test]
    fn latency_sort_orders_available_then_unprobed_then_failed() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "日本"),
            node_in("c.opengw.net", "日本"),
            node_in("d.opengw.net", "日本"),
            node_in("e.opengw.net", "日本"),
            node_in("f.opengw.net", "日本"),
        ];
        // a: 120 ms, b/f: 30 ms (tie), c: unprobed, d: failed,
        // e: probing (counts as unprobed).
        app.probe_ms.insert("a.opengw.net".to_string(), 120);
        app.probes
            .insert("a.opengw.net".to_string(), "120 ms".to_string());
        app.probe_ms.insert("b.opengw.net".to_string(), 30);
        app.probes
            .insert("b.opengw.net".to_string(), "30 ms".to_string());
        app.probe_ms.insert("f.opengw.net".to_string(), 30);
        app.probes
            .insert("f.opengw.net".to_string(), "30 ms".to_string());
        app.probes
            .insert("d.opengw.net".to_string(), "失败".to_string());
        app.probes
            .insert("e.opengw.net".to_string(), "探测中…".to_string());
        app.sort = Some((SortCol::Latency, SortDir::Asc));
        // Available by ms ascending (b/f tie -> host a-z), then
        // unprobed (c, e), then failed.
        assert_eq!(app.display_indices(), vec![1, 5, 0, 2, 4, 3]);
        app.sort = Some((SortCol::Latency, SortDir::Desc));
        // Whole order reversed: failed first, unprobed middle,
        // available by ms descending last.
        assert_eq!(app.display_indices(), vec![3, 4, 2, 0, 5, 1]);
    }

    #[test]
    fn probe_ms_tracks_probe_events() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本")];
        // A successful probe stores the ms alongside the display
        // string — the latency sort reads this number, never the
        // string.
        app.apply_event(GuiEvent::Probe {
            host: "a.opengw.net".to_string(),
            result: Ok((
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::time::Duration::from_millis(42),
            )),
        });
        assert_eq!(app.probe_ms.get("a.opengw.net"), Some(&42));
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("42 ms")
        );
        // A sweep progress event clears it (the row shows 探测中…).
        app.busy = Some(Busy::ProbingAll);
        app.apply_event(GuiEvent::ProbeAllProgress {
            current: "a.opengw.net".to_string(),
            done: 0,
            total: 1,
        });
        assert_eq!(app.probe_ms.get("a.opengw.net"), None);
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("探测中…")
        );
        // A sweep failure leaves no ms behind.
        app.apply_event(GuiEvent::ProbeAllResult {
            host: "a.opengw.net".to_string(),
            result: Err(ProbeFailure::NodeDown("no route".to_string())),
            done: 1,
            total: 1,
        });
        assert_eq!(app.probe_ms.get("a.opengw.net"), None);
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("失败")
        );
        // A sweep success stores it again.
        app.apply_event(GuiEvent::ProbeAllResult {
            host: "a.opengw.net".to_string(),
            result: Ok((
                std::net::Ipv4Addr::new(10, 0, 0, 2),
                std::time::Duration::from_millis(7),
            )),
            done: 1,
            total: 1,
        });
        assert_eq!(app.probe_ms.get("a.opengw.net"), Some(&7));
    }

    #[test]
    fn shortcut_action_guards() {
        let mut app = GuiApp::for_tests();
        // Nothing selected: neither shortcut fires.
        assert_eq!(app.shortcut_action(true, false, false), None);
        assert_eq!(app.shortcut_action(false, true, false), None);
        app.selected = Some(0);
        assert_eq!(
            app.shortcut_action(true, false, false),
            Some(ShortcutAction::Connect),
            "Enter connects the selected node"
        );
        assert_eq!(
            app.shortcut_action(false, true, false),
            Some(ShortcutAction::Probe),
            "Ctrl+R probes the selected node"
        );
        assert_eq!(
            app.shortcut_action(true, true, false),
            Some(ShortcutAction::Connect),
            "Enter wins when both are pressed"
        );
        // A text field has focus: typing must never trigger either.
        assert_eq!(app.shortcut_action(true, false, true), None);
        assert_eq!(app.shortcut_action(false, true, true), None);
        // Busy or About open: blocked.
        app.busy = Some(Busy::Fetching);
        assert_eq!(app.shortcut_action(true, false, false), None);
        app.busy = None;
        app.show_about = true;
        assert_eq!(app.shortcut_action(true, false, false), None);
        assert_eq!(app.shortcut_action(false, true, false), None);
    }

    #[test]
    fn move_selection_follows_display_order_and_stops_at_ends() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("b.opengw.net", "美国"),
            node_in("a.opengw.net", "日本"),
            node_in("c.opengw.net", "德国"),
        ];
        // No selection yet: ↓ picks the first row, ↑ picks the last.
        app.move_selection(1);
        assert_eq!(app.selected, Some(0));
        assert!(app.scroll_to_selected, "moving must request a follow-scroll");
        app.scroll_to_selected = false;
        app.selected = None;
        app.move_selection(-1);
        assert_eq!(app.selected, Some(2));
        app.scroll_to_selected = false;
        // Step down, up, and stop at the top (no change, no scroll).
        app.move_selection(-1);
        assert_eq!(app.selected, Some(1));
        app.scroll_to_selected = false;
        app.move_selection(-1);
        assert_eq!(app.selected, Some(0));
        app.scroll_to_selected = false;
        app.move_selection(-1);
        assert_eq!(app.selected, Some(0), "↑ at the top must not move");
        assert!(
            !app.scroll_to_selected,
            "no movement means no follow-scroll request"
        );
        // Walk to the bottom and stop there too.
        app.move_selection(1);
        app.move_selection(1);
        assert_eq!(app.selected, Some(2));
        app.scroll_to_selected = false;
        app.move_selection(1);
        assert_eq!(app.selected, Some(2), "↓ at the bottom must not move");
        assert!(!app.scroll_to_selected);
        // Sorted list: movement follows the shown order (德国 <
        // 日本 < 美国 in A-Z, i.e. display [2, 1, 0]).
        app.sort = Some((SortCol::Country, SortDir::Asc));
        app.selected = None;
        app.move_selection(1);
        assert_eq!(app.selected, Some(2), "first in A-Z order is 德国");
        app.move_selection(1);
        assert_eq!(app.selected, Some(1), "second is 日本");
        app.move_selection(1);
        assert_eq!(app.selected, Some(0), "third is 美国");
        // Empty list: nothing to move to.
        app.nodes = vec![];
        app.selected = None;
        app.move_selection(1);
        assert_eq!(app.selected, None);
        app.move_selection(-1);
        assert_eq!(app.selected, None);
    }

    /// Selection model: plain click selects one row, Ctrl+click
    /// toggles rows in/out of the set, Shift+click selects the
    /// range from the anchor to the clicked row in display order,
    /// and every click moves the anchor to the clicked row.
    #[test]
    fn click_row_selection_model() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
            node_in("c.opengw.net", "德国"),
            node_in("d.opengw.net", "法国"),
            node_in("e.opengw.net", "英国"),
        ];
        // Shift+click with no anchor yet: just this row.
        app.click_row(2, false, true);
        assert_eq!(app.selected, Some(2));
        assert_eq!(app.selected_set, BTreeSet::from([2]));
        // Plain click: only that row, anchor moves.
        app.click_row(1, false, false);
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.selected_set, BTreeSet::from([1]));
        // Ctrl+click adds a row; anchor moves to it.
        app.click_row(3, true, false);
        assert_eq!(app.selected, Some(3));
        assert_eq!(app.selected_set, BTreeSet::from([1, 3]));
        // Ctrl+click again toggles it back out; the anchor stays on
        // the clicked row even though it is no longer in the set.
        app.click_row(1, true, false);
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.selected_set, BTreeSet::from([3]));
        // Shift+click from the anchor (1) to row 4: the whole range.
        app.click_row(4, false, true);
        assert_eq!(app.selected, Some(4));
        assert_eq!(app.selected_set, BTreeSet::from([1, 2, 3, 4]));
        // Shift+click backwards (anchor 4 -> row 0): the range the
        // other way, anchor moves to row 0.
        app.click_row(0, false, true);
        assert_eq!(app.selected, Some(0));
        assert_eq!(
            app.selected_set,
            BTreeSet::from([0, 1, 2, 3, 4])
        );
        // Plain click collapses back to one row.
        app.click_row(2, false, false);
        assert_eq!(app.selected, Some(2));
        assert_eq!(app.selected_set, BTreeSet::from([2]));
        // Shift+click follows display order, not list order: sorted
        // A-Z by country string (code points: 德国 U+5FB7 < 日本
        // U+65E5 < 法国 U+6CD5 < 美国 U+7F8E < 英国 U+82F1), the
        // display is [2 德国， 0 日本， 3 法国， 1 美国， 4 英国].
        // The anchor is row 2 (display position 0); Shift+clicking
        // row 1 (display position 3) selects display[0..=3].
        app.sort = Some((SortCol::Country, SortDir::Asc));
        assert_eq!(app.display_indices(), vec![2, 0, 3, 1, 4]);
        app.click_row(1, false, true);
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.selected_set, BTreeSet::from([0, 1, 2, 3]));
    }

    /// The click modifiers are the press-time latch OR the release
    /// v3.15: select_all takes every displayed row (display
    /// order, not insertion order) and moves the anchor to the
    /// first displayed row; the export set follows the same
    /// order, so Ctrl+A then Ctrl+C exports the whole list.
    #[test]
    fn select_all_selects_display_order_and_sets_anchor_to_first() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
            node_in("c.opengw.net", "德国"),
            node_in("d.opengw.net", "日本"),
        ];
        // Display order by country: 德国 (c) / 日本 (a, d) / 美国 (b).
        app.sort = Some((SortCol::Country, SortDir::Asc));
        app.click_row(1, false, false);
        assert_eq!(app.selected, Some(1), "anchor starts on 美国");
        app.select_all();
        assert_eq!(app.selected_set, BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(
            app.selected,
            Some(2),
            "the anchor must be the first DISPLAYED row (德国, node 2)"
        );
        let exported = app.selected_nodes_in_display_order();
        assert_eq!(
            exported
                .iter()
                .map(|n| n.host.as_str())
                .collect::<Vec<_>>(),
            vec![
                "c.opengw.net",
                "a.opengw.net",
                "d.opengw.net",
                "b.opengw.net"
            ],
            "the export set must follow display order"
        );
    }

    /// v3.15: select_all on an empty list changes nothing.
    #[test]
    fn select_all_on_empty_list_is_a_noop() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![];
        app.select_all();
        assert!(app.selected_set.is_empty());
        assert_eq!(app.selected, None);
    }

    /// frame's: releasing Shift/Ctrl a beat before the mouse button
    /// must not lose the gesture (the v3.7 Shift+click failure),
    /// Shift pressed mid-click counts too, and Cmd counts as Ctrl.
    #[test]
    fn effective_click_mods_latches_press_time_modifiers() {
        let shift = egui::Modifiers {
            shift: true,
            ..Default::default()
        };
        let ctrl = egui::Modifiers {
            ctrl: true,
            ..Default::default()
        };
        let command = egui::Modifiers {
            command: true,
            ..Default::default()
        };
        let none = egui::Modifiers::default();
        // Shift held at press, released before the mouse button.
        assert_eq!(
            GuiApp::effective_click_mods(Some(shift), none),
            (false, true)
        );
        // Shift pressed mid-click (after the press, before release).
        assert_eq!(
            GuiApp::effective_click_mods(Some(none), shift),
            (false, true)
        );
        // Held through the whole click.
        assert_eq!(
            GuiApp::effective_click_mods(Some(shift), shift),
            (false, true)
        );
        // No modifiers at either end: a plain click.
        assert_eq!(
            GuiApp::effective_click_mods(Some(none), none),
            (false, false)
        );
        // No press latch at all (a press+release in one frame
        // before the latch was recorded): fall back to the current
        // frame's modifiers.
        assert_eq!(GuiApp::effective_click_mods(None, shift), (false, true));
        assert_eq!(GuiApp::effective_click_mods(None, none), (false, false));
        // Ctrl at press time only, and Cmd counts as Ctrl.
        assert_eq!(
            GuiApp::effective_click_mods(Some(ctrl), none),
            (true, false)
        );
        assert_eq!(
            GuiApp::effective_click_mods(Some(command), none),
            (true, false)
        );
        assert_eq!(
            GuiApp::effective_click_mods(Some(none), command),
            (true, false)
        );
        // Ctrl+Shift together survive.
        let both = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..Default::default()
        };
        assert_eq!(
            GuiApp::effective_click_mods(Some(both), none),
            (true, true)
        );
    }

    /// Arrow keys keep the v3.4 behaviour and collapse the
    /// multi-select to just the row the anchor moved to.
    #[test]
    fn arrow_keys_collapse_multi_select_to_anchor() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
            node_in("c.opengw.net", "德国"),
        ];
        app.click_row(0, false, false);
        app.click_row(2, true, false);
        assert_eq!(app.selected_set, BTreeSet::from([0, 2]));
        app.move_selection(-1);
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.selected_set, BTreeSet::from([1]));
        app.move_selection(-1);
        assert_eq!(app.selected, Some(0));
        assert_eq!(app.selected_set, BTreeSet::from([0]));
        // ↓ from the anchor also collapses (and stops at the end).
        app.move_selection(1);
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.selected_set, BTreeSet::from([1]));
    }

    fn four_nodes() -> Vec<Node> {
        vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
            node_in("c.opengw.net", "德国"),
            node_in("d.opengw.net", "法国"),
        ]
    }

    /// Delete: removes the selected nodes from the list, records
    /// their hostnames on the persistent blocklist, cleans their
    /// probe results, and clears the selection. The blocklist
    /// round-trips through the config.
    #[test]
    fn delete_selected_removes_and_blocks() {
        let mut app = GuiApp::for_tests();
        app.nodes = four_nodes();
        app.probes
            .insert("c.opengw.net".to_string(), "10 ms".to_string());
        app.probe_ms.insert("c.opengw.net".to_string(), 10);
        app.probes
            .insert("a.opengw.net".to_string(), "5 ms".to_string());
        app.probe_ms.insert("a.opengw.net".to_string(), 5);
        app.click_row(0, false, false);
        app.click_row(2, true, false);
        assert_eq!(app.selected_set, BTreeSet::from([0, 2]));
        app.delete_selected();
        let hosts: Vec<&str> = app.nodes.iter().map(|n| n.host.as_str()).collect();
        assert_eq!(hosts, vec!["b.opengw.net", "d.opengw.net"]);
        assert_eq!(
            app.blocked_hosts,
            BTreeSet::from(["a.opengw.net".to_string(), "c.opengw.net".to_string()])
        );
        // Probe results for the deleted hosts are gone; the kept
        // node's stay untouched (none recorded for b/d here).
        assert!(!app.probes.contains_key("c.opengw.net"));
        assert!(!app.probe_ms.contains_key("c.opengw.net"));
        assert!(!app.probes.contains_key("a.opengw.net"));
        // Selection is cleared.
        assert_eq!(app.selected, None);
        assert!(app.selected_set.is_empty());
        // The blocklist persists through the config round-trip.
        let cfg = app.current_config();
        assert_eq!(
            cfg.blocked_hosts,
            vec!["a.opengw.net".to_string(), "c.opengw.net".to_string()]
        );
        let mut app2 = GuiApp::for_tests();
        app2.apply_config(&cfg);
        assert_eq!(app2.blocked_hosts, app.blocked_hosts);
    }

    /// Delete skips the connected node: it stays in the list and the
    /// skip is logged. (`delete_selected_except` takes the connected
    /// host directly so the skip is testable without a live tunnel;
    /// `delete_selected` passes `connected_node_host()`.)
    #[test]
    fn delete_selected_skips_connected_node() {
        let mut app = GuiApp::for_tests();
        app.nodes = four_nodes();
        app.click_row(0, false, false);
        app.click_row(1, true, false);
        let (removed, skipped) = app.delete_selected_except(Some("b.opengw.net"));
        assert_eq!((removed, skipped), (1, 1));
        let hosts: Vec<&str> = app.nodes.iter().map(|n| n.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["b.opengw.net", "c.opengw.net", "d.opengw.net"]
        );
        assert_eq!(
            app.blocked_hosts,
            BTreeSet::from(["a.opengw.net".to_string()])
        );
        // The connected node was skipped even though it was selected.
        assert!(app.nodes.iter().any(|n| n.host == "b.opengw.net"));
    }

    /// The full delete path logs the connected-node skip in the
    /// visible log (same wording the user sees). Goes through the
    /// real reporting path with the connected host supplied
    /// directly (no live tunnel in unit tests).
    #[test]
    fn delete_selected_logs_connected_skip() {
        let mut app = GuiApp::for_tests();
        app.nodes = four_nodes();
        app.click_row(0, false, false);
        app.click_row(1, true, false);
        app.delete_selected_with_connected(Some("b.opengw.net"));
        assert!(
            app.log.iter().any(|l| l.contains("已连接的节点不能删除，已跳过 1")),
            "skip must be logged: {:?}",
            app.log
        );
        assert_eq!(app.nodes.len(), 3);
        assert!(app.nodes.iter().any(|n| n.host == "b.opengw.net"));
    }

    /// Busy guard: with a job running, deletion is disabled and a
    /// direct call is a no-op; with nothing running it is allowed.
    #[test]
    fn delete_selected_blocked_when_busy() {
        let mut app = GuiApp::for_tests();
        app.nodes = four_nodes();
        app.click_row(0, false, false);
        assert!(app.can_delete());
        app.busy = Some(Busy::Probing);
        assert!(!app.can_delete());
        app.delete_selected();
        assert_eq!(app.nodes.len(), 4, "busy delete must be a no-op");
        assert!(app.blocked_hosts.is_empty());
        app.busy = Some(Busy::ProbingAll);
        assert!(!app.can_delete());
        app.busy = None;
        assert!(app.can_delete());
        // Empty selection disables it too.
        app.clear_selection();
        assert!(!app.can_delete());
    }

    #[test]
    fn export_nodes_text_joins_display_order_with_ports() {
        // Order is the caller's (display) order, not sorted here.
        // v3.12 format: host:port, then country / operator / users
        // / speed-Mbps tab-separated (the node() fixture carries
        // isp "NTT", 1 session, 50 Mbps).
        let mut a = node_in("b.opengw.net", "美国");
        a.port = Some(443);
        let mut b = node_in("a.opengw.net", "日本");
        b.port = Some(992);
        let mut c = node_in("c.opengw.net", "德国");
        c.port = Some(995);
        assert_eq!(
            export_nodes_text(&[a, b, c], &HashMap::new()),
            "b.opengw.net:443\t美国\tNTT\t1\t50\t\na.opengw.net:992\t日本\tNTT\t1\t50\t\nc.opengw.net:995\t德国\tNTT\t1\t50\t"
        );
    }

    #[test]
    fn export_nodes_text_bare_host_for_unknown_port() {
        // A port-less node (API nodes arrive without one) exports
        // as a bare host — never an invented port — and a bare API
        // label is completed, the same target a connect dials.
        // Metadata columns are still appended (empty when unknown).
        let mut a = node_in("public-vpn-192", "日本");
        a.port = None;
        a.sessions = 0;
        a.speed_mbps = 0;
        let mut b = node_in("x.opengw.net", "美国");
        b.port = None;
        assert_eq!(
            export_nodes_text(&[a, b], &HashMap::new()),
            "public-vpn-192.opengw.net\t日本\tNTT\t\t\t\nx.opengw.net\t美国\tNTT\t1\t50\t"
        );
        assert_eq!(export_nodes_text(&[], &HashMap::new()), "");
    }

    #[test]
    fn export_selected_with_empty_selection_claims_nothing() {
        // The guard returns before touching the clipboard: no status
        // change, no log line claiming an export happened.
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本")];
        let ctx = egui::Context::default();
        app.export_selected(&ctx);
        assert_eq!(app.status, "未连接");
        assert!(!app.log.iter().any(|l| l.contains("导出")));
    }

    #[test]
    fn parse_import_line_cases() {
        // Plain old-format line: metadata stays empty.
        assert_eq!(
            match parse_import_line("a.opengw.net:443") {
                ImportLine::Node {
                    host,
                    port,
                    country,
                    isp,
                    sessions,
                    speed_mbps,
                    probe_ms,
                } => (host, port, country, isp, sessions, speed_mbps, probe_ms),
                _ => panic!("expected a node"),
            },
            (
                "a.opengw.net".to_string(),
                Some(443),
                String::new(),
                String::new(),
                0,
                0,
                None
            )
        );
        // A bare label is completed to the full FQDN on import.
        assert_eq!(
            match parse_import_line("  public-vpn-192  ") {
                ImportLine::Node { host, port, .. } => (host, port),
                _ => panic!("expected a node"),
            },
            ("public-vpn-192.opengw.net".to_string(), None)
        );
        // New v3.12 format: metadata columns are restored.
        assert_eq!(
            match parse_import_line("vpn547433109:995\t日本\tIIJ\t47\t572") {
                ImportLine::Node {
                    host,
                    port,
                    country,
                    isp,
                    sessions,
                    speed_mbps,
                    probe_ms,
                } => (host, port, country, isp, sessions, speed_mbps, probe_ms),
                _ => panic!("expected a node"),
            },
            (
                "vpn547433109.opengw.net".to_string(),
                Some(995),
                "日本".to_string(),
                "IIJ".to_string(),
                47,
                572,
                None
            )
        );
        // Trailing empty metadata fields are fine (unknown).
        assert_eq!(
            match parse_import_line("b.opengw.net:992\t\t\t\t") {
                ImportLine::Node {
                    host,
                    port,
                    country,
                    isp,
                    sessions,
                    speed_mbps,
                    probe_ms,
                } => (host, port, country, isp, sessions, speed_mbps, probe_ms),
                _ => panic!("expected a node"),
            },
            (
                "b.opengw.net".to_string(),
                Some(992),
                String::new(),
                String::new(),
                0,
                0,
                None
            )
        );
        assert!(matches!(parse_import_line(""), ImportLine::Skip));
        assert!(matches!(parse_import_line("   "), ImportLine::Skip));
        assert!(matches!(
            parse_import_line("# a comment"),
            ImportLine::Skip
        ));
        assert!(matches!(
            parse_import_line("  # indented comment"),
            ImportLine::Skip
        ));
        for bad in [":443", "a.opengw.net:", "a.opengw.net:0", "a.opengw.net:70000", "a.opengw.net:notaport", "ho st:443", "a:b:443", "a_b.opengw.net:443", "a.opengw.net:443\t日本\tIIJ\tx\t572", "a.opengw.net:443\t日本\tIIJ\t47\tfast", "a.opengw.net:443\t日本\tIIJ\t47\t572\t42\textra"] {
            assert!(
                matches!(parse_import_line(bad), ImportLine::Malformed),
                "{bad} must be malformed"
            );
        }
    }

    #[test]
    fn import_nodes_text_adds_dedups_and_unblocks() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本")];
        app.blocked_hosts
            .insert("blocked.opengw.net".to_string());
        let report = app.import_nodes_text(
            "b.opengw.net:992\n\
             a.opengw.net:443\n\
             blocked.opengw.net:443\n\
             b.opengw.net:992\n\
             not a host:port\n\
             # comment\n\
             \n\
             c.opengw.net",
        );
        assert_eq!(
            report,
            ImportReport {
                added: 3,
                duplicates: 2,
                malformed: 1,
                unblocked: vec!["blocked.opengw.net".to_string()],
            }
        );
        assert_eq!(app.nodes.len(), 4);
        assert_eq!(app.nodes[1].host, "b.opengw.net");
        assert_eq!(app.nodes[1].port, Some(992));
        // v3.12: no literal placeholder — country/operator stay
        // empty (the table shows "—") when the line carries no
        // metadata. v3.11 asserted "导入" here.
        assert_eq!(app.nodes[1].country, "");
        assert_eq!(app.nodes[1].isp, "");
        assert_eq!(app.nodes[1].source, "import");
        assert_eq!(app.nodes[2].host, "blocked.opengw.net");
        assert_eq!(app.nodes[3].host, "c.opengw.net");
        assert_eq!(app.nodes[3].port, None);
        assert!(app.blocked_hosts.is_empty(), "import unblocks its hosts");
        // The pre-existing selection is untouched by an import.
        assert!(app.selected_set.is_empty());
    }

    #[test]
    fn import_nodes_text_empty_reports_nothing() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本")];
        let report = app.import_nodes_text("  \n# only comments\n\n");
        assert_eq!(report, ImportReport::default());
        assert_eq!(app.nodes.len(), 1);
    }

    /// v3.12: export then import restores all four metadata
    /// columns plus host:port — the round trip Leo's screenshot
    /// showed losing (v3.11 exported host:port only).
    #[test]
    fn export_import_round_trip_restores_metadata() {
        let mut a = node_in("vpn547433109.opengw.net", "日本");
        a.port = Some(995);
        a.isp = "IIJ".to_string();
        a.sessions = 47;
        a.speed_mbps = 572;
        let mut b = node_in("a.opengw.net", "美国");
        b.port = Some(443);
        b.isp = "NTT".to_string();
        b.sessions = 3;
        b.speed_mbps = 120;
        let text = export_nodes_text(&[a.clone(), b.clone()], &HashMap::new());
        let mut app = GuiApp::for_tests();
        // Start from an empty list: for_tests() carries the 28
        // curated nodes, and one of the fixture hosts is among them.
        app.nodes = vec![];
        let report = app.import_nodes_text(&text);
        assert_eq!(report.added, 2);
        assert_eq!(report.malformed, 0);
        assert_eq!(app.nodes[0].host, "vpn547433109.opengw.net");
        assert_eq!(app.nodes[0].port, Some(995));
        assert_eq!(app.nodes[0].country, "日本");
        assert_eq!(app.nodes[0].isp, "IIJ");
        assert_eq!(app.nodes[0].sessions, 47);
        assert_eq!(app.nodes[0].speed_mbps, 572);
        assert_eq!(app.nodes[1].host, "a.opengw.net");
        assert_eq!(app.nodes[1].country, "美国");
        assert_eq!(app.nodes[1].sessions, 3);
        assert_eq!(app.nodes[1].speed_mbps, 120);
    }

    /// v3.16: export then import restores the probed latency
    /// (probe_ms) too, with the latency column's display string
    /// filled in — the imported value is the *last measured* one,
    /// not a fresh probe, and it sorts like a real probe result.
    #[test]
    fn import_restores_probe_ms_from_sixth_column() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![];
        let report = app.import_nodes_text(
            "a.opengw.net:443\t日本\tNTT\t3\t120\t42\n\
             b.opengw.net:992\t美国\tNTT\t1\t50\t\n\
             c.opengw.net:995\t德国\tNTT\t0\t0\t1234",
        );
        assert_eq!(report.added, 3);
        assert_eq!(report.malformed, 0);
        assert_eq!(app.probe_ms.get("a.opengw.net"), Some(&42));
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("42 ms")
        );
        // Empty sixth column = never probed: no ms, no display.
        assert_eq!(app.probe_ms.get("b.opengw.net"), None);
        assert_eq!(app.probes.get("b.opengw.net"), None);
        assert_eq!(app.probe_ms.get("c.opengw.net"), Some(&1234));
        assert_eq!(
            app.probes.get("c.opengw.net").map(|s| s.as_str()),
            Some("1234 ms")
        );
    }

    /// v3.16: the core round trip — export with a probe map, then
    /// import the text back: the latency comes back with the node.
    #[test]
    fn export_import_round_trip_restores_probe_ms() {
        let mut a = node_in("a.opengw.net", "日本");
        a.port = Some(443);
        a.sessions = 3;
        a.speed_mbps = 120;
        let mut b = node_in("b.opengw.net", "美国");
        b.port = Some(992);
        let mut probe_ms = HashMap::new();
        probe_ms.insert("a.opengw.net".to_string(), 42);
        probe_ms.insert("b.opengw.net".to_string(), 1234);
        let text = export_nodes_text(&[a, b], &probe_ms);
        assert_eq!(
            text,
            "a.opengw.net:443\t日本\tNTT\t3\t120\t42\nb.opengw.net:992\t美国\tNTT\t1\t50\t1234"
        );
        let mut app = GuiApp::for_tests();
        app.nodes = vec![];
        let report = app.import_nodes_text(&text);
        assert_eq!(report.added, 2);
        assert_eq!(report.malformed, 0);
        assert_eq!(app.probe_ms.get("a.opengw.net"), Some(&42));
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("42 ms")
        );
        assert_eq!(app.probe_ms.get("b.opengw.net"), Some(&1234));
    }

    /// v3.16: parse of the sixth column itself — a number is
    /// kept, empty is None, non-numeric is Malformed.
    #[test]
    fn parse_import_line_sixth_column() {
        assert_eq!(
            match parse_import_line("a.opengw.net:443\t日本\tNTT\t3\t120\t42") {
                ImportLine::Node { probe_ms, .. } => probe_ms,
                _ => panic!("expected a node"),
            },
            Some(42)
        );
        assert_eq!(
            match parse_import_line("a.opengw.net:443\t日本\tNTT\t3\t120\t") {
                ImportLine::Node { probe_ms, .. } => probe_ms,
                _ => panic!("expected a node"),
            },
            None
        );
        assert!(matches!(
            parse_import_line("a.opengw.net:443\t日本\tNTT\t3\t120\tfast"),
            ImportLine::Malformed
        ));
    }

    /// v3.16: a non-numeric sixth column is Malformed (the whole
    /// line is skipped, the import does not fail), and so is
    /// anything past six columns.
    #[test]
    fn import_sixth_column_non_numeric_or_too_many_is_malformed() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![];
        let report = app.import_nodes_text(
            "a.opengw.net:443\t日本\tNTT\t3\t120\tfast\n\
             b.opengw.net:992\t美国\tNTT\t1\t50\t42\textra\n\
             c.opengw.net:995\t德国\tNTT\t0\t0\t7",
        );
        assert_eq!(report.added, 1);
        assert_eq!(report.malformed, 2);
        assert_eq!(app.nodes.len(), 1);
        assert_eq!(app.nodes[0].host, "c.opengw.net");
        assert_eq!(app.probe_ms.get("c.opengw.net"), Some(&7));
    }

    /// v3.16: a 5-column v3.12–v3.15 export still imports, with
    /// no probe latency restored (the node sorts as unprobed).
    #[test]
    fn import_five_column_legacy_file_has_no_probe_ms() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![];
        let report =
            app.import_nodes_text("a.opengw.net:443\t日本\tNTT\t3\t120");
        assert_eq!(report.added, 1);
        assert_eq!(report.malformed, 0);
        assert_eq!(app.probe_ms.get("a.opengw.net"), None);
        assert_eq!(app.probes.get("a.opengw.net"), None);
    }

    /// v3.16: a duplicate host carrying a probe latency is
    /// skipped whole — the existing row's (live) probe_ms is
    /// NOT overwritten by the imported stale value. The import
    /// dedup is host-based and the existing row is authoritative:
    /// silently swapping in an old measurement would mislead
    /// the latency sort; a user who wants the imported value
    /// deletes the row first and re-imports.
    #[test]
    fn import_duplicate_with_probe_ms_keeps_existing_latency() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本")];
        app.probe_ms.insert("a.opengw.net".to_string(), 30);
        app.probes
            .insert("a.opengw.net".to_string(), "30 ms".to_string());
        let report =
            app.import_nodes_text("a.opengw.net:443\t日本\tNTT\t3\t120\t999");
        assert_eq!(report.added, 0);
        assert_eq!(report.duplicates, 1);
        assert_eq!(app.probe_ms.get("a.opengw.net"), Some(&30));
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("30 ms")
        );
    }

    /// v3.16: an imported latency takes part in the latency sort
    /// exactly like a freshly probed one (available group, ms
    /// ascending), and a re-probe overwrites / clears it by the
    /// existing probe rules.
    #[test]
    fn imported_probe_ms_sorts_and_is_covered_by_reprobe() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![];
        let report = app.import_nodes_text(
            "a.opengw.net:443\t日本\tNTT\t1\t50\t120\n\
             b.opengw.net:443\t日本\tNTT\t1\t50\t30\n\
             c.opengw.net:443\t日本\tNTT\t1\t50\t",
        );
        assert_eq!(report.added, 3);
        app.sort = Some((SortCol::Latency, SortDir::Asc));
        assert_eq!(app.display_indices(), vec![1, 0, 2]);
        // A fresh successful probe overwrites the imported value.
        app.apply_event(GuiEvent::Probe {
            host: "a.opengw.net".to_string(),
            result: Ok((
                std::net::Ipv4Addr::new(10, 0, 0, 1),
                std::time::Duration::from_millis(5),
            )),
        });
        assert_eq!(app.probe_ms.get("a.opengw.net"), Some(&5));
        assert_eq!(app.display_indices(), vec![0, 1, 2]);
        // A probe starting clears it (row shows 探测中…).
        app.busy = Some(Busy::ProbingAll);
        app.apply_event(GuiEvent::ProbeAllProgress {
            current: "b.opengw.net".to_string(),
            done: 0,
            total: 1,
        });
        assert_eq!(app.probe_ms.get("b.opengw.net"), None);
        assert_eq!(
            app.probes.get("b.opengw.net").map(|s| s.as_str()),
            Some("探测中…")
        );
    }

    /// Old plain `host:port` lines still import, with the four
    /// columns empty (shown as "—") — and the bare host completed.
    #[test]
    fn import_old_plain_format_leaves_metadata_empty() {
        let mut app = GuiApp::for_tests();
        // Start from an empty list: for_tests() carries the 28
        // curated nodes, and one of the fixture hosts is among them.
        app.nodes = vec![];
        let report = app.import_nodes_text("vpn547433109:995\nx.opengw.net");
        assert_eq!(report.added, 2);
        let n = &app.nodes[0];
        assert_eq!(n.host, "vpn547433109.opengw.net");
        assert_eq!(n.port, Some(995));
        assert_eq!(n.country, "");
        assert_eq!(n.isp, "");
        assert_eq!(n.sessions, 0);
        assert_eq!(n.speed_mbps, 0);
        assert_eq!(app.nodes[1].host, "x.opengw.net");
        assert_eq!(app.nodes[1].port, None);
    }

    /// No literal placeholder value in any imported field — the
    /// v3.11 "导入" stamp, and the manual-add "手动" / "手动添加"
    /// pair it shared the pattern with, are all gone.
    #[test]
    fn no_placeholder_values_in_imported_or_manual_nodes() {
        let mut app = GuiApp::for_tests();
        // Start from an empty list: for_tests() carries the 28
        // curated nodes, and one of the fixture hosts is among them.
        app.nodes = vec![];
        app.import_nodes_text(
            "vpn547433109:995\t日本\tIIJ\t47\t572\nplain.opengw.net:443\n",
        );
        for n in &app.nodes {
            assert_ne!(n.country, "导入");
            assert_ne!(n.isp, "导入");
            assert_ne!(n.country, "手动");
            assert_ne!(n.isp, "手动添加");
            assert_ne!(n.country, "未知");
        }
        let m = manual_node("m.opengw.net".to_string(), Some(992));
        assert_eq!(m.country, "");
        assert_eq!(m.isp, "");
        assert_eq!(m.name, "");
        assert_eq!(m.source, "manual");
    }

    /// v3.12: a refresh keeps manual/imported nodes the fresh list
    /// lacks, appended at the end in their current order.
    #[test]
    fn refresh_merge_keeps_manual_and_imported_nodes() {
        let mut app = GuiApp::for_tests();
        let mut manual = node_in("m.opengw.net", "");
        manual.source = "manual".to_string();
        manual.port = Some(995);
        let mut imported = node_in("i.opengw.net", "德国");
        imported.source = "import".to_string();
        imported.isp = "DT".to_string();
        app.nodes = vec![node_in("a.opengw.net", "日本"), manual, imported];
        let (merged, retained) = app.merge_refresh_nodes(vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
        ]);
        assert_eq!(retained, 2);
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[2].host, "m.opengw.net");
        assert_eq!(merged[2].source, "manual");
        assert_eq!(merged[3].host, "i.opengw.net");
        assert_eq!(merged[3].source, "import");
        assert_eq!(merged[3].isp, "DT");
    }

    /// When the fresh list has the same host, its row wins for
    /// metadata — but the manual port survives when the fresh row
    /// has none (the API never carries an SSTP port).
    #[test]
    fn refresh_merge_api_row_wins_but_manual_port_survives() {
        let mut app = GuiApp::for_tests();
        let mut manual = node_in("m.opengw.net", "");
        manual.source = "manual".to_string();
        manual.port = Some(995);
        manual.port_source = "manual".to_string();
        manual.isp = "OLD".to_string();
        app.nodes = vec![manual];
        let mut api = node_in("m.opengw.net", "日本");
        api.source = "api".to_string();
        api.port = None;
        api.isp = "NTT".to_string();
        api.sessions = 47;
        api.speed_mbps = 572;
        let (merged, retained) = app.merge_refresh_nodes(vec![api]);
        assert_eq!(retained, 0);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].country, "日本");
        assert_eq!(merged[0].isp, "NTT");
        assert_eq!(merged[0].sessions, 47);
        assert_eq!(merged[0].speed_mbps, 572);
        assert_eq!(merged[0].port, Some(995));
        assert_eq!(merged[0].port_source, "manual");
        assert_eq!(merged[0].source, "api");
    }

    #[test]
    fn refresh_summary_line_states_source_and_counts() {
        assert_eq!(
            refresh_summary_line(vpngate::NodeListSource::Api, 116, 125, 0),
            "刷新完成（官方 API）：已清空屏蔽 116 个，获取到 125 个。"
        );
        assert_eq!(
            refresh_summary_line(vpngate::NodeListSource::WebScrape, 96, 100, 0),
            "刷新完成（网页抓取）：已清空屏蔽 96 个，获取到 100 个。"
        );
        assert_eq!(
            refresh_summary_line(vpngate::NodeListSource::Cache, 0, 96, 0),
            "刷新完成（缓存）：已清空屏蔽 0 个，获取到 96 个。"
        );
        assert_eq!(
            refresh_summary_line(vpngate::NodeListSource::Curated, 20, 28, 0),
            "刷新完成（内嵌列表）：已清空屏蔽 20 个，获取到 28 个。"
        );
        // v3.12: kept manual/imported nodes are named in the line.
        assert_eq!(
            refresh_summary_line(vpngate::NodeListSource::Api, 116, 125, 5),
            "刷新完成（官方 API）：已清空屏蔽 116 个，获取到 125 个（含手动/导入保留 5 个）。"
        );
    }

    /// v3.15 failure sentence (Leo's exact wording, 2026-11-08):
    /// both refresh buttons write this sentence verbatim — the
    /// line starts with it, and the way + reason follow in
    /// parentheses. Never reword it, never split it.
    #[test]
    fn refresh_failure_line_keeps_leos_sentence_verbatim() {
        let api = refresh_failure_line(
            "官方 API",
            "官方 API 拉取超时（30 秒内无响应）",
        );
        assert!(
            api.starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "the line must start with Leo's exact sentence, got: {}",
            api
        );
        assert!(api.contains("官方 API"));
        assert!(api.contains("官方 API 拉取超时（30 秒内无响应）"));
        let fallback = refresh_failure_line(
            "官方 API 与网页抓取",
            "官方 API 拉取超时（30 秒内无响应）；网页抓取超时（15 秒内无响应）",
        );
        assert!(
            fallback.starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "the fallback line must start with the same sentence, got: {}",
            fallback
        );
        assert!(fallback.contains("网页抓取超时（15 秒内无响应）"));
    }

    /// v3.15 "从API刷新节点" failure: the list and the blocklist
    /// stay exactly as they were, the busy flag clears, and the
    /// status bar + log carry Leo's exact sentence with the way
    /// and the reason.
    #[test]
    fn api_refresh_failed_leaves_list_and_blocklist_untouched() {
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        app.config.blocked_hosts = vec!["b.opengw.net".to_string()];
        app.blocked_hosts = app.config.blocked_hosts.iter().cloned().collect();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("c.opengw.net", "德国"),
        ];
        app.busy = Some(Busy::Fetching);
        app.apply_event(GuiEvent::ApiRefreshFailed {
            reason: "官方 API 拉取超时（30 秒内无响应）".to_string(),
        });
        assert_eq!(app.nodes.len(), 2);
        assert_eq!(app.nodes[0].host, "a.opengw.net");
        assert_eq!(app.blocked_hosts.len(), 1);
        assert!(app.blocked_hosts.contains("b.opengw.net"));
        assert!(app.busy.is_none());
        assert!(
            app.status
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "status must carry Leo's exact sentence, got: {}",
            app.status
        );
        assert!(app.status.contains("官方 API 拉取超时（30 秒内无响应）"));
        assert!(
            app.log.iter().any(|l| l
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新")),
            "log must carry Leo's exact sentence, got: {:?}",
            app.log
        );
    }

    /// v3.15: the normal "刷新节点" button whose whole fallback
    /// chain fails (API + web both down, cache shown) writes the
    /// same sentence to the status bar and the log — the list still
    /// shows the cache, as before; only the notice is new.
    #[test]
    fn fallback_refresh_to_cache_writes_failure_sentence() {
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("old.opengw.net", "日本")];
        app.busy = Some(Busy::Fetching);
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![node_in("a.opengw.net", "日本")],
            source: vpngate::NodeListSource::Cache,
            cache_age_secs: Some(3600),
            api_error: Some("官方 API 拉取超时（30 秒内无响应）".to_string()),
            web_error: Some("网页抓取超时（15 秒内无响应）".to_string()),
        }));
        assert_eq!(app.nodes.len(), 1);
        assert_eq!(app.nodes[0].host, "a.opengw.net");
        assert!(app.busy.is_none());
        assert!(
            app.status
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "status must carry Leo's exact sentence, got: {}",
            app.status
        );
        assert!(app.status.contains("网页抓取超时（15 秒内无响应）"));
        assert!(
            app.log.iter().any(|l| l
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新")),
            "log must carry Leo's exact sentence, got: {:?}",
            app.log
        );
    }

    /// v3.15: same as the Cache case, but the fallback fell all the
    /// way to the bundled curated list (no cache file).
    #[test]
    fn fallback_refresh_to_curated_writes_failure_sentence() {
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        app.busy = Some(Busy::Fetching);
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![node_in("a.opengw.net", "日本")],
            source: vpngate::NodeListSource::Curated,
            cache_age_secs: None,
            api_error: Some("官方 API 返回了空列表".to_string()),
            web_error: Some("网页抓取解析到 0 个节点".to_string()),
        }));
        assert!(app.busy.is_none());
        assert!(
            app.status
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "status must carry Leo's exact sentence, got: {}",
            app.status
        );
        assert!(
            app.log.iter().any(|l| l
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新")),
            "log must carry Leo's exact sentence, got: {:?}",
            app.log
        );
    }

    /// v3.15 "从API刷新节点" success: the list updates, the merged
    /// list is written to the cache, and the blocklist still
    /// filters as usual (the deleted host stays hidden — this
    /// button never clears the blocklist, unlike "刷新节点").
    #[test]
    fn api_refresh_success_updates_list_and_cache() {
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        app.config.blocked_hosts = vec!["b.opengw.net".to_string()];
        app.blocked_hosts = app.config.blocked_hosts.iter().cloned().collect();
        app.nodes = vec![node_in("old.opengw.net", "日本")];
        app.busy = Some(Busy::Fetching);
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![
                node_in("a.opengw.net", "日本"),
                node_in("b.opengw.net", "美国"),
                node_in("c.opengw.net", "德国"),
            ],
            source: vpngate::NodeListSource::Api,
            cache_age_secs: None,
            api_error: None,
            web_error: None,
        }));
        assert_eq!(app.nodes.len(), 2);
        assert_eq!(app.nodes[0].host, "a.opengw.net");
        assert_eq!(app.nodes[1].host, "c.opengw.net");
        assert!(app.blocked_hosts.contains("b.opengw.net"));
        assert!(app.busy.is_none());
        assert_eq!(app.status, "节点列表已更新：2 个节点。");
        // The cache stores the full merged list (b included — the
        // blocklist filters at load, like the normal refresh).
        let cached = vpngate::load_cached_nodes();
        assert!(cached.is_some(), "API success must write the cache");
        let (cached_nodes, _) = cached.unwrap();
        assert_eq!(cached_nodes.len(), 3);
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// v3.11 refresh flow (Leo's call): a refresh clears the
    /// blocklist first — in memory and in config.toml — then the
    /// incoming list is shown in full, including hosts deleted
    /// earlier in the session. The summary line states the cleared
    /// count, the source and the final count.
    #[test]
    fn refresh_clears_blocklist_and_restores_full_list() {
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        // Session state: b was deleted earlier (blocklist 1 host,
        // persisted in config); the current list is [a, c].
        app.config.blocked_hosts = vec!["b.opengw.net".to_string()];
        app.blocked_hosts = app.config.blocked_hosts.iter().cloned().collect();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("c.opengw.net", "德国"),
        ];
        // The refresh start (start_fetch itself spawns a task, so the
        // test drives its two halves directly): clear first.
        let cleared = app.clear_blocklist();
        assert_eq!(cleared, 1);
        assert!(app.blocked_hosts.is_empty());
        // Persistence: the saved config file lost the entry too, so
        // a restart does not resurrect it.
        let path = Config::portable_config_path().expect("exe dir known");
        let back = Config::load(Some(&path)).expect("saved config loads");
        assert!(back.blocked_hosts.is_empty());
        let _ = std::fs::remove_file(&path);
        // The fetch completes: the full list comes back, b included.
        app.refresh_cleared_blocked = cleared;
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![
                node_in("a.opengw.net", "日本"),
                node_in("b.opengw.net", "美国"),
                node_in("c.opengw.net", "德国"),
            ],
            source: vpngate::NodeListSource::Api,
            cache_age_secs: None,
            api_error: None,
            web_error: None,
        }));
        assert_eq!(app.nodes.len(), 3);
        assert_eq!(app.nodes[1].host, "b.opengw.net");
        assert!(
            app.log.iter().any(|l| l
                == "刷新完成（官方 API）：已清空屏蔽 1 个，获取到 3 个。"),
            "log must carry the cleared count and final count, got: {:?}",
            app.log
        );
        // The Api branch also cached the fresh list next to the test
        // exe; clean it up like the config file above.
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    #[test]
    fn curated_status_uses_filtered_count() {
        // The curated branch used to hardcode "（28 个）" in the
        // status while the list only showed the filtered count.
        // (A non-empty blocklist at Nodes time now only happens for
        // a node deleted mid-fetch — the refresh itself clears it
        // first — but the shown count must still be the filtered
        // one.) v3.15: the status bar now carries the refresh
        // failure sentence instead (the fallback chain failed), so
        // the filtered count is asserted in the log's summary line.
        let mut app = GuiApp::for_tests();
        app.blocked_hosts.insert("a.opengw.net".to_string());
        app.blocked_hosts.insert("b.opengw.net".to_string());
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![
                node_in("a.opengw.net", "日本"),
                node_in("b.opengw.net", "美国"),
                node_in("c.opengw.net", "德国"),
            ],
            source: vpngate::NodeListSource::Curated,
            cache_age_secs: None,
            api_error: Some("api down".to_string()),
            web_error: Some("web down".to_string()),
        }));
        assert_eq!(app.nodes.len(), 1);
        assert!(
            app.log.iter().any(|l| l
                == "刷新完成（内嵌列表）：已清空屏蔽 0 个，获取到 1 个。"),
            "log summary must show the filtered count, got: {:?}",
            app.log
        );
        assert!(
            !app.log.iter().any(|l| l.contains("28 个")),
            "no hardcoded 28 anywhere in the log, got: {:?}",
            app.log
        );
        assert!(
            app.status
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "status now carries the v3.15 failure sentence, got: {}",
            app.status
        );
    }

    /// The blocklist filters every list load: an incoming list that
    /// still contains a blocked host loses it before it is shown,
    /// and the selection is cleared (indices from the old list are
    /// meaningless).
    #[test]
    fn list_load_filters_blocked_hosts() {
        let mut app = GuiApp::for_tests();
        app.nodes = four_nodes();
        app.blocked_hosts.insert("b.opengw.net".to_string());
        app.click_row(0, false, false);
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: four_nodes(),
            source: vpngate::NodeListSource::Api,
            cache_age_secs: None,
            api_error: None,
            web_error: None,
        }));
        let hosts: Vec<&str> = app.nodes.iter().map(|n| n.host.as_str()).collect();
        assert_eq!(
            hosts,
            vec!["a.opengw.net", "c.opengw.net", "d.opengw.net"]
        );
        assert_eq!(app.selected, None);
        assert!(app.selected_set.is_empty());
        // A bare API label matches its completed block entry too.
        let bare = vec![node_in("b", "美国"), node_in("z.opengw.net", "日本")];
        let kept = app.apply_blocklist(bare);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].host, "z.opengw.net");
    }

    #[test]
    fn probe_all_targets_follow_display_order() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("b.opengw.net", "美国"),
            node_in("a.opengw.net", "日本"),
            node_in("c.opengw.net", "日本"),
            node_in("d.opengw.net", "德国"),
        ];
        // Fetch order by default.
        let targets = app.probe_all_targets();
        let hosts: Vec<&str> = targets.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(
            hosts,
            ["b.opengw.net", "a.opengw.net", "c.opengw.net", "d.opengw.net"]
        );
        // Sorted A-Z: 德国 < 日本 < 美国, hostname breaks ties.
        app.sort = Some((SortCol::Country, SortDir::Asc));
        let targets = app.probe_all_targets();
        let hosts: Vec<&str> = targets.iter().map(|(h, _)| h.as_str()).collect();
        assert_eq!(
            hosts,
            ["d.opengw.net", "a.opengw.net", "c.opengw.net", "b.opengw.net"]
        );
        // Targets are dialled with the completed host:port.
        assert_eq!(targets[0].1, "d.opengw.net:992");
        // Empty list: nothing to probe.
        app.nodes = vec![];
        assert!(app.probe_all_targets().is_empty());
    }

    #[test]
    fn probe_all_events_drive_progress_and_stop() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
            node_in("c.opengw.net", "德国"),
        ];
        // Empty list: starting is a no-op (the button is disabled
        // then too).
        let mut empty = GuiApp::for_tests();
        empty.nodes = vec![];
        empty.start_probe_all(egui::Context::default());
        assert!(empty.busy.is_none());
        // Starting is blocked while another job runs.
        app.busy = Some(Busy::Fetching);
        app.start_probe_all(egui::Context::default());
        assert_eq!(app.busy, Some(Busy::Fetching));
        app.busy = None;
        app.start_probe_all(egui::Context::default());
        assert_eq!(app.busy, Some(Busy::ProbingAll));
        assert_eq!((app.probe_all_total, app.probe_all_done), (3, 0));
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("探测中…"),
            "the first row shows 探测中… right away"
        );
        assert!(app.status.contains("0/3"), "status: {}", app.status);
        // Starting again while sweeping is a no-op.
        app.start_probe_all(egui::Context::default());
        assert_eq!(app.probe_all_total, 3);
        // Progress on the first node, then its good result: the row
        // takes the latency and the progress advances.
        app.apply_event(GuiEvent::ProbeAllProgress {
            current: "a.opengw.net".to_string(),
            done: 0,
            total: 3,
        });
        assert!(app.status.contains("0/3"), "status: {}", app.status);
        assert!(app.status.contains("a.opengw.net"), "status: {}", app.status);
        app.apply_event(GuiEvent::ProbeAllResult {
            host: "a.opengw.net".to_string(),
            result: Ok((Ipv4Addr::new(10, 0, 0, 2), Duration::from_millis(95))),
            done: 1,
            total: 3,
        });
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("95 ms")
        );
        assert_eq!((app.probe_all_ok, app.probe_all_failed), (1, 0));
        // A failed node writes 失败 — and neither outcome sets the
        // error banner mid-sweep (the summary at the end is the
        // place for the outcome).
        app.apply_event(GuiEvent::ProbeAllProgress {
            current: "b.opengw.net".to_string(),
            done: 1,
            total: 3,
        });
        assert_eq!(
            app.probes.get("b.opengw.net").map(|s| s.as_str()),
            Some("探测中…")
        );
        app.apply_event(GuiEvent::ProbeAllResult {
            host: "b.opengw.net".to_string(),
            result: Err(ProbeFailure::NodeDown("timeout".to_string())),
            done: 2,
            total: 3,
        });
        assert_eq!(
            app.probes.get("b.opengw.net").map(|s| s.as_str()),
            Some("失败")
        );
        assert_eq!((app.probe_all_ok, app.probe_all_failed), (1, 1));
        assert!(
            app.error.is_empty(),
            "no per-node error banner mid-sweep: {}",
            app.error
        );
        assert_eq!(app.busy, Some(Busy::ProbingAll));
        // 停止: the flag is set (the task stops after the node in
        // flight) and the status says so; the Done event clears the
        // busy flag and writes the summary.
        app.stop_probe_all();
        assert!(app.probe_all_stop.load(Ordering::Relaxed));
        assert!(app.status.contains("正在停止"), "status: {}", app.status);
        app.apply_event(GuiEvent::ProbeAllDone {
            total: 3,
            ok: 1,
            failed: 1,
            stopped: true,
            proxy_down: false,
        });
        assert!(app.busy.is_none());
        assert!(app.status.contains("已停止"), "status: {}", app.status);
        assert!(app.status.contains("已测 2/3"), "status: {}", app.status);
        assert!(
            app.log
                .iter()
                .any(|l| l.contains("探测全部已停止：已测 2/3，1 个可用，1 个失败，1 个未测")),
            "log must carry the stopped summary: {:?}",
            app.log
        );
        // A completed sweep (not stopped) writes the finished summary.
        let mut done_app = GuiApp::for_tests();
        done_app.nodes = vec![node_in("a.opengw.net", "日本")];
        done_app.start_probe_all(egui::Context::default());
        done_app.apply_event(GuiEvent::ProbeAllResult {
            host: "a.opengw.net".to_string(),
            result: Ok((Ipv4Addr::new(10, 0, 0, 2), Duration::from_millis(64))),
            done: 1,
            total: 1,
        });
        done_app.apply_event(GuiEvent::ProbeAllDone {
            total: 1,
            ok: 1,
            failed: 0,
            stopped: false,
            proxy_down: false,
        });
        assert!(done_app.busy.is_none());
        assert_eq!(
            done_app.status,
            "探测全部完成：1 个节点，1 个可用，0 个失败。"
        );
        // A proxy-down result aborts the sweep with the proxy named.
        let mut proxy_app = GuiApp::for_tests();
        proxy_app.front_enabled = true;
        proxy_app.front_addr = "127.0.0.1:2080".to_string();
        proxy_app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
        ];
        proxy_app.start_probe_all(egui::Context::default());
        proxy_app.apply_event(GuiEvent::ProbeAllResult {
            host: "a.opengw.net".to_string(),
            result: Err(ProbeFailure::ProxyDown("connection refused".to_string())),
            done: 1,
            total: 2,
        });
        assert_eq!(
            proxy_app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("代理不通")
        );
        proxy_app.apply_event(GuiEvent::ProbeAllDone {
            total: 2,
            ok: 0,
            failed: 1,
            stopped: false,
            proxy_down: true,
        });
        assert!(proxy_app.busy.is_none());
        assert!(
            proxy_app.status.contains("前置代理不通"),
            "status: {}",
            proxy_app.status
        );
        assert!(
            proxy_app.error.contains("127.0.0.1:2080"),
            "error must name the proxy: {}",
            proxy_app.error
        );
        assert!(
            proxy_app
                .log
                .iter()
                .any(|l| l.contains("探测全部已停止：前置代理不通。已测 1/2，0 个可用，1 个失败，1 个未测")),
            "log must carry the proxy-down summary: {:?}",
            proxy_app.log
        );
    }

    #[test]
    fn branded_visuals_meet_text_contrast() {
        // WCAG contrast for the pairs a user actually reads: body
        // text on the panel, white on the indigo selection fill, the
        // cyan ∞ mark on the panel, error/warning text on the panel.
        // The palette comment above `branded_visuals` states the
        // expected ratios; this test pins them.
        fn luminance(c: egui::Color32) -> f32 {
            let f = |v: u8| {
                let s = v as f32 / 255.0;
                if s <= 0.04045 {
                    s / 12.92
                } else {
                    ((s + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * f(c.r()) + 0.7152 * f(c.g()) + 0.0722 * f(c.b())
        }
        fn contrast(a: egui::Color32, b: egui::Color32) -> f32 {
            let (l1, l2) = (luminance(a), luminance(b));
            (l1.max(l2) + 0.05) / (l1.min(l2) + 0.05)
        }
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let v = branded_visuals(theme);
            let text = v.override_text_color.expect("text colour set");
            assert!(
                contrast(text, v.panel_fill) >= 4.5,
                "{theme:?} body text on panel: {:.2}",
                contrast(text, v.panel_fill)
            );
            assert!(
                contrast(egui::Color32::WHITE, v.selection.bg_fill) >= 4.5,
                "{theme:?} white on selection: {:.2}",
                contrast(egui::Color32::WHITE, v.selection.bg_fill)
            );
            let accent = infinity_accent(v.dark_mode);
            assert!(
                contrast(accent, v.panel_fill) >= 4.5,
                "{theme:?} infinity accent on panel: {:.2}",
                contrast(accent, v.panel_fill)
            );
            assert!(
                contrast(v.error_fg_color, v.panel_fill) >= 4.5,
                "{theme:?} error text on panel: {:.2}",
                contrast(v.error_fg_color, v.panel_fill)
            );
            assert!(
                contrast(v.warn_fg_color, v.panel_fill) >= 4.5,
                "{theme:?} warning text on panel: {:.2}",
                contrast(v.warn_fg_color, v.panel_fill)
            );
        }
    }

    #[test]
    fn nodes_event_updates_state() {
        let mut app = GuiApp::for_tests();
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![node("a.opengw.net"), node("b.opengw.net")],
            source: vpngate::NodeListSource::Api,
            cache_age_secs: None,
            api_error: None,
            web_error: None,
        }));
        assert_eq!(app.nodes.len(), 2);
        assert!(app.busy.is_none());
        assert_eq!(app.selected, None);
        assert!(app.nodes_source.contains("官方 API"));
    }

    #[test]
    fn nodes_event_web_scrape_source_shows_that() {
        let mut app = GuiApp::for_tests();
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vec![node("a.opengw.net")],
            source: vpngate::NodeListSource::WebScrape,
            cache_age_secs: None,
            api_error: Some("TLS reset".to_string()),
            web_error: None,
        }));
        assert_eq!(app.nodes.len(), 1);
        assert!(app.nodes_source.contains("网页抓取"));
        assert!(app.log.iter().any(|l| l.contains("TLS reset")));
    }

    #[test]
    fn nodes_event_falls_back_to_curated_list() {
        let mut app = GuiApp::for_tests();
        app.apply_event(GuiEvent::Nodes(vpngate::NodeListUpdate {
            nodes: vpngate::curated_nodes(),
            source: vpngate::NodeListSource::Curated,
            cache_age_secs: None,
            api_error: Some("network down".to_string()),
            web_error: Some("page changed".to_string()),
        }));
        assert_eq!(app.nodes.len(), vpngate::curated_nodes().len());
        assert!(app.nodes_source.contains("内嵌列表"));
        assert!(app.log.iter().any(|l| l.contains("network down")));
        assert!(app.log.iter().any(|l| l.contains("page changed")));
    }

    #[test]
    fn probe_event_records_latency_and_failure() {
        let mut app = GuiApp::for_tests();
        app.busy = Some(Busy::Probing);
        app.apply_event(GuiEvent::Probe {
            host: "a.opengw.net".to_string(),
            result: Ok((Ipv4Addr::new(10, 0, 0, 2), Duration::from_millis(128))),
        });
        assert_eq!(
            app.probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("128 ms")
        );
        assert!(app.busy.is_none());
        app.busy = Some(Busy::Probing);
        app.apply_event(GuiEvent::Probe {
            host: "b.opengw.net".to_string(),
            result: Err(ProbeFailure::NodeDown("timeout".to_string())),
        });
        assert_eq!(
            app.probes.get("b.opengw.net").map(|s| s.as_str()),
            Some("失败")
        );
        assert!(
            !app.error.is_empty(),
            "probe failure must set an actionable error"
        );
        // Proxy-down failure names the proxy, not the node, and points
        // at the front-proxy test instead of suggesting another node.
        app.busy = Some(Busy::Probing);
        app.front_enabled = true;
        app.front_addr = "192.168.236.197:10808".to_string();
        app.apply_event(GuiEvent::Probe {
            host: "c.opengw.net".to_string(),
            result: Err(ProbeFailure::ProxyDown("connection refused".to_string())),
        });
        assert_eq!(
            app.probes.get("c.opengw.net").map(|s| s.as_str()),
            Some("代理不通")
        );
        assert!(
            app.error.contains("192.168.236.197:10808"),
            "error must name the proxy: {}",
            app.error
        );
        assert!(
            app.error.contains("测试前置代理"),
            "error must point at the proxy test: {}",
            app.error
        );
        assert!(
            app.log.iter().any(|l| l.contains("一起失败")),
            "log must note the shared cause"
        );
        // Node-down with the proxy on says the proxy is fine.
        app.busy = Some(Busy::Probing);
        app.apply_event(GuiEvent::Probe {
            host: "d.opengw.net".to_string(),
            result: Err(ProbeFailure::NodeDown("TLS handshake failed".to_string())),
        });
        assert!(
            app.error.contains("能连上，但节点不通"),
            "error must clear the proxy: {}",
            app.error
        );
    }

    #[test]
    fn classify_probe_failure_splits_proxy_from_node() {
        assert!(matches!(
            classify_probe_failure("x".to_string(), Some(false)),
            ProbeFailure::ProxyDown(_)
        ));
        assert!(matches!(
            classify_probe_failure("x".to_string(), Some(true)),
            ProbeFailure::NodeDown(_)
        ));
        assert!(matches!(
            classify_probe_failure("x".to_string(), None),
            ProbeFailure::NodeDown(_)
        ));
    }

    #[test]
    fn front_proxy_test_event_reports_both_sides() {
        use vpngate_client::net::FrontProxyCheck;
        let mut app = GuiApp::for_tests();
        app.front_addr = "192.168.236.197:10808".to_string();
        app.busy = Some(Busy::TestingFrontProxy);
        // Both reachable: status carries latencies, error clears.
        app.apply_event(GuiEvent::FrontProxyTest {
            addr: "192.168.236.197:10808".to_string(),
            google: FrontProxyCheck::Reachable {
                status: 200,
                ms: 312,
            },
            vpngate: FrontProxyCheck::Reachable {
                status: 200,
                ms: 405,
            },
        });
        assert!(
            app.status.contains("312 ms"),
            "status must show Google latency: {}",
            app.status
        );
        assert!(
            app.status.contains("405 ms"),
            "status must show vpngate.net latency: {}",
            app.status
        );
        assert!(app.error.is_empty());
        assert!(app.log.iter().any(|l| l.contains("前置代理测试")));
        // Proxy down: status + error blame the proxy and its address.
        app.busy = Some(Busy::TestingFrontProxy);
        app.apply_event(GuiEvent::FrontProxyTest {
            addr: "192.168.236.197:10808".to_string(),
            google: FrontProxyCheck::ProxyUnreachable("连前置代理端口失败".to_string()),
            vpngate: FrontProxyCheck::ProxyUnreachable("连前置代理端口失败".to_string()),
        });
        assert!(
            app.status.contains("前置代理连不上"),
            "status: {}",
            app.status
        );
        assert!(
            app.error.contains("192.168.236.197:10808"),
            "error must name the proxy: {}",
            app.error
        );
        assert!(
            app.error.contains("一起失败"),
            "error must note the shared cause: {}",
            app.error
        );
        // Proxy up, vpngate.net down through it: distinct wording.
        app.busy = Some(Busy::TestingFrontProxy);
        app.apply_event(GuiEvent::FrontProxyTest {
            addr: "192.168.236.197:10808".to_string(),
            google: FrontProxyCheck::Reachable {
                status: 200,
                ms: 300,
            },
            vpngate: FrontProxyCheck::TargetUnreachable("代理建好连接后目标站无响应".to_string()),
        });
        assert!(
            app.status.contains("vpngate.net不通"),
            "status: {}",
            app.status
        );
        assert!(app.error.contains("前置代理能连上"), "error: {}", app.error);
        assert!(
            app.error.contains("vpngate.net"),
            "error must name the failing target: {}",
            app.error
        );
        // TLS failure through a working proxy: the log must carry the
        // raw error (not just "失败") — a firewall blocking the
        // unsigned exe and a dead target look identical otherwise.
        app.busy = Some(Busy::TestingFrontProxy);
        app.apply_event(GuiEvent::FrontProxyTest {
            addr: "192.168.236.197:10808".to_string(),
            google: FrontProxyCheck::TargetUnreachable(
                "代理建好连接后目标站无响应：TLS handshake to www.google.com failed: invalid peer certificate: UnknownIssuer".to_string(),
            ),
            vpngate: FrontProxyCheck::TargetUnreachable(
                "代理建好连接后目标站无响应：TLS handshake to www.vpngate.net failed: invalid peer certificate: UnknownIssuer".to_string(),
            ),
        });
        assert!(
            app.log.iter().any(|l| l.contains("UnknownIssuer")),
            "log must carry the raw TLS error: {:?}",
            app.log
        );
        assert!(
            app.log.iter().any(|l| l.contains("TLS handshake")),
            "log must name the failing stage: {:?}",
            app.log
        );
    }

    #[test]
    fn front_proxy_test_event_uses_snapshot_address() {
        use vpngate_client::net::FrontProxyCheck;
        let mut app = GuiApp::for_tests();
        // The address field was edited mid-test (Leo typed 12.0.0.1,
        // fixed it to 127.0.0.1 while the test was running): the
        // result must name the address the test actually used
        // (12.0.0.1), not the field's current value.
        app.front_addr = "127.0.0.1:2080".to_string();
        app.busy = Some(Busy::TestingFrontProxy);
        app.apply_event(GuiEvent::FrontProxyTest {
            addr: "12.0.0.1:2080".to_string(),
            google: FrontProxyCheck::ProxyUnreachable("连接前置代理超时".to_string()),
            vpngate: FrontProxyCheck::ProxyUnreachable("连接前置代理超时".to_string()),
        });
        assert!(
            app.error.contains("12.0.0.1:2080"),
            "error must name the snapshotted address: {}",
            app.error
        );
        assert!(
            !app.error.contains("127.0.0.1:2080"),
            "error must not name the edited-in address: {}",
            app.error
        );
    }

    #[test]
    fn front_proxy_test_progress_shows_site() {
        let mut app = GuiApp::for_tests();
        app.busy = Some(Busy::TestingFrontProxy);
        app.apply_event(GuiEvent::FrontProxyTestProgress {
            site: "Google".to_string(),
        });
        assert_eq!(app.status, "正在测试前置代理… Google");
        assert!(
            app.busy.is_some(),
            "a progress event must not clear the busy flag"
        );
        app.apply_event(GuiEvent::FrontProxyTestProgress {
            site: "vpngate.net".to_string(),
        });
        assert_eq!(app.status, "正在测试前置代理… vpngate.net");
    }

    #[test]
    fn col_widths_roundtrip_through_config() {
        let mut app = GuiApp::for_tests();
        assert_eq!(app.col_widths, [90, 130, 64, 88, 80, 190, 90]);
        app.col_widths = [120, 140, 70, 95, 80, 200, 100];
        let cfg = app.current_config();
        assert_eq!(cfg.ui.node_col_widths, [120, 140, 70, 95, 80, 200, 100]);
        let mut app2 = GuiApp::for_tests();
        app2.apply_config(&cfg);
        assert_eq!(app2.col_widths, [120, 140, 70, 95, 80, 200, 100]);
    }

    /// v3.13 scroll bars: 12 px solid, foreground-colour handle, 14 px
    /// allocated in total — the numbers the screenshot test below is
    /// the visual proof of. (Verified against egui 0.36.2 source, not
    /// from memory: `bar_width` is the field; solid + AlwaysVisible
    /// draws at opacity 1.0 at rest.)
    #[test]
    fn thick_scroll_style_is_12px_solid_foreground() {
        let s = thick_scroll_style();
        assert!(!s.floating, "solid bars allocate space, they do not float");
        assert_eq!(s.bar_width, 12.0, "was 6.0 in ScrollStyle::solid()");
        assert_eq!(s.bar_inner_margin, 2.0);
        assert_eq!(s.handle_min_length, 24.0);
        assert!(
            s.foreground_color,
            "the handle must use fg_stroke (grey 60 light / grey 180 dark), not bg_fill (grey 230 light — invisible)"
        );
        assert_eq!(s.allocated_width(), 14.0, "2 + 12 + 0");
    }

    /// v3.13 panel heights: defaults (list undragged, advanced 240,
    /// log 90), drag values round-trip through config, the list
    /// formula is the default until the first drag, and a dragged
    /// list height is clamped to the current panel.
    #[test]
    fn panel_heights_roundtrip_through_config() {
        let mut app = GuiApp::for_tests();
        assert_eq!(app.list_height, None);
        assert_eq!(app.advanced_height, 240.0);
        assert_eq!(app.log_height, 90.0);
        // Undragged: the old formula is the effective height.
        assert_eq!(app.effective_list_height(600.0), 350.0);
        assert_eq!(app.effective_list_height(420.0), 170.0);
        assert_eq!(app.effective_list_height(300.0), 120.0);
        // Dragged values round-trip through config (whole pixels).
        app.list_height = Some(300.0);
        app.advanced_height = 200.0;
        app.log_height = 120.0;
        let cfg = app.current_config();
        assert_eq!(cfg.ui.list_height, Some(300));
        assert_eq!(cfg.ui.advanced_height, 200);
        assert_eq!(cfg.ui.log_height, 120);
        let mut app2 = GuiApp::for_tests();
        app2.apply_config(&cfg);
        assert_eq!(app2.list_height, Some(300.0));
        assert_eq!(app2.advanced_height, 200.0);
        assert_eq!(app2.log_height, 120.0);
        // A dragged list height wins over the formula, clamped to
        // the panel (120 px to panel minus 150 px).
        assert_eq!(app2.effective_list_height(600.0), 300.0);
        assert_eq!(app2.effective_list_height(420.0), 270.0);
        // Tiny panel: the ceiling (panel minus 150 px) is 150 px,
        // so a dragged 300 px clamps to 150, not to the 120 floor.
        assert_eq!(app2.effective_list_height(300.0), 150.0);
        // Old config without the keys loads the defaults.
        let old: Config =
            toml::from_str("[ui]\nnode_col_widths = [90, 130, 64, 88, 80, 190, 90]\n")
                .unwrap();
        let mut app3 = GuiApp::for_tests();
        app3.apply_config(&old);
        assert_eq!(app3.list_height, None);
        assert_eq!(app3.advanced_height, 240.0);
        assert_eq!(app3.log_height, 90.0);
    }

    /// A failed connect clears the busy flag and names the fix
    /// (v3.13: the tunnel-test event arm this test used to drive was
    /// removed with the tunnel-test button — the connect path is all
    /// that is left to assert here).
    #[test]
    fn connect_failure_path() {
        let mut app = GuiApp::for_tests();
        app.busy = Some(Busy::Connecting);
        app.apply_event(GuiEvent::ConnectFailed("all candidates failed".to_string()));
        assert!(app.busy.is_none());
        assert!(app.conn.is_none());
        assert!(app.error.contains("换一个节点"));
    }

    #[test]
    fn current_config_roundtrips_settings() {
        let mut app = GuiApp::for_tests();
        app.front_enabled = true;
        app.front_addr = "127.0.0.1:1081".to_string();
        app.front_user = "u".to_string();
        app.front_pass = "p".to_string();
        app.local_port = 10809;
        app.allow_lan = true;
        app.system_proxy = true;
        let cfg = app.current_config();
        assert!(cfg.front_proxy.enabled);
        assert_eq!(cfg.front_proxy.addr, "127.0.0.1:1081");
        assert_eq!(cfg.front_proxy.username.as_deref(), Some("u"));
        assert_eq!(cfg.front_proxy.password.as_deref(), Some("p"));
        assert_eq!(cfg.listen.local_port, 10809);
        assert!(cfg.listen.allow_lan);
        assert!(cfg.system_proxy.enabled);
    }

    #[test]
    fn log_lines_go_to_file_log_with_levels() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("vpngate-gui-test-{}.log", n));
        let old = vpngate_client::filelog::old_log_path(&path);
        let mut app = GuiApp::for_tests();
        // No logger yet: log calls only touch the on-screen log.
        app.log_line("info before logger".to_string());
        assert!(!path.exists(), "no file without a logger");
        app.file_logger = Some(FileLogger::new(&path));
        app.log_line("info line".to_string());
        app.log_warn("warn line".to_string());
        app.set_error("error line".to_string());
        // set_error also sets the banner.
        assert_eq!(app.error, "error line");
        drop(app);
        let text = std::fs::read_to_string(&path).expect("file log written");
        assert!(text.contains("[INFO] info line"), "info: {}", text);
        assert!(text.contains("[WARN] warn line"), "warn: {}", text);
        assert!(text.contains("[ERROR] error line"), "error: {}", text);
        assert!(
            !text.contains("info before logger"),
            "lines before the logger started stay out of the file: {}",
            text
        );
        for l in text.lines() {
            assert_eq!(
                l.as_bytes()[4],
                b'-',
                "every line starts with a YYYY-MM-DD timestamp: {}",
                l
            );
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&old);
    }

    /// LAN sharing binds the same mixed port on all interfaces: one
    /// wildcard bind serves loopback too, so the list has a single
    /// entry — no second port, and no equal-port error to raise.
    #[test]
    fn listen_addrs_local_plus_lan_same_port() {
        let mut app = GuiApp::for_tests();
        assert_eq!(app.listen_addrs(), vec!["127.0.0.1:10818".to_string()]);
        assert_eq!(app.listen_display(), "127.0.0.1:10818");
        app.allow_lan = true;
        assert_eq!(app.listen_addrs(), vec!["0.0.0.0:10818".to_string()]);
        assert_eq!(
            app.listen_display(),
            "127.0.0.1:10818 ＋ 0.0.0.0:10818"
        );
    }

    #[test]
    fn auto_save_if_dirty_persists_front_proxy() {
        // Auto-save writes next to the test exe (portable dir); verify
        // the file round-trips the front-proxy fields, then clean up.
        // Serialized with the other portable-config test (see
        // PORTABLE_CONFIG_LOCK) — parallel writes tear the file.
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        app.front_enabled = true;
        app.front_addr = "127.0.0.1:1081".to_string();
        app.front_user = "u".to_string();
        app.front_pass = "p".to_string();
        app.auto_save_if_dirty();
        let path = Config::portable_config_path().expect("exe dir known");
        let back = Config::load(Some(&path)).expect("saved config loads");
        assert!(back.front_proxy.enabled);
        assert_eq!(back.front_proxy.addr, "127.0.0.1:1081");
        assert_eq!(back.front_proxy.username.as_deref(), Some("u"));
        assert_eq!(back.front_proxy.password.as_deref(), Some("p"));
        assert_eq!(app.config, back, "saved config becomes the new baseline");
        let _ = std::fs::remove_file(&path);
        // Second call with no changes must not rewrite the file.
        app.auto_save_if_dirty();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn probe_flow_dead_front_proxy_is_proxy_down() {
        let connector = connector_for(true, &format!("127.0.0.1:{}", closed_port()), "", "");
        let res = probe_flow(
            &connector,
            "kanratown.opengw.net:992",
            Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(res, Err(ProbeFailure::ProxyDown(_))),
            "dead proxy must blame the proxy, got {:?}",
            res.map(|_| ())
        );
    }

    #[tokio::test]
    async fn probe_flow_node_down_when_proxy_tcp_ok() {
        // Fake proxy: accepts TCP, then closes. The proxy port answers,
        // so a probe failure must blame the node, not the proxy.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    break;
                };
                drop(s);
            }
        });
        let connector = connector_for(true, &format!("127.0.0.1:{}", port), "", "");
        let res = probe_flow(
            &connector,
            "kanratown.opengw.net:992",
            Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(res, Err(ProbeFailure::NodeDown(_))),
            "live proxy port must blame the node, got {:?}",
            res.map(|_| ())
        );
    }

    /// A TCP listener that accepts and holds connections forever,
    /// never sending a byte — a hanging target (a dead node whose
    /// TLS handshake never answers). Same idea as the integration
    /// test's `black_hole_port`, for the bin's own async tests.
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

    #[tokio::test]
    async fn probe_all_flow_stops_after_stop_request() {
        // Four black-hole targets, 2 s timeout each: a full sweep
        // would take ~8 s. The stop flag is set as soon as the
        // first result arrives, so the sweep must halt after one
        // or two results — the flag may land just after the loop
        // already started the next probe, and that probe still
        // finishes first.
        let targets: Vec<(String, String)> = (0..4)
            .map(|_| {
                let p = black_hole_port();
                (format!("127.0.0.1:{}", p), format!("127.0.0.1:{}", p))
            })
            .collect();
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flow = stop.clone();
        let stop_collector = stop.clone();
        let connector = Connector::new(None);
        let timeout = Duration::from_secs(2);
        let start = std::time::Instant::now();
        tokio::spawn(async move {
            probe_all_flow(
                &connector,
                targets,
                timeout,
                stop_flow,
                tx,
                egui::Context::default(),
            )
            .await;
        });
        // The std mpsc receiver blocks, so it runs on a blocking
        // thread; it sets the stop flag the moment the first
        // result arrives, then reports how many results came and
        // the Done event's verdict.
        let (results, done_ev) = tokio::task::spawn_blocking(move || {
            let mut results = 0usize;
            let mut done_ev = None;
            loop {
                match rx.recv_timeout(Duration::from_secs(20)) {
                    Ok(GuiEvent::ProbeAllResult { .. }) => {
                        results += 1;
                        stop_collector.store(true, Ordering::Relaxed);
                    }
                    Ok(GuiEvent::ProbeAllDone {
                        total,
                        ok,
                        failed,
                        stopped,
                        proxy_down,
                    }) => {
                        done_ev = Some((total, ok, failed, stopped, proxy_down));
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            (results, done_ev)
        })
        .await
        .unwrap();
        let elapsed = start.elapsed();
        let (total, ok, failed, stopped, proxy_down) =
            done_ev.expect("a Done event must arrive");
        assert_eq!(total, 4);
        assert!(stopped, "the sweep must report stopped");
        assert!(!proxy_down, "no proxy is configured, so nothing is proxy-down");
        assert_eq!(ok, 0, "black holes never answer");
        assert_eq!(failed, results, "every probed node failed");
        assert!(
            (1..=2).contains(&results),
            "the stop must halt the sweep after one or two results, got {}",
            results
        );
        assert!(
            elapsed < Duration::from_secs(6),
            "a stopped sweep must not run the full queue (~8 s), took {:?}",
            elapsed
        );
    }

    /// A port with nothing listening on it.
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    #[test]
    fn disconnect_is_a_no_op_when_not_connected() {
        let mut app = GuiApp::for_tests();
        app.disconnect();
        assert_eq!(app.status, "未连接");
    }

    /// Mock SSTP server handle (tests/mock_sstp.py, stdlib Python).
    /// Dropping it kills the server it started — unless it only
    /// reused one that was already listening (`None` child).
    struct MockServer(Option<std::process::Child>);

    impl Drop for MockServer {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// The mock-using switch tests must serialize: a `start` in one
    /// test can pkill the mock another test is mid-handshake with
    /// (same pattern as the integration tests' MOCK_LOCK).
    static MOCK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tool_exists(name: &str) -> bool {
        std::process::Command::new("which")
            .arg(name)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn ensure_mock_cert() {
        let cert = "/tmp/mock_sstp_cert.pem";
        let key = "/tmp/mock_sstp_key.pem";
        if std::path::Path::new(cert).exists() && std::path::Path::new(key).exists() {
            return;
        }
        let _ = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
                "-days", "1", "-nodes", "-subj", "/CN=localhost",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    fn start_mock_server() -> Option<MockServer> {
        // Reuse a mock that is already listening.
        if std::net::TcpStream::connect_timeout(
            &"127.0.0.1:8443".parse().unwrap(),
            Duration::from_millis(300),
        )
        .is_ok()
        {
            return Some(MockServer(None));
        }
        let _ = std::process::Command::new("pkill")
            .args(["-f", "mock_sstp.py"])
            .output();
        std::thread::sleep(Duration::from_millis(300));
        ensure_mock_cert();
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let script = format!("{}/tests/mock_sstp.py", manifest);
        let child = std::process::Command::new("python3")
            .arg(script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(MockServer(Some(child)))
    }

    fn wait_for_mock_port() -> bool {
        for _ in 0..50 {
            if std::net::TcpStream::connect("127.0.0.1:8443").is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// Open one real tunnel to the mock SSTP server, for tests that
    /// need a live `conn` without a real node. Returns the server
    /// handle (keep it alive for the test) and the tunnel. The
    /// runtime used for the handshake is dropped before returning —
    /// the tunnel is only ever disconnected afterwards, never used
    /// for traffic. `None` (with a SKIP note) when the mock cannot
    /// run — same skip policy as the integration tests.
    fn mock_tunnel() -> Option<(MockServer, Arc<SstpTunnel>)> {
        if !tool_exists("python3") || !tool_exists("openssl") {
            eprintln!("SKIP: python3/openssl not available; mock SSTP server cannot run");
            return None;
        }
        let mock = start_mock_server()?;
        if !wait_for_mock_port() {
            eprintln!("SKIP: mock SSTP server did not listen on 8443");
            return None;
        }
        let rt = tokio::runtime::Runtime::new().ok()?;
        let tunnel = rt
            .block_on(async {
                SstpTunnel::connect(
                    &Connector::new(None),
                    "127.0.0.1",
                    8443,
                    Duration::from_secs(10),
                )
                .await
            })
            .ok()?;
        Some((mock, tunnel))
    }

    /// An app "connected" to A (a.opengw.net:992) through the mock
    /// tunnel, with B as the other row. `node_in` gives both rows
    /// port 992, so the targets are `a.opengw.net:992` /
    /// `b.opengw.net:992`.
    fn connected_test_app(tunnel: Arc<SstpTunnel>) -> GuiApp {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
        ];
        let vip = tunnel.vip;
        app.conn = Some(ActiveConnection {
            tunnel,
            serve: Vec::new(),
            proxy_guard: None,
            listen_addr: "127.0.0.1:10818".to_string(),
            node_label: "a.opengw.net:992".to_string(),
            vip,
        });
        app
    }

    #[test]
    fn selected_target_builds_completed_host_port() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node("public-vpn-192"),
        ];
        // Port known: host:port, DDNS suffix already complete.
        app.selected = Some(0);
        assert_eq!(
            app.selected_target().as_deref(),
            Some("a.opengw.net:992")
        );
        // Bare DDNS label, no port: completed to the full FQDN.
        app.nodes[1].port = None;
        app.selected = Some(1);
        assert_eq!(
            app.selected_target().as_deref(),
            Some("public-vpn-192.opengw.net")
        );
        // Nothing selected: no target.
        app.selected = None;
        assert_eq!(app.selected_target(), None);
    }

    /// v3.13 switch, mock-backed: connected to A, B selected, Enter
    /// (via shortcut_action + start_connect) disconnects A and
    /// starts connecting B; Enter on A itself is a no-op; Enter while
    /// busy, with a text field focused, or with About open stays
    /// blocked; Ctrl+R while connected stays blocked too.
    #[test]
    fn enter_switches_to_another_node_while_connected() {
        let _mock_guard = MOCK_LOCK.lock().unwrap();
        let Some((_mock, tunnel)) = mock_tunnel() else {
            return;
        };
        let ctx = egui::Context::default();
        // --- Switch: connected A, B selected, Enter. ---
        let mut app = connected_test_app(tunnel.clone());
        app.selected = Some(1);
        assert!(
            !app.selected_is_connected(),
            "B is not the connected node"
        );
        assert_eq!(
            app.shortcut_action(true, false, false),
            Some(ShortcutAction::Connect),
            "Enter on another node must offer Connect even while connected"
        );
        assert_eq!(
            app.shortcut_action(false, true, false),
            None,
            "Ctrl+R while connected stays blocked"
        );
        app.start_connect(ctx.clone());
        assert!(app.conn.is_none(), "the old connection must be gone");
        assert_eq!(
            app.busy,
            Some(Busy::Connecting),
            "the new connect must have started"
        );
        assert_eq!(app.status, "正在连接 b.opengw.net:992…");
        assert!(
            app.log.iter().any(|l| l.contains("已断开 a.opengw.net:992")),
            "log must name the disconnected old node: {:?}",
            app.log
        );
        assert!(
            app.log
                .iter()
                .any(|l| l.contains("开始连接 b.opengw.net:992")),
            "log must name the new connect: {:?}",
            app.log
        );
        // --- Same node: Enter is a no-op. ---
        let mut app = connected_test_app(tunnel);
        app.selected = Some(0);
        assert!(app.selected_is_connected(), "A is the connected node");
        assert_eq!(
            app.shortcut_action(true, false, false),
            None,
            "Enter on the connected node must offer nothing"
        );
        let log_len = app.log.len();
        let status = app.status.clone();
        app.start_connect(ctx.clone());
        assert!(app.conn.is_some(), "same-node Enter must not disconnect");
        assert!(app.busy.is_none(), "same-node Enter must not start anything");
        assert_eq!(app.log.len(), log_len, "no log lines for a no-op");
        assert_eq!(app.status, status, "no status change for a no-op");
        // --- Busy / text focus / About: still blocked. ---
        app.selected = Some(1);
        app.busy = Some(Busy::Probing);
        assert_eq!(
            app.shortcut_action(true, false, false),
            None,
            "Enter while busy stays blocked"
        );
        let log_len = app.log.len();
        app.start_connect(ctx.clone());
        assert!(app.conn.is_some(), "busy Enter must not disconnect");
        assert_eq!(app.busy, Some(Busy::Probing));
        assert_eq!(app.log.len(), log_len);
        app.busy = None;
        assert_eq!(
            app.shortcut_action(true, false, true),
            None,
            "Enter with a text field focused stays blocked"
        );
        app.show_about = true;
        assert_eq!(
            app.shortcut_action(true, false, false),
            None,
            "Enter with About open stays blocked"
        );
    }

    // --- v3.14 -------------------------------------------------------

    /// v3.14 RSS (diagnosis §7): `sample_rss` writes one `[RSS]`
    /// line carrying every field the growth curve needs — tag,
    /// working set, atlas fill, sessions, conn, nodes, dropped log
    /// lines. On Linux the working set reads `n/a` (no Windows
    /// RSS in the VM); the line itself must still be written, so
    /// the plumbing is verifiable here and the numbers on Leo's
    /// machine.
    #[test]
    fn sample_rss_writes_log_line_with_all_fields() {
        let mut app = GuiApp::for_tests();
        app.sample_rss("startup");
        let line = app
            .log
            .iter()
            .find(|l| l.contains("[RSS]"))
            .expect("an [RSS] line must be logged");
        assert!(line.contains("tag=startup"), "tag: {}", line);
        assert!(line.contains("working_set="), "working set: {}", line);
        assert!(line.contains("atlas_fill="), "atlas fill: {}", line);
        assert!(line.contains("sessions=0"), "sessions: {}", line);
        assert!(line.contains("conn=false"), "conn: {}", line);
        assert!(
            line.contains(&format!("nodes={}", app.nodes.len())),
            "nodes: {}",
            line
        );
        assert!(line.contains("conn_log_dropped="), "dropped: {}", line);
    }

    /// v3.14 RSS timers: each one-shot tag fires once, at the right
    /// elapsed time — driven with fake clocks, no waiting.
    #[test]
    fn rss_timer_tags_fire_once_at_right_times() {
        let mut app = GuiApp::for_tests();
        let start = app.started_at;
        // Align the periodic anchor exactly with startup (Default
        // sets it a few ns after started_at, which would push the
        // first periodic sample a few ns past the 30-minute mark).
        app.rss_last_periodic = start;
        assert!(
            app.rss_timer_tags(start).contains(&"startup"),
            "T0 fires on the first frame"
        );
        assert!(
            !app.rss_timer_tags(start + Duration::from_secs(299))
                .contains(&"startup_plus_5min"),
            "T+5min must not fire early"
        );
        assert!(
            app.rss_timer_tags(start + Duration::from_secs(300))
                .contains(&"startup_plus_5min"),
            "T+5min fires at 5 minutes"
        );
        app.rss_connected_since = Some(start);
        assert!(
            !app.rss_timer_tags(start + Duration::from_secs(1799))
                .contains(&"connected_plus_30min"),
            "C+30min must not fire early"
        );
        assert!(
            app.rss_timer_tags(start + Duration::from_secs(1800))
                .contains(&"connected_plus_30min"),
            "C+30min fires at 30 minutes connected"
        );
        app.rss_disconnected_at = Some(start);
        assert!(
            app.rss_timer_tags(start + Duration::from_secs(10))
                .contains(&"disconnected_plus_10s"),
            "D+10s fires 10 s after disconnect"
        );
        assert!(
            app.rss_timer_tags(start + Duration::from_secs(1800))
                .contains(&"periodic"),
            "periodic fires every 30 minutes"
        );
        // Marking them done stops them firing again.
        app.rss_t0_done = true;
        app.rss_t5_done = true;
        app.rss_conn30_done = true;
        app.rss_disconnect_10s_done = true;
        app.rss_last_periodic = start + Duration::from_secs(1800);
        let tags = app.rss_timer_tags(start + Duration::from_secs(1800));
        assert!(tags.is_empty(), "done tags must not refire: {:?}", tags);
    }

    /// v3.14 RSS: disconnecting writes the D0 sample immediately.
    #[test]
    fn disconnect_logs_rss_disconnected_line() {
        let _mock_guard = MOCK_LOCK.lock().unwrap();
        let Some((_mock, tunnel)) = mock_tunnel() else {
            return;
        };
        let mut app = connected_test_app(tunnel);
        app.disconnect();
        assert!(
            app.log.iter().any(|l| l.contains("[RSS]")
                && l.contains("tag=disconnected")),
            "disconnect must sample RSS: {:?}",
            app.log
        );
        assert_eq!(app.status, "未连接");
    }

    /// v3.14 log cache (diagnosis §3 item 4): the cached join is
    /// rebuilt only when a line was added — the dirty flag is the
    /// contract, and `log_line_at` (the only writer) sets it.
    #[test]
    fn cached_log_text_rebuilds_only_on_new_lines() {
        let mut app = GuiApp::for_tests();
        app.log = vec!["a".to_string(), "b".to_string()];
        app.log_text_dirty = true;
        assert_eq!(app.cached_log_text(), "a\nb");
        assert!(!app.log_text_dirty, "clean after rebuild");
        assert_eq!(app.cached_log_text(), "a\nb", "no rebuild, same text");
        app.log_line("c".to_string());
        assert!(app.log_text_dirty, "a new line dirties the cache");
        assert_eq!(app.cached_log_text(), "a\nb\nc");
    }

    /// v3.14 list fingerprint (diagnosis §3 item 7): stable while
    /// nothing the list reads changes; moves on every input that
    /// changes what the rows show (probe result, sort, connect).
    #[test]
    fn list_fingerprint_moves_only_on_list_inputs() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本"), node_in("b.opengw.net", "美国")];
        let fp0 = app.list_fingerprint();
        assert_eq!(app.list_fingerprint(), fp0, "stable with no change");
        app.probes
            .insert("a.opengw.net".to_string(), "10 ms".to_string());
        app.probe_ms.insert("a.opengw.net".to_string(), 10);
        let fp1 = app.list_fingerprint();
        assert_ne!(fp1, fp0, "a probe result must move the fingerprint");
        assert_eq!(app.list_fingerprint(), fp1, "stable again");
        app.toggle_sort(SortCol::Sessions);
        assert_ne!(
            app.list_fingerprint(),
            fp1,
            "a sort change must move the fingerprint"
        );
    }

    /// v3.14 rows cache (diagnosis §3 item 7): a second frame with
    /// an unchanged list does NOT rebuild the rows; a probe result
    /// (which changes a row's status cell) does — and the rebuilt
    /// rows show the new status.
    #[test]
    fn rows_cache_reuses_unchanged_list_and_rebuilds_on_probe() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本"), node_in("b.opengw.net", "美国")];
        let (fp, rows) = app.cached_rows();
        assert_eq!(app.rows_built, 1, "first frame builds");
        assert_eq!(rows[0].8, "未探测");
        app.rows_cache = Some((fp, rows));
        let (fp2, rows2) = app.cached_rows();
        assert_eq!(app.rows_built, 1, "unchanged list must not rebuild");
        assert_eq!(fp2, fp);
        assert_eq!(rows2[0].8, "未探测");
        app.rows_cache = Some((fp2, rows2));
        app.probes
            .insert("a.opengw.net".to_string(), "10 ms".to_string());
        app.probe_ms.insert("a.opengw.net".to_string(), 10);
        let (_fp3, rows3) = app.cached_rows();
        assert_eq!(app.rows_built, 2, "a probe result must rebuild");
        assert_eq!(rows3[0].8, "10 ms", "rebuilt rows show the new status");
    }

    /// v3.14 display-order cache: the order is computed once and
    /// reused, and a sort toggle invalidates it.
    #[test]
    fn display_indices_cached_and_invalidated_by_sort() {
        let mut app = GuiApp::for_tests();
        app.nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
            node_in("c.opengw.net", "德国"),
        ];
        assert_eq!(app.display_indices(), vec![0, 1, 2]);
        assert!(app.order_cache.is_some(), "first call fills the cache");
        assert_eq!(app.display_indices(), vec![0, 1, 2], "cached reuse");
        app.toggle_sort(SortCol::Country);
        assert_eq!(
            app.display_indices(),
            vec![2, 0, 1],
            "sort by country (code-point order: 德国/日本/美国) must invalidate"
        );
    }

    /// v3.14 restart-resume, case 1: a marker for a node that IS in
    /// the list makes the new instance select it and start the
    /// normal connect — and the marker file is already gone (it is
    /// consumed before connecting, so it can only ever fire once).
    /// The connect itself cannot complete in a headless test (no
    /// tokio runtime in `for_tests`), so the assertion is the
    /// started connect: busy + selected + log.
    #[test]
    fn resume_connects_back_to_same_node_when_marker_present() {
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let path = tray::resume_file_path().expect("exe path known in tests");
        let _ = std::fs::remove_file(&path);
        tray::write_resume_target(&path, "a.opengw.net:992", "a.opengw.net:992")
            .expect("write resume");
        let ctx = egui::Context::default();
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本"), node_in("b.opengw.net", "美国")];
        app.try_resume(ctx);
        assert!(!path.exists(), "marker must be consumed before connecting");
        assert_eq!(app.selected, Some(0), "the resumed node is selected");
        assert_eq!(app.busy, Some(Busy::Connecting), "the connect must start");
        assert!(app.resume_pending, "resume outcome is tracked");
        assert!(
            app.log.iter().any(|l| l.contains("重启恢复")
                && l.contains("a.opengw.net:992")),
            "log names the resumed node: {:?}",
            app.log
        );
        let _ = std::fs::remove_file(&path);
    }

    /// v3.14 restart-resume, case 2: the marker's node is NOT in
    /// the list — log why, stay disconnected, do not retry.
    #[test]
    fn resume_missing_target_stays_disconnected_and_logs() {
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let path = tray::resume_file_path().expect("exe path known in tests");
        let _ = std::fs::remove_file(&path);
        tray::write_resume_target(&path, "gone.opengw.net:992", "gone.opengw.net:992")
            .expect("write resume");
        let ctx = egui::Context::default();
        let mut app = GuiApp::for_tests();
        app.nodes = vec![node_in("a.opengw.net", "日本")];
        app.try_resume(ctx);
        assert!(!path.exists(), "marker consumed even when the node is gone");
        assert_eq!(app.selected, None, "nothing selected");
        assert_eq!(app.busy, None, "no connect started");
        assert!(app.conn.is_none(), "stays disconnected");
        assert!(
            app.log.iter().any(|l| l.contains("重启恢复")
                && l.contains("不在列表里")),
            "log explains the missing node: {:?}",
            app.log
        );
        let _ = std::fs::remove_file(&path);
    }

    /// v3.14 restart-resume, case 3: no marker (a manual open) —
    /// nothing happens: no selection, no connect, no resume log.
    #[test]
    fn resume_no_marker_stays_disconnected() {
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let path = tray::resume_file_path().expect("exe path known in tests");
        let _ = std::fs::remove_file(&path);
        let ctx = egui::Context::default();
        let mut app = GuiApp::for_tests();
        let log_len = app.log.len();
        app.try_resume(ctx);
        assert_eq!(app.selected, None);
        assert_eq!(app.busy, None);
        assert!(app.conn.is_none());
        assert_eq!(app.log.len(), log_len, "no resume log without a marker");
    }

    /// v3.14 restart-resume, case 4: a manual quit deletes any
    /// resume marker (e.g. a stale one from a crashed restart), so
    /// the next manual open can never auto-connect.
    #[test]
    fn manual_quit_clears_resume_marker() {
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let path = tray::resume_file_path().expect("exe path known in tests");
        tray::write_resume_target(&path, "a.opengw.net:992", "a.opengw.net:992")
            .expect("write resume");
        assert!(path.exists());
        let mut app = GuiApp::for_tests();
        app.perform_quit();
        assert!(!path.exists(), "manual quit must delete the marker");
        let _ = std::fs::remove_file(&path);
    }

    /// v3.15 restart, case 5: `prepare_restart` on a connected
    /// app disconnects FIRST (log order: 已断开 before 正在重启),
    /// writes the resume marker, and hands back a successor
    /// command carrying `--restart-wait-pid <this pid>` — the
    /// successor waits for this process to exit before it binds
    /// 10818 or connects. Mock-backed (same skip as the other
    /// mock tests when python3/openssl are missing).
    #[test]
    fn prepare_restart_disconnects_first_writes_marker_and_wait_pid() {
        let _mock_guard = MOCK_LOCK.lock().unwrap();
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let Some((_mock, tunnel)) = mock_tunnel() else {
            return;
        };
        let path = tray::resume_file_path().expect("exe path known in tests");
        let _ = std::fs::remove_file(&path);
        let mut app = connected_test_app(tunnel);
        assert!(app.conn.is_some(), "the fixture must start connected");
        let (exe, args) = app.prepare_restart().expect("prepare_restart");
        assert!(exe.is_file(), "the successor exe must be a real file");
        assert!(
            app.conn.is_none(),
            "prepare_restart must disconnect before the successor is spawned"
        );
        assert!(path.exists(), "the resume marker must be written");
        let text = std::fs::read_to_string(&path).expect("read the marker");
        assert!(
            text.contains("a.opengw.net:992"),
            "the marker must name the resumed node, got: {}",
            text
        );
        let pid = std::process::id().to_string();
        let pos = args
            .iter()
            .position(|a| a == "--restart-wait-pid")
            .expect("the successor args must carry --restart-wait-pid");
        assert_eq!(
            args.get(pos + 1).map(|s| s.as_str()),
            Some(pid.as_str()),
            "the wait pid must be this process, args: {:?}",
            args
        );
        let dis = app
            .log
            .iter()
            .position(|l| l.contains("已断开"))
            .expect("the log must record the disconnect");
        let rst = app
            .log
            .iter()
            .position(|l| l.contains("正在重启"))
            .expect("the log must record the restart");
        assert!(
            dis < rst,
            "the log order must be disconnect-then-restart, got: {:?}",
            app.log
        );
        let _ = std::fs::remove_file(&path);
    }

    /// v3.15 restart, case 6: `prepare_restart` while
    /// disconnected writes no marker (the successor still starts
    /// disconnected) but still hands back a wait-pid command —
    /// the successor must wait for this process to exit before
    /// it takes the single-instance lock, or the lock would see
    /// a live old instance and kill the restart.
    #[test]
    fn prepare_restart_disconnected_writes_no_marker_but_waits() {
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let path = tray::resume_file_path().expect("exe path known in tests");
        let _ = std::fs::remove_file(&path);
        let mut app = GuiApp::for_tests();
        let (_exe, args) = app.prepare_restart().expect("prepare_restart");
        assert!(
            !path.exists(),
            "no marker when nothing was connected"
        );
        assert!(
            args.contains(&"--restart-wait-pid".to_string()),
            "the successor must still wait for this process, args: {:?}",
            args
        );
        assert!(
            app.log.iter().any(|l| l.contains("正在重启客户端")),
            "the restart must be logged: {:?}",
            app.log
        );
        let _ = std::fs::remove_file(&path);
    }

    /// v3.15 restart, case 7: a restart quit keeps the resume
    /// marker (the mirror of `manual_quit_clears_resume_marker`
    /// — suspect 2 in the v3.14 restart diagnosis: the marker
    /// must survive the restart's own exit, or the successor
    /// reads nothing).
    #[test]
    fn restart_quit_keeps_resume_marker() {
        let _lock = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let path = tray::resume_file_path().expect("exe path known in tests");
        tray::write_resume_target(&path, "a.opengw.net:992", "a.opengw.net:992")
            .expect("write resume");
        assert!(path.exists());
        let mut app = GuiApp::for_tests();
        app.restarting = true;
        app.perform_quit();
        assert!(
            path.exists(),
            "a restart quit must keep the marker for the successor"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// v3.15 single-instance, UI half: a raised `show_requested`
    /// flag brings the hidden window back — the same effect as a
    /// tray double-click. The watcher thread + named event that
    /// raise the flag are Windows-only and cannot run headless,
    /// so this test drives the flag consumption directly; the
    /// event delivery itself is left to Leo's real-machine check.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn second_instance_signal_shows_hidden_window() {
        use egui_kittest::Harness;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| GuiApp::for_render_tests(cc));
        harness.run_steps(10);
        harness.state_mut().hidden_to_tray = true;
        harness
            .state_mut()
            .show_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        harness.run_steps(5);
        assert!(
            !harness.state().hidden_to_tray,
            "the show request must bring the hidden window back"
        );
        assert!(
            !harness
                .state()
                .show_requested
                .load(std::sync::atomic::Ordering::SeqCst),
            "the flag must be consumed"
        );
    }

    /// v3.13 switch through the real UI (kittest): connected to A,
    /// click row B, press Enter — the old connection is dropped and
    /// a connect to B starts. Needs a graphics adapter + the mock
    /// server (same skip as the unit test above).
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn enter_key_switches_node_while_connected() {
        use egui_kittest::Harness;
        let _mock_guard = MOCK_LOCK.lock().unwrap();
        let Some((_mock, tunnel)) = mock_tunnel() else {
            return;
        };
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| GuiApp::for_render_tests(cc));
        harness.run_steps(10);
        harness.state_mut().nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
        ];
        let vip = tunnel.vip;
        harness.state_mut().conn = Some(ActiveConnection {
            tunnel,
            serve: Vec::new(),
            proxy_guard: None,
            listen_addr: "127.0.0.1:10818".to_string(),
            node_label: "a.opengw.net:992".to_string(),
            vip,
        });
        harness.run_steps(3);
        // Click row B, then Enter.
        click_row_label(&mut harness, "美国");
        assert_eq!(harness.state().selected, Some(1));
        harness.key_press(egui::Key::Enter);
        harness.run_steps(3);
        assert!(
            harness.state().conn.is_none(),
            "Enter must drop the old connection"
        );
        assert_eq!(
            harness.state().busy,
            Some(Busy::Connecting),
            "Enter must start connecting B, busy={:?}",
            harness.state().busy
        );
        assert!(
            harness
                .state()
                .log
                .iter()
                .any(|l| l.contains("已断开 a.opengw.net:992")),
            "log must name the disconnected old node: {:?}",
            harness.state().log
        );
        assert!(
            harness
                .state()
                .log
                .iter()
                .any(|l| l.contains("开始连接 b.opengw.net:992")),
            "log must name the new connect: {:?}",
            harness.state().log
        );
    }

    /// v3.13 switch through the 连接 button (kittest): while
    /// connected to A with B selected, the 连接 button next to
    /// 断开连接 disconnects A and starts connecting B — the same
    /// path as Enter. Needs a graphics adapter + the mock server.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn connect_button_switches_node_while_connected() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _mock_guard = MOCK_LOCK.lock().unwrap();
        let Some((_mock, tunnel)) = mock_tunnel() else {
            return;
        };
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| GuiApp::for_render_tests(cc));
        harness.run_steps(10);
        harness.state_mut().nodes = vec![
            node_in("a.opengw.net", "日本"),
            node_in("b.opengw.net", "美国"),
        ];
        let vip = tunnel.vip;
        harness.state_mut().conn = Some(ActiveConnection {
            tunnel,
            serve: Vec::new(),
            proxy_guard: None,
            listen_addr: "127.0.0.1:10818".to_string(),
            node_label: "a.opengw.net:992".to_string(),
            vip,
        });
        harness.state_mut().selected = Some(1);
        harness.run_steps(3);
        // The switch 连接 button must exist next to 断开连接 while
        // another node is selected (before v3.13 only 断开连接 was
        // shown when connected).
        let btn = harness.get_by_label("连接");
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(
            harness.state().conn.is_none(),
            "the switch button must drop the old connection"
        );
        assert_eq!(
            harness.state().busy,
            Some(Busy::Connecting),
            "the switch button must start connecting B, busy={:?}",
            harness.state().busy
        );
    }

    /// v3.12: hiding to the tray sets the flag and writes the
    /// one-time hint (status + log); a second hide does not repeat
    /// it. A Quit decision changes nothing here.
    #[test]
    fn apply_close_hide_sets_flag_and_hint_once() {
        let mut app = GuiApp::for_tests();
        app.apply_close(tray::CloseDecision::HideToTray);
        assert!(app.hidden_to_tray);
        assert_eq!(app.status, tray::TRAY_HINT);
        assert!(app.log.iter().any(|l| l == tray::TRAY_HINT));
        let log_len = app.log.len();
        app.apply_close(tray::CloseDecision::HideToTray);
        assert_eq!(app.log.len(), log_len, "the hint is written once");
        let mut app2 = GuiApp::for_tests();
        app2.apply_close(tray::CloseDecision::Quit);
        assert!(!app2.hidden_to_tray);
        assert_eq!(app2.status, "未连接");
    }

    /// v3.12: the real-quit path disconnects (status back to 未连接)
    /// and persists a changed setting — the same path the File-menu
    /// 退出 and the tray-menu 退出 share.
    #[test]
    fn perform_quit_disconnects_and_saves() {
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut app = GuiApp::for_tests();
        app.front_enabled = true;
        app.front_addr = "127.0.0.1:1081".to_string();
        app.perform_quit();
        assert_eq!(app.status, "未连接");
        let path = Config::portable_config_path().expect("exe dir known");
        let back = Config::load(Some(&path)).expect("saved config loads");
        assert!(back.front_proxy.enabled);
        assert_eq!(back.front_proxy.addr, "127.0.0.1:1081");
        let _ = std::fs::remove_file(&path);
    }

    /// Render the smallest window (560x420) in both themes for visual
    /// review, plus the 800x600 window in both themes, a 150% zoom
    /// render and scrolled-to-bottom renders (they must show the end
    /// of 高级设置 and the log — that is the outer-scroll fix being
    /// verified). Needs a wgpu adapter (software lavapipe is enough);
    /// on a machine without one this test fails and must be skipped,
    /// not faked.
    #[test]
    #[ignore = "renders PNGs for review; needs a graphics adapter"]
    fn render_for_review() {
        use egui_kittest::{kittest::Queryable, Harness};
        for (theme, name, zoom, scrolled, w, h) in [
            (egui::Theme::Dark, "dark", 1.0, false, 560.0, 420.0),
            (egui::Theme::Light, "light", 1.0, false, 560.0, 420.0),
            (egui::Theme::Dark, "dark-800x600", 1.0, false, 800.0, 600.0),
            (egui::Theme::Light, "light-800x600", 1.0, false, 800.0, 600.0),
            (egui::Theme::Dark, "dark-zoom150", 1.5, false, 560.0, 420.0),
            (egui::Theme::Dark, "dark-scrolled", 1.0, true, 560.0, 420.0),
            (egui::Theme::Light, "light-scrolled", 1.0, true, 560.0, 420.0),
        ] {
            let mut harness = Harness::builder()
                .with_size(egui::vec2(w, h))
                .with_theme(theme)
                .build_eframe(|cc| {
                    if scrolled {
                        GuiApp::for_render_tests_scrolled(cc)
                    } else {
                        GuiApp::for_render_tests(cc)
                    }
                });
            if zoom != 1.0 {
                harness.ctx.set_zoom_factor(zoom);
            }
            // ScrollAreas request repaints while settling, and the
            // always-visible scroll bars fade in over a few frames;
            // step a fixed number of frames instead of run() (see
            // egui-kittest skill).
            harness.run_steps(30);
            if scrolled {
                // The widgets the scroll must reveal exist in the UI.
                // (The PNG itself is the proof they are actually in
                // view — check it, don't trust this assertion alone.)
                harness.get_by_label("测试前置代理");
                harness.get_by_label("日志");
            }
            let path = std::env::temp_dir().join(format!("ui-review-{name}.png"));
            harness
                .render()
                .expect("needs a graphics adapter")
                .save(&path)
                .unwrap();
            eprintln!("{}", path.display());
        }
    }

    /// Isolation: does a bare Sense::drag handle (no ScrollArea) respond
    /// to the same kittest drag sequence? Temporary diagnostic for the
    /// column-separator test.
    #[test]
    #[ignore = "diagnostic; needs a graphics adapter"]
    fn kittest_drag_smoke() {
        use egui_kittest::Harness;
        struct DragApp {
            w: f32,
        }
        impl eframe::App for DragApp {
            fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ui, |ui| {
                    // Mirror the real layout: outer vertical ScrollArea,
                    // inner both-directions ScrollArea, header row in a
                    // horizontal layout with a 6 px drag separator.
                    egui::ScrollArea::vertical()
                        .id_salt("outer")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            egui::ScrollArea::both()
                                .id_salt("inner")
                                .max_height(120.0)
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    ui.spacing_mut().item_spacing = egui::vec2(6.0, 4.0);
                                    // Fixed layout: cells and separator at
                                    // exact rects (see the real header — the
                                    // allocate_ui_with_layout version let the
                                    // cells shrink to their label width and
                                    // put the separator in the wrong place).
                                    let (header_rect, _) = ui.allocate_exact_size(
                                        egui::vec2(238.0, 22.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.put(
                                        egui::Rect::from_min_size(
                                            egui::pos2(header_rect.left(), header_rect.top()),
                                            egui::vec2(90.0, 22.0),
                                        ),
                                        egui::Label::new("国家/地区"),
                                    );
                                    let handle_rect = egui::Rect::from_min_size(
                                        egui::pos2(header_rect.left() + 96.0, header_rect.top()),
                                        egui::vec2(6.0, 22.0),
                                    );
                                    let resp = ui.interact(
                                        handle_rect,
                                        egui::Id::new("smoke_col_sep"),
                                        egui::Sense::drag(),
                                    );
                                    if resp.dragged() || resp.drag_stopped() {
                                        self.w += resp.drag_delta().x;
                                    }
                                    ui.put(
                                        egui::Rect::from_min_size(
                                            egui::pos2(
                                                header_rect.left() + 108.0,
                                                header_rect.top(),
                                            ),
                                            egui::vec2(130.0, 22.0),
                                        ),
                                        egui::Label::new("运营商"),
                                    );
                                    for _ in 0..28 {
                                        ui.label("row");
                                    }
                                });
                        });
                });
            }
        }
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|_cc| DragApp { w: 90.0 });
        harness.run_steps(10);
        // The handle sits after the 90 px first cell: left edge ~8 px,
        // centre ~(107, 19).
        let sep = egui::pos2(107.0, 19.0);
        harness.hover_at(sep);
        harness.run();
        harness.drag_at(sep);
        harness.run();
        let target = egui::pos2(sep.x + 40.0, sep.y);
        harness.hover_at(target);
        harness.run();
        harness.drop_at(target);
        harness.run();
        assert!(
            harness.state().w >= 120.0,
            "bare drag handle should widen: w={}",
            harness.state().w
        );
    }

    /// Drag the separator after the header cell with `label` right by
    /// `delta` px and return the column widths afterwards. The
    /// separator centre is one item gap (6 px) past the cell's right
    /// edge plus half the 6 px handle: left + width + 9.
    fn drag_header_separator(
        harness: &mut egui_kittest::Harness<GuiApp>,
        label: &str,
        wi: usize,
        delta: f32,
    ) -> [u16; 7] {
        use egui_kittest::kittest::Queryable;
        let w = harness.state().col_widths[wi];
        let header = harness.get_by_label(label);
        let r = header.rect();
        let sep = egui::pos2(r.left() + w as f32 + 9.0, r.center().y);
        harness.hover_at(sep);
        harness.run();
        harness.drag_at(sep);
        harness.run();
        // Move while the button is held (a real drag sends PointerMoved
        // events between press and release; drop_at alone only sends
        // the release event, whose delta the release frame would miss).
        let target = egui::pos2(sep.x + delta, sep.y);
        harness.hover_at(target);
        harness.run();
        harness.drop_at(target);
        harness.run();
        harness.state().col_widths
    }

    /// Dragging a header separator widens that column (needs a graphics
    /// adapter, like the render test). Every resizable column but the
    /// last has a separator: 国家/地区， 运营商， 当前人数， 线路质量，
    /// 人均带宽， 主机:端口 — dragging one widens exactly that column
    /// and leaves the other six alone, and the widths persist through
    /// the config round-trip.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn column_separator_drag_widens_column() {
        use egui_kittest::Harness;
        // 800 px, not the 560 px minimum: at the default widths the
        // row is 886 px wide, so the 主机:端口 separator (x ≈ 787)
        // is off-screen at 560 px and cannot be grabbed. Dragging
        // right-to-left keeps the not-yet-dragged separators at
        // their initial positions (a drag only shifts columns to
        // its right). The drags run on narrowed widths (total
        // ≈ 524 px) so every separator is inside the 800 px window.
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 420.0))
            .build_eframe(|cc| GuiApp::for_render_tests(cc));
        harness.run_steps(10);
        assert_eq!(
            harness.state().col_widths,
            [90, 130, 64, 88, 80, 190, 90],
            "defaults before any drag"
        );
        harness.state_mut().col_widths = [50, 60, 40, 50, 40, 80, 50];
        harness.run_steps(5);
        for (label, wi) in [
            ("主机:端口", 5usize),
            ("人均带宽", 4usize),
            ("线路质量", 3usize),
            ("当前人数", 2usize),
            ("运营商", 1usize),
            ("国家/地区", 0usize),
        ] {
            let before = harness.state().col_widths;
            let after = drag_header_separator(&mut harness, label, wi, 40.0);
            assert!(
                after[wi] >= before[wi] + 30,
                "dragging the separator after {} should widen col_widths[{}]: {} -> {}",
                label,
                wi,
                before[wi],
                after[wi]
            );
            for (j, (&b, &a)) in before.iter().zip(after.iter()).enumerate() {
                if j != wi {
                    assert_eq!(
                        b, a,
                        "dragging {} must not move col_widths[{}]: {} -> {}",
                        label, j, b, a
                    );
                }
            }
        }
        // The dragged widths persist: current_config carries them,
        // and a fresh app built from that config shows the same
        // widths.
        let cfg = harness.state().current_config();
        assert_eq!(cfg.ui.node_col_widths, harness.state().col_widths);
        let mut app2 = GuiApp::for_tests();
        app2.apply_config(&cfg);
        assert_eq!(app2.col_widths, harness.state().col_widths);
    }

    /// Drag a height-handle rect straight down by `delta` px (same
    /// kittest sequence as the column-separator drag: hover, press,
    /// move while held, release).
    fn drag_handle_down(
        harness: &mut egui_kittest::Harness<GuiApp>,
        rect: egui::Rect,
        delta: f32,
    ) {
        let start = rect.center();
        harness.hover_at(start);
        harness.run();
        harness.drag_at(start);
        harness.run();
        let target = egui::pos2(start.x, start.y + delta);
        harness.hover_at(target);
        harness.run();
        harness.drop_at(target);
        harness.run();
    }

    /// v3.13: dragging each of the three height handles (node list,
    /// advanced settings, log) grows that box, and the dragged
    /// heights persist through the config round-trip. Dragged
    /// bottom-up (log, advanced, list) so a taller box above never
    /// pushes a not-yet-dragged handle off-screen mid-test. Needs a
    /// graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn height_handles_drag_and_persist() {
        use egui_kittest::Harness;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 800.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                // Compact starting heights so all three handles fit
                // in the window at once (no outer scroll needed to
                // reach them). Advanced is open in render tests.
                app.list_height = Some(150.0);
                app.advanced_height = 120.0;
                app.log_height = 60.0;
                app.log = (0..30).map(|i| format!("日志行 {i}")).collect();
                app
            });
        harness.run_steps(10);
        // Log handle first (bottom-up).
        let rect = harness
            .state()
            .log_handle_rect
            .expect("log handle must be laid out");
        drag_handle_down(&mut harness, rect, 40.0);
        let log_h = harness.state().log_height;
        assert!(
            (85.0..=120.0).contains(&log_h),
            "log height after a +40 drag: {log_h} (was 60)"
        );
        // Advanced handle.
        harness.run_steps(3);
        let rect = harness
            .state()
            .advanced_handle_rect
            .expect("advanced handle must be laid out");
        drag_handle_down(&mut harness, rect, 40.0);
        let adv_h = harness.state().advanced_height;
        assert!(
            (145.0..=180.0).contains(&adv_h),
            "advanced height after a +40 drag: {adv_h} (was 120)"
        );
        // List handle.
        harness.run_steps(3);
        let rect = harness
            .state()
            .list_handle_rect
            .expect("list handle must be laid out");
        drag_handle_down(&mut harness, rect, 40.0);
        let list_h = harness
            .state()
            .list_height
            .expect("dragging the list handle must set list_height");
        assert!(
            (175.0..=210.0).contains(&list_h),
            "list height after a +40 drag: {list_h} (was 150)"
        );
        // The dragged heights persist: current_config carries them
        // (whole pixels), and a fresh app built from that config
        // shows the same heights.
        let cfg = harness.state().current_config();
        assert!(
            (cfg.ui.list_height.unwrap() as f32 - list_h).abs() <= 1.0,
            "saved list_height {:?} vs dragged {list_h}",
            cfg.ui.list_height
        );
        assert!(
            (cfg.ui.advanced_height as f32 - adv_h).abs() <= 1.0,
            "saved advanced_height {} vs dragged {adv_h}",
            cfg.ui.advanced_height
        );
        assert!(
            (cfg.ui.log_height as f32 - log_h).abs() <= 1.0,
            "saved log_height {} vs dragged {log_h}",
            cfg.ui.log_height
        );
        let mut app2 = GuiApp::for_tests();
        app2.apply_config(&cfg);
        assert_eq!(app2.list_height, Some(list_h.round()));
        assert!((app2.advanced_height - adv_h).abs() <= 1.0);
        assert!((app2.log_height - log_h).abs() <= 1.0);
    }

    /// v3.13 scroll bars, both themes: the 28 curated nodes overflow
    /// the ~170 px list, 30 log lines overflow the 90 px log box, and
    /// the whole content overflows the panel — all three bars must
    /// have something to show. The PNGs are the proof — check them,
    /// don't trust this test alone (it only asserts the render
    /// pipeline ran); the 12 px width is asserted in
    /// `thick_scroll_style_is_12px_solid_foreground`.
    #[test]
    #[ignore = "renders PNGs for review; needs a graphics adapter"]
    fn scrollbars_visible_in_both_themes() {
        use egui_kittest::Harness;
        for (theme, name) in [
            (egui::Theme::Dark, "dark"),
            (egui::Theme::Light, "light"),
        ] {
            let mut harness = Harness::builder()
                .with_size(egui::vec2(560.0, 420.0))
                .with_theme(theme)
                .build_eframe(|cc| {
                    let mut app = GuiApp::for_render_tests(cc);
                    app.log = (0..30).map(|i| format!("日志行 {i}")).collect();
                    app
                });
            harness.run_steps(30);
            let path = std::env::temp_dir()
                .join(format!("ui-review-v313-scrollbars-{name}.png"));
            harness
                .render()
                .expect("needs a graphics adapter")
                .save(&path)
                .unwrap();
            eprintln!("{}", path.display());
        }
    }

    /// A plain click selects the row, and a press that drifts 8 px
    /// (past egui's 6 px max_click_dist) and releases on the same row
    /// still selects it — the tolerant-click fix for "rows are hard
    /// to select". Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn row_click_selects_and_drag_tolerance_selects() {
        use egui_kittest::{kittest::Queryable, Harness};
        // Taller than the 560x420 minimum so all three test rows (and
        // the selected-row screenshot at the end) fit the list.
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Plain click on the 美国 row's country cell.
        let cell = harness.get_by_label("美国");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().selected,
            Some(1),
            "clicking a row must select it"
        );
        // Drag tolerance: press on the 德国 row, drift 8 px down
        // (past egui's 6 px click limit), release on the same row.
        // Vertical drift keeps the row rect still (no vertical
        // overflow to scroll), so the release lands in the row.
        let cell = harness.get_by_label("德国");
        let start = cell.rect().center();
        harness.drag_at(start);
        harness.run();
        let moved = egui::pos2(start.x, start.y + 8.0);
        harness.hover_at(moved);
        harness.run();
        harness.drop_at(moved);
        harness.run();
        assert_eq!(
            harness.state().selected,
            Some(2),
            "an 8 px press-drag-release on a row must still select it"
        );
        // Save a screenshot of the selected row for visual review
        // (white text on the indigo selection fill).
        let path = std::env::temp_dir().join("ui-review-selected-row.png");
        harness
            .render()
            .expect("needs a graphics adapter")
            .save(&path)
            .unwrap();
        eprintln!("{}", path.display());
    }

    /// Ctrl+click multi-select, then the 删除选中 button: clicking
    /// one row selects it, Ctrl+clicking a second row adds it to the
    /// set, and 删除选中 removes both rows and records them on the
    /// blocklist. Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn ctrl_click_multi_select_and_delete_button() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Plain click on the 日本 row.
        let cell = harness.get_by_label("日本");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().selected, Some(0));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "plain click selects one row"
        );
        // Ctrl+click on the 美国 row: egui only tracks modifiers
        // from ModifiersChanged events, so queue one before the
        // press and again before the release (the row code reads
        // the modifiers on the release frame).
        let ctrl = egui::Modifiers {
            ctrl: true,
            ..Default::default()
        };
        let cell = harness.get_by_label("美国");
        let center = cell.rect().center();
        harness.event(egui::Event::ModifiersChanged(ctrl));
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(ctrl));
        harness.drop_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
        harness.run();
        assert_eq!(harness.state().selected, Some(1));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1]),
            "Ctrl+click must add the row to the set, not replace it"
        );
        // The delete button carries the count; clicking it removes
        // both rows and blocks their hostnames.
        let btn = harness.get_by_label("删除选中 (2)");
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().nodes[0].host, "c.opengw.net");
        assert_eq!(harness.state().blocked_hosts.len(), 2);
        assert!(harness.state().selected_set.is_empty());
        // No restore button any more (v3.10): the deleted hosts stay
        // on the blocklist until unblocked in config.toml.
        assert!(harness.query_by_label("恢复已删除 (2)").is_none());
    }

    /// Shift+click selects the whole range from the anchor to the
    /// clicked row (display order), and arrow keys still collapse
    /// the multi-select to the row the anchor moved to. Needs a
    /// graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn shift_click_selects_range() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                    node_in("d.opengw.net", "法国"),
                    node_in("e.opengw.net", "英国"),
                ];
                app
            });
        harness.run_steps(10);
        let shift = egui::Modifiers {
            shift: true,
            ..Default::default()
        };
        // Shift+click helper: queue ModifiersChanged(shift) before
        // the press and again before the release, mirroring the
        // Ctrl+click test (the row code reads the modifiers on the
        // release frame).
        let shift_click = |harness: &mut egui_kittest::Harness<'_, GuiApp>, label: &str| {
            let cell = harness.get_by_label(label);
            let center = cell.rect().center();
            harness.event(egui::Event::ModifiersChanged(shift));
            harness.drag_at(center);
            harness.run();
            harness.event(egui::Event::ModifiersChanged(shift));
            harness.drop_at(center);
            harness.run();
            harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
            harness.run();
        };
        // Plain click on the 日本 row: anchor 0, set {0}.
        let cell = harness.get_by_label("日本");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().selected, Some(0));
        assert_eq!(harness.state().selected_set, BTreeSet::from([0]));
        // Shift+click on the 德国 row: the range 0..=2.
        shift_click(&mut harness, "德国");
        assert_eq!(harness.state().selected, Some(2));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1, 2]),
            "Shift+click must select the range from the anchor"
        );
        // Shift+click on the 英国 row: the anchor moved to 德国 on
        // the previous click, so the range is 2..=4 — every click
        // moves the anchor (see `click_row`), a second Shift+click
        // re-anchors rather than extending from the first one.
        shift_click(&mut harness, "英国");
        assert_eq!(harness.state().selected, Some(4));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([2, 3, 4]),
            "Shift+click selects the range from the current anchor"
        );
        // Plain click on the 美国 row collapses to one row.
        let cell = harness.get_by_label("美国");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().selected_set, BTreeSet::from([1]));
        // Shift+click on the 法国 row: the range 1..=3.
        shift_click(&mut harness, "法国");
        assert_eq!(harness.state().selected, Some(3));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([1, 2, 3]),
            "Shift+click after a plain click starts from the new anchor"
        );
        // Arrow key ↓ moves the anchor and collapses the set to it.
        harness.key_press(egui::Key::ArrowDown);
        harness.run();
        assert_eq!(harness.state().selected, Some(4));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([4]),
            "arrow keys must still collapse the multi-select to one row"
        );
    }

    /// Shift+click with no anchor yet (the selection was cleared by
    /// a delete) selects just that row and makes it the anchor.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn shift_click_without_anchor_selects_single_row() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Plain click on 日本, then delete it: the selection (and
        // the anchor) is cleared, leaving [美国， 德国].
        let cell = harness.get_by_label("日本");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        let btn = harness.get_by_label("删除选中 (1)");
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().nodes.len(), 2);
        assert_eq!(harness.state().selected, None);
        assert!(harness.state().selected_set.is_empty());
        // Shift+click on the first remaining row (美国） with no
        // anchor: just that row, and it becomes the anchor.
        let shift = egui::Modifiers {
            shift: true,
            ..Default::default()
        };
        let cell = harness.get_by_label("美国");
        let center = cell.rect().center();
        harness.event(egui::Event::ModifiersChanged(shift));
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(shift));
        harness.drop_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
        harness.run();
        assert_eq!(harness.state().selected, Some(0));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "Shift+click with no anchor must fall back to a plain click"
        );
    }

    /// Shift+click still selects the range even when the user lets
    /// go of Shift before releasing the mouse button — the
    /// modifiers are latched at press time. Needs a graphics
    /// adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn shift_click_survives_early_shift_release() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Plain click on 日本: anchor 0, set {0}.
        let cell = harness.get_by_label("日本");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().selected_set, BTreeSet::from([0]));
        // Shift+click on 德国， but release Shift before the mouse
        // button: ModifiersChanged(shift) only before the press,
        // ModifiersChanged(default) before the release.
        let shift = egui::Modifiers {
            shift: true,
            ..Default::default()
        };
        let cell = harness.get_by_label("德国");
        let center = cell.rect().center();
        harness.event(egui::Event::ModifiersChanged(shift));
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().selected, Some(2));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1, 2]),
            "releasing Shift before the mouse button must not lose the range"
        );
    }

    /// End-to-end: Shift+click a range, then "删除选中" removes
    /// exactly those rows and records their hosts on the blocklist.
    /// This is the flow Leo reported as broken in v3.7 (Shift+click
    /// selected a range, but delete removed nothing): it covers both
    /// halves — the range must actually be selected (anchor +
    /// modifiers), and the delete button must read the same set the
    /// highlight shows. Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn shift_click_then_delete_removes_range() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                    node_in("d.opengw.net", "法国"),
                    node_in("e.opengw.net", "英国"),
                ];
                app
            });
        harness.run_steps(10);
        // Plain click on 日本 sets the anchor; Shift+click on 法国
        // selects the range 0..=3.
        click_row_label(&mut harness, "日本");
        assert_eq!(harness.state().selected, Some(0));
        shift_click_row_label(&mut harness, "法国");
        assert_eq!(harness.state().selected, Some(3));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1, 2, 3]),
            "Shift+click must select the range from the anchor"
        );
        // The delete button carries the count of the same set the
        // highlight shows — if it read a different state, the count
        // here would be wrong.
        let _btn = harness.get_by_label("删除选中 (4)");
        // Delete: the four rows go, their hosts land on the
        // blocklist, the selection is cleared, and only 英国 is left.
        click_button_label(&mut harness, "删除选中 (4)");
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().nodes[0].host, "e.opengw.net");
        assert_eq!(
            harness.state().blocked_hosts.len(),
            4,
            "all four deleted hosts must be blocked, got: {:?}",
            harness.state().blocked_hosts
        );
        for host in ["a.opengw.net", "b.opengw.net", "c.opengw.net", "d.opengw.net"] {
            assert!(
                harness.state().blocked_hosts.contains(host),
                "blocked_hosts must contain {}, got: {:?}",
                host,
                harness.state().blocked_hosts
            );
        }
        assert!(harness.state().selected_set.is_empty());
        assert_eq!(harness.state().selected, None);
    }

    /// End-to-end, no-anchor variant: Shift+click as the very first
    /// click selects just that row, and "删除选中" removes it.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn shift_click_first_then_delete_removes_single_row() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // No anchor yet: Shift+click on 德国 falls back to that row.
        shift_click_row_label(&mut harness, "德国");
        assert_eq!(harness.state().selected, Some(2));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([2]),
            "Shift+click with no anchor must select just that row"
        );
        let _btn = harness.get_by_label("删除选中 (1)");
        click_button_label(&mut harness, "删除选中 (1)");
        assert_eq!(harness.state().nodes.len(), 2);
        assert_eq!(harness.state().nodes[0].host, "a.opengw.net");
        assert_eq!(harness.state().nodes[1].host, "b.opengw.net");
        assert!(harness.state().blocked_hosts.contains("c.opengw.net"));
        assert!(harness.state().selected_set.is_empty());
        assert_eq!(harness.state().selected, None);
    }

    /// End-to-end, early-release variant: the same range-select +
    /// delete flow, but Shift is released before the mouse button
    /// on the Shift+click — the gesture Leo actually makes. Without
    /// the press-time modifier latch the range would be lost here
    /// and delete would have nothing to remove. Needs a graphics
    /// adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn shift_click_early_release_then_delete_removes_range() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                    node_in("d.opengw.net", "法国"),
                    node_in("e.opengw.net", "英国"),
                ];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        shift_click_row_label_early_release(&mut harness, "法国");
        assert_eq!(harness.state().selected, Some(3));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1, 2, 3]),
            "the range must survive Shift being released before the mouse button"
        );
        let _btn = harness.get_by_label("删除选中 (4)");
        click_button_label(&mut harness, "删除选中 (4)");
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().nodes[0].host, "e.opengw.net");
        assert_eq!(harness.state().blocked_hosts.len(), 4);
        assert!(harness.state().selected_set.is_empty());
        assert_eq!(harness.state().selected, None);
    }

    /// Reproduction for the v3.9 delete bug Leo reported on his
    /// Windows machine: with the list sorted, clicking a row and
    /// pressing "删除选中" logged "已删除 1 个节点" and grew the
    /// blocklist, but the clicked row stayed in the list. The row
    /// that goes must be exactly the clicked one, and the blocklist
    /// must hold exactly its host. Needs a graphics adapter, like
    /// the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn sorted_list_delete_removes_the_clicked_row() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "美国"),
                    node_in("b.opengw.net", "日本"),
                    node_in("c.opengw.net", "德国"),
                    node_in("d.opengw.net", "法国"),
                ];
                // Country A-Z: 德国(c) < 日本(b) < 法国(d) < 美国(a),
                // so display order [2, 1, 3, 0] differs from node order.
                app.sort = Some((SortCol::Country, SortDir::Asc));
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state_mut().display_indices(), vec![2, 1, 3, 0]);
        // Click the 法国 row: display position 2, node index 3.
        click_row_label(&mut harness, "法国");
        assert_eq!(harness.state().selected, Some(3));
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([3]),
            "clicking the 法国 row must select node index 3"
        );
        let _btn = harness.get_by_label("删除选中 (1)");
        click_button_label(&mut harness, "删除选中 (1)");
        let hosts: Vec<&str> = harness
            .state()
            .nodes
            .iter()
            .map(|n| n.host.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec!["a.opengw.net", "b.opengw.net", "c.opengw.net"],
            "the clicked row (d) must be gone, got: {:?}",
            hosts
        );
        assert!(harness.state().blocked_hosts.contains("d.opengw.net"));
        assert_eq!(harness.state().blocked_hosts.len(), 1);
        assert!(harness.state().selected_set.is_empty());
    }

    /// Sorted-list multi-select + delete: Ctrl+click two rows in a
    /// sorted list, delete, and both go — not the rows sitting at
    /// those display positions in node order. Needs a graphics
    /// adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn sorted_list_ctrl_click_delete_removes_both_rows() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "美国"),
                    node_in("b.opengw.net", "日本"),
                    node_in("c.opengw.net", "德国"),
                    node_in("d.opengw.net", "法国"),
                ];
                app.sort = Some((SortCol::Country, SortDir::Asc));
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state_mut().display_indices(), vec![2, 1, 3, 0]);
        // Click 德国 (node 2) then Ctrl+click 美国 (node 0).
        click_row_label(&mut harness, "德国");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([2]),
            "first click must select node index 2"
        );
        // Ctrl+click helper: plain click_row_label with Ctrl held.
        {
            use egui_kittest::kittest::Queryable as _;
            let ctrl = egui::Modifiers {
                ctrl: true,
                ..Default::default()
            };
            let cell = harness.get_by_label("美国");
            let center = cell.rect().center();
            harness.event(egui::Event::ModifiersChanged(ctrl));
            harness.drag_at(center);
            harness.run();
            harness.event(egui::Event::ModifiersChanged(ctrl));
            harness.drop_at(center);
            harness.run();
            harness.event(egui::Event::ModifiersChanged(egui::Modifiers::default()));
            harness.run();
        }
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 2]),
            "Ctrl+click must add node index 0, got: {:?}",
            harness.state().selected_set
        );
        let _btn = harness.get_by_label("删除选中 (2)");
        click_button_label(&mut harness, "删除选中 (2)");
        let hosts: Vec<&str> = harness
            .state()
            .nodes
            .iter()
            .map(|n| n.host.as_str())
            .collect();
        assert_eq!(
            hosts,
            vec!["b.opengw.net", "d.opengw.net"],
            "only the two clicked rows must go, got: {:?}",
            hosts
        );
        assert_eq!(harness.state().blocked_hosts.len(), 2);
        assert!(harness.state().blocked_hosts.contains("a.opengw.net"));
        assert!(harness.state().blocked_hosts.contains("c.opengw.net"));
        assert!(harness.state().selected_set.is_empty());
    }

    /// Press on a row, scroll the list with the mouse wheel, then
    /// release at the same screen point: the row that was PRESSED
    /// must be selected — not whichever row has scrolled under the
    /// cursor. This is the v3.9 delete bug (Leo): the tolerant-click
    /// path keys off the rows' CURRENT rects, so a click whose rows
    /// moved between press and release selects the wrong row, and
    /// the delete then removes that row while the one Leo meant
    /// stays. Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn drifted_click_after_scroll_selects_pressed_row() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = (1..=20)
                    .map(|i| {
                        node_in(
                            &format!("n{:02}.opengw.net", i),
                            &format!("国家{:02}", i),
                        )
                    })
                    .collect();
                app
            });
        harness.run_steps(10);
        // Press on the 国家05 row (node index 4).
        let cell = harness.get_by_label("国家05");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        // Scroll the list down with the wheel while the button is
        // held: the rows move, the pointer does not.
        harness.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Line,
            delta: egui::vec2(0.0, -3.0),
            modifiers: egui::Modifiers::default(),
            phase: egui::TouchPhase::Move,
        });
        harness.run();
        assert!(
            harness.state().node_list_scroll_y > 30.0,
            "the wheel must have scrolled the list by more than one row, got: {}",
            harness.state().node_list_scroll_y
        );
        // Release at the same screen point (now over another row).
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().selected,
            Some(4),
            "the pressed row (node 4) must be selected, got: {:?} (set {:?})",
            harness.state().selected,
            harness.state().selected_set
        );
        assert_eq!(harness.state().selected_set, BTreeSet::from([4]));
    }

    /// Pressing and releasing on the vertical scrollbar must not
    /// select any row. The tolerant-click path keys off any press
    /// in the window and row rects span the full list width
    /// (including the scrollbar strip), so a plain click on the
    /// scrollbar track selected whatever row sat at that height —
    /// and the next "删除选中" then removed that row while the one
    /// Leo meant stayed. Needs a graphics adapter.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn scrollbar_press_does_not_select_a_row() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "美国"),
                    node_in("b.opengw.net", "日本"),
                    node_in("c.opengw.net", "德国"),
                    node_in("d.opengw.net", "法国"),
                ];
                app
            });
        harness.run_steps(10);
        let cell = harness.get_by_label("德国");
        let y = cell.rect().center().y;
        // The vertical scrollbar sits at the far right edge of the
        // list (window is 800 wide; the bar is ~10 px).
        let on_bar = egui::pos2(787.0, y);
        harness.drag_at(on_bar);
        harness.run();
        harness.drop_at(on_bar);
        harness.run();
        assert!(
            harness.state().selected_set.is_empty(),
            "a scrollbar press must not select any row, got: {:?}",
            harness.state().selected_set
        );
        assert_eq!(harness.state().selected, None);
    }

    /// Clicking the 国家/地区 header toggles the sort A-Z / Z-A.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn country_header_click_toggles_sort() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("b.opengw.net", "美国"),
                    node_in("a.opengw.net", "日本"),
                ];
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state().sort, None);
        let header = harness.get_by_label("国家/地区");
        let center = header.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Country, SortDir::Asc)),
            "first header click sorts A-Z"
        );
        assert_eq!(
            harness.state_mut().display_indices(),
            vec![1, 0],
            "日本 before 美国 in A-Z order"
        );
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Country, SortDir::Desc)),
            "second header click sorts Z-A"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![0, 1]);
    }

    /// Clicking the 当前人数 / 线路质量 headers sorts by that column
    /// (first click = the column's most useful order, second click =
    /// reversed), and switching to the country header leaves the
    /// arrow only there. Needs a graphics adapter.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn sort_headers_toggle_and_switch_clears_arrow() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_stats("a.opengw.net", "日本", 47, 500, 10),
                    node_stats("b.opengw.net", "美国", 5, 100, 5),
                    node_stats("c.opengw.net", "德国", 301, 200, 20),
                ];
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state().sort, None);
        // 当前人数, first click: fewest first (b 5, a 47, c 301).
        let sessions_header = harness.get_by_label("当前人数");
        let sessions_center = sessions_header.rect().center();
        harness.drag_at(sessions_center);
        harness.run();
        harness.drop_at(sessions_center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Sessions, SortDir::Asc)),
            "first 当前人数 click sorts few-first"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![1, 0, 2]);
        // Same header again: most first.
        harness.drag_at(sessions_center);
        harness.run();
        harness.drop_at(sessions_center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Sessions, SortDir::Desc)),
            "second 当前人数 click sorts most-first"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![2, 0, 1]);
        // 线路质量, first click: fastest first (a 500, c 200, b 100).
        let quality_header = harness.get_by_label("线路质量");
        let quality_center = quality_header.rect().center();
        harness.drag_at(quality_center);
        harness.run();
        harness.drop_at(quality_center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Quality, SortDir::Desc)),
            "first 线路质量 click sorts fastest-first"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![0, 2, 1]);
        // 国家/地区: the arrow moves there alone (德国 < 日本 < 美国）.
        let country_header = harness.get_by_label("国家/地区");
        let country_center = country_header.rect().center();
        harness.drag_at(country_center);
        harness.run();
        harness.drop_at(country_center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Country, SortDir::Asc)),
            "switching to the country header starts A-Z"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![2, 0, 1]);
        harness.get_by_label("国家/地区 ▲");
        assert!(
            harness.query_by_label("当前人数 ▲").is_none(),
            "the sessions arrow must clear when another column sorts"
        );
        assert!(
            harness.query_by_label("当前人数 ▼").is_none(),
            "the sessions arrow must clear when another column sorts"
        );
        assert!(
            harness.query_by_label("线路质量 ▲").is_none(),
            "the quality arrow must clear when another column sorts"
        );
        assert!(
            harness.query_by_label("线路质量 ▼").is_none(),
            "the quality arrow must clear when another column sorts"
        );
    }

    /// Clicking the 延迟/状态 header sorts available nodes by ms
    /// ascending (unprobed middle, failed last) on the first click
    /// and reverses on the second. The header sits past the right
    /// edge at 560 px with the default column widths, so the test
    /// narrows the resizable columns to bring it into view. Needs
    /// a graphics adapter.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn latency_header_click_toggles_sort() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_stats("a.opengw.net", "日本", 10, 500, 10),
                    node_stats("b.opengw.net", "日本", 10, 100, 5),
                    node_stats("c.opengw.net", "日本", 10, 200, 20),
                ];
                app.col_widths = [50, 60, 40, 50, 40, 80, 50];
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state().sort, None);
        // a: 120 ms, b: unprobed, c: failed.
        harness
            .state_mut()
            .probe_ms
            .insert("a.opengw.net".to_string(), 120);
        harness
            .state_mut()
            .probes
            .insert("a.opengw.net".to_string(), "120 ms".to_string());
        harness
            .state_mut()
            .probes
            .insert("c.opengw.net".to_string(), "失败".to_string());
        let header = harness.get_by_label("延迟/状态");
        let center = header.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Latency, SortDir::Asc)),
            "first latency click: available by ms, unprobed middle, failed last"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![0, 1, 2]);
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::Latency, SortDir::Desc)),
            "second latency click reverses the whole order"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![2, 1, 0]);
    }

    /// Clicking the 人均带宽 header sorts by per-capita bandwidth
    /// (first click = highest first, second click = reversed), and
    /// the arrow moves with it. The header sits past the right edge
    /// at 560 px with the default column widths, so the test narrows
    /// the resizable columns to bring it into view. Needs a graphics
    /// adapter.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn per_capita_header_click_toggles_sort() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    // a: 572/47 = 12.2, b: 100/5 = 20.0,
                    // c: 200/1 = 200.0.
                    node_stats("a.opengw.net", "日本", 47, 572, 3),
                    node_stats("b.opengw.net", "日本", 5, 100, 5),
                    node_stats("c.opengw.net", "日本", 1, 200, 20),
                ];
                app.col_widths = [50, 60, 40, 50, 40, 80, 50];
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state().sort, None);
        let header = harness.get_by_label("人均带宽");
        let center = header.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::PerCapita, SortDir::Desc)),
            "first per-capita click: highest first"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![2, 1, 0]);
        harness.get_by_label("人均带宽 ▼");
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(
            harness.state().sort,
            Some((SortCol::PerCapita, SortDir::Asc)),
            "second per-capita click reverses the whole order"
        );
        assert_eq!(harness.state_mut().display_indices(), vec![0, 1, 2]);
    }

    /// Enter connects the selected node and Ctrl+R probes it (the
    /// same flows as the buttons). The harness has no tokio runtime,
    /// so the background task is skipped and the busy flag stays set
    /// — that is what is asserted. Needs a graphics adapter.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn keyboard_shortcuts_connect_and_probe() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本")];
                app
            });
        harness.run_steps(10);
        // No selection yet: Enter must do nothing.
        harness.key_press(egui::Key::Enter);
        harness.run_steps(3);
        assert!(harness.state().busy.is_none());
        // Select the row, then Enter: connect starts.
        let cell = harness.get_by_label("日本");
        let center = cell.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert_eq!(harness.state().selected, Some(0));
        harness.key_press(egui::Key::Enter);
        // run_steps, not run(): the spinner shown while busy requests
        // a repaint every frame, so run() never settles.
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::Connecting)),
            "Enter must start a connect, busy={:?}",
            harness.state().busy
        );
        // Reset the busy flag (the harness never clears it — no
        // runtime, no background task), then Ctrl+R: probe starts.
        harness.state_mut().busy = None;
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::R);
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::Probing)),
            "Ctrl+R must start a probe, busy={:?}",
            harness.state().busy
        );
    }

    /// ↑/↓ move the selection in display order, stop at the ends,
    /// and scroll the newly selected row into view; Enter/Ctrl+R
    /// still act on the arrow-selected row, and moving works while
    /// busy. Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn arrow_keys_move_selection_and_follow_scroll() {
        use egui_kittest::Harness;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                // Ten rows overflow the ~120 px list at 560x420
                // (about three rows fit), so walking to the bottom
                // must scroll.
                app.nodes = (0..10)
                    .map(|i| node_in(&format!("n{i}.opengw.net"), "日本"))
                    .collect();
                app
            });
        harness.run_steps(10);
        assert_eq!(harness.state().selected, None);
        // ↓ with no selection picks the first row; ↑ at the top
        // stays put.
        harness.key_press(egui::Key::ArrowDown);
        harness.run();
        assert_eq!(harness.state().selected, Some(0));
        harness.key_press(egui::Key::ArrowUp);
        harness.run();
        assert_eq!(
            harness.state().selected,
            Some(0),
            "↑ at the top must not move"
        );
        // ↓ twice, ↑ once.
        harness.key_press(egui::Key::ArrowDown);
        harness.run();
        harness.key_press(egui::Key::ArrowDown);
        harness.run();
        assert_eq!(harness.state().selected, Some(2));
        harness.key_press(egui::Key::ArrowUp);
        harness.run();
        assert_eq!(harness.state().selected, Some(1));
        // Walk to the bottom: the list must scroll and the last row
        // must end up on screen.
        for _ in 0..8 {
            harness.key_press(egui::Key::ArrowDown);
            harness.run();
        }
        assert_eq!(harness.state().selected, Some(9));
        assert!(
            harness.state().node_list_scroll_y > 0.0,
            "the list must have scrolled, scroll_y={}",
            harness.state().node_list_scroll_y
        );
        assert!(
            harness.state().selected_row_in_view,
            "the selected last row must be in view after arrowing down"
        );
        // ↓ at the bottom stays put.
        harness.key_press(egui::Key::ArrowDown);
        harness.run();
        assert_eq!(harness.state().selected, Some(9));
        // Moving the selection still works while busy (it starts
        // nothing). run_steps, not run(): the busy spinner requests
        // a repaint every frame, so run() never settles.
        harness.state_mut().busy = Some(Busy::Fetching);
        harness.key_press(egui::Key::ArrowUp);
        harness.run_steps(5);
        assert_eq!(
            harness.state().selected,
            Some(8),
            "↑ must move the selection even while busy"
        );
        harness.state_mut().busy = None;
        // Enter still connects the arrow-selected row, Ctrl+R still
        // probes it (same busy-flag proof as the shortcut test).
        harness.key_press(egui::Key::Enter);
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::Connecting)),
            "Enter must start a connect on the arrow-selected row, busy={:?}",
            harness.state().busy
        );
        harness.state_mut().busy = None;
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::R);
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::Probing)),
            "Ctrl+R must start a probe on the arrow-selected row, busy={:?}",
            harness.state().busy
        );
    }

    /// Clicking 探测全部 starts a sweep (busy = ProbingAll, first
    /// row 探测中…), one driven result advances the progress, Enter
    /// is blocked while sweeping but ↑/↓ still move the selection,
    /// and 停止 sets the stop flag so the Done event ends it with
    /// the stopped summary. The harness has no tokio runtime, so
    /// the sweep's events are driven by hand through apply_event
    /// (same approach as the shortcut test's busy-flag proof).
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn probe_all_button_starts_sweep_and_stop_halts_it() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(560.0, 420.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        assert!(harness.state().busy.is_none());
        let btn = harness.get_by_label("探测全部");
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        // run_steps, not run(): the spinner shown while busy
        // requests a repaint every frame, so run() never settles.
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::ProbingAll)),
            "clicking 探测全部 must start a sweep, busy={:?}",
            harness.state().busy
        );
        assert!(
            harness.state().status.contains("0/3"),
            "status must show the sweep progress: {}",
            harness.state().status
        );
        assert_eq!(
            harness.state().probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("探测中…"),
            "the first row shows 探测中…"
        );
        // The same button is now 停止.
        let stop_btn = harness.get_by_label("停止");
        assert!(
            stop_btn.rect().width() > 0.0,
            "the button must read 停止 while sweeping"
        );
        // Drive one result through by hand: the row takes the
        // latency and the progress advances.
        harness.state_mut().apply_event(GuiEvent::ProbeAllResult {
            host: "a.opengw.net".to_string(),
            result: Ok((Ipv4Addr::new(10, 0, 0, 2), Duration::from_millis(95))),
            done: 1,
            total: 3,
        });
        harness.run_steps(3);
        assert_eq!(
            harness.state().probes.get("a.opengw.net").map(|s| s.as_str()),
            Some("95 ms")
        );
        assert!(
            harness.state().status.contains("1/3"),
            "status must advance: {}",
            harness.state().status
        );
        // Enter is blocked while sweeping (it would start a
        // connect); arrow keys still move the selection (they
        // start nothing).
        harness.key_press(egui::Key::Enter);
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::ProbingAll)),
            "Enter must not start a connect mid-sweep"
        );
        harness.key_press(egui::Key::ArrowDown);
        harness.run_steps(3);
        assert_eq!(
            harness.state().selected,
            Some(0),
            "↓ must still move the selection while sweeping"
        );
        // Click 停止: the flag is set (the sweep stops after the
        // node in flight); the Done event clears the busy flag
        // and writes the stopped summary.
        let stop = harness.get_by_label("停止");
        let center = stop.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(
            harness.state().probe_all_stop.load(Ordering::Relaxed),
            "clicking 停止 must set the stop flag"
        );
        harness.state_mut().apply_event(GuiEvent::ProbeAllDone {
            total: 3,
            ok: 1,
            failed: 0,
            stopped: true,
            proxy_down: false,
        });
        harness.run_steps(3);
        assert!(harness.state().busy.is_none());
        assert!(
            harness.state().status.contains("已停止"),
            "status must carry the stopped summary: {}",
            harness.state().status
        );
        assert!(
            harness.state().status.contains("已测 1/3"),
            "status: {}",
            harness.state().status
        );
    }

    /// Click a button by label and return the text it copied (if
    /// any). The press runs via run(); the release is queued as a
    /// single event and stepped once, so `harness.output()` is
    /// exactly the frame where the click fired and the CopyText
    /// command lives. (`drop_at` would queue a second PointerGone
    /// event, and a plain run() would settle past the copy frame.)
    fn click_button_label_copied_text(
        harness: &mut egui_kittest::Harness<'_, GuiApp>,
        label: &str,
    ) -> Option<String> {
        use egui_kittest::kittest::Queryable;
        let btn = harness.get_by_label(label);
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::PointerButton {
            pos: center,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        });
        harness.step();
        copied_text(harness)
    }

    /// The CopyText command of the last frame, if the app copied
    /// anything in it.
    fn copied_text(harness: &egui_kittest::Harness<'_, GuiApp>) -> Option<String> {
        harness
            .output()
            .platform_output
            .commands
            .iter()
            .find_map(|c| match c {
                egui::OutputCommand::CopyText(t) => Some(t.clone()),
                _ => None,
            })
    }

    /// Ctrl+click a row by its cell label in a kittest harness
    /// (mirrors `shift_click_row_label`: egui only tracks modifiers
    /// from ModifiersChanged events, so queue one before the press
    /// and again before the release).
    fn ctrl_click_row_label(
        harness: &mut egui_kittest::Harness<'_, GuiApp>,
        label: &str,
    ) {
        use egui_kittest::kittest::Queryable;
        let ctrl = egui::Modifiers {
            ctrl: true,
            ..Default::default()
        };
        let cell = harness.get_by_label(label);
        let center = cell.rect().center();
        harness.event(egui::Event::ModifiersChanged(ctrl));
        harness.drag_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(ctrl));
        harness.drop_at(center);
        harness.run();
        harness.event(egui::Event::ModifiersChanged(
            egui::Modifiers::default(),
        ));
        harness.run();
    }

    /// 导出选中 copies the selected rows in display order — one
    /// `host:port` line per node — to the clipboard. Clicking c
    /// first and then Ctrl+clicking a selects {a, c} in that click
    /// order; the copied text must still be display order (a, c),
    /// with each node's own port. Needs a graphics adapter, like
    /// the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn export_button_copies_selected_rows_in_display_order() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                let mut a = node_in("a.opengw.net", "日本");
                a.port = Some(443);
                let mut b = node_in("b.opengw.net", "美国");
                b.port = Some(992);
                let mut c = node_in("c.opengw.net", "德国");
                c.port = Some(995);
                app.nodes = vec![a, b, c];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "德国");
        ctrl_click_row_label(&mut harness, "日本");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 2]),
            "c then Ctrl+a must select rows 0 and 2"
        );
        let copied =
            click_button_label_copied_text(&mut harness, "导出选中 (2)");
        assert_eq!(
            copied.as_deref(),
            Some("a.opengw.net:443\t日本\tNTT\t1\t50\t\nc.opengw.net:995\t德国\tNTT\t1\t50\t"),
            "export must list the selection in display order, each with its own port and metadata columns"
        );
        assert_eq!(
            harness.state().status,
            "已导出 2 个节点到剪贴板。",
            "status must confirm the export: {}",
            harness.state().status
        );
    }

    /// With nothing selected the export button is disabled: clicking
    /// it copies nothing and changes no status. Needs a graphics
    /// adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn export_button_disabled_with_no_selection() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本")];
                app
            });
        harness.run_steps(10);
        assert!(harness.state().selected_set.is_empty());
        let _btn = harness.get_by_label("导出选中");
        let copied = click_button_label_copied_text(&mut harness, "导出选中");
        assert_eq!(copied, None, "a disabled export button must copy nothing");
        assert_eq!(harness.state().status, "未连接");
    }

    /// Ctrl+C exports the selection exactly like the 导出选中
    /// button. Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn ctrl_c_exports_selection() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        shift_click_row_label(&mut harness, "美国");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1]),
            "Shift+click must select the range"
        );
        harness.event(egui::Event::Copy);
        harness.step();
        assert_eq!(
            copied_text(&harness).as_deref(),
            Some("a.opengw.net:992\t日本\tNTT\t1\t50\t\nb.opengw.net:992\t美国\tNTT\t1\t50\t"),
            "Ctrl+C must copy the selection in display order, with metadata columns"
        );
        assert_eq!(harness.state().status, "已导出 2 个节点到剪贴板。");
    }

    /// Ctrl+V imports the pasted node list: rows are appended and
    /// the status reports the counts. Needs a graphics adapter,
    /// like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn ctrl_v_imports_from_clipboard() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本")];
                app
            });
        harness.run_steps(10);
        harness.event(egui::Event::Paste(
            "b.opengw.net:992\nc.opengw.net".to_string(),
        ));
        harness.step();
        assert_eq!(harness.state().nodes.len(), 3);
        assert_eq!(harness.state().nodes[1].host, "b.opengw.net");
        assert_eq!(harness.state().nodes[1].port, Some(992));
        assert_eq!(harness.state().nodes[2].host, "c.opengw.net");
        assert_eq!(harness.state().nodes[2].port, None);
        assert_eq!(
            harness.state().status,
            "已导入 2 个节点（跳过重复 0 个，格式不对 0 个）。",
            "status must report the import counts: {}",
            harness.state().status
        );
        // The import cached the list next to the test exe; clean up.
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// With a text field focused, Ctrl+C stays the field's own copy:
    /// no export runs, nothing is copied, the status does not move.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn ctrl_c_ignored_when_text_field_focused() {
        use egui_kittest::{kittest::Queryable, Harness};
        // Short window: the node list height scales with the panel
        // (`panel_h - 250`, min 120), so a TALL window pushes
        // 高级设置 further down; a short one brings the manual-add
        // field into view.
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 500.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本")];
                app
            });
        harness.run_steps(10);
        // Select a row first, so an export would have something to
        // copy; then focus the manual-add field (first text input in
        // tree order; 高级设置 starts open in the render-test
        // constructor). The order matters: clicking a row steals the
        // text field's focus, so the field is focused last.
        click_row_label(&mut harness, "日本");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "the row must be selected before the field takes focus"
        );
        // The manual-add field sits below the fold at first (the
        // node list takes most of the window). Scroll the outer area
        // down with the wheel, then re-read the field's rect: the
        // accesskit rect follows the scroll offset.
        harness.event(egui::Event::PointerMoved(egui::pos2(400.0, 300.0)));
        harness.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Line,
            delta: egui::vec2(0.0, -5.0),
            modifiers: egui::Modifiers::default(),
            phase: egui::TouchPhase::Move,
        });
        harness.run_steps(5);
        let field = harness
            .query_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("a text input must exist");
        let center = field.rect().center();
        assert!(
            center.y < 500.0,
            "the field must have scrolled into view, rect={:?}",
            field.rect()
        );
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert!(
            harness.ctx.text_edit_focused(),
            "clicking the text field must focus it"
        );
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "focusing the field must not clear the selection"
        );
        harness.event(egui::Event::Copy);
        harness.step();
        assert_eq!(
            copied_text(&harness),
            None,
            "Ctrl+C with a focused text field must not export"
        );
        assert_eq!(harness.state().status, "未连接");
    }

    /// v3.15: Ctrl+A selects every currently displayed node (in
    /// display order), and the selection is the same set the export
    /// path uses — so Ctrl+A then Ctrl+C exports the whole list.
    /// The list is pre-sorted by country here (display order ≠
    /// insertion order: 德国/日本/美国), so the anchor assertion
    /// also proves the anchor lands on the FIRST displayed row,
    /// not the first inserted one. Needs a graphics adapter, like
    /// the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn ctrl_a_selects_all_visible_nodes() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                // Display order: 德国 (c) / 日本 (a) / 美国 (b).
                app.sort = Some((SortCol::Country, SortDir::Asc));
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "one row must be selected before Ctrl+A"
        );
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run_steps(5);
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1, 2]),
            "Ctrl+A must select every displayed node, got: {:?}",
            harness.state().selected_set
        );
        assert_eq!(
            harness.state().selected,
            Some(2),
            "the anchor must be the first DISPLAYED row (德国, node 2)"
        );
        // The selection is the export set: Ctrl+C now copies all
        // three rows, in display order.
        harness.event(egui::Event::Copy);
        harness.step();
        assert_eq!(
            copied_text(&harness).as_deref(),
            Some("c.opengw.net:992\t德国\tNTT\t1\t50\t\na.opengw.net:992\t日本\tNTT\t1\t50\t\nb.opengw.net:992\t美国\tNTT\t1\t50\t"),
            "Ctrl+A then Ctrl+C must export the whole list in display order"
        );
    }

    /// v3.15: with a text field focused, Ctrl+A stays the field's
    /// own select-all-text — the node selection must not move.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn ctrl_a_ignored_when_text_field_focused() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 500.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本")];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "the row must be selected before the field takes focus"
        );
        // Same scroll-into-view dance as
        // `ctrl_c_ignored_when_text_field_focused`: the manual-add
        // field starts below the fold; scroll the outer area down,
        // then click the first text input in tree order.
        harness.event(egui::Event::PointerMoved(egui::pos2(400.0, 300.0)));
        harness.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Line,
            delta: egui::vec2(0.0, -5.0),
            modifiers: egui::Modifiers::default(),
            phase: egui::TouchPhase::Move,
        });
        harness.run_steps(5);
        let field = harness
            .query_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("a text input must exist");
        let center = field.rect().center();
        assert!(
            center.y < 500.0,
            "the field must have scrolled into view, rect={:?}",
            field.rect()
        );
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert!(
            harness.ctx.text_edit_focused(),
            "clicking the text field must focus it"
        );
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run_steps(5);
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "Ctrl+A with a focused text field must not touch the node selection"
        );
        assert_eq!(harness.state().status, "未连接");
    }

    /// v3.11 refresh flow end to end: delete two nodes (the
    /// blocklist grows), click 刷新节点, and the deleted nodes come
    /// back with the fresh list — the blocklist is cleared when the
    /// refresh starts. Also asserts the two removed features stay
    /// gone: no "恢复已删除" button, and no "清空屏蔽列表" item in
    /// the File menu (the four import/export items are still there).
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn refresh_clears_blocklist_and_restores_deleted_nodes() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Delete a and b: only c is left, the blocklist holds 2.
        click_row_label(&mut harness, "日本");
        ctrl_click_row_label(&mut harness, "美国");
        click_button_label(&mut harness, "删除选中 (2)");
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().nodes[0].host, "c.opengw.net");
        assert_eq!(harness.state().blocked_hosts.len(), 2);
        assert!(harness
            .query_by_label_contains("恢复已删除")
            .is_none());
        // Refresh: the blocklist is cleared synchronously when the
        // refresh starts (before any network), the busy flag is set.
        // run_steps, not run(): the fetch spinner requests a repaint
        // every frame, so run() never settles.
        let btn = harness.get_by_label("刷新节点");
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(
            harness.state().blocked_hosts.is_empty(),
            "refresh must clear the blocklist at once, got: {:?}",
            harness.state().blocked_hosts
        );
        assert!(
            matches!(harness.state().busy, Some(Busy::Fetching)),
            "refresh must set the fetching flag, busy={:?}",
            harness.state().busy
        );
        assert_eq!(harness.state().status, "正在拉取节点列表…");
        // Drive the fetch result through by hand (no runtime in the
        // harness): the full list comes back, a and b included.
        harness.state_mut().apply_event(GuiEvent::Nodes(
            vpngate::NodeListUpdate {
                nodes: vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ],
                source: vpngate::NodeListSource::Api,
                cache_age_secs: None,
                api_error: None,
                web_error: None,
            },
        ));
        harness.run_steps(3);
        assert_eq!(harness.state().nodes.len(), 3);
        assert_eq!(harness.state().nodes[0].host, "a.opengw.net");
        assert_eq!(harness.state().nodes[1].host, "b.opengw.net");
        assert!(harness.state().blocked_hosts.is_empty());
        assert!(
            harness.state().log.iter().any(|l| l
                == "刷新完成（官方 API）：已清空屏蔽 2 个，获取到 3 个。"),
            "log must carry the cleared count and final count, got: {:?}",
            harness.state().log
        );
        // The File menu has the four import/export items and no
        // "清空屏蔽列表" (Leo rejected that fix in favour of the
        // refresh auto-clear). Note the menu items carrying a
        // shortcut show it in their accesskit label.
        click_button_label(&mut harness, "文件");
        assert!(harness.query_by_label("清空屏蔽列表").is_none());
        let _export = harness.get_by_label("导出到剪切板 Ctrl+C");
        let _export_file = harness.get_by_label("导出到config");
        let _import = harness.get_by_label("从剪切板导入 Ctrl+V");
        let _import_file = harness.get_by_label("从文件config导入");
        click_button_label(&mut harness, "文件");
        // The delete + the hand-driven Api result wrote config.toml
        // and nodes_cache.json next to the test exe; clean up.
        if let Some(path) = Config::portable_config_path() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// v3.15 "从API刷新节点": the button sits immediately left of
    /// "刷新节点" on the same row, and clicking it sets the
    /// fetching flag WITHOUT clearing the blocklist (unlike
    /// "刷新节点", which clears first — the API button only filters
    /// by the blocklist, so deleted nodes stay hidden).
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn api_refresh_button_left_of_refresh_and_keeps_blocklist() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Position: same row, API button immediately left of
        // "刷新节点" (right edge a few px left of its left edge).
        let api_btn = harness.get_by_label("从API刷新节点");
        let refresh_btn = harness.get_by_label("刷新节点");
        let api_rect = api_btn.rect();
        let refresh_rect = refresh_btn.rect();
        assert!(
            (api_rect.center().y - refresh_rect.center().y).abs() < 4.0,
            "both buttons must be on the same row, api center y {}, refresh center y {}",
            api_rect.center().y,
            refresh_rect.center().y
        );
        assert!(
            api_rect.right() <= refresh_rect.left() + 1.0,
            "API button must be left of 刷新节点, api right {}, refresh left {}",
            api_rect.right(),
            refresh_rect.left()
        );
        assert!(
            refresh_rect.left() - api_rect.right() < 20.0,
            "the two buttons must be adjacent, gap {}",
            refresh_rect.left() - api_rect.right()
        );
        // Delete a and b: only c is left, the blocklist holds 2.
        click_row_label(&mut harness, "日本");
        ctrl_click_row_label(&mut harness, "美国");
        click_button_label(&mut harness, "删除选中 (2)");
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().blocked_hosts.len(), 2);
        // Click the API button (drag/drop + run_steps: the fetch
        // spinner requests a repaint every frame, so run() never
        // settles — same as the 刷新节点 test above). Re-fetch the
        // button: the row deletes above may have reflowed layout.
        let api_btn = harness.get_by_label("从API刷新节点");
        let center = api_btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(
            harness.state().blocked_hosts.len() == 2,
            "API refresh must NOT clear the blocklist, got: {:?}",
            harness.state().blocked_hosts
        );
        assert!(
            matches!(harness.state().busy, Some(Busy::Fetching)),
            "API refresh must set the fetching flag, busy={:?}",
            harness.state().busy
        );
        assert_eq!(harness.state().status, "正在从官方 API 拉取节点列表…");
    }

    /// v3.15 failure sentence, end to end in the harness: the API
    /// button fails, the log + status carry Leo's exact sentence
    /// with the way and the reason, and the list stays exactly as
    /// it was. A later success through the same button then updates
    /// the list (the blocklist still filters the deleted hosts).
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn api_refresh_failed_shows_sentence_and_keeps_list() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        // Delete a and b first, so "list stays as it was" is a
        // visible claim (only c shows, blocklist holds 2).
        click_row_label(&mut harness, "日本");
        ctrl_click_row_label(&mut harness, "美国");
        click_button_label(&mut harness, "删除选中 (2)");
        assert_eq!(harness.state().nodes.len(), 1);
        let api_btn = harness.get_by_label("从API刷新节点");
        let center = api_btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(matches!(harness.state().busy, Some(Busy::Fetching)));
        // Drive the failure through by hand (no runtime in the
        // harness): the list must not move, the sentence must show.
        harness.state_mut().apply_event(GuiEvent::ApiRefreshFailed {
            reason: "官方 API 拉取超时（30 秒内无响应）".to_string(),
        });
        harness.run_steps(3);
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().nodes[0].host, "c.opengw.net");
        assert_eq!(harness.state().blocked_hosts.len(), 2);
        assert!(harness.state().busy.is_none());
        assert!(
            harness
                .state()
                .status
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新"),
            "status must carry Leo's exact sentence, got: {}",
            harness.state().status
        );
        assert!(harness.state().status.contains("官方 API 拉取超时"));
        assert!(
            harness.state().log.iter().any(|l| l
                .starts_with("当前方式刷新节点失败，请用另一种方式刷新")),
            "log must carry Leo's exact sentence, got: {:?}",
            harness.state().log
        );
        // The button works again after the failure: drive a success
        // through by hand — the full list comes back, a and b still
        // filtered by the blocklist.
        let api_btn = harness.get_by_label("从API刷新节点");
        let center = api_btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(matches!(harness.state().busy, Some(Busy::Fetching)));
        harness.state_mut().apply_event(GuiEvent::Nodes(
            vpngate::NodeListUpdate {
                nodes: vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ],
                source: vpngate::NodeListSource::Api,
                cache_age_secs: None,
                api_error: None,
                web_error: None,
            },
        ));
        harness.run_steps(3);
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().nodes[0].host, "c.opengw.net");
        assert_eq!(harness.state().blocked_hosts.len(), 2);
        // The hand-driven Api result wrote nodes_cache.json next
        // to the test exe; clean up (config.toml was written by
        // the delete above).
        if let Some(path) = Config::portable_config_path() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// v3.12: export → delete → import restores the four metadata
    /// columns (country, operator, users, quality) — the round
    /// trip Leo's screenshot showed losing (v3.11 exported
    /// host:port only, and stamped "导入" into the two text
    /// columns). Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn export_import_round_trip_keeps_four_columns() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut a = node_in("vpn547433109.opengw.net", "日本");
        a.port = Some(995);
        a.isp = "IIJ".to_string();
        a.sessions = 47;
        a.speed_mbps = 572;
        let mut b = node_in("a.opengw.net", "美国");
        b.port = Some(443);
        b.isp = "NTT".to_string();
        b.sessions = 3;
        b.speed_mbps = 120;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![a, b];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        shift_click_row_label(&mut harness, "美国");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0, 1]),
            "Shift+click must select the range"
        );
        // Export, then delete the two rows, then paste the exported
        // text back: the four columns must come back with them.
        let copied =
            click_button_label_copied_text(&mut harness, "导出选中 (2)");
        assert_eq!(
            copied.as_deref(),
            Some("vpn547433109.opengw.net:995\t日本\tIIJ\t47\t572\t\na.opengw.net:443\t美国\tNTT\t3\t120\t"),
            "export must carry the four metadata columns"
        );
        click_button_label(&mut harness, "删除选中 (2)");
        assert_eq!(harness.state().nodes.len(), 0);
        harness.event(egui::Event::Paste(
            copied.expect("export must have copied text"),
        ));
        harness.step();
        assert_eq!(harness.state().nodes.len(), 2);
        let first = &harness.state().nodes[0];
        assert_eq!(first.host, "vpn547433109.opengw.net");
        assert_eq!(first.port, Some(995));
        assert_eq!(first.country, "日本");
        assert_eq!(first.isp, "IIJ");
        assert_eq!(first.sessions, 47);
        assert_eq!(first.speed_mbps, 572);
        let second = &harness.state().nodes[1];
        assert_eq!(second.host, "a.opengw.net");
        assert_eq!(second.country, "美国");
        assert_eq!(second.sessions, 3);
        assert_eq!(second.speed_mbps, 120);
        assert_eq!(
            harness.state().status,
            "已导入 2 个节点（跳过重复 0 个，格式不对 0 个）。"
        );
        // The delete + the import wrote config.toml and
        // nodes_cache.json next to the test exe; clean up.
        if let Some(path) = Config::portable_config_path() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// v3.16: export → delete → import restores the probed
    /// latency too — the copied text carries a sixth column, and
    /// after the paste the latency column shows it again.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn export_import_round_trip_keeps_probe_ms() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut a = node_in("vpn547433109.opengw.net", "日本");
        a.port = Some(995);
        a.isp = "IIJ".to_string();
        a.sessions = 47;
        a.speed_mbps = 572;
        let mut b = node_in("a.opengw.net", "美国");
        b.port = Some(443);
        b.isp = "NTT".to_string();
        b.sessions = 3;
        b.speed_mbps = 120;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.probe_ms
                    .insert("vpn547433109.opengw.net".to_string(), 42);
                app.probes.insert(
                    "vpn547433109.opengw.net".to_string(),
                    "42 ms".to_string(),
                );
                app.nodes = vec![a, b];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        shift_click_row_label(&mut harness, "美国");
        let copied =
            click_button_label_copied_text(&mut harness, "导出选中 (2)");
        assert_eq!(
            copied.as_deref(),
            Some("vpn547433109.opengw.net:995\t日本\tIIJ\t47\t572\t42\na.opengw.net:443\t美国\tNTT\t3\t120\t"),
            "export must carry the probed latency as a sixth column (empty when unprobed)"
        );
        click_button_label(&mut harness, "删除选中 (2)");
        assert_eq!(harness.state().nodes.len(), 0);
        harness.event(egui::Event::Paste(
            copied.expect("export must have copied text"),
        ));
        harness.step();
        assert_eq!(harness.state().nodes.len(), 2);
        assert_eq!(
            harness.state().probe_ms.get("vpn547433109.opengw.net"),
            Some(&42)
        );
        assert_eq!(
            harness
                .state()
                .probes
                .get("vpn547433109.opengw.net")
                .map(|s| s.as_str()),
            Some("42 ms")
        );
        assert_eq!(
            harness.state().probe_ms.get("a.opengw.net"),
            None,
            "the unprobed node stays unprobed after the round trip"
        );
        if let Some(path) = Config::portable_config_path() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// v3.12: an imported node the fresh API list lacks survives a
    /// refresh, appended at the end with its metadata intact.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn refresh_keeps_imported_nodes() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut imported = node_in("m.opengw.net", "德国");
        imported.source = "import".to_string();
        imported.port = Some(995);
        imported.isp = "DT".to_string();
        imported.sessions = 9;
        imported.speed_mbps = 300;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本"), imported];
                app
            });
        harness.run_steps(10);
        let btn = harness.get_by_label("刷新节点");
        let center = btn.rect().center();
        harness.drag_at(center);
        harness.run_steps(3);
        harness.drop_at(center);
        harness.run_steps(3);
        assert!(
            matches!(harness.state().busy, Some(Busy::Fetching)),
            "refresh must set the fetching flag, busy={:?}",
            harness.state().busy
        );
        // Drive the fetch result through by hand (no runtime in the
        // harness): the fresh list lacks the imported node.
        harness.state_mut().apply_event(GuiEvent::Nodes(
            vpngate::NodeListUpdate {
                nodes: vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                ],
                source: vpngate::NodeListSource::Api,
                cache_age_secs: None,
                api_error: None,
                web_error: None,
            },
        ));
        harness.run_steps(3);
        assert_eq!(harness.state().nodes.len(), 3);
        assert_eq!(harness.state().nodes[2].host, "m.opengw.net");
        assert_eq!(harness.state().nodes[2].source, "import");
        assert_eq!(harness.state().nodes[2].country, "德国");
        assert_eq!(harness.state().nodes[2].isp, "DT");
        assert_eq!(harness.state().nodes[2].sessions, 9);
        assert_eq!(harness.state().nodes[2].speed_mbps, 300);
        assert!(
            harness
                .state()
                .log
                .iter()
                .any(|l| l
                    == "刷新完成（官方 API）：已清空屏蔽 0 个，获取到 3 个（含手动/导入保留 1 个）。"),
            "log must name the retained manual/imported node, got: {:?}",
            harness.state().log
        );
        if let Some(path) = Config::portable_config_path() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(cache) = vpngate::cache_path() {
            let _ = std::fs::remove_file(&cache);
        }
    }

    /// v3.12: pressing Del with a row selected deletes it through
    /// the same path as the 删除选中 button — the row goes, the
    /// blocklist grows, and the status wording matches the button.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn del_key_deletes_selected_row() {
        use egui_kittest::{kittest::Queryable, Harness};
        let _guard = PORTABLE_CONFIG_LOCK.lock().unwrap();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                    node_in("c.opengw.net", "德国"),
                ];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        harness.key_press(egui::Key::Delete);
        harness.run_steps(3);
        assert_eq!(harness.state().nodes.len(), 2);
        assert_eq!(harness.state().nodes[0].host, "b.opengw.net");
        assert_eq!(harness.state().blocked_hosts.len(), 1);
        assert!(harness
            .state()
            .blocked_hosts
            .contains("a.opengw.net"));
        assert_eq!(
            harness.state().status,
            "已删除 1 个节点（本次会话里隐藏，刷新后会带回来）。"
        );
        if let Some(path) = Config::portable_config_path() {
            let _ = std::fs::remove_file(&path);
        }
    }

    /// v3.12: with a text field focused, Del belongs to the field
    /// (deletes a character) and must not delete the selected row
    /// — same focus guard as Ctrl+C / Enter / Ctrl+R.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn del_key_ignored_when_text_field_focused() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 500.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![node_in("a.opengw.net", "日本")];
                app
            });
        harness.run_steps(10);
        // Select a row first, then focus the manual-add field (first
        // text input in tree order). The order matters: clicking a
        // row steals the text field's focus, so the field is
        // focused last. Same scroll-into-view dance as the Ctrl+C
        // focus test.
        click_row_label(&mut harness, "日本");
        assert_eq!(
            harness.state().selected_set,
            BTreeSet::from([0]),
            "the row must be selected before the field takes focus"
        );
        harness.event(egui::Event::PointerMoved(egui::pos2(400.0, 300.0)));
        harness.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Line,
            delta: egui::vec2(0.0, -5.0),
            modifiers: egui::Modifiers::default(),
            phase: egui::TouchPhase::Move,
        });
        harness.run_steps(5);
        let field = harness
            .query_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("a text input must exist");
        let center = field.rect().center();
        assert!(
            center.y < 500.0,
            "the field must have scrolled into view, rect={:?}",
            field.rect()
        );
        harness.drag_at(center);
        harness.run();
        harness.drop_at(center);
        harness.run();
        assert!(
            harness.ctx.text_edit_focused(),
            "clicking the text field must focus it"
        );
        harness.key_press(egui::Key::Delete);
        harness.run_steps(3);
        assert_eq!(
            harness.state().nodes.len(),
            1,
            "Del with a focused text field must not delete the row"
        );
        assert!(
            harness.state().blocked_hosts.is_empty(),
            "the blocklist must stay empty"
        );
    }

    /// v3.12: Del while a job is running (probe/connect/refresh/
    /// probe-all) deletes nothing — same busy guard as the button.
    /// Needs a graphics adapter, like the render test.
    #[test]
    #[ignore = "drives the UI with kittest; needs a graphics adapter"]
    fn del_key_ignored_while_busy() {
        use egui_kittest::{kittest::Queryable, Harness};
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_eframe(|cc| {
                let mut app = GuiApp::for_render_tests(cc);
                app.nodes = vec![
                    node_in("a.opengw.net", "日本"),
                    node_in("b.opengw.net", "美国"),
                ];
                app
            });
        harness.run_steps(10);
        click_row_label(&mut harness, "日本");
        harness.state_mut().busy = Some(Busy::Probing);
        harness.key_press(egui::Key::Delete);
        harness.run_steps(3);
        assert_eq!(
            harness.state().nodes.len(),
            2,
            "Del while busy must not delete anything"
        );
        assert!(harness.state().blocked_hosts.is_empty());
        harness.state_mut().busy = None;
        // The same keypress now works, once the job is over.
        harness.key_press(egui::Key::Delete);
        harness.run_steps(3);
        assert_eq!(harness.state().nodes.len(), 1);
        assert_eq!(harness.state().blocked_hosts.len(), 1);
    }

    /// The ∞ mark (U+221E) must render as a glyph, not a missing-glyph
    /// box, in both themes, at the 17 pt size the status column uses.
    /// The PNGs are the proof — check them, don't trust this test
    /// alone (it only asserts the render pipeline ran).
    #[test]
    #[ignore = "renders PNGs for review; needs a graphics adapter"]
    fn render_infinity_glyph() {
        use egui_kittest::Harness;
        struct GlyphApp;
        impl eframe::App for GlyphApp {
            fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("∞")
                            .size(17.0)
                            .color(infinity_accent(ui.visuals().dark_mode)),
                    );
                    ui.label(egui::RichText::new("∞ 已连接 public-vpn-192").size(15.0));
                    ui.label("∞ ∞ ∞ — 17 pt / 15 pt: must be the infinity glyph, not a box.");
                });
            }
        }
        for (theme, name) in [(egui::Theme::Dark, "dark"), (egui::Theme::Light, "light")] {
            let mut harness = Harness::builder()
                .with_size(egui::vec2(320.0, 160.0))
                .with_theme(theme)
                .build_eframe(|cc| {
                    GuiApp::setup_visuals(cc);
                    GlyphApp
                });
            harness.run_steps(10);
            let path = std::env::temp_dir().join(format!("ui-review-infinity-{name}.png"));
            harness
                .render()
                .expect("needs a graphics adapter")
                .save(&path)
                .unwrap();
            eprintln!("{}", path.display());
        }
    }
}
