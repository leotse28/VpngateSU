//! VPNGate node list.
//!
//! Sources:
//! * Official API `https://www.vpngate.net/api/iphone/` — CSV with columns
//!   HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,
//!   Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,
//!   OpenVPN_ConfigData_Base64. It does **not** carry the MS-SSTP port.
//! * Bundled `nodes.json` — 28 curated nodes decoded from the earlier
//!   Cloudflare Worker config, each with a **known SSTP host:port** and
//!   backup nodes. This is the only reliable SSTP-port source we have.
//!
//! `list` therefore shows API nodes merged with the curated table: a node
//! whose hostname appears in `nodes.json` gets its known SSTP port; every
//! other API node is shown with `sstp_port: ?` and can only be connected
//! by manual `host:port` entry or by `probe` trying candidate ports
//! (443, 992, 995).

use crate::net::{https_get, Connector};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const API_URL: &str = "https://www.vpngate.net/api/iphone/";

/// Public relay list page, used as the fallback when the API is
/// unreachable (the page is plain HTML, no login, no JS needed).
pub const WEB_URL: &str = "https://www.vpngate.net/cn/";

/// Candidate SSTP ports tried by `probe` when no port is given.
pub const CANDIDATE_SSTP_PORTS: &[u16] = &[443, 992, 995];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub country: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub isp: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub score: u64,
    #[serde(default)]
    pub ping_ms: u64,
    #[serde(default)]
    pub speed_mbps: u64,
    #[serde(default)]
    pub sessions: u64,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub backups: Vec<String>,
    /// Where the SSTP port came from: "curated" | "manual" | "probed" | "unknown" | "web-scrape".
    #[serde(default)]
    pub port_source: String,
    /// Where this node entry came from: "api" | "web-scrape" | "curated" | "manual".
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CuratedNode {
    host: String,
    port: u16,
    country: String,
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    backups: Vec<String>,
}

/// The bundled curated list (28 nodes, known SSTP ports).
pub fn curated_nodes() -> Vec<Node> {
    let raw = include_str!("../nodes.json");
    let parsed: Vec<CuratedNode> = serde_json::from_str(raw).expect("nodes.json is valid JSON");
    parsed
        .into_iter()
        .map(|c| Node {
            host: c.host,
            port: Some(c.port),
            country: c.country,
            country_code: c.country_code,
            isp: c.isp,
            name: c.name,
            score: 0,
            ping_ms: 0,
            speed_mbps: 0,
            sessions: 0,
            ip: String::new(),
            backups: c.backups,
            port_source: "curated".to_string(),
            source: "curated".to_string(),
        })
        .collect()
}

/// The API's Speed column is bits per second, not Mbps: convert,
/// rounding to the nearest whole Mbps (77,570,260 bps → 78 Mbps).
/// Ping (cols[3]) is already ms and sessions (cols[7]) a plain
/// count, so they pass through unchanged. The scrape path already
/// stores whole Mbps (the page prints "261.83 Mbps"), so after this
/// both sources are the same unit — and the 线路质量 sort compares
/// like for like instead of putting every API node first.
fn bps_to_mbps(bps: u64) -> u64 {
    (bps + 500_000) / 1_000_000
}

pub fn parse_api_csv(text: &str) -> Vec<Node> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 || line.starts_with('#') || line.starts_with('*') || line.trim().is_empty() {
            continue;
        }
        if line.starts_with("HostName,") {
            continue;
        }
        // The OpenVPN config column is base64 without commas, so a plain
        // split is safe for the first 15 columns.
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 14 {
            continue;
        }
        let num = |i: usize| cols.get(i).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        out.push(Node {
            host: cols[0].to_string(),
            port: None,
            country: cols[5].to_string(),
            country_code: cols[6].to_string(),
            // cols[11] is LogType ("2weeks", "0", ...) — not the ISP.
            // Operator is cols[12] (e.g. "SoftBank BB"). The name stays
            // empty, like the web-scrape path: the Chinese display name
            // comes only from the curated table.
            isp: cols[12].to_string(),
            name: String::new(),
            score: num(2),
            ping_ms: num(3),
            speed_mbps: bps_to_mbps(num(4)),
            sessions: num(7),
            ip: cols[1].to_string(),
            backups: Vec::new(),
            port_source: "unknown".to_string(),
            source: "api".to_string(),
        });
    }
    out
}

/// Fetch the live API list and merge known SSTP ports from the curated table.
pub async fn fetch_api_nodes(connector: &Connector) -> Result<Vec<Node>, String> {
    let (status, body) = https_get(connector, API_URL, &[], true).await?;
    if status != 200 {
        return Err(format!("VPNGate API returned HTTP {}", status));
    }
    let text = String::from_utf8_lossy(&body).to_string();
    let mut nodes = parse_api_csv(&text);
    let curated = curated_nodes();
    for n in nodes.iter_mut() {
        if let Some(c) = curated.iter().find(|c| c.host == n.host) {
            n.port = c.port;
            n.backups = c.backups.clone();
            n.port_source = "curated".to_string();
            if n.isp.is_empty() {
                n.isp = c.isp.clone();
            }
        }
    }
    Ok(nodes)
}

/// API-only refresh (v3.15 "从API刷新节点"): the official API
/// (CSV) and nothing else — no web scrape, no cache, no curated
/// list. Success returns the nodes; any failure is an `Err` with
/// the reason, so the caller reports it plainly instead of silently
/// falling back to the scrape. Same 30 s ceiling and same error
/// wording as the API tier of the fallback chain.
pub async fn fetch_api_only(connector: &Connector) -> Result<Vec<Node>, String> {
    fetch_api_only_timeout(connector, API_FETCH_TIMEOUT).await
}

/// Testable core: the timeout is a parameter so tests can use a
/// short one against a black-holed proxy instead of waiting 30 s.
async fn fetch_api_only_timeout(
    connector: &Connector,
    api_timeout: Duration,
) -> Result<Vec<Node>, String> {
    match tokio::time::timeout(api_timeout, fetch_api_nodes(connector)).await {
        Ok(Ok(nodes)) if !nodes.is_empty() => Ok(nodes),
        Ok(Ok(_)) => Err("官方 API 返回了空列表".to_string()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(format!(
            "官方 API 拉取超时（{} 秒内无响应）",
            api_timeout.as_secs()
        )),
    }
}

// ---------------------------------------------------------------------------
// Web scrape fallback: https://www.vpngate.net/cn/
//
// When the official API is unreachable (common on Leo's network), the
// public relay list page is the next best source: it is plain HTML, no
// login, no JS. Each table row is one relay; the DDNS hostname is in
// the second cell and the MS-SSTP cell carries "SSTP 主机名 :
// host[:port]" — an explicit port there is the real SSTP port,
// otherwise 443 (VPNGate's standard SSTP port) is used.
//
// The parser is defensive on purpose: the page layout changes, so it
// scans table rows for `.opengw.net` hostnames instead of relying on
// exact markup, and never panics on unexpected input. Rows from the
// page's other tables (session log, country ranking) contain no
// `.opengw.net` hostname and are skipped automatically.
// ---------------------------------------------------------------------------

/// Strip HTML tags from `s` and collapse runs of whitespace to one space.
fn strip_tags_collapse(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    let mut last_ws = true; // trims leading whitespace
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if in_tag => {}
            _ if c.is_whitespace() => {
                if !last_ws {
                    out.push(' ');
                    last_ws = true;
                }
            }
            _ => {
                out.push(c);
                last_ws = false;
            }
        }
    }
    out.trim_end().to_string()
}

/// Text of the first `<td>...</td>` cell in a row (the country column),
/// tags stripped. Empty when the row has no readable first cell.
fn first_cell_text(row: &str) -> String {
    let Some(td) = row.find("<td") else {
        return String::new();
    };
    let Some(gt) = row[td..].find('>') else {
        return String::new();
    };
    let body = &row[td + gt + 1..];
    let Some(end) = body.find("</td>") else {
        return String::new();
    };
    strip_tags_collapse(&body[..end])
}

/// Inner bodies of the `<td>...</td>` cells in one `<tr ...>...</tr>` row
/// fragment, in order. A cell without a closing `</td>` ends the scan
/// (malformed HTML must not panic the parser). Never panics.
fn row_cell_bodies(row: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = row;
    while let Some(td) = rest.find("<td") {
        let after_td = &rest[td..];
        let Some(gt) = after_td.find('>') else {
            break;
        };
        let body_start = td + gt + 1;
        let Some(end) = rest[body_start..].find("</td>") else {
            break;
        };
        out.push(&rest[body_start..body_start + end]);
        rest = &rest[body_start + end + "</td>".len()..];
    }
    out
}

/// Operator name from a relay-table row: the cell whose stripped text
/// starts with "By " — the "志愿者操作员的名字 (+ 操作员的消息)" column
/// (column 9 of the live page; the same field the official API calls
/// Operator, cols[12]). The name is the text after "By " up to the
/// first ", " (message separator), " E-mail:" or ' "' (greeting quote),
/// or the end of the cell — e.g. "By Daiyuu Nobori, Japan. Academic
/// Use Only." -> "Daiyuu Nobori", "By Japan VPN" + E-mail + greeting
/// -> "Japan VPN". Empty when the row has no such cell, the cell is
/// empty, or nothing remains after trimming. A missing operator must
/// never break host/country parsing; it only leaves the ISP cell blank.
/// Note the page has no separate ISP/telecom column: the only
/// ISP-identifying text is the ISP hostname in parens in the DDNS cell
/// (e.g. `(public-vpn-14-01.vpngate.v4.open.ad.jp)`), present only for
/// some nodes and a hostname, not a name — so the operator column is
/// the source, matching what the API path already shows in the GUI's
/// 运营商 column for the same nodes.
fn row_operator_name(row: &str) -> String {
    for body in row_cell_bodies(row) {
        let text = strip_tags_collapse(body);
        let Some(rest) = text.strip_prefix("By ") else {
            continue;
        };
        let mut name = rest;
        for term in [", ", " E-mail:", " \""] {
            if let Some(i) = name.find(term) {
                name = &name[..i];
            }
        }
        return name.trim().to_string();
    }
    String::new()
}

/// Parse the first number in `s` (digits with optional thousands
/// commas and one decimal point, e.g. "1,234", "261.83") as f64.
/// None when there is no digit at all. Used by the sessions /
/// line-quality cells, whose numbers carry units ("会话", "Mbps",
/// "ms") and thousands separators.
fn first_number(s: &str) -> Option<f64> {
    let mut buf = String::new();
    let mut seen_digit = false;
    let mut seen_dot = false;
    for c in s.chars() {
        match c {
            '0'..='9' => {
                buf.push(c);
                seen_digit = true;
            }
            ',' if seen_digit => {
                // Thousands separator inside a number: skip.
            }
            '.' if seen_digit && !seen_dot => {
                buf.push(c);
                seen_dot = true;
            }
            _ if seen_digit => break,
            _ => {}
        }
    }
    if !seen_digit {
        return None;
    }
    buf.parse::<f64>().ok()
}

/// Sessions count from a relay-table row: the "VPN 会话数" cell
/// (column 3 of the live page) reads like "285 会话 14 天" — the
/// integer before "会话". 0 when the cell is missing, empty or has
/// no number (unknown, not "zero sessions").
fn row_sessions(row: &str) -> u64 {
    let cells = row_cell_bodies(row);
    let Some(cell) = cells.get(2) else {
        return 0;
    };
    let text = strip_tags_collapse(cell);
    let Some(i) = text.find("会话") else {
        return 0;
    };
    first_number(&text[..i])
        .map(|v| v.round() as u64)
        .unwrap_or(0)
}

/// Line quality from a relay-table row: the "线路质量" cell
/// (column 4) reads like "261.83 Mbps Ping: 8 ms ..." — speed is
/// the number before "Mbps" (decimal, rounded to whole Mbps), ping
/// the number after "Ping:" before "ms". (0, 0) when the cell is
/// missing or unparsable; a missing Ping still yields the speed.
fn row_line_quality(row: &str) -> (u64, u64) {
    let cells = row_cell_bodies(row);
    let Some(cell) = cells.get(3) else {
        return (0, 0);
    };
    let text = strip_tags_collapse(cell);
    let speed = text
        .find("Mbps")
        .and_then(|i| first_number(&text[..i]))
        .map(|v| v.round() as u64)
        .unwrap_or(0);
    let ping = text
        .find("Ping:")
        .and_then(|i| first_number(&text[i + "Ping:".len()..]))
        .map(|v| v.round() as u64)
        .unwrap_or(0);
    (speed, ping)
}

/// Is `host` a plausible VPNGate DDNS hostname? It must end in
/// `.opengw.net` with every label alphanumeric-or-hyphen and non-empty.
/// This accepts the `vpn<digits>` names, the `public-vpn-<n>` names
/// (most rows on the page) and the other DDNS names in the same table
/// (e.g. `kanratown`, `laud`); the ISP-hostname column
/// (`*.vpngate.v4.open.ad.jp`, `*.ppp-bb.dion.ne.jp`, ...) does not
/// end in `.opengw.net` and is excluded.
fn valid_ddns_host(host: &str) -> bool {
    let Some(base) = host.strip_suffix(".opengw.net") else {
        return false;
    };
    if base.is_empty() {
        return false;
    }
    base.split('.').all(|label| {
        !label.is_empty()
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Scan one table row for `.opengw.net` hostnames, in row order.
/// Returns `(host, explicit_port)` pairs; the port is `Some` only when
/// the hostname is immediately followed by `:digits` (the MS-SSTP cell
/// writes `host:port`; the DDNS cell writes the bare hostname).
fn extract_hosts(row: &str) -> Vec<(String, Option<u16>)> {
    let mut out = Vec::new();
    let bytes = row.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = row[search_from..].find(".opengw.net") {
        let end = search_from + rel; // index just past the hostname
                                     // Walk back over hostname characters.
        let mut start = end;
        while start > 0 {
            let c = bytes[start - 1] as char;
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                start -= 1;
            } else {
                break;
            }
        }
        let host = &row[start..end + ".opengw.net".len()];
        // Optional ":port" right after the hostname.
        let mut port = None;
        let after = end + ".opengw.net".len();
        if bytes.get(after) == Some(&b':') {
            let mut digits = String::new();
            let mut i = after + 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                digits.push(bytes[i] as char);
                i += 1;
            }
            if let Ok(p) = digits.parse::<u16>() {
                if p > 0 {
                    port = Some(p);
                }
            }
        }
        if valid_ddns_host(host) {
            out.push((host.to_string(), port));
        }
        search_from = end + ".opengw.net".len();
    }
    out
}

/// Parse the VPNGate relay list page into nodes, in table order,
/// deduplicated by hostname. A hostname seen first in the DDNS cell
/// (no port) and again in the MS-SSTP cell with an explicit port keeps
/// its first-seen position but takes the explicit port. The operator
/// name is taken from the row's "志愿者操作员的名字" cell ("By ...")
/// into `isp`, so the GUI's 运营商 column is filled for scraped rows
/// just like for API rows; nodes whose hostname is in the curated table
/// get their known SSTP port instead of the scraped 443 default (and
/// the curated ISP fills in only where the scraped operator is empty).
pub fn parse_web_page(html: &str) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    for row in html.split("<tr") {
        if !row.contains(".opengw.net") {
            continue;
        }
        let country = first_cell_text(row);
        let isp = row_operator_name(row);
        let sessions = row_sessions(row);
        let (speed_mbps, ping_ms) = row_line_quality(row);
        for (host, port) in extract_hosts(row) {
            // "opengw.net" on its own is not a relay (it is the domain
            // itself, not a DDNS hostname under it). `valid_ddns_host`
            // already rejects it, but filter it explicitly so a bare
            // domain can never become a node entry.
            if host == "opengw.net" {
                continue;
            }
            if let Some(existing) = out.iter_mut().find(|n| n.host == host) {
                // Seen again (DDNS cell, then MS-SSTP cell): an explicit
                // port beats the 443 default from the first sighting.
                if let Some(p) = port {
                    if existing.port == Some(443) {
                        existing.port = Some(p);
                        existing.port_source = "web-scrape".to_string();
                    }
                }
                continue;
            }
            out.push(Node {
                host,
                port: Some(port.unwrap_or(443)),
                // An empty country stays empty — the table shows
                // "—" for it. No literal placeholder ("未知" etc.)
                // in a data field: v3.12 removes every such
                // placeholder (import "导入", manual "手动", here).
                country: country.clone(),
                country_code: String::new(),
                isp: isp.clone(),
                name: String::new(),
                score: 0,
                ping_ms,
                speed_mbps,
                sessions,
                ip: String::new(),
                backups: Vec::new(),
                port_source: "web-scrape".to_string(),
                source: "web-scrape".to_string(),
            });
        }
    }
    let curated = curated_nodes();
    for n in out.iter_mut() {
        if let Some(c) = curated.iter().find(|c| c.host == n.host) {
            n.port = c.port;
            n.backups = c.backups.clone();
            n.port_source = "curated".to_string();
            if n.isp.is_empty() {
                n.isp = c.isp.clone();
            }
        }
    }
    out
}

/// Fetch the relay list page and parse it. Errors when the page cannot
/// be fetched or no node parses out of it (the layout may have changed).
pub async fn fetch_web_nodes(connector: &Connector) -> Result<Vec<Node>, String> {
    let (status, body) = https_get(
        connector,
        WEB_URL,
        &[("Accept-Language", "zh-CN,zh;q=0.9")],
        true,
    )
    .await?;
    if status != 200 {
        return Err(format!("VPNGate 网页返回 HTTP {}", status));
    }
    let text = String::from_utf8_lossy(&body).to_string();
    let nodes = parse_web_page(&text);
    if nodes.is_empty() {
        return Err("VPNGate 网页里没有解析到节点（页面结构可能变了）".to_string());
    }
    Ok(nodes)
}

/// Where a node list came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeListSource {
    /// Official API `api/iphone`.
    Api,
    /// Scraped from the public relay list page.
    WebScrape,
    /// `nodes_cache.json` from the last successful fetch.
    Cache,
    /// Bundled 28-node curated list.
    Curated,
}

impl NodeListSource {
    /// One-line label for the UI, given the node count and (for cache)
    /// its age in seconds.
    pub fn label(&self, n: usize, cache_age_secs: Option<u64>) -> String {
        match self {
            NodeListSource::Api => format!("官方 API（{} 个节点）", n),
            NodeListSource::WebScrape => {
                format!("网页抓取（{} 个节点，官方 API 不可用）", n)
            }
            NodeListSource::Cache => {
                let age = cache_age_secs.unwrap_or(0);
                let age_text = if age < 3600 {
                    format!("约 {} 分钟前保存", age / 60 + 1)
                } else {
                    format!("约 {} 小时前保存", age / 3600)
                };
                format!("缓存列表（{} 个，{}）", n, age_text)
            }
            NodeListSource::Curated => "内嵌列表（官方 API 与网页都不可用）".to_string(),
        }
    }
}

/// The result of one node-list refresh: the nodes, where they came from,
/// and why the earlier sources failed (for the log line).
#[derive(Debug, Clone)]
pub struct NodeListUpdate {
    pub nodes: Vec<Node>,
    pub source: NodeListSource,
    pub cache_age_secs: Option<u64>,
    pub api_error: Option<String>,
    pub web_error: Option<String>,
}

/// Pure picker for the fallback chain (no network): the first
/// non-empty source wins — API, then web scrape, then cache, then the
/// bundled curated list.
pub fn pick_node_list(
    api: Option<Vec<Node>>,
    web: Option<Vec<Node>>,
    cache: Option<(Vec<Node>, u64)>,
) -> (Vec<Node>, NodeListSource, Option<u64>) {
    if let Some(nodes) = api {
        if !nodes.is_empty() {
            return (nodes, NodeListSource::Api, None);
        }
    }
    if let Some(nodes) = web {
        if !nodes.is_empty() {
            return (nodes, NodeListSource::WebScrape, None);
        }
    }
    if let Some((nodes, age)) = cache {
        return (nodes, NodeListSource::Cache, Some(age));
    }
    (curated_nodes(), NodeListSource::Curated, None)
}

/// Full fallback chain: official API first, then the relay list page,
/// then the local cache, then the bundled curated list. The last two
/// never fail, so this always returns a list.
/// Per-tier ceilings for a node-list fetch. `https_get` has no timeout
/// of its own, so without this a refresh with the front proxy off (or
/// a black-holed target) hangs for over a minute — Leo's v3.2 log
/// showed 85 s on startup.
/// The API tier gets 30 s: it is the richer source (Operator, Message,
/// score, ping, speed) and is slow through Leo's front proxy (the
/// front-proxy test alone takes ~7 s for vpngate.net); 15 s cut it off
/// mid-flight (Leo's v3.4 log: API timed out at 15 s, fell back to the
/// 100-node scrape). The web tier stays 15 s. Worst case 30 + 15 = 45 s,
/// still far below the old 85 s hang.
pub const API_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
pub const WEB_FETCH_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn fetch_nodes_with_fallback(connector: &Connector) -> NodeListUpdate {
    fetch_nodes_with_fallback_timeout(connector, API_FETCH_TIMEOUT, WEB_FETCH_TIMEOUT).await
}

/// Testable core: the per-tier timeouts are parameters so tests can use
/// short ones against a black-holed proxy instead of waiting 30 s.
async fn fetch_nodes_with_fallback_timeout(
    connector: &Connector,
    api_timeout: Duration,
    web_timeout: Duration,
) -> NodeListUpdate {
    let mut api_error = None;
    let api = match tokio::time::timeout(api_timeout, fetch_api_nodes(connector)).await {
        Ok(Ok(nodes)) if !nodes.is_empty() => Some(nodes),
        Ok(Ok(_)) => {
            api_error = Some("官方 API 返回了空列表".to_string());
            None
        }
        Ok(Err(e)) => {
            api_error = Some(e);
            None
        }
        Err(_) => {
            api_error = Some(format!(
                "官方 API 拉取超时（{} 秒内无响应）",
                api_timeout.as_secs()
            ));
            None
        }
    };
    let mut web_error = None;
    let web = if api.is_none() {
        match tokio::time::timeout(web_timeout, fetch_web_nodes(connector)).await {
            Ok(Ok(nodes)) if !nodes.is_empty() => Some(nodes),
            Ok(Ok(_)) => {
                web_error = Some("网页抓取解析到 0 个节点".to_string());
                None
            }
            Ok(Err(e)) => {
                web_error = Some(e);
                None
            }
            Err(_) => {
                web_error = Some(format!(
                    "网页抓取超时（{} 秒内无响应）",
                    web_timeout.as_secs()
                ));
                None
            }
        }
    } else {
        None
    };
    let cache = load_cached_nodes();
    let (nodes, source, cache_age_secs) = pick_node_list(api, web, cache);
    NodeListUpdate {
        nodes,
        source,
        cache_age_secs,
        api_error,
        web_error,
    }
}

// ---------------------------------------------------------------------------
// Node-list cache (portable): the last good API list is saved next to the
// executable as `nodes_cache.json`, so a refresh that fails — the API is
// often unreachable (TLS reset / blocked network) — still shows a recent
// list instead of only the 28 bundled nodes.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct CachedList {
    fetched_at: u64,
    nodes: Vec<Node>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `nodes_cache.json` next to the executable (portable location).
pub fn cache_path() -> Option<PathBuf> {
    crate::config::Config::portable_dir().map(|d| d.join("nodes_cache.json"))
}

/// Save a fresh API list to the cache. Errors are swallowed by callers
/// (a missing cache only means the next failed refresh falls back to
/// the bundled list).
pub fn save_cached_nodes(nodes: &[Node]) -> Result<(), String> {
    let Some(path) = cache_path() else {
        return Err("cannot locate executable directory".to_string());
    };
    save_cached_nodes_to(&path, nodes)
}

/// Path-taking core of `save_cached_nodes` (tests use a temp path).
pub fn save_cached_nodes_to(path: &std::path::Path, nodes: &[Node]) -> Result<(), String> {
    let payload = CachedList {
        fetched_at: now_unix(),
        nodes: nodes.to_vec(),
    };
    let text = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {}", path.display(), e))
}

/// Load the cached list, if it exists and parses. Returns the nodes and
/// their age in seconds.
pub fn load_cached_nodes() -> Option<(Vec<Node>, u64)> {
    let path = cache_path()?;
    load_cached_nodes_from(&path)
}

/// Path-taking core of `load_cached_nodes` (tests use a temp path).
pub fn load_cached_nodes_from(path: &std::path::Path) -> Option<(Vec<Node>, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    let payload: CachedList = serde_json::from_str(&text).ok()?;
    if payload.nodes.is_empty() {
        return None;
    }
    Some((payload.nodes, now_unix().saturating_sub(payload.fetched_at)))
}

/// Nodes to show when the official API is unreachable: the cached list
/// saved after the last successful fetch, if any, else the bundled
/// curated list. The second value is the cache age in seconds
/// (`None` when the list is the bundled curated one).
pub fn fallback_nodes() -> (Vec<Node>, Option<u64>) {
    if let Some((nodes, age)) = load_cached_nodes() {
        return (nodes, Some(age));
    }
    (curated_nodes(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_api_csv_sample() {
        let csv = "# comment\n* vpn_servers\nHostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\nvpn267947139.opengw.net,1.2.3.4,1000000,10,100,Japan,JP,5,1000,2000,3000,0,SoftBank BB,,AAAA\n";
        let nodes = parse_api_csv(csv);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].host, "vpn267947139.opengw.net");
        assert_eq!(nodes[0].country, "Japan");
        assert_eq!(nodes[0].score, 1000000);
        assert_eq!(nodes[0].port, None);
        // cols[11] is LogType ("0" here, "2weeks" in the live list) —
        // the ISP is Operator, cols[12]. Before the fix both isp and
        // name read cols[11], so the ISP column showed "2weeks".
        assert_eq!(nodes[0].isp, "SoftBank BB");
        assert!(nodes[0].name.is_empty(), "API nodes carry no display name");
        // Speed 100 here is 100 bps → 0 Mbps (rounds to nearest);
        // Ping is already ms and sessions a plain count.
        assert_eq!(nodes[0].speed_mbps, 0, "100 bps rounds to 0 Mbps");
        assert_eq!(nodes[0].ping_ms, 10);
        assert_eq!(nodes[0].sessions, 5);
    }

    #[test]
    fn parse_api_csv_speed_is_bps_not_mbps() {
        // Leo's v3.6 report: 线路质量 showed "77570260M" — the API
        // Speed column is bits per second, not Mbps.
        let csv = "# comment\n* vpn_servers\nHostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\nvpn267947139.opengw.net,1.2.3.4,1000000,12,77570260,Japan,JP,47,1000,2000,3000,0,SoftBank BB,,AAAA\n";
        let nodes = parse_api_csv(csv);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].speed_mbps, 78, "77,570,260 bps → 78 Mbps");
        assert_eq!(nodes[0].ping_ms, 12, "ping stays in ms");
        assert_eq!(nodes[0].sessions, 47, "sessions stay a plain count");
        // Rounding to nearest: 500,000 bps → 1 Mbps, 499,999 → 0.
        assert_eq!(bps_to_mbps(500_000), 1);
        assert_eq!(bps_to_mbps(499_999), 0);
        assert_eq!(bps_to_mbps(1_500_000), 2);
    }

    #[test]
    fn resolve_target_completes_bare_ddns_labels() {
        // Leo's v3.1 log: API nodes arrived as bare labels
        // ("public-vpn-192", "vpn321359264") and the probe dialled
        // them as-is. The suffix is completed here, at the single
        // choke point probe/connect (GUI + CLI) both use.
        let c = resolve_target("public-vpn-192");
        assert_eq!(c.len(), 3, "candidate SSTP ports");
        assert!(c.iter().all(|(h, _)| h == "public-vpn-192.opengw.net"));
        assert_eq!(
            c.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            vec![443, 992, 995]
        );
        assert_eq!(
            resolve_target("public-vpn-192:995"),
            vec![("public-vpn-192.opengw.net".to_string(), 995)]
        );
        // A bare "opengw" completes to a name that cleanly fails DNS
        // instead of dialling whatever the proxy makes of the label.
        assert_eq!(
            resolve_target("opengw"),
            vec![
                ("opengw.opengw.net".to_string(), 443),
                ("opengw.opengw.net".to_string(), 992),
                ("opengw.opengw.net".to_string(), 995),
            ]
        );
        // FQDNs and IPs are untouched.
        assert_eq!(
            resolve_target("kanratown.opengw.net:992"),
            vec![("kanratown.opengw.net".to_string(), 992)]
        );
        assert_eq!(
            resolve_target("127.0.0.1:8443"),
            vec![("127.0.0.1".to_string(), 8443)]
        );
        // Curated hosts keep their known port and backups.
        let c = resolve_target("kanratown.opengw.net");
        assert_eq!(c[0], ("kanratown.opengw.net".to_string(), 992));
        assert_eq!(c.len(), 3, "known port + 2 curated backups");
    }

    #[test]
    fn parse_web_page_never_yields_bare_domain() {
        // A page that merely mentions the domain must not produce a
        // node whose host is "opengw.net" itself.
        let html = r#"<table>
<tr><td>Japan</td><td>DDNS hostnames end with opengw.net — see <b>vpn1.opengw.net</b></td><td>SSTP 主机名 : <b>opengw.net</b></td></tr>
<tr><td>Japan</td><td><b>vpn2.opengw.net</b> 1.1.1.1</td><td>SSTP 主机名 : <b>vpn2.opengw.net</b></td></tr>
</table>"#;
        let nodes = parse_web_page(html);
        // vpn1 (mentioned in the text) and vpn2 (the real row) both
        // parse; the bare "opengw.net" in the SSTP cell must not.
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].host, "vpn1.opengw.net");
        assert_eq!(nodes[1].host, "vpn2.opengw.net");
        assert!(nodes.iter().all(|n| n.host != "opengw.net"));
    }

    #[test]
    fn curated_has_28_known_ports() {
        let nodes = curated_nodes();
        assert_eq!(nodes.len(), 28);
        assert!(nodes.iter().all(|n| n.port.is_some()));
        assert!(nodes
            .iter()
            .any(|n| n.host == "kanratown.opengw.net" && n.port == Some(992)));
    }

    #[test]
    fn node_cache_roundtrip() {
        let dir = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = dir.join(format!("vpngate-cache-test-{}.json", stamp));
        let mut nodes = curated_nodes();
        nodes.truncate(3);
        save_cached_nodes_to(&path, &nodes).expect("save cache");
        let (back, age) = load_cached_nodes_from(&path).expect("load cache");
        assert_eq!(back.len(), 3);
        assert_eq!(back[0].host, nodes[0].host);
        assert!(age < 60, "fresh cache must be seconds old");
        let _ = std::fs::remove_file(&path);
        assert!(load_cached_nodes_from(&path).is_none());
    }

    /// Synthetic HTML shaped like the real relay table: a header row,
    /// rows with/without an explicit SSTP port, a duplicate host, a row
    /// with no SSTP support, and non-DDNS hostnames that must be ignored.
    fn sample_relay_html() -> &'static str {
        r#"<html><body><table>
<tr><th>国家 / 地区</th><th>DDNS 主机名 IP 地址</th><th>MS-SSTP</th></tr>
<tr><td><img src="/images/flags/JP.png"> Japan</td>
<td><b>public-vpn-52.opengw.net</b> 219.100.37.16 (public-vpn-01-16.vpngate.v4.open.ad.jp)</td>
<td>SSTP 主机名 : <b>public-vpn-52.opengw.net</b></td></tr>
<tr><td><img src="/images/flags/US.png"> United States</td>
<td><b>vpn678091301.opengw.net</b> 184.97.202.118</td>
<td>SSTP 主机名 : <b>vpn678091301.opengw.net:1427</b></td></tr>
<tr><td><img src="/images/flags/JP.png"> Japan</td>
<td><b>kanratown.opengw.net</b> 1.2.3.4</td>
<td>SSTP 主机名 : <b>kanratown.opengw.net</b></td></tr>
<tr><td><img src="/images/flags/JP.png"> Japan</td>
<td><b>vpn395062778.opengw.net</b> 50.110.65.218</td>
<td></td></tr>
</table>
<table><tr><td>VPN-23751640530</td><td>United Kingdom</td><td>163.131.1.1</td></tr></table>
</body></html>"#
    }

    #[test]
    fn parse_web_page_sample() {
        let nodes = parse_web_page(sample_relay_html());
        // Table order, deduplicated; the session-log table contributes nothing.
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[0].host, "public-vpn-52.opengw.net");
        assert_eq!(nodes[0].country, "Japan");
        assert_eq!(nodes[0].port, Some(443), "no explicit port -> 443 default");
        assert_eq!(nodes[0].source, "web-scrape");
        assert_eq!(nodes[1].host, "vpn678091301.opengw.net");
        assert_eq!(nodes[1].country, "United States");
        assert_eq!(
            nodes[1].port,
            Some(1427),
            "explicit SSTP port from the MS-SSTP cell"
        );
        // kanratown is in the curated table with known port 992.
        assert_eq!(nodes[2].host, "kanratown.opengw.net");
        assert_eq!(
            nodes[2].port,
            Some(992),
            "curated port beats the scraped default"
        );
        assert_eq!(nodes[2].port_source, "curated");
        // Row with an empty MS-SSTP cell still yields a node on port 443.
        assert_eq!(nodes[3].host, "vpn395062778.opengw.net");
        assert_eq!(nodes[3].port, Some(443));
        // ISP hostnames (vpngate.v4.open.ad.jp) must not leak in.
        assert!(nodes.iter().all(|n| n.host.ends_with(".opengw.net")));
    }

    #[test]
    fn parse_web_page_dedupes_and_ignores_garbage() {
        // Same host in two rows: first occurrence wins, explicit port upgrades.
        let html = r#"<table>
<tr><td>Japan</td><td><b>vpn111.opengw.net</b> 1.1.1.1</td><td>SSTP 主机名 : <b>vpn111.opengw.net</b></td></tr>
<tr><td>Japan</td><td><b>vpn111.opengw.net</b> 1.1.1.1</td><td>SSTP 主机名 : <b>vpn111.opengw.net:1999</b></td></tr>
<tr><td>Japan</td><td><b>not-a-host.example.com</b></td><td></td></tr>
</table>"#;
        let nodes = parse_web_page(html);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].host, "vpn111.opengw.net");
        assert_eq!(nodes[0].port, Some(1999));

        assert!(parse_web_page("").is_empty());
        assert!(parse_web_page("<html><body>no table here</body></html>").is_empty());
        assert!(parse_web_page("<tr><td>no hostname at all</td></tr>").is_empty());
    }

    #[test]
    fn row_operator_name_edges() {
        // Direct helper checks (rows are `<tr`-split fragments).
        let row = |cell: &str| format!("<td>Japan</td><td>x.opengw.net</td><td>{}</td>", cell);
        assert_eq!(
            row_operator_name(&row("<b><i>By Daiyuu Nobori, Japan. Academic Use Only.</i></b>")),
            "Daiyuu Nobori"
        );
        assert_eq!(
            row_operator_name(&row("<b><i>By MOODLE-SERVER's owner</i></b>")),
            "MOODLE-SERVER's owner"
        );
        assert_eq!(
            row_operator_name(&row(
                "<b><i>By Japan VPN</i></b> <i>E-mail: jdyes2w0a@mozmail.com</i> \
                 <i>\"こんにちは! Hello!\"</i>"
            )),
            "Japan VPN"
        );
        assert_eq!(row_operator_name(&row("")), "");
        assert_eq!(row_operator_name(&row("By ")), "");
        // No "By " cell at all, and a "Bye" that must not match.
        assert_eq!(row_operator_name("<td>Japan</td><td>x.opengw.net</td>"), "");
        assert_eq!(
            row_operator_name(&row("Bye someone")),
            "",
            "\"Bye\" is not the \"By \" marker"
        );
    }

    /// Synthetic HTML shaped like the live relay table (10 columns),
    /// built from the live page text (2026-11-07): operator cells with
    /// a message, without one, with an E-mail + greeting suffix, an
    /// empty operator cell, and a 3-column row with no operator cell.
    fn sample_relay_html_with_operator() -> &'static str {
        r#"<html><body><table>
<tr><th>国家 / 地区</th><th>DDNS 主机名 IP 地址</th><th>VPN 会话数</th><th>线路质量</th><th>SSL-VPN</th><th>L2TP/IPsec</th><th>OpenVPN</th><th>MS-SSTP</th><th>志愿者操作员的名字</th><th>总分</th></tr>
<tr><td>Japan</td>
<td><b>public-vpn-192.opengw.net</b> 219.100.37.209 (public-vpn-14-01.vpngate.v4.open.ad.jp)</td>
<td>285 会话 14 天</td><td>261.83 Mbps Ping: 8 ms 日志策略: 两周</td>
<td>TCP: 443 UDP: 支持</td><td></td><td>TCP: 443 UDP: 1195</td>
<td>SSTP 主机名 : <b>public-vpn-192.opengw.net</b></td>
<td><b><i>By Daiyuu Nobori, Japan. Academic Use Only.</i></b></td>
<td>2,940,710</td></tr>
<tr><td>India</td>
<td><b>vpn359610091.opengw.net</b> 103.172.220.133</td>
<td>70 会话 27 天</td><td>195.31 Mbps Ping: 11 ms 日志策略: 两周</td>
<td>TCP: 995 UDP: 支持</td><td></td><td>TCP: 995 UDP: 1195</td>
<td>SSTP 主机名 : <b>vpn359610091.opengw.net</b></td>
<td><b><i>By MOODLE-SERVER's owner</i></b></td>
<td>1,486,191</td></tr>
<tr><td>India</td>
<td><b>vpn359610091.opengw.net</b> 103.172.220.133</td>
<td>70 会话 27 天</td><td>195.31 Mbps Ping: 11 ms 日志策略: 两周</td>
<td>TCP: 995 UDP: 支持</td><td></td><td>TCP: 995 UDP: 1195</td>
<td>SSTP 主机名 : <b>vpn359610091.opengw.net:995</b></td>
<td><b><i>By MOODLE-SERVER's owner</i></b></td>
<td>1,486,191</td></tr>
<tr><td>Romania</td>
<td><b>vpn111222333.opengw.net</b> 217.138.212.62</td>
<td>127 会话 12 天</td><td>149.25 Mbps Ping: 5 ms 日志策略: 两周</td>
<td>TCP: 443</td><td></td><td>TCP: 443 UDP: 1194</td>
<td>SSTP 主机名 : <b>vpn111222333.opengw.net</b></td>
<td><b><i>By Japan VPN</i></b> <i>E-mail: jdyes2w0a@mozmail.com</i> <i>"こんにちは! Hello!"</i></td>
<td>1,462,238</td></tr>
<tr><td>Japan</td>
<td><b>vpn99990120.opengw.net</b> 180.197.121.148 (180-197-121-148.area54c.commufa.jp)</td>
<td>68 会话 2 天</td><td>670.44 Mbps Ping: 12 ms 日志策略: 两周</td>
<td></td><td>L2TP/IPsec 连接指南</td><td></td><td></td><td></td>
<td>965,869</td></tr>
<tr><td>Thailand</td><td><b>vpn216782972.opengw.net</b> 27.130.188.53</td><td></td></tr>
</table></body></html>"#
    }

    #[test]
    fn row_sessions_and_line_quality_edges() {
        // Direct helper checks (rows are `<tr`-split fragments).
        // The 10-column layout: cell 3 = VPN 会话数, cell 4 = 线路质量.
        let row = |sessions: &str, quality: &str| {
            format!(
                "<td>Japan</td><td><b>x.opengw.net</b> 1.1.1.1</td><td>{}</td><td>{}</td>",
                sessions, quality
            )
        };
        assert_eq!(
            row_sessions(&row("285 会话 14 天", "")),
            285,
            "integer before 会话"
        );
        assert_eq!(
            row_sessions(&row("1,234 会话 30 天", "")),
            1234,
            "thousands comma in the count"
        );
        assert_eq!(row_sessions(&row("", "")), 0, "empty sessions cell");
        assert_eq!(
            row_sessions(&row("285", "")),
            0,
            "number without 会话 is not a session count"
        );
        assert_eq!(
            row_sessions("<td>Japan</td><td><b>x.opengw.net</b></td>"),
            0,
            "row with no sessions cell at all"
        );
        assert_eq!(
            row_line_quality(&row("", "261.83 Mbps Ping: 8 ms 日志策略: 两周")),
            (262, 8),
            "decimal speed rounds, ping after Ping:"
        );
        assert_eq!(
            row_line_quality(&row("", "572.32 Mbps Ping: 3 ms")),
            (572, 3),
            "the doc example: 572M@3ms"
        );
        assert_eq!(
            row_line_quality(&row("", "47.44 Mbps Ping: 26 ms")),
            (47, 26),
            "sub-50 Mbps rounds down"
        );
        assert_eq!(
            row_line_quality(&row("", "1,024.5 Mbps Ping: 12 ms")),
            (1025, 12),
            "thousands comma in the speed"
        );
        assert_eq!(
            row_line_quality(&row("", "670.44 Mbps 日志策略: 两周")),
            (670, 0),
            "speed without a Ping still parses"
        );
        assert_eq!(
            row_line_quality(&row("", "")),
            (0, 0),
            "empty quality cell"
        );
        assert_eq!(
            row_line_quality("<td>Japan</td><td><b>x.opengw.net</b></td>"),
            (0, 0),
            "row with no quality cell at all"
        );
    }

    #[test]
    fn parse_web_page_extracts_sessions_and_quality() {
        // Same 10-column fixture as the operator test: sessions and
        // line quality come from columns 3 and 4 of each row.
        let nodes = parse_web_page(sample_relay_html_with_operator());
        assert_eq!(nodes.len(), 5);
        assert_eq!(nodes[0].host, "public-vpn-192.opengw.net");
        assert_eq!(nodes[0].sessions, 285);
        assert_eq!(nodes[0].speed_mbps, 262, "261.83 Mbps rounds to 262");
        assert_eq!(nodes[0].ping_ms, 8);
        assert_eq!(nodes[1].host, "vpn359610091.opengw.net");
        assert_eq!(nodes[1].sessions, 70);
        assert_eq!(nodes[1].speed_mbps, 195);
        assert_eq!(nodes[1].ping_ms, 11);
        assert_eq!(nodes[2].host, "vpn111222333.opengw.net");
        assert_eq!(nodes[2].sessions, 127);
        assert_eq!(nodes[2].speed_mbps, 149);
        assert_eq!(nodes[2].ping_ms, 5);
        assert_eq!(nodes[3].host, "vpn99990120.opengw.net");
        assert_eq!(nodes[3].sessions, 68);
        assert_eq!(nodes[3].speed_mbps, 670);
        assert_eq!(nodes[3].ping_ms, 12);
        // 3-column row with no sessions/quality cells: all zero
        // (unknown), and host/country parsing is unaffected.
        assert_eq!(nodes[4].host, "vpn216782972.opengw.net");
        assert_eq!(nodes[4].sessions, 0);
        assert_eq!(nodes[4].speed_mbps, 0);
        assert_eq!(nodes[4].ping_ms, 0);
        assert_eq!(nodes[4].country, "Thailand");
    }

    #[test]
    fn parse_web_page_extracts_operator() {
        let nodes = parse_web_page(sample_relay_html_with_operator());
        assert_eq!(nodes.len(), 5, "duplicate host deduped, all rows kept");
        // Operator name, message stripped — same field the API calls
        // Operator, so the GUI's 运营商 column matches across sources.
        assert_eq!(nodes[0].host, "public-vpn-192.opengw.net");
        assert_eq!(nodes[0].isp, "Daiyuu Nobori");
        assert_eq!(nodes[0].country, "Japan");
        assert_eq!(nodes[0].port, Some(443));
        // Duplicate row: first occurrence wins, explicit port upgrades.
        assert_eq!(nodes[1].host, "vpn359610091.opengw.net");
        assert_eq!(nodes[1].isp, "MOODLE-SERVER's owner");
        assert_eq!(nodes[1].port, Some(995));
        // E-mail + greeting suffix must not leak into the name.
        assert_eq!(nodes[2].host, "vpn111222333.opengw.net");
        assert_eq!(nodes[2].isp, "Japan VPN");
        // Empty operator cell: node still parses, ISP stays empty.
        assert_eq!(nodes[3].host, "vpn99990120.opengw.net");
        assert_eq!(nodes[3].isp, "");
        assert_eq!(nodes[3].port, Some(443), "no SSTP cell -> 443 default");
        // 3-column row with no operator cell at all: same as before.
        assert_eq!(nodes[4].host, "vpn216782972.opengw.net");
        assert_eq!(nodes[4].isp, "");
        assert_eq!(nodes[4].country, "Thailand");
    }

    #[test]
    fn fallback_chain_prefers_api_then_web_then_cache() {
        let one = |h: &str| Node {
            host: h.to_string(),
            port: Some(443),
            country: "Japan".to_string(),
            country_code: "JP".to_string(),
            isp: String::new(),
            name: String::new(),
            score: 0,
            ping_ms: 0,
            speed_mbps: 0,
            sessions: 0,
            ip: String::new(),
            backups: Vec::new(),
            port_source: "api".to_string(),
            source: "api".to_string(),
        };
        // API wins when present, even if web and cache also exist.
        let (nodes, src, age) = pick_node_list(
            Some(vec![one("api.opengw.net")]),
            Some(vec![one("web.opengw.net")]),
            Some((vec![one("cache.opengw.net")], 3600)),
        );
        assert_eq!(src, NodeListSource::Api);
        assert_eq!(nodes[0].host, "api.opengw.net");
        assert_eq!(age, None);
        // API empty -> web scrape wins over cache.
        let (nodes, src, _) = pick_node_list(
            Some(vec![]),
            Some(vec![one("web.opengw.net")]),
            Some((vec![one("cache.opengw.net")], 3600)),
        );
        assert_eq!(src, NodeListSource::WebScrape);
        assert_eq!(nodes[0].host, "web.opengw.net");
        // Both empty -> cache, with its age.
        let (nodes, src, age) =
            pick_node_list(None, None, Some((vec![one("cache.opengw.net")], 7200)));
        assert_eq!(src, NodeListSource::Cache);
        assert_eq!(nodes[0].host, "cache.opengw.net");
        assert_eq!(age, Some(7200));
        // Nothing at all -> bundled curated list.
        let (nodes, src, _) = pick_node_list(None, None, None);
        assert_eq!(src, NodeListSource::Curated);
        assert_eq!(nodes.len(), 28);
    }

    /// A black-holed front proxy (accepts TCP, never answers) must not
    /// hang a refresh: each tier is capped, so the whole fallback
    /// returns in about two tier timeouts with the timeout wording.
    /// Regression test for Leo's v3.2 startup hang (85 s, no proxy).
    #[tokio::test]
    async fn fetch_fallback_bounds_black_holed_proxy() {
        // Black hole: accept and hold, never send a byte.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    // Hold the socket open forever; the TLS/SOCKS5
                    // handshake on it never completes.
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    drop(s);
                });
            }
        });
        let mut fp = crate::config::FrontProxy::default();
        fp.enabled = true;
        fp.addr = format!("127.0.0.1:{}", port);
        let connector = Connector::new(Some(fp));
        let start = std::time::Instant::now();
        let upd = fetch_nodes_with_fallback_timeout(
            &connector,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(8),
            "two 2 s tiers must finish well inside 8 s, took {:?}",
            elapsed
        );
        assert!(
            elapsed >= Duration::from_secs(3),
            "both tiers must actually run their timeouts, took {:?}",
            elapsed
        );
        assert!(
            matches!(upd.source, NodeListSource::Curated | NodeListSource::Cache),
            "a timed-out fetch must fall back to a local list, got {:?}",
            upd.source
        );
        assert!(
            upd.api_error.as_deref().unwrap_or("").contains("超时"),
            "API tier must report a timeout, got {:?}",
            upd.api_error
        );
        assert!(
            upd.web_error.as_deref().unwrap_or("").contains("超时"),
            "web tier must report a timeout, got {:?}",
            upd.web_error
        );
    }

    /// v3.15 API-only refresh ("从API刷新节点"): the same black
    /// hole must fail as an `Err` — never as a silently substituted
    /// list. One tier, one timeout: it returns in ~2 s (not ~4 s,
    /// which would mean the web tier ran too) with the timeout
    /// wording, so the GUI can report the failure plainly and leave
    /// the list untouched.
    #[tokio::test]
    async fn fetch_api_only_times_out_on_black_holed_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    drop(s);
                });
            }
        });
        let mut fp = crate::config::FrontProxy::default();
        fp.enabled = true;
        fp.addr = format!("127.0.0.1:{}", port);
        let connector = Connector::new(Some(fp));
        let start = std::time::Instant::now();
        let res = fetch_api_only_timeout(&connector, Duration::from_secs(2)).await;
        let elapsed = start.elapsed();
        let err = res.expect_err("a black-holed API must fail, not return a list");
        assert!(
            err.contains("超时"),
            "API-only failure must carry the timeout wording, got {:?}",
            err
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "one 2 s tier must finish well inside 5 s — a second tier (web scrape) would take ~4 s, took {:?}",
            elapsed
        );
        assert!(
            elapsed >= Duration::from_secs(1),
            "the API tier must actually run its timeout, took {:?}",
            elapsed
        );
    }
}

/// Resolve a user-supplied target into an ordered list of (host, port)
/// candidates to try. Backups from the curated list are appended.
pub fn resolve_target(target: &str) -> Vec<(String, u16)> {
    // host:port
    if let Some((h, p)) = target.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            if !h.is_empty() {
                return vec![(complete_ddns_host(h), port)];
            }
        }
    }
    // Index into the curated list.
    if let Ok(idx) = target.parse::<usize>() {
        let nodes = curated_nodes();
        if let Some(n) = nodes.get(idx) {
            let mut out = vec![(n.host.clone(), n.port.unwrap_or(443))];
            for b in &n.backups {
                if let Some((h, p)) = b.rsplit_once(':') {
                    if let Ok(port) = p.parse::<u16>() {
                        out.push((h.to_string(), port));
                    }
                }
            }
            return out;
        }
        eprintln!("curated index {} out of range (0..{})", idx, nodes.len());
        std::process::exit(2);
    }
    // Hostname known in the curated list?
    let nodes = curated_nodes();
    if let Some(n) = nodes.iter().find(|n| n.host == target) {
        let mut out = vec![(n.host.clone(), n.port.unwrap_or(443))];
        for b in &n.backups {
            if let Some((h, p)) = b.rsplit_once(':') {
                if let Ok(port) = p.parse::<u16>() {
                    out.push((h.to_string(), port));
                }
            }
        }
        return out;
    }
    // Unknown hostname: try the common SSTP ports.
    CANDIDATE_SSTP_PORTS
        .iter()
        .map(|p| (complete_ddns_host(target), *p))
        .collect()
}

/// A bare VPNGate label with no dot is a DDNS hostname whose
/// ".opengw.net" suffix is missing. Leo's v3.1 log showed API nodes
/// arriving as "public-vpn-192" / "vpn321359264" (and even "opengw"),
/// and the probe then dialled the bare label — whatever the front
/// proxy's DNS made of it — instead of the real relay. Complete it
/// defensively; FQDNs (they contain a dot) and IP addresses are
/// untouched. Public so the GUI can log the completed host:port in
/// its probe/connect start lines.
pub fn complete_ddns_host(host: &str) -> String {
    if host.contains('.') {
        host.to_string()
    } else {
        format!("{}.opengw.net", host)
    }
}
