//! JNI bridge: a thin JSON-in / JSON-out boundary between the Kotlin UI
//! (`io.github.leotse28.vpngatesu.NativeBridge`) and the vendored
//! vpngate-client core.
//!
//! Design notes (see DESIGN.md §2):
//! * The boundary is deliberately small: init, config get/save, node
//!   refresh (fallback chain or API-only), cached-list load, connect /
//!   disconnect, status, log tail. Every call returns one JSON string;
//!   errors are `{"ok":false,"error":"..."}` — never a null, never a
//!   panic across the FFI boundary (`catch_unwind` in each export).
//! * The tokio runtime lives in this .so and is created once in
//!   `nativeInit`. JNI calls from Kotlin run on `Dispatchers.IO` and
//!   use `Handle::block_on`; they never run on a tokio worker thread.
//! * The node-list fallback chain is re-implemented here with the
//!   path-taking cache variants (`load_cached_nodes_from` /
//!   `save_cached_nodes_to`) because the lib's own `cache_path()` is
//!   exe-relative (`portable_dir()`), which has no meaning on Android.
//!   Semantics match `fetch_nodes_with_fallback` exactly
//!   (API 30 s → web 15 s → cache → curated, via `pick_node_list`).
//! * Connection logs (`ConnLog` channel from `serve_mixed`) are
//!   forwarded by a runtime task into the same `FileLogger` file the
//!   UI reads back with `nativeGetLogs`, so the log view is a single
//!   source of truth: `filesDir/vpngate-gui.log` (2 MB rotation, same
//!   format as the desktop client).
//! * No GUI crates are linked (the path dependency has
//!   `default-features = false`); the .so must not contain eframe /
//!   egui / wgpu symbols — checked at build time, see the report.

use jni::objects::{JObject, JString};
use jni::sys::{jboolean, jint};
use jni::{Env, EnvUnowned};
use serde_json::{json, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use vpngate_client::{
    config::Config,
    filelog::{FileLogger, LogLevel},
    net::Connector,
    socks5,
    sstp::SstpTunnel,
    vpngate,
};

/// Vendored core version (frozen v3.16 + the `gui`-feature decoupling).
const CORE_VERSION: &str = "0.3.16";

const API_TIMEOUT: Duration = Duration::from_secs(30);
const WEB_TIMEOUT: Duration = Duration::from_secs(15);
const LOG_TAIL_LINES: usize = 200;

struct ActiveConn {
    tunnel: Arc<SstpTunnel>,
    serve: Vec<JoinHandle<()>>,
    host: String,
    port: u16,
    listen_addr: String,
}

struct State {
    files_dir: PathBuf,
    config: Config,
    nodes: Vec<vpngate::Node>,
    nodes_label: String,
    conn: Option<ActiveConn>,
}

static RT: OnceLock<Runtime> = OnceLock::new();
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static LOGGER: OnceLock<Mutex<FileLogger>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn err_json(msg: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": msg.to_string() }).to_string()
}

fn log_line(level: LogLevel, message: &str) {
    if let Some(l) = LOGGER.get() {
        if let Ok(mut l) = l.lock() {
            l.log(level, message);
        }
    }
}

fn config_json(cfg: &Config) -> Value {
    json!({
        "frontEnabled": cfg.front_proxy.enabled,
        "frontAddr": cfg.front_proxy.addr,
        "listenAddr": cfg.listen.addr,
        "localPort": cfg.listen.local_port,
        "allowLan": cfg.listen.allow_lan,
        "timeoutSecs": cfg.tunnel.timeout_secs,
    })
}

fn cache_path(files_dir: &PathBuf) -> PathBuf {
    files_dir.join("nodes_cache.json")
}

fn config_path(files_dir: &PathBuf) -> PathBuf {
    files_dir.join("config.toml")
}

fn log_path(files_dir: &PathBuf) -> PathBuf {
    files_dir.join(vpngate_client::filelog::LOG_FILE_NAME)
}

/// Run a JSON-producing closure inside the JNI env and return the
/// result as a Java string. Panics inside the closure become JSON
/// errors (never unwind across FFI — `with_env` also catches them);
/// only a failure to allocate the Java string itself throws a
/// RuntimeException and returns null (OOM only).
fn run_native<'caller, F>(mut unowned: EnvUnowned<'caller>, f: F) -> JString<'caller>
where
    F: FnOnce(&mut Env) -> String,
{
    let outcome = unowned.with_env(|env| -> Result<JString<'_>, jni::errors::Error> {
        let out = catch_unwind(AssertUnwindSafe(|| f(env)))
            .unwrap_or_else(|_| err_json("internal panic in native call"));
        JString::from_str(env, out)
    });
    outcome.resolve::<jni::errors::ThrowRuntimeExAndDefault>()
}

// ---------------------------------------------------------------------------
// nativeInit(filesDir: String): String
// ---------------------------------------------------------------------------

fn init(files_dir: &str) -> String {
    if STATE.get().is_some() {
        return json!({ "ok": true, "already": true }).to_string();
    }
    let files_dir = PathBuf::from(files_dir);
    if let Err(e) = std::fs::create_dir_all(&files_dir) {
        return err_json(format!("cannot create filesDir {}: {e}", files_dir.display()));
    }
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return err_json(format!("cannot start tokio runtime: {e}")),
    };
    let cfg_path = config_path(&files_dir);
    let cfg = match Config::load(Some(&cfg_path)) {
        Ok(cfg) => cfg,
        Err(e) => return err_json(e),
    };
    let mut logger = FileLogger::new(&log_path(&files_dir));
    logger.write_header(&cfg, None, Some(&cfg_path));
    let _ = RT.set(rt);
    let _ = LOGGER.set(Mutex::new(logger));
    let _ = STATE.set(Mutex::new(State {
        files_dir,
        config: cfg.clone(),
        nodes: Vec::new(),
        nodes_label: String::new(),
        conn: None,
    }));
    log_line(
        LogLevel::Info,
        &format!("VpngateSU JNI init (core {CORE_VERSION}); 前置代理：{}",
            if cfg.front_proxy.enabled {
                format!("已启用 {}", cfg.front_proxy.addr)
            } else {
                "未启用".to_string()
            }),
    );
    json!({ "ok": true, "already": false, "config": config_json(&cfg), "coreVersion": CORE_VERSION }).to_string()
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeInit<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
    files_dir: JString<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| init(&files_dir.to_string()))
}

// ---------------------------------------------------------------------------
// nativeGetConfig(): String / nativeSaveConfig(json: String): String
// ---------------------------------------------------------------------------

fn get_config() -> String {
    match STATE.get().and_then(|s| s.lock().ok()) {
        Some(st) => json!({ "ok": true, "config": config_json(&st.config) }).to_string(),
        None => err_json("not initialised (call nativeInit first)"),
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeGetConfig<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| get_config())
}

fn save_config(body: &str) -> String {
    let v: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return err_json(format!("bad settings JSON: {e}")),
    };
    let (files_dir, mut cfg) = match STATE.get().and_then(|s| s.lock().ok()) {
        Some(g) => (g.files_dir.clone(), g.config.clone()),
        None => return err_json("not initialised (call nativeInit first)"),
    };
    if let Some(b) = v.get("frontEnabled").and_then(Value::as_bool) {
        cfg.front_proxy.enabled = b;
    }
    if let Some(a) = v.get("frontAddr").and_then(Value::as_str) {
        if a.is_empty() {
            return err_json("前置代理地址不能为空");
        }
        cfg.front_proxy.addr = a.to_string();
    }
    if let Some(a) = v.get("listenAddr").and_then(Value::as_str) {
        if a.is_empty() {
            return err_json("监听地址不能为空");
        }
        cfg.listen.addr = a.to_string();
    }
    if let Some(p) = v.get("localPort").and_then(Value::as_u64) {
        if !(1..=65535).contains(&p) {
            return err_json(format!("本地端口超出范围：{p}"));
        }
        cfg.listen.local_port = p as u16;
    }
    if let Some(b) = v.get("allowLan").and_then(Value::as_bool) {
        cfg.listen.allow_lan = b;
    }
    if let Some(t) = v.get("timeoutSecs").and_then(Value::as_u64) {
        if !(1..=120).contains(&t) {
            return err_json(format!("隧道超时超出范围：{t} 秒"));
        }
        cfg.tunnel.timeout_secs = t;
    }
    let path = config_path(&files_dir);
    if let Err(e) = cfg.save(&path) {
        return err_json(e);
    }
    if let Ok(mut g) = STATE.get().unwrap().lock() {
        g.config = cfg.clone();
    }
    log_line(
        LogLevel::Info,
        &format!(
            "设置已保存：前置代理 {}，本地代理 {}",
            if cfg.front_proxy.enabled {
                cfg.front_proxy.addr.clone()
            } else {
                "未启用".to_string()
            },
            cfg.listen.display_addrs()
        ),
    );
    json!({ "ok": true, "config": config_json(&cfg) }).to_string()
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeSaveConfig<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
    body: JString<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| save_config(&body.to_string()))
}

// ---------------------------------------------------------------------------
// Node lists
// ---------------------------------------------------------------------------

fn nodes_json(nodes: &[vpngate::Node]) -> Value {
    serde_json::to_value(nodes).unwrap_or(Value::Array(Vec::new()))
}

fn refresh_nodes(api_only: bool) -> String {
    let (rt, files_dir, cfg) = match (RT.get(), STATE.get().and_then(|s| s.lock().ok())) {
        (Some(rt), Some(st)) => (rt, st.files_dir.clone(), st.config.clone()),
        _ => return err_json("not initialised (call nativeInit first)"),
    };
    let connector = Connector::from_config(&cfg);
    let cache = cache_path(&files_dir);
    if api_only {
        return match rt.block_on(vpngate::fetch_api_only(&connector)) {
            Ok(nodes) => {
                let n = nodes.len();
                let _ = vpngate::save_cached_nodes_to(&cache, &nodes);
                let label = format!("官方 API（{n} 个节点）");
                if let Ok(mut st) = STATE.get().unwrap().lock() {
                    st.nodes = nodes.clone();
                    st.nodes_label = label.clone();
                }
                log_line(LogLevel::Info, &format!("从 API 刷新节点：{n} 个"));
                json!({ "ok": true, "nodes": nodes_json(&nodes), "source": "api", "label": label }).to_string()
            }
            Err(e) => {
                log_line(LogLevel::Warn, &format!("从 API 刷新节点失败：{e}"));
                err_json(format!("当前方式刷新节点失败，请用另一种方式刷新：{e}"))
            }
        };
    }
    // Full fallback chain (mirrors fetch_nodes_with_fallback, but with
    // the path-taking cache so it works from filesDir on Android).
    let mut api_error = None;
    let api = match rt.block_on(tokio::time::timeout(
        API_TIMEOUT,
        vpngate::fetch_api_nodes(&connector),
    )) {
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
            api_error = Some(format!("官方 API 拉取超时（{} 秒内无响应）", API_TIMEOUT.as_secs()));
            None
        }
    };
    let mut web_error = None;
    let web = if api.is_none() {
        match rt.block_on(tokio::time::timeout(
            WEB_TIMEOUT,
            vpngate::fetch_web_nodes(&connector),
        )) {
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
                web_error = Some(format!("网页抓取超时（{} 秒内无响应）", WEB_TIMEOUT.as_secs()));
                None
            }
        }
    } else {
        None
    };
    let cache_data = vpngate::load_cached_nodes_from(&cache);
    let (nodes, source, cache_age_secs) = vpngate::pick_node_list(api, web, cache_data);
    let (source_str, save_cache) = match source {
        vpngate::NodeListSource::Api => ("api", true),
        vpngate::NodeListSource::WebScrape => ("web", true),
        vpngate::NodeListSource::Cache => ("cache", false),
        vpngate::NodeListSource::Curated => ("curated", false),
    };
    if save_cache {
        let _ = vpngate::save_cached_nodes_to(&cache, &nodes);
    }
    let n = nodes.len();
    let label = source.label(n, cache_age_secs);
    if let Ok(mut st) = STATE.get().unwrap().lock() {
        st.nodes = nodes.clone();
        st.nodes_label = label.clone();
    }
    log_line(
        LogLevel::Info,
        &format!(
            "刷新节点：{label}{}",
            match (&api_error, &web_error) {
                (Some(a), Some(w)) => format!("；API 失败：{a}；网页失败：{w}"),
                (Some(a), None) => format!("；API 失败：{a}"),
                (None, Some(w)) => format!("；网页失败：{w}"),
                (None, None) => String::new(),
            }
        ),
    );
    json!({
        "ok": true,
        "nodes": nodes_json(&nodes),
        "source": source_str,
        "label": label,
        "apiError": api_error,
        "webError": web_error,
    })
    .to_string()
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeRefreshNodes<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
    api_only: jboolean,
) -> JString<'caller> {
    run_native(unowned, |_env| refresh_nodes(api_only))
}

fn load_cached_nodes() -> String {
    let files_dir = match STATE.get().and_then(|s| s.lock().ok()) {
        Some(st) => st.files_dir.clone(),
        None => return err_json("not initialised (call nativeInit first)"),
    };
    let (nodes, source_str, label) =
        match vpngate::load_cached_nodes_from(&cache_path(&files_dir)) {
            Some((nodes, age)) => {
                let label = vpngate::NodeListSource::Cache.label(nodes.len(), Some(age));
                (nodes, "cache", label)
            }
            None => {
                let nodes = vpngate::curated_nodes();
                let label = vpngate::NodeListSource::Curated.label(nodes.len(), None);
                (nodes, "curated", label)
            }
        };
    if let Ok(mut st) = STATE.get().unwrap().lock() {
        st.nodes = nodes.clone();
        st.nodes_label = label.clone();
    }
    json!({ "ok": true, "nodes": nodes_json(&nodes), "source": source_str, "label": label }).to_string()
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeLoadCachedNodes<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| load_cached_nodes())
}

// ---------------------------------------------------------------------------
// Connect / disconnect / status
// ---------------------------------------------------------------------------

fn connect(host: &str, port: i32) -> String {
    let (rt, cfg) = match (RT.get(), STATE.get().and_then(|s| s.lock().ok())) {
        (Some(rt), Some(st)) => (rt, st.config.clone()),
        _ => return err_json("not initialised (call nativeInit first)"),
    };
    if let Ok(st) = STATE.get().unwrap().lock() {
        if st.conn.is_some() {
            return err_json("已连接，请先断开");
        }
    }
    let target = if port > 0 {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };
    let candidates = vpngate::resolve_target(&target);
    let timeout = Duration::from_secs(cfg.tunnel.timeout_secs);
    let connector = Connector::from_config(&cfg);
    log_line(
        LogLevel::Info,
        &format!("连接 {target}（{} 个候选）…", candidates.len()),
    );
    let tunnel = match rt.block_on(SstpTunnel::connect_any(&connector, &candidates, timeout)) {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("{} 个候选均失败；最后一次：{e}", candidates.len());
            log_line(LogLevel::Warn, &format!("连接 {target} 失败：{msg}"));
            return err_json(msg);
        }
    };
    let vip = tunnel.vip;
    // Bind the local mixed-proxy port (one 2 s retry on AddrInUse,
    // same as the desktop client).
    let mut listeners = Vec::new();
    for addr in cfg.listen.listen_addrs() {
        let listener = match rt.block_on(tokio::net::TcpListener::bind(&addr)) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                std::thread::sleep(Duration::from_secs(2));
                match rt.block_on(tokio::net::TcpListener::bind(&addr)) {
                    Ok(l) => l,
                    Err(e2) => {
                        let msg = format!(
                            "本地混合代理无法监听 {addr}：{e2}（已重试一次，端口仍被占用，换一个端口再试）"
                        );
                        log_line(LogLevel::Warn, &msg);
                        return err_json(msg);
                    }
                }
            }
            Err(e) => {
                let msg = format!("本地混合代理无法监听 {addr}：{e}（端口可能被占用，换一个端口再试）");
                log_line(LogLevel::Warn, &msg);
                return err_json(msg);
            }
        };
        listeners.push(listener);
    }
    // Connection log: serve_mixed sends one line per accepted
    // connection; a runtime task forwards them into the file log.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(512);
    rt.spawn(async move {
        while let Some(line) = rx.recv().await {
            log_line(LogLevel::Info, &line);
        }
    });
    let mut serve = Vec::new();
    for listener in listeners {
        serve.push(rt.spawn(socks5::serve_mixed(
            listener,
            tunnel.clone(),
            timeout,
            Some(tx.clone()),
        )));
    }
    let listen_display = cfg.listen.display_addrs();
    if let Ok(mut st) = STATE.get().unwrap().lock() {
        st.conn = Some(ActiveConn {
            tunnel,
            serve,
            host: host.to_string(),
            port: if port > 0 { port as u16 } else { 0 },
            listen_addr: listen_display.clone(),
        });
    }
    log_line(
        LogLevel::Info,
        &format!("已连接 {target}，出口 {vip}，本地代理 {listen_display}"),
    );
    json!({ "ok": true, "vip": vip.to_string(), "listenAddr": listen_display, "host": host }).to_string()
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeConnect<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
    host: JString<'caller>,
    port: jint,
) -> JString<'caller> {
    run_native(unowned, |_env| connect(&host.to_string(), port))
}

fn disconnect() -> String {
    if STATE.get().is_none() {
        return err_json("not initialised (call nativeInit first)");
    }
    let conn = match STATE.get().unwrap().lock() {
        Ok(mut g) => g.conn.take(),
        Err(e) => return err_json(format!("state lock poisoned: {e}")),
    };
    match conn {
        Some(c) => {
            for h in &c.serve {
                h.abort();
            }
            // Dropping the last Arc<SstpTunnel> closes the tunnel.
            drop(c);
            log_line(LogLevel::Info, "已断开隧道");
            json!({ "ok": true }).to_string()
        }
        None => err_json("未连接"),
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeDisconnect<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| disconnect())
}

fn get_status() -> String {
    let Some(st) = STATE.get().and_then(|s| s.lock().ok()) else {
        return err_json("not initialised (call nativeInit first)");
    };
    match &st.conn {
        Some(c) => json!({
            "ok": true,
            "connected": true,
            "host": c.host,
            "port": c.port,
            "vip": c.tunnel.vip.to_string(),
            "sessions": c.tunnel.session_count(),
            "listenAddr": c.listen_addr,
            "alive": !c.tunnel.is_dead(),
        })
        .to_string(),
        None => json!({ "ok": true, "connected": false }).to_string(),
    }
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeGetStatus<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| get_status())
}

// ---------------------------------------------------------------------------
// nativeGetLogs(): String — tail of the file log
// ---------------------------------------------------------------------------

fn get_logs() -> String {
    let files_dir = match STATE.get().and_then(|s| s.lock().ok()) {
        Some(st) => st.files_dir.clone(),
        None => return err_json("not initialised (call nativeInit first)"),
    };
    let text = std::fs::read_to_string(log_path(&files_dir)).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    json!({
        "ok": true,
        "lines": lines[start..].to_vec(),
        "droppedConnLog": socks5::conn_log_dropped(),
    })
    .to_string()
}

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeGetLogs<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| get_logs())
}

// ---------------------------------------------------------------------------
// nativeGetVersion(): String
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_io_github_leotse28_vpngatesu_NativeBridge_nativeGetVersion<'caller>(
    unowned: EnvUnowned<'caller>,
    _thiz: JObject<'caller>,
) -> JString<'caller> {
    run_native(unowned, |_env| {
        json!({ "ok": true, "version": env!("CARGO_PKG_VERSION"), "coreVersion": CORE_VERSION }).to_string()
    })
}
