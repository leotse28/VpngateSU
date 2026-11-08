//! vpngate-client — minimal Rust client for VPNGate volunteer nodes.
//!
//! Subcommands:
//!   list     fetch the VPNGate node list (official API) and show it
//!   probe    SSTP handshake only: does the node give us a virtual IP?
//!   connect  establish the tunnel and serve a local mixed proxy (SOCKS5+HTTP)
//!   test     establish the tunnel and run generate_204 + google HTTPS

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vpngate_client::config::Config;
use vpngate_client::net::{self, Connector};
use vpngate_client::{socks5, sstp, sysproxy, vpngate};

#[derive(Parser)]
#[command(
    name = "vpngate-client",
    version,
    about = "VPNGate (SoftEther/SSTP) client in Rust — local SOCKS5, no TUN, no GUI"
)]
struct Cli {
    /// Config file (TOML). Default: config.toml next to the exe
    /// (portable), then ./config.toml in the working directory.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Front SOCKS5 proxy, e.g. 127.0.0.1:1080 (overrides config)
    #[arg(long, global = true)]
    front_socks5: Option<String>,

    /// Tunnel timeout in seconds (overrides config)
    #[arg(long, global = true)]
    timeout: Option<u64>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// List VPNGate nodes from the official API (merged with known SSTP ports)
    List {
        /// Filter by country (substring, case-insensitive), e.g. JP
        #[arg(long)]
        country: Option<String>,
        /// Max rows to print
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// SSTP handshake only: connect to a node and report the virtual IP
    Probe {
        /// Node: host:port, hostname, or index into the curated list
        target: String,
    },
    /// Connect and serve a local mixed proxy (SOCKS5+HTTP) until Ctrl-C
    Connect {
        /// Node: host:port, hostname, or index into the curated list
        target: String,
        /// Local listen address, e.g. 127.0.0.1:10818
        #[arg(long)]
        listen: Option<String>,
        /// Bind 0.0.0.0 (allow LAN), like V2Ray's allow-LAN
        #[arg(long)]
        allow_lan: bool,
        /// Also set the OS system proxy to the local mixed-proxy port
        #[arg(long)]
        system_proxy: bool,
    },
    /// Connect and run an end-to-end check (generate_204 + Google HTTPS)
    Test {
        /// Node: host:port, hostname, or index into the curated list
        target: String,
    },
}

fn load_config(cli: &Cli) -> Config {
    let path = Config::resolve_config_path(cli.config.as_deref());
    match Config::load(path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {}", e);
            std::process::exit(2);
        }
    }
}

fn effective_connector(cfg: &Config, cli: &Cli) -> Connector {
    let mut cfg = cfg.clone();
    if let Some(addr) = &cli.front_socks5 {
        cfg.front_proxy.enabled = true;
        cfg.front_proxy.addr = addr.clone();
    }
    Connector::from_config(&cfg)
}

fn effective_timeout(cfg: &Config, cli: &Cli) -> Duration {
    Duration::from_secs(cli.timeout.unwrap_or(cfg.tunnel.timeout_secs))
}

async fn connect_first(
    connector: &Connector,
    candidates: &[(String, u16)],
    timeout: Duration,
) -> Result<std::sync::Arc<sstp::SstpTunnel>, String> {
    // One race over all candidate ports (first success wins); a dead
    // node costs about one timeout, not one per port in series.
    println!(
        "trying {} candidate(s) in parallel ...",
        candidates.len()
    );
    match sstp::SstpTunnel::connect_any(connector, candidates, timeout).await {
        Ok(t) => {
            println!(
                "tunnel up: {}:{} virtual IP {}",
                t.host, t.port, t.vip
            );
            Ok(t)
        }
        Err(e) => Err(format!(
            "all {} candidate(s) failed; last error: {}",
            candidates.len(),
            e
        )),
    }
}

async fn cmd_list(cli: &Cli, cfg: &Config, country: Option<String>, limit: usize) -> i32 {
    let connector = effective_connector(cfg, cli);
    // Fallback chain: official API -> relay list page scrape -> local
    // cache -> bundled curated list. The last two never fail.
    let upd = vpngate::fetch_nodes_with_fallback(&connector).await;
    let nodes = &upd.nodes;
    match upd.source {
        vpngate::NodeListSource::Api => {
            println!(
                "# VPNGate live list ({} nodes from api/iphone)",
                nodes.len()
            );
            let _ = vpngate::save_cached_nodes(nodes);
        }
        vpngate::NodeListSource::WebScrape => {
            eprintln!(
                "# WARNING: live API fetch failed ({}); showing {} nodes scraped from {}.",
                upd.api_error.as_deref().unwrap_or("unknown error"),
                nodes.len(),
                vpngate::WEB_URL
            );
            let _ = vpngate::save_cached_nodes(nodes);
        }
        vpngate::NodeListSource::Cache => {
            eprintln!(
                "# WARNING: live API failed ({}) and web scrape failed ({}); showing cached list ({} nodes, {}h old).",
                upd.api_error.as_deref().unwrap_or("unknown error"),
                upd.web_error.as_deref().unwrap_or("unknown error"),
                nodes.len(),
                upd.cache_age_secs.unwrap_or(0) / 3600
            );
        }
        vpngate::NodeListSource::Curated => {
            eprintln!(
                "# WARNING: live API failed ({}) and web scrape failed ({}); showing bundled curated list only.",
                upd.api_error.as_deref().unwrap_or("unknown error"),
                upd.web_error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    let mut shown = 0usize;
    println!(
        "{:<4} {:<32} {:<22} {:>8} {:>6} {:>7} {:>5}  {:<6} {}",
        "idx", "host", "country", "score", "ping", "speed", "sess", "sstp", "isp"
    );
    for (i, n) in nodes.iter().enumerate() {
        if let Some(c) = &country {
            let c = c.to_lowercase();
            if !n.country.to_lowercase().contains(&c) && !n.country_code.to_lowercase().contains(&c)
            {
                continue;
            }
        }
        let port = n
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".to_string());
        println!(
            "{:<4} {:<32} {:<22} {:>8} {:>6} {:>7} {:>5}  {:<6} {}",
            i, n.host, n.country, n.score, n.ping_ms, n.speed_mbps, n.sessions, port, n.isp
        );
        shown += 1;
        if shown >= limit {
            break;
        }
    }
    println!("# shown {} nodes. sstp '?' = port unknown: use `probe <host>` to try candidate ports, or enter host:port manually.", shown);
    println!("# node sources, in order: official API, then the relay list page ({}), then the local cache, then the bundled curated list (28 nodes with known SSTP ports).", vpngate::WEB_URL);
    0
}

async fn cmd_probe(cli: &Cli, cfg: &Config, target: &str) -> i32 {
    let connector = effective_connector(cfg, cli);
    let timeout = effective_timeout(cfg, cli);
    let candidates = vpngate::resolve_target(target);
    print!(
        "probe {} ({} candidate(s) in parallel) ... ",
        target,
        candidates.len()
    );
    match sstp::SstpTunnel::probe_any(&connector, &candidates, timeout).await {
        Ok((vip, ms)) => {
            println!("ALIVE virtual-ip={} in {}ms", vip, ms.as_millis());
            0
        }
        Err(e) => {
            println!("dead: {}", e);
            eprintln!("all candidates failed");
            1
        }
    }
}

async fn cmd_test(cli: &Cli, cfg: &Config, target: &str) -> i32 {
    let connector = effective_connector(cfg, cli);
    let timeout = effective_timeout(cfg, cli);
    let candidates = vpngate::resolve_target(target);
    let tunnel = match connect_first(&connector, &candidates, timeout).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("connect failed: {}", e);
            return 1;
        }
    };
    // 1) Plain HTTP generate_204 through the tunnel.
    println!("-- generate_204 (http://www.gstatic.com/generate_204) --");
    match tunnel.open_stream("www.gstatic.com", 80, timeout).await {
        Ok(mut s) => {
            let req = b"GET http://www.gstatic.com/generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n";
            if let Err(e) = s.write_all(req).await {
                println!("write failed: {}", e);
                return 1;
            }
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(timeout, s.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    let head = String::from_utf8_lossy(&buf[..n]);
                    println!("response: {}", head.lines().next().unwrap_or("(empty)"));
                    if head.contains("204") {
                        println!("generate_204: PASS");
                    } else {
                        println!("generate_204: unexpected response");
                    }
                }
                Ok(Err(e)) => println!("read failed: {}", e),
                Err(_) => println!("read timed out after {:?}", timeout),
            }
        }
        Err(e) => println!("open stream failed: {}", e),
    }
    // 2) HTTPS to Google through the tunnel (TLS inside the tunnel).
    println!("-- google https (https://www.google.com/) --");
    match tunnel.open_stream("www.google.com", 443, timeout).await {
        Ok(stream) => {
            match tokio::time::timeout(
                timeout,
                net::verified_tls_connect(stream, "www.google.com"),
            )
            .await {
                Ok(Ok(mut tls)) => {
                    let req = format!(
                        "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\nUser-Agent: vpngate-client/{}\r\n\r\n",
                        env!("CARGO_PKG_VERSION")
                    );
                    if let Err(e) = tls.write_all(req.as_bytes()).await {
                        println!("TLS write failed: {}", e);
                        return 1;
                    }
                    let mut buf = vec![0u8; 4096];
                    match tokio::time::timeout(timeout, tls.read(&mut buf)).await {
                        Ok(Ok(n)) => {
                            let head = String::from_utf8_lossy(&buf[..n]);
                            println!("response: {}", head.lines().next().unwrap_or("(empty)"));
                            println!("google https: got {} bytes", n);
                        }
                        Ok(Err(e)) => println!("TLS read failed: {}", e),
                        Err(_) => println!("TLS read timed out after {:?}", timeout),
                    }
                }
                Ok(Err(e)) => println!("TLS handshake to google failed: {}", e),
                Err(_) => println!("TLS handshake timed out after {:?}", timeout),
            }
        }
        Err(e) => println!("open stream failed: {}", e),
    }
    0
}

async fn cmd_connect(
    cli: &Cli,
    cfg: &Config,
    target: &str,
    listen: Option<String>,
    allow_lan: bool,
    system_proxy: bool,
) -> i32 {
    let mut cfg = cfg.clone();
    if allow_lan {
        cfg.listen.allow_lan = true;
    }
    if system_proxy {
        cfg.system_proxy.enabled = true;
    }
    let connector = effective_connector(&cfg, cli);
    let timeout = effective_timeout(&cfg, cli);
    let candidates = vpngate::resolve_target(target);
    let tunnel = match connect_first(&connector, &candidates, timeout).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("connect failed: {}", e);
            return 1;
        }
    };
    // Listen addresses: --listen overrides the local address (old
    // single-listener behavior); otherwise `listen_addrs()` — always
    // 127.0.0.1:local_port, or the same port on 0.0.0.0 when LAN
    // sharing is on (one mixed server, no second port). The system
    // proxy points at the loopback form of the first address.
    let (addrs, display): (Vec<String>, String) = match &listen {
        Some(a) => (vec![a.clone()], a.clone()),
        None => (cfg.listen.listen_addrs(), cfg.listen.display_addrs()),
    };
    let mut serves = tokio::task::JoinSet::new();
    for addr in &addrs {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => {
                serves.spawn(socks5::serve_mixed(l, tunnel.clone(), timeout, None));
            }
            Err(e) => {
                eprintln!(
                    "cannot bind mixed proxy listener {}: {} (port may be in use, try another port)",
                    addr, e
                );
                return 1;
            }
        }
    }
    let mut guard = None;
    if cfg.system_proxy.enabled {
        let loopback = vpngate_client::config::loopback_of(&addrs[0]);
        match sysproxy::SystemProxyGuard::set(&loopback, cfg.system_proxy.service.as_deref()) {
            Ok(g) => {
                println!("system proxy: {}", g.applied.as_deref().unwrap_or(""));
                guard = Some(g);
            }
            Err(e) => eprintln!("WARNING: could not set system proxy: {}", e),
        }
    }
    println!("tunnel virtual IP: {}", tunnel.vip);
    println!("本地混合代理（SOCKS5+HTTP）监听 {}", display);
    tokio::select! {
        _ = serves.join_next() => 0,
        _ = tokio::signal::ctrl_c() => {
            println!("\nCtrl-C, shutting down...");
            if let Some(g) = &guard {
                g.unset();
            }
            0
        }
    }
}

/// Launched with no subcommand (e.g. double-clicked in Explorer):
/// explain that this is the command-line build with no window, point
/// at the GUI exe in the same folder, show the basic usage, and wait
/// for Enter so the console window does not flash and vanish.
fn print_no_args_notice() {
    println!("vpngate-client 是命令行版本，没有窗口。");
    println!("想用图形界面，请双击同一文件夹里的 vpngate-gui.exe。");
    println!();
    println!("基本用法（在命令行里运行）：");
    println!("  vpngate-client list                    列出节点");
    println!("  vpngate-client probe <节点>            探测节点是否能连");
    println!(
        "  vpngate-client connect <节点>          连接并开本地混合代理（SOCKS5+HTTP，默认 127.0.0.1:10818）"
    );
    println!("  vpngate-client test <节点>             连接并测试隧道");
    println!("节点可以写 主机名:端口，例如 kanratown.opengw.net:992。");
    println!();
    println!("按回车键退出…");
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let Some(cmd) = &cli.cmd else {
        print_no_args_notice();
        return;
    };
    let cfg = load_config(&cli);
    let code = match cmd {
        Cmd::List { country, limit } => cmd_list(&cli, &cfg, country.clone(), *limit).await,
        Cmd::Probe { target } => cmd_probe(&cli, &cfg, target).await,
        Cmd::Connect {
            target,
            listen,
            allow_lan,
            system_proxy,
        } => {
            cmd_connect(
                &cli,
                &cfg,
                target,
                listen.clone(),
                *allow_lan,
                *system_proxy,
            )
            .await
        }
        Cmd::Test { target } => cmd_test(&cli, &cfg, target).await,
    };
    std::process::exit(code);
}
