//! TOML configuration. CLI flags override the file; the file is optional.
//!
//! Portable layout: the program keeps everything next to its own
//! executable, nothing in %APPDATA% or the user profile. Config is read
//! from (in order) `--config <path>`, `config.toml` next to the exe,
//! `./config.toml` in the working directory; if none exists, defaults
//! are used. The GUI's "保存设置" writes to `config.toml` next to the
//! exe, so the whole folder can be copied elsewhere and keeps working.
//!
//! Example (`config.example.toml`):
//! ```toml
//! [front_proxy]
//! enabled = false
//! addr = "127.0.0.1:1080"
//! # username = ""
//! # password = ""
//!
//! [listen]
//! addr = "127.0.0.1"
//! local_port = 10818
//! allow_lan = false
//!
//! [system_proxy]
//! enabled = false
//! # service = "Wi-Fi"   # macOS network service name
//!
//! [tunnel]
//! timeout_secs = 10
//!
//! [ui]
//! node_col_widths = [90, 130, 64, 88, 80, 190, 90]
//! ```

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct Config {
    #[serde(default)]
    pub front_proxy: FrontProxy,
    #[serde(default)]
    pub listen: Listen,
    #[serde(default)]
    pub system_proxy: SystemProxy,
    #[serde(default)]
    pub tunnel: Tunnel,
    #[serde(default)]
    pub ui: UiSettings,
    /// Hostnames the user deleted from the node list (multi-select
    /// delete). They stay hidden for this session only: the next
    /// explicit refresh clears the whole list first and brings the
    /// full list back (v3.11, Leo's call — delete is session-only
    /// hiding). Until then they stay out of every list load — API
    /// refresh, web scrape, cache, embedded fallback — and out of
    /// the startup load. Stored as canonical completed hostnames
    /// (see `blocked_key` in the GUI); empty by default, so old
    /// config files load unchanged.
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FrontProxy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_front_addr")]
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl Default for FrontProxy {
    fn default() -> Self {
        Self {
            enabled: false,
            addr: default_front_addr(),
            username: None,
            password: None,
        }
    }
}

fn default_front_addr() -> String {
    "127.0.0.1:1080".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Listen {
    #[serde(default = "default_listen_addr")]
    pub addr: String,
    /// Local mixed-proxy port (SOCKS5 + HTTP on one port). `port`
    /// stays accepted as an alias so config files written by older
    /// versions keep working. Old files may also still carry a
    /// `lan_port` key (pre-v3.7 separate LAN port) — serde ignores
    /// unknown fields, so it loads fine and is dropped on save.
    #[serde(default = "default_local_port", alias = "port")]
    pub local_port: u16,
    #[serde(default)]
    pub allow_lan: bool,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            addr: default_listen_addr(),
            local_port: default_local_port(),
            allow_lan: false,
        }
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_local_port() -> u16 {
    10818
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SystemProxy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub service: Option<String>,
}

impl Default for SystemProxy {
    fn default() -> Self {
        Self {
            enabled: false,
            service: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Tunnel {
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout(),
        }
    }
}

fn default_timeout() -> u64 {
    10
}

/// GUI-only settings: no effect on the CLI.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct UiSettings {
    /// Node-list column widths in pixels, in display order: country,
    /// ISP, 当前人数， 线路质量， 人均带宽， host:port, latency/status.
    /// Draggable at the header separators in the GUI (every resizable
    /// column but the last has one); persisted with the rest of the
    /// settings via auto-save. Pre-v3.7 configs stored only 4 widths
    /// (country, ISP, host:port, latency/status) and v3.12 configs
    /// stored 6 — those load too, with the newer columns taking
    /// their defaults (see `de_col_widths`).
    #[serde(default = "default_col_widths", deserialize_with = "de_col_widths")]
    pub node_col_widths: [u16; 7],
    /// Node-list box height in pixels, once the user has dragged its
    /// resize handle (v3.13). `None` = never dragged: the GUI uses
    /// its formula default (`panel_h - 250`, at least 120 px) instead,
    /// so old configs (no such key) and fresh installs behave exactly
    /// as before until the user drags. Whole pixels (`u16`, like
    /// `node_col_widths` — `UiSettings` derives `Eq`, which `f32`
    /// cannot satisfy); the GUI keeps the live value as `f32` and
    /// rounds on save. A dragged value is clamped on use (see
    /// `clamp_list_height`): at least 120 px, at most the panel
    /// height minus room for the rest of the UI.
    #[serde(default)]
    pub list_height: Option<u16>,
    /// Advanced-settings box height in pixels (the CollapsingHeader
    /// body scrolls inside it, v3.13). Default 240 px; clamped to
    /// 120–600 px on use (see `clamp_advanced_height`).
    #[serde(default = "default_advanced_height")]
    pub advanced_height: u16,
    /// Log box height in pixels (v3.13). Default 90 px (the old
    /// hard-coded value); clamped to 60–400 px on use (see
    /// `clamp_log_height`).
    #[serde(default = "default_log_height")]
    pub log_height: u16,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            node_col_widths: default_col_widths(),
            list_height: None,
            advanced_height: default_advanced_height(),
            log_height: default_log_height(),
        }
    }
}

/// Default advanced-settings box height (v3.13): the body holds the
/// manual-add row, front-proxy grid, test button, save row and log
/// path — about 280 px of content, so 240 px shows most of it with
/// the rest one scroll away.
fn default_advanced_height() -> u16 {
    240
}

/// Default log box height: the pre-v3.13 hard-coded value.
fn default_log_height() -> u16 {
    90
}

/// Clamp a dragged node-list height to its sane range for the current
/// panel height: never below 120 px, never so tall the buttons /
/// advanced section / log below it have no room (panel minus 150 px).
pub fn clamp_list_height(h: f32, panel_h: f32) -> f32 {
    h.clamp(120.0, (panel_h - 150.0).max(120.0))
}

/// Clamp a dragged advanced-settings height: 120–600 px.
pub fn clamp_advanced_height(h: f32) -> f32 {
    h.clamp(120.0, 600.0)
}

/// Clamp a dragged log height: 60–400 px.
pub fn clamp_log_height(h: f32) -> f32 {
    h.clamp(60.0, 400.0)
}

fn default_col_widths() -> [u16; 7] {
    [90, 130, 64, 88, 80, 190, 90]
}

/// Accept the current 7-element `node_col_widths`, the v3.12
/// 6-element form, and the pre-v3.7 4-element form. The 6-element
/// order was (country, ISP, 当前人数， 线路质量， host:port,
/// latency/status); the new 人均带宽 column (index 4) takes its
/// default and the old host:port and latency/status values move to
/// indices 5 and 6. The 4-element order was (country, ISP,
/// host:port, latency/status); the three newer columns （当前人数 at
/// index 2, 线路质量 at index 3, 人均带宽 at index 4) take their
/// defaults, and the old host:port and latency/status values move
/// to indices 5 and 6. Any other length (a hand-edited file, a
/// future shape) falls back to the defaults rather than failing the
/// whole config load.
fn de_col_widths<'de, D>(deserializer: D) -> Result<[u16; 7], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let widths = Vec::<u16>::deserialize(deserializer)?;
    Ok(match widths.len() {
        7 => [
            widths[0], widths[1], widths[2], widths[3], widths[4], widths[5], widths[6],
        ],
        6 => {
            let d = default_col_widths();
            [
                widths[0], widths[1], widths[2], widths[3], d[4], widths[4], widths[5],
            ]
        }
        4 => {
            let d = default_col_widths();
            [widths[0], widths[1], d[2], d[3], d[4], widths[2], widths[3]]
        }
        _ => default_col_widths(),
    })
}

impl Config {
    /// Directory holding this executable — the portable home for
    /// `config.toml` and `nodes_cache.json`. `None` when the exe path
    /// cannot be determined (rare; then only the working directory
    /// is used).
    pub fn portable_dir() -> Option<PathBuf> {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    }

    /// `config.toml` next to the executable (portable location), whether
    /// or not the file exists yet. This is where the GUI saves settings.
    pub fn portable_config_path() -> Option<PathBuf> {
        Self::portable_dir().map(|d| d.join("config.toml"))
    }

    /// Where to load the config from: an explicit `--config` path first,
    /// then `config.toml` next to the exe if it exists, then
    /// `./config.toml` in the working directory if it exists.
    /// `None` means "no file — use defaults".
    pub fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = explicit {
            return Some(p.to_path_buf());
        }
        if let Some(p) = Self::portable_config_path() {
            if p.exists() {
                return Some(p);
            }
        }
        let cwd = PathBuf::from("config.toml");
        if cwd.exists() {
            return Some(cwd);
        }
        None
    }

    /// Load from `path` if it exists; otherwise return defaults.
    /// A missing file is not an error.
    pub fn load(path: Option<&Path>) -> Result<Config, String> {
        let Some(path) = path else {
            return Ok(Config::default());
        };
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {}", path.display(), e))?;
        toml::from_str(&text).map_err(|e| format!("cannot parse config {}: {}", path.display(), e))
    }

    /// Write this config as TOML to `path` (creates parent dirs if
    /// needed). Used by the GUI's "保存设置".
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = toml::to_string(self).map_err(|e| format!("cannot encode config: {}", e))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
            }
        }
        std::fs::write(path, text)
            .map_err(|e| format!("cannot write config {}: {}", path.display(), e))
    }
}

impl Listen {
    /// Addresses to actually bind: always `addr:local_port`, and
    /// when LAN sharing is on the SAME port on all interfaces
    /// (`0.0.0.0:local_port`) instead — one mixed (SOCKS5+HTTP)
    /// server, one port. A wildcard bind already serves loopback,
    /// so 127.0.0.1 and 0.0.0.0 are never bound together on the
    /// same port (the second bind would fail with "address in use").
    pub fn listen_addrs(&self) -> Vec<String> {
        if self.allow_lan {
            vec![format!("0.0.0.0:{}", self.local_port)]
        } else {
            vec![format!("{}:{}", self.addr, self.local_port)]
        }
    }

    /// What the user sees for the local proxy: the loopback address
    /// always, plus the LAN address when sharing is on — even though
    /// that is a single wildcard bind under the hood (see
    /// `listen_addrs`). E.g. "127.0.0.1:10818" or
    /// "127.0.0.1:10818 ＋ 0.0.0.0:10818".
    pub fn display_addrs(&self) -> String {
        if self.allow_lan {
            format!(
                "127.0.0.1:{} ＋ 0.0.0.0:{}",
                self.local_port, self.local_port
            )
        } else {
            format!("{}:{}", self.addr, self.local_port)
        }
    }

    /// Loopback address of the local proxy — what the system proxy
    /// and browsers should point at (a 0.0.0.0 bind is not a usable
    /// proxy address).
    pub fn loopback_addr(&self) -> String {
        format!("127.0.0.1:{}", self.local_port)
    }
}

/// The loopback form of a listen address: a `0.0.0.0:port` bind
/// becomes `127.0.0.1:port`; anything else passes through unchanged.
/// Used for the system-proxy target (and `--listen` overrides).
pub fn loopback_of(addr: &str) -> String {
    match addr.strip_prefix("0.0.0.0:") {
        Some(rest) => format!("127.0.0.1:{}", rest),
        None => addr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(name: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vpngate-cfg-test-{}-{}.toml", n, name))
    }

    #[test]
    fn save_load_roundtrip() {
        let mut cfg = Config::default();
        cfg.front_proxy.enabled = true;
        cfg.front_proxy.addr = "127.0.0.1:1080".to_string();
        cfg.front_proxy.username = Some("u".to_string());
        cfg.front_proxy.password = Some("p".to_string());
        cfg.listen.local_port = 10809;
        cfg.listen.allow_lan = true;
        cfg.system_proxy.enabled = true;
        cfg.tunnel.timeout_secs = 15;
        let path = tmp_path("roundtrip");
        cfg.save(&path).expect("save works");
        let back = Config::load(Some(&path)).expect("load works");
        assert!(back.front_proxy.enabled);
        assert_eq!(back.front_proxy.username.as_deref(), Some("u"));
        assert_eq!(back.front_proxy.password.as_deref(), Some("p"));
        assert_eq!(back.listen.local_port, 10809);
        assert!(back.listen.allow_lan);
        assert!(back.system_proxy.enabled);
        assert_eq!(back.tunnel.timeout_secs, 15);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listen_addrs_local_always_lan_same_port() {
        let mut l = Listen::default();
        assert_eq!(l.listen_addrs(), vec!["127.0.0.1:10818".to_string()]);
        assert_eq!(l.display_addrs(), "127.0.0.1:10818");
        assert_eq!(l.loopback_addr(), "127.0.0.1:10818");
        l.allow_lan = true;
        // One wildcard bind on the SAME port (it already serves
        // loopback); the display still names both reachabilities.
        assert_eq!(l.listen_addrs(), vec!["0.0.0.0:10818".to_string()]);
        assert_eq!(l.display_addrs(), "127.0.0.1:10818 ＋ 0.0.0.0:10818");
        assert_eq!(l.loopback_addr(), "127.0.0.1:10818");
        assert_eq!(loopback_of("0.0.0.0:10818"), "127.0.0.1:10818");
        assert_eq!(loopback_of("127.0.0.1:10818"), "127.0.0.1:10818");
        assert_eq!(loopback_of("192.168.1.2:10818"), "192.168.1.2:10818");
    }

    #[test]
    fn old_lan_port_key_is_ignored_not_an_error() {
        // Pre-v3.7 configs carry a separate lan_port; loading one
        // must not fail, and the old value must not come back.
        let cfg: Config = toml::from_str(
            "[listen]\nlocal_port = 10818\nlan_port = 10809\nallow_lan = true\n",
        )
        .unwrap();
        assert_eq!(cfg.listen.local_port, 10818);
        assert!(cfg.listen.allow_lan);
        assert_eq!(cfg.listen.listen_addrs(), vec!["0.0.0.0:10818".to_string()]);
        // Saving drops the stale key.
        let path = tmp_path("old-lan-port");
        cfg.save(&path).expect("save works");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("lan_port"), "saved config drops lan_port: {}", text);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn old_port_key_still_parses_as_local_port() {
        let cfg: Config = toml::from_str("[listen]\nport = 10811\n").unwrap();
        assert_eq!(cfg.listen.local_port, 10811);
    }

    #[test]
    fn ui_col_widths_default_and_roundtrip() {
        let cfg = Config::default();
        assert_eq!(cfg.ui.node_col_widths, [90, 130, 64, 88, 80, 190, 90]);
        let parsed: Config = toml::from_str(
            "[ui]\nnode_col_widths = [120, 140, 70, 95, 80, 200, 100]\n",
        )
        .unwrap();
        assert_eq!(parsed.ui.node_col_widths, [120, 140, 70, 95, 80, 200, 100]);
        // A config file without [ui] keeps the defaults.
        let parsed2: Config = toml::from_str("[listen]\nlocal_port = 10818\n").unwrap();
        assert_eq!(parsed2.ui.node_col_widths, [90, 130, 64, 88, 80, 190, 90]);
        assert_eq!(parsed2.listen.local_port, 10818);
        let path = tmp_path("ui-widths");
        parsed.save(&path).expect("save works");
        let back = Config::load(Some(&path)).expect("load works");
        assert_eq!(back.ui.node_col_widths, [120, 140, 70, 95, 80, 200, 100]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ui_col_widths_migrates_old_6_element_config() {
        // A v3.12 config stored 6 widths (country, ISP, 当前人数,
        // 线路质量, host:port, latency/status). Loading it keeps
        // those six values in place and inserts the new 人均带宽
        // column (default 80) at index 4, shifting host:port and
        // latency/status to indices 5 and 6 — no error, no lost
        // settings.
        let parsed: Config = toml::from_str(
            "[ui]\nnode_col_widths = [120, 140, 70, 95, 200, 100]\n",
        )
        .unwrap();
        assert_eq!(
            parsed.ui.node_col_widths,
            [120, 140, 70, 95, 80, 200, 100]
        );
        // Saving writes the new 7-element form, which loads back
        // unchanged.
        let path = tmp_path("ui-widths-migrate-6");
        parsed.save(&path).expect("save works");
        let text = std::fs::read_to_string(&path).expect("saved file readable");
        assert!(
            text.contains("node_col_widths = [120, 140, 70, 95, 80, 200, 100]"),
            "saved as 7 elements: {}",
            text
        );
        let back = Config::load(Some(&path)).expect("load works");
        assert_eq!(back.ui.node_col_widths, [120, 140, 70, 95, 80, 200, 100]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ui_col_widths_migrates_old_4_element_config() {
        // A pre-v3.7 config stored [country, ISP, host:port,
        // latency/status]. Loading it keeps those four values in
        // place and fills the three newer columns （当前人数 /
        // 线路质量 / 人均带宽） with their defaults — no error, no
        // lost settings.
        let parsed: Config =
            toml::from_str("[ui]\nnode_col_widths = [120, 140, 200, 100]\n").unwrap();
        assert_eq!(
            parsed.ui.node_col_widths,
            [120, 140, 64, 88, 80, 200, 100]
        );
        // Saving writes the new 7-element form, which loads back
        // unchanged.
        let path = tmp_path("ui-widths-migrate");
        parsed.save(&path).expect("save works");
        let text = std::fs::read_to_string(&path).expect("saved file readable");
        assert!(
            text.contains("node_col_widths = [120, 140, 64, 88, 80, 200, 100]"),
            "saved as 7 elements: {}",
            text
        );
        let back = Config::load(Some(&path)).expect("load works");
        assert_eq!(back.ui.node_col_widths, [120, 140, 64, 88, 80, 200, 100]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ui_col_widths_unexpected_length_falls_back_to_default() {
        // A hand-edited array of any other length must not fail the
        // whole config load — it falls back to the defaults.
        for n in [1, 3, 5, 8] {
            let widths: Vec<u16> = (0..n).map(|i| 50 + i as u16).collect();
            let text = format!(
                "[ui]\nnode_col_widths = [{}]\n",
                widths
                    .iter()
                    .map(|w| w.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let parsed: Config = toml::from_str(&text).unwrap();
            assert_eq!(
                parsed.ui.node_col_widths,
                [90, 130, 64, 88, 80, 190, 90],
                "{}-element array should fall back to defaults",
                n
            );
        }
    }

    #[test]
    fn ui_panel_heights_default_roundtrip_and_old_config() {
        // v3.13: fresh defaults — list undragged (None = formula),
        // advanced 240 px, log 90 px (the old hard-coded value).
        let cfg = Config::default();
        assert_eq!(cfg.ui.list_height, None);
        assert_eq!(cfg.ui.advanced_height, 240);
        assert_eq!(cfg.ui.log_height, 90);
        // Explicit values round-trip through save/load.
        let parsed: Config = toml::from_str(
            "[ui]\nlist_height = 300\nadvanced_height = 200\nlog_height = 120\n",
        )
        .unwrap();
        assert_eq!(parsed.ui.list_height, Some(300));
        assert_eq!(parsed.ui.advanced_height, 200);
        assert_eq!(parsed.ui.log_height, 120);
        let path = tmp_path("ui-heights");
        parsed.save(&path).expect("save works");
        let back = Config::load(Some(&path)).expect("load works");
        assert_eq!(back.ui.list_height, Some(300));
        assert_eq!(back.ui.advanced_height, 200);
        assert_eq!(back.ui.log_height, 120);
        let _ = std::fs::remove_file(&path);
        // Old config files carry none of the three keys: they load
        // with the defaults, not an error.
        let old: Config =
            toml::from_str("[ui]\nnode_col_widths = [90, 130, 64, 88, 80, 190, 90]\n").unwrap();
        assert_eq!(old.ui.list_height, None);
        assert_eq!(old.ui.advanced_height, 240);
        assert_eq!(old.ui.log_height, 90);
    }

    #[test]
    fn panel_height_clamps() {
        // List: at least 120 px; at most panel minus 150 px (and
        // never below 120 even on a tiny panel).
        assert_eq!(clamp_list_height(50.0, 600.0), 120.0);
        assert_eq!(clamp_list_height(500.0, 600.0), 450.0);
        assert_eq!(clamp_list_height(300.0, 600.0), 300.0);
        assert_eq!(clamp_list_height(500.0, 420.0), 270.0);
        assert_eq!(clamp_list_height(500.0, 200.0), 120.0);
        // Advanced: 120–600 px. Log: 60–400 px.
        assert_eq!(clamp_advanced_height(50.0), 120.0);
        assert_eq!(clamp_advanced_height(900.0), 600.0);
        assert_eq!(clamp_advanced_height(240.0), 240.0);
        assert_eq!(clamp_log_height(10.0), 60.0);
        assert_eq!(clamp_log_height(900.0), 400.0);
        assert_eq!(clamp_log_height(90.0), 90.0);
    }

    #[test]
    fn blocked_hosts_default_empty_and_roundtrip() {
        let cfg = Config::default();
        assert!(cfg.blocked_hosts.is_empty());
        // Old config files carry no blocked_hosts key: they load
        // with an empty blocklist, not an error.
        let parsed: Config = toml::from_str("[listen]\nlocal_port = 10818\n").unwrap();
        assert!(parsed.blocked_hosts.is_empty());
        let mut cfg = Config::default();
        cfg.blocked_hosts = vec![
            "b.opengw.net".to_string(),
            "a.opengw.net".to_string(),
        ];
        let path = tmp_path("blocked-hosts");
        cfg.save(&path).expect("save works");
        let back = Config::load(Some(&path)).expect("load works");
        assert_eq!(
            back.blocked_hosts,
            vec!["b.opengw.net".to_string(), "a.opengw.net".to_string()]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_prefers_explicit_path() {
        let p = PathBuf::from("does-not-exist.toml");
        assert_eq!(Config::resolve_config_path(Some(&p)), Some(p));
    }

    #[test]
    fn portable_path_is_next_to_exe() {
        let p = Config::portable_config_path().expect("exe path known in tests");
        assert_eq!(p.file_name().unwrap(), "config.toml");
        assert!(p.parent().is_some());
    }
}
