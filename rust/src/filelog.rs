//! Append-only file log for the GUI (`vpngate-gui.log` next to the exe).
//!
//! The on-screen log only keeps the last 100 lines and vanishes when
//! the program closes, so a failure Leo reports later ("the refresh
//! failed yesterday") cannot be diagnosed from it. The file log keeps
//! every line (info / warning / error) with a local timestamp, so the
//! file next to the exe is the first thing to ask for when debugging.
//!
//! Rules:
//! * **Never log passwords.** The session header only takes the front
//!   proxy's enabled flag and address — there is no password parameter
//!   anywhere in this module, and the test
//!   `session_header_never_logs_password` proves a config with a
//!   password set still produces a header without it.
//! * **Never crash the GUI.** A file that cannot be opened makes the
//!   logger a no-op (`open_failed` is set so the caller can warn once
//!   in the UI log); a failed write disables the logger silently.
//! * **Rotation at 2 MiB.** When the file would grow past the limit it
//!   is renamed to `vpngate-gui.log.old` (replacing a stale one) and a
//!   fresh file starts. A failed rename truncates the file instead;
//!   a failed reopen disables the logger.

use crate::config::Config;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default rotation limit: 2 MiB.
pub const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

/// File name, always next to the exe (portable dir, same as config.toml).
pub const LOG_FILE_NAME: &str = "vpngate-gui.log";

/// Path of the rotated file for a given log path: the log path with
/// ".old" appended (`vpngate-gui.log` -> `vpngate-gui.log.old`, the
/// same name as before for the real log). Per-path, not a fixed
/// name in the directory — so two loggers in the same directory
/// (e.g. two tests running in parallel) never share a `.old` file
/// and cannot delete each other's rotated log mid-test.
pub fn old_log_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".old");
    PathBuf::from(s)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn tag(self) -> &'static str {
        match self {
            LogLevel::Info => "[INFO]",
            LogLevel::Warn => "[WARN]",
            LogLevel::Error => "[ERROR]",
        }
    }
}

/// Local timestamp `YYYY-MM-DD HH:MM:SS`.
pub fn local_timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// One log line: `2026-11-07 19:45:03 [INFO] message`.
pub fn format_line(level: LogLevel, message: &str) -> String {
    format!("{} {} {}", local_timestamp(), level.tag(), message)
}

/// Session-header lines for the start of a run: start time, version,
/// exe path, config path, front proxy enabled + address. Built from a
/// `Config` so the header can never see the proxy password — the
/// header only reads `front_proxy.enabled` / `front_proxy.addr`.
/// Pure (no I/O), so tests can prove the no-password property.
pub fn session_header_lines(
    cfg: &Config,
    exe_path: Option<&Path>,
    config_path: Option<&Path>,
) -> Vec<String> {
    let mut lines = vec![format!(
        "=== VPNGate 客户端启动，版本 {} ===",
        env!("CARGO_PKG_VERSION")
    )];
    lines.push(format!(
        "程序：{}",
        exe_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "未知".to_string())
    ));
    lines.push(format!(
        "配置：{}",
        config_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "默认设置（没有 config.toml）".to_string())
    ));
    if cfg.front_proxy.enabled {
        lines.push(format!("前置代理：已启用 {}", cfg.front_proxy.addr));
    } else {
        lines.push("前置代理：未启用".to_string());
    }
    lines
}

/// `vpngate-gui.log` next to the exe (portable dir). The caller falls
/// back to `./vpngate-gui.log` when the portable dir is unknown.
pub fn log_path_for_dir(dir: &Path) -> PathBuf {
    dir.join(LOG_FILE_NAME)
}

pub struct FileLogger {
    path: PathBuf,
    file: Option<File>,
    bytes_written: u64,
    max_bytes: u64,
    /// True when the file could not be opened (at construction, at a
    /// rotation, or after a failed write). The caller shows this once
    /// in the UI log; logging itself stays a no-op.
    pub open_failed: bool,
    /// The open/rotation error text, if any (for the one-time warning).
    pub open_error: Option<String>,
}

impl FileLogger {
    /// Open (or create) `path` for appending.
    pub fn new(path: &Path) -> Self {
        Self::with_max_bytes(path, MAX_LOG_BYTES)
    }

    /// Same as `new`, with a custom rotation limit (tests use a small one).
    pub fn with_max_bytes(path: &Path, max_bytes: u64) -> Self {
        let bytes_written = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Self {
                path: path.to_path_buf(),
                file: Some(file),
                bytes_written,
                max_bytes,
                open_failed: false,
                open_error: None,
            },
            Err(e) => Self {
                path: path.to_path_buf(),
                file: None,
                bytes_written,
                max_bytes,
                open_failed: true,
                open_error: Some(e.to_string()),
            },
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_open(&self) -> bool {
        self.file.is_some()
    }

    /// Write the session header (see `session_header_lines`).
    pub fn write_header(
        &mut self,
        cfg: &Config,
        exe_path: Option<&Path>,
        config_path: Option<&Path>,
    ) {
        for line in session_header_lines(cfg, exe_path, config_path) {
            self.log(LogLevel::Info, &line);
        }
    }

    /// Append one line (with timestamp and level tag). No-op when the
    /// file is not open. Rotates first when the line would push the
    /// file past the limit. Never panics, never propagates an error.
    pub fn log(&mut self, level: LogLevel, message: &str) {
        if self.file.is_none() {
            return;
        }
        let line = format_line(level, message);
        let line_len = (line.len() + 1) as u64; // +1 for the newline
        if self.bytes_written > 0 && self.bytes_written + line_len > self.max_bytes {
            self.rotate();
            if self.file.is_none() {
                return;
            }
        }
        let Some(f) = self.file.as_mut() else {
            return;
        };
        match f.write_all(line.as_bytes()) {
            Ok(()) => match f.write_all(b"\n") {
                Ok(()) => {
                    self.bytes_written += line_len;
                    let _ = f.flush();
                }
                Err(e) => self.disable(e.to_string()),
            },
            Err(e) => self.disable(e.to_string()),
        }
    }

    /// Rotate: rename the current file to `.old` and start fresh. A
    /// failed rename falls back to truncating the file in place; a
    /// failed reopen disables the logger.
    fn rotate(&mut self) {
        // Close our handle first (dropping is what closes it).
        self.file.take();
        let old_path = old_log_path(&self.path);
        let _ = std::fs::remove_file(&old_path);
        let renamed = std::fs::rename(&self.path, &old_path).is_ok();
        let opened = if renamed {
            OpenOptions::new().create(true).append(true).open(&self.path)
        } else {
            // Rename failed (e.g. another process holds the file):
            // truncate in place instead of losing the log entirely.
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)
        };
        match opened {
            Ok(file) => {
                self.file = Some(file);
                self.bytes_written = 0;
            }
            Err(e) => self.disable(e.to_string()),
        }
    }

    fn disable(&mut self, err: String) {
        self.file = None;
        self.open_failed = true;
        self.open_error = Some(err);
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
        std::env::temp_dir().join(format!("vpngate-log-test-{}-{}.log", n, name))
    }

    fn cleanup(paths: &[PathBuf]) {
        for p in paths {
            let _ = std::fs::remove_file(p);
        }
    }

    /// `YYYY-MM-DD HH:MM:SS` — 19 chars, separators at fixed places.
    fn looks_like_timestamp(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() == 19
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b' '
            && b[13] == b':'
            && b[16] == b':'
            && b.iter()
                .enumerate()
                .all(|(i, c)| [4, 7, 10, 13, 16].contains(&i) || c.is_ascii_digit())
    }

    #[test]
    fn timestamp_format_is_local_yyyymmdd_hhmmss() {
        let ts = local_timestamp();
        assert!(
            looks_like_timestamp(&ts),
            "timestamp must be YYYY-MM-DD HH:MM:SS, got {}",
            ts
        );
    }

    #[test]
    fn writes_lines_with_timestamp_and_level() {
        let path = tmp_path("lines");
        let old = old_log_path(&path);
        let mut log = FileLogger::new(&path);
        assert!(log.is_open(), "fresh temp file must open");
        log.log(LogLevel::Info, "hello info");
        log.log(LogLevel::Warn, "a warning");
        log.log(LogLevel::Error, "an error");
        drop(log);
        let text = std::fs::read_to_string(&path).expect("log file written");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "three lines: {}", text);
        assert!(lines[0].ends_with("[INFO] hello info"), "line 0: {}", lines[0]);
        assert!(lines[1].ends_with("[WARN] a warning"), "line 1: {}", lines[1]);
        assert!(lines[2].ends_with("[ERROR] an error"), "line 2: {}", lines[2]);
        for l in &lines {
            let ts: String = l.chars().take(19).collect();
            assert!(
                looks_like_timestamp(&ts),
                "line must start with a timestamp: {}",
                l
            );
        }
        cleanup(&[path, old]);
    }

    #[test]
    fn rotates_after_max_bytes_and_keeps_old() {
        let path = tmp_path("rotate");
        let old = old_log_path(&path);
        // Each line is ~50 bytes ("YYYY-MM-DD HH:MM:SS [INFO] " is 27
        // + "rotation line number N" is 22 + newline): with a 200-byte
        // limit, lines 0-3 fill the file, line 4 rotates (.old gets
        // lines 0-3), lines 4-7 fill it again, line 8 rotates again
        // (.old gets lines 4-7) and the current file ends with 8-9.
        let mut log = FileLogger::with_max_bytes(&path, 200);
        for i in 0..10 {
            log.log(LogLevel::Info, &format!("rotation line number {}", i));
        }
        drop(log);
        assert!(old.exists(), ".old file must exist after rotation");
        let old_text = std::fs::read_to_string(&old).expect(".old readable");
        assert!(
            old_text.contains("rotation line number 4"),
            ".old keeps the previous generation: {}",
            old_text
        );
        assert!(
            old_text.contains("rotation line number 7"),
            ".old keeps the whole previous generation: {}",
            old_text
        );
        assert!(
            !old_text.contains("rotation line number 9"),
            ".old must not contain the latest line: {}",
            old_text
        );
        let cur_text = std::fs::read_to_string(&path).expect("current log readable");
        assert!(
            (cur_text.len() as u64) <= 200,
            "current file stays within the limit: {} bytes",
            cur_text.len()
        );
        assert!(
            cur_text.contains("rotation line number 8")
                && cur_text.contains("rotation line number 9"),
            "current file keeps the latest lines: {}",
            cur_text
        );
        cleanup(&[path, old]);
    }

    #[test]
    fn session_header_never_logs_password() {
        let mut cfg = Config::default();
        cfg.front_proxy.enabled = true;
        cfg.front_proxy.addr = "192.168.236.197:10808".to_string();
        cfg.front_proxy.username = Some("some-user".to_string());
        cfg.front_proxy.password = Some("s3cr3t-pw-do-not-log".to_string());
        let lines = session_header_lines(
            &cfg,
            Some(Path::new("C:\\tools\\vpngate-gui.exe")),
            Some(Path::new("C:\\tools\\config.toml")),
        );
        let joined = lines.join("\n");
        assert!(
            !joined.contains("s3cr3t-pw-do-not-log"),
            "header must never contain the password: {}",
            joined
        );
        assert!(
            !joined.contains("some-user"),
            "header must not contain the proxy username either: {}",
            joined
        );
        assert!(joined.contains("192.168.236.197:10808"), "addr: {}", joined);
        assert!(joined.contains("已启用"), "enabled flag: {}", joined);
        // The version in the header tracks the package version; never
        // hardcode it here, or the next version bump breaks this test.
        assert!(
            joined.contains(env!("CARGO_PKG_VERSION")),
            "version: {}",
            joined
        );
        // Disabled proxy: no address at all.
        let cfg2 = Config::default();
        let lines2 = session_header_lines(&cfg2, None, None);
        let joined2 = lines2.join("\n");
        assert!(joined2.contains("未启用"), "disabled: {}", joined2);
        assert!(joined2.contains("默认设置"), "no config file: {}", joined2);
    }

    #[test]
    fn open_failure_is_not_fatal() {
        // Parent directory does not exist: the open must fail cleanly.
        let path = std::env::temp_dir()
            .join("vpngate-log-test-no-such-dir")
            .join("vpngate-gui.log");
        let mut log = FileLogger::new(&path);
        assert!(!log.is_open());
        assert!(log.open_failed);
        assert!(log.open_error.is_some());
        log.log(LogLevel::Error, "this must not panic");
        log.write_header(&Config::default(), None, None);
    }

    #[test]
    fn header_written_to_file() {
        let path = tmp_path("header");
        let old = old_log_path(&path);
        let mut cfg = Config::default();
        cfg.front_proxy.enabled = true;
        cfg.front_proxy.addr = "192.168.236.197:10808".to_string();
        let mut log = FileLogger::new(&path);
        log.write_header(&cfg, Some(Path::new("vpngate-gui.exe")), None);
        drop(log);
        let text = std::fs::read_to_string(&path).expect("log file written");
        assert!(text.contains("VPNGate 客户端启动"), "header: {}", text);
        assert!(text.contains("192.168.236.197:10808"), "addr: {}", text);
        assert!(text.contains("[INFO]"), "header lines are INFO: {}", text);
        cleanup(&[path, old]);
    }
}
