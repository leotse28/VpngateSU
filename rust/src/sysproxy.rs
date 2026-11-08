//! Optional system-proxy mode.
//!
//! When enabled, `connect` points the OS system proxy at the local
//! SOCKS5 port and restores the previous state on exit (Ctrl-C).
//! When disabled, nothing here is touched.
//!
//! * Windows: `reg.exe` on
//!   `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
//!   (`ProxyEnable`, `ProxyServer`).
//! * macOS: `networksetup -setwebproxy/-setsecurewebproxy` on the
//!   configured network service (default `Wi-Fi`).
//! * Linux: `gsettings org.gnome.system.proxy` (GNOME); if `gsettings`
//!   is absent, prints `export` lines for the user instead of failing.
//!
//! All of it is best-effort: a failure is reported, not fatal.

use std::process::Command;

pub struct SystemProxyGuard {
    /// Human-readable description of what was applied (for logging).
    pub applied: Option<String>,
    listen: String,
    service: Option<String>,
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {}: {}", cmd, e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!(
            "{} {:?} failed: {}",
            cmd,
            args,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

impl SystemProxyGuard {
    /// Set the system proxy to `listen` (e.g. "127.0.0.1:10818").
    /// Returns a guard; dropping the guard does NOT unset — call
    /// [`SystemProxyGuard::unset`] explicitly on clean shutdown.
    pub fn set(listen: &str, service: Option<&str>) -> Result<Self, String> {
        let applied = set_impl(listen, service)?;
        Ok(Self {
            applied: Some(applied),
            listen: listen.to_string(),
            service: service.map(|s| s.to_string()),
        })
    }

    pub fn unset(&self) {
        if self.applied.is_none() {
            return;
        }
        match unset_impl(&self.listen, self.service.as_deref()) {
            Ok(msg) => println!("system proxy restored: {}", msg),
            Err(e) => eprintln!("WARNING: failed to restore system proxy: {}", e),
        }
    }
}

#[cfg(target_os = "windows")]
fn set_impl(listen: &str, _service: Option<&str>) -> Result<String, String> {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    run(
        "reg",
        &[
            "add",
            key,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ],
    )?;
    run(
        "reg",
        &[
            "add",
            key,
            "/v",
            "ProxyServer",
            "/t",
            "REG_SZ",
            "/d",
            listen,
            "/f",
        ],
    )?;
    Ok(format!("Windows system proxy -> {}", listen))
}

#[cfg(target_os = "windows")]
fn unset_impl(_listen: &str, _service: Option<&str>) -> Result<String, String> {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    run(
        "reg",
        &[
            "add",
            key,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ],
    )?;
    Ok("Windows system proxy disabled".to_string())
}

#[cfg(target_os = "macos")]
fn set_impl(listen: &str, service: Option<&str>) -> Result<String, String> {
    let svc = service.unwrap_or("Wi-Fi");
    let (host, port) = listen.split_once(':').ok_or("bad listen addr")?;
    run("networksetup", &["-setwebproxy", svc, host, port])?;
    run("networksetup", &["-setwebproxystate", svc, "on"])?;
    run("networksetup", &["-setsecurewebproxy", svc, host, port])?;
    run("networksetup", &["-setsecurewebproxystate", svc, "on"])?;
    Ok(format!("macOS system proxy ({}) -> {}", svc, listen))
}

#[cfg(target_os = "macos")]
fn unset_impl(_listen: &str, service: Option<&str>) -> Result<String, String> {
    let svc = service.unwrap_or("Wi-Fi");
    run("networksetup", &["-setwebproxystate", svc, "off"])?;
    run("networksetup", &["-setsecurewebproxystate", svc, "off"])?;
    Ok(format!("macOS system proxy ({}) disabled", svc))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn set_impl(listen: &str, _service: Option<&str>) -> Result<String, String> {
    // GNOME gsettings, if present and usable.
    if Command::new("gsettings").arg("--version").output().is_ok() {
        let (host, port) = listen.split_once(':').ok_or("bad listen addr")?;
        let ok = run(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "manual"],
        )
        .is_ok()
            && run(
                "gsettings",
                &["set", "org.gnome.system.proxy.socks", "host", host],
            )
            .is_ok()
            && run(
                "gsettings",
                &["set", "org.gnome.system.proxy.socks", "port", port],
            )
            .is_ok();
        if ok {
            return Ok(format!("GNOME system proxy (SOCKS) -> {}", listen));
        }
        // gsettings exists but the schema is missing (e.g. headless VM):
        // fall through to the export-lines hint instead of failing.
    }
    // No supported desktop proxy API: hand the user shell lines instead.
    Ok(format!(
        "no usable system-proxy API (gsettings missing or schema absent); set it yourself:\n  export http_proxy=socks5://{0}\n  export https_proxy=socks5://{0}\n  export all_proxy=socks5://{0}",
        listen
    ))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn unset_impl(_listen: &str, _service: Option<&str>) -> Result<String, String> {
    if Command::new("gsettings").arg("--version").output().is_ok() {
        if run(
            "gsettings",
            &["set", "org.gnome.system.proxy", "mode", "auto"],
        )
        .is_ok()
        {
            return Ok("GNOME system proxy set back to auto".to_string());
        }
    }
    Ok(
        "nothing to restore (no usable gsettings); unset the exported variables yourself"
            .to_string(),
    )
}
