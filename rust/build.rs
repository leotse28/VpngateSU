//! Windows-only: embed `assets/icon.ico` into the executables
//! (both `vpngate-gui.exe` and `vpngate-client.exe` share one icon).
//!
//! No new crates: the resource compiler is invoked directly
//! (mingw `windres` when cross-compiling, `rc.exe` for MSVC).
//! Linux/macOS builds skip this entirely. If the icon or the
//! resource compiler is missing, the build still succeeds — just
//! without an embedded icon (a `cargo:warning` is printed).
//!
//! Regenerate the icon with: `python3 assets/make_icon.py`

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("windows") {
        return;
    }
    let icon = Path::new("assets/icon.ico");
    if !icon.exists() {
        println!("cargo:warning=assets/icon.ico not found; building without an embedded icon (run python3 assets/make_icon.py to generate it)");
        return;
    }
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // .rc with an absolute icon path (avoids windres CWD issues).
    let icon_abs = icon.canonicalize().unwrap_or_else(|_| icon.to_path_buf());
    let icon_str = icon_abs.to_string_lossy().replace('\\', "/");
    let rc_path = out_dir.join("vpngate_icon.rc");
    if std::fs::write(&rc_path, format!("1 ICON \"{}\"\n", icon_str)).is_err() {
        println!("cargo:warning=cannot write icon .rc; building without an embedded icon");
        return;
    }
    // Pick the resource compiler: WINDRES env > mingw windres (cross)
    // > plain windres > rc.exe (MSVC).
    let candidates: Vec<String> = if let Ok(w) = std::env::var("WINDRES") {
        vec![w]
    } else if target.contains("gnu") {
        vec![
            "x86_64-w64-mingw32-windres".to_string(),
            "windres".to_string(),
        ]
    } else {
        vec!["rc.exe".to_string()]
    };
    for tool in &candidates {
        let is_rc = tool.to_lowercase().ends_with("rc.exe");
        let out = out_dir.join(if is_rc {
            "vpngate_icon.res"
        } else {
            "vpngate_icon.o"
        });
        let status = if is_rc {
            Command::new(tool)
                .arg("/fo")
                .arg(&out)
                .arg(&rc_path)
                .status()
        } else {
            Command::new(tool)
                .arg(&rc_path)
                .arg("-O")
                .arg("coff")
                .arg("--target=pe-x86-64")
                .arg("-o")
                .arg(&out)
                .status()
        };
        match status {
            Ok(s) if s.success() => {
                println!("cargo:rustc-link-arg={}", out.display());
                return;
            }
            _ => continue,
        }
    }
    println!("cargo:warning=no resource compiler found (windres/rc.exe); building without an embedded icon");
}
