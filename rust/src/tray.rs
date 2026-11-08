//! System tray (v3.12, Windows only): minimize-to-tray like
//! v2rayN / NekoBox — the X button hides the main window instead of
//! quitting, and the tray icon's menu offers 显示主界面 / 重启客户端 /
//! 退出.
//!
//! Only the icon/menu plumbing is Windows-only (`tray-icon` 0.19,
//! which pairs with eframe 0.36's winit 0.30). Everything testable
//! without a window — the close decision, the menu-id dispatch, the
//! restart command construction, the .ico parsing — is plain code in
//! this module and runs on Linux too, so `cargo test` covers it.
//! On Linux the GUI compiles a stub: no tray handle, X quits as
//! before.
//!
//! The whole module is behind the `gui` Cargo feature (see
//! `src/lib.rs`): its icon decoding needs the `image` crate, so a
//! `--no-default-features` (Android .so) build excludes it entirely,
//! tests included. Only the GUI binary uses this module.

use std::path::PathBuf;

/// What the tray asked the app to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayRequest {
    /// Show the main window again (tray click / menu 显示主界面).
    Show,
    /// Relaunch the exe and quit this instance (menu 重启客户端).
    Restart,
    /// Really quit (menu 退出).
    Quit,
}

/// Tray menu item ids — also the `MenuId` strings in the tray menu.
pub const MENU_SHOW: &str = "show";
pub const MENU_RESTART: &str = "restart";
pub const MENU_QUIT: &str = "quit";

/// Map a tray menu item id to the request it makes. Unknown ids
/// (a stale menu, a typo) map to nothing — never crash on a menu
/// event we did not build.
pub fn menu_action(id: &str) -> Option<TrayRequest> {
    match id {
        MENU_SHOW => Some(TrayRequest::Show),
        MENU_RESTART => Some(TrayRequest::Restart),
        MENU_QUIT => Some(TrayRequest::Quit),
        _ => None,
    }
}

/// What an X click (a `close_requested` flag) means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDecision {
    /// Hide the window to the tray; the app keeps running.
    HideToTray,
    /// Really quit: disconnect, restore the system proxy, save.
    Quit,
}

/// Decide what a close request does. With a live tray an X click
/// hides; an explicit quit — File menu 退出 or tray menu 退出,
/// both of which set `quit_requested` first — always really quits.
/// Without a tray (Linux, or tray creation failed on Windows) every
/// close request quits, exactly as before v3.12.
pub fn decide_close(tray_active: bool, quit_requested: bool) -> CloseDecision {
    if tray_active && !quit_requested {
        CloseDecision::HideToTray
    } else {
        CloseDecision::Quit
    }
}

/// Build the command that restarts the client: the current exe path
/// with the current arguments, so the new instance starts exactly
/// like this one was started. Since v3.14 a restart while connected
/// also writes a one-shot resume marker (`resume.json`, see
/// `write_resume_target`) so the new instance auto-connects to the
/// same node once; the command itself carries no node — the marker
/// is a file, not an argument. Only the command is built here;
/// spawning it is the GUI's job, so this stays unit-testable
/// without launching a process.
pub fn restart_command() -> std::io::Result<(PathBuf, Vec<String>)> {
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    Ok((exe, args))
}

/// The line written once — status bar and log — the first time the
/// window hides to the tray, so the user does not think the program
/// vanished.
pub const TRAY_HINT: &str = "已最小化到托盘，右键托盘图标可退出/显示主界面。";

/// PNG file magic (first 8 bytes).
const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Extract the largest PNG entry from a .ico file's bytes.
///
/// A .ico is a 6-byte header (count at bytes 4–5) plus one 16-byte
/// directory entry per image: width, height, colour count, reserved,
/// planes (u16), bit count (u16), byte size (u32 LE), offset
/// (u32 LE). Vista-style .ico files embed PNGs; our
/// `assets/icon.ico` holds five (16/24/32/48/256 px, v3.14) and the
/// 256 px one is the largest. Entries that are not PNGs (old BMP
/// entries) are skipped; a malformed file yields `None`. A width or
/// height byte of 0 means 256 px.
pub fn largest_png_in_ico(ico: &[u8]) -> Option<&[u8]> {
    let mut best: Option<&[u8]> = None;
    for png in ico_png_entries(ico) {
        if best.map_or(true, |b: &[u8]| png.len() > b.len()) {
            best = Some(png);
        }
    }
    best
}

/// Every PNG entry in a .ico file's bytes, in directory order.
/// Shared by `largest_png_in_ico` and `png_in_ico` so the directory
/// parsing lives in exactly one place.
fn ico_png_entries(ico: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    if ico.len() < 6 {
        return out;
    }
    let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
    for i in 0..count {
        let off = 6 + i * 16;
        if off + 16 > ico.len() {
            break;
        }
        let size = u32::from_le_bytes(
            ico[off + 8..off + 12].try_into().unwrap_or([0; 4]),
        ) as usize;
        let at = u32::from_le_bytes(
            ico[off + 12..off + 16].try_into().unwrap_or([0; 4]),
        ) as usize;
        let Some(end) = at.checked_add(size) else {
            continue;
        };
        let Some(data) = ico.get(at..end) else {
            continue;
        };
        if data.len() >= PNG_MAGIC.len() && &data[..8] == PNG_MAGIC {
            out.push(data);
        }
    }
    out
}

/// Extract the PNG entry of exactly `size` px from a .ico file's
/// bytes (`size` is the edge length: 16, 24, 32, 48 or 256 — a
/// directory byte of 0 means 256). `None` when the .ico has no such
/// entry or is malformed. v3.14: the tray takes the 16 px entry and
/// the window icon the 32 px entry, instead of both scaling the
/// largest one.
pub fn png_in_ico(ico: &[u8], size: u32) -> Option<&[u8]> {
    if ico.len() < 6 {
        return None;
    }
    let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
    for i in 0..count {
        let off = 6 + i * 16;
        if off + 16 > ico.len() {
            break;
        }
        let w = ico[off];
        let entry_size: u32 = if w == 0 { 256 } else { w as u32 };
        if entry_size != size {
            continue;
        }
        let data_size = u32::from_le_bytes(
            ico[off + 8..off + 12].try_into().ok()?,
        ) as usize;
        let at = u32::from_le_bytes(
            ico[off + 12..off + 16].try_into().ok()?,
        ) as usize;
        let data = ico.get(at..at.checked_add(data_size)?)?;
        if data.len() >= PNG_MAGIC.len() && &data[..8] == PNG_MAGIC {
            return Some(data);
        }
    }
    None
}

/// Decode one .ico entry of exactly `size` px into RGBA pixels:
/// `(rgba bytes, width, height)`. The caller feeds this to
/// `tray_icon::Icon::from_rgba` (tray, 16 px); the GUI wraps the
/// 32 px result in `egui::IconData` itself (window icon). Plain
/// PNG work, so it is tested on Linux too.
pub fn decode_icon_rgba(ico: &[u8], size: u32) -> Option<(Vec<u8>, u32, u32)> {
    let png = png_in_ico(ico, size)?;
    let img = image::load_from_memory(png).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    Some((rgba.into_raw(), w, h))
}

/// Decode the tray icon's RGBA pixels from the .ico bytes:
/// `(rgba bytes, width, height)`. v3.14: the 16 px entry — the
/// hand-tuned pixel稿 — not the 256 px entry downscaled by Windows
/// (that downscale is what made the v3.13 tray icon unreadable).
/// Falls back to the largest entry if a 16 px entry is missing, so
/// an old .ico still yields a tray icon instead of none.
/// High-DPI note: `tray-icon` 0.19 takes a single RGBA bitmap, so
/// only one size can be handed over. The tray's logical size is
/// 16 px; handing it the 16 px稿 means standard-DPI trays show the
/// hand-tuned pixels exactly, and on high-DPI Windows the shell
/// upscales those 16 px (slightly soft, but the 2 px strokes stay
/// legible). Handing it the 32 px稿 instead would make Windows
/// downscale on standard DPI — the same blur that v3.13 had, just
/// less of it — so 16 px is the right single choice.
pub fn decode_tray_icon_rgba(ico: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    decode_icon_rgba(ico, 16).or_else(|| {
        let png = largest_png_in_ico(ico)?;
        let img = image::load_from_memory(png).ok()?;
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        Some((rgba.into_raw(), w, h))
    })
}

/// Decode the window/taskbar icon's RGBA pixels: the 32 px entry
/// of the same .ico (v3.14 — the window icon used to be unset and
/// fell back to the exe default). v3.15: this returns a plain
/// `(rgba, width, height)` tuple and the GUI wraps it in
/// `egui::IconData` at the call site — the old `window_icon_data`
/// returned `eframe::egui::IconData` from this shared module and
/// dragged eframe/wgpu/winit into the CLI binary (which grew from
/// ~16 MB to ~34 MB for one icon conversion).
pub fn decode_window_icon_rgba(ico: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    decode_icon_rgba(ico, 32)
}

/// What happened on the tray icon itself, in platform-neutral terms
/// (the `tray-icon` event types are Windows-only, so the mapping
/// from event to request is split: the Windows code classifies the
/// event into one of these, and `tray_click_request` — plain code,
/// tested on Linux — decides what it means).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayClickKind {
    /// Left button released (a single click).
    SingleClickUp,
    /// Left button double-clicked.
    DoubleClick,
    /// Anything else on the icon (right click, middle click, …).
    Other,
}

/// Map a tray-icon click to the request it makes. v3.14 (Leo
/// 11:36): a left single-click is IGNORED — it no longer pops the
/// main window; only a left double-click shows it. The right-click
/// menu's 显示主界面 is a different path (`menu_action`) and is
/// unchanged.
pub fn tray_click_request(kind: TrayClickKind) -> Option<TrayRequest> {
    match kind {
        TrayClickKind::DoubleClick => Some(TrayRequest::Show),
        TrayClickKind::SingleClickUp | TrayClickKind::Other => None,
    }
}

// ---------------------------------------------------------------------------
// Restart-resume marker (v3.14): a one-shot "reconnect to this node"
// note, written by the old instance just before it restarts and
// consumed (file deleted) by the new instance at startup. A small
// JSON file next to the exe (`resume.json`), NOT a config.toml key:
// the portable config is user settings + auto-save, and a transient
// marker there would survive a manual quit and fire on the next
// manual open. The file carries the dialled target (`host:port`,
// DDNS suffix already completed, exactly as `node_label`), a display
// label, and the write time (unix seconds); a marker older than
// `RESUME_MAX_AGE_SECS` is stale (the new instance crashed before
// consuming it) and is ignored + removed, so it can never
// auto-connect a later manual open.
// ---------------------------------------------------------------------------

/// How long a resume marker stays valid: restart-to-startup is
/// seconds, so 10 minutes is generous and still bounds the
/// crash-window.
pub const RESUME_MAX_AGE_SECS: u64 = 600;

/// File name of the resume marker, next to the exe.
pub const RESUME_FILE_NAME: &str = "resume.json";

/// One restart-resume marker, as read back from `resume.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeTarget {
    /// Dialled target, e.g. "a.opengw.net:992".
    pub target: String,
    /// Display label (same string as `target` today).
    pub label: String,
}

/// `resume.json` next to the exe (portable location). `None` when
/// the exe path cannot be determined.
pub fn resume_file_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(RESUME_FILE_NAME)))
}

/// Write a resume marker (overwrites any stale one). Best-effort
/// from the caller's side: the restart proceeds without resume when
/// this fails.
pub fn write_resume_target(
    path: &std::path::Path,
    target: &str,
    label: &str,
) -> Result<(), String> {
    let created_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let text = serde_json::json!({
        "target": target,
        "label": label,
        "created_unix": created_unix,
    })
    .to_string();
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {}", path.display(), e))
}

/// Read + delete the resume marker, if there is a fresh valid one.
/// `None` (and the file removed when present) for a missing,
/// unparseable, target-less, or stale marker — a bad marker must
/// never auto-connect, and must not linger to fire later.
pub fn take_resume_target(path: &std::path::Path) -> Option<ResumeTarget> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return None,
    };
    // Consume exactly once: delete first, whatever the content says.
    let _ = std::fs::remove_file(path);
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let target = v.get("target")?.as_str()?.to_string();
    if target.is_empty() {
        return None;
    }
    let label = v
        .get("label")
        .and_then(|l| l.as_str())
        .unwrap_or(&target)
        .to_string();
    let created = v.get("created_unix").and_then(|c| c.as_u64()).unwrap_or(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if created == 0 || now.saturating_sub(created) > RESUME_MAX_AGE_SECS {
        return None;
    }
    Some(ResumeTarget { target, label })
}

/// Best-effort removal of a resume marker (manual quit: a later
/// manual open must never auto-connect). Ignores all errors.
pub fn clear_resume_target(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Windows-only tray plumbing (tray-icon 0.19)
// ---------------------------------------------------------------------------

/// The live tray icon. Dropping it removes the icon from the tray
/// (tray-icon's Windows backend issues NIM_DELETE on drop), so the
/// quit path must `take()` the handle — never leak it.
#[cfg(windows)]
pub struct TrayHandle {
    _tray: tray_icon::TrayIcon,
}

#[cfg(windows)]
impl TrayHandle {
    /// Build the tray icon (from `assets/icon.ico`, the program's
    /// own icon) and its right-click menu: 显示主界面 / 重启客户端 /
    /// 退出. Any failure returns the reason as a string — the caller
    /// logs it and runs without a tray, so a broken tray never
    /// breaks the program (X then quits as before).
    pub fn new() -> Result<Self, String> {
        let (rgba, w, h) =
            decode_tray_icon_rgba(include_bytes!("../assets/icon.ico"))
                .ok_or_else(|| "托盘图标解码失败（assets/icon.ico）".to_string())?;
        let icon = tray_icon::Icon::from_rgba(rgba, w, h)
            .map_err(|e| format!("托盘图标无效：{e}"))?;
        let menu = tray_icon::menu::Menu::new();
        for (id, label) in [
            (MENU_SHOW, "显示主界面"),
            (MENU_RESTART, "重启客户端"),
        ] {
            menu.append(&tray_icon::menu::MenuItem::with_id(
                id, label, true, None,
            ))
            .map_err(|e| format!("托盘菜单创建失败：{e}"))?;
        }
        menu.append(&tray_icon::menu::PredefinedMenuItem::separator())
            .map_err(|e| format!("托盘菜单创建失败：{e}"))?;
        menu.append(&tray_icon::menu::MenuItem::with_id(
            MENU_QUIT, "退出", true, None,
        ))
        .map_err(|e| format!("托盘菜单创建失败：{e}"))?;
        let tray = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("VPNGate 客户端")
            .with_icon(icon)
            .build()
            .map_err(|e| format!("托盘创建失败：{e}"))?;
        Ok(Self { _tray: tray })
    }

    /// Drain pending tray-icon and menu events into requests.
    /// Left single-click (button released) is IGNORED in v3.14 —
    /// it no longer shows the main window (Leo 11:36); only a left
    /// double-click shows it. Anything else on the icon itself is
    /// ignored. The right-click menu is the tray-icon default:
    /// right-clicking the icon pops the menu, no code needed.
    pub fn drain_requests(&self) -> Vec<TrayRequest> {
        let mut out = Vec::new();
        while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
            let kind = match ev {
                tray_icon::TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                } => TrayClickKind::SingleClickUp,
                tray_icon::TrayIconEvent::DoubleClick {
                    button: tray_icon::MouseButton::Left,
                    ..
                } => TrayClickKind::DoubleClick,
                _ => TrayClickKind::Other,
            };
            if let Some(req) = tray_click_request(kind) {
                out.push(req);
            }
        }
        while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if let Some(req) = menu_action(&ev.id.0) {
                out.push(req);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_close_hides_only_with_tray_and_no_quit_request() {
        assert_eq!(
            decide_close(true, false),
            CloseDecision::HideToTray,
            "X with a live tray hides"
        );
        assert_eq!(
            decide_close(true, true),
            CloseDecision::Quit,
            "an explicit quit (tray/File 退出) really quits"
        );
        assert_eq!(
            decide_close(false, false),
            CloseDecision::Quit,
            "no tray (Linux, or tray creation failed) quits as before"
        );
        assert_eq!(decide_close(false, true), CloseDecision::Quit);
    }

    #[test]
    fn menu_action_maps_all_three_items_and_nothing_else() {
        assert_eq!(menu_action(MENU_SHOW), Some(TrayRequest::Show));
        assert_eq!(menu_action(MENU_RESTART), Some(TrayRequest::Restart));
        assert_eq!(menu_action(MENU_QUIT), Some(TrayRequest::Quit));
        assert_eq!(menu_action(""), None);
        assert_eq!(menu_action("show-me"), None);
    }

    #[test]
    fn restart_command_is_the_current_exe_with_current_args() {
        let (exe, args) = restart_command().expect("current_exe must work");
        assert!(
            exe.is_file(),
            "the restart target must be a real file, got: {}",
            exe.display()
        );
        assert_eq!(
            args,
            std::env::args().skip(1).collect::<Vec<_>>(),
            "arguments must round-trip (the new instance starts like this one)"
        );
    }

    #[test]
    fn largest_png_in_ico_finds_the_256px_entry() {
        let ico = include_bytes!("../assets/icon.ico");
        let png = largest_png_in_ico(ico).expect("icon.ico must hold a PNG");
        assert_eq!(&png[..8], PNG_MAGIC);
        // The 256 px entry is the largest of the five (v3.15 ring
        // icon; was 2266 bytes for the v3.13 bold-V). Assert the
        // decoded size, not a byte count — the byte count changes
        // with every redraw.
        let img = image::load_from_memory(png).expect("256 px entry decodes");
        assert_eq!(img.to_rgba8().dimensions(), (256, 256));
    }

    #[test]
    fn png_in_ico_finds_all_five_sizes() {
        // v3.14: the .ico carries one native PNG per size (v3.13
        // lacked the 24 px entry). Each must be found by exact size.
        let ico = include_bytes!("../assets/icon.ico");
        for size in [16u32, 24, 32, 48] {
            let png = png_in_ico(ico, size)
                .unwrap_or_else(|| panic!("icon.ico must hold a {} px entry", size));
            assert_eq!(&png[..8], PNG_MAGIC);
            let img = image::load_from_memory(png).expect("entry decodes");
            assert_eq!(img.to_rgba8().dimensions(), (size as u32, size as u32));
        }
        // 256 px is stored with a 0 width/height byte.
        let png = png_in_ico(ico, 256).expect("icon.ico must hold a 256 px entry");
        let img = image::load_from_memory(png).expect("256 px entry decodes");
        assert_eq!(img.to_rgba8().dimensions(), (256, 256));
        assert_eq!(png_in_ico(ico, 20), None, "no 20 px entry exists");
        assert_eq!(png_in_ico(&[], 16), None);
    }

    #[test]
    fn decode_tray_icon_rgba_is_16x16() {
        // v3.14: the tray uses the hand-tuned 16 px稿, NOT the
        // 256 px entry downscaled by Windows (that was the v3.13
        // tray blur).
        let ico = include_bytes!("../assets/icon.ico");
        let (rgba, w, h) =
            decode_tray_icon_rgba(ico).expect("icon.ico must decode");
        assert_eq!((w, h), (16, 16));
        assert_eq!(rgba.len(), 16 * 16 * 4);
    }

    #[test]
    fn decode_tray_icon_rgba_matches_ico_16px_entry() {
        // v3.15: the tray icon is the .ico's 16 px entry, byte
        // for byte — not a rescale of any other entry. If the
        // 16 px entry ever changes without the tray following,
        // this fails.
        let ico = include_bytes!("../assets/icon.ico");
        let (rgba, w, h) =
            decode_tray_icon_rgba(ico).expect("icon.ico must decode");
        assert_eq!((w, h), (16, 16));
        let png = png_in_ico(ico, 16).expect("16 px entry must exist");
        let expected = image::load_from_memory(png)
            .expect("16 px entry decodes")
            .to_rgba8()
            .into_raw();
        assert_eq!(
            rgba, expected,
            "tray RGBA must equal the 16 px entry decoded directly"
        );
    }

    #[test]
    fn icon_sizes_share_one_ring_shape() {
        // v3.15: all five .ico entries are the same ring — a
        // square pure-white bbox (outer diameter 0.58–0.65S;
        // Leo's band is 62–68%, the AA edge pixels move the
        // pure-white bbox a little) with an indigo hole in the
        // middle, never a white centre. The v3.14 shield fails
        // this at every size: its bbox is taller than wide
        // (0.625S wide but 0.71–0.75S tall), so a shield .ico
        // would fail the height band — this is the regression
        // test for "five sizes, one ring".
        let ico = include_bytes!("../assets/icon.ico");
        for size in [16u32, 24, 32, 48, 256] {
            let png = png_in_ico(ico, size).unwrap_or_else(|| {
                panic!("icon.ico must hold a {} px entry", size)
            });
            let img = image::load_from_memory(png).expect("entry decodes");
            let rgba = img.to_rgba8();
            assert_eq!(rgba.dimensions(), (size, size));
            let (mut min_x, mut max_x) = (size, 0u32);
            let (mut min_y, mut max_y) = (size, 0u32);
            for (x, y, p) in rgba.enumerate_pixels() {
                if *p == image::Rgba([255, 255, 255, 255]) {
                    min_x = min_x.min(x);
                    max_x = max_x.max(x);
                    min_y = min_y.min(y);
                    max_y = max_y.max(y);
                }
            }
            let bw = max_x - min_x + 1;
            let bh = max_y - min_y + 1;
            let wf = bw as f32 / size as f32;
            let hf = bh as f32 / size as f32;
            assert!(
                (0.55..=0.70).contains(&wf),
                "{} px entry: white width fraction {} is outside 0.55-0.70",
                size, wf
            );
            assert!(
                (0.55..=0.70).contains(&hf),
                "{} px entry: white height fraction {} is outside 0.55-0.70",
                size, hf
            );
            assert!(
                (bw as i32 - bh as i32).abs() <= 1,
                "{} px entry: the ring bbox must be square, got {}x{}",
                size, bw, bh
            );
            let centre = rgba.get_pixel(size / 2, size / 2);
            assert_ne!(
                *centre,
                image::Rgba([255, 255, 255, 255]),
                "{} px entry: the centre must be the indigo hole, not white",
                size
            );
        }
    }

    #[test]
    fn decode_window_icon_rgba_is_32x32() {
        // v3.14: the window/taskbar icon is the 32 px entry from
        // the same .ico (ViewportBuilder.with_icon).
        let ico = include_bytes!("../assets/icon.ico");
        let (rgba, w, h) =
            decode_window_icon_rgba(ico).expect("icon.ico must decode");
        assert_eq!((w, h), (32, 32));
        assert_eq!(rgba.len(), 32 * 32 * 4);
        // v3.15: the tuple is what the GUI wraps in IconData —
        // garbage in means no icon, not a crash.
        assert_eq!(decode_window_icon_rgba(&[]), None);
        assert_eq!(decode_window_icon_rgba(b"not an icon"), None);
    }

    #[test]
    fn tray_click_single_is_ignored_double_shows() {
        // v3.14 (Leo 11:36): a left single-click on the tray icon
        // must NOT pop the main window; a left double-click still
        // does. The right-click menu's 显示主界面 is untouched
        // (menu_action test above still maps it to Show).
        assert_eq!(
            tray_click_request(TrayClickKind::SingleClickUp),
            None,
            "single click must produce no request"
        );
        assert_eq!(
            tray_click_request(TrayClickKind::DoubleClick),
            Some(TrayRequest::Show),
            "double-click must still show the window"
        );
        assert_eq!(
            tray_click_request(TrayClickKind::Other),
            None,
            "anything else on the icon is ignored"
        );
    }

    fn resume_tmp_path(name: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("vpngate-resume-test-{}-{}.json", n, name))
    }

    #[test]
    fn resume_roundtrip_and_consumed_once() {
        // v3.14 restart-resume: write once, take once, second take
        // finds nothing (the marker is single-use) and the file is
        // gone.
        let path = resume_tmp_path("once");
        write_resume_target(&path, "a.opengw.net:992", "a.opengw.net:992")
            .expect("write resume");
        assert!(path.exists(), "resume file must exist after write");
        let rt = take_resume_target(&path).expect("first take must find it");
        assert_eq!(rt.target, "a.opengw.net:992");
        assert_eq!(rt.label, "a.opengw.net:992");
        assert!(!path.exists(), "take must delete the file");
        assert_eq!(take_resume_target(&path), None, "second take finds nothing");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resume_stale_file_is_ignored_and_removed() {
        // A resume file older than the 10-minute window (e.g. the
        // new instance crashed before consuming it) must NOT
        // auto-connect on the next manual open — it is ignored and
        // the stale file is removed.
        let path = resume_tmp_path("stale");
        let old = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        let text = format!(
            "{{\"target\":\"a.opengw.net:992\",\"label\":\"a.opengw.net:992\",\"created_unix\":{}}}",
            old
        );
        std::fs::write(&path, text).unwrap();
        assert_eq!(take_resume_target(&path), None, "stale resume ignored");
        assert!(!path.exists(), "stale file must be removed");
    }

    #[test]
    fn resume_bad_file_is_ignored_and_removed() {
        // Missing file, garbage, or a JSON without the target must
        // never auto-connect — and the bad file is removed so it
        // cannot fire later.
        let path = resume_tmp_path("bad");
        assert_eq!(take_resume_target(&path), None, "missing file is fine");
        std::fs::write(&path, "not json at all").unwrap();
        assert_eq!(take_resume_target(&path), None, "garbage ignored");
        assert!(!path.exists(), "garbage file must be removed");
        std::fs::write(&path, "{\"label\":\"x\"}").unwrap();
        assert_eq!(take_resume_target(&path), None, "no-target JSON ignored");
        assert!(!path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resume_file_path_is_next_to_exe() {
        let p = resume_file_path().expect("exe path known in tests");
        assert_eq!(p.file_name().unwrap(), "resume.json");
        assert!(p.parent().is_some());
    }
}
