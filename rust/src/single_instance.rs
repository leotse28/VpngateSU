//! Single-instance guard for the GUI (v3.15), plus the restart
//! handover wait that shares its waiting logic.
//!
//! Only the GUI (`vpngate-gui.exe`) is single-instance — the CLI
//! (`vpngate-client.exe`) is a command-line tool and is exempt.
//! A second launch must not open a second window: it signals the
//! running instance to come forward (restore + focus — the same
//! effect as a tray double-click, `show_main_window`) and then
//! exits.
//!
//! Mechanism (Windows, no new dependencies — the Win32 calls are
//! declared here as `extern "system"`, the same pattern as the
//! `GetProcessMemoryInfo` extern in `vpngate-gui.rs`):
//! * Lock: a named mutex `Local\VPNGATE-LITE-SingleInstance`.
//!   The OS releases it when the owning process exits, so a
//!   crashed instance can never leave a stale lock behind.
//! * Signal: a named auto-reset event
//!   `Local\VPNGATE-LITE-ShowWindow`. The running instance's
//!   watcher thread waits on it and sets `show_requested` +
//!   requests a repaint; `ui()` then shows the window.
//! * Restart handover: the tray's 重启客户端 spawns the successor
//!   with a hidden `--restart-wait-pid <old pid>` argument (see
//!   `prepare_restart`). The successor is NOT a duplicate launch:
//!   it first waits for the old process to exit
//!   (`wait_for_pid_exit`, up to `PID_WAIT_TIMEOUT_MS`), and only
//!   then takes the lock. If the old process is still alive after
//!   that, the lock wait runs once more (up to
//!   `LOCK_WAIT_TIMEOUT_MS`) as a backstop, and only then does the
//!   successor give up, signal the old instance, and exit. A plain
//!   double-click (no wait-pid argument) never waits: lock held
//!   means an instance is running, so it signals and exits at
//!   once.
//!
//! Non-Windows (Linux/macOS dev builds only): the same shapes
//! with files instead of kernel objects — an atomic `create_new`
//! lock file carrying the owner's pid (a dead pid is stolen, so
//! a crash cannot wedge it) and a show-request file the watcher
//! thread polls. The production target is Windows-only, so the
//! file backend exists so the acquire/second-fails/stale-steal
//! logic is testable in the VM.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(not(windows))]
use std::path::PathBuf;

/// Hidden argument the restart flow passes to its successor:
/// `--restart-wait-pid <old pid>`. Never shown in help text; only
/// `restart_client` writes it and `main()` reads it.
pub const RESTART_WAIT_PID_ARG: &str = "--restart-wait-pid";

/// How long a restart successor waits for the old process to
/// exit before it goes on (the old instance disconnects and quits
/// right after spawning it, so the usual handover is well under a
/// second; the timeout only bites when the old process is hung).
pub const PID_WAIT_TIMEOUT_MS: u64 = 10_000;

/// Backstop wait for the single-instance lock, restart
/// successors only: after the pid wait, the lock should already
/// be free — this covers the (near-impossible) case where the pid
/// wait lied. A plain double-click never waits at all.
pub const LOCK_WAIT_TIMEOUT_MS: u64 = 5_000;

/// Poll interval for both waits.
pub const LOCK_POLL_MS: u64 = 250;

/// Windows named mutex for the single-instance lock.
#[cfg(windows)]
const MUTEX_NAME: &str = "Local\\VPNGATE-LITE-SingleInstance";
/// Windows named auto-reset event a second launch sets to ask the
/// running instance to show its window.
#[cfg(windows)]
const SHOW_EVENT_NAME: &str = "Local\\VPNGATE-LITE-ShowWindow";

/// Parse the hidden restart argument out of the process
/// arguments (everything after the exe name). `Some(pid)` when
/// `--restart-wait-pid <pid>` is present with a numeric pid.
pub fn parse_restart_wait_pid(args: &[String]) -> Option<u32> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == RESTART_WAIT_PID_ARG {
            return it.next().and_then(|v| v.parse::<u32>().ok());
        }
    }
    None
}

/// Drop a stale `--restart-wait-pid <pid>` pair from an argument
/// list (a restart successor that restarts again must not hand
/// its own wait-pid down — the new successor waits for THIS
/// process, not the grandparent). Every other argument is kept,
/// in order.
pub fn restart_args_without_wait_pid(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if a == RESTART_WAIT_PID_ARG {
            let _ = it.next();
        } else {
            out.push(a.clone());
        }
    }
    out
}

/// Pure half of the lock wait: keep waiting while the lock is
/// held and the budget is not spent. A plain double-click never
/// enters the wait at all (its timeout is 0); a restart
/// successor waits up to `LOCK_WAIT_TIMEOUT_MS`.
pub fn should_keep_waiting_for_lock(
    lock_held: bool,
    waited_ms: u64,
    timeout_ms: u64,
) -> bool {
    lock_held && waited_ms < timeout_ms
}

/// Wait until the process `pid` has exited, or the timeout
/// expires. A pid that does not exist returns `true` at once.
/// Windows waits on the real process handle (immune to pid
/// reuse); other platforms poll `/proc/<pid>`.
pub fn wait_for_pid_exit(pid: u32, timeout_ms: u64) -> bool {
    #[cfg(windows)]
    {
        wait_for_pid_exit_windows(pid, timeout_ms)
    }
    #[cfg(not(windows))]
    {
        wait_for_pid_exit_proc(pid, timeout_ms)
    }
}

#[cfg(not(windows))]
fn wait_for_pid_exit_proc(pid: u32, timeout_ms: u64) -> bool {
    let start = Instant::now();
    loop {
        if !PathBuf::from(format!("/proc/{}", pid)).exists() {
            return true;
        }
        if start.elapsed().as_millis() as u64 >= timeout_ms {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
fn wait_for_pid_exit_windows(pid: u32, timeout_ms: u64) -> bool {
    let start = Instant::now();
    loop {
        let handle = unsafe { OpenProcess(0x0010_0000, 0, pid) };
        if handle.is_null() {
            // 87 = ERROR_INVALID_PARAMETER: no such process — it
            // is already gone. Any other error (e.g. 5, access
            // denied) means the process exists: keep polling.
            if unsafe { GetLastError() } == 87 {
                return true;
            }
        } else {
            let remaining =
                timeout_ms.saturating_sub(start.elapsed().as_millis() as u64);
            let r = unsafe { WaitForSingleObject(handle, remaining as u32) };
            unsafe { CloseHandle(handle) };
            if r == 0 {
                return true; // WAIT_OBJECT_0: the process exited.
            }
            if r == 0x102 {
                return false; // WAIT_TIMEOUT.
            }
            return false; // WAIT_FAILED or abandoned: give up waiting.
        }
        if start.elapsed().as_millis() as u64 >= timeout_ms {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---------------------------------------------------------------------------
// Windows FFI (kernel32 only; no new crates)
// ---------------------------------------------------------------------------

#[cfg(windows)]
type Handle = *mut std::ffi::c_void;

#[cfg(windows)]
extern "system" {
    fn CreateMutexW(
        attrs: *const std::ffi::c_void,
        initial_owner: i32,
        name: *const u16,
    ) -> Handle;
    fn CreateEventW(
        attrs: *const std::ffi::c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> Handle;
    fn OpenEventW(desired_access: u32, inherit: i32, name: *const u16) -> Handle;
    fn SetEvent(handle: Handle) -> i32;
    fn OpenProcess(desired_access: u32, inherit: i32, pid: u32) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// The lock itself
// ---------------------------------------------------------------------------

/// The held single-instance lock. Dropping it releases the lock
/// (Windows: closing the mutex handle; other platforms: removing
/// the lock file). It must live for the whole process — `main()`
/// holds it on its stack across `run_native`.
pub struct SingleInstanceGuard {
    #[cfg(windows)]
    mutex: Handle,
    #[cfg(windows)]
    event: Handle,
    #[cfg(not(windows))]
    lock_path: PathBuf,
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.event);
            CloseHandle(self.mutex);
        }
    }
}

#[cfg(not(windows))]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Try to take the single-instance lock once, right now.
/// `Some(guard)` when this process owns it; `None` when another
/// instance already holds it (or the lock could not be created).
/// Windows: named mutex (+ the show event is created with it).
/// Other platforms: atomic `create_new` lock file holding the
/// owner's pid — a lock whose pid is dead is stolen.
fn try_acquire_lock() -> Option<SingleInstanceGuard> {
    #[cfg(windows)]
    {
        let name = wide(MUTEX_NAME);
        let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if mutex.is_null() {
            return None;
        }
        if unsafe { GetLastError() } == 183 {
            // ERROR_ALREADY_EXISTS: another instance holds it.
            // This handle is a second reference to the same mutex
            // — close it and report "held".
            unsafe { CloseHandle(mutex) };
            return None;
        }
        // We own the lock: create the show event the second launch
        // will set (auto-reset, initially unset). If that fails the
        // lock still holds — the event is best-effort, the mutex
        // is the lock.
        let event_name = wide(SHOW_EVENT_NAME);
        let event = unsafe {
            CreateEventW(std::ptr::null(), 0, 0, event_name.as_ptr())
        };
        if event.is_null() {
            unsafe { CloseHandle(mutex) };
            return None;
        }
        Some(SingleInstanceGuard { mutex, event })
    }
    #[cfg(not(windows))]
    {
        let path = lock_file_path();
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{}", std::process::id());
                Some(SingleInstanceGuard { lock_path: path })
            }
            Err(_) => {
                // Held — or stale (owner dead): read the pid and
                // steal the lock when its owner is gone.
                let dead = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|t| t.trim().parse::<u32>().ok())
                    .map(|pid| !PathBuf::from(format!("/proc/{}", pid)).exists())
                    .unwrap_or(false);
                if dead {
                    let _ = std::fs::remove_file(&path);
                    return try_acquire_lock();
                }
                None
            }
        }
    }
}

/// Where the non-Windows lock file lives (dev builds only).
#[cfg(not(windows))]
fn lock_file_path() -> PathBuf {
    std::env::temp_dir().join("vpngate-gui-single-instance.lock")
}

/// Where the non-Windows show-request file lives (dev builds
/// only): a second launch creates it, the watcher deletes it.
#[cfg(not(windows))]
fn show_file_path() -> PathBuf {
    std::env::temp_dir().join("vpngate-gui-show-window")
}

/// One poll of the non-Windows show file: when it exists, remove
/// it and raise `flag`. Returns whether a show was requested.
/// The watcher thread just calls this in a loop.
#[cfg(not(windows))]
fn check_show_file_once(flag: &AtomicBool) -> bool {
    let path = show_file_path();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
        flag.store(true, Ordering::SeqCst);
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Startup outcome + signalling
// ---------------------------------------------------------------------------

/// What `acquire_startup` decided this process is.
pub enum StartupOutcome {
    /// This process owns the lock: run the GUI. The guard must
    /// be kept alive for the whole process.
    Primary(SingleInstanceGuard),
    /// Another instance is running (and has been signalled to
    /// show its window): exit without opening a window.
    SecondInstance,
}

/// Take the lock, or signal the running instance and report
/// `SecondInstance`. `wait_pid` is `Some(old pid)` exactly when
/// this process is a restart successor (spawned by
/// `restart_client` with `--restart-wait-pid`): it first waits
/// for the old process to exit, then — as a backstop — waits for
/// the lock itself. A plain launch (`None`) never waits: a held
/// lock means a live instance, so it signals and exits at once.
///
/// One waiting policy for both the restart handover and the
/// single-instance lock — the two never get separate timers.
pub fn acquire_startup(wait_pid: Option<u32>) -> StartupOutcome {
    if let Some(pid) = wait_pid {
        // The old instance disconnects and quits right after
        // spawning us; wait for it to actually be gone, so the
        // local port and the lock are both free before we bind
        // or connect. A hung old process just costs the timeout.
        let _ = wait_for_pid_exit(pid, PID_WAIT_TIMEOUT_MS);
    }
    if let Some(guard) = try_acquire_lock() {
        return StartupOutcome::Primary(guard);
    }
    if wait_pid.is_some() {
        // Backstop: the pid wait above should already have freed
        // the lock — if it did not, poll a little longer before
        // concluding this is a duplicate launch.
        let start = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(LOCK_POLL_MS));
            if let Some(guard) = try_acquire_lock() {
                return StartupOutcome::Primary(guard);
            }
            if !should_keep_waiting_for_lock(
                true,
                start.elapsed().as_millis() as u64,
                LOCK_WAIT_TIMEOUT_MS,
            ) {
                break;
            }
        }
    }
    signal_existing();
    StartupOutcome::SecondInstance
}

/// Ask the running instance to show its window (best-effort: a
/// missing event / unwritable file just means the signal is
/// lost — the running instance stays as it is, and this process
/// still exits). Windows retries opening the event briefly: the
/// primary creates it in `main()` just after taking the lock, so
/// a second launch racing that window still gets through.
pub fn signal_existing() {
    #[cfg(windows)]
    {
        let name = wide(SHOW_EVENT_NAME);
        for _ in 0..5 {
            let handle =
                unsafe { OpenEventW(0x0010_0002, 0, name.as_ptr()) };
            if !handle.is_null() {
                unsafe {
                    SetEvent(handle);
                    CloseHandle(handle);
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    #[cfg(not(windows))]
    {
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(show_file_path());
    }
}

/// Watch for a second launch's show request and raise `flag`
/// (plus `on_signal`, normally a repaint request) when one
/// arrives. Spawned once, from `GuiApp::new` — only the primary
/// instance ever gets there, so the watcher always belongs to
/// the lock owner. The thread is detached; it dies with the
/// process.
pub fn spawn_show_watcher(
    flag: Arc<AtomicBool>,
    on_signal: impl Fn() + Send + Sync + 'static,
) {
    std::thread::spawn(move || {
        #[cfg(windows)]
        {
            // Open the event the primary created in `main()`
            // (retry: `GuiApp::new` runs just after it).
            let name = wide(SHOW_EVENT_NAME);
            let handle = loop {
                let h =
                    unsafe { OpenEventW(0x0010_0000, 0, name.as_ptr()) };
                if !h.is_null() {
                    break h;
                }
                std::thread::sleep(Duration::from_millis(250));
            };
            loop {
                // Auto-reset: each SetEvent releases exactly one
                // wait, so one second launch means one show.
                let r = unsafe { WaitForSingleObject(handle, 0xFFFF_FFFF) };
                if r == 0 {
                    flag.store(true, Ordering::SeqCst);
                    on_signal();
                } else {
                    // WAIT_FAILED / abandoned: the event is gone;
                    // nothing more to wait on, so the thread ends.
                    break;
                }
            }
        }
        #[cfg(not(windows))]
        {
            loop {
                if check_show_file_once(&flag) {
                    on_signal();
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_restart_wait_pid_finds_the_flag() {
        assert_eq!(
            parse_restart_wait_pid(&[
                "--restart-wait-pid".to_string(),
                "1234".to_string()
            ]),
            Some(1234)
        );
        assert_eq!(
            parse_restart_wait_pid(&[
                "--front".to_string(),
                "x".to_string(),
                "--restart-wait-pid".to_string(),
                "99".to_string(),
            ]),
            Some(99)
        );
        assert_eq!(parse_restart_wait_pid(&[]), None);
        assert_eq!(
            parse_restart_wait_pid(&["--restart-wait-pid".to_string()]),
            None,
            "flag with no value is not a pid"
        );
        assert_eq!(
            parse_restart_wait_pid(&[
                "--restart-wait-pid".to_string(),
                "not-a-pid".to_string()
            ]),
            None,
            "a non-numeric value is not a pid"
        );
    }

    #[test]
    fn restart_args_drop_only_the_wait_pid_pair() {
        // A successor that restarts again must not hand its own
        // wait-pid down: the next successor waits for THIS
        // process, and `prepare_restart` appends a fresh pair.
        let args = vec![
            "--config".to_string(),
            "x.toml".to_string(),
            "--restart-wait-pid".to_string(),
            "1234".to_string(),
            "--verbose".to_string(),
        ];
        assert_eq!(
            restart_args_without_wait_pid(&args),
            vec![
                "--config".to_string(),
                "x.toml".to_string(),
                "--verbose".to_string(),
            ]
        );
        assert_eq!(
            restart_args_without_wait_pid(&["--restart-wait-pid".to_string()]),
            Vec::<String>::new(),
            "a dangling flag is dropped with no value to take"
        );
        assert!(restart_args_without_wait_pid(&[]).is_empty());
    }

    #[test]
    fn should_keep_waiting_for_lock_matrix() {
        // Plain double-click never waits (timeout 0).
        assert!(!should_keep_waiting_for_lock(true, 0, 0));
        // A restart successor waits until the budget is spent.
        assert!(should_keep_waiting_for_lock(true, 0, LOCK_WAIT_TIMEOUT_MS));
        assert!(should_keep_waiting_for_lock(
            true,
            LOCK_WAIT_TIMEOUT_MS - 1,
            LOCK_WAIT_TIMEOUT_MS
        ));
        assert!(!should_keep_waiting_for_lock(
            true,
            LOCK_WAIT_TIMEOUT_MS,
            LOCK_WAIT_TIMEOUT_MS
        ));
        // A free lock stops the wait at once.
        assert!(!should_keep_waiting_for_lock(
            false,
            0,
            LOCK_WAIT_TIMEOUT_MS
        ));
    }

    #[test]
    fn wait_for_pid_exit_returns_at_once_for_a_dead_pid() {
        // A process that is already gone (spawn `sleep`, kill it,
        // then wait) must return true without burning the timeout.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep must exist in the test VM");
        let pid = child.id();
        child.kill().expect("kill the sleeper");
        let _ = child.wait();
        let start = Instant::now();
        assert!(
            wait_for_pid_exit(pid, 5_000),
            "a dead pid must report exited"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "no waiting on a dead pid, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn wait_for_pid_exit_times_out_on_a_live_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep must exist in the test VM");
        let pid = child.id();
        let start = Instant::now();
        assert!(
            !wait_for_pid_exit(pid, 200),
            "a live pid must not report exited"
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the timeout must bound the wait, took {:?}",
            start.elapsed()
        );
        child.kill().expect("kill the sleeper");
        let _ = child.wait();
        assert!(
            wait_for_pid_exit(pid, 5_000),
            "the killed pid must report exited afterwards"
        );
    }

    /// The lock primitive itself, on the non-Windows file backend:
    /// a second acquire fails while the first is held, succeeds
    /// once it is dropped, and a stale lock (dead owner pid) is
    /// stolen instead of wedging every later launch.
    #[cfg(not(windows))]
    #[test]
    fn file_lock_second_acquire_fails_and_stale_is_stolen() {
        let path = lock_file_path();
        let _ = std::fs::remove_file(&path);
        let first = try_acquire_lock().expect("first acquire must succeed");
        assert!(
            try_acquire_lock().is_none(),
            "a second acquire while held must fail"
        );
        drop(first);
        assert!(
            try_acquire_lock().is_some(),
            "after the drop the lock must be free again"
        );
        // Stale: a lock file naming a dead pid must not block.
        // Use a pid we know is dead: spawn + kill a sleeper.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep must exist");
        let pid = child.id();
        child.kill().expect("kill the sleeper");
        let _ = child.wait();
        std::fs::write(&path, format!("{}\n", pid)).expect("write a stale lock");
        let stolen = try_acquire_lock();
        assert!(
            stolen.is_some(),
            "a lock whose owner is dead must be stolen, not block"
        );
        drop(stolen);
        let _ = std::fs::remove_file(&path);
    }

    /// The lock primitive itself, on the Windows named mutex:
    /// a second acquire reports "already exists" while the first
    /// is held. Windows-only — it cannot run in the Linux VM, so
    /// the VM-runnable coverage is the file-backend test above
    /// plus the decision/wait tests; this one runs on a Windows
    /// build (or not at all — it is honest about that in the
    /// test report).
    #[cfg(windows)]
    #[test]
    fn named_mutex_second_acquire_reports_exists() {
        let first = try_acquire_lock().expect("first acquire must succeed");
        assert!(
            try_acquire_lock().is_none(),
            "a second acquire while held must fail"
        );
        drop(first);
        assert!(
            try_acquire_lock().is_some(),
            "after the drop the lock must be free again"
        );
    }

    /// The non-Windows show file: one poll raises the flag and
    /// removes the file, a second poll finds nothing.
    #[cfg(not(windows))]
    #[test]
    fn check_show_file_once_raises_and_clears() {
        let flag = AtomicBool::new(false);
        let path = show_file_path();
        let _ = std::fs::remove_file(&path);
        assert!(!check_show_file_once(&flag));
        assert!(!flag.load(Ordering::SeqCst));
        std::fs::write(&path, "").expect("write a show request");
        assert!(check_show_file_once(&flag));
        assert!(flag.load(Ordering::SeqCst));
        assert!(!path.exists(), "the request must be consumed");
        assert!(!check_show_file_once(&flag));
    }
}
