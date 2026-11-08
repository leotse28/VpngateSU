//! vpngate-client library: MS-SSTP + PPP tunnel to VPNGate volunteer
//! nodes, a userspace TCP stack over the tunnel, a local SOCKS5 server,
//! and the VPNGate node list. Shared by the CLI binary (`vpngate-client`)
//! and the desktop GUI binary (`vpngate-gui`).

pub mod config;
pub mod doh;
pub mod filelog;
pub mod net;
pub mod single_instance;
pub mod socks5;
pub mod sstp;
pub mod sysproxy;
/// Desktop GUI only (behind the `gui` feature): the tray icon decode
/// uses the `image` crate and the live handle uses Windows-only
/// `tray-icon`, so the whole module — including its tests — is
/// excluded from `--no-default-features` (Android .so) builds.
/// Only the GUI binary uses it; the CLI never did.
#[cfg(feature = "gui")]
pub mod tray;
pub mod util;
pub mod vpngate;
