# VpngateSU

Android port of [VPNGATE-LITE](https://github.com/leotse28/VPNGATE-LITE) (based on v3.16).

A userspace tunnel client: local mixed SOCKS5 + HTTP proxy port, front SOCKS5 proxy,
and an MS-SSTP tunnel to VPNGate volunteer nodes. Port-proxy only — no virtual
NIC, no routing-table changes, no system-wide VPN.

- Target: Android 11 and above (minSdk 30)
- Status: in development — design phase (`DESIGN.md` to follow)

See `DESIGN.md` for the porting plan once it lands.
