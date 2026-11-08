//! DNS resolution for tunnel targets.
//!
//! Order (ported from the JS reference):
//! 1. Literal IPv4 → as-is.
//! 2. Small static map (google/gstatic fallback used by the JS code).
//! 3. DNS-over-HTTPS JSON to 1.1.1.1, then cloudflare-dns.com.
//! 4. System resolver (`tokio::net::lookup_host`) as a last resort.

use std::net::SocketAddr;

use crate::net::{https_get, Connector};

const STATIC: &[(&str, &str)] = &[
    ("cp.cloudflare.com", "104.16.132.229"),
    ("one.one.one.one", "1.1.1.1"),
    ("api.ipify.org", "172.67.74.152"),
    ("icanhazip.com", "104.18.114.97"),
];

fn is_ipv4(s: &str) -> bool {
    s.split('.').count() == 4
        && s.split('.').all(|p| {
            !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u8>().is_ok()
        })
}

/// Pick the address the IPv4-only tunnel can use from a resolver
/// answer: the first IPv4 address wins when several are returned
/// (A and AAAA mixed). When only IPv6 addresses came back, say so
/// plainly — the caller used to take the first address blindly and
/// the tunnel then failed with a cryptic "bad resolved IP" (seen
/// for ipv6.icanhazip.com, which resolves to 2606:4700::6810:b8f1).
fn pick_ipv4(host: &str, addrs: &[SocketAddr]) -> Result<String, String> {
    if let Some(v4) = addrs.iter().find(|sa| sa.ip().is_ipv4()) {
        return Ok(v4.ip().to_string());
    }
    if let Some(v6) = addrs.first() {
        return Err(format!(
            "only IPv6 addresses for {} ({}); the tunnel is IPv4-only",
            host,
            v6.ip()
        ));
    }
    Err(format!("system DNS: no address for {}", host))
}

/// Resolve `host` to an IPv4 string.
pub async fn resolve_ipv4(connector: &Connector, host: &str) -> Result<String, String> {
    if is_ipv4(host) {
        return Ok(host.to_string());
    }
    if let Some((_, ip)) = STATIC.iter().find(|(h, _)| *h == host) {
        return Ok(ip.to_string());
    }
    for base in [
        "https://1.1.1.1/dns-query",
        "https://cloudflare-dns.com/dns-query",
    ] {
        let url = format!("{}?name={}&type=A", base, host);
        match https_get(connector, &url, &[("Accept", "application/dns-json")], true).await {
            Ok((200, body)) => {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                    if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
                        for a in ans {
                            if a.get("type").and_then(|t| t.as_u64()) == Some(1) {
                                if let Some(ip) = a.get("data").and_then(|d| d.as_str()) {
                                    return Ok(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Ok((code, _)) => {
                eprintln!("DoH {} returned HTTP {}", base, code);
            }
            Err(e) => {
                eprintln!("DoH {} failed: {}", base, e);
            }
        }
    }
    // Fallback: system resolver (may be poisoned behind a firewall; best effort).
    if host.ends_with("gstatic.com") || host.ends_with("google.com") {
        return Ok("142.251.150.120".to_string());
    }
    match tokio::net::lookup_host((host, 80)).await {
        Ok(it) => pick_ipv4(host, &it.collect::<Vec<_>>()),
        Err(e) => Err(format!("DNS failed for {}: {}", host, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), 80)
    }

    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(s.parse().unwrap(), 443)
    }

    /// A+AAAA mixed: the IPv4 address wins, even when the IPv6
    /// address comes first (the v3.9 ipv6.icanhazip.com case:
    /// the resolver returned 2606:4700::6810:b8f1 first).
    #[test]
    fn pick_ipv4_prefers_ipv4_over_ipv6() {
        assert_eq!(
            pick_ipv4(
                "ipv6.icanhazip.com",
                &[v6("2606:4700::6810:b8f1"), v4("104.18.114.97")]
            )
            .unwrap(),
            "104.18.114.97"
        );
        // First IPv4 wins when several are returned.
        assert_eq!(
            pick_ipv4("example.com", &[v4("1.2.3.4"), v4("5.6.7.8")]).unwrap(),
            "1.2.3.4"
        );
    }

    /// Only AAAA: a clear error, not a bare IPv6 string that the
    /// tunnel would later reject as "bad resolved IP".
    #[test]
    fn pick_ipv4_only_ipv6_is_a_clear_error() {
        let err = pick_ipv4("ipv6.icanhazip.com", &[v6("2606:4700::6810:b8f1")])
            .unwrap_err();
        assert!(
            err.contains("only IPv6") && err.contains("IPv4-only"),
            "unexpected error: {}",
            err
        );
        assert!(err.contains("2606:4700::6810:b8f1"));
    }

    #[test]
    fn pick_ipv4_empty_is_a_clear_error() {
        assert!(pick_ipv4("example.com", &[]).is_err());
    }
}
