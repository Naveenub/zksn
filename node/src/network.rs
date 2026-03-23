//! Yggdrasil address space enforcement — `200::/7`.
//!
//! Yggdrasil assigns every node an IPv6 address in the `200::/7` prefix.
//! Any address outside this range means the socket is bound to or dialling
//! the real internet, which leaks the node's IP address and destroys the
//! transport-layer anonymity guarantee.
//!
//! ## Address space
//!
//! `200::/7` is the first 7 bits of the IPv6 address being `0000 001`.
//! In practice this covers all addresses whose first byte is `0x02` or `0x03`
//! (big-endian), i.e., `[0x02, ...]` through `[0x03, ...]`.
//!
//! ```text
//! 0000 001? ???? ???? ...   ← first 7 bits of 200::
//! first byte in {0x02, 0x03}
//! ```
//!
//! ## Usage
//!
//! All enforcement is gated on `NetworkConfig::yggdrasil_only`.
//! Set `yggdrasil_only = false` in `node.toml` for development/testnet
//! where Yggdrasil is not running.

use std::net::{IpAddr, SocketAddr};

// ── Core predicate ────────────────────────────────────────────────────────────

/// Returns `true` if `addr` falls inside the Yggdrasil `200::/7` prefix.
///
/// IPv4 addresses always return `false`.
pub fn is_yggdrasil(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => {
            let b = v6.octets();
            // 200::/7 → first 7 bits = 0000 001 → first byte ∈ {0x02, 0x03}
            b[0] & 0xFE == 0x02
        }
        IpAddr::V4(_) => false,
    }
}

/// Returns `true` if the socket address string parses to a Yggdrasil address.
///
/// Returns `false` for unparseable strings (they will fail elsewhere).
pub fn is_yggdrasil_addr(addr: &str) -> bool {
    // Strip brackets from bare IPv6 if present, then try socket addr parse
    addr.parse::<SocketAddr>()
        .map(|sa| is_yggdrasil(&sa.ip()))
        .unwrap_or(false)
}

// ── Enforcement helpers ───────────────────────────────────────────────────────

/// Error message emitted when a non-Yggdrasil address is rejected.
fn rejection_msg(addr: &str, context: &str) -> String {
    format!(
        "{context} '{addr}' is not in the Yggdrasil address space (200::/7).\n\
         A node operating outside Yggdrasil exposes its real IP address and \
         breaks transport-layer anonymity.\n\
         To run without Yggdrasil (development only), set \
         `network.yggdrasil_only = false` in node.toml."
    )
}

/// Validate a bind address. Returns `Err` if enforcement is active and the
/// address is not in the Yggdrasil space.
pub fn check_bind(addr: &str, enforce: bool) -> anyhow::Result<()> {
    if enforce && !is_yggdrasil_addr(addr) {
        anyhow::bail!("{}", rejection_msg(addr, "Listen address"));
    }
    Ok(())
}

/// Validate an outbound peer address. Returns `Err` if enforcement is active
/// and the address is not in the Yggdrasil space.
pub fn check_peer(addr: &str, enforce: bool) -> anyhow::Result<()> {
    if enforce && !is_yggdrasil_addr(addr) {
        anyhow::bail!("{}", rejection_msg(addr, "Peer address"));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── is_yggdrasil ──────────────────────────────────────────────────────────

    #[test]
    fn test_yggdrasil_low_boundary() {
        // 200:: = 0200:0000:... → first byte 0x02
        let addr: IpAddr = "200::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(is_yggdrasil(&addr));
    }

    #[test]
    fn test_yggdrasil_high_boundary() {
        // 3ff:ffff:... → first byte 0x03 (still in 200::/7)
        let addr: IpAddr = "3ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            .parse::<Ipv6Addr>()
            .unwrap()
            .into();
        assert!(is_yggdrasil(&addr));
    }

    #[test]
    fn test_yggdrasil_typical_address() {
        // Typical Yggdrasil address in the 200::/7 range
        let addr: IpAddr = "0201:cafe:dead:beef:1234:5678:abcd:ef01"
            .parse::<Ipv6Addr>()
            .unwrap()
            .into();
        assert!(is_yggdrasil(&addr));
    }

    #[test]
    fn test_not_yggdrasil_loopback() {
        let addr: IpAddr = "::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_not_yggdrasil_global_unicast() {
        // 2001:db8:: is documentation range, first byte 0x20 ≠ 0x02/0x03
        let addr: IpAddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_not_yggdrasil_link_local() {
        let addr: IpAddr = "fe80::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_not_yggdrasil_ipv4() {
        let addr: IpAddr = "192.168.1.1".parse::<Ipv4Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_not_yggdrasil_ipv4_loopback() {
        let addr: IpAddr = "127.0.0.1".parse::<Ipv4Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_boundary_just_below_200() {
        // 0x01xx — first byte 0x01, not in range
        let addr: IpAddr = "100::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_boundary_just_above_3ff() {
        // 0x04xx — first byte 0x04, not in range
        let addr: IpAddr = "400::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_yggdrasil(&addr));
    }

    // ── is_yggdrasil_addr ─────────────────────────────────────────────────────

    #[test]
    fn test_addr_string_yggdrasil() {
        assert!(is_yggdrasil_addr("[200::1]:9001"));
    }

    #[test]
    fn test_addr_string_not_yggdrasil() {
        assert!(!is_yggdrasil_addr("127.0.0.1:9001"));
    }

    #[test]
    fn test_addr_string_invalid() {
        assert!(!is_yggdrasil_addr("not-an-address"));
    }

    #[test]
    fn test_addr_string_ipv6_loopback() {
        assert!(!is_yggdrasil_addr("[::1]:9001"));
    }

    // ── check_bind ────────────────────────────────────────────────────────────

    #[test]
    fn test_check_bind_passes_when_not_enforced() {
        // Enforcement off → any address accepted
        assert!(check_bind("127.0.0.1:9001", false).is_ok());
        assert!(check_bind("[::1]:9001", false).is_ok());
        assert!(check_bind("garbage", false).is_ok());
    }

    #[test]
    fn test_check_bind_passes_yggdrasil_when_enforced() {
        assert!(check_bind("[200::1]:9001", true).is_ok());
        assert!(check_bind("[0201:cafe::1]:9001", true).is_ok());
    }

    #[test]
    fn test_check_bind_rejects_localhost_when_enforced() {
        let r = check_bind("127.0.0.1:9001", true);
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("200::/7"));
        assert!(msg.contains("yggdrasil_only"));
    }

    #[test]
    fn test_check_bind_rejects_ipv6_non_yggdrasil_when_enforced() {
        assert!(check_bind("[::1]:9001", true).is_err());
        assert!(check_bind("[2001:db8::1]:9001", true).is_err());
    }

    // ── check_peer ────────────────────────────────────────────────────────────

    #[test]
    fn test_check_peer_passes_when_not_enforced() {
        assert!(check_peer("192.168.1.1:9001", false).is_ok());
    }

    #[test]
    fn test_check_peer_passes_yggdrasil_when_enforced() {
        assert!(check_peer("[300::dead:beef]:9001", true).is_ok());
    }

    #[test]
    fn test_check_peer_rejects_ipv4_when_enforced() {
        let r = check_peer("1.2.3.4:9001", true);
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("200::/7"));
    }
}
