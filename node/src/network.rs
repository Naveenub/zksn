//! Mesh address space enforcement — Yggdrasil `200::/7` and CJDNS `fc00::/8`.
//!
//! Yggdrasil assigns every node an IPv6 address in the `200::/7` prefix.
//! CJDNS (the configured fallback mesh, see `docs/ARCHITECTURE.md`) assigns
//! addresses in `fc00::/8`. Any address outside these ranges means the
//! socket is bound to or dialling the real internet, which leaks the node's
//! IP address and destroys the transport-layer anonymity guarantee.
//!
//! ## Address spaces
//!
//! `200::/7` is the first 7 bits of the IPv6 address being `0000 001`.
//! In practice this covers all addresses whose first byte is `0x02` or `0x03`
//! (big-endian), i.e., `[0x02, ...]` through `[0x03, ...]`.
//!
//! `fc00::/8` covers addresses whose first byte is exactly `0xFC` — this is
//! the range CJDNS derives from a node's public key (distinct from the
//! standard-ULA `fd00::/8` half of `fc00::/7`, which CJDNS does not use).
//!
//! ```text
//! 0000 001? ???? ???? ...   ← first 7 bits of 200::   (Yggdrasil)
//! first byte in {0x02, 0x03}
//!
//! 1111 1100 ???? ???? ...   ← first 8 bits of fc00::  (CJDNS)
//! first byte == 0xFC
//! ```
//!
//! ## Usage
//!
//! All enforcement is gated on `NetworkConfig::yggdrasil_only`.
//! Set `yggdrasil_only = false` in `node.toml` for development/testnet
//! where neither mesh daemon is running.
//!
//! Address-format checks alone only prove a string *looks* like a mesh
//! address — they don't prove Yggdrasil or CJDNS is actually running.
//! [`verify_mesh_interface_live`] closes that gap by checking the host's
//! real network interfaces.

use std::net::{IpAddr, SocketAddr};

// ── Core predicates ───────────────────────────────────────────────────────────

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

/// Returns `true` if `addr` falls inside the CJDNS `fc00::/8` prefix.
///
/// IPv4 addresses always return `false`.
pub fn is_cjdns(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => v6.octets()[0] == 0xFC,
        IpAddr::V4(_) => false,
    }
}

/// Returns `true` if `addr` is a Yggdrasil or CJDNS mesh address.
pub fn is_mesh(addr: &IpAddr) -> bool {
    is_yggdrasil(addr) || is_cjdns(addr)
}

/// Returns `true` if the socket address string parses to a mesh address
/// (Yggdrasil or CJDNS).
///
/// Returns `false` for unparseable strings (they will fail elsewhere).
pub fn is_mesh_addr(addr: &str) -> bool {
    // Strip brackets from bare IPv6 if present, then try socket addr parse
    addr.parse::<SocketAddr>()
        .map(|sa| is_mesh(&sa.ip()))
        .unwrap_or(false)
}

// ── Enforcement helpers ───────────────────────────────────────────────────────

/// Error message emitted when a non-mesh address is rejected.
fn rejection_msg(addr: &str, context: &str) -> String {
    format!(
        "{context} '{addr}' is not in the Yggdrasil (200::/7) or CJDNS \
         (fc00::/8) address space.\n\
         A node operating outside the mesh exposes its real IP address and \
         breaks transport-layer anonymity.\n\
         To run without the mesh (development only), set \
         `network.yggdrasil_only = false` in node.toml."
    )
}

/// Validate a bind address. Returns `Err` if enforcement is active and the
/// address is not in the Yggdrasil or CJDNS space.
pub fn check_bind(addr: &str, enforce: bool) -> anyhow::Result<()> {
    if enforce && !is_mesh_addr(addr) {
        anyhow::bail!("{}", rejection_msg(addr, "Listen address"));
    }
    Ok(())
}

/// Validate an outbound peer address. Returns `Err` if enforcement is active
/// and the address is not in the Yggdrasil or CJDNS space.
pub fn check_peer(addr: &str, enforce: bool) -> anyhow::Result<()> {
    if enforce && !is_mesh_addr(addr) {
        anyhow::bail!("{}", rejection_msg(addr, "Peer address"));
    }
    Ok(())
}

/// Confirm the host actually has a live network interface bound to the
/// Yggdrasil or CJDNS address space.
///
/// [`is_mesh_addr`] only validates that a configured address *looks* right;
/// it can't tell whether `yggdrasil` or `cjdroute` is actually running. This
/// walks the OS interface table and requires at least one real interface to
/// carry a mesh address before mesh-only enforcement is allowed to proceed —
/// otherwise a misconfigured or crashed mesh daemon would silently enforce a
/// guarantee it isn't providing.
pub fn verify_mesh_interface_live(enforce: bool) -> anyhow::Result<()> {
    if !enforce {
        return Ok(());
    }
    let interfaces = if_addrs::get_if_addrs()
        .map_err(|e| anyhow::anyhow!("failed to enumerate network interfaces: {e}"))?;
    if !interfaces.iter().any(|i| is_mesh(&i.ip())) {
        anyhow::bail!(
            "network.yggdrasil_only is set but no local network interface carries a \
             Yggdrasil (200::/7) or CJDNS (fc00::/8) address. Start `yggdrasil` or \
             `cjdroute` first, or set `network.yggdrasil_only = false` in node.toml \
             for development."
        );
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

    // ── is_cjdns ──────────────────────────────────────────────────────────────

    #[test]
    fn test_cjdns_typical_address() {
        // CJDNS addresses are derived from a pubkey hash and always start fc.
        let addr: IpAddr = "fc00:1234:5678:9abc:def0:1234:5678:9abc"
            .parse::<Ipv6Addr>()
            .unwrap()
            .into();
        assert!(is_cjdns(&addr));
        assert!(!is_yggdrasil(&addr));
    }

    #[test]
    fn test_cjdns_excludes_standard_ula() {
        // fd00::/8 is standard ULA, not CJDNS space (fc00::/8 only).
        let addr: IpAddr = "fd00::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_cjdns(&addr));
    }

    #[test]
    fn test_cjdns_excludes_ipv4() {
        let addr: IpAddr = "192.168.1.1".parse::<Ipv4Addr>().unwrap().into();
        assert!(!is_cjdns(&addr));
    }

    // ── is_mesh ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mesh_accepts_yggdrasil_and_cjdns() {
        let ygg: IpAddr = "200::1".parse::<Ipv6Addr>().unwrap().into();
        let cjdns: IpAddr = "fc00::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(is_mesh(&ygg));
        assert!(is_mesh(&cjdns));
    }

    #[test]
    fn test_mesh_rejects_other_space() {
        let addr: IpAddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into();
        assert!(!is_mesh(&addr));
    }

    // ── is_mesh_addr ──────────────────────────────────────────────────────────

    #[test]
    fn test_addr_string_yggdrasil() {
        assert!(is_mesh_addr("[200::1]:9001"));
    }

    #[test]
    fn test_addr_string_cjdns() {
        assert!(is_mesh_addr("[fc00::1]:9001"));
    }

    #[test]
    fn test_addr_string_not_mesh() {
        assert!(!is_mesh_addr("127.0.0.1:9001"));
    }

    #[test]
    fn test_addr_string_invalid() {
        assert!(!is_mesh_addr("not-an-address"));
    }

    #[test]
    fn test_addr_string_ipv6_loopback() {
        assert!(!is_mesh_addr("[::1]:9001"));
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
    fn test_check_bind_passes_cjdns_when_enforced() {
        assert!(check_bind("[fc00::1]:9001", true).is_ok());
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

    #[test]
    fn test_check_peer_passes_cjdns_when_enforced() {
        assert!(check_peer("[fc00::dead:beef]:9001", true).is_ok());
    }

    // ── verify_mesh_interface_live ──────────────────────────────────────────────

    #[test]
    fn test_verify_mesh_interface_live_noop_when_not_enforced() {
        // Sandboxed/CI hosts never have a real mesh interface — this must
        // stay Ok(()) regardless, since enforcement is off.
        assert!(verify_mesh_interface_live(false).is_ok());
    }
}
