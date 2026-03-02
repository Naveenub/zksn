//! # Node Metrics
//!
//! Prometheus-compatible metrics for mix node monitoring.
//! Exposed on a local-only HTTP endpoint — never transmitted externally.

use prometheus::{
    register_counter, register_gauge, register_histogram,
    Counter, Gauge, Histogram, HistogramOpts,
};
use std::sync::OnceLock;

pub struct NodeMetrics {
    pub packets_received:   Counter,
    pub packets_forwarded:  Counter,
    pub packets_delivered:  Counter,
    pub cover_packets_sent: Counter,
    pub pool_depth:         Gauge,
    pub mixing_delay_ms:    Histogram,
    pub active_peers:       Gauge,
}

static METRICS: OnceLock<NodeMetrics> = OnceLock::new();

impl NodeMetrics {
    pub fn global() -> &'static NodeMetrics {
        METRICS.get_or_init(NodeMetrics::new)
    }

    fn new() -> Self {
        // prometheus 0.13: register_counter!("name", "help") — simple two-arg form
        Self {
            packets_received: register_counter!(
                "zksn_packets_received_total",
                "Total Sphinx packets received"
            ).expect("metrics registration failed"),

            packets_forwarded: register_counter!(
                "zksn_packets_forwarded_total",
                "Total packets forwarded to next hop"
            ).expect("metrics registration failed"),

            packets_delivered: register_counter!(
                "zksn_packets_delivered_total",
                "Total packets delivered to local service"
            ).expect("metrics registration failed"),

            cover_packets_sent: register_counter!(
                "zksn_cover_packets_sent_total",
                "Total cover traffic packets emitted"
            ).expect("metrics registration failed"),

            pool_depth: register_gauge!(
                "zksn_pool_depth",
                "Current number of packets held in mixing pool"
            ).expect("metrics registration failed"),

            mixing_delay_ms: register_histogram!(
                HistogramOpts::new(
                    "zksn_mixing_delay_ms",
                    "Packet mixing delays in milliseconds",
                ).buckets(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 5000.0])
            ).expect("metrics registration failed"),

            active_peers: register_gauge!(
                "zksn_active_peers",
                "Number of currently connected peers"
            ).expect("metrics registration failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_global_is_singleton() {
        let a = NodeMetrics::global();
        let b = NodeMetrics::global();
        // Both pointers must be identical
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn test_counter_increments() {
        let m = NodeMetrics::global();
        let before = m.packets_received.get();
        m.packets_received.inc();
        assert_eq!(m.packets_received.get(), before + 1.0);
    }

    #[test]
    fn test_gauge_inc_dec() {
        let m = NodeMetrics::global();
        let before = m.active_peers.get();
        m.active_peers.inc();
        m.active_peers.dec();
        assert_eq!(m.active_peers.get(), before);
    }
}
