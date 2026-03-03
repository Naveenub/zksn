use prometheus::{register_counter, register_gauge, register_histogram,
    Counter, Gauge, Histogram, HistogramOpts};
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
    pub fn global() -> &'static NodeMetrics { METRICS.get_or_init(NodeMetrics::new) }
    fn new() -> Self {
        Self {
            packets_received:   register_counter!("zksn_packets_received_total",   "Total Sphinx packets received").unwrap(),
            packets_forwarded:  register_counter!("zksn_packets_forwarded_total",  "Total packets forwarded").unwrap(),
            packets_delivered:  register_counter!("zksn_packets_delivered_total",  "Total packets delivered locally").unwrap(),
            cover_packets_sent: register_counter!("zksn_cover_packets_sent_total", "Total cover packets emitted").unwrap(),
            pool_depth:         register_gauge!("zksn_pool_depth",    "Packets held in mixing pool").unwrap(),
            active_peers:       register_gauge!("zksn_active_peers",  "Connected peers").unwrap(),
            mixing_delay_ms:    register_histogram!(HistogramOpts::new("zksn_mixing_delay_ms", "Mixing delays in ms")
                .buckets(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 5000.0])).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn test_metrics_singleton() {
        let a = NodeMetrics::global();
        let b = NodeMetrics::global();
        assert!(std::ptr::eq(a, b));
    }
    #[test] fn test_counter_increments() {
        let m = NodeMetrics::global();
        let before = m.packets_received.get();
        m.packets_received.inc();
        assert_eq!(m.packets_received.get(), before + 1.0);
    }
}
