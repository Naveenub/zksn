//! # Node Metrics
//!
//! Prometheus-compatible metrics for mix node monitoring.
//! All metrics are local-only — never transmitted outside the node.
//!
//! Exposed on a local-only HTTP endpoint (not accessible from outside the node).

use prometheus::{
    register_counter, register_gauge, register_histogram,
    Counter, Gauge, Histogram, HistogramOpts, Opts,
};
use std::sync::OnceLock;

pub struct NodeMetrics {
    pub packets_received: Counter,
    pub packets_forwarded: Counter,
    pub packets_delivered: Counter,
    pub cover_packets_sent: Counter,
    pub pool_depth: Gauge,
    pub mixing_delay_ms: Histogram,
    pub active_peers: Gauge,
}

static METRICS: OnceLock<NodeMetrics> = OnceLock::new();

impl NodeMetrics {
    pub fn global() -> &'static NodeMetrics {
        METRICS.get_or_init(|| NodeMetrics::new())
    }

    fn new() -> Self {
        Self {
            packets_received: register_counter!(
                Opts::new("zksn_packets_received_total", "Total Sphinx packets received")
            ).unwrap(),

            packets_forwarded: register_counter!(
                Opts::new("zksn_packets_forwarded_total", "Total packets forwarded to next hop")
            ).unwrap(),

            packets_delivered: register_counter!(
                Opts::new("zksn_packets_delivered_total", "Total packets delivered to local service")
            ).unwrap(),

            cover_packets_sent: register_counter!(
                Opts::new("zksn_cover_packets_sent_total", "Total cover traffic packets emitted")
            ).unwrap(),

            pool_depth: register_gauge!(
                Opts::new("zksn_pool_depth", "Current number of packets held in mixing pool")
            ).unwrap(),

            mixing_delay_ms: register_histogram!(
                HistogramOpts::new("zksn_mixing_delay_ms", "Observed packet mixing delays in milliseconds")
                    .buckets(vec![10.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 5000.0])
            ).unwrap(),

            active_peers: register_gauge!(
                Opts::new("zksn_active_peers", "Number of currently connected peers")
            ).unwrap(),
        }
    }
}
