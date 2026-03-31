use crate::net_stats::InterfaceStats;
use crate::port_scanner::PortEntry;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

const HISTORY_LEN: usize = 60;

pub struct MetricsHistory {
    /// Aggregate network rates across all interfaces
    pub rx_history: VecDeque<f64>,
    pub tx_history: VecDeque<f64>,
    /// Current rates for display
    pub current_rx: f64,
    pub current_tx: f64,

    prev_interface_stats: Option<Vec<InterfaceStats>>,
    prev_timestamp: Option<Instant>,

    /// Current connection state distribution
    pub state_counts: Vec<(String, u64)>,

    /// Top processes by connection count (sorted descending)
    pub top_processes: Vec<(String, u64)>,
}

impl MetricsHistory {
    pub fn new() -> Self {
        Self {
            rx_history: VecDeque::new(),
            tx_history: VecDeque::new(),
            current_rx: 0.0,
            current_tx: 0.0,
            prev_interface_stats: None,
            prev_timestamp: None,
            state_counts: Vec::new(),
            top_processes: Vec::new(),
        }
    }

    pub fn update(&mut self, entries: &[PortEntry], interface_stats: Vec<InterfaceStats>) {
        self.update_net_rates(&interface_stats);
        self.update_state_counts(entries);
        self.update_top_processes(entries);

        self.prev_interface_stats = Some(interface_stats);
        self.prev_timestamp = Some(Instant::now());
    }

    fn update_net_rates(&mut self, current: &[InterfaceStats]) {
        let (prev_stats, prev_time) = match (&self.prev_interface_stats, &self.prev_timestamp) {
            (Some(s), Some(t)) => (s, t),
            _ => return,
        };

        let elapsed = prev_time.elapsed().as_secs_f64();
        if elapsed < 0.01 {
            return;
        }

        let prev_map: HashMap<&str, &InterfaceStats> =
            prev_stats.iter().map(|s| (s.name.as_str(), s)).collect();

        let mut total_rx: f64 = 0.0;
        let mut total_tx: f64 = 0.0;

        for iface in current {
            if let Some(prev) = prev_map.get(iface.name.as_str()) {
                total_rx += (iface.rx_bytes.saturating_sub(prev.rx_bytes)) as f64 / elapsed;
                total_tx += (iface.tx_bytes.saturating_sub(prev.tx_bytes)) as f64 / elapsed;
            }
        }

        self.current_rx = total_rx;
        self.current_tx = total_tx;

        self.rx_history.push_back(total_rx);
        self.tx_history.push_back(total_tx);

        if self.rx_history.len() > HISTORY_LEN {
            self.rx_history.pop_front();
        }
        if self.tx_history.len() > HISTORY_LEN {
            self.tx_history.pop_front();
        }
    }

    fn update_state_counts(&mut self, entries: &[PortEntry]) {
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for e in entries {
            *counts.entry(e.state.as_str()).or_insert(0) += 1;
        }
        let mut sorted: Vec<(String, u64)> = counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        self.state_counts = sorted;
    }

    fn update_top_processes(&mut self, entries: &[PortEntry]) {
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for e in entries {
            if e.pid > 0 {
                *counts.entry(e.process_name.as_str()).or_insert(0) += 1;
            }
        }
        let mut sorted: Vec<(String, u64)> = counts
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(8);
        self.top_processes = sorted;
    }

    pub fn max_net_rate(&self) -> f64 {
        self.rx_history
            .iter()
            .chain(self.tx_history.iter())
            .copied()
            .fold(100.0_f64, f64::max) // at least 100 B/s for readable axis
    }
}
