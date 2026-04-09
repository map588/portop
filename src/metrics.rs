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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_stats::InterfaceStats;
    use crate::port_scanner::PortEntry;

    // ------------------------------------------------------------------
    // 1. MetricsHistory::new — initial state
    // ------------------------------------------------------------------

    #[test]
    fn new_has_empty_histories_and_zero_rates() {
        let m = MetricsHistory::new();
        assert!(m.rx_history.is_empty());
        assert!(m.tx_history.is_empty());
        assert_eq!(m.current_rx, 0.0);
        assert_eq!(m.current_tx, 0.0);
        assert!(m.state_counts.is_empty());
        assert!(m.top_processes.is_empty());
    }

    // ------------------------------------------------------------------
    // 2. update_state_counts (via update)
    // ------------------------------------------------------------------

    #[test]
    fn state_counts_sorted_descending() {
        let entries = vec![
            PortEntry::test("tcp", "0.0.0.0", 80, "LISTEN"),
            PortEntry::test("tcp", "0.0.0.0", 443, "LISTEN"),
            PortEntry::test("tcp", "0.0.0.0", 8080, "LISTEN"),
            PortEntry::test("tcp", "0.0.0.0", 22, "ESTABLISHED"),
            PortEntry::test("tcp", "0.0.0.0", 23, "ESTABLISHED"),
            PortEntry::test("tcp", "0.0.0.0", 9000, "TIME_WAIT"),
        ];

        let mut m = MetricsHistory::new();
        m.update(&entries, vec![]);

        assert_eq!(m.state_counts.len(), 3);
        assert_eq!(m.state_counts[0], ("LISTEN".to_string(), 3));
        assert_eq!(m.state_counts[1], ("ESTABLISHED".to_string(), 2));
        assert_eq!(m.state_counts[2], ("TIME_WAIT".to_string(), 1));
    }

    #[test]
    fn state_counts_empty_entries() {
        let mut m = MetricsHistory::new();
        m.update(&[], vec![]);
        assert!(m.state_counts.is_empty());
    }

    // ------------------------------------------------------------------
    // 3. update_top_processes (via update)
    // ------------------------------------------------------------------

    #[test]
    fn top_processes_sorted_descending_and_pid_zero_excluded() {
        let entries = vec![
            PortEntry::test("tcp", "0.0.0.0", 80, "LISTEN").with_process(1, "nginx"),
            PortEntry::test("tcp", "0.0.0.0", 443, "LISTEN").with_process(1, "nginx"),
            PortEntry::test("tcp", "0.0.0.0", 8080, "LISTEN").with_process(1, "nginx"),
            PortEntry::test("tcp", "0.0.0.0", 9000, "ESTABLISHED").with_process(2, "chrome"),
            PortEntry::test("tcp", "0.0.0.0", 9001, "ESTABLISHED").with_process(2, "chrome"),
            PortEntry::test("tcp", "0.0.0.0", 22, "ESTABLISHED").with_process(3, "ssh"),
            // pid == 0: should be excluded
            PortEntry::test("tcp", "0.0.0.0", 1234, "ESTABLISHED"),
        ];

        let mut m = MetricsHistory::new();
        m.update(&entries, vec![]);

        assert_eq!(m.top_processes.len(), 3);
        assert_eq!(m.top_processes[0], ("nginx".to_string(), 3));
        assert_eq!(m.top_processes[1], ("chrome".to_string(), 2));
        assert_eq!(m.top_processes[2], ("ssh".to_string(), 1));
    }

    #[test]
    fn top_processes_truncated_to_eight() {
        // 10 unique processes — only the top 8 should survive
        let mut entries = Vec::new();
        for i in 0..10u32 {
            let count = 10 - i; // process 0 has count 10, process 9 has count 1
            for _ in 0..count {
                entries.push(
                    PortEntry::test("tcp", "0.0.0.0", (i * 100) as u16, "ESTABLISHED")
                        .with_process(i + 1, &format!("proc{}", i)),
                );
            }
        }

        let mut m = MetricsHistory::new();
        m.update(&entries, vec![]);

        assert_eq!(m.top_processes.len(), 8);
        // Highest count first
        assert_eq!(m.top_processes[0].0, "proc0");
        assert_eq!(m.top_processes[0].1, 10);
    }

    // ------------------------------------------------------------------
    // 4. max_net_rate
    // ------------------------------------------------------------------

    #[test]
    fn max_net_rate_empty_returns_floor() {
        let m = MetricsHistory::new();
        assert_eq!(m.max_net_rate(), 100.0);
    }

    #[test]
    fn max_net_rate_returns_max_of_rx_and_tx() {
        let mut m = MetricsHistory::new();
        m.rx_history.push_back(200.0);
        m.rx_history.push_back(150.0);
        m.tx_history.push_back(500.0);
        m.tx_history.push_back(300.0);
        assert_eq!(m.max_net_rate(), 500.0);
    }

    // ------------------------------------------------------------------
    // 5. update integration — net rates computed on second call
    // ------------------------------------------------------------------

    #[test]
    fn net_rates_stay_zero_on_first_update() {
        let stats = vec![InterfaceStats {
            name: "eth0".to_string(),
            rx_bytes: 1000,
            tx_bytes: 2000,
        }];

        let mut m = MetricsHistory::new();
        m.update(&[], stats);

        // First call has no prev_stats, so rates must remain 0
        assert_eq!(m.current_rx, 0.0);
        assert_eq!(m.current_tx, 0.0);
        assert!(m.rx_history.is_empty());
        assert!(m.tx_history.is_empty());
    }

    #[test]
    fn net_rates_computed_on_second_update() {
        let stats1 = vec![InterfaceStats {
            name: "eth0".to_string(),
            rx_bytes: 0,
            tx_bytes: 0,
        }];
        let stats2 = vec![InterfaceStats {
            name: "eth0".to_string(),
            rx_bytes: 10_000,
            tx_bytes: 5_000,
        }];

        let mut m = MetricsHistory::new();
        m.update(&[], stats1);

        // Sleep briefly so elapsed >= 0.01 s threshold
        std::thread::sleep(std::time::Duration::from_millis(20));

        m.update(&[], stats2);

        // Rates must now be positive
        assert!(m.current_rx > 0.0, "expected rx > 0, got {}", m.current_rx);
        assert!(m.current_tx > 0.0, "expected tx > 0, got {}", m.current_tx);
        assert_eq!(m.rx_history.len(), 1);
        assert_eq!(m.tx_history.len(), 1);
    }
}
