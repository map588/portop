pub struct ColumnVisibility {
    pub proto: bool,
    pub local_addr: bool,
    pub local_port: bool,
    pub remote_addr: bool,
    pub remote_port: bool,
    pub state: bool,
    pub direction: bool,
    pub pid: bool,
    pub process: bool,
    pub user: bool,
    pub memory: bool,
}

impl Default for ColumnVisibility {
    fn default() -> Self {
        Self {
            proto: true,
            local_addr: true,
            local_port: true,
            remote_addr: true,
            remote_port: true,
            state: true,
            direction: true,
            pid: true,
            process: true,
            user: true,
            memory: true,
        }
    }
}

pub struct GraphVisibility {
    pub network_activity: bool,
    pub connection_states: bool,
    pub process_stats: bool,
}

impl Default for GraphVisibility {
    fn default() -> Self {
        Self {
            network_activity: true,
            connection_states: true,
            process_stats: true,
        }
    }
}

pub struct Config {
    pub columns: ColumnVisibility,
    pub graphs: GraphVisibility,
    pub refresh_interval: u64,
}

impl Config {
    pub fn new(refresh_interval: u64) -> Self {
        Self {
            columns: ColumnVisibility::default(),
            graphs: GraphVisibility::default(),
            refresh_interval,
        }
    }

    /// Total number of selectable option items in the menu.
    pub const OPTION_COUNT: usize = 15; // 11 columns + 3 graphs + 1 interval

    /// Toggle or adjust the option at the given cursor index.
    /// For toggles, flips the bool. For interval, no-op (use adjust_interval).
    pub fn toggle(&mut self, index: usize) {
        match index {
            0 => self.columns.proto = !self.columns.proto,
            1 => self.columns.local_addr = !self.columns.local_addr,
            2 => self.columns.local_port = !self.columns.local_port,
            3 => self.columns.remote_addr = !self.columns.remote_addr,
            4 => self.columns.remote_port = !self.columns.remote_port,
            5 => self.columns.state = !self.columns.state,
            6 => self.columns.direction = !self.columns.direction,
            7 => self.columns.pid = !self.columns.pid,
            8 => self.columns.process = !self.columns.process,
            9 => self.columns.user = !self.columns.user,
            10 => self.columns.memory = !self.columns.memory,
            11 => self.graphs.network_activity = !self.graphs.network_activity,
            12 => self.graphs.connection_states = !self.graphs.connection_states,
            13 => self.graphs.process_stats = !self.graphs.process_stats,
            _ => {} // interval row — no-op for toggle
        }
    }

    pub fn adjust_interval(&mut self, delta: i64) {
        let new_val = self.refresh_interval as i64 + delta;
        self.refresh_interval = new_val.clamp(1, 30) as u64;
    }

    /// Returns (label, state_string) for each option item.
    pub fn option_items(&self) -> Vec<(&'static str, OptionState)> {
        vec![
            ("Protocol", OptionState::Toggle(self.columns.proto)),
            ("Local Address", OptionState::Toggle(self.columns.local_addr)),
            ("Local Port", OptionState::Toggle(self.columns.local_port)),
            ("Remote Address", OptionState::Toggle(self.columns.remote_addr)),
            ("Remote Port", OptionState::Toggle(self.columns.remote_port)),
            ("State", OptionState::Toggle(self.columns.state)),
            ("Direction", OptionState::Toggle(self.columns.direction)),
            ("PID", OptionState::Toggle(self.columns.pid)),
            ("Process", OptionState::Toggle(self.columns.process)),
            ("User", OptionState::Toggle(self.columns.user)),
            ("Memory", OptionState::Toggle(self.columns.memory)),
            ("Network Activity", OptionState::Toggle(self.graphs.network_activity)),
            ("Connection States", OptionState::Toggle(self.graphs.connection_states)),
            ("Process Stats", OptionState::Toggle(self.graphs.process_stats)),
            ("Refresh Interval", OptionState::Value(self.refresh_interval)),
        ]
    }

    /// Returns the section header index for a given option (for rendering).
    pub fn section_for(index: usize) -> Option<&'static str> {
        match index {
            0 => Some("Columns"),
            11 => Some("Graphs"),
            14 => Some("Settings"),
            _ => None,
        }
    }
}

pub enum OptionState {
    Toggle(bool),
    Value(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Config::new ---

    #[test]
    fn new_defaults_all_columns_true() {
        let cfg = Config::new(5);
        assert!(cfg.columns.proto);
        assert!(cfg.columns.local_addr);
        assert!(cfg.columns.local_port);
        assert!(cfg.columns.remote_addr);
        assert!(cfg.columns.remote_port);
        assert!(cfg.columns.state);
        assert!(cfg.columns.direction);
        assert!(cfg.columns.pid);
        assert!(cfg.columns.process);
        assert!(cfg.columns.user);
        assert!(cfg.columns.memory);
    }

    #[test]
    fn new_defaults_all_graphs_true() {
        let cfg = Config::new(5);
        assert!(cfg.graphs.network_activity);
        assert!(cfg.graphs.connection_states);
        assert!(cfg.graphs.process_stats);
    }

    #[test]
    fn new_stores_refresh_interval() {
        let cfg = Config::new(10);
        assert_eq!(cfg.refresh_interval, 10);
    }

    // --- Config::toggle ---

    #[test]
    fn toggle_index_0_proto_false_then_true() {
        let mut cfg = Config::new(5);
        assert!(cfg.columns.proto);
        cfg.toggle(0);
        assert!(!cfg.columns.proto);
        cfg.toggle(0);
        assert!(cfg.columns.proto);
    }

    #[test]
    fn toggle_index_5_state_becomes_false() {
        let mut cfg = Config::new(5);
        assert!(cfg.columns.state);
        cfg.toggle(5);
        assert!(!cfg.columns.state);
    }

    #[test]
    fn toggle_index_11_network_activity_becomes_false() {
        let mut cfg = Config::new(5);
        assert!(cfg.graphs.network_activity);
        cfg.toggle(11);
        assert!(!cfg.graphs.network_activity);
    }

    #[test]
    fn toggle_index_14_interval_row_is_noop() {
        let mut cfg = Config::new(5);
        cfg.toggle(14);
        assert_eq!(cfg.refresh_interval, 5);
    }

    #[test]
    fn toggle_out_of_range_is_noop() {
        let mut cfg = Config::new(5);
        cfg.toggle(20);
        // All columns and graphs should remain at their defaults.
        assert!(cfg.columns.proto);
        assert!(cfg.graphs.network_activity);
        assert_eq!(cfg.refresh_interval, 5);
    }

    // --- Config::adjust_interval ---

    #[test]
    fn adjust_interval_increment() {
        let mut cfg = Config::new(5);
        cfg.adjust_interval(1);
        assert_eq!(cfg.refresh_interval, 6);
    }

    #[test]
    fn adjust_interval_decrement() {
        let mut cfg = Config::new(5);
        cfg.adjust_interval(-1);
        assert_eq!(cfg.refresh_interval, 4);
    }

    #[test]
    fn adjust_interval_clamp_at_min() {
        let mut cfg = Config::new(1);
        cfg.adjust_interval(-1);
        assert_eq!(cfg.refresh_interval, 1);
    }

    #[test]
    fn adjust_interval_clamp_at_max() {
        let mut cfg = Config::new(30);
        cfg.adjust_interval(1);
        assert_eq!(cfg.refresh_interval, 30);
    }

    #[test]
    fn adjust_interval_large_negative_clamps_to_min() {
        let mut cfg = Config::new(5);
        cfg.adjust_interval(-100);
        assert_eq!(cfg.refresh_interval, 1);
    }

    // --- Config::option_items ---

    #[test]
    fn option_items_returns_option_count_items() {
        let cfg = Config::new(5);
        assert_eq!(cfg.option_items().len(), Config::OPTION_COUNT);
    }

    #[test]
    fn option_items_first_is_protocol_toggle_true() {
        let cfg = Config::new(5);
        let items = cfg.option_items();
        let (label, state) = &items[0];
        assert_eq!(*label, "Protocol");
        assert!(matches!(state, OptionState::Toggle(true)));
    }

    #[test]
    fn option_items_last_is_refresh_interval_value() {
        let cfg = Config::new(7);
        let items = cfg.option_items();
        let (label, state) = &items[Config::OPTION_COUNT - 1];
        assert_eq!(*label, "Refresh Interval");
        assert!(matches!(state, OptionState::Value(7)));
    }

    #[test]
    fn option_items_first_reflects_toggle_after_toggle() {
        let mut cfg = Config::new(5);
        cfg.toggle(0);
        let items = cfg.option_items();
        assert!(matches!(items[0].1, OptionState::Toggle(false)));
    }

    // --- Config::section_for ---

    #[test]
    fn section_for_index_0_is_columns() {
        assert_eq!(Config::section_for(0), Some("Columns"));
    }

    #[test]
    fn section_for_index_11_is_graphs() {
        assert_eq!(Config::section_for(11), Some("Graphs"));
    }

    #[test]
    fn section_for_index_14_is_settings() {
        assert_eq!(Config::section_for(14), Some("Settings"));
    }

    #[test]
    fn section_for_index_5_is_none() {
        assert_eq!(Config::section_for(5), None);
    }

    #[test]
    fn section_for_out_of_range_is_none() {
        assert_eq!(Config::section_for(99), None);
    }
}
