pub struct ColumnVisibility {
    pub proto: bool,
    pub local_addr: bool,
    pub local_port: bool,
    pub remote_addr: bool,
    pub remote_port: bool,
    pub state: bool,
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
    pub const OPTION_COUNT: usize = 14; // 10 columns + 3 graphs + 1 interval

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
            6 => self.columns.pid = !self.columns.pid,
            7 => self.columns.process = !self.columns.process,
            8 => self.columns.user = !self.columns.user,
            9 => self.columns.memory = !self.columns.memory,
            10 => self.graphs.network_activity = !self.graphs.network_activity,
            11 => self.graphs.connection_states = !self.graphs.connection_states,
            12 => self.graphs.process_stats = !self.graphs.process_stats,
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
            10 => Some("Graphs"),
            13 => Some("Settings"),
            _ => None,
        }
    }
}

pub enum OptionState {
    Toggle(bool),
    Value(u64),
}
