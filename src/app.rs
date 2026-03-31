use crate::config::Config;
use crate::metrics::MetricsHistory;
use crate::net_stats::{self, InterfaceStats};
use crate::port_scanner::{self, PortEntry};
use crate::tui::{self, Tui};
use crate::ui;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, MouseEvent, MouseEventKind, MouseButton};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppMode {
    Normal,
    Filter,
    ConfirmKill,
    Options,
    Sort,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortField {
    Protocol,
    LocalAddr,
    LocalPort,
    RemoteAddr,
    RemotePort,
    State,
    Pid,
    ProcessName,
}

pub const SORT_FIELDS: &[(SortField, &str)] = &[
    (SortField::LocalPort, "Local Port"),
    (SortField::Protocol, "Protocol"),
    (SortField::LocalAddr, "Local Address"),
    (SortField::RemoteAddr, "Remote Address"),
    (SortField::RemotePort, "Remote Port"),
    (SortField::State, "State"),
    (SortField::Pid, "PID"),
    (SortField::ProcessName, "Process Name"),
];

/// Data produced by the background scanner thread.
struct ScanResult {
    entries: Vec<PortEntry>,
    interface_stats: Vec<InterfaceStats>,
}

pub struct App {
    pub entries: Vec<PortEntry>,
    pub filtered_entries: Vec<PortEntry>,
    pub selected: Option<usize>,
    pub mode: AppMode,
    pub filter: String,
    pub sort_field: SortField,
    pub sort_ascending: bool,
    pub protocol_filter: String,
    pub last_refresh: Instant,
    pub message: Option<(String, Instant)>,
    pub config: Config,
    pub metrics: MetricsHistory,
    pub options_cursor: usize,
    pub sort_cursor: usize,
    pub table_offset: usize,

    /// Channel to receive scan results from background thread.
    scan_rx: mpsc::Receiver<ScanResult>,
    /// Flag to request an immediate refresh from the background thread.
    force_refresh: Arc<AtomicBool>,
    /// Shared refresh interval the background thread reads.
    shared_interval: Arc<AtomicU64>,
    /// Stored table area rect for mouse click resolution.
    pub table_area: ratatui::prelude::Rect,
}

impl App {
    pub fn new(refresh_interval: u64, protocol: &str) -> Self {
        let (scan_tx, scan_rx) = mpsc::channel();
        let force_refresh = Arc::new(AtomicBool::new(true)); // trigger immediate first scan
        let shared_interval = Arc::new(AtomicU64::new(refresh_interval));

        // Spawn background scanner thread
        {
            let force_flag = Arc::clone(&force_refresh);
            let interval_ref = Arc::clone(&shared_interval);
            std::thread::spawn(move || {
                scanner_loop(scan_tx, force_flag, interval_ref);
            });
        }

        Self {
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            selected: None,
            mode: AppMode::Normal,
            filter: String::new(),
            sort_field: SortField::LocalPort,
            sort_ascending: true,
            protocol_filter: protocol.to_string(),
            last_refresh: Instant::now(),
            message: None,
            config: Config::new(refresh_interval),
            metrics: MetricsHistory::new(),
            options_cursor: 0,
            sort_cursor: 0,
            table_offset: 0,
            scan_rx,
            force_refresh,
            shared_interval,
            table_area: ratatui::prelude::Rect::default(),
        }
    }

    /// Check for new data from the background scanner (non-blocking).
    fn poll_scan_results(&mut self) {
        // Drain all pending results, keep only the latest
        let mut latest: Option<ScanResult> = None;
        while let Ok(result) = self.scan_rx.try_recv() {
            latest = Some(result);
        }
        if let Some(result) = latest {
            self.entries = result.entries;
            self.apply_filter_and_sort();
            self.metrics.update(&self.entries, result.interface_stats);
            self.last_refresh = Instant::now();
        }
    }

    /// Request the background thread to refresh immediately.
    fn request_refresh(&self) {
        self.force_refresh.store(true, Ordering::Relaxed);
    }

    fn apply_filter_and_sort(&mut self) {
        let filter_lower = self.filter.to_lowercase();
        let proto = self.protocol_filter.to_lowercase();

        self.filtered_entries = self
            .entries
            .iter()
            .filter(|e| {
                if proto != "all" && !e.protocol.starts_with(&proto) {
                    return false;
                }
                if filter_lower.is_empty() {
                    return true;
                }
                let searchable = format!(
                    "{} {} {} {} {} {} {}",
                    e.protocol,
                    e.local_addr,
                    e.local_port,
                    e.remote_addr,
                    e.remote_port,
                    e.process_name,
                    e.process_user,
                )
                .to_lowercase();
                searchable.contains(&filter_lower)
            })
            .cloned()
            .collect();

        self.sort_entries();

        if let Some(sel) = self.selected {
            if sel >= self.filtered_entries.len() {
                self.selected = if self.filtered_entries.is_empty() {
                    None
                } else {
                    Some(self.filtered_entries.len() - 1)
                };
            }
        } else if !self.filtered_entries.is_empty() {
            self.selected = Some(0);
        }
    }

    fn sort_entries(&mut self) {
        self.filtered_entries.sort_by(|a, b| {
            let cmp = match self.sort_field {
                SortField::Protocol => a.protocol.cmp(&b.protocol),
                SortField::LocalAddr => a.local_addr.cmp(&b.local_addr),
                SortField::LocalPort => a.local_port.cmp(&b.local_port),
                SortField::RemoteAddr => a.remote_addr.cmp(&b.remote_addr),
                SortField::RemotePort => a.remote_port.cmp(&b.remote_port),
                SortField::State => a.state.cmp(&b.state),
                SortField::Pid => a.pid.cmp(&b.pid),
                SortField::ProcessName => a.process_name.cmp(&b.process_name),
            };
            if self.sort_ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });
    }

    fn select_up(&mut self) {
        if let Some(sel) = self.selected {
            if sel > 0 {
                self.selected = Some(sel - 1);
            }
        }
    }

    fn select_down(&mut self) {
        if let Some(sel) = self.selected {
            if sel < self.filtered_entries.len().saturating_sub(1) {
                self.selected = Some(sel + 1);
            }
        }
    }

    fn set_sort(&mut self, field: SortField) {
        if self.sort_field == field {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_field = field;
            self.sort_ascending = true;
        }
        self.sort_entries();
    }

    pub fn ensure_visible(&mut self, viewport_height: usize) {
        if let Some(sel) = self.selected {
            if sel < self.table_offset {
                self.table_offset = sel;
            } else if sel >= self.table_offset + viewport_height {
                self.table_offset = sel - viewport_height + 1;
            }
        }
    }

    fn do_kill(&mut self, signal: i32) {
        if let Some(idx) = self.selected {
            if let Some(entry) = self.filtered_entries.get(idx) {
                let pid = entry.pid;
                let name = entry.process_name.clone();
                let sig_name = if signal == 9 { "SIGKILL" } else { "SIGTERM" };
                if pid > 0 {
                    match port_scanner::kill_process(pid, signal) {
                        Ok(()) => {
                            self.message = Some((
                                format!("Sent {} to {} (PID {})", sig_name, name, pid),
                                Instant::now(),
                            ));
                            self.request_refresh();
                        }
                        Err(e) => {
                            self.message = Some((
                                format!("Failed to kill: {}", e),
                                Instant::now(),
                            ));
                        }
                    }
                }
            }
        }
        self.mode = AppMode::Normal;
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.mode {
            AppMode::Normal => match key.code {
                KeyCode::Char('q') => return false,
                KeyCode::Char('r') | KeyCode::F(5) => {
                    self.request_refresh();
                    self.message = Some(("Refreshing...".to_string(), Instant::now()));
                }
                KeyCode::Char('/') => {
                    self.mode = AppMode::Filter;
                }
                KeyCode::Char('s') => {
                    if self.selected.is_some() {
                        self.mode = AppMode::ConfirmKill;
                    }
                }
                KeyCode::Char('o') => {
                    self.mode = AppMode::Options;
                    self.options_cursor = 0;
                }
                KeyCode::Char('S') => {
                    self.mode = AppMode::Sort;
                    self.sort_cursor = SORT_FIELDS
                        .iter()
                        .position(|(f, _)| *f == self.sort_field)
                        .unwrap_or(0);
                }
                KeyCode::Char('1') => self.set_sort(SortField::LocalPort),
                KeyCode::Char('2') => self.set_sort(SortField::Protocol),
                KeyCode::Char('3') => self.set_sort(SortField::State),
                KeyCode::Char('4') => self.set_sort(SortField::Pid),
                KeyCode::Char('5') => self.set_sort(SortField::ProcessName),
                KeyCode::Char('k') | KeyCode::Up => self.select_up(),
                KeyCode::Char('j') | KeyCode::Down => self.select_down(),
                KeyCode::Char('g') => self.selected = Some(0),
                KeyCode::Char('G') => {
                    self.selected = if self.filtered_entries.is_empty() {
                        None
                    } else {
                        Some(self.filtered_entries.len() - 1)
                    }
                }
                KeyCode::PageUp => {
                    if let Some(sel) = self.selected {
                        self.selected = Some(sel.saturating_sub(10));
                    }
                }
                KeyCode::PageDown => {
                    if let Some(sel) = self.selected {
                        self.selected = Some(
                            (sel + 10).min(self.filtered_entries.len().saturating_sub(1)),
                        );
                    }
                }
                KeyCode::Esc => {
                    self.filter.clear();
                    self.apply_filter_and_sort();
                }
                _ => {}
            },
            AppMode::Filter => match key.code {
                KeyCode::Enter | KeyCode::Esc => {
                    self.mode = AppMode::Normal;
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.apply_filter_and_sort();
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.apply_filter_and_sort();
                }
                _ => {}
            },
            AppMode::ConfirmKill => match key.code {
                KeyCode::Enter => self.do_kill(9),
                KeyCode::Char('t') => self.do_kill(15),
                KeyCode::Esc => self.mode = AppMode::Normal,
                _ => {}
            },
            AppMode::Options => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    if self.options_cursor < Config::OPTION_COUNT - 1 {
                        self.options_cursor += 1;
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if self.options_cursor > 0 {
                        self.options_cursor -= 1;
                    }
                }
                KeyCode::Char(' ') | KeyCode::Enter => {
                    self.config.toggle(self.options_cursor);
                }
                KeyCode::Char('h') | KeyCode::Left => {
                    if self.options_cursor == Config::OPTION_COUNT - 1 {
                        self.config.adjust_interval(-1);
                        self.shared_interval.store(self.config.refresh_interval, Ordering::Relaxed);
                    }
                }
                KeyCode::Char('l') | KeyCode::Right => {
                    if self.options_cursor == Config::OPTION_COUNT - 1 {
                        self.config.adjust_interval(1);
                        self.shared_interval.store(self.config.refresh_interval, Ordering::Relaxed);
                    }
                }
                KeyCode::Esc | KeyCode::Char('o') => {
                    self.mode = AppMode::Normal;
                }
                _ => {}
            },
            AppMode::Sort => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    if self.sort_cursor < SORT_FIELDS.len() - 1 {
                        self.sort_cursor += 1;
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if self.sort_cursor > 0 {
                        self.sort_cursor -= 1;
                    }
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let field = SORT_FIELDS[self.sort_cursor].0;
                    self.set_sort(field);
                    self.mode = AppMode::Normal;
                }
                KeyCode::Esc | KeyCode::Char('S') => {
                    self.mode = AppMode::Normal;
                }
                _ => {}
            },
        }
        true
    }

    fn handle_mouse(&mut self, event: MouseEvent) {
        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let row = event.row;
                let ta = self.table_area;

                // Check if click is within the table data area
                // Table has: 1 border top + 1 header row, then data rows
                let data_start_y = ta.y + 2;
                let data_end_y = ta.y + ta.height.saturating_sub(1); // exclude bottom border

                if event.column >= ta.x
                    && event.column < ta.x + ta.width
                    && row >= data_start_y
                    && row < data_end_y
                {
                    let clicked_row = (row - data_start_y) as usize;
                    let absolute_idx = self.table_offset + clicked_row;
                    if absolute_idx < self.filtered_entries.len() {
                        self.selected = Some(absolute_idx);
                    }
                }
            }
            MouseEventKind::ScrollUp => self.select_up(),
            MouseEventKind::ScrollDown => self.select_down(),
            _ => {}
        }
    }
}

/// Background thread: scans ports and collects network stats on a timer.
/// Sends results over `tx`. Checks `force_flag` for immediate refresh requests.
fn scanner_loop(
    tx: mpsc::Sender<ScanResult>,
    force_flag: Arc<AtomicBool>,
    interval: Arc<AtomicU64>,
) {
    let poll_interval = Duration::from_millis(100);
    let mut last_scan = Instant::now() - Duration::from_secs(60); // ensure immediate first scan

    loop {
        let current_interval = interval.load(Ordering::Relaxed);
        let should_scan = force_flag.swap(false, Ordering::Relaxed)
            || last_scan.elapsed() >= Duration::from_secs(current_interval);

        if should_scan {
            let entries = port_scanner::scan_ports();
            let interface_stats = net_stats::collect_interface_stats();
            last_scan = Instant::now();

            if tx.send(ScanResult { entries, interface_stats }).is_err() {
                return; // main thread dropped the receiver, exit
            }
        }

        std::thread::sleep(poll_interval);
    }
}

pub fn run(mut terminal: Tui, app: &mut App) -> color_eyre::Result<()> {
    let tick_rate = Duration::from_millis(50); // faster tick for responsive UI

    loop {
        // Check for new data from background scanner (non-blocking)
        app.poll_scan_results();

        terminal.draw(|f| ui::draw(f, &mut *app))?;

        // Clear stale messages after 3s
        if let Some((_, ts)) = app.message {
            if ts.elapsed() > Duration::from_secs(3) {
                app.message = None;
            }
        }

        if let Some(event) = tui::poll_event(tick_rate)? {
            match event {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Press {
                        if !app.handle_key(key) {
                            return Ok(());
                        }
                    }
                }
                Event::Mouse(mouse) => {
                    app.handle_mouse(mouse);
                }
                _ => {}
            }
        }
    }
}
