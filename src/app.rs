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

/// Detailed info gathered for a single process.
#[derive(Debug, Clone)]
pub struct ProcessDetail {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
    pub mem_kb: u64,
    /// All port entries belonging to this PID.
    pub connections: Vec<PortEntry>,
    /// Open file descriptors (from lsof).
    pub open_files: Vec<OpenFile>,
    pub scroll_offset: usize,
}

#[derive(Debug, Clone)]
pub struct OpenFile {
    pub fd: String,
    pub file_type: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppMode {
    Normal,
    Filter,
    ConfirmKill,
    Options,
    Sort,
    Detail,
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
    Direction,
    User,
    Memory,
}

pub const SORT_FIELDS: &[(SortField, &str)] = &[
    (SortField::LocalPort, "Local Port"),
    (SortField::Protocol, "Protocol"),
    (SortField::LocalAddr, "Local Address"),
    (SortField::RemoteAddr, "Remote Address"),
    (SortField::RemotePort, "Remote Port"),
    (SortField::State, "State"),
    (SortField::Direction, "Direction"),
    (SortField::Pid, "PID"),
    (SortField::ProcessName, "Process Name"),
    (SortField::User, "User"),
    (SortField::Memory, "Memory"),
];

/// Data produced by the background scanner thread.
struct ScanResult {
    entries: Vec<PortEntry>,
    interface_stats: Vec<InterfaceStats>,
}

pub struct App {
    pub entries: Vec<PortEntry>,
    /// Indices into `entries` for the currently visible (filtered + sorted) rows.
    filtered_indices: Vec<usize>,
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

    scan_rx: mpsc::Receiver<ScanResult>,
    force_refresh: Arc<AtomicBool>,
    shared_interval: Arc<AtomicU64>,
    pub table_area: ratatui::prelude::Rect,
    /// Maps (x_start, x_end) ranges to SortField for header click detection.
    pub header_columns: Vec<(u16, u16, SortField)>,
    pub detail: Option<ProcessDetail>,
    last_click: Option<(u16, u16, Instant)>,
}

impl App {
    pub fn new(refresh_interval: u64, protocol: &str) -> Self {
        let (scan_tx, scan_rx) = mpsc::channel();
        let force_refresh = Arc::new(AtomicBool::new(true));
        let shared_interval = Arc::new(AtomicU64::new(refresh_interval));

        {
            let force_flag = Arc::clone(&force_refresh);
            let interval_ref = Arc::clone(&shared_interval);
            std::thread::spawn(move || {
                scanner_loop(scan_tx, force_flag, interval_ref);
            });
        }

        Self {
            entries: Vec::new(),
            filtered_indices: Vec::new(),
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
            header_columns: Vec::new(),
            detail: None,
            last_click: None,
        }
    }

    // -- Accessors for filtered view --

    /// Number of visible (filtered) entries.
    pub fn filtered_len(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Get a filtered entry by filtered-view index.
    pub fn filtered_entry(&self, idx: usize) -> Option<&PortEntry> {
        self.filtered_indices
            .get(idx)
            .and_then(|&i| self.entries.get(i))
    }

    /// Iterate over a slice of filtered entries (for the visible window).
    pub fn filtered_slice(&self, start: usize, end: usize) -> impl Iterator<Item = &PortEntry> {
        self.filtered_indices[start..end]
            .iter()
            .map(|&i| &self.entries[i])
    }

    // -- Data updates --

    fn poll_scan_results(&mut self) {
        let mut latest: Option<ScanResult> = None;
        while let Ok(result) = self.scan_rx.try_recv() {
            latest = Some(result);
        }
        if let Some(result) = latest {
            self.entries = result.entries;
            self.apply_filter_and_sort();
            self.metrics.update(&self.entries, result.interface_stats);
            self.last_refresh = Instant::now();
            self.refresh_detail();
        }
    }

    fn request_refresh(&self) {
        self.force_refresh.store(true, Ordering::Relaxed);
    }

    fn apply_filter_and_sort(&mut self) {
        let filter_lower = self.filter.to_lowercase();
        let proto = self.protocol_filter.to_lowercase();

        self.filtered_indices = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                if proto != "all" && !e.protocol.starts_with(&proto) {
                    return false;
                }
                if filter_lower.is_empty() {
                    return true;
                }
                let searchable = format!(
                    "{} {} {} {} {} {} {} {} {}",
                    e.protocol,
                    e.local_addr,
                    e.local_port,
                    e.remote_addr,
                    e.remote_host.as_deref().unwrap_or(""),
                    e.remote_port,
                    e.direction,
                    e.process_name,
                    e.process_user,
                )
                .to_lowercase();
                searchable.contains(&filter_lower)
            })
            .map(|(i, _)| i)
            .collect();

        self.sort_entries();

        if let Some(sel) = self.selected {
            if sel >= self.filtered_indices.len() {
                self.selected = if self.filtered_indices.is_empty() {
                    None
                } else {
                    Some(self.filtered_indices.len() - 1)
                };
            }
        } else if !self.filtered_indices.is_empty() {
            self.selected = Some(0);
        }
    }

    fn sort_entries(&mut self) {
        let entries = &self.entries;
        let field = self.sort_field;
        let ascending = self.sort_ascending;

        self.filtered_indices.sort_by(|&ai, &bi| {
            let a = &entries[ai];
            let b = &entries[bi];
            let cmp = match field {
                SortField::Protocol => a.protocol.cmp(&b.protocol),
                SortField::LocalAddr => a.local_addr.cmp(&b.local_addr),
                SortField::LocalPort => a.local_port.cmp(&b.local_port),
                SortField::RemoteAddr => a.remote_addr.cmp(&b.remote_addr),
                SortField::RemotePort => a.remote_port.cmp(&b.remote_port),
                SortField::State => a.state.cmp(&b.state),
                SortField::Pid => a.pid.cmp(&b.pid),
                SortField::ProcessName => a.process_name.cmp(&b.process_name),
                SortField::Direction => a.direction.cmp(&b.direction),
                SortField::User => a.process_user.cmp(&b.process_user),
                SortField::Memory => a.process_mem.cmp(&b.process_mem),
            };
            if ascending { cmp } else { cmp.reverse() }
        });
    }

    // -- Navigation --

    fn select_up(&mut self) {
        if let Some(sel) = self.selected {
            if sel > 0 {
                self.selected = Some(sel - 1);
            }
        }
    }

    fn select_down(&mut self) {
        if let Some(sel) = self.selected {
            if sel < self.filtered_indices.len().saturating_sub(1) {
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
            if let Some(entry) = self.filtered_entry(idx) {
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

    fn refresh_detail(&mut self) {
        if let Some(ref mut detail) = self.detail {
            let pid = detail.pid;

            // Update connections from latest entries
            detail.connections = self
                .entries
                .iter()
                .filter(|e| e.pid == pid)
                .cloned()
                .collect();

            // Update process info from any matching entry
            if let Some(entry) = self.entries.iter().find(|e| e.pid == pid) {
                detail.name = entry.process_name.clone();
                detail.cmdline = entry.process_cmdline.clone();
                detail.user = entry.process_user.clone();
                detail.mem_kb = entry.process_mem;
            }

            // Refresh open files
            detail.open_files = gather_open_files(pid);
        }
    }

    fn enter_detail(&mut self) {
        if let Some(idx) = self.selected {
            if let Some(entry) = self.filtered_entry(idx) {
                let pid = entry.pid;
                if pid == 0 {
                    return;
                }
                let name = entry.process_name.clone();
                let cmdline = entry.process_cmdline.clone();
                let user = entry.process_user.clone();
                let mem_kb = entry.process_mem;

                let connections: Vec<PortEntry> = self
                    .entries
                    .iter()
                    .filter(|e| e.pid == pid)
                    .cloned()
                    .collect();

                let open_files = gather_open_files(pid);

                self.detail = Some(ProcessDetail {
                    pid,
                    name,
                    cmdline,
                    user,
                    mem_kb,
                    connections,
                    open_files,
                    scroll_offset: 0,
                });
                self.mode = AppMode::Detail;
            }
        }
    }

    // -- Input handling --

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
                KeyCode::Enter => self.enter_detail(),
                KeyCode::Char('k') | KeyCode::Up => self.select_up(),
                KeyCode::Char('j') | KeyCode::Down => self.select_down(),
                KeyCode::Char('g') => self.selected = Some(0),
                KeyCode::Char('G') => {
                    self.selected = if self.filtered_indices.is_empty() {
                        None
                    } else {
                        Some(self.filtered_indices.len() - 1)
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
                            (sel + 10).min(self.filtered_indices.len().saturating_sub(1)),
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
            AppMode::Detail => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                    self.mode = AppMode::Normal;
                    self.detail = None;
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    if let Some(ref mut d) = self.detail {
                        d.scroll_offset = d.scroll_offset.saturating_add(1);
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if let Some(ref mut d) = self.detail {
                        d.scroll_offset = d.scroll_offset.saturating_sub(1);
                    }
                }
                KeyCode::PageDown => {
                    if let Some(ref mut d) = self.detail {
                        d.scroll_offset = d.scroll_offset.saturating_add(10);
                    }
                }
                KeyCode::PageUp => {
                    if let Some(ref mut d) = self.detail {
                        d.scroll_offset = d.scroll_offset.saturating_sub(10);
                    }
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
        if self.mode == AppMode::Detail {
            match event.kind {
                MouseEventKind::ScrollUp => {
                    if let Some(ref mut d) = self.detail {
                        d.scroll_offset = d.scroll_offset.saturating_sub(3);
                    }
                }
                MouseEventKind::ScrollDown => {
                    if let Some(ref mut d) = self.detail {
                        d.scroll_offset = d.scroll_offset.saturating_add(3);
                    }
                }
                _ => {}
            }
            return;
        }

        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let row = event.row;
                let col = event.column;
                let ta = self.table_area;

                let header_y = ta.y + 1;
                let data_start_y = ta.y + 2;
                let data_end_y = ta.y + ta.height.saturating_sub(1);

                if row == header_y {
                    // Click on header row — sort by that column
                    for &(x_start, x_end, field) in &self.header_columns {
                        if col >= x_start && col < x_end {
                            self.set_sort(field);
                            break;
                        }
                    }
                } else if col >= ta.x
                    && col < ta.x + ta.width
                    && row >= data_start_y
                    && row < data_end_y
                {
                    let clicked_row = (row - data_start_y) as usize;
                    let absolute_idx = self.table_offset + clicked_row;
                    if absolute_idx < self.filtered_indices.len() {
                        // Double-click detection
                        let is_double = if let Some((pr, pc, pt)) = self.last_click {
                            pr == row && pc == col && pt.elapsed() < Duration::from_millis(400)
                        } else {
                            false
                        };

                        self.selected = Some(absolute_idx);

                        if is_double {
                            self.enter_detail();
                            self.last_click = None;
                        } else {
                            self.last_click = Some((row, col, Instant::now()));
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => self.select_up(),
            MouseEventKind::ScrollDown => self.select_down(),
            _ => {}
        }
    }
}

fn scanner_loop(
    tx: mpsc::Sender<ScanResult>,
    force_flag: Arc<AtomicBool>,
    interval: Arc<AtomicU64>,
) {
    let poll_interval = Duration::from_millis(100);
    let mut last_scan = Instant::now() - Duration::from_secs(60);
    let mut dns_cache = port_scanner::DnsCache::new();

    loop {
        let current_interval = interval.load(Ordering::Relaxed);
        let should_scan = force_flag.swap(false, Ordering::Relaxed)
            || last_scan.elapsed() >= Duration::from_secs(current_interval);

        if should_scan {
            let mut entries = port_scanner::scan_ports();
            let interface_stats = net_stats::collect_interface_stats();
            dns_cache.resolve_entries(&mut entries);
            last_scan = Instant::now();

            if tx.send(ScanResult { entries, interface_stats }).is_err() {
                return;
            }
        }

        std::thread::sleep(poll_interval);
    }
}

/// Gather open files for a process using lsof.
#[cfg(unix)]
fn gather_open_files(pid: u32) -> Vec<OpenFile> {
    use std::process::Command;

    let output = match Command::new("lsof")
        .args(["-p", &pid.to_string(), "-n", "-P", "-w", "-F", "ftfn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();
    let mut fd = String::new();
    let mut ftype = String::new();
    let mut name = String::new();

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let (tag, value) = (line.as_bytes()[0], &line[1..]);
        match tag {
            b'f' => {
                // Flush previous entry
                if !fd.is_empty() && !name.is_empty() {
                    files.push(OpenFile {
                        fd: fd.clone(),
                        file_type: ftype.clone(),
                        name: name.clone(),
                    });
                }
                fd = value.to_string();
                ftype.clear();
                name.clear();
            }
            b't' => ftype = value.to_string(),
            b'n' => name = value.to_string(),
            _ => {}
        }
    }
    // Flush last
    if !fd.is_empty() && !name.is_empty() {
        files.push(OpenFile {
            fd,
            file_type: ftype,
            name,
        });
    }

    files
}

#[cfg(target_os = "windows")]
fn gather_open_files(_pid: u32) -> Vec<OpenFile> {
    // Windows doesn't have lsof; could use handle.exe but it's not standard
    Vec::new()
}

pub fn run(mut terminal: Tui, app: &mut App) -> color_eyre::Result<()> {
    let tick_rate = Duration::from_millis(50);

    loop {
        app.poll_scan_results();

        terminal.draw(|f| ui::draw(f, &mut *app))?;

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
