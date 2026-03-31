use crate::port_scanner::{self, PortEntry};
use crate::tui::{self, Tui};
use crate::ui;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppMode {
    Normal,
    Filter,
    ConfirmKill,
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

pub struct App {
    pub entries: Vec<PortEntry>,
    pub filtered_entries: Vec<PortEntry>,
    pub selected: Option<usize>,
    pub mode: AppMode,
    pub filter: String,
    pub sort_field: SortField,
    pub sort_ascending: bool,
    pub refresh_interval: u64,
    pub protocol_filter: String,
    pub last_refresh: Instant,
    pub message: Option<(String, Instant)>,
}

impl App {
    pub fn new(refresh_interval: u64, protocol: &str) -> Self {
        let mut app = Self {
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            selected: None,
            mode: AppMode::Normal,
            filter: String::new(),
            sort_field: SortField::LocalPort,
            sort_ascending: true,
            refresh_interval,
            protocol_filter: protocol.to_string(),
            last_refresh: Instant::now(),
            message: None,
        };
        app.refresh_ports();
        app
    }

    pub fn refresh_ports(&mut self) {
        self.entries = port_scanner::scan_ports();
        self.apply_filter_and_sort();
        self.last_refresh = Instant::now();
    }

    fn apply_filter_and_sort(&mut self) {
        let filter_lower = self.filter.to_lowercase();
        let proto = self.protocol_filter.to_lowercase();

        self.filtered_entries = self
            .entries
            .iter()
            .filter(|e| {
                // Protocol filter
                if proto != "all" && !e.protocol.starts_with(&proto) {
                    return false;
                }
                // Text filter
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

        // Preserve selection or reset
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
                                format!("✓ Sent {} to {} (PID {})", sig_name, name, pid),
                                Instant::now(),
                            ));
                            std::thread::sleep(Duration::from_millis(300));
                            self.refresh_ports();
                        }
                        Err(e) => {
                            self.message = Some((
                                format!("✗ Failed to kill: {}", e),
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
                    self.refresh_ports();
                    self.message = Some(("↻ Refreshed".to_string(), Instant::now()));
                }
                KeyCode::Char('/') => {
                    self.mode = AppMode::Filter;
                }
                // 's' = signal (opens kill dialog)
                KeyCode::Char('s') => {
                    if self.selected.is_some() {
                        self.mode = AppMode::ConfirmKill;
                    }
                }
                // 'S' = cycle sort
                KeyCode::Char('S') => {
                    let fields = [
                        SortField::LocalPort,
                        SortField::Protocol,
                        SortField::State,
                        SortField::Pid,
                        SortField::ProcessName,
                        SortField::LocalAddr,
                    ];
                    let current_idx = fields.iter().position(|&f| f == self.sort_field).unwrap_or(0);
                    let next_idx = (current_idx + 1) % fields.len();
                    self.set_sort(fields[next_idx]);
                }
                KeyCode::Char('1') => self.set_sort(SortField::LocalPort),
                KeyCode::Char('2') => self.set_sort(SortField::Protocol),
                KeyCode::Char('3') => self.set_sort(SortField::State),
                KeyCode::Char('4') => self.set_sort(SortField::Pid),
                KeyCode::Char('5') => self.set_sort(SortField::ProcessName),
                // Vim-style navigation
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
                KeyCode::Char('h') => {
                    // Scroll left / no-op for now — reserved for horizontal scroll
                }
                KeyCode::Char('l') => {
                    // Scroll right / no-op for now — reserved for horizontal scroll
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
                KeyCode::Enter => {}
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
                KeyCode::Enter => self.do_kill(9),       // SIGKILL
                KeyCode::Char('t') => self.do_kill(15),   // SIGTERM
                KeyCode::Esc => self.mode = AppMode::Normal,
                _ => {}
            },
        }
        true
    }
}

pub fn run(mut terminal: Tui, app: &mut App) -> color_eyre::Result<()> {
    let tick_rate = Duration::from_millis(250);

    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        // Auto-refresh
        if app.last_refresh.elapsed() >= Duration::from_secs(app.refresh_interval) {
            app.refresh_ports();
        }

        // Clear stale messages after 3s
        if let Some((_, ts)) = app.message {
            if ts.elapsed() > Duration::from_secs(3) {
                app.message = None;
            }
        }

        if let Some(event) = tui::poll_event(tick_rate)? {
            if let Event::Key(key) = event {
                if key.kind == KeyEventKind::Press {
                    if !app.handle_key(key) {
                        return Ok(());
                    }
                }
            }
        }
    }
}
