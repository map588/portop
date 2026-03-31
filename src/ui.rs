use crate::app::{App, AppMode, SortField};
use ratatui::prelude::*;
use ratatui::widgets::*;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header / search
            Constraint::Min(5),   // table
            Constraint::Length(3), // status bar
        ])
        .split(f.area());

    draw_search_bar(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_status_bar(f, app, chunks[2]);

    if app.mode == AppMode::ConfirmKill {
        draw_kill_dialog(f, app);
    }
}

fn draw_search_bar(f: &mut Frame, app: &App, area: Rect) {
    let style = Style::default().fg(Color::Cyan).bold();
    let input_style = Style::default().fg(Color::Yellow);

    let title = if app.filter.is_empty() {
        Span::styled(" 🔍 PortMaster — Press / to filter, q to quit ", style)
    } else {
        Span::styled(
            format!(" 🔍 Filter: {}█", app.filter),
            input_style,
        )
    };

    let bar = Paragraph::new(Line::from(title))
        .style(Style::default().bg(Color::DarkGray))
        .alignment(Alignment::Left);
    f.render_widget(bar, area);
}

// Column display widths — each cell is padded/truncated to exactly this width
const W_PROTO: usize = 5;    // "tcp6"
const W_LADDR: usize = 15;   // IPv4 fits; IPv6 truncated
const W_PORT: usize = 5;
const W_RADDR: usize = 15;
const W_RPORT: usize = 5;
const W_STATE: usize = 11;   // "ESTABLISHED" = 11
const W_PID: usize = 7;
const W_PROC: usize = 15;
const W_USER: usize = 8;
const W_RSS: usize = 7;

fn sort_arrow(app: &App, field: SortField) -> &'static str {
    if app.sort_field == field {
        if app.sort_ascending { "▲" } else { "▼" }
    } else {
        " "
    }
}

fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let header_style = Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .bold();
    let highlight_style = Style::default().bg(Color::Blue).fg(Color::White).bold();

    let header = Row::new(vec![
        Cell::from(pad_to(format!("Proto{}", sort_arrow(app, SortField::Protocol)), W_PROTO)),
        Cell::from(pad_to(format!("L-Addr{}", sort_arrow(app, SortField::LocalAddr)), W_LADDR)),
        Cell::from(pad_to(format!("Port{}", sort_arrow(app, SortField::LocalPort)), W_PORT + 1)),
        Cell::from(pad_to(format!("R-Addr{}", sort_arrow(app, SortField::RemoteAddr)), W_RADDR)),
        Cell::from(pad_to(format!("RP{}", sort_arrow(app, SortField::RemotePort)), W_RPORT)),
        Cell::from(pad_to(format!("State{}", sort_arrow(app, SortField::State)), W_STATE)),
        Cell::from(pad_to(format!("PID{}", sort_arrow(app, SortField::Pid)), W_PID)),
        Cell::from(pad_to(format!("Process{}", sort_arrow(app, SortField::ProcessName)), W_PROC)),
        Cell::from(pad_to("User", W_USER)),
        Cell::from(pad_to("RSS(MB)", W_RSS)),
    ])
    .style(header_style);

    let rows: Vec<Row> = app
        .filtered_entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let state_style = match entry.state.as_str() {
                "LISTEN" => Style::default().fg(Color::Green),
                "ESTABLISHED" => Style::default().fg(Color::Yellow),
                "TIME_WAIT" | "CLOSE_WAIT" => Style::default().fg(Color::DarkGray),
                "UNREPLIED" => Style::default().fg(Color::Magenta),
                _ => Style::default().fg(Color::White),
            };

            let mem_mb = format!("{:.1}", entry.process_mem as f64 / 1024.0);

            let row = Row::new(vec![
                Cell::from(pad_to(&entry.protocol, W_PROTO)),
                Cell::from(fit_str(&entry.local_addr, W_LADDR)),
                Cell::from(format!("{:>width$}", entry.local_port, width = W_PORT)),
                Cell::from(fit_str(&entry.remote_addr, W_RADDR)),
                Cell::from(if entry.remote_port > 0 {
                    format!("{:>width$}", entry.remote_port, width = W_RPORT)
                } else {
                    pad_to("—", W_RPORT)
                }),
                Cell::from(Span::styled(
                    fit_str(&entry.state, W_STATE),
                    state_style,
                )),
                Cell::from(if entry.pid > 0 {
                    format!("{:>width$}", entry.pid, width = W_PID)
                } else {
                    pad_to("—", W_PID)
                }),
                Cell::from(fit_str(&entry.process_name, W_PROC)),
                Cell::from(fit_str(&entry.process_user, W_USER)),
                Cell::from(if entry.process_mem > 0 {
                    format!("{:>width$}", mem_mb, width = W_RSS)
                } else {
                    pad_to("—", W_RSS)
                }),
            ]);

            if Some(i) == app.selected {
                row.style(highlight_style)
            } else {
                row
            }
        })
        .collect();

    // Column widths must match the W_* constants exactly
    let widths = [
        Constraint::Length(W_PROTO as u16),
        Constraint::Length(W_LADDR as u16),
        Constraint::Length((W_PORT + 1) as u16),
        Constraint::Length(W_RADDR as u16),
        Constraint::Length(W_RPORT as u16),
        Constraint::Length(W_STATE as u16),
        Constraint::Length(W_PID as u16),
        Constraint::Length(W_PROC as u16),
        Constraint::Length(W_USER as u16),
        Constraint::Length(W_RSS as u16),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Open Ports "),
        );

    f.render_widget(table, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let selected_info = if let Some(idx) = app.selected {
        if let Some(entry) = app.filtered_entries.get(idx) {
            if entry.pid > 0 {
                format!(
                    " PID {} | {} | {}",
                    entry.pid,
                    truncate_str(&entry.process_cmdline, 60),
                    entry.process_user,
                )
            } else {
                " No process associated".to_string()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let left = Span::styled(
        format!(
            " {} ports | j/k nav | / filter | S sort | s signal | r refresh | q quit ",
            app.filtered_entries.len(),
        ),
        Style::default().fg(Color::Black).bg(Color::Cyan),
    );

    let right = Span::styled(
        format!("{} ", selected_info),
        Style::default().fg(Color::Black).bg(Color::Green),
    );

    let bar = Paragraph::new(Line::from(vec![left, right]));
    f.render_widget(bar, area);
}

fn draw_kill_dialog(f: &mut Frame, app: &App) {
    let entry = app
        .selected
        .and_then(|i| app.filtered_entries.get(i));

    let msg = if let Some(e) = entry {
        if e.pid > 0 {
            format!(
                "  Send signal to {} (PID: {})?\n\n  [Enter] SIGKILL (-9)  [t] SIGTERM (-15)  [Esc] Cancel  ",
                e.process_name, e.pid,
            )
        } else {
            "  No process to kill.\n\n  [Esc] Cancel  ".to_string()
        }
    } else {
        "  Nothing selected.\n\n  [Esc] Cancel  ".to_string()
    };

    let dialog = Paragraph::new(msg)
        .style(Style::default().fg(Color::Red).bold())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(" ⚠ Signal "),
        );

    let area = centered_rect(50, 20, f.area());
    f.render_widget(Clear, area);
    f.render_widget(dialog, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Compute display width of a string
fn display_width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
}

/// Pad a string to exactly `width` display columns (left-aligned).
/// Truncates with '…' if too wide.
fn pad_to(s: impl AsRef<str>, width: usize) -> String {
    let s = s.as_ref();
    let dw = display_width(s);
    if dw > width {
        truncate_to_width(s, width)
    } else {
        // Right-pad with spaces to hit exactly `width` display columns
        let padding = width - dw;
        let mut out = String::with_capacity(s.len() + padding);
        out.push_str(s);
        for _ in 0..padding {
            out.push(' ');
        }
        out
    }
}

/// Fit a string to exactly `width` display columns.
/// Truncates with '…' if too wide, right-pads with spaces if too narrow.
fn fit_str(s: &str, width: usize) -> String {
    pad_to(s, width)
}

/// Truncate a string to fit within `width` display columns, appending '…' if needed.
/// Result is padded to exactly `width` columns.
fn truncate_to_width(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".to_string();
    }
    // Find cutoff where display width <= width - 1 (leaving room for '…')
    let mut col = 0;
    let mut cutoff = s.len();
    for (i, ch) in s.char_indices() {
        let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if col + w > width - 1 {
            cutoff = i;
            break;
        }
        col += w;
    }
    let mut result = format!("{}…", &s[..cutoff]);
    let result_w = display_width(&result);
    if result_w < width {
        for _ in 0..(width - result_w) {
            result.push(' ');
        }
    }
    result
}

/// Simple truncate for non-column contexts (status bar etc)
fn truncate_str(s: &str, max: usize) -> String {
    let width = display_width(s);
    if width > max {
        truncate_to_width(s, max)
    } else {
        s.to_string()
    }
}
