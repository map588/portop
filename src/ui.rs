use crate::app::{App, AppMode, SortField, SORT_FIELDS};
use crate::config::OptionState;
use ratatui::prelude::*;
use ratatui::widgets::*;

pub fn draw(f: &mut Frame, app: &mut App) {
    let has_net = app.config.graphs.network_activity;
    let has_bars = app.config.graphs.connection_states || app.config.graphs.process_stats;

    let mut constraints = vec![
        Constraint::Length(3), // search bar
        Constraint::Min(5),   // table
    ];
    if has_net {
        constraints.push(Constraint::Length(10));
    }
    if has_bars {
        constraints.push(Constraint::Length(10));
    }
    constraints.push(Constraint::Length(3)); // status bar

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    draw_search_bar(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);

    let mut graph_idx = 2;
    if has_net {
        draw_network_chart(f, app, chunks[graph_idx]);
        graph_idx += 1;
    }
    if has_bars {
        draw_bar_charts(f, app, chunks[graph_idx]);
        graph_idx += 1;
    }

    draw_status_bar(f, app, chunks[graph_idx]);

    if app.mode == AppMode::ConfirmKill {
        draw_kill_dialog(f, app);
    }
    if app.mode == AppMode::Options {
        draw_options_menu(f, app);
    }
    if app.mode == AppMode::Sort {
        draw_sort_menu(f, app);
    }
}

fn draw_search_bar(f: &mut Frame, app: &App, area: Rect) {
    let style = Style::default().fg(Color::Cyan).bold();
    let input_style = Style::default().fg(Color::Yellow);

    let title = if app.filter.is_empty() {
        Span::styled(" portop — Press / to filter, o options, q to quit ", style)
    } else {
        Span::styled(format!(" Filter: {}_", app.filter), input_style)
    };

    let bar = Paragraph::new(Line::from(title))
        .style(Style::default().bg(Color::DarkGray))
        .alignment(Alignment::Left);
    f.render_widget(bar, area);
}

// Column display widths
const W_PROTO: usize = 5;
const W_LADDR: usize = 15;
const W_PORT: usize = 5;
const W_RADDR: usize = 15;
const W_RPORT: usize = 5;
const W_STATE: usize = 11;
const W_DIR: usize = 10;
const W_PID: usize = 7;
const W_MEM: usize = 7;

fn sort_arrow(app: &App, field: SortField) -> &'static str {
    if app.sort_field == field {
        if app.sort_ascending {
            "▲"
        } else {
            "▼"
        }
    } else {
        " "
    }
}

/// Helper to build a visible column definition.
struct ColDef {
    constraint: Constraint,
    header: Cell<'static>,
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    app.table_area = area; // store for mouse click resolution

    let header_style = Style::default().fg(Color::Black).bg(Color::Cyan).bold();
    let highlight_style = Style::default().bg(Color::Blue).fg(Color::White).bold();

    // Table area minus borders (2) and header (1)
    let viewport_height = area.height.saturating_sub(3) as usize;
    app.ensure_visible(viewport_height);

    let cols = &app.config.columns;

    // Build visible column definitions
    let mut col_defs: Vec<ColDef> = Vec::new();

    if cols.proto {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_PROTO as u16),
            header: Cell::from(pad_to(
                format!("Proto{}", sort_arrow(app, SortField::Protocol)),
                W_PROTO,
            )),
        });
    }
    if cols.local_addr {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_LADDR as u16),
            header: Cell::from(pad_to(
                format!("L-Addr{}", sort_arrow(app, SortField::LocalAddr)),
                W_LADDR,
            )),
        });
    }
    if cols.local_port {
        col_defs.push(ColDef {
            constraint: Constraint::Length((W_PORT + 1) as u16),
            header: Cell::from(pad_to(
                format!("Port{}", sort_arrow(app, SortField::LocalPort)),
                W_PORT + 1,
            )),
        });
    }
    if cols.remote_addr {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_RADDR as u16),
            header: Cell::from(pad_to(
                format!("R-Addr{}", sort_arrow(app, SortField::RemoteAddr)),
                W_RADDR,
            )),
        });
    }
    if cols.remote_port {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_RPORT as u16),
            header: Cell::from(pad_to(
                format!("RP{}", sort_arrow(app, SortField::RemotePort)),
                W_RPORT,
            )),
        });
    }
    if cols.state {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_STATE as u16),
            header: Cell::from(pad_to(
                format!("State{}", sort_arrow(app, SortField::State)),
                W_STATE,
            )),
        });
    }
    if cols.direction {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_DIR as u16),
            header: Cell::from(pad_to(
                format!("Direction{}", sort_arrow(app, SortField::Direction)),
                W_DIR,
            )),
        });
    }
    if cols.pid {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_PID as u16),
            header: Cell::from(pad_to(
                format!("PID{}", sort_arrow(app, SortField::Pid)),
                W_PID,
            )),
        });
    }
    if cols.process {
        col_defs.push(ColDef {
            constraint: Constraint::Fill(2),
            header: Cell::from(format!("Process{}", sort_arrow(app, SortField::ProcessName))),
        });
    }
    if cols.user {
        col_defs.push(ColDef {
            constraint: Constraint::Fill(1),
            header: Cell::from("User"),
        });
    }
    if cols.memory {
        col_defs.push(ColDef {
            constraint: Constraint::Length(W_MEM as u16),
            header: Cell::from(pad_to("Mem(MB)", W_MEM)),
        });
    }

    let widths: Vec<Constraint> = col_defs.iter().map(|c| c.constraint).collect();
    let header = Row::new(col_defs.into_iter().map(|c| c.header).collect::<Vec<_>>())
        .style(header_style);

    let offset = app.table_offset;
    let visible_end = (offset + viewport_height).min(app.filtered_len());

    let rows: Vec<Row> = app
        .filtered_slice(offset, visible_end)
        .enumerate()
        .map(|(vi, entry)| {
            let i = vi + offset; // absolute index
            let state_style = Style::default().fg(state_color(&entry.state));

            let mem_mb = format!("{:.1}", entry.process_mem as f64 / 1024.0);

            let mut cells: Vec<Cell> = Vec::new();

            if cols.proto {
                cells.push(Cell::from(pad_to(&entry.protocol, W_PROTO)));
            }
            if cols.local_addr {
                cells.push(Cell::from(pad_to(&entry.local_addr, W_LADDR)));
            }
            if cols.local_port {
                cells.push(Cell::from(format!(
                    "{:>width$}",
                    entry.local_port,
                    width = W_PORT
                )));
            }
            if cols.remote_addr {
                cells.push(Cell::from(pad_to(&entry.remote_addr, W_RADDR)));
            }
            if cols.remote_port {
                cells.push(Cell::from(if entry.remote_port > 0 {
                    format!("{:>width$}", entry.remote_port, width = W_RPORT)
                } else {
                    pad_to("—", W_RPORT)
                }));
            }
            if cols.state {
                cells.push(Cell::from(Span::styled(
                    pad_to(&entry.state, W_STATE),
                    state_style,
                )));
            }
            if cols.direction {
                let dir_style = Style::default().fg(direction_color(&entry.direction));
                let dir_label = match entry.direction.as_str() {
                    "Inbound" => "\u{25c2} In",
                    "Outbound" => "\u{25b8} Out",
                    "Listen" => "\u{25cf} Listen",
                    "Loopback" => "\u{21c4} Loop",
                    "Local" => "\u{00b7} Local",
                    other => other,
                };
                cells.push(Cell::from(Span::styled(
                    pad_to(dir_label, W_DIR),
                    dir_style,
                )));
            }
            if cols.pid {
                cells.push(Cell::from(if entry.pid > 0 {
                    format!("{:>width$}", entry.pid, width = W_PID)
                } else {
                    pad_to("—", W_PID)
                }));
            }
            if cols.process {
                cells.push(Cell::from(entry.process_name.as_str()));
            }
            if cols.user {
                cells.push(Cell::from(entry.process_user.as_str()));
            }
            if cols.memory {
                cells.push(Cell::from(if entry.process_mem > 0 {
                    format!("{:>width$}", mem_mb, width = W_MEM)
                } else {
                    pad_to("—", W_MEM)
                }));
            }

            let row = Row::new(cells);
            if Some(i) == app.selected {
                row.style(highlight_style)
            } else {
                row
            }
        })
        .collect();

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Open Ports "),
    );

    f.render_widget(table, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let selected_info = if let Some(idx) = app.selected {
        if let Some(entry) = app.filtered_entry(idx) {
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

    let msg = if let Some((ref text, _)) = app.message {
        format!(" {} |", text)
    } else {
        String::new()
    };

    let left = Span::styled(
        format!(
            " {} ports |{} j/k nav | / filter | S sort | s signal | o options | r refresh | q quit ",
            app.filtered_len(),
            msg,
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
    let entry = app.selected.and_then(|i| app.filtered_entry(i));

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
                .title(" Signal "),
        );

    let area = centered_rect(50, 20, f.area());
    f.render_widget(Clear, area);
    f.render_widget(dialog, area);
}

// ---------------------------------------------------------------------------
// Options menu overlay
// ---------------------------------------------------------------------------

fn draw_options_menu(f: &mut Frame, app: &App) {
    let area = centered_rect(50, 70, f.area());
    f.render_widget(Clear, area);

    let items = app.config.option_items();
    let mut lines: Vec<Line> = Vec::new();

    for (idx, (label, state)) in items.iter().enumerate() {
        // Section header
        if let Some(section) = crate::config::Config::section_for(idx) {
            if idx > 0 {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!("  {}:", section),
                Style::default().fg(Color::Cyan).bold(),
            )));
        }

        let is_selected = idx == app.options_cursor;
        let marker = if is_selected { ">" } else { " " };

        let line_text = match state {
            OptionState::Toggle(on) => {
                let check = if *on { "x" } else { " " };
                format!("  {} [{}] {}", marker, check, label)
            }
            OptionState::Value(val) => {
                format!("  {}     {} < {}s >", marker, label, val)
            }
        };

        let style = if is_selected {
            Style::default().fg(Color::White).bg(Color::Blue).bold()
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(Span::styled(line_text, style)));
    }

    // Help footer
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  j/k nav  Space toggle  h/l adjust  Esc close",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Options "),
    );

    f.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Sort menu overlay
// ---------------------------------------------------------------------------

fn draw_sort_menu(f: &mut Frame, app: &App) {
    let area = centered_rect(40, 50, f.area());
    f.render_widget(Clear, area);

    let mut lines: Vec<Line> = Vec::new();

    for (idx, (field, label)) in SORT_FIELDS.iter().enumerate() {
        let is_selected = idx == app.sort_cursor;
        let is_active = *field == app.sort_field;
        let marker = if is_selected { ">" } else { " " };
        let arrow = if is_active {
            if app.sort_ascending { " ▲" } else { " ▼" }
        } else {
            ""
        };

        let line_text = format!("  {} {}{}", marker, label, arrow);

        let style = if is_selected {
            Style::default().fg(Color::White).bg(Color::Blue).bold()
        } else if is_active {
            Style::default().fg(Color::Cyan).bold()
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(Span::styled(line_text, style)));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  j/k nav  Enter select  Esc close",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Sort By "),
    );

    f.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Graph panels
// ---------------------------------------------------------------------------

fn draw_network_chart(f: &mut Frame, app: &App, area: Rect) {
    let max_rate = app.metrics.max_net_rate();
    let len = app.metrics.rx_history.len().max(app.metrics.tx_history.len());
    let x_max = (len as f64).max(10.0); // at least 10 so early points aren't squished

    let rx_data: Vec<(f64, f64)> = app
        .metrics
        .rx_history
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v))
        .collect();

    let tx_data: Vec<(f64, f64)> = app
        .metrics
        .tx_history
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v))
        .collect();

    let rx_label = format!("RX {}", format_bytes_rate(app.metrics.current_rx));
    let tx_label = format!("TX {}", format_bytes_rate(app.metrics.current_tx));

    let datasets = vec![
        Dataset::default()
            .name(rx_label)
            .marker(symbols::Marker::Braille)
            .graph_type(ratatui::widgets::GraphType::Line)
            .style(Style::default().fg(Color::Green))
            .data(&rx_data),
        Dataset::default()
            .name(tx_label)
            .marker(symbols::Marker::Braille)
            .graph_type(ratatui::widgets::GraphType::Line)
            .style(Style::default().fg(Color::Red))
            .data(&tx_data),
    ];

    let y_label = format_bytes_rate(max_rate);
    let y_mid = format_bytes_rate(max_rate / 2.0);

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Network I/O "),
        )
        .x_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, x_max])
                .labels(vec![
                    Line::from(format!("{}s ago", len * 2)),
                    Line::from("now"),
                ]),
        )
        .y_axis(
            Axis::default()
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, max_rate])
                .labels(vec![
                    Line::from("0"),
                    Line::from(y_mid),
                    Line::from(y_label),
                ]),
        )
        .legend_position(Some(ratatui::widgets::LegendPosition::TopRight));

    f.render_widget(chart, area);
}

/// Render connection-state and process bar charts side-by-side.
fn draw_bar_charts(f: &mut Frame, app: &App, area: Rect) {
    let show_states = app.config.graphs.connection_states;
    let show_procs = app.config.graphs.process_stats;

    let h_constraints = match (show_states, show_procs) {
        (true, true) => vec![Constraint::Percentage(50), Constraint::Percentage(50)],
        (true, false) => vec![Constraint::Percentage(100)],
        (false, true) => vec![Constraint::Percentage(100)],
        _ => return,
    };

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(h_constraints)
        .split(area);

    let mut panel_idx = 0;

    if show_states {
        let bar_data: Vec<(&str, u64)> = app
            .metrics
            .state_counts
            .iter()
            .map(|(s, c)| (s.as_str(), *c))
            .collect();

        let bars: Vec<Bar> = bar_data
            .iter()
            .map(|(label, value)| {
                let color = state_color(label);
                Bar::default()
                    .label(Line::from(*label))
                    .value(*value)
                    .style(Style::default().fg(color))
            })
            .collect();

        let group = BarGroup::default().bars(&bars);
        let n = bars.len().max(1) as u16;
        let avail = panels[panel_idx].width.saturating_sub(2); // borders
        let bar_w = ((avail / n).max(1)).min(8);

        let chart = BarChart::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Connection States "),
            )
            .data(group)
            .bar_width(bar_w)
            .bar_gap(1)
            .bar_style(Style::default().fg(Color::Cyan))
            .value_style(Style::default().fg(Color::White).bold());

        f.render_widget(chart, panels[panel_idx]);
        panel_idx += 1;
    }

    if show_procs {
        let bars: Vec<Bar> = app
            .metrics
            .top_processes
            .iter()
            .map(|(name, count)| {
                Bar::default()
                    .label(Line::from(name.as_str()))
                    .value(*count)
                    .style(Style::default().fg(Color::Yellow))
            })
            .collect();

        let group = BarGroup::default().bars(&bars);
        let n = bars.len().max(1) as u16;
        let avail = panels[panel_idx].width.saturating_sub(2);
        let bar_w = ((avail / n).max(1)).min(8);

        let chart = BarChart::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Top Processes "),
            )
            .data(group)
            .bar_width(bar_w)
            .bar_gap(1)
            .bar_style(Style::default().fg(Color::Yellow))
            .value_style(Style::default().fg(Color::White).bold());

        f.render_widget(chart, panels[panel_idx]);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn state_color(state: &str) -> Color {
    match state {
        "LISTEN" => Color::Green,
        "ESTABLISHED" => Color::Yellow,
        "TIME_WAIT" | "CLOSE_WAIT" => Color::DarkGray,
        "UNREPLIED" | "OPEN" => Color::Magenta,
        "SYN_SENT" | "SYN_RECV" => Color::Red,
        _ => Color::White,
    }
}

fn direction_color(dir: &str) -> Color {
    match dir {
        "Listen" => Color::Green,
        "Inbound" => Color::Cyan,
        "Outbound" => Color::Yellow,
        "Loopback" => Color::DarkGray,
        "Local" => Color::Magenta,
        _ => Color::White,
    }
}

fn format_bytes_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000_000.0 {
        format!("{:.1} GB/s", bytes_per_sec / 1_000_000_000.0)
    } else if bytes_per_sec >= 1_000_000.0 {
        format!("{:.1} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1_000.0)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
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

fn display_width(s: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(s)
}

fn pad_to(s: impl AsRef<str>, width: usize) -> String {
    let s = s.as_ref();
    let dw = display_width(s);
    if dw > width {
        truncate_to_width(s, width)
    } else {
        let padding = width - dw;
        let mut out = String::with_capacity(s.len() + padding);
        out.push_str(s);
        for _ in 0..padding {
            out.push(' ');
        }
        out
    }
}

fn truncate_to_width(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".to_string();
    }
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

fn truncate_str(s: &str, max: usize) -> String {
    let width = display_width(s);
    if width > max {
        truncate_to_width(s, max)
    } else {
        s.to_string()
    }
}
