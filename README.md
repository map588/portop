# portop

A `top`-like TUI for monitoring open ports and their associated processes. Built with Rust using [ratatui](https://ratatui.rs).

![Linux](https://img.shields.io/badge/platform-linux-blue) ![macOS](https://img.shields.io/badge/platform-macOS-blue) ![Windows](https://img.shields.io/badge/platform-windows-blue)

## Features

- Live view of all TCP/UDP sockets (IPv4 and IPv6)
- Process info: name, PID, user, command line, RSS memory, traffic direction
- **Process detail view** — select a process to see all its connections, network sockets, and open files
- **Mouse support** — click to select, scroll wheel to navigate, click column headers to sort, double-click to open detail view
- **Auto-fit columns** — column widths scale to fit their content
- Sortable columns via keyboard or mouse (click header to sort, click again to reverse)
- Live text filtering across all fields
- Send SIGTERM/SIGKILL to processes directly from the TUI
- Vim-style navigation (`j`/`k`/`g`/`G`)
- Auto-refresh on a configurable interval
- **Options menu** (`o`) — toggle columns and graph panels, adjust refresh interval
- **Sort menu** (`S`) — pick sort field from a list
- **Live graphs** — network I/O rates, connection state distribution, top processes by connection count

## Install

Requires Rust 1.70+.

```sh
# From source
git clone https://github.com/map588/portop.git && cd portop

cargo build --release
sudo cp target/release/portop /usr/local/bin/

# Or just install
cargo install --path .

# To 'try before you buy'
cargo run --release
```

> **Note:** Root/sudo is recommended on Linux and macOS to see all processes and their socket mappings.

## Usage

```sh
portop                    # default: all protocols, 2s refresh
portop -i 5               # refresh every 5 seconds
portop -p tcp             # show only TCP sockets
```

## Keybindings

### Main View

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Navigate rows |
| `g` / `G` | Jump to top / bottom |
| `PgUp` / `PgDn` | Scroll by 10 |
| `Enter` | Open process detail view |
| `/` | Enter filter mode (live search) |
| `Esc` | Clear filter / cancel |
| `S` | Open sort menu |
| `1`–`5` | Quick sort by column (port, proto, state, PID, name) |
| `s` | Signal selected process |
| `o` | Open options menu |
| `r` / `F5` | Force refresh |
| `q` | Quit |

### Mouse

| Action | Effect |
|--------|--------|
| Click row | Select |
| Double-click row | Open process detail |
| Click column header | Sort by column (click again to reverse) |
| Scroll wheel | Navigate rows |

### Process Detail View

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Scroll |
| `PgUp` / `PgDn` | Scroll by 10 |
| `Esc` / `q` / `Enter` | Back to main view |

### Options Menu

| Key | Action |
|-----|--------|
| `j` / `k` | Navigate options |
| `Space` / `Enter` | Toggle selected option |
| `h` / `l` | Decrease / increase refresh interval |
| `Esc` | Close menu |

## Platform Support

| Platform | Method |
|----------|--------|
| **Linux** | Reads `/proc/net/tcp{,6}`, `/proc/net/udp{,6}` and `/proc/*/fd` directly |
| **macOS** | Uses `lsof` and `ps` for port/process discovery |
| **Windows** | Uses `netstat -ano` and `tasklist` |

Root/sudo recommended on Linux and macOS to see all sockets.

## License

MIT
