# portop

A `top`-like TUI for monitoring open ports and their associated processes. Built with Rust using [ratatui](https://ratatui.rs).

![Linux](https://img.shields.io/badge/platform-linux-blue) ![macOS](https://img.shields.io/badge/platform-macOS-blue)

## Features

- Live view of all TCP/UDP sockets (IPv4 and IPv6)
- Process info: name, PID, user, command line, RSS memory
- Sortable columns (port, protocol, state, PID, process name)
- Live text filtering across all fields
- Send SIGTERM/SIGKILL to processes directly from the TUI
- Vim-style navigation (`j`/`k`/`g`/`G`)
- Auto-refresh on a configurable interval
- **Options menu** (`o`) — toggle columns and graph panels, adjust refresh interval
- **Live graphs** — network I/O rates, connection state distribution, top processes by connection count

## Install

Requires Rust 1.70+.

```sh
# From source
git clone https://github.com/matthewprock/portop.git && cd portop

cargo build --release
sudo cp target/release/portop /usr/local/bin/

# Or just install
cargo install --path .

# To 'try before you buy'
cargo run --release
```

> **Note:** Root/sudo is recommended to see all processes and their socket mappings.

## Usage

```sh
portop                    # default: all protocols, 2s refresh
portop -i 5               # refresh every 5 seconds
portop -p tcp             # show only TCP sockets
```

## Keybindings

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Navigate rows |
| `g` / `G` | Jump to top / bottom |
| `PgUp` / `PgDn` | Scroll by 10 |
| `/` | Enter filter mode (live search) |
| `Esc` | Clear filter / cancel |
| `S` | Cycle sort column |
| `1`–`5` | Sort by column (port, proto, state, PID, name) |
| `s` | Signal selected process |
| `o` | Open options menu |
| `r` / `F5` | Force refresh |
| `q` | Quit |

### Options Menu

| Key | Action |
|-----|--------|
| `j` / `k` | Navigate options |
| `Space` / `Enter` | Toggle selected option |
| `h` / `l` | Decrease / increase refresh interval |
| `Esc` | Close menu |

## Platform Support

- **Linux** — reads `/proc/net/tcp{,6}`, `/proc/net/udp{,6}` and `/proc/*/fd` directly
- **macOS** — uses `lsof` and `ps` for port/process discovery
- Root/sudo recommended on both platforms to see all sockets

## License

MIT
