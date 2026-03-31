#[derive(Debug, Clone)]
pub struct PortEntry {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub process_cmdline: String,
    pub process_user: String,
    pub process_mem: u64,
}

pub fn kill_process(pid: u32, signal: i32) -> Result<(), String> {
    let ret = unsafe { libc::kill(pid as i32, signal) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

// ---------------------------------------------------------------------------
// Linux: read /proc/net/{tcp,tcp6,udp,udp6}
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn scan_ports() -> Vec<PortEntry> {
    let mut entries = Vec::new();
    scan_net_file("/proc/net/tcp", "tcp", &mut entries);
    scan_net_file("/proc/net/tcp6", "tcp6", &mut entries);
    scan_net_file("/proc/net/udp", "udp", &mut entries);
    scan_net_file("/proc/net/udp6", "udp6", &mut entries);
    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

#[cfg(target_os = "linux")]
fn scan_net_file(path: &str, proto: &str, entries: &mut Vec<PortEntry>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = fields[1];
        let remote = fields[2];
        let state_raw = fields[3];
        let inode = fields.get(9).unwrap_or(&"");

        let (local_ip, local_port) = parse_address_linux(local);
        let (remote_ip, remote_port) = parse_address_linux(remote);

        let state = decode_state(state_raw, proto);

        let pid = find_pid_by_inode(inode);

        let (process_name, process_cmdline, process_user) = if pid > 0 {
            get_process_info_linux(pid)
        } else {
            ("—".to_string(), "—".to_string(), "—".to_string())
        };

        let process_mem = if pid > 0 { get_rss_linux(pid) } else { 0 };

        entries.push(PortEntry {
            protocol: proto.to_string(),
            local_addr: local_ip,
            local_port,
            remote_addr: remote_ip,
            remote_port,
            state,
            pid,
            process_name,
            process_cmdline,
            process_user,
            process_mem,
        });
    }
}

#[cfg(target_os = "linux")]
fn parse_address_linux(addr: &str) -> (String, u16) {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return (addr.to_string(), 0);
    }

    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    let ip = if ip_hex.len() == 8 {
        let n = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        format!(
            "{}.{}.{}.{}",
            n & 0xFF,
            (n >> 8) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 24) & 0xFF,
        )
    } else if ip_hex.len() == 32 {
        let mut groups = Vec::new();
        for i in (0..32).step_by(4) {
            if i + 4 <= ip_hex.len() {
                if let Ok(v) = u16::from_str_radix(&ip_hex[i..i + 4], 16) {
                    groups.push(format!("{:x}", v));
                }
            }
        }
        let result = groups.join(":");
        if result.len() > 20 {
            format!("{}…", &result[..19])
        } else {
            result
        }
    } else {
        ip_hex.to_string()
    };

    (ip, port)
}

#[cfg(target_os = "linux")]
fn decode_state(state_hex: &str, proto: &str) -> String {
    if proto.starts_with("udp") {
        match state_hex {
            "07" => "UNREPLIED".to_string(),
            "01" => "ESTABLISHED".to_string(),
            _ => format!("STATE({})", state_hex),
        }
    } else {
        match state_hex {
            "01" => "ESTABLISHED".to_string(),
            "02" => "SYN_SENT".to_string(),
            "03" => "SYN_RECV".to_string(),
            "04" => "FIN_WAIT1".to_string(),
            "05" => "FIN_WAIT2".to_string(),
            "06" => "TIME_WAIT".to_string(),
            "07" => "CLOSE".to_string(),
            "08" => "CLOSE_WAIT".to_string(),
            "09" => "LAST_ACK".to_string(),
            "0A" => "LISTEN".to_string(),
            "0B" => "CLOSING".to_string(),
            _ => format!("STATE({})", state_hex),
        }
    }
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: &str) -> u32 {
    if inode == "0" {
        return 0;
    }

    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fd_dir) = std::fs::read_dir(&fd_path) {
                    for fd_entry in fd_dir.flatten() {
                        if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                            let link_str = link.to_string_lossy();
                            if link_str.contains(&format!("socket:[{}]", inode)) {
                                return pid;
                            }
                        }
                    }
                }
            }
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn get_process_info_linux(pid: u32) -> (String, String, String) {
    let name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_default();

    let user = get_process_user_linux(pid);

    (name, cmdline, user)
}

#[cfg(target_os = "linux")]
fn get_process_user_linux(pid: u32) -> String {
    use std::os::unix::fs::MetadataExt;
    let path = format!("/proc/{}", pid);
    std::fs::metadata(path)
        .map(|m| username_from_uid(m.uid()))
        .unwrap_or_else(|_| "—".to_string())
}

#[cfg(target_os = "linux")]
fn get_rss_linux(pid: u32) -> u64 {
    if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().unwrap_or(0);
                }
            }
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn username_from_uid(uid: u32) -> String {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return format!("uid:{}", uid);
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    name.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// macOS: parse `lsof -i -n -P` output
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn scan_ports() -> Vec<PortEntry> {
    use std::process::Command;

    let output = match Command::new("lsof")
        .args(["-i", "-n", "-P", "-w", "+c", "0"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in stdout.lines().skip(1) {
        if let Some(entry) = parse_lsof_line(line) {
            entries.push(entry);
        }
    }

    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

#[cfg(target_os = "macos")]
fn parse_lsof_line(line: &str) -> Option<PortEntry> {
    // lsof columns (whitespace-separated, NAME may contain spaces):
    // COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF  NODE  NAME
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 9 {
        return None;
    }

    let process_name = fields[0].to_string();
    let pid: u32 = fields[1].parse().ok()?;
    let process_user = fields[2].to_string();
    let node = fields[7]; // TCP or UDP

    let protocol = match node {
        "TCP" => {
            if fields[4] == "IPv6" { "tcp6" } else { "tcp" }
        }
        "UDP" => {
            if fields[4] == "IPv6" { "udp6" } else { "udp" }
        }
        _ => return None,
    };

    // NAME field is everything from fields[8] onward
    let name = fields[8..].join(" ");

    let (local_addr, local_port, remote_addr, remote_port, state) =
        parse_lsof_name(&name, protocol)?;

    let cmdline = get_cmdline_macos(pid);
    let process_mem = get_rss_macos(pid);

    Some(PortEntry {
        protocol: protocol.to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        pid,
        process_name,
        process_cmdline: cmdline,
        process_user,
        process_mem,
    })
}

#[cfg(target_os = "macos")]
fn parse_lsof_name(
    name: &str,
    proto: &str,
) -> Option<(String, u16, String, u16, String)> {
    // Formats:
    //   TCP: "host:port->rhost:rport (STATE)" or "host:port (STATE)" or "*:port"
    //   UDP: "host:port" or "*:port" or "host:port->rhost:rport"

    // Strip trailing state like " (LISTEN)" or " (ESTABLISHED)"
    let (addr_part, state) = if let Some(idx) = name.rfind('(') {
        let s = name[idx + 1..].trim_end_matches(')').trim().to_string();
        (name[..idx].trim(), s)
    } else {
        (name.trim(), if proto.starts_with("udp") { "OPEN".to_string() } else { String::new() })
    };

    // Split on "->" for remote
    let (local_str, remote_str) = if let Some(idx) = addr_part.find("->") {
        (&addr_part[..idx], Some(&addr_part[idx + 2..]))
    } else {
        (addr_part, None)
    };

    let (local_addr, local_port) = parse_host_port(local_str)?;
    let (remote_addr, remote_port) = if let Some(r) = remote_str {
        parse_host_port(r).unwrap_or(("*".to_string(), 0))
    } else {
        ("*".to_string(), 0)
    };

    Some((local_addr, local_port, remote_addr, remote_port, state))
}

#[cfg(target_os = "macos")]
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // "127.0.0.1:8080" or "*:5353" or "[::1]:80"
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port: u16 = s[idx + 1..].parse().ok()?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        Some((host.to_string(), port))
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn get_cmdline_macos(pid: u32) -> String {
    use std::process::Command;
    Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        })
        .unwrap_or_else(|| "—".to_string())
}

#[cfg(target_os = "macos")]
fn get_rss_macos(pid: u32) -> u64 {
    use std::process::Command;
    Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0)
}
