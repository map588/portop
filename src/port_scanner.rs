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
    use std::collections::HashMap;

    // Build inode->PID map once upfront instead of walking /proc/*/fd per inode
    let inode_map = build_inode_pid_map();

    let mut entries = Vec::new();
    scan_net_file("/proc/net/tcp", "tcp", &inode_map, &mut entries);
    scan_net_file("/proc/net/tcp6", "tcp6", &inode_map, &mut entries);
    scan_net_file("/proc/net/udp", "udp", &inode_map, &mut entries);
    scan_net_file("/proc/net/udp6", "udp6", &inode_map, &mut entries);
    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

/// Build a reverse map of socket inode -> PID by scanning /proc/*/fd once.
#[cfg(target_os = "linux")]
fn build_inode_pid_map() -> std::collections::HashMap<String, u32> {
    use std::collections::HashMap;

    let mut map = HashMap::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid = match name_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_path = format!("/proc/{}/fd", pid);
        let fd_dir = match std::fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                // Format: "socket:[12345]"
                if let Some(rest) = link_str.strip_prefix("socket:[") {
                    if let Some(inode) = rest.strip_suffix(']') {
                        map.insert(inode.to_string(), pid);
                    }
                }
            }
        }
    }
    map
}

#[cfg(target_os = "linux")]
fn scan_net_file(
    path: &str,
    proto: &str,
    inode_map: &std::collections::HashMap<String, u32>,
    entries: &mut Vec<PortEntry>,
) {
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

        let pid = if *inode != "0" {
            inode_map.get(*inode).copied().unwrap_or(0)
        } else {
            0
        };

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
// macOS: parse `lsof -i -n -P` output + batched `ps` for process details
// ---------------------------------------------------------------------------

/// Process info fetched via a single batched `ps` call.
#[cfg(target_os = "macos")]
struct ProcessInfo {
    cmdline: String,
    rss_kb: u64,
}

/// Batch-fetch cmdline and RSS for all given PIDs in a single `ps` invocation.
#[cfg(target_os = "macos")]
fn batch_process_info(pids: &[u32]) -> std::collections::HashMap<u32, ProcessInfo> {
    use std::collections::HashMap;
    use std::process::Command;

    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    // ps -o pid=,rss=,command= -p pid1,pid2,pid3
    let pid_list: String = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let output = match Command::new("ps")
        .args(["-o", "pid=,rss=,command=", "-p", &pid_list])
        .output()
    {
        Ok(o) => o,
        Err(_) => return map,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: "  PID   RSS COMMAND..."
        // Split into at most 3 parts: pid, rss, rest-is-command
        let mut parts = line.splitn(3, char::is_whitespace);
        let pid_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let rss_str = loop {
            // skip empty parts from multiple spaces
            match parts.next() {
                Some(s) if s.trim().is_empty() => continue,
                Some(s) => break s.trim(),
                None => break "0",
            }
        };
        let cmdline = loop {
            match parts.next() {
                Some(s) if s.trim().is_empty() => continue,
                Some(s) => break s.trim().to_string(),
                None => break String::new(),
            }
        };

        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rss_kb: u64 = rss_str.parse().unwrap_or(0);

        map.insert(pid, ProcessInfo { cmdline, rss_kb });
    }
    map
}

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

    // First pass: parse lsof lines to get basic entries and collect PIDs
    let mut raw_entries: Vec<(PortEntry, u32)> = Vec::new();
    let mut pids: Vec<u32> = Vec::new();

    for line in stdout.lines().skip(1) {
        if let Some(entry) = parse_lsof_line(line) {
            let pid = entry.pid;
            if pid > 0 && !pids.contains(&pid) {
                pids.push(pid);
            }
            raw_entries.push((entry, pid));
        }
    }

    // Single batched ps call for all PIDs
    let proc_info = batch_process_info(&pids);

    // Enrich entries with process details
    let mut entries: Vec<PortEntry> = raw_entries
        .into_iter()
        .map(|(mut entry, pid)| {
            if let Some(info) = proc_info.get(&pid) {
                entry.process_cmdline = info.cmdline.clone();
                entry.process_mem = info.rss_kb;
            }
            entry
        })
        .collect();

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

    let process_name = decode_lsof_escapes(fields[0]);
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

    Some(PortEntry {
        protocol: protocol.to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        pid,
        process_name,
        process_cmdline: "—".to_string(), // filled in by batch_process_info
        process_user,
        process_mem: 0, // filled in by batch_process_info
    })
}

#[cfg(target_os = "macos")]
fn parse_lsof_name(
    name: &str,
    proto: &str,
) -> Option<(String, u16, String, u16, String)> {
    let (addr_part, state) = if let Some(idx) = name.rfind('(') {
        let s = name[idx + 1..].trim_end_matches(')').trim().to_string();
        (name[..idx].trim(), s)
    } else {
        (name.trim(), if proto.starts_with("udp") { "OPEN".to_string() } else { String::new() })
    };

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

/// Decode lsof's `\xHH` escape sequences (e.g. `\x20` -> space).
#[cfg(target_os = "macos")]
fn decode_lsof_escapes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Peek for 'x' followed by two hex digits
            let mut tentative = chars.clone();
            if tentative.next() == Some('x') {
                let h1 = tentative.next();
                let h2 = tentative.next();
                if let (Some(d1), Some(d2)) = (h1, h2) {
                    let hex = format!("{}{}", d1, d2);
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        chars = tentative; // consume the 3 chars
                        continue;
                    }
                }
            }
            result.push(c);
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(target_os = "macos")]
fn parse_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(idx) = s.rfind(':') {
        let host = &s[..idx];
        let port: u16 = s[idx + 1..].parse().ok()?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        Some((host.to_string(), port))
    } else {
        None
    }
}
