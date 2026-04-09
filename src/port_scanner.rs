use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;

#[derive(Debug, Clone)]
pub struct PortEntry {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    /// Resolved hostname for remote_addr, if available.
    pub remote_host: Option<String>,
    pub state: String,
    pub direction: String,
    pub pid: u32,
    pub process_name: String,
    pub process_cmdline: String,
    pub process_user: String,
    pub process_mem: u64,
}

#[cfg(test)]
impl PortEntry {
    /// Test helper: create a PortEntry with minimal required fields.
    pub fn test(proto: &str, local_addr: &str, local_port: u16, state: &str) -> Self {
        Self {
            protocol: proto.to_string(),
            local_addr: local_addr.to_string(),
            local_port,
            remote_addr: "*".to_string(),
            remote_port: 0,
            remote_host: None,
            state: state.to_string(),
            direction: String::new(),
            pid: 0,
            process_name: "test".to_string(),
            process_cmdline: "test".to_string(),
            process_user: "user".to_string(),
            process_mem: 0,
        }
    }

    /// Builder: set remote address fields.
    pub fn with_remote(mut self, addr: &str, port: u16) -> Self {
        self.remote_addr = addr.to_string();
        self.remote_port = port;
        self
    }

    /// Builder: set PID and process name.
    pub fn with_process(mut self, pid: u32, name: &str) -> Self {
        self.pid = pid;
        self.process_name = name.to_string();
        self
    }

    /// Builder: set memory.
    pub fn with_mem(mut self, mem_kb: u64) -> Self {
        self.process_mem = mem_kb;
        self
    }

    /// Builder: set resolved hostname.
    pub fn with_host(mut self, host: &str) -> Self {
        self.remote_host = Some(host.to_string());
        self
    }
}

/// Cache for reverse DNS lookups. Persists across scan cycles.
pub struct DnsCache {
    cache: HashMap<String, Option<String>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Resolve IP addresses to hostnames for all entries, using the cache.
    pub fn resolve_entries(&mut self, entries: &mut [PortEntry]) {
        for entry in entries.iter_mut() {
            if entry.remote_addr == "*" || entry.remote_addr.is_empty() {
                continue;
            }
            let ip = &entry.remote_addr;
            if !self.cache.contains_key(ip) {
                let resolved = reverse_lookup(ip);
                self.cache.insert(ip.clone(), resolved);
            }
            entry.remote_host = self.cache.get(ip).cloned().flatten();
        }
    }
}

fn reverse_lookup(ip: &str) -> Option<String> {
    // Skip loopback / wildcard / link-local — not useful to resolve
    if ip == "127.0.0.1" || ip == "::1" || ip.starts_with("127.") || ip == "*" {
        return None;
    }

    // Use a dummy port for ToSocketAddrs; we only care about the reverse lookup
    let sock_addr = format!("{}:0", ip);
    let addr = sock_addr.to_socket_addrs().ok()?.next()?;

    // std doesn't have reverse DNS, use libc getnameinfo
    resolve_addr(&addr)
}

#[cfg(unix)]
fn resolve_addr(addr: &std::net::SocketAddr) -> Option<String> {
    use std::ffi::CStr;

    // Build a sockaddr on the stack, then pass a pointer to getnameinfo.
    // macOS/BSD sockaddr structs have a sin_len/sin6_len field; Linux does not.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sa_len: libc::socklen_t;

    match addr {
        std::net::SocketAddr::V4(v4) => {
            let sin = &mut storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = v4.port().to_be();
                (*sin).sin_addr.s_addr = u32::from(*v4.ip()).to_be();
                #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
                {
                    (*sin).sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                }
            }
            sa_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        std::net::SocketAddr::V6(v6) => {
            let sin6 = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = v6.port().to_be();
                (*sin6).sin6_flowinfo = v6.flowinfo();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
                (*sin6).sin6_scope_id = v6.scope_id();
                #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
                {
                    (*sin6).sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                }
            }
            sa_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
    }

    let sa_ptr = &storage as *const _ as *const libc::sockaddr;
    let mut host_buf = [0u8; 256];
    let ret = unsafe {
        libc::getnameinfo(
            sa_ptr,
            sa_len,
            host_buf.as_mut_ptr() as *mut libc::c_char,
            host_buf.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            0,
        )
    };

    if ret != 0 {
        return None;
    }

    let hostname = unsafe { CStr::from_ptr(host_buf.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();

    // getnameinfo returns the numeric IP if it can't resolve — skip those
    if hostname == addr.ip().to_string() {
        return None;
    }

    Some(hostname)
}

#[cfg(target_os = "windows")]
fn resolve_addr(_addr: &std::net::SocketAddr) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// Shared: direction inference
// ---------------------------------------------------------------------------

pub(crate) fn is_loopback(addr: &str) -> bool {
    addr == "127.0.0.1" || addr.starts_with("127.") || addr == "::1"
}

/// Compute the `direction` field for every entry based on state, addresses,
/// and whether the local port has a corresponding LISTEN socket.
pub(crate) fn compute_directions(entries: &mut [PortEntry]) {
    let listen_ports: HashSet<u16> = entries
        .iter()
        .filter(|e| e.state == "LISTEN")
        .map(|e| e.local_port)
        .collect();

    for entry in entries.iter_mut() {
        entry.direction = match entry.state.as_str() {
            "LISTEN" => "Listen",
            "SYN_SENT" => "Outbound",
            "SYN_RECV" => "Inbound",
            _ if entry.remote_addr == "*" || entry.remote_port == 0 => "Local",
            _ if is_loopback(&entry.local_addr) && is_loopback(&entry.remote_addr) => "Loopback",
            _ if listen_ports.contains(&entry.local_port) => "Inbound",
            _ => "Outbound",
        }
        .to_string();
    }
}

// ---------------------------------------------------------------------------
// Platform-specific process kill
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub fn kill_process(pid: u32, signal: i32) -> Result<(), String> {
    let ret = unsafe { libc::kill(pid as i32, signal) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

#[cfg(target_os = "windows")]
pub fn kill_process(pid: u32, signal: i32) -> Result<(), String> {
    use std::process::Command;
    let mut cmd = Command::new("taskkill");
    cmd.args(["/PID", &pid.to_string()]);
    if signal == 9 {
        cmd.arg("/F"); // force kill ≈ SIGKILL
    }
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Linux: read /proc/net/{tcp,tcp6,udp,udp6}
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn scan_ports() -> Vec<PortEntry> {
    use std::collections::HashMap;

    let inode_map = build_inode_pid_map();

    let mut entries = Vec::new();
    scan_net_file("/proc/net/tcp", "tcp", &inode_map, &mut entries);
    scan_net_file("/proc/net/tcp6", "tcp6", &inode_map, &mut entries);
    scan_net_file("/proc/net/udp", "udp", &inode_map, &mut entries);
    scan_net_file("/proc/net/udp6", "udp6", &inode_map, &mut entries);
    compute_directions(&mut entries);
    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

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
            remote_host: None,
            state,
            direction: String::new(),
            pid,
            process_name,
            process_cmdline,
            process_user,
            process_mem,
        });
    }
}

#[allow(dead_code)] // used on Linux; tested on all platforms
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

#[allow(dead_code)] // used on Linux; tested on all platforms
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

#[cfg(target_os = "macos")]
struct ProcessInfo {
    cmdline: String,
    rss_kb: u64,
}

#[cfg(target_os = "macos")]
fn batch_process_info(pids: &[u32]) -> std::collections::HashMap<u32, ProcessInfo> {
    use std::collections::HashMap;
    use std::process::Command;

    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

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
        let mut parts = line.splitn(3, char::is_whitespace);
        let pid_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let rss_str = loop {
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

    let proc_info = batch_process_info(&pids);

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

    compute_directions(&mut entries);
    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

fn parse_lsof_line(line: &str) -> Option<PortEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 9 {
        return None;
    }

    let process_name = decode_lsof_escapes(fields[0]);
    let pid: u32 = fields[1].parse().ok()?;
    let process_user = fields[2].to_string();
    let node = fields[7];

    let protocol = match node {
        "TCP" => {
            if fields[4] == "IPv6" { "tcp6" } else { "tcp" }
        }
        "UDP" => {
            if fields[4] == "IPv6" { "udp6" } else { "udp" }
        }
        _ => return None,
    };

    let name = fields[8..].join(" ");

    let (local_addr, local_port, remote_addr, remote_port, state) =
        parse_lsof_name(&name, protocol)?;

    Some(PortEntry {
        protocol: protocol.to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        remote_host: None,
        state,
        direction: String::new(),
        pid,
        process_name,
        process_cmdline: "—".to_string(),
        process_user,
        process_mem: 0,
    })
}

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

fn decode_lsof_escapes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut tentative = chars.clone();
            if tentative.next() == Some('x') {
                let h1 = tentative.next();
                let h2 = tentative.next();
                if let (Some(d1), Some(d2)) = (h1, h2) {
                    let hex = format!("{}{}", d1, d2);
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        chars = tentative;
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

// ---------------------------------------------------------------------------
// Windows: parse `netstat -ano` output + `tasklist` for process details
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
struct WinProcessInfo {
    name: String,
    mem_kb: u64,
}

#[cfg(target_os = "windows")]
fn batch_process_info_windows(pids: &[u32]) -> std::collections::HashMap<u32, WinProcessInfo> {
    use std::collections::HashMap;
    use std::process::Command;

    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    let output = match Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return map,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid_set: HashSet<u32> = pids.iter().copied().collect();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // CSV: "name.exe","PID","Session","Session#","Mem K"
        // Strip outer quotes and split by ","
        let line = line.trim_matches('"');
        let fields: Vec<&str> = line.split("\",\"").collect();
        if fields.len() < 5 {
            continue;
        }

        let name = fields[0];
        let pid: u32 = match fields[1].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if !pid_set.contains(&pid) {
            continue;
        }

        // Memory: "250,000 K" — strip commas and " K" suffix
        let mem_str = fields[4].trim();
        let mem_str = mem_str
            .trim_end_matches(" K")
            .trim_end_matches(" k")
            .replace(',', "");
        let mem_kb: u64 = mem_str.trim().parse().unwrap_or(0);

        map.insert(
            pid,
            WinProcessInfo {
                name: name.to_string(),
                mem_kb,
            },
        );
    }

    map
}

#[cfg(target_os = "windows")]
pub fn scan_ports() -> Vec<PortEntry> {
    use std::collections::HashMap;
    use std::process::Command;

    let output = match Command::new("netstat").args(["-ano"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut entries = Vec::new();
    let mut pids: Vec<u32> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Active") || line.starts_with("Proto") {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let proto_raw = fields[0];

        let (protocol, state, pid_str) = if proto_raw.starts_with("TCP") {
            if fields.len() < 5 {
                continue;
            }
            let proto = if proto_raw == "TCP" { "tcp" } else { "tcp6" };
            (proto, normalize_windows_state(fields[3]), fields[4])
        } else if proto_raw.starts_with("UDP") {
            let proto = if proto_raw == "UDP" { "udp" } else { "udp6" };
            (proto, "OPEN".to_string(), fields[3])
        } else {
            continue;
        };

        let pid: u32 = pid_str.parse().unwrap_or(0);
        let (local_addr, local_port) = parse_windows_address(fields[1]);
        let (remote_addr, remote_port) = parse_windows_address(fields[2]);

        if pid > 0 && !pids.contains(&pid) {
            pids.push(pid);
        }

        entries.push(PortEntry {
            protocol: protocol.to_string(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            remote_host: None,
            state,
            direction: String::new(),
            pid,
            process_name: "—".to_string(),
            process_cmdline: "—".to_string(),
            process_user: "—".to_string(),
            process_mem: 0,
        });
    }

    // Enrich with process info
    let proc_info = batch_process_info_windows(&pids);
    for entry in &mut entries {
        if let Some(info) = proc_info.get(&entry.pid) {
            entry.process_name = info.name.clone();
            entry.process_cmdline = info.name.clone();
            entry.process_mem = info.mem_kb;
        }
    }

    compute_directions(&mut entries);
    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

#[allow(dead_code)] // used on Windows; tested on all platforms
fn parse_windows_address(addr: &str) -> (String, u16) {
    if addr == "*:*" {
        return ("*".to_string(), 0);
    }

    // IPv6: [::]:port or [::1]:port
    if let Some(bracket_end) = addr.rfind(']') {
        let ip = &addr[1..bracket_end];
        let port: u16 = addr
            .get(bracket_end + 2..)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        return (ip.to_string(), port);
    }

    // IPv4: 0.0.0.0:port
    if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        let port: u16 = addr[colon + 1..].parse().unwrap_or(0);
        (ip.to_string(), port)
    } else {
        (addr.to_string(), 0)
    }
}

#[allow(dead_code)] // used on Windows; tested on all platforms
fn normalize_windows_state(state: &str) -> String {
    match state {
        "LISTENING" => "LISTEN".to_string(),
        "FIN_WAIT_1" => "FIN_WAIT1".to_string(),
        "FIN_WAIT_2" => "FIN_WAIT2".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // compute_directions
    // -------------------------------------------------------------------------

    #[test]
    fn test_direction_listen() {
        let mut entries = vec![PortEntry::test("tcp", "0.0.0.0", 80, "LISTEN")];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Listen");
    }

    #[test]
    fn test_direction_syn_sent() {
        let mut entries = vec![
            PortEntry::test("tcp", "192.168.1.1", 54321, "SYN_SENT")
                .with_remote("10.0.0.1", 443),
        ];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Outbound");
    }

    #[test]
    fn test_direction_syn_recv() {
        let mut entries = vec![
            PortEntry::test("tcp", "192.168.1.1", 80, "SYN_RECV")
                .with_remote("10.0.0.1", 54321),
        ];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Inbound");
    }

    #[test]
    fn test_direction_local_wildcard_remote() {
        // remote_addr == "*"
        let mut entries = vec![
            PortEntry::test("tcp", "0.0.0.0", 8080, "ESTABLISHED"),
        ];
        // default remote is "*" from PortEntry::test
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Local");
    }

    #[test]
    fn test_direction_local_zero_remote_port() {
        // remote_port == 0
        let mut entries = vec![
            PortEntry::test("udp", "0.0.0.0", 53, "OPEN")
                .with_remote("10.0.0.1", 0),
        ];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Local");
    }

    #[test]
    fn test_direction_loopback() {
        let mut entries = vec![
            PortEntry::test("tcp", "127.0.0.1", 9000, "ESTABLISHED")
                .with_remote("::1", 54321),
        ];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Loopback");
    }

    #[test]
    fn test_direction_inbound_via_listen_port() {
        // Port 443 has a LISTEN entry; established connection on same port → Inbound
        let mut entries = vec![
            PortEntry::test("tcp", "0.0.0.0", 443, "LISTEN"),
            PortEntry::test("tcp", "192.168.1.1", 443, "ESTABLISHED")
                .with_remote("10.0.0.1", 54321),
        ];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Listen");
        assert_eq!(entries[1].direction, "Inbound");
    }

    #[test]
    fn test_direction_outbound_default() {
        // Non-loopback, no LISTEN on local port, not a special state
        let mut entries = vec![
            PortEntry::test("tcp", "192.168.1.1", 54321, "ESTABLISHED")
                .with_remote("93.184.216.34", 443),
        ];
        compute_directions(&mut entries);
        assert_eq!(entries[0].direction, "Outbound");
    }

    // -------------------------------------------------------------------------
    // parse_lsof_line
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_lsof_line_tcp_ipv4() {
        let line = "Google   1234    user   12u  IPv4 0x1234      0t0  TCP  192.168.1.1:443->10.0.0.1:52000 (ESTABLISHED)";
        let entry = parse_lsof_line(line).expect("should parse");
        assert_eq!(entry.protocol, "tcp");
        assert_eq!(entry.local_addr, "192.168.1.1");
        assert_eq!(entry.local_port, 443);
        assert_eq!(entry.remote_addr, "10.0.0.1");
        assert_eq!(entry.remote_port, 52000);
        assert_eq!(entry.state, "ESTABLISHED");
        assert_eq!(entry.pid, 1234);
        assert_eq!(entry.process_name, "Google");
        assert_eq!(entry.process_user, "user");
    }

    #[test]
    fn test_parse_lsof_line_tcp_ipv6() {
        let line = "Firefox  5678    user   15u  IPv6 0x5678      0t0  TCP  [::1]:8080 (LISTEN)";
        let entry = parse_lsof_line(line).expect("should parse");
        assert_eq!(entry.protocol, "tcp6");
        assert_eq!(entry.local_addr, "::1");
        assert_eq!(entry.local_port, 8080);
        assert_eq!(entry.state, "LISTEN");
        assert_eq!(entry.pid, 5678);
    }

    #[test]
    fn test_parse_lsof_line_udp() {
        let line = "dns      9999    root   10u  IPv4 0xabcd      0t0  UDP  *:53";
        let entry = parse_lsof_line(line).expect("should parse");
        assert_eq!(entry.protocol, "udp");
        assert_eq!(entry.local_addr, "*");
        assert_eq!(entry.local_port, 53);
        assert_eq!(entry.state, "OPEN");
        assert_eq!(entry.pid, 9999);
    }

    #[test]
    fn test_parse_lsof_line_non_network_node() {
        // node field is "REG", not TCP/UDP
        let line = "proc     1234    user   12u  IPv4 0x1234      0t0  REG  /some/file";
        assert!(parse_lsof_line(line).is_none());
    }

    #[test]
    fn test_parse_lsof_line_too_few_fields() {
        let line = "proc 1234 user";
        assert!(parse_lsof_line(line).is_none());
    }

    // -------------------------------------------------------------------------
    // parse_lsof_name
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_lsof_name_tcp_with_arrow_and_state() {
        let result = parse_lsof_name("192.168.1.1:443->10.0.0.1:52000 (ESTABLISHED)", "tcp")
            .expect("should parse");
        let (local_addr, local_port, remote_addr, remote_port, state) = result;
        assert_eq!(local_addr, "192.168.1.1");
        assert_eq!(local_port, 443);
        assert_eq!(remote_addr, "10.0.0.1");
        assert_eq!(remote_port, 52000);
        assert_eq!(state, "ESTABLISHED");
    }

    #[test]
    fn test_parse_lsof_name_listen_no_arrow() {
        let result = parse_lsof_name("*:80 (LISTEN)", "tcp").expect("should parse");
        let (local_addr, local_port, remote_addr, remote_port, state) = result;
        assert_eq!(local_addr, "*");
        assert_eq!(local_port, 80);
        assert_eq!(remote_addr, "*");
        assert_eq!(remote_port, 0);
        assert_eq!(state, "LISTEN");
    }

    #[test]
    fn test_parse_lsof_name_udp_no_state() {
        let result = parse_lsof_name("*:53", "udp").expect("should parse");
        let (_local_addr, local_port, _remote_addr, _remote_port, state) = result;
        assert_eq!(local_port, 53);
        assert_eq!(state, "OPEN");
    }

    #[test]
    fn test_parse_lsof_name_ipv6_bracket() {
        let result = parse_lsof_name("[::1]:8080 (LISTEN)", "tcp6").expect("should parse");
        let (local_addr, local_port, _remote_addr, _remote_port, state) = result;
        assert_eq!(local_addr, "::1");
        assert_eq!(local_port, 8080);
        assert_eq!(state, "LISTEN");
    }

    // -------------------------------------------------------------------------
    // parse_host_port
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_host_port_ipv4() {
        let (host, port) = parse_host_port("192.168.1.1:443").expect("should parse");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_ipv6_bracket() {
        let (host, port) = parse_host_port("[::1]:8080").expect("should parse");
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_host_port_wildcard() {
        let (host, port) = parse_host_port("*:80").expect("should parse");
        assert_eq!(host, "*");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_host_port_no_colon() {
        assert!(parse_host_port("invalid").is_none());
    }

    // -------------------------------------------------------------------------
    // decode_lsof_escapes
    // -------------------------------------------------------------------------

    #[test]
    fn test_decode_lsof_escapes_hex() {
        assert_eq!(decode_lsof_escapes("hello\\x20world"), "hello world");
    }

    #[test]
    fn test_decode_lsof_escapes_no_escapes() {
        assert_eq!(decode_lsof_escapes("no-escapes"), "no-escapes");
    }

    #[test]
    fn test_decode_lsof_escapes_trailing_backslash() {
        // A lone trailing backslash should be kept as-is (no valid hex follows)
        assert_eq!(decode_lsof_escapes("trail\\"), "trail\\");
    }

    // -------------------------------------------------------------------------
    // parse_address_linux
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_address_linux_ipv4() {
        let (ip, port) = parse_address_linux("0100007F:0050");
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_address_linux_all_zeros() {
        let (ip, port) = parse_address_linux("00000000:0000");
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_address_linux_invalid_no_colon() {
        let (ip, port) = parse_address_linux("invalid");
        assert_eq!(ip, "invalid");
        assert_eq!(port, 0);
    }

    // -------------------------------------------------------------------------
    // decode_state
    // -------------------------------------------------------------------------

    #[test]
    fn test_decode_state_tcp_listen() {
        assert_eq!(decode_state("0A", "tcp"), "LISTEN");
    }

    #[test]
    fn test_decode_state_tcp_established() {
        assert_eq!(decode_state("01", "tcp"), "ESTABLISHED");
    }

    #[test]
    fn test_decode_state_tcp_time_wait() {
        assert_eq!(decode_state("06", "tcp"), "TIME_WAIT");
    }

    #[test]
    fn test_decode_state_udp_unreplied() {
        assert_eq!(decode_state("07", "udp"), "UNREPLIED");
    }

    #[test]
    fn test_decode_state_udp_established() {
        assert_eq!(decode_state("01", "udp"), "ESTABLISHED");
    }

    #[test]
    fn test_decode_state_unknown() {
        assert_eq!(decode_state("FF", "tcp"), "STATE(FF)");
    }

    // -------------------------------------------------------------------------
    // parse_windows_address
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_windows_address_wildcard() {
        let (ip, port) = parse_windows_address("*:*");
        assert_eq!(ip, "*");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_windows_address_ipv4() {
        let (ip, port) = parse_windows_address("0.0.0.0:80");
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_windows_address_ipv6() {
        let (ip, port) = parse_windows_address("[::]:443");
        assert_eq!(ip, "::");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_windows_address_ipv6_loopback() {
        let (ip, port) = parse_windows_address("[::1]:8080");
        assert_eq!(ip, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_parse_windows_address_no_colon() {
        let (ip, port) = parse_windows_address("noport");
        assert_eq!(ip, "noport");
        assert_eq!(port, 0);
    }

    // -------------------------------------------------------------------------
    // normalize_windows_state
    // -------------------------------------------------------------------------

    #[test]
    fn test_normalize_windows_state_listening() {
        assert_eq!(normalize_windows_state("LISTENING"), "LISTEN");
    }

    #[test]
    fn test_normalize_windows_state_fin_wait_1() {
        assert_eq!(normalize_windows_state("FIN_WAIT_1"), "FIN_WAIT1");
    }

    #[test]
    fn test_normalize_windows_state_established_passthrough() {
        assert_eq!(normalize_windows_state("ESTABLISHED"), "ESTABLISHED");
    }

    // -------------------------------------------------------------------------
    // is_loopback
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_loopback_127_0_0_1() {
        assert!(is_loopback("127.0.0.1"));
    }

    #[test]
    fn test_is_loopback_127_prefix() {
        assert!(is_loopback("127.0.0.2"));
    }

    #[test]
    fn test_is_loopback_ipv6() {
        assert!(is_loopback("::1"));
    }

    #[test]
    fn test_is_loopback_non_loopback() {
        assert!(!is_loopback("10.0.0.1"));
    }

    #[test]
    fn test_is_loopback_wildcard() {
        assert!(!is_loopback("*"));
    }
}
