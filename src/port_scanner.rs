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
    pub process_cpu: f32,
    pub process_mem: u64,
}

pub fn scan_ports() -> Vec<PortEntry> {
    let mut entries = Vec::new();

    // Parse /proc/net/tcp and /proc/net/tcp6
    scan_net_file("/proc/net/tcp", "tcp", &mut entries);
    scan_net_file("/proc/net/tcp6", "tcp6", &mut entries);
    scan_net_file("/proc/net/udp", "udp", &mut entries);
    scan_net_file("/proc/net/udp6", "udp6", &mut entries);

    entries.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    entries
}

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

        let (local_ip, local_port) = parse_address(local);
        let (remote_ip, remote_port) = parse_address(remote);

        let state = decode_state(state_raw, proto);

        let pid = find_pid_by_inode(inode);

        let (process_name, process_cmdline, process_user) = if pid > 0 {
            get_process_info(pid)
        } else {
            ("—".to_string(), "—".to_string(), "—".to_string())
        };

        let (process_cpu, process_mem) = if pid > 0 {
            get_process_stats(pid)
        } else {
            (0.0, 0)
        };

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
            process_cpu,
            process_mem,
        });
    }
}

fn parse_address(addr: &str) -> (String, u16) {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return (addr.to_string(), 0);
    }

    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    let ip = if ip_hex.len() == 8 {
        // IPv4
        let n = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        format!(
            "{}.{}.{}.{}",
            n & 0xFF,
            (n >> 8) & 0xFF,
            (n >> 16) & 0xFF,
            (n >> 24) & 0xFF,
        )
    } else if ip_hex.len() == 32 {
        // IPv6 — abbreviate
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

fn find_pid_by_inode(inode: &str) -> u32 {
    if inode == "0" {
        return 0;
    }

    // Walk /proc/*/fd/* to find which pid owns this socket inode
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

fn get_process_info(pid: u32) -> (String, String, String) {
    let name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .map(|s| s.replace('\0', " ").trim().to_string())
        .unwrap_or_default();

    let user = get_process_user(pid);

    (name, cmdline, user)
}

fn get_process_user(pid: u32) -> String {
    use std::os::unix::fs::MetadataExt;
    let path = format!("/proc/{}", pid);
    std::fs::metadata(path)
        .map(|m| {
            let uid = m.uid();
            get_username(uid)
        })
        .unwrap_or_else(|_| "—".to_string())
}

fn get_username(uid: u32) -> String {
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3 {
                if let Ok(file_uid) = fields[2].parse::<u32>() {
                    if file_uid == uid {
                        return fields[0].to_string();
                    }
                }
            }
        }
    }
    format!("uid:{}", uid)
}

fn get_process_stats(pid: u32) -> (f32, u64) {
    // Parse /proc/pid/stat for CPU
    let cpu = if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
        let fields: Vec<&str> = stat.split_whitespace().collect();
        if fields.len() >= 17 {
            let utime: f64 = fields[13].parse().unwrap_or(0.0);
            let stime: f64 = fields[14].parse().unwrap_or(0.0);
            let total: f64 = utime + stime;
            let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) as f64 };
            if clk_tck > 0.0 {
                let seconds = total / clk_tck;
                (seconds as f32 * 100.0).min(999.9)
            } else {
                0.0
            }
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Parse /proc/pid/status for memory (VmRSS in kB)
    let mem = if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
        let mut rss = 0u64;
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    rss = parts[1].parse().unwrap_or(0);
                }
                break;
            }
        }
        rss
    } else {
        0
    };

    (cpu, mem)
}

pub fn kill_process(pid: u32, signal: i32) -> Result<(), String> {
    use std::process::Command;
    let sig = match signal {
        9 => "9",
        15 => "15",
        _ => "15",
    };
    let result = Command::new("kill")
        .arg(format!("-{}", sig))
        .arg(pid.to_string())
        .output();

    match result {
        Ok(output) => {
            if output.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&output.stderr).to_string())
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
