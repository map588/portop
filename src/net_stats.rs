#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// ---------------------------------------------------------------------------
// Linux: parse /proc/net/dev
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub fn collect_interface_stats() -> Vec<InterfaceStats> {
    let content = match std::fs::read_to_string("/proc/net/dev") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut stats = Vec::new();
    // Skip first 2 header lines
    for line in content.lines().skip(2) {
        let line = line.trim();
        if let Some((name, rest)) = line.split_once(':') {
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if fields.len() >= 9 {
                let rx_bytes = fields[0].parse().unwrap_or(0);
                let tx_bytes = fields[8].parse().unwrap_or(0);
                let name = name.trim().to_string();
                if name != "lo" {
                    stats.push(InterfaceStats { name, rx_bytes, tx_bytes });
                }
            }
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// macOS: parse netstat -ib
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub fn collect_interface_stats() -> Vec<InterfaceStats> {
    use std::collections::HashMap;
    use std::process::Command;

    let output = match Command::new("netstat").args(["-ib"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut totals: HashMap<String, (u64, u64)> = HashMap::new();

    for line in stdout.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        if fields.len() < 11 {
            continue;
        }

        let name = fields[0];
        // Skip loopback
        if name == "lo0" {
            continue;
        }

        // Only count <Link#N> rows to avoid double-counting
        if !fields[2].starts_with("<Link") {
            continue;
        }

        let ibytes: u64 = fields[6].parse().unwrap_or(0);
        let obytes: u64 = fields[9].parse().unwrap_or(0);

        let entry = totals.entry(name.to_string()).or_insert((0, 0));
        entry.0 += ibytes;
        entry.1 += obytes;
    }

    totals
        .into_iter()
        .map(|(name, (rx, tx))| InterfaceStats {
            name,
            rx_bytes: rx,
            tx_bytes: tx,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Windows: parse netstat -e
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn collect_interface_stats() -> Vec<InterfaceStats> {
    use std::process::Command;

    let output = match Command::new("netstat").args(["-e"]).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Format:
    //                            Received            Sent
    // Bytes                    123456789       987654321
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("Bytes") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 3 {
                let rx: u64 = fields[1].parse().unwrap_or(0);
                let tx: u64 = fields[2].parse().unwrap_or(0);
                return vec![InterfaceStats {
                    name: "all".to_string(),
                    rx_bytes: rx,
                    tx_bytes: tx,
                }];
            }
        }
    }

    Vec::new()
}
