use std::fs::File;
use std::io::{self, BufRead};

#[derive(PartialEq)]
pub struct TableEntry {
    pub dest_mac: String,
    pub src_mac: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub port: u16,
    pub protocol: String,
    pub payload_length: usize,
}

impl Default for TableEntry {
    fn default() -> Self {
        Self {
            dest_mac: "00:11:22:33:44:55".into(),
            src_mac: "66:77:88:99:AA:BB".into(),
            src_ip: "192.168.1.1".into(),
            dest_ip: "192.168.1.2".into(),
            port: 80,
            protocol: "TCP".into(),
            payload_length: 512,
        }
    }
}

impl TableEntry {
    fn parse_line(line: &str) -> Option<TableEntry> {
        let parts: Vec<&str> = line.split(',').collect();
        
        if parts.len() != 7 {
            return None; // Skip if the line doesn't have exactly 7 fields
        }

        let (dest_mac, src_mac, src_ip, dest_ip, port_str, protocol, payload_length_str) = (
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
            parts[3].to_string(),
            parts[4],
            parts[5].to_string(),
            parts[6],
        );

        // Validate and parse port and payload length
        let port = match port_str.parse::<u16>() {
            Ok(p) if p > 0 => p,
            _ => return None, // Skip if port is not a valid positive u16 number
        };

        let payload_length = match payload_length_str.parse::<usize>() {
            Ok(pl) if pl > 0 => pl,
            _ => return None, // Skip if payload length is not a valid positive usize number
        };

        // Skip if any mandatory fields are empty
        if dest_mac.is_empty() || src_mac.is_empty() || src_ip.is_empty() || dest_ip.is_empty() || protocol.is_empty() {
            return None;
        }

        Some(TableEntry {
            dest_mac,
            src_mac,
            src_ip,
            dest_ip,
            port,
            protocol,
            payload_length,
        })
    }

    pub fn read_table_entries(filename: &str) -> Vec<TableEntry> {
        let mut entries = Vec::new();

        if let Ok(file) = File::open(filename) {
            for line in io::BufReader::new(file).lines() {
                if let Ok(l) = line {
                    if let Some(entry) = TableEntry::parse_line(&l) {
                        entries.push(entry);
                    }
                }
            }
        }

        entries
    }
}
