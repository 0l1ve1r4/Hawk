use pcap::{Capture, Device, Packet};

use crate::tools::ipv4::IPV4_PROTOCOL_ID;
use crate::tools::tcp::TCP_PROTOCOL_ID;
use crate::tools::udp::UDP_PROTOCOL_ID;

use std::fs::OpenOptions;
use std::io::Write;

use std::fs::File;
use std::io::Read;

fn format_ip(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

fn get_mac(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn write_to_file(data: &str) {
    if let Err(e) = OpenOptions::new()
        .write(true)
        .truncate(false)
        .create(true)  // Create the file if it doesn't exist
        .open("src/tools/packages.txt")
        .and_then(|mut file| file.write_all(data.as_bytes()))
    {
        eprintln!("Failed to write to file: {}", e);
    }
}

fn handle_package(packet: &Packet) {
    let ethernet_header = crate::tools::ethernet::EthernetHeader::unpack(&packet.data);  

    let dest_mac = get_mac(ethernet_header.dest);
    let src_mac = get_mac(ethernet_header.src);
    let mut protocol = "".to_string();
    let mut src_ip = "".to_string();
    let mut dest_ip = "".to_string();
    let mut port = 0;
    let mut payload_length = 0;

    if packet.data.len() < 24 {
        eprintln!("Packet too short");
        return;
    }

    if packet.data[12] == IPV4_PROTOCOL_ID {
        let ipv4_header = crate::tools::ipv4::Ipv4Header::unpack(&packet.data[14..]);
        let ipv4_header = match ipv4_header {
            Ok(header) => header,
            Err(e) => {
                eprintln!("Failed to unpack IPv4 header: {}", e);
                return;
            }
        };

        src_ip = format_ip(ipv4_header.src);
        dest_ip = format_ip(ipv4_header.dst);
        payload_length = ipv4_header.length;

        match packet.data[23] {
            UDP_PROTOCOL_ID => {
                let udp_header = crate::tools::udp::UdpHeader::unpack(&packet.data);
                protocol = "IPv4/UDP".to_string();
                // Assuming UDP header contains port information
                port = udp_header.src_port;
            }
            TCP_PROTOCOL_ID => {
                let tcp_header = crate::tools::tcp::TcpHeader::unpack(&packet.data);
                protocol = "IPv4/TCP".to_string();
                // Assuming TCP header contains port information
                port = tcp_header.src_port;
            }
            _ => {
                crate::utils::debug("Other protocol", crate::utils::LogLevel::Warning);
            }
        }
    }

    write_to_file(&format!(
        "{},{},{},{},{},{},{}\n",
        dest_mac,
        src_mac,
        src_ip,
        dest_ip,
        port,
        protocol,
        payload_length
    ));




}

pub fn print_file() {
    let mut buf = [0u8; 1];  // Initialize a buffer to hold the file content

    let mut file = File::open("src/tools/packages.txt").expect("file not found");
    file.read_exact(&mut buf).expect("failed to read file");

    println!("File content: {:?}", buf);
}   

pub fn start_sniffing() {
    let mut buf = [0u8; 1];  // Initialize a buffer to hold the file content

    let device = Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("failed to create capture")
        .immediate_mode(true)
        .open()
        .expect("failed to open capture");

    let mut count: i32 = 0;

    loop {
        cap.for_each(None, |packet| {
            handle_package(&packet);
            count += 1;
    
            let mut file = File::open("src/tools/atomic.txt").expect("file not found");
            file.read_exact(&mut buf).expect("failed to read file");
    
            if &buf == b"0" {
                print_file();
                panic!("Stop requested by communication channel"); 
            }
        }).expect("failed during packet capture");


    }


}   