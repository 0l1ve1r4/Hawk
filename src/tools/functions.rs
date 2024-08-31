use pcap::{Capture, Device, Packet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

use crate::tools::ipv4::IPV4_PROTOCOL_ID;
use crate::tools::tcp::TCP_PROTOCOL_ID;
use crate::tools::udp::UDP_PROTOCOL_ID;

fn write_to_file(data: &str) {
    if let Err(e) = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("src/tools/packages.txt")
        .and_then(|mut file| file.write_all(data.as_bytes()))
    {
        eprintln!("Failed to write to file: {}", e);
    }
}

fn clear_file() {
    if let Err(e) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("src/tools/packages.txt")
        .and_then(|mut file| file.write_all(b""))
    {
        eprintln!("Failed to clear file: {}", e);
    }
}

fn handle_packet(packet: &Packet) {
    use crate::tools::{
        ethernet::EthernetHeader, 
        utils::{get_mac, format_ip}, 
        ipv4::Ipv4Header, 
        udp::UdpHeader, 
        tcp::TcpHeader,
    };

    let ethernet_header = EthernetHeader::unpack(&packet.data);  
    let (dest_mac, src_mac) = (
        get_mac(ethernet_header.dest),
        get_mac(ethernet_header.src),
    );

    if packet.data.len() < 24 {
        eprintln!("Packet too short");
        return;
    }

    let mut protocol = String::new();
    let mut src_ip = String::new();
    let mut dest_ip = String::new();
    let mut port = 0;
    let mut payload_length = 0;

    if packet.data[12] == IPV4_PROTOCOL_ID {
        match Ipv4Header::unpack(&packet.data[14..]) {
            Ok(ipv4_header) => {
                src_ip = format_ip(ipv4_header.src);
                dest_ip = format_ip(ipv4_header.dst);
                payload_length = ipv4_header.length;

                match packet.data[23] {
                    UDP_PROTOCOL_ID => {
                        let udp_header = UdpHeader::unpack(&packet.data);
                        protocol = "IPv4/UDP".to_string();
                        port = udp_header.src_port;
                    }
                    TCP_PROTOCOL_ID => {
                        let tcp_header = TcpHeader::unpack(&packet.data);
                        protocol = "IPv4/TCP".to_string();
                        port = tcp_header.src_port;
                    }
                    _ => {
                        crate::utils::debug("Other protocol", crate::utils::LogLevel::Debug);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to unpack IPv4 header: {}", e);
                return;
            }
        }
    }

    write_to_file(&format!(
        "{},{},{},{},{},{},{}\n",
        dest_mac, src_mac, src_ip, dest_ip, port, protocol, payload_length
    ));
}

pub fn start_sniffing() {
    let device = Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");

    println!("Using device {}", device.name);
    clear_file();

    let mut cap = Capture::from_device(device)
        .expect("failed to create capture")
        .immediate_mode(true)
        .open()
        .expect("failed to open capture");

    let mut buf = [0u8; 1];

    loop {
        if let Err(e) = cap.for_each(None, |packet| {
            handle_packet(&packet);

            let mut file = File::open("src/tools/atomic.txt").expect("file not found");
            file.read_exact(&mut buf).expect("failed to read file");

            if &buf == b"0" {
                panic!("Stop requested by communication channel"); 
            }
        }) {
            eprintln!("Error during packet capture: {}", e);
            break;
        }
    }
}
