use pcap::{Capture, Device, Packet};
use std::fs::File;
use std::io::Read;

use crate::utils::{
    debug,
    LogLevel
};

use crate::tools::{
    ipv4::IPV4_PROTOCOL_ID, 
    ipv6::IPV6_PROTOCOL_ID, 
    tcp::TCP_PROTOCOL_ID, tcp::TcpHeader,
    udp::UDP_PROTOCOL_ID, udp::UdpHeader,
    package_data::PacketData,
    ethernet::EthernetHeader,    
    utils::{get_mac, format_ip},
    ipv4::Ipv4Header, 
    ipv6::Ipv6Header,
};

fn handle_packet(packet: &Packet) {
    if packet.data.len() < 24 {
        eprintln!("Packet too short");
        return;
    }

    let ethernet_header: EthernetHeader = EthernetHeader::unpack(&packet.data);  
    let mut data: PacketData = PacketData::new();
    
    data.src_mac = get_mac(ethernet_header.src);
    data.dest_mac = get_mac(ethernet_header.dest);

    match packet.data[12] {
        IPV4_PROTOCOL_ID => handle_ip_packet(&packet.data[14..], &mut data, true),
        IPV6_PROTOCOL_ID => handle_ip_packet(&packet.data[14..], &mut data, false),
        _ => debug("Unknown Protocol", LogLevel::Debug),
    }

    data.write();
}

fn handle_ip_packet(ip_data: &[u8], data: &mut PacketData, is_ipv4: bool) {
    if is_ipv4 {
        match Ipv4Header::unpack(ip_data) {
            Ok(ipv4_header) => {
                data.src_ip = format_ip(ipv4_header.src);
                data.dest_ip = format_ip(ipv4_header.dst);
                data.payload_length = ipv4_header.length;

                match ip_data[9] {
                    UDP_PROTOCOL_ID => unpack_udp(ip_data, data, "IPv4/UDP"),
                    TCP_PROTOCOL_ID => unpack_tcp(ip_data, data, "IPv4/TCP"),
                    _ => unpack_unknown(data, "Unknown IPV4"),
                }
            }
            Err(e) => eprintln!("Failed to unpack IPv4 header: {}", e),
        }
    } else {
        match Ipv6Header::unpack(ip_data) {
            Ok(ipv6_header) => {
                data.src_ip = ipv6_header.src.iter()
                .map(|&b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .chunks(2)
                .map(|chunk| chunk.join(""))
                .collect::<Vec<String>>()
                .join(":");
            
            data.dest_ip = ipv6_header.dst.iter()
                .map(|&b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .chunks(2)
                .map(|chunk| chunk.join(""))
                .collect::<Vec<String>>()
                .join(":");
                data.payload_length = ipv6_header.payload_length;

                match ip_data[6] { // In IPv6, the next header is at position 6
                    UDP_PROTOCOL_ID => unpack_udp(ip_data, data, "IPv6/UDP"),
                    TCP_PROTOCOL_ID => unpack_tcp(ip_data, data, "IPv6/TCP"),
                    _ => unpack_unknown(data, "Unknown IPV6"),
                }
            }
            Err(e) => eprintln!("Failed to unpack IPv6 header: {}", e),
        }
    }
}

fn unpack_unknown(data: &mut PacketData, protocol: &str) {
    data.protocol = protocol.to_string();
    data.port = 0;
}

fn unpack_udp(ip_data: &[u8], data: &mut PacketData, protocol: &str) {
    let udp_header = UdpHeader::unpack(ip_data);
    data.protocol = protocol.to_string();
    data.port = udp_header.src_port;
}

fn unpack_tcp(ip_data: &[u8], data: &mut PacketData, protocol: &str) {
    let tcp_header = TcpHeader::unpack(ip_data);
    data.protocol = protocol.to_string();
    data.port = tcp_header.src_port;
}

pub fn start_sniffing() {
    crate::tools::package_data::clear_file();

    let device = Device::lookup()
        .expect("Device lookup failed")
        .expect("No device available");

    println!("Using device {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("Failed to create capture")
        .immediate_mode(true)
        .open()
        .expect("Failed to open capture");

    let mut buf = [0u8; 1];

    loop {
        if let Err(e) = cap.for_each(None, |packet| {
            handle_packet(&packet);

            if let Err(e) = check_stop_condition("src/tools/atomic.txt", &mut buf) {
                eprintln!("Error during stop condition check: {}", e);
                return;
            }
        }) {
            eprintln!("Error during packet capture: {}", e);
            break;
        }
    }
}

fn check_stop_condition(file_path: &str, buf: &mut [u8]) -> Result<(), String> {
    let mut file = File::open(file_path).map_err(|e| format!("File not found: {}", e))?;
    file.read_exact(buf).map_err(|e| format!("Failed to read file: {}", e))?;
    
    if buf[0] == b'0' {
        panic!("Stop requested by communication channel");
    }

    Ok(())
}
