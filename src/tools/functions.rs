use pcap::{Capture, Device, Packet};

use crate::tools::ipv4::IPV4_PROTOCOL_ID;
use crate::tools::tcp::TCP_PROTOCOL_ID;
use crate::tools::udp::UDP_PROTOCOL_ID;

fn handle_package(packet: &Packet) {
    if packet.data.len() < 24 {
        eprintln!("Packet too short");
        return;
    }
    
    if packet.data[12] == IPV4_PROTOCOL_ID {
        let header = crate::tools::ipv4::Ipv4Header::unpack(&packet.data[14..]);
        let string_h = crate::tools::ipv4::Ipv4Header::to_string(&header.unwrap());    
        println!("{}", string_h);

        match packet.data[23] {
            UDP_PROTOCOL_ID => {
                let header = crate::tools::udp::UdpHeader::unpack(&packet.data);
                let string_h = crate::tools::udp::UdpHeader::to_string(&header);
                println!("{}", string_h);
            }
            TCP_PROTOCOL_ID => {
                let header = crate::tools::tcp::TcpHeader::unpack(&packet.data);
                let string_h = crate::tools::tcp::TcpHeader::to_string(&header);
                println!("{}", string_h);
            }
            _ => {
                crate::utils::debug("Other protocol", crate::utils::LogLevel::Warning);
            }
        }
    }
}

pub fn start_sniffing() {
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
    cap.for_each(None, |packet| {
        handle_package(&packet);
        count += 1;
        if count > 100 {
            crate::utils::debug("Stopping packet capture", crate::utils::LogLevel::Debug);
            panic!();
        }
    })
    .expect("failed during packet capture");
}