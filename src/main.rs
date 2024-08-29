/* 

This file is part of Hawk.

Copyright (C) 2024 - Guilherme Santos

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

Run 'sudo env "PATH=$HOME/.cargo/bin:$PATH" cargo build' to compile the project.
Run 'sudo env "PATH=$HOME/.cargo/bin:$PATH" cargo run' to run the project.

sudo needs to be used because the program needs to access the network interface.

*/

mod tools;
mod utils;

use tools::{ipv4::IPV4_PROTOCOL_ID, tcp};
use tools::tcp::TCP_PROTOCOL_ID;
use tools::udp;

use pcap::{Capture, Device, Packet};
use tools::udp::UDP_PROTOCOL_ID;

fn handle_package(packet: &Packet) {
    // Ensure packet.data is long enough before accessing indices
    if packet.data.len() < 24 {
        eprintln!("Packet too short");
        return;
    }
    
    // Check for IP packets (IPv4 and IPv6)
    if packet.data[12] == IPV4_PROTOCOL_ID {
        let header = tools::ipv4::Ipv4Header::unpack(&packet.data[14..]);
        let string_h = tools::ipv4::Ipv4Header::to_string(&header.unwrap());    
        println!("{}", string_h);

        // Check for UDP (0x11) or TCP (0x06) protocol
        match packet.data[23] {
            UDP_PROTOCOL_ID => {
                let header = udp::UdpHeader::unpack(&packet.data);
                let string_h = udp::UdpHeader::to_string(&header);
                println!("{}", string_h);
            }
            TCP_PROTOCOL_ID => {
                let header = tcp::TcpHeader::unpack(&packet.data);
                let string_h = tcp::TcpHeader::to_string(&header);
                println!("{}", string_h);
            }
            _ => {
                utils::debug("Other protocol", utils::LogLevel::Warning);
            }
        }
    }
}

fn main() {
    // Get the default Device
    let device = Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    // Setup Capture
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
            utils::debug("Stopping packet capture", utils::LogLevel::Debug);
            panic!();
        }
    })
    .expect("failed during packet capture");
}