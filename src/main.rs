// Import the Ipv4Header from the tools::Ipv4 module
mod tools;  // Include the tools module
use tools::ipv4::Ipv4Header;

fn main() {
    // Example IPv4 packet (first 20 bytes represent the IPv4 header)
    let packet: [u8; 20] = [
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x68,
        0xc0, 0xa8, 0x00, 0x01
    ];

    // Attempt to unpack the IPv4 header from the packet
    match Ipv4Header::unpack(&packet) {
        Ok(header) => {
            // Print the unpacked header using the to_string method
            println!("{}", Ipv4Header::to_string(&header));
        },
        Err(e) => {
            // Handle the error (e.g., buffer too small)
            eprintln!("Error unpacking IPv4 header: {}", e);
        }
    }
}