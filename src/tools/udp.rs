#[allow(dead_code)]
pub const UDP_PROTOCOL_ID: u8 = 0x11;

#[allow(dead_code)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn unpack(data: &[u8]) -> UdpHeader {
        UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        }
    }

    pub fn to_string(header: &UdpHeader) -> String {
        format!(
            "UDP Header:\n  Source Port: {}\n  Destination Port: {}\n  Length: {}\n  Checksum: 0x{:04x}",
            header.src_port,
            header.dst_port,
            header.length,
            header.checksum
        )
    }
}
