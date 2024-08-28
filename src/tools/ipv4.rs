#[allow(dead_code)]
pub const IPV4_PROTOCOL_ID: u16 = 0x0800; 
#[allow(dead_code)]

pub struct Ipv4Header {
    version: u8,
    ihl: u8,
    dscp: u8,
    length: u16,
    id: u16,
    flags: u8,  
    fragment_offset: u16,  
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
}

impl Ipv4Header {
    pub fn unpack(buffer: &[u8]) -> Result<Ipv4Header, &'static str> {
        if buffer.len() < 20 {
            return Err("Buffer too small to be a valid IPv4 header");
        }

        let flags_fragment_offset = u16::from_be_bytes([buffer[6], buffer[7]]);
        let header = Ipv4Header {
            version: buffer[0] >> 4,
            ihl: buffer[0] & 0x0F,
            dscp: buffer[1] >> 2,
            length: u16::from_be_bytes([buffer[2], buffer[3]]),
            id: u16::from_be_bytes([buffer[4], buffer[5]]),
            flags: ((flags_fragment_offset >> 13) & 0x07) as u8,  // Top 3 bits are flags
            fragment_offset: flags_fragment_offset & 0x1FFF,  // Bottom 13 bits are fragment offset
            ttl: buffer[8],
            protocol: buffer[9],
            checksum: u16::from_be_bytes([buffer[10], buffer[11]]),
            src: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            dst: u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]),
        };

        Ok(header)
    }

    pub fn to_string(header: &Ipv4Header) -> String {
        format!(
            "IPv4 Header:\n  Version: {}\n  IHL: {}\n  DSCP: {}\n  Length: {}\n  ID: {}\n  Flags: {}\n  Fragment Offset: {}\n  TTL: {}\n  Protocol: {}\n  Checksum: 0x{:04x}\n  Source IP: {}.{}.{}.{}\n  Destination IP: {}.{}.{}.{}",
            header.version,
            header.ihl,
            header.dscp,
            header.length,
            header.id,
            header.flags,
            header.fragment_offset,
            header.ttl,
            header.protocol,
            header.checksum,
            (header.src >> 24) & 0xFF,
            (header.src >> 16) & 0xFF,
            (header.src >> 8) & 0xFF,
            header.src & 0xFF,
            (header.dst >> 24) & 0xFF,
            (header.dst >> 16) & 0xFF,
            (header.dst >> 8) & 0xFF,
            header.dst & 0xFF
        )
    }
}
