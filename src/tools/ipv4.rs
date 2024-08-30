#[allow(dead_code)]
pub const IPV4_PROTOCOL_ID: u8 = 0x08;

#[allow(dead_code)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: u32,
    pub dst: u32,
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
            flags: ((flags_fragment_offset >> 13) & 0x07) as u8, // Top 3 bits are flags
            fragment_offset: flags_fragment_offset & 0x1FFF, // Bottom 13 bits are fragment offset
            ttl: buffer[8],
            protocol: buffer[9],
            checksum: u16::from_be_bytes([buffer[10], buffer[11]]),
            src: u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]),
            dst: u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]),
        };

        Ok(header)
    }

}
