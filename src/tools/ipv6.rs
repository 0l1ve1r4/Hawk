pub const IPV6_PROTOCOL_ID: u8 = 0x86;

#[allow(dead_code)]
pub struct Ipv6Header {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    pub payload_length: u16,
    next_header: u8,
    hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl Ipv6Header {
    pub fn unpack(buffer : &[u8]) -> Result<Ipv6Header, &'static str> {
        if buffer.len() < 40 {
            return Err("Buffer too small to be a valid IPv6 header");
        }

        let version = buffer[0] >> 4;
        let traffic_class = ((buffer[0] & 0x0F) << 4) | (buffer[1] >> 4);
        let flow_label = ((u32::from(buffer[1] & 0x0F) << 16)
                        | (u32::from(buffer[2]) << 8)
                        | u32::from(buffer[3])) & 0x000FFFFF;

        let header = Ipv6Header {
            version,
            traffic_class,
            flow_label,
            payload_length: u16::from_be_bytes([buffer[4], buffer[5]]),
            next_header: buffer[6],
            hop_limit: buffer[7],
            src: [
                buffer[8], buffer[9], buffer[10], buffer[11],
                buffer[12], buffer[13], buffer[14], buffer[15],
                buffer[16], buffer[17], buffer[18], buffer[19],
                buffer[20], buffer[21], buffer[22], buffer[23],
            ],
            dst: [
                buffer[24], buffer[25], buffer[26], buffer[27],
                buffer[28], buffer[29], buffer[30], buffer[31],
                buffer[32], buffer[33], buffer[34], buffer[35],
                buffer[36], buffer[37], buffer[38], buffer[39],
            ],
        };

        Ok(header)
    }
}
