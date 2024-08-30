#[allow(dead_code)]
pub const TCP_PROTOCOL_ID: u8 = 0x06;
#[allow(dead_code)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn unpack(data: &[u8]) -> TcpHeader {
        TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: data[12] >> 4,
            flags: data[13],
            window_size: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
        }
    }
    #[allow(dead_code)]
    pub fn to_string(header: &TcpHeader) -> String {
        format!(
            "TCP Header:\n  Source Port: {}\n  Destination Port: {}\n  Sequence Number: {}\n  Acknowledgment Number: {}\n  Data Offset: {}\n  Flags: {}\n  Window Size: {}\n  Checksum: 0x{:04x}\n  Urgent Pointer: {}",
            header.src_port,
            header.dst_port,
            header.seq_num,
            header.ack_num,
            header.data_offset,
            header.flags,
            header.window_size,
            header.checksum,
            header.urgent_pointer,
        )
    }
}
