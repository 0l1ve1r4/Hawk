const ETHERTYPE_IP: u16 = 0x0800;

struct EthernetHeader {
    dest: [u8; 6],
    src:  [u8; 6],
    ethertype: u16,
}

impl EthernetHeader {
    pub fn unpack(data: &[u8]) -> EthernetHeader {
        let mut header = EthernetHeader {
            dest: [0; 6],
            src: [0; 6],
            ethertype: u16::from_be_bytes([data[12], data[13]]), 
        };

        for i in 0..6 {
            header.dest[i] = data[i];
            header.src[i] = data[i + 6];
        }
        
        header
    }

    pub fn print(header: &EthernetHeader) -> () { 
        println!("Ethernet Header");
        println!("  Destination: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            header.dest[0], header.dest[1], header.dest[2], header.dest[3], header.dest[4], header.dest[5]);
        println!("  Source: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
            header.src[0], header.src[1], header.src[2], header.src[3], header.src[4], header.src[5]);
        println!("  Ethertype: 0x{:04x}", header.ethertype);
    }
}