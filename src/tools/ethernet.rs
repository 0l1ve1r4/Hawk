#[allow(dead_code)]

const ETHERTYPE_IP: u16 = 0x0800;

#[allow(dead_code)]
pub struct EthernetHeader {
    pub dest: [u8; 6],
    pub src:  [u8; 6],
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

}
