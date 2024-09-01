use std::fs::OpenOptions;
use std::io::Write;

fn write_to_file(data: &str) -> () {
    if let Err(e) = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("src/tools/packages.txt")
        .and_then(|mut file| file.write_all(data.as_bytes()))
    {
        eprintln!("Failed to write to file: {}", e);
    }
}

pub fn clear_file() -> (){
    if let Err(e) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("src/tools/packages.txt")
        .and_then(|mut file| file.write_all(b""))
    {
        eprintln!("Failed to clear file: {}", e);
    }
}

pub struct PacketData {
    pub protocol: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_mac: String,
    pub dest_mac: String,
    pub port: u16,
    pub payload_length: u16,

}

impl PacketData {
    pub fn new() -> PacketData {
        // Clear previous analisys
        PacketData {
            protocol: "".to_string(),
            src_ip: "".to_string(),
            dest_ip: "".to_string(),
            src_mac: "".to_string(),
            dest_mac: "".to_string(),
            port: 0,
            payload_length: 0,
        }
    }

    pub fn write(&self) -> (){
        write_to_file(&format!(
            "{},{},{},{},{},{},{}\n",
            self.dest_mac, self.src_mac, self.src_ip, self.dest_ip, self.port, self.protocol, self.payload_length
        ));
    }

}