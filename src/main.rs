// sudo env "PATH=$HOME/.cargo/bin:$PATH" cargo run

mod utils;
mod tools;

use eframe::egui;

fn main() {
    let options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "Hawk - Network Analyzer",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::default()))),
    );

}


#[derive(Default)]
pub struct MyApp {
    counter: i32,
    data: Vec<TableEntry>,
}

pub struct TableEntry {
    dest_mac: String,
    src_mac: String,
    src_ip: String,
    dest_ip: String,
    port: u16,
    protocol: String,
    payload_length: usize,
}

impl Default for TableEntry {
    fn default() -> Self {
        Self {
            dest_mac: "00:11:22:33:44:55".into(),
            src_mac: "66:77:88:99:AA:BB".into(),
            src_ip: "192.168.1.1".into(),
            dest_ip: "192.168.1.2".into(),
            port: 80,
            protocol: "TCP".into(),
            payload_length: 512,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open").clicked() {}
                    if ui.button("Save").clicked() {}
                });

                if ui.button("Run").clicked() {
                    tools::functions::start_sniffing();
                    self.insert_entry(TableEntry::default());
                }

                if ui.button("Stop").clicked() {}
                if ui.button("Clear").clicked() {}
                if ui.button("Analysis").clicked() {}
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Packet Information Table");

            egui::Grid::new("packet_table")
                .striped(true)
                .min_col_width(100.0)
                .show(ui, |ui| {
                    ui.label("Dest MAC");
                    ui.label("Src MAC");
                    ui.label("Src IP");
                    ui.label("Dest IP");
                    ui.label("Port");
                    ui.label("Protocol");
                    ui.label("Payload Length");
                    ui.end_row();

                    for entry in &self.data {
                        ui.label(&entry.dest_mac);
                        ui.label(&entry.src_mac);
                        ui.label(&entry.src_ip);
                        ui.label(&entry.dest_ip);
                        ui.label(entry.port.to_string());
                        ui.label(&entry.protocol);
                        ui.label(entry.payload_length.to_string());
                        ui.end_row();
                    }
                });
        });
    }
}

impl MyApp {
    fn insert_entry(&mut self, entry: TableEntry) {
        self.data.push(entry);
        self.counter += 1;
    }
}
