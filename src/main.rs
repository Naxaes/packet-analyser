#![allow(unused)]

mod shared;
mod endian;
mod ipv4;
mod tcp;
mod ethernet;
mod visitor;

use std::io::Error;
use pcap::{self, Device, Capture, Packet};
use crate::ethernet::Ethernet;
use crate::visitor::Visitor;


fn main() {
    let mut printer = visitor::Printer::new();

    // Fetch the network interface from the command line or use the default one.
    let interface = std::env::args().nth(1).unwrap_or("en0".to_string());

    // Select the network interface if present.
    let mut device = Device::list()
        .expect("Device lookup failed")
        .into_iter()
        .find(|x| x.name == interface)
        .unwrap_or(
            Device::lookup()
                .expect("Device lookup failed")
                .expect("No devices found")
        );

    println!("Using device {}", device.name);

    let mut cap = Capture::from_device(device)
        .expect("Failed to open device")
        .promisc(true)
        .immediate_mode(true)
        .open()
        .expect("Failed to open device");

    println!("Waiting...");
    while let Ok(packet) = cap.next_packet() {
        if let Err(error) = printer.visit_packet(&packet) {
            println!("[ERROR]: {}", error);
        }
    }
}