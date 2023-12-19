extern crate chrono;
use chrono::prelude::DateTime;
use chrono::{NaiveDateTime, Utc};
use std::time::{SystemTime, UNIX_EPOCH, Duration};


use std::io::{Error, ErrorKind};
use chrono::format::format;
use pcap::Packet;
use crate::ethernet::{self, Ethernet};
use crate::ipv4::{self, IPv4};
use crate::tcp;
use crate::tcp::Tcp;


pub trait Visitor<'a, T> where T: Default {
    fn visit_packet(&mut self, packet: &'a Packet) -> Result<T, Error> {
        self.visit_packet_payload(packet)
    }
    fn visit_ethernet(&mut self, packet: &Ethernet<'a>) -> Result<T, Error> {
        self.visit_ethernet_payload(&packet.payload()?)
    }
    fn visit_ipv4(&mut self, packet: &IPv4<'a>) -> Result<T, Error> {
        self.visit_ipv4_payload(&packet.payload()?)
    }
    fn visit_tcp(&mut self, packet: &Tcp<'a>) -> Result<T, Error> {
        todo!("Not implemented")
    }

    fn visit_packet_payload(&mut self, packet: &'a Packet) -> Result<T, Error> {
        match Ethernet::from_bytes(packet.data) {
            Ok(payload) => self.visit_ethernet(&payload),
            Err(error) => Err(error)
        }
    }

    fn visit_ethernet_payload(&mut self, payload: &ethernet::Payload<'a>) -> Result<T, Error> {
        match payload {
            ethernet::Payload::IPv4(payload) => self.visit_ipv4(&payload),
            ethernet::Payload::Invalid => Err(Error::new(ErrorKind::Other, format!("Ethernet payload is not implemented"))),
        }
    }

    fn visit_ipv4_payload(&mut self, payload: &ipv4::Payload<'a>) -> Result<T, Error> {
        match payload {
            ipv4::Payload::Tcp(payload) => self.visit_tcp(&payload),
            _ => Err(Error::new(ErrorKind::Other, format!("Ipv4 payload is not implemented"))),
        }
    }

    fn visit_raw_payload(&mut self, payload: &[u8]) -> Result<T, Error> {
        Ok(T::default())
    }
}


pub struct Printer {
    indentation: usize,
}

impl Printer {
    pub fn new() -> Self {
        Self { indentation: 0 }
    }
}


impl<'a> Visitor<'a, ()> for Printer {
    fn visit_packet(&mut self, packet: &Packet) -> Result<(), Error> {
        let timestamp = NaiveDateTime::from_timestamp_opt(packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as u32 * 1000)
            .map(|time| time.format("%H:%M:%S%.6f"));

        let time = timestamp.map(|x| x.to_string())
            .unwrap_or("<invalid timestamp>".to_string());

        println!("---------- Packet [ size {} ] @ {} -----------------------------", packet.header.len, time);
        let result = self.visit_packet_payload(packet);
        println!("---------------------------------------------------------------------------------");
        result
    }

    fn visit_ethernet(&mut self, packet: &Ethernet<'a>) -> Result<(), Error> {
        println!("| - Ethernet [ payload size {} ]",  packet.raw_payload().len());
        println!("|    Source                : {:?}", packet.source());
        println!("|    Destination           : {:?}", packet.destination());
        println!("|    Ether Type            : {:?}", packet.ether_type());
        println!("|    Crc                   : {:?}", packet.crc());
        self.visit_ethernet_payload(&packet.payload()?)
    }

    fn visit_ipv4(&mut self, packet: &IPv4<'a>) -> Result<(), Error> {
        println!("|- Ipv4 [ payload size {} ]", packet.raw_payload().len());
        println!("|    Header Length         : {:?}", packet.header_length());
        println!("|    Version               : {:?}", packet.version());
        println!("|    Reserved 1            : {:?}", packet.reserved1());
        println!("|    Cost                  : {:?}", packet.cost());
        println!("|    Reliability           : {:?}", packet.reliability());
        println!("|    Throughput            : {:?}", packet.throughput());
        println!("|    Delay                 : {:?}", packet.delay());
        println!("|    Precedence            : {:?}", packet.precedence());
        println!("|    Total Length          : {:?}", packet.total_length());
        println!("|    Identification        : {:?}", packet.identification());
        println!("|    Reserved 2            : {:?}", packet.reserved2());
        println!("|    Df                    : {:?}", packet.df());
        println!("|    Mf                    : {:?}", packet.mf());
        println!("|    Fragment_offset       : {:?}", packet.fragment_offset());
        println!("|    Time To Live          : {:?}", packet.time_to_live());
        println!("|    Protocol              : {:?}", packet.protocol());
        println!("|    Header Checksum       : {:?}", packet.header_checksum());
        println!("|    Source Address        : {:?}", packet.source_address());
        println!("|    Destination Address   : {:?}", packet.destination_address());
        self.visit_ipv4_payload(&packet.payload()?)
    }

    fn visit_tcp(&mut self, packet: &Tcp<'a>) -> Result<(), Error> {
        println!("| - Tcp [ payload size {} ]", packet.raw_payload().len());
        println!("|    Source Port           : {:?}", packet.source_port());
        println!("|    Destination Port      : {:?}", packet.destination_port());
        println!("|    Sequence Number       : {:?}", packet.sequence_number());
        println!("|    Acknowledgment Number : {:?}", packet.acknowledgment_number());
        println!("|    Reserved              : {:?}", packet.reserved());
        println!("|    Data Offset           : {:?}", packet.data_offset());
        println!("|    Cwr                   : {:?}", packet.cwr());
        println!("|    Ece                   : {:?}", packet.ece());
        println!("|    Urg                   : {:?}", packet.urg());
        println!("|    Ack                   : {:?}", packet.ack());
        println!("|    Psh                   : {:?}", packet.psh());
        println!("|    Rst                   : {:?}", packet.rst());
        println!("|    Syn                   : {:?}", packet.syn());
        println!("|    Fin                   : {:?}", packet.fin());
        println!("|    Window Size           : {:?}", packet.window_size());
        println!("|    Check Sum             : {:?}", packet.check_sum());
        println!("|    Urgent Pointer        : {:?}", packet.urgent_pointer());
        for (i, option) in packet.options().enumerate() {
            println!("|    Option[{}]             : {:?}", i, option);
        }
        self.visit_raw_payload(packet.raw_payload())
    }

    fn visit_raw_payload(&mut self, payload: &[u8]) -> Result<(), Error> {
        println!("| - Payload  [ size {} ]", payload.len());


        for chunk in payload.chunks(16) {
            print!("|    ");

            for bytes in chunk.chunks(4) {
                for byte in bytes {
                    print!("{:02x} ", *byte);
                }
                print!(" ")
            }

            print!("    ");

            for byte in chunk {
                let character = *byte as char;
                let character = if character.is_whitespace() { '.' } else { character };
                print!("{}", character);
            }
            println!();
        }

        Ok(())
    }
}


