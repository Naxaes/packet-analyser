/*
https://standards.ieee.org/ieee/802.3/10422/
*/


use crate::endian::be_to_fe;
use crate::shared::*;
use crate::ipv4;

use std::fmt::write;
use std::io::{Error, ErrorKind};
use std::io::ErrorKind::Other;
use std::ops::{Index, Range};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use crate::ethernet::Payload::Invalid;


pub const ADDRESS_SIZE     : usize = 6;
pub const ETHER_TYPE_SIZE  : usize = 2;
pub const CRC_SIZE         : usize = 4;

pub const HEADER_SIZE      : usize = ADDRESS_SIZE * 2 + ETHER_TYPE_SIZE;
pub const MIN_TOTAL_SIZE   : usize = 6 + 6 + 2 + 4;
pub const MAX_TOTAL_SIZE   : usize = 1518;
pub const MAX_PAYLOAD_SIZE : usize = MAX_TOTAL_SIZE - HEADER_SIZE;

pub const MINIMUM_MAXIMUM_SEGMENT_SIZE: usize = 576;


/*
0x0800 	Internet Protocol version 4 (IPv4)
0x0806 	Address Resolution Protocol (ARP)
0x0842 	Wake-on-LAN[8]
0x22F0 	Audio Video Transport Protocol (AVTP)
0x22F3 	IETF TRILL Protocol
0x22EA 	Stream Reservation Protocol
0x6002 	DEC MOP RC
0x6003 	DECnet Phase IV, DNA Routing
0x6004 	DEC LAT
0x8035 	Reverse Address Resolution Protocol (RARP)
0x809B 	AppleTalk (Ethertalk)
0x80F3 	AppleTalk Address Resolution Protocol (AARP)
0x8100 	VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility[9]
0x8102 	Simple Loop Prevention Protocol (SLPP)
0x8103 	Virtual Link Aggregation Control Protocol (VLACP)
0x8137 	IPX
0x8204 	QNX Qnet
0x86DD 	Internet Protocol Version 6 (IPv6)
0x8808 	Ethernet flow control
0x8809 	Ethernet Slow Protocols[10] such as the Link Aggregation Control Protocol (LACP)
0x8819 	CobraNet
0x8847 	MPLS unicast
0x8848 	MPLS multicast
0x8863 	PPPoE Discovery Stage
0x8864 	PPPoE Session Stage
0x887B 	HomePlug 1.0 MME
0x888E 	EAP over LAN (IEEE 802.1X)
0x8892 	PROFINET Protocol
0x889A 	HyperSCSI (SCSI over Ethernet)
0x88A2 	ATA over Ethernet
0x88A4 	EtherCAT Protocol
0x88A8 	Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel
0x88AB 	Ethernet Powerlink[citation needed]
0x88B8 	GOOSE (Generic Object Oriented Substation event)
0x88B9 	GSE (Generic Substation Events) Management Services
0x88BA 	SV (Sampled Value Transmission)
0x88BF 	MikroTik RoMON (unofficial)
0x88CC 	Link Layer Discovery Protocol (LLDP)
0x88CD 	SERCOS III
0x88E1 	HomePlug Green PHY
0x88E3 	Media Redundancy Protocol (IEC62439-2)
0x88E5 	IEEE 802.1AE MAC security (MACsec)
0x88E7 	Provider Backbone Bridges (PBB) (IEEE 802.1ah)
0x88F7 	Precision Time Protocol (PTP) over IEEE 802.3 Ethernet
0x88F8 	NC-SI
0x88FB 	Parallel Redundancy Protocol (PRP)
0x8902 	IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
0x8906 	Fibre Channel over Ethernet (FCoE)
0x8914 	FCoE Initialization Protocol
0x8915 	RDMA over Converged Ethernet (RoCE)
0x891D 	TTEthernet Protocol Control Frame (TTE)
0x893a 	1905.1 IEEE Protocol
0x892F 	High-availability Seamless Redundancy (HSR)
0x9000 	Ethernet Configuration Testing Protocol[11]
0xF1C1 	Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)
 */

#[derive(Debug)]
pub enum Payload<'a> {
    IPv4(ipv4::IPv4<'a>),
    Invalid
}


#[repr(u16)]
#[derive(Debug)]
pub enum EtherType  {
    Unknown = 0x0000,
    IPv4 = 0x0008,   //  0x0800  Internet Protocol version 4 (IPv4)
    ARP  = 0x0608,   //  0x0806  Address Resolution Protocol (ARP)
    RARP = 0x3580,   //  0x8035  Reverse Address Resolution Protocol (RARP)
    SLPP = 0x0281,   //  0x8102  Simple Loop Prevention Protocol (SLPP)
    IPv6 = 0xDD86,   //  0x86DD  Internet Protocol Version 6 (IPv6)
}

impl EtherType {
    pub fn from_code(code: u16) -> Self {
        match code {
            0x0008 => Self::IPv4,
            0x0608 => Self::ARP,
            0x3580 => Self::RARP,
            0x0281 => Self::SLPP,
            0xDD86 => Self::IPv6,
            _ => Self::Unknown,
        }
    }
}


#[derive(Clone)]
pub struct Ethernet<'a> {
    data: &'a [u8],
}


impl<'a> Ethernet<'a> {
    pub const MAC_ADDRESS_SIZE : usize = 6;
    pub const ETHER_TYPE_SIZE  : usize = 2;
    pub const CRC_SIZE         : usize = 4;
    pub const HEADER_SIZE      : usize = 2 * ADDRESS_SIZE + ETHER_TYPE_SIZE + CRC_SIZE;

    pub const DEST_MAC_ADDRESS_OFFSET: Range<usize> = 0..6;
    pub const SRC_MAC_ADDRESS_OFFSET:  Range<usize> = 6..12;
    pub const ETHER_TYPE_OFFSET:       Range<usize> = 12..14;
    pub const PAYLOAD_OFFSET:                usize  = 14;

    // pub const MINIMUM_MAXIMUM_SEGMENT_SIZE: usize = 576;


    pub fn destination(&self) -> MacAddress { unsafe { MacAddress::from_bytes_unchecked(&self.data[Self::DEST_MAC_ADDRESS_OFFSET]) } }
    pub fn source(&self)      -> MacAddress { unsafe { MacAddress::from_bytes_unchecked(&self.data[Self::SRC_MAC_ADDRESS_OFFSET])  } }

    /// Values of 1500 and below mean that it is used to indicate the size of the payload in octets, while values
    /// of 1536 and above indicate that it is used as an EtherType, to indicate which protocol is encapsulated in
    /// the payload of the frame.
    pub fn ether_type(&self)  -> EtherType { EtherType::from_code((&self.data[Self::ETHER_TYPE_OFFSET]).read_u16::<LittleEndian>().unwrap()) }
    pub fn raw_payload(&self) -> &'a [u8]  { &self.data[Self::PAYLOAD_OFFSET..self.data.len()-Self::CRC_SIZE] }

    pub fn payload_size(&self) -> usize { self.data.len() - HEADER_SIZE }

    pub fn payload(&self) -> Result<Payload<'a>, Error> {
        match self.ether_type() {
            EtherType::IPv4 => {
                let payload = ipv4::IPv4::from_bytes(self.raw_payload())?;
                Ok(Payload::IPv4(payload))
            },
            EtherType::ARP  => Ok(Invalid),
            EtherType::RARP => Ok(Invalid),
            EtherType::SLPP => Ok(Invalid),
            EtherType::IPv6 => Ok(Invalid),
            EtherType::Unknown => Ok(Invalid),
        }
    }

    pub fn crc(&self) -> u32 { (&self.data[self.data.len() - Self::CRC_SIZE..]).read_u32::<LittleEndian>().unwrap() }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < HEADER_SIZE {
            return Err(Error::new(Other, format!("Ethernet data too small, expected at least {}, got {}", HEADER_SIZE, data.len())))
        }

        let me = Self { data };
        Ok(me)
    }
}



impl<'a> std::fmt::Debug for Ethernet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Ethernet\n")?;
        write!(f, "    Source:      {:?}\n", self.source())?;
        write!(f, "    Destination: {:?}\n", self.destination())?;
        write!(f, "    Ether Type:  {:?}\n", self.ether_type())?;
        write!(f, "    Payload:     {:?}\n", self.payload())?;
        write!(f, "    Crc:         {:?}\n", self.crc())?;
        Ok(())
    }
}














