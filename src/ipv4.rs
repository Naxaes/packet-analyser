use std::io::{Error, ErrorKind};
use std::ops::{Index, Range};
use std::path::Iter;
use crate::tcp;



// @NOTE(ted): Assuming big endian (network endian) to little endian (hardware endian).
fn u8(data: &[u8],  i: usize) -> u8  { unsafe { (*data.get_unchecked(i+0)) } }
fn u16(data: &[u8], i: usize) -> u16 { unsafe { (*data.get_unchecked(i+1) as u16) << 8  | (*data.get_unchecked(i+0) as u16) << 0 } }
fn u32(data: &[u8], i: usize) -> u32 { unsafe { (*data.get_unchecked(i+3) as u32) << 24 | (*data.get_unchecked(i+2) as u32) << 16 | (*data.get_unchecked(i+1) as u32) << 8 | (*data.get_unchecked(i) as u32) << 0 } }
fn u64(data: &[u8], i: usize) -> u64 { unsafe { (*data.get_unchecked(i+7) as u64) << 56 | (*data.get_unchecked(i+6) as u64) << 48 | (*data.get_unchecked(i+5) as u64) << 40 | (*data.get_unchecked(i+4) as u64) << 32 | (*data.get_unchecked(i+3) as u64) << 24 | (*data.get_unchecked(i+2) as u64) << 16 | (*data.get_unchecked(i+1) as u64) << 8 | (*data.get_unchecked(i) as u64) << 0 } }



#[derive(Copy, Clone)]
pub struct Ipv4Address {
    data: [u8; 4]
}

impl Ipv4Address {
    pub fn from_bytes(bytes: [u8; 4]) -> Self {
        Self { data: bytes }
    }
}

impl std::fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.data[0], self.data[1], self.data[2], self.data[3])?;
        Ok(())
    }
}



// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#[derive(Debug)]
pub enum Protocol {
    Unknown = 0x92,  // Unassigned
    TCP = 6,
    UDP = 17
}

impl Protocol {
    pub fn from_value(value: u32) -> Self {
        match value {
            6  => Self::TCP,
            17 => Self::UDP,
            _  => Self::Unknown
        }
    }
}

#[derive(Debug)]
pub enum Payload<'a> {
    Tcp(tcp::Tcp<'a>),
}



struct BitArray<'a> {
    data: &'a [u8],
}

impl<'a> BitArray<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn at(&self, range: Range<usize>) -> Result<usize, Error> {
        let mut result = match range.len() {
            0..=8 => u8(&self.data, range.start / 8) as usize,
            9..=16 => u16(&self.data, range.start / 8) as usize,
            17..=32 => u32(&self.data, range.start / 8) as usize,
            33..=64 => u64(&self.data, range.start / 8) as usize,
            _ => return Err(Error::new(ErrorKind::Other, format!("Invalid range, must be 1-64, got {}", range.len())))
        };

        let start = range.start % 8;
        let end = range.end % 8;

        result = result >> start & 0xFFFF_FFFF_FFFF_FFFF >> (8 - end);
        Ok(result)
    }
}


#[derive(Clone)]
pub struct IPv4<'a> {
    data: &'a [u8],
}

impl<'a> IPv4<'a> {
    pub const VERSION_BITS             : Range<usize> = 0..4;
    pub const HEADER_LENGTH_BITS       : Range<usize> = 4..8;
    pub const DSCP_BITS                : Range<usize> = 8..14;
    pub const ECN_BITS                 : Range<usize> = 14..16;
    pub const TOTAL_LENGTH_BITS        : Range<usize> = 16..32;
    pub const IDENTIFICATION_BITS      : Range<usize> = 32..48;
    pub const FLAGS_BITS               : Range<usize> = 48..51;
    pub const FRAGMENT_OFFSET_BITS     : Range<usize> = 51..64;
    pub const TTL_BITS                 : Range<usize> = 64..72;
    pub const PROTOCOL_BITS            : Range<usize> = 72..80;
    pub const HEADER_CHECKSUM_BITS     : Range<usize> = 80..96;
    pub const SOURCE_ADDRESS_BITS      : Range<usize> = 96..128;
    pub const DESTINATION_ADDRESS_BITS : Range<usize> = 128..160;


    // @NOTE(ted): Assuming big endian (network endian) to little endian (hardware endian).
    fn u8(&self,  i: usize) -> u8  { unsafe { (*self.data.get_unchecked(i+0)) } }
    fn u16(&self, i: usize) -> u16 { unsafe { (*self.data.get_unchecked(i+1) as u16) << 8  | (*self.data.get_unchecked(i+0) as u16) << 0 } }
    fn u32(&self, i: usize) -> u32 { unsafe { (*self.data.get_unchecked(i+3) as u32) << 24 | (*self.data.get_unchecked(i+2) as u32) << 16 | (*self.data.get_unchecked(i+1) as u32) << 8 | (*self.data.get_unchecked(i) as u32) << 0 } }

    /// Version is always 4.
    pub fn version(&self) -> u8 { 4 }

    pub fn version_raw(&self)    -> u8 { (self.u8(0) & 0b1111_0000) >> 4 }
    pub fn header_length(&self)  -> u8 { (self.u8(0) & 0b0000_1111) >> 0 }

    // TODO: Check DSCP/ECN
    pub fn reserved1(&self)     -> u8 { (self.u8(1) & 0b0000_0001) >> 0 }
    pub fn cost(&self)          -> u8 { (self.u8(1) & 0b0000_0010) >> 1 }
    pub fn reliability(&self)   -> u8 { (self.u8(1) & 0b0000_0100) >> 2 }
    pub fn throughput(&self)    -> u8 { (self.u8(1) & 0b0000_1000) >> 3 }
    pub fn delay(&self)         -> u8 { (self.u8(1) & 0b0001_0000) >> 4 }
    pub fn precedence(&self)    -> u8 { (self.u8(1) & 0b1110_0000) >> 5 }

    pub fn total_length(&self)   -> u16 { self.u16(2) }
    pub fn identification(&self) -> u16 { self.u16(4) }

    pub fn reserved2(&self) -> u8 { (self.u8(6) & 0b0000_0001) >> 0 }
    pub fn df(&self)        -> u8 { (self.u8(6) & 0b0000_0001) >> 0 }
    pub fn mf(&self)        -> u8 { (self.u8(6) & 0b0000_0001) >> 0 }
    pub fn fragment_offset(&self) -> u16 { (self.u8(7) as u16) | (self.u8(6) as u16 & 0b0001_1111) }

    pub fn time_to_live(&self)        -> u8       { (self.u8(8))   }
    pub fn protocol(&self)            -> Protocol { Protocol::from_value(self.u8(9) as u32) }
    pub fn header_checksum(&self)     -> u16      { (self.u16(10)) }
    pub fn source_address(&self)      -> Ipv4Address { Ipv4Address::from_bytes(unsafe { std::mem::transmute(self.u32(12)) }) }
    pub fn destination_address(&self) -> Ipv4Address { Ipv4Address::from_bytes(unsafe { std::mem::transmute(self.u32(16)) }) }


    // pub fn has_options(&self) -> bool { self.header_length() > 5 }
    // pub fn options(&self) -> OptionIter<'a> {
    //     let total_header_length = self.header_length() * 4;
    //
    //     OptionIter {
    //         data: self.data[total_header_length..],
    //         index: 0
    //     }
    // }

    pub fn raw_payload(&self) -> &'a [u8] {
        &self.data[14..self.data.len()-4]
    }

    pub fn payload(&self) -> Result<Payload<'a>, Error> {
        match self.protocol() {
            Protocol::TCP => Ok(Payload::Tcp(tcp::Tcp::from_bytes(self.raw_payload())?)),
            Protocol::UDP => Err(Error::new(ErrorKind::Other, "UDP not implemented")),
            _ => Err(Error::new(ErrorKind::Other, "Unknown protocol")),
        }
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 20 {
            return Err(Error::new(ErrorKind::Other, format!("Ipv4 data too small, expected at least 20, got {}", data.len())));
        } else {
            let me = Self { data };

            // TODO: Verify all data.
            if me.version_raw()   != 4  { return Err(Error::new(ErrorKind::Other, "Version must be 4")) }
            if me.header_length()  < 5  { return Err(Error::new(ErrorKind::Other, "Header length too small")) }
            if me.header_length()  > 20 { return Err(Error::new(ErrorKind::Other, "Header length too big")) }
            if me.reserved1()     != 0  { return Err(Error::new(ErrorKind::Other, "Reserved flag is not 0")) }

            Ok(me)
        }
    }
}


impl<'a> std::fmt::Debug for IPv4<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "    Ipv4\n")?;
        write!(f, "        header_length:       {:?}\n", self.header_length())?;
        write!(f, "        version:             {:?}\n", self.version())?;
        write!(f, "        reserved1:           {:?}\n", self.reserved1())?;
        write!(f, "        cost:                {:?}\n", self.cost())?;
        write!(f, "        reliability:         {:?}\n", self.reliability())?;
        write!(f, "        throughput:          {:?}\n", self.throughput())?;
        write!(f, "        delay:               {:?}\n", self.delay())?;
        write!(f, "        precedence:          {:?}\n", self.precedence())?;
        write!(f, "        total_length:        {:?}\n", self.total_length())?;
        write!(f, "        identification:      {:?}\n", self.identification())?;
        write!(f, "        reserved2:           {:?}\n", self.reserved2())?;
        write!(f, "        df:                  {:?}\n", self.df())?;
        write!(f, "        mf:                  {:?}\n", self.mf())?;
        write!(f, "        fragment_offset:     {:?}\n", self.fragment_offset())?;
        write!(f, "        time_to_live:        {:?}\n", self.time_to_live())?;
        write!(f, "        protocol:            {:?}\n", self.protocol())?;
        write!(f, "        header_checksum:     {:?}\n", self.header_checksum())?;
        write!(f, "        source_address:      {:?}\n", self.source_address())?;
        write!(f, "        destination_address: {:?}\n", self.destination_address())?;
        write!(f, "        payload: {:?}\n",    self.payload())?;
        Ok(())
    }
}