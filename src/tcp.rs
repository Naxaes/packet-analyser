use std::io::{Error, ErrorKind};
use std::ops::Range;
use chrono::format::format;
use crate::tcp::Option::{MaximumSegmentSize, NoOperation, Sack, SackPermitted, Timestamp, WindowScale};


// @NOTE(ted): Assuming big endian (network endian) to little endian (hardware endian).
fn be2leu8(data: &[u8],  i: usize) -> u8  { unsafe { (*data.get_unchecked(i+0)) } }
fn be2leu16(data: &[u8], i: usize) -> u16 { unsafe { (*data.get_unchecked(i+1) as u16) << 8  | (*data.get_unchecked(i+0) as u16) << 0 } }
fn be2leu32(data: &[u8], i: usize) -> u32 { unsafe { (*data.get_unchecked(i+3) as u32) << 24 | (*data.get_unchecked(i+2) as u32) << 16 | (*data.get_unchecked(i+1) as u32) << 8 | (*data.get_unchecked(i) as u32) << 0 } }


#[derive(Debug)]
pub enum Option {
    NoOperation,
    MaximumSegmentSize{ size: u16 },
    WindowScale{ scale: u8 },
    SackPermitted,
    Sack { begin: u32, end: u32 },
    Sack2 {  },
    Sack3 {  },
    Sack4 {  },
    Timestamp { timestamp: u32, echo: u32 }
}


pub struct OptionIter<'a> {
    data: &'a [u8],
    index: usize,
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = Option;

    fn next(&mut self) -> std::option::Option<Self::Item> {
        let kind = self.data.get(self.index)?;
        self.index += 1;

        match kind {
            0 => None,  // EndOfOptions
            1 => Some(NoOperation),
            2 => {
                if self.data.len() < self.index + 2 { return None; }
                let size = be2leu16(&self.data, self.index);
                self.index += 2;
                Some(MaximumSegmentSize { size })
            },
            3 => {
                if self.data.len() < self.index + 1 { return None; }
                let scale = be2leu8(&self.data, self.index);
                self.index += 1;
                Some(WindowScale { scale })
            },
            4 => Some(SackPermitted),
            5 => {
                if self.data.len() < self.index + 4 { return None; }
                let begin = be2leu32(&self.data, self.index);
                self.index += 4;
                if self.data.len() < self.index + 4 { return None; }
                let end = be2leu32(&self.data, self.index);
                self.index += 4;
                Some(Sack { begin, end })
            },
            6..=7 => None,
            8 => {
                if self.data.len() < self.index + 4 { return None; }
                let timestamp = be2leu32(&self.data, self.index);
                self.index += 4;
                if self.data.len() < self.index + 4 { return None; }
                let echo = be2leu32(&self.data, self.index);
                self.index += 4;
                Some(Timestamp { timestamp, echo })
            }
            _ => None
        }
    }
}


#[derive(Clone)]
pub struct Tcp<'a> {
    data: &'a [u8],
}

impl<'a> Tcp<'a> {
    pub const SOURCE_PORT_BITS:           Range<usize> = 0..16;
    pub const DESTINATION_PORT_BITS:      Range<usize> = 16..32;
    pub const SEQUENCE_NUMBER_BITS:       Range<usize> = 32..64;
    pub const ACKNOWLEDGMENT_NUMBER_BITS: Range<usize> = 64..96;
    pub const RESERVED_BITS:              Range<usize> = 96..100;
    pub const DATA_OFFSET_BITS:           Range<usize> = 100..104;
    pub const CWR_BITS:                   Range<usize> = 104..105;
    pub const ECE_BITS:                   Range<usize> = 105..106;
    pub const URG_BITS:                   Range<usize> = 106..107;
    pub const ACK_BITS:                   Range<usize> = 107..108;
    pub const PSH_BITS:                   Range<usize> = 108..109;
    pub const RST_BITS:                   Range<usize> = 109..110;
    pub const SYN_BITS:                   Range<usize> = 110..111;
    pub const FIN_BITS:                   Range<usize> = 111..112;
    pub const WINDOW_SIZE_BITS:           Range<usize> = 112..128;
    pub const CHECK_SUM_BITS:             Range<usize> = 128..144;
    pub const URGENT_POINTER_BITS:        Range<usize> = 144..160;


    /// Version is always 4.
    pub fn source_port(&self)      -> u16 { be2leu16(&self.data, 0) }
    pub fn destination_port(&self) -> u16 { be2leu16(&self.data, 2) }

    pub fn sequence_number(&self)        -> u32 { be2leu32(&self.data, 4) }
    pub fn acknowledgment_number(&self)  -> u32 { be2leu32(&self.data, 8) }

    pub fn reserved(&self)    -> u8 { (be2leu8(&self.data, 12) & 0b1111_0000) >> 4 }
    pub fn data_offset(&self) -> u8 { (be2leu8(&self.data, 12) & 0b0000_1111) >> 0 }

    pub fn cwr(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0000_0001) >> 0 }
    pub fn ece(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0000_0010) >> 1 }
    pub fn urg(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0000_0100) >> 2 }
    pub fn ack(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0000_1000) >> 3 }
    pub fn psh(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0001_0000) >> 4 }
    pub fn rst(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0010_0000) >> 5 }
    pub fn syn(&self) -> u8 { (be2leu8(&self.data, 13) & 0b0100_0000) >> 6 }
    pub fn fin(&self) -> u8 { (be2leu8(&self.data, 13) & 0b1000_0000) >> 7 }

    pub fn window_size(&self)    -> u16 { be2leu16(&self.data, 14) }
    pub fn check_sum(&self)      -> u16 { be2leu16(&self.data, 16) }
    pub fn urgent_pointer(&self) -> u16 { be2leu16(&self.data, 18) }

    pub fn header_size(&self) -> usize { self.data_offset() as usize * 4 }

    pub fn raw_payload(&self) -> &[u8] {
        &self.data[self.header_size()..]
    }

    pub fn options(&self) -> OptionIter<'a> {
        let options = &self.data[20..];
        OptionIter {
            data: options,
            index: 0
        }
    }

    pub fn from_bytes(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 20 {
            return Err(Error::new(ErrorKind::Other, format!("Tcp data too small, expected at least 20, got {}", data.len())));
        }

        let me = Self { data };

        if me.header_size() > data.len() {
            return Err(Error::new(ErrorKind::Other, format!("Tcp header size too big, expected at most {}, got {}", data.len(), me.header_size())));
        }

        // TODO: Verify all data.
        Ok(me)
    }
}


impl<'a> std::fmt::Debug for Tcp<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "    Tcp\n")?;
        write!(f, "        source_port:           {:?}\n", self.source_port())?;
        write!(f, "        destination_port:      {:?}\n", self.destination_port())?;
        write!(f, "        sequence_number:       {:?}\n", self.sequence_number())?;
        write!(f, "        acknowledgment_number: {:?}\n", self.acknowledgment_number())?;
        write!(f, "        reserved:              {:?}\n", self.reserved())?;
        write!(f, "        data_offset:           {:?}\n", self.data_offset())?;
        write!(f, "        cwr:                   {:?}\n", self.cwr())?;
        write!(f, "        ece:                   {:?}\n", self.ece())?;
        write!(f, "        urg:                   {:?}\n", self.urg())?;
        write!(f, "        ack:                   {:?}\n", self.ack())?;
        write!(f, "        psh:                   {:?}\n", self.psh())?;
        write!(f, "        rst:                   {:?}\n", self.rst())?;
        write!(f, "        syn:                   {:?}\n", self.syn())?;
        write!(f, "        fin:                   {:?}\n", self.fin())?;
        write!(f, "        window_size:           {:?}\n", self.window_size())?;
        write!(f, "        check_sum:             {:?}\n", self.check_sum())?;
        write!(f, "        urgent_pointer:        {:?}\n", self.urgent_pointer())?;
        for (i, option) in self.options().enumerate() {
            write!(f, "        option[{}]:        {:?}\n", i, option)?;
        }
        Ok(())
    }
}