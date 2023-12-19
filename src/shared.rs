use std::io::{Error, ErrorKind};
use std::io::ErrorKind::Other;


#[allow(non_upper_case_globals)]
pub const NETWORK_PROTOCOL_IPv4 : u16 = 0x0800;
#[allow(non_upper_case_globals)]
pub const NETWORK_PROTOCOL_IPv6 : u16 = 0x86DD;
pub const NETWORK_PROTOCOL_ARP  : u16 = 0x0806;

pub const TRANSPORT_PROTOCOL_UDP : u8 = 0x11;
pub const TRANSPORT_PROTOCOL_TCP : u8 = 0x06;



#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct MacAddress {
    data: [u8; 6]
}


impl MacAddress {
    pub unsafe fn from_bytes_unchecked(data: &[u8]) -> Self {
        let array = <&[u8; 6]>::try_from(data).unwrap();
        Self { data: *array }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 6 {
            return Err(Error::new(Other, format!("MacAddress needs 6 bytes, got {}", data.len())))
        } else {
            let mut x: [u8; 6] = [0; 6];
            x.copy_from_slice(&data[0..6]);
            Ok(Self { data: x })
        }
    }
}


impl std::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}:{}:{}:{}:{}", self.data[0], self.data[1], self.data[2], self.data[3], self.data[4], self.data[5])
    }
}