use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ip::{AddrParseError, Network};

pub(crate) fn ip_v4_netw(val: &str) -> Result<Network, AddrParseError> {
    let mut pair = val.splitn(2, '/');
    let ip: Ipv4Addr = pair.next().unwrap().parse()?;
    if ip.is_unspecified() {
        return Err(AddrParseError);
    }
    if let Some(mask) = pair.next() {
        let mask = mask.parse()?;
        // make sure this is a valid mask
        let value: u32 = ip.octets().iter().fold(0, |acc, &x| acc + u32::from(x));
        if value == 0 || (value & !value != 0) {
            Err(AddrParseError)
        } else {
            Ok(Network::V4(ip, mask))
        }
    } else {
        // We have to "guess" the mask.
        //
        // FIXME(@little-dude) right now, we look at the number or bytes that are 0, but maybe we
        // should use the number of bits that are 0.
        //
        // In other words, with this implementation, the mask of `128.192.0.0` will be
        // `255.255.0.0` (a.k.a `/16`). But we could also consider that the mask is `/10` (a.k.a
        // `255.63.0.0`).
        //
        // My only source on topic is the "DNS and Bind" book which suggests using bytes, not bits.
        let octets = ip.octets();
        let mask = if octets[3] == 0 {
            if octets[2] == 0 {
                if octets[1] == 0 {
                    Ipv4Addr::new(255, 0, 0, 0)
                } else {
                    Ipv4Addr::new(255, 255, 0, 0)
                }
            } else {
                Ipv4Addr::new(255, 255, 255, 0)
            }
        } else {
            Ipv4Addr::new(255, 255, 255, 255)
        };
        Ok(Network::V4(ip, mask))
    }
}

pub(crate) fn ip_v6_netw(val: &str) -> Result<Network, AddrParseError> {
    let mut pair = val.splitn(2, '/');
    let ip = pair.next().unwrap().parse()?;
    if let Some(msk) = pair.next() {
        // FIXME: validate the mask
        Ok(Network::V6(ip, msk.parse()?))
    } else {
        // FIXME: "guess" an appropriate mask for the IP
        Ok(Network::V6(
            ip,
            Ipv6Addr::new(
                65_535, 65_535, 65_535, 65_535, 65_535, 65_535, 65_535, 65_535,
            ),
        ))
    }
}
