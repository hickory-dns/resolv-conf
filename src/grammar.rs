use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::Utf8Error;

use crate::{AddrParseError, Network};

/// Error while parsing resolv.conf file
#[derive(Debug)]
pub enum ParseError {
    /// Error that may be returned when the string to parse contains invalid UTF-8 sequences
    InvalidUtf8(usize, Utf8Error),
    /// Error returned a value for a given directive is invalid.
    /// This can also happen when the value is missing, if the directive requires a value.
    InvalidValue(usize),
    /// Error returned when a value for a given option is invalid.
    /// This can also happen when the value is missing, if the option requires a value.
    InvalidOptionValue(usize),
    /// Error returned when a invalid option is found.
    InvalidOption(usize),
    /// Error returned when a invalid directive is found.
    InvalidDirective(usize),
    /// Error returned when a value cannot be parsed an an IP address.
    InvalidIp(usize, AddrParseError),
    /// Error returned when there is extra data at the end of a line.
    ExtraData(usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseError::InvalidUtf8(line, err) => write!(f, "bad unicode at line {line}: {err}"),
            ParseError::InvalidValue(line) => write!(
                f,
                "directive at line {line} is improperly formatted or contains invalid value",
            ),
            ParseError::InvalidOptionValue(line) => write!(
                f,
                "directive options at line {line} contains invalid value of some option",
            ),
            ParseError::InvalidOption(line) => {
                write!(f, "option at line {line} is not recognized")
            }
            ParseError::InvalidDirective(line) => {
                write!(f, "directive at line {line} is not recognized")
            }
            ParseError::InvalidIp(line, err) => {
                write!(f, "directive at line {line} contains invalid IP: {err}")
            }
            ParseError::ExtraData(line) => write!(f, "extra data at the end of line {line}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::InvalidUtf8(_, err) => Some(err),
            _ => None,
        }
    }
}

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
