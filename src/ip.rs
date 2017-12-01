use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A network, that is an IP address and a mask
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// Represent an IPv4 network address
    V4(Ipv4Addr, Ipv4Addr),
    /// Represent an IPv6 network address
    V6(Ipv6Addr, Ipv6Addr),
}

/// Represent an IP address. This type is similar to `std::net::IpAddr` but it supports IPv6 scope
/// identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ip {
    /// Represent an IPv4 address
    V4(Ipv4Addr),
    /// Represent an IPv6 and its scope identifier, if any
    V6(Ipv6Addr, Option<String>),
}

impl Into<IpAddr> for Ip {
    fn into(self) -> IpAddr {
        match self {
            Ip::V4(ip) => IpAddr::from(ip),
            Ip::V6(ip, _) => IpAddr::from(ip),
        }
    }
}

impl<'a> Into<IpAddr> for &'a Ip {
    fn into(self) -> IpAddr {
        match *self {
            Ip::V4(ref ip) => IpAddr::from(*ip),
            Ip::V6(ref ip, _) => IpAddr::from(*ip),
        }
    }
}

impl From<Ipv6Addr> for Ip {
    fn from(value: Ipv6Addr) -> Self {
        Ip::V6(value, None)
    }
}

impl From<Ipv4Addr> for Ip {
    fn from(value: Ipv4Addr) -> Self {
        Ip::V4(value)
    }
}

impl From<IpAddr> for Ip {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => Ip::from(ip),
            IpAddr::V6(ip) => Ip::from(ip),
        }
    }
}

impl Ip {
    /// Parse a string representing an IP address.
    pub fn parse(s: &str) -> Result<Ip, AddrParseError> {
        let mut parts = s.split('%');
        let addr = parts.next().unwrap();
        match IpAddr::from_str(addr) {
            Ok(IpAddr::V4(ip)) => {
                if parts.next().is_some() {
                    // It's not a valid IPv4 address if it contains a '%'
                    Err(AddrParseError)
                } else {
                    Ok(Ip::from(ip))
                }
            }
            Ok(IpAddr::V6(ip)) => if let Some(scope_id) = parts.next() {
                if scope_id.is_empty() {
                    return Err(AddrParseError);
                }
                for c in scope_id.chars() {
                    if !c.is_alphanumeric() {
                        return Err(AddrParseError);
                    }
                }
                Ok(Ip::V6(ip, Some(scope_id.to_string())))
            } else {
                Ok(Ip::V6(ip, None))
            },
            Err(e) => Err(e.into()),
        }
    }
}

/// An error which can be returned when parsing an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl Error for AddrParseError {
    fn description(&self) -> &str {
        "invalid IP address syntax"
    }
}

impl From<::std::net::AddrParseError> for AddrParseError {
    fn from(_: ::std::net::AddrParseError) -> Self {
        AddrParseError
    }
}
