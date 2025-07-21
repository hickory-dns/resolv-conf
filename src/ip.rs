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

impl Network {
    pub(crate) fn v4_from_str(val: &str) -> Result<Self, AddrParseError> {
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

            Ok(Self::V4(ip, mask))
        }
    }

    pub(crate) fn v6_from_str(val: &str) -> Result<Self, AddrParseError> {
        let mut pair = val.splitn(2, '/');
        let ip = pair.next().unwrap().parse()?;
        if let Some(msk) = pair.next() {
            // FIXME: validate the mask
            Ok(Self::V6(ip, msk.parse()?))
        } else {
            // FIXME: "guess" an appropriate mask for the IP
            Ok(Self::V6(
                ip,
                Ipv6Addr::new(
                    65_535, 65_535, 65_535, 65_535, 65_535, 65_535, 65_535, 65_535,
                ),
            ))
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Network::V4(address, mask) => write!(fmt, "{address}/{mask}"),
            Network::V6(address, mask) => write!(fmt, "{address}/{mask}"),
        }
    }
}

/// Represent an IP address. This type is similar to `std::net::IpAddr` but it supports IPv6 scope
/// identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopedIp {
    /// Represent an IPv4 address
    V4(Ipv4Addr),
    /// Represent an IPv6 and its scope identifier, if any
    V6(Ipv6Addr, Option<String>),
}

impl From<ScopedIp> for IpAddr {
    fn from(val: ScopedIp) -> Self {
        match val {
            ScopedIp::V4(ip) => IpAddr::from(ip),
            ScopedIp::V6(ip, _) => IpAddr::from(ip),
        }
    }
}

impl From<&ScopedIp> for IpAddr {
    fn from(val: &ScopedIp) -> Self {
        match val {
            ScopedIp::V4(ip) => IpAddr::from(*ip),
            ScopedIp::V6(ip, _) => IpAddr::from(*ip),
        }
    }
}

impl From<Ipv6Addr> for ScopedIp {
    fn from(value: Ipv6Addr) -> Self {
        ScopedIp::V6(value, None)
    }
}

impl From<Ipv4Addr> for ScopedIp {
    fn from(value: Ipv4Addr) -> Self {
        ScopedIp::V4(value)
    }
}

impl From<IpAddr> for ScopedIp {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => ScopedIp::from(ip),
            IpAddr::V6(ip) => ScopedIp::from(ip),
        }
    }
}

impl FromStr for ScopedIp {
    type Err = AddrParseError;
    /// Parse a string representing an IP address.
    fn from_str(s: &str) -> Result<ScopedIp, AddrParseError> {
        let mut parts = s.split('%');
        let addr = parts.next().unwrap();
        match IpAddr::from_str(addr) {
            Ok(IpAddr::V4(ip)) => {
                if parts.next().is_some() {
                    // It's not a valid IPv4 address if it contains a '%'
                    Err(AddrParseError)
                } else {
                    Ok(ScopedIp::from(ip))
                }
            }
            Ok(IpAddr::V6(ip)) => {
                if let Some(scope_id) = parts.next() {
                    if scope_id.is_empty() {
                        return Err(AddrParseError);
                    }
                    for c in scope_id.chars() {
                        if !c.is_alphanumeric() {
                            return Err(AddrParseError);
                        }
                    }
                    Ok(ScopedIp::V6(ip, Some(scope_id.to_string())))
                } else {
                    Ok(ScopedIp::V6(ip, None))
                }
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl fmt::Display for ScopedIp {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScopedIp::V4(address) => address.fmt(fmt),
            ScopedIp::V6(address, None) => address.fmt(fmt),
            ScopedIp::V6(address, Some(scope)) => write!(fmt, "{address}%{scope}"),
        }
    }
}

/// An error which can be returned when parsing an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("invalid IP address syntax")
    }
}

impl Error for AddrParseError {}

impl From<::std::net::AddrParseError> for AddrParseError {
    fn from(_: ::std::net::AddrParseError) -> Self {
        AddrParseError
    }
}
