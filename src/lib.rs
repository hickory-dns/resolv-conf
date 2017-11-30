//! The crate simply parses `/etc/resolv.conf` file and creates a config object
//!
//!

#[macro_use]
extern crate quick_error;

mod grammar;

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub use grammar::ParseError;

/// A network, that is an IP address and the mask
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    // Address netmask
    V4(Ipv4Addr, Ipv4Addr),
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

impl From<std::net::AddrParseError> for AddrParseError {
    fn from(_: std::net::AddrParseError) -> Self {
        AddrParseError
    }
}

/// Encompasses the nameserver configuration
///
/// Currently the options and defaults match those of linux/glibc
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// List of nameservers
    pub nameservers: Vec<Ip>,
    /// List of suffixes to append to name when it doesn't contain ndots
    pub search: Vec<String>,
    /// List of preferred addresses
    pub sortlist: Vec<Network>,
    /// Enable DNS resolve debugging
    pub debug: bool,
    /// Number of dots in name to try absolute resolving first (default 1)
    pub ndots: u32,
    /// Dns query timeout (default 5 [sec])
    pub timeout: u32,
    /// Number of attempts to resolve name if server is inaccesible (default 2)
    pub attempts: u32,
    /// Round-robin selection of servers (default false)
    pub rotate: bool,
    /// Don't check names for validity (default false)
    pub no_check_names: bool,
    /// Try AAAA query before A
    pub inet6: bool,
    /// Use reverse lookup of ipv6 using bit-label format described instead
    /// of nibble format
    pub ip6_bytestring: bool,
    /// Do ipv6 reverse lookups in ip6.int zone instead of ip6.arpa
    /// (default false)
    pub ip6_dotint: bool,
    /// Enable dns extensions described in RFC 2671
    pub edns0: bool,
    /// Don't make ipv4 and ipv6 requests simultaneously
    pub single_request: bool,
    /// Use same socket for the A and AAAA requests
    pub single_request_reopen: bool,
    /// Don't resolve unqualified name as top level domain
    pub no_tld_query: bool,
    /// Force using TCP for DNS resolution
    pub use_vc: bool,
}

impl Config {
    pub fn new() -> Config {
        Config {
            nameservers: Vec::new(),
            search: Vec::new(),
            sortlist: Vec::new(),
            debug: false,
            ndots: 1,
            timeout: 5,
            attempts: 2,
            rotate: false,
            no_check_names: false,
            inet6: false,
            ip6_bytestring: false,
            ip6_dotint: false,
            edns0: false,
            single_request: false,
            single_request_reopen: false,
            no_tld_query: false,
            use_vc: false,
        }
    }
    pub fn parse<T: AsRef<[u8]>>(buf: T) -> Result<Config, grammar::ParseError> {
        grammar::parse(buf.as_ref())
    }
}
