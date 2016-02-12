extern crate ip;
#[macro_use] extern crate nom;

mod grammar;

pub use ip::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub enum Network {
    // Address netmask
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

#[derive(Clone, Debug)]
pub struct Config {
    /// List of nameservers
    pub nameservers: Vec<IpAddr>,
    /// List of suffixes to append to name when it doesn't contain ndots
    pub search: Vec<String>,
    /// List of preferred addresses
    pub sortlist: Vec<Network>,
    /// Number of dots in name to try absolute resolving first (default 1)
    pub ndots: u32,
    /// Dns query timeout (default 5 [sec])
    pub timeout: u32,
    /// Number of types resolver will retry if server is inaccesible (default 2)
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
}

impl Config {
    pub fn new() -> Config {
        Config {
            nameservers: Vec::new(),
            search: Vec::new(),
            sortlist: Vec::new(),
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
        }
    }
    pub fn parse(buf: &[u8]) -> Result<Config, grammar::ParseError> {
        grammar::parse(buf)
    }
}


