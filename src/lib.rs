//! The crate simply parses `/etc/resolv.conf` file and creates a config object
//!
//! # Examples
//!
//! ## Parsing a config from a string
//! ```rust
//! extern crate resolv_conf;
//!
//! use std::net::{Ipv4Addr, Ipv6Addr};
//! use resolv_conf::{ScopedIp, Config, Network};
//!
//! fn main() {
//!     let config_str = "
//! options ndots:8 timeout:8 attempts:8
//!
//! domain example.com
//! search example.com sub.example.com
//!
//! nameserver 2001:4860:4860::8888
//! nameserver 2001:4860:4860::8844
//! nameserver 8.8.8.8
//! nameserver 8.8.4.4
//!
//! options rotate
//! options inet6 no-tld-query
//!
//! sortlist 130.155.160.0/255.255.240.0 130.155.0.0";
//!
//!     // Parse the config.
//!     let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
//!
//!     // We can build configs manually as well, either directly or with Config::new()
//!     let mut expected_config = Config::new();
//!     expected_config.nameservers = vec![
//!         ScopedIp::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), None),
//!         ScopedIp::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844), None),
//!         ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)),
//!         ScopedIp::V4(Ipv4Addr::new(8, 8, 4, 4)),
//!     ];
//!     expected_config.sortlist = vec![
//!         Network::V4(Ipv4Addr::new(130, 155, 160, 0), Ipv4Addr::new(255, 255, 240, 0)),
//!         Network::V4(Ipv4Addr::new(130, 155, 0, 0), Ipv4Addr::new(255, 255, 0, 0)),
//!     ];
//!     expected_config.debug = false;
//!     expected_config.ndots = 8;
//!     expected_config.timeout = 8;
//!     expected_config.attempts = 8;
//!     expected_config.rotate = true;
//!     expected_config.no_check_names = false;
//!     expected_config.inet6 = true;
//!     expected_config.ip6_bytestring = false;
//!     expected_config.ip6_dotint = false;
//!     expected_config.edns0 = false;
//!     expected_config.single_request = false;
//!     expected_config.single_request_reopen = false;
//!     expected_config.no_tld_query = true;
//!     expected_config.use_vc = false;
//!     expected_config.set_domain(String::from("example.com"));
//!     expected_config.set_search(vec![
//!         String::from("example.com"),
//!         String::from("sub.example.com")
//!     ]);
//!
//!     // We can compare configurations, since resolv_conf::Config implements Eq
//!     assert_eq!(parsed_config, expected_config);
//! }
//! ```
//!
//! ## Parsing a file
//!
//! ```rust
//! use std::io::Read;
//! use std::fs::File;
//!
//! extern crate resolv_conf;
//!
//! fn main() {
//!     // Read the file
//!     let mut buf = Vec::with_capacity(4096);
//!     let mut f = File::open("/etc/resolv.conf").unwrap();
//!     f.read_to_end(&mut buf).unwrap();
//!
//!     // Parse the buffer
//!     let cfg = resolv_conf::Config::parse(&buf).unwrap();
//!
//!     // Print the config
//!     println!("---- Parsed /etc/resolv.conf -----\n{:#?}\n", cfg);
//! }
//! ```

#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

use std::str::Utf8Error;

mod config;
pub use config::{Config, DomainIter, Family, Lookup};
mod ip;
pub use ip::{AddrParseError, Network, ScopedIp};

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
