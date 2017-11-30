//! The crate simply parses `/etc/resolv.conf` file and creates a config object
//!
//!

#[macro_use]
extern crate quick_error;

mod grammar;
mod ip;
mod config;


pub use grammar::{parse, ParseError};
pub use ip::{AddrParseError, Ip, Network};
pub use config::Config;
