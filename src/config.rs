use {ScopedIp, Network};


/// Represent a resolver configuration, as described in `man 5 resolv.conf` on linux.
/// The options and defaults match those in this `man` page.
///
/// ```rust
/// extern crate resolv_conf;
///
/// use std::net::Ipv4Addr;
/// use resolv_conf::{Config, ScopedIp};
///
/// fn main() {
///     // Create a new config
///     let mut config = Config::new();
///     config.nameservers.push(ScopedIp::V4(Ipv4Addr::new(8, 8, 8, 8)));
///     config.search.push("example.com".into());
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// List of nameservers
    pub nameservers: Vec<ScopedIp>,
    /// Domain to append to name when it doesn't contain ndots
    pub domain: Option<String>,
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
    /// Port to use be used for this resolver. This option applies only to Mac Os.
    pub port: Option<u16>,
}

impl Config {
    /// Create a new `Config` object with default values.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::Config;
    /// # fn main() {
    /// assert_eq!(
    ///     Config::new(),
    ///     Config {
    ///         nameservers: vec![],
    ///         domain: None,
    ///         search: vec![],
    ///         sortlist: vec![],
    ///         debug: false,
    ///         ndots: 1,
    ///         timeout: 5,
    ///         attempts: 2,
    ///         rotate: false,
    ///         no_check_names: false,
    ///         inet6: false,
    ///         ip6_bytestring: false,
    ///         ip6_dotint: false,
    ///         edns0: false,
    ///         single_request: false,
    ///         single_request_reopen: false,
    ///         no_tld_query: false,
    ///         use_vc: false,
    ///         port: None,
    ///     });
    /// # }
    pub fn new() -> Config {
        Config {
            nameservers: Vec::new(),
            domain: None,
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
            port: None,
        }
    }
}
