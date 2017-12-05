use std::iter::{IntoIterator, Iterator};
use std::slice::Iter;
use {grammar, Network, ParseError, ScopedIp};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum LastSearch {
    None,
    Domain,
    Search,
}


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
///     config.set_search(vec!["example.com".into()]);
///
///     // Parse a config
///     let parsed = Config::parse("nameserver 8.8.8.8\nsearch example.com").unwrap();
///     assert_eq!(parsed, config);
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// List of nameservers
    pub nameservers: Vec<ScopedIp>,
    /// Indicated whether the last line that has been parsed is a "domain" directive or a "search"
    /// directive. This is important for compatibility with glibc, since in glibc's implementation,
    /// "search" and "domain" are mutually exclusive, and only the last directive is taken into
    /// consideration.
    last_search: LastSearch,
    /// Domain to append to name when it doesn't contain ndots
    domain: Option<String>,
    /// List of suffixes to append to name when it doesn't contain ndots
    search: Option<Vec<String>>,
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
    /// Create a new `Config` object with default values.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::Config;
    /// # fn main() {
    /// let config = Config::new();
    /// assert_eq!(config.nameservers, vec![]);
    /// assert!(config.get_domain().is_none());
    /// assert!(config.get_search().is_none());
    /// assert_eq!(config.sortlist, vec![]);
    /// assert_eq!(config.debug, false);
    /// assert_eq!(config.ndots, 1);
    /// assert_eq!(config.timeout, 5);
    /// assert_eq!(config.attempts, 2);
    /// assert_eq!(config.rotate, false);
    /// assert_eq!(config.no_check_names, false);
    /// assert_eq!(config.inet6, false);
    /// assert_eq!(config.ip6_bytestring, false);
    /// assert_eq!(config.ip6_dotint, false);
    /// assert_eq!(config.edns0, false);
    /// assert_eq!(config.single_request, false);
    /// assert_eq!(config.single_request_reopen, false);
    /// assert_eq!(config.no_tld_query, false);
    /// assert_eq!(config.use_vc, false);
    /// # }
    pub fn new() -> Config {
        Config {
            nameservers: Vec::new(),
            domain: None,
            search: None,
            last_search: LastSearch::None,
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

    /// Parse a buffer and return the corresponding `Config` object.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::{ScopedIp, Config};
    /// # fn main() {
    /// let config_str = "# /etc/resolv.conf
    /// nameserver  8.8.8.8
    /// nameserver  8.8.4.4
    /// search      example.com sub.example.com
    /// options     ndots:8 attempts:8";
    ///
    /// // Parse the config
    /// let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
    ///
    /// // Print the config
    /// println!("{:?}", parsed_config);
    /// # }
    /// ```
    pub fn parse<T: AsRef<[u8]>>(buf: T) -> Result<Config, ParseError> {
        grammar::parse(buf.as_ref())
    }

    /// Return the suffixes declared in the last "domain" or "search" directive.
    ///
    /// ```rust
    /// # extern crate resolv_conf;
    /// use resolv_conf::{ScopedIp, Config};
    /// # fn main() {
    /// let config_str = "search example.com sub.example.com\ndomain localdomain";
    /// let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
    /// let domains = parsed_config.get_last_search_or_domain()
    ///                            .map(|domain| domain.clone())
    ///                            .collect::<Vec<String>>();
    /// assert_eq!(domains, vec![String::from("localdomain")]);
    ///
    /// let config_str = "domain localdomain\nsearch example.com sub.example.com";
    /// let parsed_config = Config::parse(&config_str).expect("Failed to parse config");
    /// let domains = parsed_config.get_last_search_or_domain()
    ///                            .map(|domain| domain.clone())
    ///                            .collect::<Vec<String>>();
    /// assert_eq!(domains, vec![String::from("example.com"), String::from("sub.example.com")]);
    /// # }
    pub fn get_last_search_or_domain<'a>(&'a self) -> DomainIter<'a> {
        match self.last_search {
            LastSearch::Search => DomainIter::Search(
                self.get_search()
                    .and_then(|domains| Some(domains.into_iter())),
            ),
            LastSearch::Domain => DomainIter::Domain(self.get_domain()),
            LastSearch::None => DomainIter::None,
        }
    }

    /// Return the domain declared in the last "domain" directive.
    pub fn get_domain(&self) -> Option<&String> {
        self.domain.as_ref()
    }

    /// Return the domains declared in the last "search" directive.
    pub fn get_search(&self) -> Option<&Vec<String>> {
        self.search.as_ref()
    }

    /// Set the domain corresponding to the "domain" directive.
    pub fn set_domain(&mut self, domain: String) {
        self.domain = Some(domain);
        self.last_search = LastSearch::Domain;
    }

    /// Set the domains corresponding the "search" directive.
    pub fn set_search(&mut self, search: Vec<String>) {
        self.search = Some(search);
        self.last_search = LastSearch::Search;
    }
}

/// A iterator returned by [`Config.get_last_search_or_domain`](struct.Config.html#method.get_last_search_or_domain)
#[derive(Debug, Clone)]
pub enum DomainIter<'a> {
    Search(Option<Iter<'a, String>>),
    Domain(Option<&'a String>),
    None,
}

impl<'a> Iterator for DomainIter<'a> {
    type Item = &'a String;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            DomainIter::Search(Some(ref mut domains)) => domains.next(),
            DomainIter::Domain(ref mut domain) => domain.take(),
            _ => None,
        }
    }
}
