use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::str::{Utf8Error, from_utf8};

use {Config, Network};

quick_error!{
    /// Error while parsing resolv.conf file
    #[derive(Debug)]
    pub enum ParseError {
        InvalidUtf8(line: usize, err: Utf8Error) {
            display("bad unicode at line {}: {}", line, err)
            cause(err)
        }
        InvalidValue(line: usize) {
            display("directive at line {} is improperly formatted \
                or contains invalid value", line)
        }
        InvalidOptionValue(line: usize) {
            display("directive options at line {} contains invalid \
                value of some option", line)
        }
        InvalidIp(line: usize, err: AddrParseError) {
            display("directive at line {} contains invalid IP: {}", line, err)
        }
        ExtraData(line: usize) {
            display("extra data at the end of the line {}", line)
        }
    }
}


fn ip_v4_netw(val: &str) -> Result<Network, AddrParseError> {
    let mut pair = val.splitn(2, '/');
    let ip = pair.next().unwrap().parse()?;
    if let Some(msk) = pair.next() {
        Ok(Network::V4(ip, msk.parse()?))
    } else {
        Ok(Network::V4(ip, Ipv4Addr::new(255, 255, 255, 255)))
    }
}
fn ip_v6_netw(val: &str) -> Result<Network, AddrParseError> {
    let mut pair = val.splitn(2, '/');
    let ip = pair.next().unwrap().parse()?;
    if let Some(msk) = pair.next() {
        Ok(Network::V6(ip, msk.parse()?))
    } else {
        Ok(Network::V6(
            ip,
            Ipv6Addr::new(65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535),
        ))
    }
}


pub fn parse(bytes: &[u8]) -> Result<Config, ParseError> {
    use self::ParseError::*;
    let mut cfg = Config::new();
    'lines: for (lineno, line) in bytes.split(|&x| x == b'\n').enumerate() {
        for &c in line.iter() {
            if c != b'\t' && c != b' ' {
                if c == b';' || c == b'#' {
                    continue 'lines;
                } else {
                    break;
                }
            }
        }
        // All that dances above to allow invalid utf-8 inside the comments
        let mut words = from_utf8(line)
            .map_err(|e| InvalidUtf8(lineno, e))?
            .split_whitespace();
        let keyword = match words.next() {
            Some(x) => x,
            None => continue,
        };
        match keyword {
            "nameserver" => {
                let srv = words
                    .next()
                    .and_then(|x| x.parse().ok())
                    .ok_or(InvalidValue(lineno))?;
                cfg.nameservers.push(srv);
                if words.next().is_some() {
                    return Err(ExtraData(lineno));
                }
            }
            "domain" => {
                let dom = words
                    .next()
                    .and_then(|x| x.parse().ok())
                    .ok_or(InvalidValue(lineno))?;
                cfg.search.clear();
                cfg.search.push(dom);
                if words.next().is_some() {
                    return Err(ExtraData(lineno));
                }
            }
            "search" => {
                cfg.search.clear();
                cfg.search.extend(words.map(|x| x.to_string()));
            }
            "sortlist" => {
                cfg.sortlist.clear();
                for pair in words {
                    let netw = ip_v4_netw(pair)
                        .or_else(|_| ip_v6_netw(pair))
                        .map_err(|e| InvalidIp(lineno, e))?;
                    cfg.sortlist.push(netw);
                }
            }
            "options" => {
                for pair in words {
                    let mut iter = pair.splitn(2, ':');
                    let key = iter.next().unwrap();
                    let value = iter.next();
                    if iter.next().is_some() {
                        return Err(ExtraData(lineno));
                    }
                    match (key, value) {
                        // TODO(tailhook) ensure that values are None?
                        ("debug", _) => cfg.debug = true,
                        ("ndots", Some(x)) => {
                            cfg.ndots = x.parse().map_err(|_| InvalidOptionValue(lineno))?
                        }
                        ("timeout", Some(x)) => {
                            cfg.timeout = x.parse().map_err(|_| InvalidOptionValue(lineno))?
                        }
                        ("attempts", Some(x)) => {
                            cfg.attempts = x.parse().map_err(|_| InvalidOptionValue(lineno))?
                        }
                        ("rotate", _) => cfg.rotate = true,
                        ("no-check-names", _) => cfg.no_check_names = true,
                        ("inet6", _) => cfg.inet6 = true,
                        ("ip6-bytestring", _) => cfg.ip6_bytestring = true,
                        ("ip6-dotint", _) => cfg.ip6_dotint = true,
                        ("no-ip6-dotint", _) => cfg.ip6_dotint = false,
                        ("edns0", _) => cfg.edns0 = true,
                        ("single-request", _) => cfg.single_request = true,
                        ("single-request-reopen", _) => cfg.single_request_reopen = true,
                        ("no-tld-query", _) => cfg.no_tld_query = true,
                        ("use-vc", _) => cfg.use_vc = true,
                        // Ignore unknown options
                        _ => {}
                    }
                }
            }
            // Ignore unknown directives
            _ => {}
        }
    }
    Ok(cfg)
}
