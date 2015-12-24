use std::str::from_utf8;
use nom::{space, eof};
use nom::IResult::{Done};

use {Config, IpAddr};


#[derive(Debug)]
enum Directive<'a> {
    Nameserver(&'a str),
    Domain(&'a str),
    Search(Vec<&'a str>),
    Nothing,
}


pub type ParseError = u32; // FIXME


pub fn parse(input: &[u8]) -> Result<Config, ParseError> {
    match config(&input[..]) {
        Done(_, rc) => Ok(rc),
        _ => Err(0)
    }
}

named!(nameserver<&[u8], Directive>,
    chain!(
        tag!("nameserver") ~
        space ~
        value: map_res!(take_until!("\n"), from_utf8) ~
        char!('\n'),
    || { Directive::Nameserver(value) }));

named!(domain<&[u8], Directive>,
    chain!(
        tag!("domain") ~
        space ~
        value: map_res!(take_until!("\n"), from_utf8) ~
        char!('\n'),
    || { Directive::Domain(value) }));

named!(search<&[u8], Directive>,
    chain!(
        tag!("search") ~
        items: many1!(chain!(
            space ~
            n: map_res!(take_until_either!(" \n"), from_utf8),
            || { n })) ~
        char!('\n'),
    || { Directive::Search(items) }));

named!(nothing<&[u8], Directive>,
    chain!(
        char!('#') ~
        take_until!("\n") ~
        char!('\n'),
    || { Directive::Nothing }));


named!(directive<&[u8], Directive>, alt!(
    nameserver |
    domain |
    search |
    nothing));

named!(directives<&[u8], Vec<Directive> >, many0!(directive));


named!(config<&[u8], Config>,
    chain!(
        rc: map_res!(directives, parse_directives) ~ eof,
        || { rc }));

fn parse_directives(directives: Vec<Directive>) -> Result<Config, ()> {
    use self::Directive::*;
    let mut cfg = Config::new();
    for dir in directives {
        match dir {
            Nameserver(n) => {
                cfg.nameservers.push(
                    IpAddr::V4(try!(n.parse().map_err(|_| ()))))
            }
            Domain(d) => {
                cfg.search = vec![d.to_string()];
            }
            Search(items) => {
                cfg.search = items
                    .iter().map(|x| x.to_string()).collect();
            }
            Nothing => {}
        }
    }
    Ok(cfg)
}
