use std::fs::File;
use std::io::Read;

extern crate resolv_conf;

fn main() {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let cfg = resolv_conf::Config::parse(&buf).unwrap();
    println!("---- Config -----\n{cfg:#?}\n");
}
