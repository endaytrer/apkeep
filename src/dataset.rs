// apkeep: a Rust port of APKeep and the Atomic Predicates Verifier, modified
// from the originals. See LICENSE.

//! The data plane: topology, FIBs, edge ports and ACLs, in NDD's text formats.

use std::collections::HashMap;
use std::io;
use std::path::Path;

/// A device and one of its ports; devices are numbered as they first appear.
pub type Port = (u32, u32);

/// A FIB entry: device, port, prefix, prefix length.
pub type FibEntry = (u32, u32, u64, u32);

/// One five-tuple rule, a field a wildcard when its prefix length is 0 or its
/// range `(-1, -1)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub permit: bool,
    /// Address and prefix length.
    pub src: (u64, u32),
    pub dst: (u64, u32),
    /// Inclusive ranges.
    pub src_port: (i64, i64),
    pub dst_port: (i64, i64),
    pub proto: (i64, i64),
}

/// A data plane, loaded from a directory of five files:
///
/// - `topo.txt`: `device port device port`, one link per line;
/// - `fib.txt`: `device port a.b.c.d/len`, longest prefix winning;
/// - `edgeports.txt`: `device port`, the host-facing ports;
/// - `acl.txt`: `name permit|deny src dst srcport dstport proto`, each ACL's
///   rules in order, first match winning, `any` a wildcard;
/// - `aclmap.txt`: `device port name`, the ACL filtering what enters a port.
///
/// Empty lines and lines starting with `#` are skipped.
#[derive(Clone, Debug)]
pub struct Dataset {
    pub links: Vec<(Port, Port)>,
    pub fib: Vec<FibEntry>,
    pub edge_ports: Vec<Port>,
    /// The ACLs by name, in the order they first appear.
    pub acls: Vec<(String, Vec<Rule>)>,
    pub acl_map: HashMap<Port, String>,
}

/// `"any"` or `"a.b.c.d/len"`.
fn cidr(s: &str) -> (u64, u32) {
    if s.eq_ignore_ascii_case("any") {
        return (0, 0);
    }
    let (addr, len) = s.split_once('/').map_or((s, 32), |(a, l)| (a, l.parse().expect("a prefix length")));
    let ip = addr.split('.').fold(0u64, |v, o| (v << 8) | (o.parse::<u64>().expect("an octet") & 0xff));
    (ip & 0xffff_ffff, len)
}

/// `"any"`, `"lo-hi"` or a single value.
fn range(s: &str) -> (i64, i64) {
    if s.eq_ignore_ascii_case("any") {
        return (-1, -1);
    }
    // A leading sign is no separator.
    match s[1..].find('-') {
        Some(dash) => (s[..dash + 1].parse().expect("a bound"), s[dash + 2..].parse().expect("a bound")),
        None => {
            let v = s.parse().expect("a value");
            (v, v)
        }
    }
}

impl Rule {
    /// `permit|deny src dst srcport dstport proto`.
    pub fn parse(line: &str) -> Rule {
        let t: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(t.len(), 6, "a rule has 6 fields: {line}");
        Rule {
            permit: t[0].eq_ignore_ascii_case("permit"),
            src: cidr(t[1]),
            dst: cidr(t[2]),
            src_port: range(t[3]),
            dst_port: range(t[4]),
            proto: range(t[5]),
        }
    }
}

impl Dataset {
    /// Load the five files of `dir`. Malformed lines panic.
    pub fn load(dir: &Path) -> io::Result<Dataset> {
        let lines = |name: &str| -> io::Result<Vec<String>> {
            let text = std::fs::read_to_string(dir.join(name))
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", dir.join(name).display())))?;
            Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect())
        };
        let mut devices: HashMap<String, u32> = HashMap::new();
        let mut device = |name: &str| {
            let next = devices.len() as u32;
            *devices.entry(name.to_string()).or_insert(next)
        };
        let number = |s: &str| s.parse::<u32>().expect("a port");

        let links = lines("topo.txt")?
            .iter()
            .map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                ((device(t[0]), number(t[1])), (device(t[2]), number(t[3])))
            })
            .collect();
        let fib = lines("fib.txt")?
            .iter()
            .map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                let (ip, len) = cidr(t[2]);
                (device(t[0]), number(t[1]), ip, len)
            })
            .collect();
        let edge_ports = lines("edgeports.txt")?
            .iter()
            .map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                (device(t[0]), number(t[1]))
            })
            .collect();
        let mut acls: Vec<(String, Vec<Rule>)> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        for l in lines("acl.txt")? {
            let (name, rule) = l.split_once(' ').expect("an ACL name and a rule");
            let i = *index.entry(name.to_string()).or_insert_with(|| {
                acls.push((name.to_string(), Vec::new()));
                acls.len() - 1
            });
            acls[i].1.push(Rule::parse(rule));
        }
        let acl_map = lines("aclmap.txt")?
            .iter()
            .map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                ((device(t[0]), number(t[1])), t[2].to_string())
            })
            .collect();
        Ok(Dataset { links, fib, edge_ports, acls, acl_map })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rules() {
        let r = Rule::parse("deny 10.0.1.0/24 any 80 1024-65535 any");
        assert!(!r.permit);
        assert_eq!(r.src, (0x0a00_0100, 24));
        assert_eq!(r.dst, (0, 0));
        assert_eq!(r.src_port, (80, 80));
        assert_eq!(r.dst_port, (1024, 65535));
        assert_eq!(r.proto, (-1, -1));
    }
}
