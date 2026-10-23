// apkeep: a Rust port of APKeep and the Atomic Predicates Verifier, modified
// from the originals. See LICENSE.

//! Rules to predicates: prefixes, ranges, rules and ordered ACLs.

use crate::{Engine, Rule, DST_IP, DST_PORT, PROTOCOL, SRC_IP, SRC_PORT, WIDTH};

/// The engine's variable for bit `bit` (0 the MSB) of `field`.
pub fn var<E: Engine>(e: &mut E, field: usize, bit: u32) -> E::F {
    let base: u32 = WIDTH[..field].iter().sum();
    e.var((base + bit) as usize)
}

/// The top `len` bits of `field` equal to those of `value`; 0 is the wildcard.
pub fn prefix<E: Engine>(e: &mut E, field: usize, value: u64, len: u32) -> E::F {
    let width = WIDTH[field];
    assert!(len <= width, "a prefix longer than its field");
    let mut acc = e.constant(true);
    for bit in 0..len {
        let one = (value >> (width - 1 - bit)) & 1 != 0;
        let lit = var(e, field, bit);
        let term = if one { lit } else { e.not(&lit) };
        acc = e.and(&acc, &term);
    }
    acc
}

/// `[lo, hi]` within `width` bits as the fewest aligned blocks, each
/// `(base, prefix length)`.
pub fn cover(mut lo: i64, hi: i64, width: u32) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    while lo <= hi {
        let mut size = if lo == 0 { width } else { lo.trailing_zeros().min(width) };
        while size > 0 && lo + (1 << size) - 1 > hi {
            size -= 1;
        }
        out.push((lo as u64, width - size));
        let next = lo + (1 << size);
        if next <= lo {
            break;
        }
        lo = next;
    }
    out
}

/// `lo <= field <= hi`, the disjunction of its prefix cover; a negative bound
/// is the wildcard.
pub fn field_range<E: Engine>(e: &mut E, field: usize, (lo, hi): (i64, i64)) -> E::F {
    let width = WIDTH[field];
    let max = (1i64 << width) - 1;
    if lo < 0 || hi < 0 || (lo <= 0 && hi >= max) {
        return e.constant(true);
    }
    if lo > hi {
        return e.constant(false);
    }
    let mut acc = e.constant(false);
    for (base, len) in cover(lo, hi, width) {
        let p = prefix(e, field, base, len);
        acc = e.or(&acc, &p);
    }
    acc
}

/// The packets a rule matches.
pub fn matches<E: Engine>(e: &mut E, r: &Rule) -> E::F {
    let mut acc = e.constant(true);
    let p = prefix(e, SRC_IP, r.src.0, r.src.1);
    acc = e.and(&acc, &p);
    let p = prefix(e, DST_IP, r.dst.0, r.dst.1);
    acc = e.and(&acc, &p);
    let p = field_range(e, SRC_PORT, r.src_port);
    acc = e.and(&acc, &p);
    let p = field_range(e, DST_PORT, r.dst_port);
    acc = e.and(&acc, &p);
    let p = field_range(e, PROTOCOL, r.proto);
    e.and(&acc, &p)
}

/// The packets an ordered ACL permits, the first match winning.
pub fn permit_set<E: Engine>(e: &mut E, rules: &[Rule]) -> E::F {
    let mut permit = e.constant(false);
    let mut matched = e.constant(false);
    for r in rules {
        let m = matches(e, r);
        let fresh = e.diff(&m, &matched);
        if r.permit {
            permit = e.or(&permit, &fresh);
        }
        matched = e.or(&matched, &m);
    }
    permit
}

#[cfg(test)]
mod tests {
    use super::cover;

    /// Every range of 6-bit values: the blocks are aligned, disjoint, in
    /// order, cover exactly the range, and no two could merge.
    #[test]
    fn covers() {
        for lo in 0..64 {
            for hi in lo..64 {
                let blocks = cover(lo, hi, 6);
                let mut next = lo as u64;
                for &(base, len) in &blocks {
                    let size = 1u64 << (6 - len);
                    assert_eq!(base, next);
                    assert_eq!(base % size, 0, "aligned");
                    next = base + size;
                }
                assert_eq!(next, hi as u64 + 1);
                for w in blocks.windows(2) {
                    let ((a, la), (_, lb)) = (w[0], w[1]);
                    assert!(!(la == lb && a % (2u64 << (6 - la)) == 0), "mergeable blocks in {lo}-{hi}");
                }
            }
        }
    }
}
