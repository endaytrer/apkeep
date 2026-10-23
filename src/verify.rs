// apkeep: a Rust port of APKeep and the Atomic Predicates Verifier, modified
// from the originals. See LICENSE.

//! The kernels: forwarding, ACLs, atomic predicates and reachability.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::encode::{permit_set, prefix};
use crate::{Dataset, Engine, FibEntry, Port, DST_IP};

/// A growable bit set: the atoms a predicate is made of.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bits(Vec<u64>);

impl Bits {
    /// `0..n`.
    pub fn full(n: usize) -> Bits {
        let mut b = Bits(vec![u64::MAX; n / 64]);
        if !n.is_multiple_of(64) {
            b.0.push((1 << (n % 64)) - 1);
        }
        b
    }
    pub fn get(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|w| w >> (i % 64) & 1 == 1)
    }
    pub fn set(&mut self, i: usize) {
        if self.0.len() <= i / 64 {
            self.0.resize(i / 64 + 1, 0);
        }
        self.0[i / 64] |= 1 << (i % 64);
    }
    /// Keep only `other`'s bits.
    pub fn and(&mut self, other: &Bits) {
        self.0.truncate(other.0.len());
        for (w, o) in self.0.iter_mut().zip(&other.0) {
            *w &= o;
        }
    }
    /// Add `other`'s bits; whether any was new.
    pub fn or(&mut self, other: &Bits) -> bool {
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), 0);
        }
        let mut grew = false;
        for (w, o) in self.0.iter_mut().zip(&other.0) {
            grew |= o & !*w != 0;
            *w |= o;
        }
        grew
    }
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }
    pub fn len(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.0.len() * 64).filter(|&i| self.get(i))
    }
}

/// The atomic predicates, and the atoms making up each input predicate.
#[derive(Clone, Debug)]
pub struct Atoms<F> {
    pub atoms: Vec<F>,
    pub set_of: HashMap<F, Bits>,
}

/// Each device's ports' forwarding predicates, under longest-prefix match as
/// `BDDACLWrapper.getfwdbdds` computes them: each device's entries from the
/// longest prefix down, each claiming only what no longer prefix claimed.
/// Ports that forward nothing are left out.
pub fn forwarding<E: Engine>(e: &mut E, data: &Dataset) -> Vec<(Port, E::F)> {
    let mut by_device: Vec<(u32, Vec<&FibEntry>)> = Vec::new();
    let mut index: HashMap<u32, usize> = HashMap::new();
    for entry in &data.fib {
        let i = *index.entry(entry.0).or_insert_with(|| {
            by_device.push((entry.0, Vec::new()));
            by_device.len() - 1
        });
        by_device[i].1.push(entry);
    }
    let mut out = Vec::new();
    for (device, mut entries) in by_device {
        // Stable, as Java's sort.
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.3));
        let mut claimed = e.constant(false);
        let mut acc: Vec<(Port, E::F)> = Vec::new();
        for &&(_, port, ip, len) in &entries {
            let hit = prefix(e, DST_IP, ip, len);
            let fresh = e.diff(&hit, &claimed);
            if fresh != e.constant(false) {
                match acc.iter_mut().find(|(p, _)| *p == (device, port)) {
                    Some((_, old)) => *old = e.or(old, &fresh),
                    None => acc.push(((device, port), fresh)),
                }
            }
            claimed = e.or(&claimed, &hit);
        }
        out.extend(acc);
    }
    out
}

/// Yang and Lam's atomic predicates, with APKeep's bookkeeping: when an atom
/// splits, both halves join every predicate's set the atom was in.
pub fn atomic_predicates<E: Engine>(e: &mut E, predicates: &[E::F]) -> Atoms<E::F> {
    let (tru, fls) = (e.constant(true), e.constant(false));
    let mut atoms = vec![tru.clone()];
    let mut sets: Vec<(E::F, Bits)> = Vec::new();
    for p in predicates {
        let mut mine = Bits::default();
        if *p == tru {
            mine = Bits::full(atoms.len());
            sets.push((p.clone(), mine));
            continue;
        }
        if *p == fls {
            sets.push((p.clone(), mine));
            continue;
        }
        // The atoms appended below lie outside `p`.
        let n = atoms.len();
        for i in 0..n {
            let a = atoms[i].clone();
            let inside = e.and(&a, p);
            if inside == a {
                mine.set(i);
                continue;
            }
            if inside == fls {
                continue;
            }
            let outside = e.diff(&a, p);
            atoms[i] = inside;
            let j = atoms.len();
            atoms.push(outside);
            mine.set(i);
            for (_, s) in &mut sets {
                if s.get(i) {
                    s.set(j);
                }
            }
        }
        sets.push((p.clone(), mine));
    }
    Atoms { atoms, set_of: sets.into_iter().collect() }
}

/// The pairs of edge ports a packet can travel between, walking sets of
/// atoms: no decision-diagram operation at all. A packet enters at an edge
/// port through its ACL, if any, and leaves through every port whose
/// forwarding predicate it is in.
pub fn reachability<F: Eq + std::hash::Hash>(
    data: &Dataset,
    port_predicate: &[(Port, F)],
    acl_predicate: &[(String, F)],
    ap: &Atoms<F>,
) -> usize {
    let n = ap.atoms.len();
    let set = |f: &F| ap.set_of.get(f).cloned().unwrap_or_default();
    let port_atoms: HashMap<Port, Bits> = port_predicate.iter().map(|(p, f)| (*p, set(f))).collect();
    let acl_atoms: HashMap<&str, Bits> = acl_predicate.iter().map(|(a, f)| (a.as_str(), set(f))).collect();
    let mut peer: HashMap<Port, Port> = HashMap::new();
    for &(a, b) in &data.links {
        peer.insert(a, b);
        peer.insert(b, a);
    }
    let mut device_ports: HashMap<u32, Vec<Port>> = HashMap::new();
    for (p, _) in port_predicate {
        device_ports.entry(p.0).or_default().push(*p);
    }

    let mut pairs = 0;
    for &src in &data.edge_ports {
        let mut start = Bits::full(n);
        if let Some(acl) = data.acl_map.get(&src).and_then(|a| acl_atoms.get(a.as_str())) {
            start.and(acl);
        }
        if start.is_empty() {
            continue;
        }
        let mut seen: HashMap<u32, Bits> = HashMap::from([(src.0, start)]);
        let mut queue = VecDeque::from([src.0]);
        let mut reached: HashSet<Port> = HashSet::new();
        while let Some(dev) = queue.pop_front() {
            let here = seen[&dev].clone();
            for out in device_ports.get(&dev).map_or(&[][..], Vec::as_slice) {
                let mut carried = here.clone();
                carried.and(port_atoms.get(out).unwrap_or(&Bits::default()));
                if carried.is_empty() {
                    continue;
                }
                let Some(next) = peer.get(out) else {
                    // A host-facing port: the packet arrives.
                    if *out != src {
                        reached.insert(*out);
                    }
                    continue;
                };
                match seen.get_mut(&next.0) {
                    None => {
                        seen.insert(next.0, carried);
                        queue.push_back(next.0);
                    }
                    Some(known) => {
                        if known.or(&carried) {
                            queue.push_back(next.0);
                        }
                    }
                }
            }
        }
        pairs += reached.len();
    }
    pairs
}

/// The time each phase of [`verify`] took.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    pub forwarding: Duration,
    pub acl: Duration,
    pub atomic_predicates: Duration,
    pub reachability: Duration,
}

impl Timings {
    pub fn total(&self) -> Duration {
        self.forwarding + self.acl + self.atomic_predicates + self.reachability
    }
}

/// What [`verify`] computed.
#[derive(Clone, Debug)]
pub struct Verification<F> {
    /// Each port's forwarding predicate.
    pub port_predicate: Vec<(Port, F)>,
    /// Each ACL's permitted set, in the dataset's order.
    pub acl_predicate: Vec<(String, F)>,
    /// The distinct predicates of both, in order: the atomic predicates'
    /// input.
    pub predicates: Vec<F>,
    pub atoms: Atoms<F>,
    /// Reachable pairs of edge ports.
    pub pairs: usize,
    pub timings: Timings,
}

/// The whole workload: the forwarding and ACL predicates, their atomic
/// predicates, and reachability.
pub fn verify<E: Engine>(e: &mut E, data: &Dataset) -> Verification<E::F> {
    let t0 = Instant::now();
    let port_predicate = forwarding(e, data);
    let t1 = Instant::now();
    let acl_predicate: Vec<(String, E::F)> =
        data.acls.iter().map(|(name, rules)| (name.clone(), permit_set(e, rules))).collect();
    let t2 = Instant::now();

    let mut predicates = Vec::new();
    let mut seen = HashSet::new();
    for f in port_predicate.iter().map(|(_, f)| f).chain(acl_predicate.iter().map(|(_, f)| f)) {
        if seen.insert(f.clone()) {
            predicates.push(f.clone());
        }
    }
    let atoms = atomic_predicates(e, &predicates);
    let t3 = Instant::now();
    let pairs = reachability(data, &port_predicate, &acl_predicate, &atoms);
    let t4 = Instant::now();

    let timings = Timings { forwarding: t1 - t0, acl: t2 - t1, atomic_predicates: t3 - t2, reachability: t4 - t3 };
    Verification { port_predicate, acl_predicate, predicates, atoms, pairs, timings }
}
