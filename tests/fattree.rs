//! The k = 4 fat tree on OxiDD's BDDs: the atoms, reachable pairs and
//! header-space fractions of the netverify harness's Java driver on the same
//! dataset.

// OxiDD's functions hash by their root node, which never changes.
#![allow(clippy::mutable_key_type)]

use std::collections::{HashMap, HashSet};
use std::path::Path;

use oxidd::bdd::BDDFunction;
use oxidd::util::num::F64;
use oxidd::util::SatCountCache;
use oxidd::{BooleanFunction, Manager, ManagerRef};

use apkeep::{Dataset, Engine, HEADER_BITS};

struct Bdd {
    t: BDDFunction,
    f: BDDFunction,
    vars: Vec<BDDFunction>,
}

impl Bdd {
    fn new() -> Bdd {
        let mref = oxidd::bdd::new_manager(1 << 22, 1 << 20, 1);
        mref.with_manager_exclusive(|m| {
            let vars = m.add_vars(HEADER_BITS).map(|i| BDDFunction::var(m, i).unwrap()).collect();
            Bdd { t: BDDFunction::t(m), f: BDDFunction::f(m), vars }
        })
    }

    /// The fraction of the 2^104 headers in `f`.
    fn fraction(&self, f: &BDDFunction) -> f64 {
        let mut cache: SatCountCache<F64, std::hash::RandomState> = SatCountCache::default();
        (f.sat_count(HEADER_BITS, &mut cache).0.log2() - f64::from(HEADER_BITS)).exp2()
    }
}

impl Engine for Bdd {
    type F = BDDFunction;

    fn var(&mut self, i: usize) -> BDDFunction {
        self.vars[i].clone()
    }
    fn constant(&self, value: bool) -> BDDFunction {
        if value { self.t.clone() } else { self.f.clone() }
    }
    fn not(&mut self, f: &BDDFunction) -> BDDFunction {
        f.not().unwrap()
    }
    fn and(&mut self, f: &BDDFunction, g: &BDDFunction) -> BDDFunction {
        f.and(g).unwrap()
    }
    fn or(&mut self, f: &BDDFunction, g: &BDDFunction) -> BDDFunction {
        f.or(g).unwrap()
    }
    fn diff(&mut self, f: &BDDFunction, g: &BDDFunction) -> BDDFunction {
        g.imp_strict(f).unwrap()
    }
}

#[test]
fn fat_tree_4() {
    let data = Dataset::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ft4")).unwrap();
    let mut bdd = Bdd::new();
    let v = apkeep::verify(&mut bdd, &data);

    assert_eq!(v.atoms.atoms.len(), 626);
    assert_eq!(v.pairs, 216);
    let fwd: f64 = v.port_predicate.iter().map(|(_, f)| bdd.fraction(f)).sum();
    let acl: f64 = v.acl_predicate.iter().map(|(_, f)| bdd.fraction(f)).sum();
    assert_eq!(format!("{fwd:.12}"), "16.036471962929");
    assert_eq!(format!("{acl:.12}"), "0.003815886799");

    // The atoms partition the header space.
    let mut union = bdd.f.clone();
    for (i, a) in v.atoms.atoms.iter().enumerate() {
        assert!(a.and(&union).unwrap() == bdd.f, "atom {i} overlaps an earlier one");
        union = union.or(a).unwrap();
    }
    assert!(union == bdd.t);

    // Each predicate is the union of its atoms.
    let distinct: HashSet<_> = v.predicates.iter().collect();
    assert_eq!(distinct.len(), v.predicates.len());
    let sets: HashMap<_, _> = v.atoms.set_of.iter().collect();
    for p in &v.predicates {
        let rebuilt = sets[p].iter().fold(bdd.f.clone(), |acc, i| acc.or(&v.atoms.atoms[i]).unwrap());
        assert!(rebuilt == *p);
    }
}
