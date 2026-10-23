# apkeep

APKeep's atomic predicates and all-pairs reachability in Rust, over any
decision-diagram engine.

A port of the network-verification workload that
[NDD](https://github.com/XJTU-NetVerify/NDD) runs on APKeep (Zhang et al.,
*APKeep: Realtime Verification for Real Networks*, NSDI '20) and Yang and
Lam's Atomic Predicates Verifier:

1. forwarding predicates from the FIBs, longest prefix winning;
2. ACL predicates, first match winning;
3. the atomic predicates of all of them, with APKeep's bookkeeping of which
   atoms make up each predicate;
4. the pairs of edge ports a packet can travel between, walking sets of
   atoms.

The crate has no decision-diagram engine of its own. `Engine` is the handful
of operations the workload performs (`var`, `constant`, `not`, `and`, `or`,
`diff`); implement it for BDDs, NDDs or anything canonical, and every engine
runs the same operations in the same order on the same data, so their times
and sizes compare directly.

```rust
use apkeep::{Dataset, Engine};

fn run<E: Engine>(engine: &mut E) {
    let data = Dataset::load("tests/data/ft4".as_ref()).unwrap();
    let v = apkeep::verify(engine, &data);
    println!("{} atoms, {} reachable pairs in {:?}", v.atoms.atoms.len(), v.pairs, v.timings.total());
}
```

The variables are NDD's 104-bit five-tuple, `srcip(32) dstip(32) srcport(16)
dstport(16) proto(8)`, bit 0 of each field its most significant. A dataset is
a directory of `topo.txt`, `fib.txt`, `edgeports.txt`, `acl.txt` and
`aclmap.txt`; `Dataset` documents the formats, and
[`tests/data/ft4`](tests/data/ft4) is a k = 4 fat tree. `cargo test` runs it
on OxiDD's BDDs and checks the atoms, pairs and header-space fractions against
the Java implementation.

```toml
[dependencies]
apkeep = { git = "https://github.com/endaytrer/apkeep" }
```

## License

The Atomic Predicates Verifier's MIT-style license; see [LICENSE](LICENSE).
Its fourth condition asks that any report or paper describing results derived
from this software cite Hongkun Yang and Simon S. Lam, *Real-time Verification
of Network Properties using Atomic Predicates*, IEEE/ACM Transactions on
Networking 24(2), 2016.
