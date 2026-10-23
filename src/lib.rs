// apkeep: a Rust port of APKeep and the Atomic Predicates Verifier, modified
// from the originals. See LICENSE.

//! APKeep's atomic predicates and all-pairs reachability, over any
//! decision-diagram engine.
//!
//! A port of the network-verification workload that NDD
//! (<https://github.com/XJTU-NetVerify/NDD>) runs on APKeep (Zhang et al.,
//! NSDI '20) and Yang and Lam's Atomic Predicates Verifier: forwarding
//! predicates under longest-prefix match, ACL predicates under first match,
//! the atomic predicates of them all, and the pairs of edge ports a packet
//! can travel between.
//!
//! The crate has no decision-diagram engine of its own: [`Engine`] is the
//! handful of operations the workload performs, and every engine runs the same
//! operations in the same order on the same [`Dataset`], so their times and
//! sizes compare directly.
//!
//! The variables are NDD's 104-bit five-tuple, `srcip(32) dstip(32)
//! srcport(16) dstport(16) proto(8)` ([`WIDTH`]), bit 0 of each field its
//! most significant: engine variable `i` is bit `i` of the concatenation.
//!
//! ```no_run
//! # fn run<E: apkeep::Engine>(engine: &mut E) {
//! let data = apkeep::Dataset::load("data/ft4".as_ref()).unwrap();
//! let v = apkeep::verify(engine, &data);
//! println!("{} atoms, {} reachable pairs", v.atoms.atoms.len(), v.pairs);
//! # }
//! ```

mod dataset;
pub mod encode;
mod verify;

use std::hash::Hash;

pub use dataset::{Dataset, FibEntry, Port, Rule};
pub use verify::{atomic_predicates, forwarding, reachability, verify, Atoms, Bits, Timings, Verification};

/// The widths of the five-tuple's fields, in variable order.
pub const WIDTH: [u32; 5] = [32, 32, 16, 16, 8];
/// The number of variables, the five-tuple's bits.
pub const HEADER_BITS: u32 = 104;

pub const SRC_IP: usize = 0;
pub const DST_IP: usize = 1;
pub const SRC_PORT: usize = 2;
pub const DST_PORT: usize = 3;
pub const PROTOCOL: usize = 4;

/// A Boolean-function engine over the [`HEADER_BITS`] variables, variable 0
/// the topmost.
pub trait Engine {
    /// A handle, canonical: equal exactly when the functions are.
    type F: Clone + Eq + Hash;

    fn var(&mut self, i: usize) -> Self::F;
    fn constant(&self, value: bool) -> Self::F;
    fn not(&mut self, f: &Self::F) -> Self::F;
    fn and(&mut self, f: &Self::F, g: &Self::F) -> Self::F;
    fn or(&mut self, f: &Self::F, g: &Self::F) -> Self::F;
    /// `f ∧ ¬g`.
    fn diff(&mut self, f: &Self::F, g: &Self::F) -> Self::F;
}
