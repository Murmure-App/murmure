//! "Have I had this one already?" for numbers that mostly arrive in order.
//!
//! Used for the ids of a contact's `/tell`s and for the line numbers of a
//! room member. Both are redelivered or relayed, so the same number can come
//! twice, and both can arrive out of order: a redelivery after a link dropped,
//! a room line that came round by the relay after its successor came direct.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// How many numbers are kept above a gap.
///
/// A gap can be one that never fills: a contact's outbox numbers every message
/// it sends, to anyone, so the ids we get skip the ones that went to somebody
/// else. Without a bound those gaps would keep every id after them for ever.
/// ponytail: past the bound the oldest gap is given up for lost, so a message
/// that arrives more than 256 messages late is taken for a repeat and dropped.
/// Numbering per recipient would remove the gaps; that changes what is stored.
const WINDOW: usize = 256;

/// Every number below `floor` has been seen, plus the ones in `above`.
///
/// Field order is the on-disk format: a contact stored these two as adjacent
/// fields before this type existed, and postcard writes a struct as its
/// fields in order, so the sealed book reads back unchanged.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub floor: u64,
    pub above: BTreeSet<u64>,
}

impl Seen {
    /// Nothing seen yet, and nothing below `floor` will be taken.
    pub fn starting_at(floor: u64) -> Self {
        Seen {
            floor,
            above: BTreeSet::new(),
        }
    }

    /// Seen already, or below the floor.
    pub fn has(&self, n: u64) -> bool {
        n < self.floor || self.above.contains(&n)
    }

    /// Record `n`. False if [`Self::has`] it already.
    pub fn accept(&mut self, n: u64) -> bool {
        if self.has(n) {
            return false;
        }
        self.above.insert(n);
        self.settle();
        while self.above.len() > WINDOW {
            let oldest = self.above.pop_first().expect("over the window, so not empty");
            self.floor = oldest + 1;
            self.settle();
        }
        true
    }

    /// Fold into the floor whatever now follows it without a gap.
    fn settle(&mut self) {
        while self.above.remove(&self.floor) {
            self.floor += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_out_of_order_and_repeated() {
        let mut seen = Seen::default();
        assert!(seen.accept(0));
        assert!(seen.accept(2), "a gap is not a repeat");
        assert!(seen.accept(1), "the late one still counts");
        assert!(!seen.accept(1));
        assert!(!seen.accept(2));
        assert_eq!(seen.floor, 3);
        assert!(seen.above.is_empty());
    }

    /// Ids that went to someone else never come: the window stays bounded,
    /// and nothing already taken is taken twice.
    #[test]
    fn gaps_that_never_fill_do_not_grow_it() {
        let mut seen = Seen::default();
        for n in (0..3000).step_by(3) {
            assert!(seen.accept(n));
        }
        assert!(seen.above.len() <= WINDOW, "{}", seen.above.len());
        for n in (0..3000).step_by(3) {
            assert!(!seen.accept(n), "{n} came back as new");
        }
    }

    #[test]
    fn nothing_below_the_start() {
        let mut seen = Seen::starting_at(57);
        assert!(!seen.accept(56));
        assert!(seen.accept(59));
        assert!(seen.accept(57));
        assert!(!seen.accept(59));
    }

    /// The book stored `seen_floor: u64` then `seen_above: BTreeSet<u64>`.
    #[test]
    fn reads_the_two_fields_it_replaced() {
        let old = postcard::to_stdvec(&(7u64, BTreeSet::from([9u64, 12]))).unwrap();
        let seen: Seen = postcard::from_bytes(&old).unwrap();
        assert_eq!(seen, Seen { floor: 7, above: BTreeSet::from([9, 12]) });
    }
}
