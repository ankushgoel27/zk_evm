use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
};

use keccak_hash::H256;
use serde::{Deserialize, Serialize};

/// Each `CodeAddress` can be called one or more times, each time creating a new
/// `Context`. Each `Context` will contain one or more offsets of `JUMPDEST`.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextJumpDests(pub HashMap<usize, BTreeSet<usize>>);

/// The result after proving a `JumpDestTableWitness`.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct JumpDestTableProcessed(pub HashMap<usize, Vec<usize>>);

/// Map `CodeAddress -> (Context -> [JumpDests])`
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub struct JumpDestTableWitness(pub HashMap<H256, ContextJumpDests>);

impl JumpDestTableWitness {
    /// Insert `offset` into `ctx` under the corrresponding `code_hash`.
    /// Creates the required `ctx` keys and `code_hash`. Idempotent.
    pub fn insert(&mut self, code_hash: &H256, ctx: usize, offset: usize) {
        self.0.entry(*code_hash).or_default();

        self.0.get_mut(code_hash).unwrap().0.entry(ctx).or_default();

        self.0
            .get_mut(code_hash)
            .unwrap()
            .0
            .get_mut(&ctx)
            .unwrap()
            .insert(offset);

        assert!(self.0.contains_key(code_hash));
        assert!(self.0[code_hash].0.contains_key(&ctx));
        assert!(self.0[code_hash].0[&ctx].contains(&offset));
    }
}

impl Display for JumpDestTableWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== JumpDest table ===")?;

        for (code, ctxtbls) in &self.0 {
            write!(f, "codehash: {:?}\n{}", code, ctxtbls)?;
        }
        Ok(())
    }
}

impl Display for ContextJumpDests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (ctx, offsets) in &self.0 {
            write!(f, "      ctx: {}, offsets: [", ctx)?;
            for offset in offsets {
                write!(f, "{:#10x} ", offset)?;
            }
            writeln!(f, "]")?;
        }
        Ok(())
    }
}
