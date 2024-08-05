//! This module defines the various proof types used throughout the block proof
//! generation process.

use evm_arithmetization::{
    proof::{HashOrPV, PublicValues},
    BlockHeight,
};
use plonky2::hash::poseidon::PoseidonHash;
use serde::{Deserialize, Serialize};

use crate::types::{Field, PlonkyProofIntern};

/// A transaction proof along with its public values, for proper connection with
/// contiguous proofs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedTxnProof {
    /// Public values of this transaction proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
}

/// An aggregation proof along with its public values, for proper connection
/// with contiguous proofs.
///
/// Aggregation proofs can represent any contiguous range of two or more
/// transactions, up to an entire block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggProof {
    /// Public values of this aggregation proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
}

/// A block proof along with the block height against which this proof ensures
/// the validity since the last proof checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBlockProof {
    /// Associated block height.
    pub b_height: BlockHeight,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
}

/// An aggregation block proof along with its public values, for proper
/// verification by a third-party.
///
/// Aggregation block proofs can represent any aggregation of independent
/// blocks.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggBlockProof {
    /// Public values of this aggregation proof.
    pub p_vals: HashOrPV<Field, PoseidonHash>,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AggregatableProof {
    /// The underlying proof is a transaction proof.
    Txn(GeneratedTxnProof),
    /// The underlying proof is an aggregation proof.
    Agg(GeneratedAggProof),
}

impl AggregatableProof {
    pub fn public_values(&self) -> PublicValues {
        match self {
            AggregatableProof::Txn(info) => info.p_vals.clone(),
            AggregatableProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            AggregatableProof::Txn(_) => false,
            AggregatableProof::Agg(_) => true,
        }
    }

    pub(crate) const fn intern(&self) -> &PlonkyProofIntern {
        match self {
            AggregatableProof::Txn(info) => &info.intern,
            AggregatableProof::Agg(info) => &info.intern,
        }
    }
}

impl From<GeneratedTxnProof> for AggregatableProof {
    fn from(v: GeneratedTxnProof) -> Self {
        Self::Txn(v)
    }
}

impl From<GeneratedAggProof> for AggregatableProof {
    fn from(v: GeneratedAggProof) -> Self {
        Self::Agg(v)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AggregatableBlockProof {
    /// The underlying proof is a single block proof.
    Block(GeneratedBlockProof),
    /// The underlying proof is an aggregated proof.
    Agg(GeneratedAggBlockProof),
}

impl AggregatableBlockProof {
    pub fn public_values(&self) -> HashOrPV<Field, PoseidonHash> {
        match self {
            AggregatableBlockProof::Block(info) => {
                HashOrPV::Val(PublicValues::from_public_inputs(&info.intern.public_inputs))
            }
            AggregatableBlockProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            AggregatableBlockProof::Block(_) => false,
            AggregatableBlockProof::Agg(_) => true,
        }
    }

    pub(crate) const fn intern(&self) -> &PlonkyProofIntern {
        match self {
            AggregatableBlockProof::Block(info) => &info.intern,
            AggregatableBlockProof::Agg(info) => &info.intern,
        }
    }
}

impl From<GeneratedBlockProof> for AggregatableBlockProof {
    fn from(v: GeneratedBlockProof) -> Self {
        Self::Block(v)
    }
}

impl From<GeneratedAggBlockProof> for AggregatableBlockProof {
    fn from(v: GeneratedAggBlockProof) -> Self {
        Self::Agg(v)
    }
}
