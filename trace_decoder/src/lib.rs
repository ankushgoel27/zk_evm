//! <div class="warning">
//! This library is undergoing major refactoring as part of (#275)(https://github.com/0xPolygonZero/zk_evm/issues/275).
//! Consider all TODOs to be tracked under that issue.
//! </div>
//!
//! Your neighborhood zk-ready [ethereum](https://github.com/0xPolygonZero/erigon)
//! [node](https://github.com/0xPolygonHermez/cdk-erigon/) emits binary "witnesses"[^1].
//!
//! But [`plonky2`], your prover, wants [`GenerationInputs`].
//!
//! This library helps you get there.
//!
//! [^1]: A witness is an attestation of the state of the world, which can be
//!       proven by a prover.
//!
//! # Non-Goals
//! - Performance - this won't be the bottleneck in any proving system.
//! - Robustness - malicious or malformed input may crash this library.
//!
//! TODO(0xaatif): refactor all the docs below
//!
//! It might not be obvious why we need traces for each txn in order to generate
//! proofs. While it's true that we could just run all the txns of a block in an
//! EVM to generate the traces ourselves, there are a few major downsides:
//! - The client is likely a full node and already has to run the txns in an EVM
//!   anyways.
//! - We want this protocol to be as agnostic as possible to the underlying
//!   chain that we're generating proofs for, and running our own EVM would
//!   likely cause us to loose this genericness.
//!
//! While it's also true that we run our own zk-EVM (plonky2) to generate
//! proofs, it's critical that we are able to generate txn proofs in parallel.
//! Since generating proofs with plonky2 is very slow, this would force us to
//! sequentialize the entire proof generation process. So in the end, it's ideal
//! if we can get this information sent to us instead.
//!
//! This library generates an Intermediary Representation (IR) of
//! a block's transactions, given a [BlockTrace] and some additional
//! data represented by [OtherBlockData].
//!
//! It first preprocesses the [BlockTrace] to provide transaction,
//! withdrawals and tries data that can be directly used to generate an IR.
//! For each transaction, this library extracts the
//! necessary data from the processed transaction information to
//! return the IR.
//!
//! The IR is used to generate root proofs, then aggregation proofs and finally
//! block proofs. Because aggregation proofs require at least two entries, we
//! pad the vector of IRs thanks to additional dummy payload intermediary
//! representations whenever necessary.
//!
//! ### [Withdrawals](https://ethereum.org/staking/withdrawals) and Padding
//!
//! Withdrawals are all proven together in a dummy payload. A dummy payload
//! corresponds to the IR of a proof with no transaction. They must, however, be
//! proven last. The padding is therefore carried out as follows: If there are
//! no transactions in the block, we add two dummy transactions. The withdrawals
//! -- if any -- are added to the second dummy transaction. If there is only one
//! transaction in the block, we add one dummy transaction. If
//! there are withdrawals, the dummy transaction is at the end. Otherwise, it is
//! added at the start. If there are two or more transactions:
//! - if there are no withdrawals, no dummy transactions are added
//! - if there are withdrawals, one dummy transaction is added at the end, with
//!   all the withdrawals in it.

#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

/// The broad overview is as follows:
///
/// 1. Ethereum nodes emit a bunch of binary [`wire::Instruction`]s, which are
///    parsed in [`wire`].
/// 2. They are passed to one of two "frontends", depending on the node
///    - [`type2`], which contains an [`smt_trie`].
///    - [`type1`], which contains an [`mpt_trie`].
/// 3. The frontend ([`type1::Frontend`] or [`type2::Frontend`]) is passed to
///    the "backend", which lowers to [`evm_arithmetization::GenerationInputs`].
///
/// Deviations from the specification are signalled with `BUG(spec)` in the
/// code.
const _DEVELOPER_DOCS: () = ();

/// Defines the main functions used to generate the IR.
mod decoding;
// TODO(0xaatif): add backend/prod support
/// Defines functions that processes a [BlockTrace] so that it is easier to turn
/// the block transactions into IRs.
mod processed_block_trace;
mod shim;
mod type1;
#[cfg(test)]
#[allow(dead_code)]
mod type2;
mod wire;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::ensure;
use either::Either;
use ethereum_types::{Address, U256};
use evm_arithmetization::generation::mpt::transaction_testing::LegacyTransactionRlp;
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::TrieInputs;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::GenerationInputs;
use itertools::Itertools;
use keccak_hash::keccak as hash;
use keccak_hash::H256;
use mpt_trie::partial_trie::HashedPartialTrie;
use serde::{Deserialize, Serialize};
use shim::{TriePath, TypedMpt};

/// Core payload needed to generate proof for a block.
/// Additional data retrievable from the blockchain node (using standard ETH RPC
/// API) may be needed for proof generation.
///
/// The trie preimages are the hashed partial tries at the
/// start of the block. A [TxnInfo] contains all the transaction data
/// necessary to generate an IR.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockTrace {
    /// The state and storage trie pre-images (i.e. the tries before
    /// the execution of the current block) in multiple possible formats.
    pub trie_pre_images: BlockTraceTriePreImages,

    /// The code_db is a map of code hashes to the actual code. This is needed
    /// to execute transactions.
    pub code_db: Option<HashMap<H256, Vec<u8>>>,

    /// Traces and other info per transaction. The index of the transaction
    /// within the block corresponds to the slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTraceTriePreImages {
    /// The trie pre-image with separate state/storage tries.
    Separate(SeparateTriePreImages),
    /// The trie pre-image with combined state/storage tries.
    Combined(CombinedPreImages),
}

/// State/Storage trie pre-images that are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SeparateTriePreImages {
    /// State trie.
    pub state: SeparateTriePreImage,
    /// Storage trie.
    pub storage: SeparateStorageTriesPreImage,
}

/// A trie pre-image where state & storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateTriePreImage {
    /// Storage or state trie format that can be processed as is, as it
    /// corresponds to the internal format.
    Direct(HashedPartialTrie),
}

/// A trie pre-image where both state & storage are combined into one payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CombinedPreImages {
    /// Compact combined state and storage tries.
    #[serde(with = "crate::hex")]
    pub compact: Vec<u8>,
}

/// A trie pre-image where state and storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStorageTriesPreImage {
    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<H256, SeparateTriePreImage>),
}

/// Info specific to txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnInfo {
    /// Trace data for the txn. This is used by the protocol to:
    /// - Mutate it's own trie state between txns to arrive at the correct trie
    ///   state for the start of each txn.
    /// - Create minimal partial tries needed for proof gen based on what state
    ///   the txn accesses. (eg. What trie nodes are accessed).
    pub traces: HashMap<Address, TxnTrace>,

    /// Data that is specific to the txn as a whole.
    pub meta: TxnMeta,
}

/// Structure holding metadata for one transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnMeta {
    /// Txn byte code.
    #[serde(with = "crate::hex")]
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new txn value inserted into the txn trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde(with = "crate::hex")]
    pub new_txn_trie_node_byte: Vec<u8>,

    /// Rlped bytes of the new receipt value inserted into the receipt trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde(with = "crate::hex")]
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnTrace {
    /// If the balance changed, then the new balance will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    /// Account addresses that were only read by the txn.
    ///
    /// Note that if storage is written to, then it does not need to appear in
    /// this list (but is also fine if it does).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_read: Option<Vec<H256>>,

    /// Account storage locations that were mutated by the txn along with their
    /// new value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_written: Option<HashMap<H256, U256>>,

    /// Contract code that this account has accessed or created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_usage: Option<ContractCodeUsage>,

    /// True if the account existed before this txn but self-destructed at the
    /// end of this txn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_destructed: Option<bool>,
}

/// Contract code access type. Used by txn traces.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(H256),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(#[serde(with = "crate::hex")] Vec<u8>),
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    /// Data that is specific to the block.
    pub b_data: BlockLevelData,
    /// State trie root hash at the checkpoint.
    pub checkpoint_state_trie_root: H256,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    /// All block data excluding block hashes and withdrawals.
    pub b_meta: BlockMetadata,
    /// Block hashes: the previous 256 block hashes and the current block hash.
    pub b_hashes: BlockHashes,
    /// Block withdrawal addresses and values.
    pub withdrawals: Vec<(Address, U256)>,
}

/// TODO(0xaatif): <https://github.com/0xPolygonZero/zk_evm/issues/275>
///                document this once we have the API finalized
pub fn entrypoint(
    trace: BlockTrace,
    other: OtherBlockData,
    _resolve: impl Fn(H256) -> Vec<u8>,
) -> anyhow::Result<Vec<GenerationInputs>> {
    use anyhow::Context as _;
    use evm_arithmetization::generation::mpt::AccountRlp;
    use mpt_trie::partial_trie::PartialTrie as _;

    use crate::{
        BlockTraceTriePreImages, CombinedPreImages, SeparateStorageTriesPreImage,
        SeparateTriePreImage, SeparateTriePreImages,
    };

    let BlockTrace {
        trie_pre_images,
        code_db: oob_code,
        txn_info,
    } = trace;

    let OtherBlockData {
        b_data:
            BlockLevelData {
                b_meta,
                b_hashes,
                withdrawals,
            },
        checkpoint_state_trie_root,
    } = other.clone(); // TODO(0xaatif): remove this clone

    let (state, storage, mut in_band_code) = match trie_pre_images {
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(storage),
        }) => (
            state,
            storage
                .into_iter()
                .map(|(k, SeparateTriePreImage::Direct(v))| (k, v))
                .collect::<HashMap<_, _>>(),
            BTreeSet::new(),
        ),
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions =
                wire::parse(&compact).context("couldn't parse instructions from binary format")?;

            // Set up the execution layer
            // See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#tries-in-ethereum>
            // -----------------------------------------------------------------

            // Per-block,
            // keyed by `rlp(transactionIndex)`
            let transactions = TypedMpt::<Either<LegacyTransactionRlp, ()>>::default(); // TODO(0xaatif): what else?

            // Per-block,
            // keyed by `rlp(transactionIndex)`
            let receipts = TypedMpt::<Vec<u8>>::default(); // TODO(0xaatif): what else?

            let type1::Frontend {
                // Global,
                // keyed by `keccak256(ethereumAddress)`.
                state,
                code,
                // Global per-account
                mut storage,
            } = type1::frontend(instructions)?;

            let mut hash2code = code
                .into_iter()
                .map(|bin| (crate::hash(&bin), bin.into_vec()))
                .collect::<BTreeMap<_, _>>();
            hash2code.insert(crate::hash([]), Vec::new());
            for (hash, oob) in oob_code.into_iter().flatten() {
                ensure!(crate::hash(&oob) == hash, "bad hash in out-of-band code_db");
                hash2code.insert(hash, oob);
            }

            let inline_accounts_before_block = state
                .iter()
                .filter_map(|(k, v)| v.right().map(|acct| (*k, acct)))
                .collect::<BTreeMap<_, _>>();

            // accumulators
            let mut acc_gas_used = 0;

            // one for every transaction
            let mut all_generation_inputs = vec![];

            for (
                ix,
                (
                    pos,
                    TxnInfo {
                        traces,
                        meta:
                            TxnMeta {
                                byte_code,
                                new_txn_trie_node_byte,
                                new_receipt_trie_node_byte,
                                gas_used,
                            },
                    },
                ),
            ) in txn_info.into_iter().with_position().enumerate()
            {
                bump_storage(&traces, &inline_accounts_before_block, &mut storage);

                let tries = TrieInputs {
                    state_trie: state.clone().into(),
                    transactions_trie: transactions.clone().into(),
                    receipts_trie: receipts.clone().into(),
                    storage_tries: storage
                        .clone()
                        .into_iter()
                        .map(|(k, v)| (k.into_hash_left_padded(), v.into()))
                        .collect(),
                };

                transactions.insert(&rlp::encode(&ix), byte_code);
                receipts.insert(
                    &rlp::encode(&ix),
                    Either::Right(
                        match rlp::decode::<LegacyReceiptRlp>(&new_receipt_trie_node_byte) {
                            Ok(_) => new_receipt_trie_node_byte,
                            Err(_) => rlp::decode(&new_receipt_trie_node_byte).context(
                                "couldn't decode bytes as a legacy receipt or a plain vector",
                            )?,
                        },
                    ),
                );

                all_generation_inputs.push(GenerationInputs {
                    txn_number_before: ix.into(),
                    gas_used_before: acc_gas_used.into(),
                    gas_used_after: {
                        acc_gas_used += gas_used;
                        acc_gas_used.into()
                    },
                    // TODO(0xaatif): this shouldn't be `Option`al
                    signed_txn: match byte_code.is_empty() {
                        true => None,
                        false => Some(byte_code),
                    },
                    withdrawals: Vec::new(), // fixed up later
                    tries,
                    trie_roots_after: TrieRoots {
                        state_root: todo!(),
                        transactions_root: todo!(),
                        receipts_root: todo!(),
                    },
                    checkpoint_state_trie_root,
                    contract_code: traces
                        .values()
                        .filter_map(|it| match it.code_usage.as_ref()? {
                            ContractCodeUsage::Read(hash) => Some(
                                hash2code
                                    .get_key_value(hash)
                                    .context("missing code for transaction")
                                    .map(|(k, v)| (*k, v.clone())),
                            ),
                            ContractCodeUsage::Write(bytes) => {
                                let hash = hash(bytes);
                                // TODO(0xaatif): why do we do this?
                                hash2code.insert(hash, bytes.clone());
                                Some(Ok((hash, bytes.clone())))
                            }
                        })
                        .collect::<Result<_, _>>()?,
                    block_metadata: b_meta.clone(),
                    block_hashes: b_hashes.clone(),
                })
            }

            todo!()
        }
    };

    let accounts_before_block = state
        .items()
        .filter_map(|(addr, data)| {
            data.as_val()
                .map(|data| (addr.into(), rlp::decode::<AccountRlp>(data).unwrap()))
        })
        .collect();

    for (hash, code) in oob_code.into_iter().flatten() {
        ensure!(crate::hash(&code) == hash, "bad oob code_db");
        in_band_code.insert(code);
    }
    let code = in_band_code;
    let mut hash2code = code.into_iter().map(|v| (hash(&v), v)).collect();

    let last_tx_idx = txn_info.len().saturating_sub(1);

    let txn_info = txn_info
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let extra_state_accesses = if last_tx_idx == i {
                // If this is the last transaction, we mark the withdrawal addresses
                // as accessed in the state trie.
                other
                    .b_data
                    .withdrawals
                    .iter()
                    .map(|(addr, _)| crate::hash(addr.as_bytes()))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };

            processed_block_trace::process(
                t,
                &accounts_before_block,
                &extra_state_accesses,
                &mut hash2code,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(decoding::into_txn_proof_gen_ir(
        state,
        storage,
        txn_info,
        other.b_data.withdrawals.clone(),
        other,
    )?)
}

fn bump_storage(
    traces: &HashMap<ethereum_types::H160, TxnTrace>,
    inline_accounts_before_block: &BTreeMap<TriePath, AccountRlp>,
    storage: &mut BTreeMap<TriePath, TypedMpt<Vec<u8>>>,
) {
    let did_access_storage = traces
        .iter()
        .filter_map(|(addr, trace)| {
            let read = trace.storage_read.as_ref().is_some_and(|it| !it.is_empty());
            let wrote = trace
                .storage_written
                .as_ref()
                .is_some_and(|it| !it.is_empty());
            match read || wrote {
                true => Some(hash(addr)),
                false => None,
            }
        })
        .collect::<BTreeSet<_>>();

    for (path, acct) in inline_accounts_before_block {
        if acct.storage_root != TypedMpt::<AccountRlp>::default().hash()
            // TODO(0xaatif): why is this line needed?
            && !did_access_storage.contains(&path.into_hash_left_padded())
        {
            // need to init storage
            storage.entry(*path).or_insert_with(|| {
                let mut it = TypedMpt::default();
                it.insert(TriePath::default(), Either::Left(acct.storage_root));
                it
            });
        }
    }
}

/// Like `#[serde(with = "hex")`, but tolerates and emits leading `0x` prefixes
mod hex {
    use std::{borrow::Cow, fmt};

    use serde::{de::Error as _, Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: hex::ToHex,
    {
        let s = data.encode_hex::<String>();
        serializer.serialize_str(&format!("0x{}", s))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: hex::FromHex,
        T::Error: fmt::Display,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        match s.strip_prefix("0x") {
            Some(rest) => T::from_hex(rest),
            None => T::from_hex(&*s),
        }
        .map_err(D::Error::custom)
    }
}

#[cfg(test)]
#[derive(serde::Deserialize)]
struct Case {
    #[serde(with = "hex")]
    pub bytes: Vec<u8>,
    #[serde(deserialize_with = "h256")]
    pub expected_state_root: ethereum_types::H256,
}

#[cfg(test)]
fn h256<'de, D: serde::Deserializer<'de>>(it: D) -> Result<ethereum_types::H256, D::Error> {
    Ok(ethereum_types::H256(hex::deserialize(it)?))
}
