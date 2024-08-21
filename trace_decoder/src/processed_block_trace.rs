use std::collections::{HashMap, HashSet};

use anyhow::{bail, Context as _};
use ethereum_types::{Address, H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use zk_evm_common::EMPTY_TRIE_HASH;

use crate::typed_mpt::TrieKey;
use crate::PartialTriePreImages;
use crate::{hash, TxnTrace};
use crate::{ContractCodeUsage, TxnInfo};

const FIRST_PRECOMPILE_ADDRESS: U256 = U256([1, 0, 0, 0]);
const LAST_PRECOMPILE_ADDRESS: U256 = U256([10, 0, 0, 0]);

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace {
    pub tries: PartialTriePreImages,
    pub txn_info: Vec<ProcessedTxnInfo>,
    pub withdrawals: Vec<(Address, U256)>,
}

#[derive(Debug)]
pub(crate) struct ProcessedBlockTracePreImages {
    pub tries: PartialTriePreImages,
    pub extra_code_hash_mappings: Option<HashMap<H256, Vec<u8>>>,
}

#[derive(Debug, Default)]
pub(crate) struct ProcessedTxnInfo {
    pub nodes_used_by_txn: NodesUsedByTxn,
    pub contract_code_accessed: HashSet<Vec<u8>>,
    pub meta: TxnMetaState,
}

/// Code hash mappings that we have constructed from parsing the block
/// trace.
/// If there are any txns that create contracts, then they will also
/// get added here as we process the deltas.
pub(crate) struct Hash2Code {
    /// Key must always be [`hash`] of value.
    inner: HashMap<H256, Vec<u8>>,
}

impl Hash2Code {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
    fn get(&mut self, hash: H256) -> anyhow::Result<Vec<u8>> {
        match self.inner.get(&hash) {
            Some(code) => Ok(code.clone()),
            None => bail!("no code for hash {}", hash),
        }
    }
    fn insert(&mut self, code: Vec<u8>) {
        self.inner.insert(hash(&code), code);
    }
}

impl FromIterator<Vec<u8>> for Hash2Code {
    fn from_iter<II: IntoIterator<Item = Vec<u8>>>(iter: II) -> Self {
        let mut this = Self::new();
        for code in iter {
            this.insert(code)
        }
        this
    }
}

impl TxnInfo {
    pub(crate) fn into_processed_txn_info(
        self,
        tries: &PartialTriePreImages,
        all_accounts_in_pre_image: &[(H256, AccountRlp)],
        extra_state_accesses: &[Address],
        hash2code: &mut Hash2Code,
    ) -> anyhow::Result<ProcessedTxnInfo> {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_accessed = HashSet::from([vec![]]); // we always "access" empty code

        for (
            addr,
            TxnTrace {
                balance,
                nonce,
                storage_read,
                storage_written,
                code_usage,
                self_destructed,
            },
        ) in self.traces
        {
            let hashed_addr = hash(addr.as_bytes());

            // record storage changes
            let storage_written = storage_written.unwrap_or_default();
            nodes_used_by_txn.storage_accesses.push((
                hashed_addr,
                storage_read
                    .into_iter()
                    .flatten()
                    .chain(storage_written.keys().copied())
                    .map(|H256(bytes)| TrieKey::from_hash(hash(bytes)))
                    .collect(),
            ));
            nodes_used_by_txn.storage_writes.push((
                hashed_addr,
                storage_written
                    .iter()
                    .map(|(k, v)| (TrieKey::from_hash(*k), rlp::encode(v).to_vec()))
                    .collect(),
            ));

            // record state changes
            let state_write = StateWrite {
                balance,
                nonce,
                storage_trie_change: !storage_written.is_empty(),
                code_hash: code_usage.as_ref().map(|it| match it {
                    ContractCodeUsage::Read(hash) => *hash,
                    ContractCodeUsage::Write(bytes) => hash(bytes),
                }),
            };

            if state_write != StateWrite::default() {
                // a write occurred
                nodes_used_by_txn.state_writes.push((addr, state_write))
            }

            let is_precompile = (FIRST_PRECOMPILE_ADDRESS..LAST_PRECOMPILE_ADDRESS)
                .contains(&U256::from_big_endian(&addr.0));

            // Trie witnesses will only include accessed precompile accounts as hash
            // nodes if the transaction calling them reverted. If this is the case, we
            // shouldn't include them in this transaction's `state_accesses` to allow the
            // decoder to build a minimal state trie without hitting any hash node.
            if !is_precompile || tries.state.get_by_address(addr).is_some() {
                nodes_used_by_txn.state_accesses.push(addr);
            }

            match code_usage {
                Some(ContractCodeUsage::Read(hash)) => {
                    contract_code_accessed.insert(hash2code.get(hash)?);
                }
                Some(ContractCodeUsage::Write(code)) => {
                    contract_code_accessed.insert(code.clone());
                    hash2code.insert(code);
                }
                None => {}
            }

            if self_destructed.unwrap_or_default() {
                nodes_used_by_txn.self_destructed_accounts.push(hashed_addr);
            }
        }

        for &hashed_addr in extra_state_accesses {
            nodes_used_by_txn.state_accesses.push(hashed_addr);
        }

        let accounts_with_storage_accesses = nodes_used_by_txn
            .storage_accesses
            .iter()
            .filter(|(_, slots)| !slots.is_empty())
            .map(|(addr, _)| *addr)
            .collect::<HashSet<_>>();

        for (addr, state) in all_accounts_in_pre_image {
            if state.storage_root != EMPTY_TRIE_HASH
                && !accounts_with_storage_accesses.contains(addr)
            {
                nodes_used_by_txn
                    .accts_with_unaccessed_storage
                    .insert(*addr, state.storage_root);
            }
        }

        Ok(ProcessedTxnInfo {
            nodes_used_by_txn,
            contract_code_accessed,
            meta: TxnMetaState {
                txn_bytes: match self.meta.byte_code.is_empty() {
                    false => Some(self.meta.byte_code),
                    true => None,
                },
                receipt_node_bytes: check_receipt_bytes(self.meta.new_receipt_trie_node_byte)?,
                gas_used: self.meta.gas_used,
            },
        })
    }
}

fn check_receipt_bytes(bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    match rlp::decode::<LegacyReceiptRlp>(&bytes) {
        Ok(_) => Ok(bytes),
        Err(_) => {
            rlp::decode(&bytes).context("couldn't decode receipt as a legacy receipt or raw bytes")
        }
    }
}

/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub state_accesses: Vec<Address>,
    pub state_writes: Vec<(Address, StateWrite)>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub storage_accesses: Vec<(H256, Vec<TrieKey>)>,
    #[allow(clippy::type_complexity)]
    pub storage_writes: Vec<(H256, Vec<(TrieKey, Vec<u8>)>)>,
    /// Hashed address -> storage root.
    pub accts_with_unaccessed_storage: HashMap<H256, H256>,
    pub self_destructed_accounts: Vec<H256>,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct StateWrite {
    pub balance: Option<U256>,
    pub nonce: Option<U256>,
    pub storage_trie_change: bool,
    pub code_hash: Option<H256>,
}

#[derive(Debug, Default)]
pub(crate) struct TxnMetaState {
    /// [`None`] if this is a dummy transaction inserted for padding.
    pub txn_bytes: Option<Vec<u8>>,
    pub receipt_node_bytes: Vec<u8>,
    pub gas_used: u64,
}

impl TxnMetaState {
    pub fn is_dummy(&self) -> bool {
        self.txn_bytes.is_none()
    }
}
