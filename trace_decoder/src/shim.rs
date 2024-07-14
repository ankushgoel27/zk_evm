use std::{array, collections::BTreeMap};

use anyhow::ensure;
use either::Either;
use ethereum_types::{Address, H256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use mpt_trie::partial_trie::PartialTrie as _;
use rlp::Encodable;
use u4::{AsNibbles, U4};

/// Map where keys are [up to 64 nibbles](TriePath), and values are either a
/// [hash](H256) or an inline [`rlp::Encodable`]/[`rlp::Decodable`] value.
///
/// [Merkle Patricia Trees](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie)
/// are _maps_, where keys are typically _sequences_ of an _alphabet_.
///
/// Map values are typically indirect (i.e a _hash_),
/// but in this structure may be stored _inline_.
#[derive(Debug, Clone)]
struct TypedMpt<T> {
    /// Note that [alloy_trie::HashBuilder] requires sorted paths.
    map: BTreeMap<TriePath, Either<H256, T>>,
}

impl<T> Default for TypedMpt<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TypedMpt<T> {
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
    pub fn remove(&mut self, path: TriePath) -> Option<Either<H256, T>> {
        self.map.remove(&path)
    }
    /// # Behaviour on empty `paths`
    /// It is invalid to insert a value at the root of a trie (the empty
    /// path)[^1].
    /// In `debug` builds, this will panic if the path is empty,
    /// and in release builds the value is immediately dropped.
    ///
    /// [^1]: This logic is inherited from [`alloy_trie`].
    ///
    /// # Panics
    /// - See above.
    pub fn insert(&mut self, path: TriePath, value: T) -> Option<Either<H256, T>> {
        if path.components.is_empty() {
            match cfg!(debug_assertions) {
                true => panic!("values may not be inserted at the root of a trie"),
                false => return None,
            }
        }
        self.map.insert(path, Either::Right(value))
    }
    pub fn insert_branch(&mut self, path: TriePath, hash: H256) -> Option<Either<H256, T>> {
        self.map.insert(path, Either::Left(hash))
    }
    pub fn get(&self, path: TriePath) -> Option<Either<H256, &T>> {
        self.map.get(&path).map(|it| it.as_ref().map_left(|it| *it))
    }
    pub fn root(&self) -> H256
    where
        T: Encodable,
    {
        let mut hasher = alloy_trie::HashBuilder::default();
        for (path, v) in &self.map {
            let mut nibbles = alloy_trie::Nibbles::new();
            for u4 in path.components {
                nibbles.push(u4 as u8)
            }
            match v {
                Either::Left(H256(hash)) => {
                    // TODO(0xaatif): I don't know what the `stored_in_database` parameter does
                    hasher.add_branch(nibbles, (*hash).into(), false)
                }
                Either::Right(t) => hasher.add_leaf(nibbles, &rlp::encode(t)),
            }
        }
        H256(*hasher.root().as_ref())
    }
    pub fn values(&self) -> impl Iterator<Item = (TriePath, &T)> {
        self.map
            .iter()
            .filter_map(|(k, v)| Some((*k, v.as_ref().right()?)))
    }
    pub fn iter(&self) -> impl Iterator<Item = (TriePath, Either<H256, &T>)> {
        self.map
            .iter()
            .map(|(k, v)| (*k, v.as_ref().map_left(|h| *h)))
    }
    pub fn into_legacy(self) -> mpt_trie::partial_trie::HashedPartialTrie
    where
        T: rlp::Encodable,
    {
        let mut legacy = mpt_trie::partial_trie::HashedPartialTrie::default();
        for (path, v) in self.map {
            let mut nibbles = mpt_trie::nibbles::Nibbles::default();
            for u4 in path.components {
                nibbles.push_nibble_back(u4 as u8);
            }
            match v {
                Either::Left(h) => legacy.insert(nibbles, h),
                Either::Right(v) => legacy.insert(nibbles, &*rlp::encode(&v)),
            }
            .expect("internal error in legacy MPT library")
        }
        legacy
    }
}

impl<'a, T> IntoIterator for &'a TypedMpt<T> {
    type Item = (TriePath, Either<H256, &'a T>);

    type IntoIter = Box<dyn Iterator<Item = (TriePath, Either<H256, &'a T>)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// Per-block.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#receipts-trie>
#[derive(Debug, Clone, Default)]
pub struct TransactionTrie {
    typed: TypedMpt<Vec<u8>>,
}

impl TransactionTrie {
    /// # Panics
    /// - On very large transaction indices
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> Option<Either<H256, Vec<u8>>> {
        self.typed.insert(TriePath::from_txn_ix(txn_ix), val)
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
}

impl From<TransactionTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: TransactionTrie) -> Self {
        value.typed.into_legacy()
    }
}

/// Per-block
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#transaction-trie>
#[derive(Debug, Clone, Default)]
pub struct ReceiptTrie {
    typed: TypedMpt<Vec<u8>>,
}

impl ReceiptTrie {
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) {
        self.typed.insert(TriePath::from_txn_ix(txn_ix), val);
    }
}

impl From<ReceiptTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: ReceiptTrie) -> Self {
        value.typed.into_legacy()
    }
}

/// Global
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#state-trie>
#[derive(Debug, Clone, Default)]
pub struct StateTrie {
    typed: TypedMpt<AccountRlp>,
}

impl StateTrie {
    pub fn insert(
        &mut self,
        path: TriePath,
        account: AccountRlp,
    ) -> Option<Either<H256, AccountRlp>> {
        self.typed.insert(path, account)
    }
    pub fn insert_branch(
        &mut self,
        path: TriePath,
        hash: H256,
    ) -> Option<Either<H256, AccountRlp>> {
        self.typed.insert_branch(path, hash)
    }
    pub fn get_by_path(&self, path: TriePath) -> Option<Either<H256, AccountRlp>> {
        self.typed.map.get(&path).copied()
    }
    pub fn get_by_address(&self, address: Address) -> Option<Either<H256, AccountRlp>> {
        self.get_by_path(TriePath::from_hash(keccak_hash::keccak(address)))
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
    pub fn iter(&self) -> impl Iterator<Item = (TriePath, Either<H256, AccountRlp>)> + '_ {
        self.typed
            .iter()
            .map(|(path, eith)| (path, eith.map_right(|acct| *acct)))
    }
}

impl From<StateTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: StateTrie) -> Self {
        value.typed.into_legacy()
    }
}

/// Global, per-account.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie>
#[derive(Debug, Clone, Default)]
pub struct StorageTrie {
    typed: TypedMpt<Vec<u8>>,
}
impl StorageTrie {
    pub fn insert(&mut self, path: TriePath, value: Vec<u8>) -> Option<Either<H256, Vec<u8>>> {
        self.typed.insert(path, value)
    }
    pub fn insert_branch(&mut self, path: TriePath, hash: H256) -> Option<Either<H256, Vec<u8>>> {
        self.typed.insert_branch(path, hash)
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
    pub fn remove(&mut self, path: TriePath) -> Option<Either<H256, Vec<u8>>> {
        self.typed.map.remove(&path)
    }
}

impl From<StorageTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: StorageTrie) -> Self {
        value.typed.into_legacy()
    }
}

/// Bounded nonempty sequence of [`U4`], used as a key for [`TypedMpt`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TriePath {
    components: copyvec::CopyVec<U4, 64>,
}

impl TriePath {
    pub fn new(components: impl IntoIterator<Item = U4>) -> anyhow::Result<Self> {
        let components = copyvec::CopyVec::try_from_iter(components)?;
        Ok(TriePath { components })
    }
    pub fn into_hash_left_padded(mut self) -> H256 {
        for _ in 0..self.components.spare_capacity_mut().len() {
            self.components.insert(0, U4::Dec00)
        }
        let mut packed = [0u8; 32];
        AsNibbles(&mut packed).pack_from_slice(&self.components);
        H256::from_slice(&packed)
    }
    pub fn from_address(address: Address) -> Self {
        Self::from_hash(keccak_hash::keccak(address))
    }
    pub fn from_hash(H256(bytes): H256) -> Self {
        Self::new(AsNibbles(bytes)).expect("32 bytes is 64 nibbles, which fits")
    }
    fn from_txn_ix(txn_ix: usize) -> Self {
        TriePath::new(AsNibbles(rlp::encode(&txn_ix))).expect(
            "\
            rlp of an usize goes through a u64, which is 8 bytes,
            which will be 9 bytes RLP'ed.
            9 < 32
        ",
        )
    }
}

impl From<TriePath> for mpt_trie::nibbles::Nibbles {
    fn from(value: TriePath) -> Self {
        let mut theirs = mpt_trie::nibbles::Nibbles::default();
        for component in value.components {
            theirs.push_nibble_back(component as u8)
        }
        theirs
    }
}
#[test]
fn test() {
    use mpt_trie::partial_trie::PartialTrie as _;

    let mut ours = TypedMpt::<Vec<u8>>::new();
    let mut theirs = mpt_trie::partial_trie::HashedPartialTrie::default();

    for (ix, v) in [vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]]
        .into_iter()
        .enumerate()
        .take(3)
    {
        let path = TriePath::from_txn_ix(ix);
        theirs.insert(path, &v[..]).unwrap();
        ours.insert(path, v);
    }
    let our_hash = ours.root();
    let their_hash = theirs.hash();
    assert_eq!(our_hash, their_hash)
}
