use std::{array, collections::BTreeMap};

use anyhow::ensure;
use either::Either;
use ethereum_types::H256;
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
    inner: BTreeMap<TriePath, Either<H256, T>>,
}

impl<T> Default for TypedMpt<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TypedMpt<T> {
    pub const fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }
    pub fn remove(&mut self, path: TriePath) -> Option<Either<H256, T>> {
        self.inner.remove(&path)
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
        self.inner.insert(path, Either::Right(value))
    }
    pub fn insert_branch(&mut self, path: TriePath, hash: H256) -> Option<Either<H256, T>> {
        self.inner.insert(path, Either::Left(hash))
    }
    pub fn get(&self, path: TriePath) -> Option<Either<H256, &T>> {
        self.inner
            .get(&path)
            .map(|it| it.as_ref().map_left(|it| *it))
    }
    pub fn root(&self) -> H256
    where
        T: Encodable,
    {
        let mut hasher = alloy_trie::HashBuilder::default();
        for (path, v) in &self.inner {
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
        self.inner
            .iter()
            .filter_map(|(k, v)| Some((*k, v.as_ref().right()?)))
    }
    pub fn iter(&self) -> impl Iterator<Item = (TriePath, Either<H256, &T>)> {
        self.inner
            .iter()
            .map(|(k, v)| (*k, v.as_ref().map_left(|h| *h)))
    }
    pub fn into_legacy(self) -> mpt_trie::partial_trie::HashedPartialTrie
    where
        T: rlp::Encodable,
    {
        let mut legacy = mpt_trie::partial_trie::HashedPartialTrie::default();
        for (path, v) in self.inner {
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
    inner: TypedMpt<Vec<u8>>,
}

impl TransactionTrie {
    /// # Panics
    /// - On very large transaction indices
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> Option<Either<H256, Vec<u8>>> {
        self.inner.insert(TriePath::from_txn_ix(txn_ix), val)
    }
    pub fn root(&self) -> H256 {
        self.inner.root()
    }
}

impl From<TransactionTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: TransactionTrie) -> Self {
        value.inner.into_legacy()
    }
}

/// Per-block
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#transaction-trie>
#[derive(Debug, Clone, Default)]
pub struct ReceiptTrie {
    inner: TypedMpt<Vec<u8>>,
}

impl ReceiptTrie {
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) {
        self.inner.insert(TriePath::from_txn_ix(txn_ix), val);
    }
}

impl From<ReceiptTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: ReceiptTrie) -> Self {
        value.inner.into_legacy()
    }
}

/// Global
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#state-trie>
#[derive(Debug, Clone, Default)]
pub struct StateTrie {
    inner: TypedMpt<AccountRlp>,
}

impl StateTrie {
    pub fn insert(
        &mut self,
        path: TriePath,
        account: AccountRlp,
    ) -> Option<Either<H256, AccountRlp>> {
        self.inner.insert(path, account)
    }
    pub fn insert_branch(
        &mut self,
        path: TriePath,
        hash: H256,
    ) -> Option<Either<H256, AccountRlp>> {
        self.inner.insert_branch(path, hash)
    }
    pub fn get(&self, path: TriePath) -> Option<Either<H256, AccountRlp>> {
        self.inner.inner.get(&path).map(|it| *it)
    }
    pub fn root(&self) -> H256 {
        self.inner.root()
    }
    pub fn iter(&self) -> impl Iterator<Item = (TriePath, Either<H256, AccountRlp>)> + '_ {
        self.inner
            .iter()
            .map(|(path, eith)| (path, eith.map_right(|acct| *acct)))
    }
}

impl From<StateTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: StateTrie) -> Self {
        value.inner.into_legacy()
    }
}

/// Global, per-account.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie>
#[derive(Debug, Clone, Default)]
pub struct StorageTrie {
    inner: TypedMpt<Vec<u8>>,
}
impl StorageTrie {
    pub fn insert(&mut self, path: TriePath, value: Vec<u8>) -> Option<Either<H256, Vec<u8>>> {
        self.inner.insert(path, value)
    }
    pub fn insert_branch(&mut self, path: TriePath, hash: H256) -> Option<Either<H256, Vec<u8>>> {
        self.inner.insert_branch(path, hash)
    }
    pub fn root(&self) -> H256 {
        self.inner.root()
    }
    pub fn remove(&mut self, path: TriePath) -> Option<Either<H256, Vec<u8>>> {
        self.inner.inner.remove(&path)
    }
}

impl From<StorageTrie> for mpt_trie::partial_trie::HashedPartialTrie {
    fn from(value: StorageTrie) -> Self {
        value.inner.into_legacy()
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
    pub fn from_hash(h: H256) -> Self {
        todo!()
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
fn into_hash() {
    let path = TriePath::new((0..10).flat_map(U4::new)).unwrap();
    assert_eq!(
        path.into_hash_left_padded(),
        mpt_trie::nibbles::Nibbles::from(path).into()
    );
}

#[test]
fn empty() {
    let hash = H256([1; 32]);
    let theirs =
        mpt_trie::partial_trie::HashedPartialTrie::new(mpt_trie::partial_trie::Node::Hash(hash))
            .hash();
    let mut ours = TypedMpt::<evm_arithmetization::generation::mpt::AccountRlp>::default();
    ours.insert(TriePath::default(), Either::Left(hash));
    assert_eq!(theirs, ours.root());
}

#[cfg(test)]
mod tests {
    use quickcheck::Arbitrary;

    use super::*;
    type Theirs = mpt_trie::partial_trie::HashedPartialTrie;
    type Ours = TypedMpt<Vec<u8>>;

    quickcheck::quickcheck! {
        fn test(ours: TypedMpt<Vec<u8>>) -> () {
            do_test(ours)
        }
    }

    fn do_test(ours: TypedMpt<Vec<u8>>) {
        let theirs = Theirs::from(ours.clone());
        assert_eq!(theirs.hash(), ours.root())
    }

    fn ours2theirs(iter: impl IntoIterator<Item = (TriePath, Either<H256, Vec<u8>>)>) -> Theirs {
        let mut this = Theirs::default();
        for (k, v) in iter {
            this.insert(
                mpt_trie::nibbles::Nibbles::from(k),
                match v {
                    Either::Left(hash) => mpt_trie::trie_ops::ValOrHash::Hash(hash),
                    Either::Right(vec) => mpt_trie::trie_ops::ValOrHash::Val(vec),
                },
            )
            .unwrap();
        }
        this
    }

    impl<T: Arbitrary> Arbitrary for TypedMpt<T> {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                inner: Vec::<(_, ImplArbitrary<Either<ImplArbitrary<_>, _>>)>::arbitrary(g)
                    .into_iter()
                    .map(|(path, ImplArbitrary(inner))| {
                        (path, inner.map_left(|ImplArbitrary(it)| it))
                    })
                    .collect(),
            }
        }
    }

    #[derive(Clone)]
    struct ImplArbitrary<T>(T);

    impl Arbitrary for ImplArbitrary<H256> {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            ImplArbitrary(H256(array::from_fn(|_ix| Arbitrary::arbitrary(g))))
        }
    }

    impl<L, R> Arbitrary for ImplArbitrary<Either<L, R>>
    where
        L: Arbitrary,
        R: Arbitrary,
    {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let options = [
                Either::Left(Arbitrary::arbitrary(g)),
                Either::Right(Arbitrary::arbitrary(g)),
            ];
            ImplArbitrary(g.choose(&options).cloned().unwrap())
        }
    }

    impl Arbitrary for TriePath {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            Self {
                components: Arbitrary::arbitrary(g),
            }
        }

        fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
            Box::new(
                self.components
                    .shrink()
                    .map(|components| Self { components }),
            )
        }
    }
}

#[test]
fn test1() {
    use mpt_trie::partial_trie::PartialTrie as _;
    let mut mpt = mpt_trie::partial_trie::HashedPartialTrie::default();
    let val = &[1, 2, 3, 4][..];
    mpt.insert(mpt_trie::nibbles::Nibbles::default(), val)
        .unwrap();
    let alloy = H256(
        alloy_trie::HashBuilder {
            stack: vec![val.to_vec()],
            ..Default::default()
        }
        .root()
        .0,
    );
    assert_eq!(mpt.hash(), alloy)
}
