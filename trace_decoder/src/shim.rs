use std::collections::BTreeMap;

use anyhow::bail;
use arrayvec::ArrayVec;
use either::Either;
use ethereum_types::H256;
use mpt_trie::partial_trie::PartialTrie as _;
use u4::U4;

/// Bounded stack of [`U4`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TriePath {
    components: ArrayVec<U4, 64>,
}

impl TriePath {
    pub fn new(components: impl IntoIterator<Item = U4>) -> anyhow::Result<Self> {
        let mut this = TriePath::default();
        let mut excess = 0usize;
        for component in components {
            match this.components.try_push(component) {
                Ok(()) => {}
                Err(_) => excess += 1,
            }
        }
        if excess != 0 {
            bail!(
                "too many components in trie path, excess of {} in limit of {}",
                excess,
                this.components.capacity(),
            )
        }
        Ok(this)
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypedMpt<T> {
    inner: BTreeMap<TriePath, Either<ethereum_types::H256, T>>,
}

impl<T> TypedMpt<T> {
    pub fn insert(&mut self, path: TriePath, item: Either<H256, T>) -> Option<Either<H256, T>> {
        self.inner.insert(path, item)
    }
    pub fn iter(&self) -> std::collections::btree_map::Iter<TriePath, Either<H256, T>> {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a TypedMpt<T> {
    type Item = (&'a TriePath, &'a Either<H256, T>);

    type IntoIter = std::collections::btree_map::Iter<'a, TriePath, Either<H256, T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> Default for TypedMpt<T> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

impl<T> From<TypedMpt<T>> for mpt_trie::partial_trie::HashedPartialTrie
where
    T: rlp::Encodable,
{
    fn from(value: TypedMpt<T>) -> Self {
        let mut theirs = mpt_trie::partial_trie::HashedPartialTrie::default();
        for (k, v) in value.inner {
            match v {
                Either::Left(it) => theirs.insert(k, it),
                Either::Right(it) => theirs.insert(k, rlp::encode(&it).to_vec()),
            }
            .expect("internal error in MPT library")
        }
        theirs
    }
}

impl<T> TypedMpt<T>
where
    T: rlp::Encodable + Clone,
{
    pub fn hash(&self) -> H256 {
        mpt_trie::partial_trie::HashedPartialTrie::from(self.clone()).hash()
    }
}
