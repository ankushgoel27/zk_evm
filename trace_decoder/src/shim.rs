use std::collections::BTreeMap;

use either::Either;
use ethereum_types::H256;
use mpt_trie::partial_trie::PartialTrie as _;
use u4::{AsNibbles, U4};

/// Bounded sequence of [`U4`], used as a key for [`TypedMpt`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TriePath {
    components: copyvec::CopyVec<U4, 64>,
}

impl TriePath {
    pub fn new(components: impl IntoIterator<Item = U4>) -> anyhow::Result<Self> {
        Ok(TriePath {
            components: copyvec::CopyVec::try_from_iter(components)?,
        })
    }
    pub fn into_hash_left_padded(mut self) -> H256 {
        for _ in 0..self.components.spare_capacity_mut().len() {
            self.components.insert(0, U4::Dec00)
        }
        let mut packed = [0u8; 32];
        AsNibbles(&mut packed).pack_from_slice(&self.components);
        H256::from_slice(&packed)
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
    assert_eq!(theirs, ours.hash());
}

/// Map where keys are [up to 64 nibbles](TriePath), and values are either a
/// [hash](H256) or an inline [`rlp::Encodable`]/[`rlp::Decodable`] value.
///
/// [Merkle Patricia Trees](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie)
/// are _maps_, where keys are typically _sequences_ of an _alphabet_.
///
/// Map values are typically indirect (i.e a _hash_),
/// but in this structure may be stored _inline_.
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
    T: rlp::Encodable,
{
    pub fn hash(&self) -> H256 {
        // we avoid superfluous clones this way
        mpt_trie::partial_trie::HashedPartialTrie::from(TypedMpt {
            inner: self
                .iter()
                .map(|(k, v)| (*k, v.as_ref().map_either(|h| *h, RefEncodable)))
                .collect(),
        })
        .hash()
    }
}

struct RefEncodable<T>(T); // TODO(0xaatif): impl<T> rlp::Encodable for &T where T: rlp::Encodable { .. }
impl<T> rlp::Encodable for RefEncodable<&T>
where
    T: rlp::Encodable,
{
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        T::rlp_append(self.0, s)
    }
}
