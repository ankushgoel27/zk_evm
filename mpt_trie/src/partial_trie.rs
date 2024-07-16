//! Definitions for the core types [`PartialTrie`] and [`Nibbles`].

use std::{fmt::Debug, ops::Deref};

use ethereum_types::H256;
use serde::{Deserialize, Serialize};

use crate::{
    nibbles::Nibbles,
    trie_hashing::{hash_trie, rlp_encode_and_hash_node, EncodedNode},
    trie_ops::{TrieOpResult, ValOrHash},
    utils::TryFromIterator,
};

/// A node (and equivalently, a tree) in a [Merkle Patricia Trie](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/).
///
/// Nodes may be [hashed](Self::hash) recursively.
///
/// Any node in the trie may be replaced by its [hash](Self::hash) in a
/// [Node::Hash], and the root hash of the trie will remain unchanged.
///
/// ```text
///     R            R'
///    / \          / \
///   A   B        H   B
///  / \   \            \
/// C   D   E            E
/// ```
///
/// That is, if `H` is `A`'s hash, then the roots of `R` and `R'` are the same.
///
/// This is particularly useful for pruning unrequired data from tries.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Node {
    /// An empty trie.
    #[default]
    Empty,
    /// The digest of trie whose data does not need to be stored.
    ///
    /// **Important note**: Hash nodes should **only** be created to replace
    /// `PartialTrie`s whose RLP encoding is >= 32 bytes. Creating a hash node
    /// for a `PartialTrie` smaller than this will cause an incorrect hash to be
    /// generated for the trie.
    Hash(H256),
    /// A branch node, which consists of 16 children and an optional value.
    Branch {
        /// A slice containing the 16 children of this branch node.
        children: [Box<Self>; 16],
        /// The payload of this node.
        value: Vec<u8>,
    },
    /// An extension node, which consists of a list of nibbles and a single
    /// child.
    Extension {
        /// The path of this extension.
        nibbles: Nibbles,
        /// The child of this extension node.
        child: Box<Self>,
    },
    /// A leaf node, which consists of a list of nibbles and a value.
    Leaf {
        /// The path of this leaf node.
        nibbles: Nibbles,
        /// The payload of this node
        value: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrozenNode {
    node: Node,
    hash: H256,
}

impl FrozenNode {
    pub fn thaw(self) -> Node {
        self.node
    }
}
impl Deref for FrozenNode {
    type Target = Node;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl Node {
    pub fn freeze(self) -> FrozenNode {
        FrozenNode {
            hash: self.hash(),
            node: self,
        }
    }
    /// Creates a new partial trie from a node.
    pub fn new(node: Node) -> Self {
        node
    }
    /// Inserts a node into the trie.
    pub fn insert<K, V>(&mut self, k: K, v: V) -> TrieOpResult<()>
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
    {
        self.trie_insert(k, v)?;
        Ok(())
    }
    /// Add more nodes to the trie through an iterator
    pub fn extend<K, V, I>(&mut self, nodes: I) -> TrieOpResult<()>
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.trie_extend(nodes)?;
        Ok(())
    }
    /// Get a node if it exists in the trie.
    pub fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        self.trie_get(k)
    }

    /// Deletes a `Leaf` node or `Branch` value field if it exists.
    ///
    /// To agree with Ethereum specs, deleting nodes does not result in the trie
    /// removing nodes that are redundant after deletion. For example, a
    /// `Branch` node that is completely empty after all of its children are
    /// deleted is not pruned. Also note:
    /// - Deleted leaves are replaced with `Empty` nodes.
    /// - Deleted branch values are replaced with empty `Vec`s.
    ///
    /// # Panics
    /// If a `Hash` node is traversed, a panic will occur. Since `Hash` nodes
    /// are meant for parts of the trie that are not relevant, traversing one
    /// means that a `Hash` node was created that potentially should not have
    /// been.
    pub fn delete<K>(&mut self, k: K) -> TrieOpResult<Option<Vec<u8>>>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        self.trie_delete(k)
    }
    /// Get the hash for the node.
    pub fn hash(&self) -> H256 {
        self.get_hash()
    }
    /// Returns an iterator over the trie that returns all key/value pairs for
    /// every `Leaf` and `Hash` node.
    pub fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        self.trie_items()
    }
    /// Returns an iterator over the trie that returns all keys for every `Leaf`
    /// and `Hash` node.
    pub fn keys(&self) -> impl Iterator<Item = Nibbles> {
        self.trie_keys()
    }
    /// Returns an iterator over the trie that returns all values for every
    /// `Leaf` and `Hash` node.
    pub fn values(&self) -> impl Iterator<Item = ValOrHash> {
        self.trie_values()
    }
    /// Returns `true` if the trie contains an element with the given key.
    pub fn contains<K>(&self, k: K) -> bool
    where
        K: Into<Nibbles>,
    {
        self.trie_has_item_by_key(k)
    }
}

impl Node {
    pub(crate) fn hash_intern(&self) -> EncodedNode {
        rlp_encode_and_hash_node(self)
    }
    pub(crate) fn get_hash(&self) -> H256 {
        hash_trie(self)
    }
}

impl<K, V> TryFromIterator<(K, V)> for Node
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn try_from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> TrieOpResult<Self> {
        let mut root = Node::Empty;
        root.extend(nodes)?;
        Ok(root)
    }
}
