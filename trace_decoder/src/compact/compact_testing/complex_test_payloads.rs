use crate::{
    compact::compact_processing_common::{CompactParsingResult, Header, ProcessedCompactOutput},
    types::TrieRootHash,
};

pub(super) type ProcessedCompactPrestateFn<T, U> =
    fn(T) -> CompactParsingResult<ProcessedCompactOutput<U>>;

pub(super) struct TestProtocolInputAndRoot {
    pub(super) byte_str: &'static str,
    pub(super) root_str: &'static str,
}

impl TestProtocolInputAndRoot {
    pub(super) fn header_and_hash_checks(self, calculated_hash: TrieRootHash, header: Header) {
        let expected_hash = TrieRootHash::from_slice(&hex::decode(self.root_str).unwrap());

        assert!(header.version_is_compatible(1));
        assert_eq!(calculated_hash, expected_hash);
    }
}

#[cfg(test)]
pub(super) fn init_testing_env() {
    let _ = pretty_env_logger::try_init();
}

#[cfg(test)]
pub(super) fn h_decode_key(h_bytes: &str) -> mpt_trie::nibbles::Nibbles {
    let bytes = hex::decode(h_bytes).unwrap();
    crate::compact::compact_processing_common::key_bytes_to_nibbles(&bytes)
}

#[cfg(test)]
pub(super) fn h_decode(b_str: &str) -> Vec<u8> {
    hex::decode(b_str).unwrap()
}