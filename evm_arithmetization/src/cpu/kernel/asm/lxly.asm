/// LxLy bridge contract.
/// This file contain both pre-block and post-block LxLy contract specific execution.

global lxly_set_scalable_address:
    // stack: (empty)
    PUSH start_txn
    // stack: retdest
    PUSH @ADDRESS_SCALABLE_L2_STATE_KEY
    %is_non_existent
    %jumpi(create_scalable_l2_account)

global lxly_update_scalable_storage:
    // stack: retdest
    %blocknumber
    PUSH @LAST_BLOCK_STORAGE_POS
    // stack: last_block_slot, block_number, retdest
    %write_scalable_storage

    // Post ETROG upgrade

lxly_update_scalable_timestamp:
    %timestamp
    PUSH @TIMESTAMP_STORAGE_POS
    // stack: timestamp_slot, timestamp, retdest
    %write_scalable_storage
    




%macro write_scalable_storage
    // stack: slot, value
    // First we write the value to MPT data, and get a pointer to it.
    %get_trie_data_size
    // stack: value_ptr, slot, value
    SWAP2
    // stack: value, slot, value_ptr
    %append_to_trie_data
    // stack: slot, value_ptr

    // Next, call mpt_insert on the account's storage root.
    %stack (slot, value_ptr) -> (slot, value_ptr, %%after_write_scalable_storage)
    %slot_to_storage_key
    // stack: storage_key, value_ptr, after_write_scalable_storage
    PUSH 64 // storage_key has 64 nibbles
    %get_storage_trie(@ADDRESS_SCALABLE_L2_STATE_KEY)
    // stack: storage_root_ptr, 64, storage_key, value_ptr, after_write_scalable_storage
    %jump(mpt_insert)

%%after_write_scalable_storage:
    // stack: new_storage_root_ptr
    %get_account_data(@ADDRESS_SCALABLE_L2_STATE_KEY)
    // stack: account_ptr, new_storage_root_ptr

    // Update the copied account with our new storage root pointer.
    %add_const(2)
    // stack: account_storage_root_ptr_ptr, new_storage_root_ptr
    %mstore_trie_data
%endmacro

create_scalable_l2_account:
    // stack: (empty)
    PUSH lxly_update_scalable_storage
    // stack: retdest
    %get_trie_data_size // pointer to new account we're about to create
    // stack: new_account_ptr, retdest
    PUSH 0 %append_to_trie_data // nonce
    PUSH 0 %append_to_trie_data // balance
    PUSH 0 %append_to_trie_data // storage root pointer
    PUSH @EMPTY_STRING_HASH %append_to_trie_data // code hash
    // stack: new_account_ptr, retdest
    PUSH @L2ADDRESS_SCALABLE_L2_STATE_KEY
    // stack: key, new_account_ptr, retdest
    %jump(mpt_insert_state_trie)