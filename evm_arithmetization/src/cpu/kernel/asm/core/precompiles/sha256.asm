global precompile_sha256:
    // stack: address, retdest, new_ctx, (old stack)
    %pop2
    // stack: new_ctx, (old stack)
    %set_new_ctx_parent_pc(after_precompile)
    // stack: new_ctx, (old stack)
    DUP1
    SET_CONTEXT
    %checkpoint // Checkpoint
    %increment_call_depth
    // stack: (empty)
    PUSH @IS_KERNEL // true
    // stack: kexit_info

    %calldatasize
    %num_bytes_to_num_words
    // stack: data_words_len, kexit_info
    %mul_const(@SHA256_DYNAMIC_GAS)
    PUSH @SHA256_STATIC_GAS
    ADD
    // stack: gas, kexit_info
    %charge_gas

    // Copy the call data to the kernel general segment (sha2 expects it there) and call sha2.
    %calldatasize
    GET_CONTEXT

    %stack (ctx, size) ->
        (
        ctx, @SEGMENT_CALLDATA,          // SRC
        ctx,
        size, sha2,                      // count, retdest
        0, size, sha256_contd            // sha2 input: virt, num_bytes, retdest
        )
    %build_address_no_offset
    %stack(addr, ctx) -> (ctx, @SEGMENT_KERNEL_GENERAL, 1, addr)
    %build_address
    // stack: DST, SRC, count, retdest, virt, num_bytes, retdest

    %jump(memcpy_bytes)

sha256_contd:
    // stack: hash, kexit_info
    // Store the result hash to the parent's return data using `mstore_unpacking`.
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 32)
    %mload_context_metadata(@CTX_METADATA_PARENT_CONTEXT)
    %stack (parent_ctx, hash) -> (parent_ctx, @SEGMENT_RETURNDATA, hash)
    %build_address_no_offset
    MSTORE_32BYTES_32
    %jump(pop_and_return_success)
