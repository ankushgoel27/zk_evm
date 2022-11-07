// We put the message schedule in memory starting at 64 * num_blocks + 2.
%macro message_schedule_addr_from_num_blocks

%macro blake_internal_state_addr
    PUSH 0
    // stack: 0
    %mload_kernel_general
    // stack: num_blocks
    %mul_const(128)
    // stack: num_bytes
%endmacro

%macro blake_message_addr
    %blake_internal_state_addr
    %add_const(16)
%endmacro

global blake_compression:
    // stack: h_0, ..., h_7, t_0, t_1, f_0, f_1, m_0, ..., m_15
    %blake_compression_internal_state_addr
    // stack: start, h_0, ..., h_7, t_0, t_1, f_0, f_1, m_0, ..., m_15
    %rep 8
        SWAP1
        DUP2
        %mstore_kernel_general
        %increment
    %endrep
    // stack: start + 8, t_0, t_1, f_0, f_1, m_0, ..., m_15
    PUSH 0
    // stack: 0, start + 8, t_0, t_1, f_0, f_1, m_0, ..., m_15
    %rep 4
        // stack: i, loc, ...
        DUP2
        DUP2
        // stack: i, loc, i, loc,...
        %blake_iv
        // stack: IV_i, loc, i, loc,...
        SWAP1
        // stack: loc, IV_i, i, loc,...
        %mstore_kernel_general
        // stack: i, loc,...
        %increment
        SWAP1
        %increment
        SWAP1
        // stack: i + 1, loc + 1,...
    %endrep
    %rep 4
        // stack: i, loc, val, next_val, next_val,...
        %stack (i, loc, val) -> (i, val, loc, i, loc)
        // stack: i, val, loc, i, loc, next_val,...
        %blake_iv
        // stack: IV_i, val, loc, i, loc, next_val,...
        XOR
        // stack: val ^ IV_i, loc, i, loc, next_val,...
        SWAP1
        // stack: loc, val ^ IV_i, i, loc, next_val,...
        %mstore_kernel_general
        // stack: i, loc, next_val,...
        %increment
        SWAP1
        %increment
        SWAP1
        // stack: i + 1, loc + 1, next_val,...
    %endrep
    // stack: 8, loc + 16, m_0, ..., m_15
    POP
    POP
    // stack: m_0, ..., m_15
    %blake_compression_message_addr
    // stack: addr, m_0, ..., m_15
    %rep 16
        SWAP1
        DUP2
        %mstore_kernel_general
        %increment
    %endrep
    // stack: (empty)
    %blake_compression_internal_state_addr
    // stack: start
    PUSH 0
    // stack: round=0, start
    %rep 12
        // stack: round, start
        %call_blake_g_function(0, 4, 8, 12, 0, 1)
        %call_blake_g_function(1, 5, 9, 13, 2, 3)
        %call_blake_g_function(2, 6, 10, 14, 4, 5)
        %call_blake_g_function(3, 7, 11, 15, 6, 7)
        %call_blake_g_function(0, 5, 10, 15, 8, 9)
        %call_blake_g_function(1, 6, 11, 12, 10, 11)
        %call_blake_g_function(2, 7, 8, 13, 12, 13)
        %call_blake_g_function(3, 4, 9, 14, 14, 15)
        // stack: round, start
        %increment
        // stack: round + 1, start
    %endrep
    
