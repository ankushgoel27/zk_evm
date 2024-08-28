use std::{
    collections::{HashMap, HashSet},
    ops::Not,
    sync::OnceLock,
};

use __compat_primitive_types::{H256, U256};
use alloy::{
    primitives::{keccak256, Address, B256, U160},
    providers::{
        ext::DebugApi as _,
        network::{eip2718::Encodable2718, Ethereum, Network},
        Provider,
    },
    rpc::types::{
        eth::Transaction,
        eth::{AccessList, Block},
        trace::geth::{
            AccountState, DefaultFrame, DiffMode, GethDebugBuiltInTracerType, GethDebugTracerType,
            GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, PreStateConfig,
            PreStateFrame, PreStateMode,
        },
    },
    transports::Transport,
};
use anyhow::{ensure, Context as _};
use evm_arithmetization::{jumpdest::JumpDestTableWitness, CodeDb};
use futures::stream::{FuturesOrdered, TryStreamExt};
use trace_decoder::{ContractCodeUsage, TxnInfo, TxnMeta, TxnTrace};
use tracing::trace;

use crate::Compat;

/// Provides a way to check in constant time if an address points to a
/// precompile.
fn precompiles() -> &'static HashSet<Address> {
    static PRECOMPILES: OnceLock<HashSet<Address>> = OnceLock::new();
    PRECOMPILES.get_or_init(|| {
        HashSet::<Address>::from_iter((1..=0xa).map(|x| Address::from(U160::from(x))))
    })
}

/// Provides a way to check in constant time if `op` is in the set of normal
/// halting states. They are defined in the Yellowpaper, 9.4.4. Normal Halting.
fn normal_halting() -> &'static HashSet<&'static str> {
    static NORMAL_HALTING: OnceLock<HashSet<&str>> = OnceLock::new();
    NORMAL_HALTING.get_or_init(|| HashSet::<&str>::from_iter(["RETURN", "REVERT", "STOP"]))
}

/// Processes the transactions in the given block and updates the code db.
pub(super) async fn process_transactions<ProviderT, TransportT>(
    block: &Block,
    provider: &ProviderT,
) -> anyhow::Result<(CodeDb, Vec<TxnInfo>)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    block
        .transactions
        .as_transactions()
        .context("No transactions in block")?
        .iter()
        .map(|tx| process_transaction(provider, tx))
        .collect::<FuturesOrdered<_>>()
        .try_fold(
            (HashMap::new(), Vec::new()),
            |(mut code_db, mut txn_infos), (tx_code_db, txn_info)| async move {
                code_db.extend(tx_code_db);
                txn_infos.push(txn_info);
                Ok((code_db, txn_infos))
            },
        )
        .await
}

/// Processes the transaction with the given transaction hash and updates the
/// accounts state.
async fn process_transaction<ProviderT, TransportT>(
    provider: &ProviderT,
    tx: &Transaction,
) -> anyhow::Result<(CodeDb, TxnInfo)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let (tx_receipt, pre_trace, diff_trace, structlog_trace) =
        fetch_tx_data(provider, &tx.hash).await?;
    let tx_status = tx_receipt.status();
    let tx_receipt = tx_receipt.map_inner(rlp::map_receipt_envelope);
    let access_list = parse_access_list(tx.access_list.as_ref());

    let (code_db, mut tx_traces) = match (pre_trace, diff_trace) {
        (
            GethTrace::PreStateTracer(PreStateFrame::Default(read)),
            GethTrace::PreStateTracer(PreStateFrame::Diff(diff)),
        ) => process_tx_traces(access_list, read, diff).await?,
        _ => unreachable!(),
    };

    // Handle case when transaction failed and a contract creation was reverted
    if !tx_status && tx_receipt.contract_address.is_some() {
        tx_traces.insert(tx_receipt.contract_address.unwrap(), TxnTrace::default());
    }
    let jumpdest_table: Option<JumpDestTableWitness> =
        if let GethTrace::Default(structlog_frame) = structlog_trace {
            generate_jumpdest_table(tx, &structlog_frame, &tx_traces)
                .await
                .map(Some)
                .unwrap_or_default()
        } else {
            unreachable!()
        };

    let tx_meta = TxnMeta {
        byte_code: <Ethereum as Network>::TxEnvelope::try_from(tx.clone())?.encoded_2718(),
        new_receipt_trie_node_byte: alloy::rlp::encode(tx_receipt.inner),
        gas_used: tx_receipt.gas_used as u64,
        jumpdest_table,
    };

    Ok((
        code_db,
        TxnInfo {
            meta: tx_meta,
            traces: tx_traces
                .into_iter()
                .map(|(k, v)| (k.compat(), v))
                .collect(),
        },
    ))
}

/// Fetches the transaction data for the given transaction hash.
async fn fetch_tx_data<ProviderT, TransportT>(
    provider: &ProviderT,
    tx_hash: &B256,
) -> anyhow::Result<(
    <Ethereum as Network>::ReceiptResponse,
    GethTrace,
    GethTrace,
    GethTrace,
)>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let tx_receipt_fut = provider.get_transaction_receipt(*tx_hash);
    let pre_trace_fut = provider.debug_trace_transaction(*tx_hash, prestate_tracing_options(false));
    let diff_trace_fut = provider.debug_trace_transaction(*tx_hash, prestate_tracing_options(true));
    let structlog_trace_fut =
        provider.debug_trace_transaction(*tx_hash, structlog_tracing_options());

    let (tx_receipt, pre_trace, diff_trace, structlog_trace) = futures::try_join!(
        tx_receipt_fut,
        pre_trace_fut,
        diff_trace_fut,
        structlog_trace_fut
    )?;

    Ok((
        tx_receipt.context("Transaction receipt not found.")?,
        pre_trace,
        diff_trace,
        structlog_trace,
    ))
}

/// Parse the access list data into a hashmap.
fn parse_access_list(access_list: Option<&AccessList>) -> HashMap<Address, HashSet<H256>> {
    let mut result = HashMap::new();

    if let Some(access_list) = access_list {
        for item in access_list.0.clone() {
            result
                .entry(item.address)
                .or_insert_with(HashSet::new)
                .extend(item.storage_keys.into_iter().map(Compat::compat));
        }
    }

    result
}

/// Processes the transaction traces and updates the accounts state.
async fn process_tx_traces(
    mut access_list: HashMap<Address, HashSet<H256>>,
    read_trace: PreStateMode,
    diff_trace: DiffMode,
) -> anyhow::Result<(CodeDb, HashMap<Address, TxnTrace>)> {
    let DiffMode {
        pre: pre_trace,
        post: post_trace,
    } = diff_trace;

    let addresses: HashSet<_> = read_trace
        .0
        .keys()
        .chain(post_trace.keys())
        .chain(pre_trace.keys())
        .chain(access_list.keys())
        .copied()
        .collect();

    let mut traces = HashMap::new();
    let mut code_db: CodeDb = HashMap::new();

    for address in addresses {
        let read_state = read_trace.0.get(&address);
        let pre_state = pre_trace.get(&address);
        let post_state = post_trace.get(&address);

        let balance = post_state.and_then(|x| x.balance.map(Compat::compat));
        let (storage_read, storage_written) = process_storage(
            access_list.remove(&address).unwrap_or_default(),
            read_state,
            post_state,
            pre_state,
        );
        let code = process_code(post_state, read_state, &mut code_db).await;
        let nonce = process_nonce(post_state, &code);
        let self_destructed = process_self_destruct(post_state, pre_state);

        let result = TxnTrace {
            balance,
            nonce,
            storage_read,
            storage_written,
            code_usage: code,
            self_destructed,
        };

        traces.insert(address, result);
    }

    Ok((code_db, traces))
}

/// Processes the nonce for the given account state.
///
/// If a contract is created, the nonce is set to 1.
fn process_nonce(
    post_state: Option<&AccountState>,
    code_usage: &Option<ContractCodeUsage>,
) -> Option<U256> {
    post_state
        .and_then(|x| x.nonce.map(Into::into))
        .or_else(|| {
            if let Some(ContractCodeUsage::Write(_)) = code_usage.as_ref() {
                Some(U256::from(1))
            } else {
                None
            }
        })
}

/// Processes the self destruct for the given account state.
/// This wraps the actual boolean indicator into an `Option` so that we can skip
/// serialization of `None` values, which represent most cases.
fn process_self_destruct(
    post_state: Option<&AccountState>,
    pre_state: Option<&AccountState>,
) -> Option<bool> {
    if post_state.is_none() {
        // EIP-6780:
        // A contract is considered created at the beginning of a create
        // transaction or when a CREATE series operation begins execution (CREATE,
        // CREATE2, and other operations that deploy contracts in the future). If a
        // balance exists at the contract’s new address it is still considered to be a
        // contract creation.
        if let Some(acc) = pre_state {
            if acc.code.is_none() && acc.storage.keys().collect::<Vec<_>>().is_empty() {
                return Some(true);
            }
        }
    }

    None
}

/// Processes the storage for the given account state.
///
/// Returns the storage read and written for the given account in the
/// transaction and updates the storage keys.
fn process_storage(
    access_list: HashSet<__compat_primitive_types::H256>,
    acct_state: Option<&AccountState>,
    post_acct: Option<&AccountState>,
    pre_acct: Option<&AccountState>,
) -> (Option<Vec<H256>>, Option<HashMap<H256, U256>>) {
    let mut storage_read = access_list;
    storage_read.extend(
        acct_state
            .map(|acct| {
                acct.storage
                    .keys()
                    .copied()
                    .map(Compat::compat)
                    .collect::<Vec<H256>>()
            })
            .unwrap_or_default(),
    );

    let mut storage_written: HashMap<H256, U256> = post_acct
        .map(|x| {
            x.storage
                .iter()
                .map(|(k, v)| ((*k).compat(), U256::from_big_endian(&v.0)))
                .collect()
        })
        .unwrap_or_default();

    // Add the deleted keys to the storage written
    if let Some(pre_acct) = pre_acct {
        for key in pre_acct.storage.keys() {
            storage_written
                .entry((*key).compat())
                .or_insert(U256::zero());
        }
    };

    (
        Option::from(storage_read.into_iter().collect::<Vec<H256>>()).filter(|v| !v.is_empty()),
        Option::from(storage_written).filter(|v| !v.is_empty()),
    )
}

/// Processes the code usage for the given account state.
async fn process_code(
    post_state: Option<&AccountState>,
    read_state: Option<&AccountState>,
    code_db: &mut CodeDb,
) -> Option<ContractCodeUsage> {
    match (
        post_state.and_then(|x| x.code.as_ref()),
        read_state.and_then(|x| x.code.as_ref()),
    ) {
        (Some(post_code), _) => {
            let code_hash = keccak256(post_code).compat();
            code_db.insert(code_hash, post_code.to_vec());
            Some(ContractCodeUsage::Write(post_code.to_vec()))
        }
        (_, Some(read_code)) => {
            let code_hash = keccak256(read_code).compat();
            code_db.insert(code_hash, read_code.to_vec());

            Some(ContractCodeUsage::Read(code_hash))
        }
        _ => None,
    }
}

mod rlp {
    use alloy::consensus::{Receipt, ReceiptEnvelope};
    use alloy::rpc::types::eth::ReceiptWithBloom;

    pub fn map_receipt_envelope(
        rpc: ReceiptEnvelope<alloy::rpc::types::eth::Log>,
    ) -> ReceiptEnvelope<alloy::primitives::Log> {
        match rpc {
            ReceiptEnvelope::Legacy(it) => ReceiptEnvelope::Legacy(map_receipt_with_bloom(it)),
            ReceiptEnvelope::Eip2930(it) => ReceiptEnvelope::Eip2930(map_receipt_with_bloom(it)),
            ReceiptEnvelope::Eip1559(it) => ReceiptEnvelope::Eip1559(map_receipt_with_bloom(it)),
            ReceiptEnvelope::Eip4844(it) => ReceiptEnvelope::Eip4844(map_receipt_with_bloom(it)),
            other => panic!("unsupported receipt type: {:?}", other),
        }
    }
    fn map_receipt_with_bloom(
        rpc: ReceiptWithBloom<alloy::rpc::types::eth::Log>,
    ) -> ReceiptWithBloom<alloy::primitives::Log> {
        let ReceiptWithBloom {
            receipt:
                Receipt {
                    status,
                    cumulative_gas_used,
                    logs,
                },
            logs_bloom,
        } = rpc;
        ReceiptWithBloom {
            receipt: Receipt {
                status,
                cumulative_gas_used,
                logs: logs.into_iter().map(|it| it.inner).collect(),
            },
            logs_bloom,
        }
    }
}

/// Tracing options for the debug_traceTransaction call.
fn prestate_tracing_options(diff_mode: bool) -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        tracer_config: PreStateConfig {
            diff_mode: Some(diff_mode),
        }
        .into(),
        tracer: Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::PreStateTracer,
        )),
        ..GethDebugTracingOptions::default()
    }
}

/// Tracing options for the `debug_traceTransaction` call to get structlog.
/// Used for filling JUMPDEST table.
fn structlog_tracing_options() -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        config: GethDefaultTracingOptions {
            disable_stack: Some(false),
            disable_memory: Some(true),
            disable_storage: Some(true),
            ..GethDefaultTracingOptions::default()
        },
        tracer: None,
        ..GethDebugTracingOptions::default()
    }
}

/// Generate at JUMPDEST table by simulating the call stack in EVM,
/// using a Geth structlog as input.
async fn generate_jumpdest_table(
    tx: &Transaction,
    structlog_trace: &DefaultFrame,
    tx_traces: &HashMap<Address, TxnTrace>,
) -> anyhow::Result<JumpDestTableWitness> {
    trace!("Generating JUMPDEST table for tx: {}", tx.hash);
    ensure!(
        structlog_trace.struct_logs.is_empty().not(),
        "Structlog is empty."
    );

    let mut jumpdest_table = JumpDestTableWitness::default();

    let callee_addr_to_code_hash: HashMap<Address, H256> = tx_traces
        .iter()
        .map(|(callee_addr, trace)| (callee_addr, &trace.code_usage))
        .filter(|(_callee_addr, code_usage)| code_usage.is_some())
        .map(|(callee_addr, code_usage)| {
            (*callee_addr, code_usage.as_ref().unwrap().get_code_hash())
        })
        .collect();

    ensure!(
        tx.to.is_some(),
        format!("No `to`-address for tx: {}.", tx.hash)
    );
    let to_address: Address = tx.to.unwrap();

    // Guard against transactions to a non-contract address.
    ensure!(
        callee_addr_to_code_hash.contains_key(&to_address),
        format!("Callee addr {} is not at contract address", to_address)
    );
    let entrypoint_code_hash: H256 = callee_addr_to_code_hash[&to_address];

    // `None` encodes that previous `entry`` was not a JUMP or JUMPI with true
    // condition, `Some(jump_target)` encodes we came from a JUMP or JUMPI with
    // true condition and target `jump_target`.
    let mut prev_jump = None;

    // Contains the previous op.
    let mut prev_op = "";

    // Call depth of the previous `entry`. We initialize to 0 as this compares
    // smaller to 1.
    let mut prev_depth = 0;
    // The next available context. Starts at 1. Never decrements.
    let mut next_ctx_available = 1;
    // Immediately use context 1;
    let mut call_stack = vec![(entrypoint_code_hash, next_ctx_available)];
    next_ctx_available += 1;

    for (step, entry) in structlog_trace.struct_logs.iter().enumerate() {
        let op = entry.op.as_str();
        let curr_depth = entry.depth;

        let exception_occurred = prev_entry_caused_exception(prev_op, prev_depth, curr_depth);
        if exception_occurred {
            ensure!(
                call_stack.is_empty().not(),
                "Call stack was empty after exception."
            );
            // discard callee frame and return control to caller.
            call_stack.pop().unwrap();
        }

        ensure!(
            entry.depth as usize <= next_ctx_available,
            "Structlog is malformed."
        );
        ensure!(call_stack.is_empty().not(), "Call stack was empty.");
        let (code_hash, ctx) = call_stack.last().unwrap();
        trace!("TX:   {:?}", tx.hash);
        trace!("STEP: {:?}", step);
        trace!("STEPS: {:?}", structlog_trace.struct_logs.len());
        trace!("PREV OPCODE: {}", prev_op);
        trace!("OPCODE: {}", entry.op.as_str());
        trace!("CODE: {:?}", code_hash);
        trace!("CTX:  {:?}", ctx);
        trace!("EXCEPTION OCCURED: {:?}", exception_occurred);
        trace!("PREV_DEPTH:  {:?}", prev_depth);
        trace!("CURR_DEPTH:  {:?}", curr_depth);
        trace!("{:#?}\n", entry);

        match op {
            "CALL" | "CALLCODE" | "DELEGATECALL" | "STATICCALL" => {
                let callee_address = {
                    // This is the same stack index (i.e. 2nd) for all four opcodes. See https://ethervm.io/#F1
                    ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                    let mut evm_stack = entry.stack.as_ref().unwrap().iter().rev();

                    let callee_raw_opt = evm_stack.nth(1);
                    ensure!(
                        callee_raw_opt.is_some(),
                        "Stack must contain at least two values for a CALL instruction."
                    );
                    let callee_raw = *callee_raw_opt.unwrap();

                    let lower_bytes = U160::from(callee_raw);
                    Address::from(lower_bytes)
                };

                if precompiles().contains(&callee_address) {
                    trace!("Called precompile at address {}.", &callee_address);
                } else if callee_addr_to_code_hash.contains_key(&callee_address) {
                    let code_hash = callee_addr_to_code_hash[&callee_address];
                    call_stack.push((code_hash, next_ctx_available));
                } else {
                    // This case happens if calling an EOA. This is described
                    // under opcode `STOP`: https://www.evm.codes/#00?fork=cancun
                    trace!(
                        "Callee address {} has no associated `code_hash`.",
                        &callee_address
                    );
                }
                next_ctx_available += 1;
                prev_jump = None;
            }
            "JUMP" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                let mut evm_stack = entry.stack.as_ref().unwrap().iter().rev();

                let jump_target_opt = evm_stack.next();
                ensure!(
                    jump_target_opt.is_some(),
                    "Stack must contain at least one value for a JUMP instruction."
                );
                let jump_target = jump_target_opt.unwrap().to::<u64>();

                prev_jump = Some(jump_target);
            }
            "JUMPI" => {
                ensure!(entry.stack.as_ref().is_some(), "No evm stack found.");
                let mut evm_stack = entry.stack.as_ref().unwrap().iter().rev();

                let jump_target_opt = evm_stack.next();
                ensure!(
                    jump_target_opt.is_some(),
                    "Stack must contain at least one value for a JUMPI instruction."
                );
                let jump_target = jump_target_opt.unwrap().to::<u64>();

                let jump_condition_opt = evm_stack.next();
                ensure!(
                    jump_condition_opt.is_some(),
                    "Stack must contain at least two values for a JUMPI instruction."
                );
                let jump_condition = jump_condition_opt.unwrap().is_zero().not();

                prev_jump = if jump_condition {
                    Some(jump_target)
                } else {
                    None
                };
            }
            "JUMPDEST" => {
                ensure!(
                    call_stack.is_empty().not(),
                    "Call stack was empty when a JUMPDEST was encountered."
                );
                let (code_hash, ctx) = call_stack.last().unwrap();
                let jumped_here = if let Some(jmp_target) = prev_jump {
                    ensure!(
                        jmp_target == entry.pc,
                        "The structlog seems to make improper JUMPs."
                    );
                    true
                } else {
                    false
                };
                let jumpdest_offset = entry.pc as usize;
                if jumped_here {
                    jumpdest_table.insert(code_hash, *ctx, jumpdest_offset);
                }
                // else: we do not care about JUMPDESTs reached through fall-through.
                prev_jump = None;
            }
            "EXTCODECOPY" | "EXTCODESIZE" => {
                next_ctx_available += 1;
                prev_jump = None;
            }
            "RETURN" | "REVERT" | "STOP" => {
                ensure!(call_stack.is_empty().not(), "Call stack was empty at POP.");
                call_stack.pop().unwrap();
                prev_jump = None;
            }
            _ => {
                prev_jump = None;
            }
        }

        prev_depth = curr_depth;
        prev_op = op;
    }
    Ok(jumpdest_table)
}

/// Check if an exception occurred. An exception will cause the current call
/// context at `depth` to yield control to the caller context at `depth-1`.
/// Returning statements, viz. RETURN, REVERT, STOP, do this too, so we need to
/// exclude them.
fn prev_entry_caused_exception(prev_entry: &str, prev_depth: u64, curr_depth: u64) -> bool {
    prev_depth > curr_depth && normal_halting().contains(&prev_entry).not()
}
