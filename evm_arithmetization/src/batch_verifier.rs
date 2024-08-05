use std::iter::once;

use anyhow::{ensure, Result};
use ethereum_types::{BigEndianHash, U256};
use hashbrown::HashMap;
use itertools::Itertools;
use plonky2::batch_fri::verifier::verify_batch_fri_proof;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use starky::batch_proof::{BatchStarkProof, BatchStarkProofWithPublicInputs};
use starky::config::StarkConfig;
use starky::cross_table_lookup::{
    get_ctl_vars_from_proofs, num_ctl_helper_columns_by_table, verify_cross_table_lookups,
    CtlCheckVars,
};
use starky::evaluation_frame::StarkEvaluationFrame;
use starky::lookup::{get_grand_product_challenge_set, GrandProductChallenge};
use starky::proof::{StarkOpeningSet, StarkProofChallenges};
use starky::stark::Stark;
use starky::verifier::{verify_opening_set, verify_stark_proof_with_challenges};

use crate::all_stark::{
    AllStark, Table, ALL_DEGREE_LOGS, ALL_SORTED_TABLES, NUM_TABLES, TABLE_TO_SORTED_INDEX,
};
use crate::batch_proof::EvmProof;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::get_challenges::observe_public_values;
use crate::memory::segments::Segment;
use crate::memory::VALUE_LIMBS;
use crate::proof::{AllProof, AllProofChallenges, MemCap, PublicValues};
use crate::prover::all_fri_instance_info;
use crate::util::h2u;

/// Verify a batched STARK EVM proof.
pub fn verify_evm_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    all_stark: &AllStark<F, D>,
    evm_proof: EvmProof<F, C, D>,
    config: &StarkConfig,
    is_initial: bool,
) -> Result<()> {
    // let mut challenger = Challenger::<F, C::Hasher>::new();

    let challenges = evm_proof
        .get_challenges(&config)
        .expect("Bad EVM proof challenges?");

    let openings = &evm_proof.batch_proof.openings;

    let num_lookup_columns = all_stark.num_lookups_helper_columns(config);

    let all_ctl_helper_columns = num_ctl_helper_columns_by_table(
        &all_stark.cross_table_lookups,
        all_stark.arithmetic_stark.constraint_degree(),
    );

    let num_ctl_helper_columns_per_table = (0..NUM_TABLES)
        .map(|i| {
            all_ctl_helper_columns
                .iter()
                .map(|ctl_cols: &[usize; NUM_TABLES]| ctl_cols[i])
                .sum()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let ctl_vars_per_table = CtlCheckVars::from_proofs::<C, NUM_TABLES>(
        openings,
        &all_stark.cross_table_lookups,
        &challenges
            .lookup_challenge_set
            .as_ref()
            .expect("No lookup challenges?"),
        &num_lookup_columns,
        &all_ctl_helper_columns,
    );

    verify_all_openings(
        all_stark,
        &evm_proof,
        &challenges,
        &ctl_vars_per_table,
        config,
    )?;

    let mut degree_bits_squashed = ALL_DEGREE_LOGS.to_vec();
    degree_bits_squashed.dedup();

    let merkle_caps = once(evm_proof.batch_proof.trace_cap.clone())
        .chain(evm_proof.batch_proof.auxiliary_polys_cap.clone())
        .chain(evm_proof.batch_proof.quotient_polys_cap.clone())
        .collect_vec();

    let num_trace_polys_sorted_per_table = (0..NUM_TABLES)
        .map(|i| openings[*ALL_SORTED_TABLES[i]].local_values.len())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let num_auxiliary_columns_sorted_per_table = (0..NUM_TABLES)
        .map(|i| {
            openings[*ALL_SORTED_TABLES[i]]
                .auxiliary_polys
                .as_ref()
                .expect("No auxiliary polys?")
                .len()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let num_quotient_polys_sorted_per_table = (0..NUM_TABLES)
        .map(|i| {
            openings[*ALL_SORTED_TABLES[i]]
                .quotient_polys
                .as_ref()
                .expect("No quotient polys?")
                .len()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let instances = all_fri_instance_info::<F, C, D>(
        all_stark,
        challenges.stark_zeta,
        &num_trace_polys_sorted_per_table,
        &num_auxiliary_columns_sorted_per_table,
        &num_quotient_polys_sorted_per_table,
        &num_ctl_helper_columns_per_table,
        config,
    );

    let fri_openings = openings
        .iter()
        .map(|opening| opening.to_fri_openings())
        .collect::<Vec<_>>();

    verify_batch_fri_proof::<F, C, D>(
        &degree_bits_squashed,
        &instances,
        &fri_openings,
        &challenges.fri_challenges,
        &merkle_caps,
        &evm_proof.batch_proof.opening_proof,
        &config.fri_params(degree_bits_squashed[0]),
    )

    // Ok(())
}

fn verify_all_openings<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const N: usize,
>(
    all_stark: &AllStark<F, D>,
    evm_proof: &EvmProof<F, C, D>,
    challenges: &StarkProofChallenges<F, D>,
    ctl_vars_per_table: &[Vec<CtlCheckVars<F, <F as Extendable<D>>::Extension, <F as Extendable<D>>::Extension, D>>;
         N],
    config: &StarkConfig,
) -> Result<()> {
    let openings = &evm_proof.batch_proof.openings;

    // Arithmetic.
    {
        let stark = &all_stark.arithmetic_stark;
        let table = Table::Arithmetic;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // BytePacking.
    {
        let stark = &all_stark.byte_packing_stark;
        let table = Table::BytePacking;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // Cpu.
    {
        let stark = &all_stark.cpu_stark;
        let table = Table::Cpu;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // Keccak.
    {
        let stark = &all_stark.keccak_stark;
        let table = Table::Keccak;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // KeccakSponge.
    {
        let stark = &all_stark.keccak_sponge_stark;
        let table = Table::KeccakSponge;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // Logic.
    {
        let stark = &all_stark.logic_stark;
        let table = Table::Logic;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // Memory.
    {
        let stark = &all_stark.memory_stark;
        let table = Table::Memory;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // MemBefore.
    {
        let stark = &all_stark.mem_before_stark;
        let table = Table::MemBefore;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    // MemAfter.
    {
        let stark = &all_stark.mem_after_stark;
        let table = Table::MemAfter;
        verify_opening_set::<F, C, _, D>(
            stark,
            &openings[*table],
            ALL_DEGREE_LOGS[TABLE_TO_SORTED_INDEX[*table]],
            challenges,
            Some(&ctl_vars_per_table[*table]),
            config,
        );
    }

    Ok(())
}
