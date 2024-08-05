use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueHint};
use zero_bin_common::prover_state::cli::CliProverStateConfig;

#[derive(Parser)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    /// The file containing the proof to verify
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    pub(crate) file_path: PathBuf,
    /// The prover configuration used to generate the preprocessed circuits
    /// and the verifier state.
    #[clap(flatten)]
    pub(crate) prover_state_config: CliProverStateConfig,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Verifies a block proof for a given chain.
    VerifyBlock,
    /// Verifies an aggregation of independent block proofs.
    VerifyAggreg,
}
