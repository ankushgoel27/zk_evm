use anyhow::Result;
use blake2::Blake2b512;
use ethereum_types::{U256, U512};
use rand::{thread_rng, Rng};
use ripemd::{Digest, Ripemd160};
use sha2::Sha256;

use crate::cpu::kernel::interpreter::InterpreterSetup;
use crate::memory::segments::Segment::KernelGeneral;

/// Standard Blake2b implementation.
fn blake2b(input: Vec<u8>) -> U512 {
    let mut hasher = Blake2b512::new();
    hasher.update(input);
    U512::from(&hasher.finalize()[..])
}

/// Standard RipeMD implementation.
fn ripemd(input: Vec<u8>) -> U256 {
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    U256::from(&hasher.finalize()[..])
}

/// Standard Sha2 implementation.
fn sha2(input: Vec<u8>) -> U256 {
    let mut hasher = Sha256::new();
    hasher.update(input);
    U256::from(&hasher.finalize()[..])
}

fn make_random_input() -> Vec<u8> {
    // Generate a random message, between 0 and 9999 bytes.
    let mut rng = thread_rng();
    let num_bytes = rng.gen_range(0..10000);
    (0..num_bytes).map(|_| rng.gen()).collect()
}

fn make_custom_input() -> Vec<u8> {
    // Hardcode a custom message
    vec![
        86, 124, 206, 245, 74, 57, 250, 43, 60, 30, 254, 43, 143, 144, 242, 215, 13, 103, 237, 61,
        90, 105, 123, 250, 189, 181, 110, 192, 227, 57, 145, 46, 221, 238, 7, 181, 146, 111, 209,
        150, 31, 157, 229, 126, 206, 105, 37, 17,
    ]
}

fn combine_u256s(hi: U256, lo: U256) -> U512 {
    let mut result = U512::from(hi);
    result <<= 256;
    result += U512::from(lo);
    result
}

fn prepare_test<T>(
    hash_fn_label: &str,
    standard_implementation: &dyn Fn(Vec<u8>) -> T,
) -> Result<(T, T, Vec<U256>, Vec<U256>)> {
    // Make the input.
    let message_random = make_random_input();
    let message_custom = make_custom_input();

    // Hash the message using a standard implementation.
    let expected_random = standard_implementation(message_random.clone());
    let expected_custom = standard_implementation(message_custom.clone());

    let inp: usize = 136;

    // Load the message into the kernel.
    let interpreter_setup_random = InterpreterSetup {
        label: hash_fn_label.to_string(),
        stack: vec![
            U256::from(inp),
            U256::from(message_random.len()),
            U256::from(0xdeadbeefu32),
        ],
        segment: KernelGeneral,
        memory: vec![(
            inp,
            message_random
                .iter()
                .map(|&x| U256::from(x as u32))
                .collect(),
        )],
    };

    let interpreter_setup_custom = InterpreterSetup {
        label: hash_fn_label.to_string(),
        stack: vec![
            U256::from(inp),
            U256::from(message_custom.len()),
            U256::from(0xdeadbeefu32),
        ],
        segment: KernelGeneral,
        memory: vec![(
            inp,
            message_custom
                .iter()
                .map(|&x| U256::from(x as u32))
                .collect(),
        )],
    };

    // Run the kernel code.
    let result_random = interpreter_setup_random.run().unwrap();
    let result_custom = interpreter_setup_custom.run().unwrap();

    Ok((
        expected_random,
        expected_custom,
        result_random.stack().to_vec(),
        result_custom.stack().to_vec(),
    ))
}

fn test_hash_256(
    hash_fn_label: &str,
    standard_implementation: &dyn Fn(Vec<u8>) -> U256,
) -> Result<()> {
    let (expected_random, expected_custom, random_stack, custom_stack) =
        prepare_test(hash_fn_label, standard_implementation).unwrap();

    // Extract the final output.
    let actual_random = random_stack[0];
    let actual_custom = custom_stack[0];

    // Check that the result is correct.
    assert_eq!(expected_random, actual_random);
    assert_eq!(expected_custom, actual_custom);

    Ok(())
}

fn test_hash_512(
    hash_fn_label: &str,
    standard_implementation: &dyn Fn(Vec<u8>) -> U512,
) -> Result<()> {
    let (expected_random, expected_custom, random_stack, custom_stack) =
        prepare_test(hash_fn_label, standard_implementation).unwrap();

    // Extract the final output.
    let actual_random = combine_u256s(random_stack[0], random_stack[1]);
    let actual_custom = combine_u256s(custom_stack[0], custom_stack[1]);

    // Check that the result is correct.
    assert_eq!(expected_random, actual_random);
    assert_eq!(expected_custom, actual_custom);

    Ok(())
}

// #[test]
// fn test_blake2b() -> Result<()> {
//     test_hash_512("blake2b", &blake2b)
// }

#[test]
fn test_ripemd() -> Result<()> {
    test_hash_256("ripemd", &ripemd)
}

// #[test]
// fn test_sha2() -> Result<()> {
//     test_hash_256("sha2", &sha2)
// }
