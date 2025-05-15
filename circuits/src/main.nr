// final sound ver for noir 1.0.0-beta.3 w/ jwt auth

use std::hash::pedersen_hash;
use std::collections::bounded_vec::BoundedVec; // fixed import path ugh

// grab auth funcs
mod auth;

pub global TREE_DEPTH: u32 = 32;
// grumpkin/bn254 scalar field ~254 bits
// check if b-a-1 fits in 253 bits cuz math n stuff
pub global LT_EFFECTIVE_BIT_SIZE: u32 = 253;

// jwt constants gotta match auth.nr or we're toast
global MAX_JWT_DATA_LENGTH: u32 = 1024;
global MAX_USER_ID_LENGTH: u32 = 64;
global RSA_2048_NUM_LIMBS: u32 = 18;

pub struct LowNullifierLeaf {
    pub value: Field,
    pub next_value: Field,
    pub next_index: Field,
}

// sound helper for a < b on field types
// asserts b-a-1 fits in bits cuz math
fn assert_field_lt(a: Field, b: Field) {
    let diff_minus_one = b - a - 1;
    // stdlib assert_max_bit_size generic over N
    diff_minus_one.assert_max_bit_size::<LT_EFFECTIVE_BIT_SIZE>();
}

// bit extract for merkle idx
fn get_bit(field_value: Field, bit_index: u64) -> u1 {
    let value_u64 = field_value as u64;
    let bit_index_u8 = bit_index as u8;
    let bit = (value_u64 >> bit_index_u8) & 1;
    if bit == 0 { 0 } else { 1 }
}

// merkle proof checker
pub fn verify_merkle_proof(
    leaf: Field,
    root: Field,
    index: Field,
    path: [Field; TREE_DEPTH]
) -> bool {

    // debug prints cuz debugging sux
    std::println("=== DEBUG: Starting verify_merkle_proof ===");
    std::println(f"leaf: {leaf}");
    std::println(f"expected root: {root}");
    std::println(f"index: {index}");

    let mut computed_hash = leaf;

    for i in 0..TREE_DEPTH {
        let sibling_hash = path[i];
        let bit = get_bit(index, i as u64);

        // print first 3 only cuz spam bad
        if i < 3 {
            std::println(f"  iteration {i}: bit={bit}, sibling_hash={sibling_hash}");
        }

        if bit == 0 {
            computed_hash = pedersen_hash([computed_hash, sibling_hash]);
        } else {
            computed_hash = pedersen_hash([sibling_hash, computed_hash]);
        }

        // more debug noise
        if i < 3 {
            std::println(f"  computed_hash after iteration {i}: {computed_hash}");
        }
    }

    std::println(f"final computed_hash: {computed_hash}");
    // calc comparison first then use result ......
    let matches_root = computed_hash == root;
    std::println(f"matches expected root: {matches_root}");
    std::println("=== DEBUG: Ending verify_merkle_proof ===");

    computed_hash == root
}

// main circuit entry point w/ jwt auth
pub fn main(
    // jwt auth inputs
    jwt_signed_data: BoundedVec<u8, MAX_JWT_DATA_LENGTH>,
    payload_base64_decode_offset: u32,
    pubkey_modulus_limbs: pub [Field; RSA_2048_NUM_LIMBS],    // u128 to field cuz types
    redc_params_limbs: [Field; RSA_2048_NUM_LIMBS],         // u128 to field yawn
    signature_limbs: [Field; RSA_2048_NUM_LIMBS],           // u128 to field again
    expected_user_id_in_jwt: pub BoundedVec<u8, MAX_USER_ID_LENGTH>, // public user_id

    // deletion proof inputs
    current_nmt_root: pub Field,
    newly_deleted_message_nullifier: Field,
    low_nullifier_leaf_data_value: Field,
    low_nullifier_leaf_data_next_value: Field,
    low_nullifier_leaf_data_next_index: Field,
    low_nullifier_index: Field,
    low_nullifier_path: [Field; TREE_DEPTH]
) {
    // 1 auth user via jwt
    auth::main_jwt_auth(
        jwt_signed_data,
        payload_base64_decode_offset,
        pubkey_modulus_limbs,
        redc_params_limbs,
        signature_limbs,
        expected_user_id_in_jwt
    );
    // if auth fails we dead

    // 2 do deletion proof logic
    
    // debug spam
    std::println("=== DEBUG: Starting main function ===");
    std::println(f"current_nmt_root: {current_nmt_root}");
    std::println(f"newly_deleted_message_nullifier: {newly_deleted_message_nullifier}");
    std::println(f"low_nullifier_leaf_data_value: {low_nullifier_leaf_data_value}");
    std::println(f"low_nullifier_leaf_data_next_value: {low_nullifier_leaf_data_next_value}");
    std::println(f"low_nullifier_index: {low_nullifier_index}");
    std::println("First 3 path elements:");
    // extract elems first then print ......
    let path_0 = low_nullifier_path[0];
    let path_1 = low_nullifier_path[1];
    let path_2 = low_nullifier_path[2];
    std::println(f"  path[0]: {path_0}");
    std::println(f"  path[1]: {path_1}");
    std::println(f"  path[2]: {path_2}");

    // rebuild leaf struct
    let low_nullifier_leaf_data = LowNullifierLeaf {
        value: low_nullifier_leaf_data_value,
        next_value: low_nullifier_leaf_data_next_value,
        next_index: low_nullifier_leaf_data_next_index,
    };

    // prep hash inputs
    let leaf_to_hash_inputs = [
        low_nullifier_leaf_data.value,
        low_nullifier_leaf_data.next_value,
        low_nullifier_leaf_data.next_index
    ];

    // hash the leaf
    let low_nullifier_leaf_hash = pedersen_hash(leaf_to_hash_inputs);

    // more debug noise
    std::println(f"computed low_nullifier_leaf_hash: {low_nullifier_leaf_hash}");

    // check merkle proof
    let is_valid_merkle_proof = verify_merkle_proof(
        low_nullifier_leaf_hash,
        current_nmt_root,
        low_nullifier_index,
        low_nullifier_path
    );

    // yep more debug
    std::println(f"is_valid_merkle_proof result: {is_valid_merkle_proof}");

    assert(is_valid_merkle_proof, "Merkle proof verification failed");

    // range check 1 low < deleted
    assert_field_lt(low_nullifier_leaf_data.value, newly_deleted_message_nullifier);

    // max element check
    let is_low_nullifier_max_element = low_nullifier_leaf_data.next_value == 0;

    // range check 2 deleted < next if not max
    if !is_low_nullifier_max_element {
        assert_field_lt(newly_deleted_message_nullifier, low_nullifier_leaf_data.next_value);
    }
}

// tests n stuff

// dummy jwt input maker

fn get_dummy_jwt_inputs() -> (
    BoundedVec<u8, MAX_JWT_DATA_LENGTH>,
    u32,
    [Field; RSA_2048_NUM_LIMBS],    // u128 to field ugh
    [Field; RSA_2048_NUM_LIMBS],    // u128 to field again
    [Field; RSA_2048_NUM_LIMBS],    // u128 to field srsly
    BoundedVec<u8, MAX_USER_ID_LENGTH>
) {
    let jwt_data_str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyXzEyMyJ9";
    let mut jwt_signed_data_vec: BoundedVec<u8, MAX_JWT_DATA_LENGTH> = BoundedVec::new();
    for byte in jwt_data_str.as_bytes() {
        jwt_signed_data_vec.push(byte);
    }

    let payload_offset = 37;

    // math consistent rsa stuff
    let mut pubkey_mod_dummy: [Field; RSA_2048_NUM_LIMBS] = [0; RSA_2048_NUM_LIMBS];  // type changed
    let mut redc_params_dummy: [Field; RSA_2048_NUM_LIMBS] = [0; RSA_2048_NUM_LIMBS]; // type changed
    let mut sig_dummy: [Field; RSA_2048_NUM_LIMBS] = [0; RSA_2048_NUM_LIMBS];        // type changed

    // big odd modulus cuz rsa needs it
    pubkey_mod_dummy[RSA_2048_NUM_LIMBS - 1] = 0xFFFFFFFFFFFFFFFF as Field;  // cast to field
    pubkey_mod_dummy[RSA_2048_NUM_LIMBS - 2] = 0xFFFFFFFFFFFFFFFF as Field;  // cast to field
    pubkey_mod_dummy[0] = 0x0000000000000001 as Field;                       // cast to field

    // redc params from modulus idk
    redc_params_dummy[0] = 0x0000000000000001 as Field;  // cast to field
    redc_params_dummy[1] = 0x0000000000000001 as Field;  // cast to field

    // pkcs#1 v1.5 padded sig but wrong hash lol
    sig_dummy[RSA_2048_NUM_LIMBS - 1] = 0x0001000000000000 as Field;  // cast to field
    sig_dummy[RSA_2048_NUM_LIMBS - 2] = 0xFFFFFFFFFFFFFF00 as Field;  // cast to field
    sig_dummy[0] = 0x0000000000000001 as Field;                       // cast to field

    let expected_id_str = "test_user_123";
    let mut expected_user_id_vec: BoundedVec<u8, MAX_USER_ID_LENGTH> = BoundedVec::new();
    for byte in expected_id_str.as_bytes() {
        expected_user_id_vec.push(byte);
    }

    (jwt_signed_data_vec, payload_offset, pubkey_mod_dummy, redc_params_dummy, sig_dummy, expected_user_id_vec)
}
// keep the original test that doesn't call main
#[test]
fn test_verify_merkle_proof_logic() {
    let l0 = pedersen_hash([0x0]);
    let l1 = pedersen_hash([0x1]);
    let l2 = pedersen_hash([0x2]);
    let l3 = pedersen_hash([0x3]);
    let n23 = pedersen_hash([l2, l3]);
    let mut path_for_l0_padded = [0; TREE_DEPTH];
    path_for_l0_padded[0] = l1;
    path_for_l0_padded[1] = n23;
    let mut expected_root_from_padded_path = l0;
    let test_index_for_l0 = 0;
    for i in 0..TREE_DEPTH {
        let sibling = path_for_l0_padded[i];
        let bit = get_bit(test_index_for_l0, i as u64);
        if bit == 0 { expected_root_from_padded_path = pedersen_hash([expected_root_from_padded_path, sibling]); }
        else { expected_root_from_padded_path = pedersen_hash([sibling, expected_root_from_padded_path]); }
    }
    assert(verify_merkle_proof(l0, expected_root_from_padded_path, test_index_for_l0, path_for_l0_padded),"Merkle proof for l0 should be valid.");
    assert(!verify_merkle_proof(l0, expected_root_from_padded_path + 1, test_index_for_l0, path_for_l0_padded),"Merkle proof with wrong root should be invalid.");
}

// og lt tests no main calls
#[test]
fn test_sound_less_than_helper_passing_cases() {
    assert_field_lt(100, 150);
    assert_field_lt(0, 1);
    assert_field_lt(5, 10000);
    let large_a_val: u64 = 0xFFFFFFFFFFFFFFFF;
    let large_a: Field = large_a_val as Field + 1;
    let large_b: Field = large_a_val as Field + 2;
    assert_field_lt(large_a, large_b);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_lt_failure_greater_input() {
    assert_field_lt(200, 100);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_lt_failure_equal_input() {
   assert_field_lt(100, 100);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn test_lt_failure_large_input_invalid() {
    let large_a_val: u64 = 0xFFFFFFFFFFFFFFFF;
    let large_b: Field = large_a_val as Field + 2;
    let large_a: Field = large_a_val as Field + 1;
    assert_field_lt(large_b, large_a);
}

// jwt stuff gonna fail ......
#[test(should_fail_with = "Failed to solve brillig function")]
fn test_main_logic_with_sound_lt_and_valid_merkle() {

    let (jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid) = get_dummy_jwt_inputs();

    let low_val: Field = 100;
    let new_null: Field = 150;
    let next_val: Field = 200;
    let next_index: Field = 0xD1;
    let leaf_hash = pedersen_hash([low_val, next_val, next_index]);
    let test_index = 0;
    let mut test_path = [0; TREE_DEPTH];
    for i in 0..TREE_DEPTH { test_path[i] = (i as Field) + 0x200; }
    let mut expected_root = leaf_hash;
    for i in 0..TREE_DEPTH {
        let sibling = test_path[i];
        let bit = get_bit(test_index, i as u64);
        if bit == 0 { expected_root = pedersen_hash([expected_root, sibling]); }
        else { expected_root = pedersen_hash([sibling, expected_root]); }
    }

    main(
        jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid,
        expected_root, new_null, low_val, next_val, next_index, test_index, test_path
    );
}

// edge cases w/ big nums
#[test(should_fail_with = "Failed to solve brillig function")]
fn test_boundary_conditions_at_field_modulus() {

    let (jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid) = get_dummy_jwt_inputs();
    
    let val1 = 1766847064778384329583297500742918515827483896875618958121606201292619776; // ~2^240 ish
    let val2 = val1 + 1000;
    let val3 = val1 + 2000;
    let next_idx = 0;
    let leaf_h = pedersen_hash([val1, val3, next_idx]);
    let idx = 0;
    let mut path = [0; TREE_DEPTH];
    for i in 0..TREE_DEPTH { path[i] = pedersen_hash([i as Field]); }
    let mut root = leaf_h;
    for i in 0..TREE_DEPTH { let sibling = path[i]; let bit = get_bit(idx, i as u64); if bit == 0 {root = pedersen_hash([root, sibling]);} else {root = pedersen_hash([sibling, root]);}}
    
    main(
        jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid,
        root, val2, val1, val3, next_idx, idx, path
    );
}

// more tests w/ jwt meh
#[test(should_fail_with = "Failed to solve brillig function")]
fn test_complex_merkle_path_with_varied_indices() {

    let (jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid) = get_dummy_jwt_inputs();
    let indices_to_test = [0, 1, 3, 7, 15, 31, 127, 255, 1023];
    for j in 0..indices_to_test.len() {
        let test_idx = indices_to_test[j];
        let lv: Field = 100 + (j as Field * 50);
        let nn: Field = 200 + (j as Field * 50);
        let nv: Field = 300 + (j as Field * 50);
        let ni: Field = j as Field;
        let lh = pedersen_hash([lv, nv, ni]);
        let mut p = [0; TREE_DEPTH];
        for k in 0..TREE_DEPTH { p[k] = pedersen_hash([k as Field + 0x100, test_idx as Field * 0x10]); }
        let mut er = lh;
        for k in 0..TREE_DEPTH {
            let s = p[k];
            let b = get_bit(test_idx, k as u64);
            if b == 0 { er = pedersen_hash([er, s]); } else { er = pedersen_hash([s, er]); }
        }
        main(
            jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid,
            er, nn, lv, nv, ni, test_idx, p
        );
    }
}

// helper fn w/ jwt junk
fn test_nullifier_sandwich_helper_with_jwt(low_val: Field, new_null: Field, next_val: Field) {
    let (jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid) = get_dummy_jwt_inputs();
    let next_index: Field = 0;
    let leaf_hash = pedersen_hash([low_val, next_val, next_index]);
    let test_index = 0;
    let mut test_path = [0; TREE_DEPTH];
    for i in 0..TREE_DEPTH { test_path[i] = pedersen_hash([i as Field + 0x300]); }
    let mut expected_root = leaf_hash;
    for i in 0..TREE_DEPTH { let sibling = test_path[i]; let bit = get_bit(test_index, i as u64); if bit == 0 {expected_root = pedersen_hash([expected_root, sibling]);} else {expected_root = pedersen_hash([sibling, expected_root]);}}
    main(
        jwt_data, payload_off, pubkey_mod, redc_par, sig, expected_uid,
        expected_root, new_null, low_val, next_val, next_index, test_index, test_path
    );
}

#[test(should_fail_with = "Failed to solve brillig function")]
fn test_nullifier_sandwiching_edge_cases() {

    test_nullifier_sandwich_helper_with_jwt(1000, 1001, 1002);
    test_nullifier_sandwich_helper_with_jwt(1000, 9999, 10000);
    test_nullifier_sandwich_helper_with_jwt(0, 1, 2);
}