// In ~/ephemeral-echo/circuits/src/auth.nr

use dep::noir_jwt::JWT;
use std::collections::bounded_vec::BoundedVec;

// These globals might be referenced from main.nr if not redefined there.
pub global MAX_JWT_DATA_LENGTH_AUTH: u32 = 1024;
pub global MAX_USER_ID_LENGTH_AUTH: u32 = 64;
pub global RSA_2048_NUM_LIMBS_AUTH: u32 = 18;

// Keep Field arrays in our function signature as requested
pub fn main_jwt_auth(
    jwt_signed_data: BoundedVec<u8, MAX_JWT_DATA_LENGTH_AUTH>,
    payload_base64_decode_offset: u32,
    pubkey_modulus_limbs: [Field; RSA_2048_NUM_LIMBS_AUTH],
    redc_params_limbs: [Field; RSA_2048_NUM_LIMBS_AUTH],
    signature_limbs: [Field; RSA_2048_NUM_LIMBS_AUTH],
    expected_user_id: BoundedVec<u8, MAX_USER_ID_LENGTH_AUTH>
) {
    // Convert Field arrays to u128 arrays for JWT library
    let mut pubkey_modulus_u128: [u128; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    let mut redc_params_u128: [u128; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    let mut signature_u128: [u128; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    
    for i in 0..RSA_2048_NUM_LIMBS_AUTH {
        pubkey_modulus_u128[i] = pubkey_modulus_limbs[i] as u128;
        redc_params_u128[i] = redc_params_limbs[i] as u128;
        signature_u128[i] = signature_limbs[i] as u128;
    }
    
    let jwt_verifier = JWT::init(
        jwt_signed_data,
        payload_base64_decode_offset,
        pubkey_modulus_u128,
        redc_params_u128,
        signature_u128,
    );

    // This will assert internally if the signature is invalid.
    jwt_verifier.verify();

    // This will assert internally if the claim doesn't match or isn't found.
    jwt_verifier.assert_claim_string("user_id".as_bytes(), expected_user_id);
}

// ==================== Tests ====================

// Test 1: Changed name to avoid duplicate
#[test(should_fail_with = "Failed to solve brillig function")]
fn test_auth_main_jwt_auth_dummy_fail_signature() {

    let jwt_data_str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyXzEyMyJ9";
    let mut jwt_signed_data_vec: BoundedVec<u8, MAX_JWT_DATA_LENGTH_AUTH> = BoundedVec::new();
    for byte in jwt_data_str.as_bytes() {
        jwt_signed_data_vec.push(byte);
    }

    let payload_offset = 37;

    let mut pubkey_mod_dummy: [Field; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    for i in 0..RSA_2048_NUM_LIMBS_AUTH {
        pubkey_mod_dummy[i] = (i + 1) as Field;
    }

    let mut redc_params_dummy: [Field; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    for i in 0..RSA_2048_NUM_LIMBS_AUTH {
        redc_params_dummy[i] = (i + 100) as Field;
    }

    let mut sig_dummy: [Field; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    for i in 0..RSA_2048_NUM_LIMBS_AUTH {
        sig_dummy[i] = (i + 200) as Field;
    }

    let expected_id_str = "test_user_123";
    let mut expected_user_id_vec: BoundedVec<u8, MAX_USER_ID_LENGTH_AUTH> = BoundedVec::new();
    for byte in expected_id_str.as_bytes() {
        expected_user_id_vec.push(byte);
    }

    main_jwt_auth(
        jwt_signed_data_vec,
        payload_offset,
        pubkey_mod_dummy,
        redc_params_dummy,
        sig_dummy,
        expected_user_id_vec
    );
}

// Test 2: Changed name and fixed bit shift and arithmetic
#[test(should_fail_with = "Failed to solve brillig function")]
fn test_auth_main_jwt_auth_dummy_fail_brillig() {
    let jwt_data_str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyXzEyMyJ9";
    let mut jwt_signed_data_vec: BoundedVec<u8, MAX_JWT_DATA_LENGTH_AUTH> = BoundedVec::new();
    for byte in jwt_data_str.as_bytes() {
        jwt_signed_data_vec.push(byte);
    }

    let payload_offset = 37;

    // Use more realistic values
    let mut pubkey_mod_dummy: [Field; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    let mut redc_params_dummy: [Field; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];
    let mut sig_dummy: [Field; RSA_2048_NUM_LIMBS_AUTH] = [0; RSA_2048_NUM_LIMBS_AUTH];

    pubkey_mod_dummy[0] = 0xFFFFFFFFFFFFFFFF as Field;
    for i in 1..RSA_2048_NUM_LIMBS_AUTH {
        // Fix the arithmetic expression by casting the result to Field
        let shift_amount = (i as u8) * 8;
        let divisor = (1 as u64) << shift_amount;
        pubkey_mod_dummy[i] = (0x0100000000000000 / divisor) as Field;
    }

    redc_params_dummy[0] = 0x0001000000000001 as Field;
    for i in 1..RSA_2048_NUM_LIMBS_AUTH {
        redc_params_dummy[i] = 0x01 as Field;
    }

    sig_dummy[0] = 0x7FFFFFFFFFFFFFFF as Field;
    for i in 1..RSA_2048_NUM_LIMBS_AUTH {
        sig_dummy[i] = 0x01 as Field;
    }

    let expected_id_str = "test_user_123";
    let mut expected_user_id_vec: BoundedVec<u8, MAX_USER_ID_LENGTH_AUTH> = BoundedVec::new();
    for byte in expected_id_str.as_bytes() {
        expected_user_id_vec.push(byte);
    }

    main_jwt_auth(
        jwt_signed_data_vec,
        payload_offset,
        pubkey_mod_dummy,
        redc_params_dummy,
        sig_dummy,
        expected_user_id_vec
    );
}