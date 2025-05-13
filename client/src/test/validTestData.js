// client/src/test/validTestData.js

import { generateInputs as generateNoirJwtCircuitInputs } from 'noir-jwt';

// These constants must match the globals in your Noir code
const MAX_JWT_DATA_LENGTH = 1024;
const MAX_USER_ID_LENGTH = 64;
const RSA_2048_NUM_LIMBS = 18;
const TREE_DEPTH_JS = 32;

function processDataToArray(dataInput, maxLength, inputName = "dataInput") {
    let arr = [];
    let actualLength = 0;
    
    // First check if it's the noir-jwt SDK output format
    if (dataInput && typeof dataInput === 'object' && 'storage' in dataInput) {
        // Handle SDK format: { storage: [...], len: number }
        if (Array.isArray(dataInput.storage)) {
            arr = dataInput.storage.map(byte => {
                if (typeof byte === 'number') return "0x" + byte.toString(16).padStart(2, '0');
                if (typeof byte === 'string' && byte.startsWith('0x')) return byte;
                return "0x00";
            });
            actualLength = dataInput.len || dataInput.storage.length;
        }
    } else if (dataInput instanceof Uint8Array) {
        arr = Array.from(dataInput).map(byte => "0x" + byte.toString(16).padStart(2, '0'));
        actualLength = dataInput.length;
    } else if (Array.isArray(dataInput)) {
        arr = dataInput.map(byte =>
            typeof byte === 'number' ? "0x" + byte.toString(16).padStart(2, '0') :
            (typeof byte === 'string' && byte.startsWith('0x')) ? byte :
            "0x00"
        );
        actualLength = dataInput.length;
    } else {
        console.error(`processDataToArray for ${inputName}: received unexpected type or null/undefined. Input:`, dataInput, `Type: ${typeof dataInput}`);
        for(let i = 0; i < maxLength; i++) { arr.push("0x00"); }
        return { storage: arr, len: 0 };
    }
    
    if (actualLength > maxLength) {
        arr = arr.slice(0, maxLength);
        actualLength = maxLength;
    }
    while(arr.length < maxLength) {
        arr.push("0x00");
    }
    return { storage: arr, len: actualLength };
}

// THIS IS THE CRITICAL ISSUE: The noir-jwt SDK outputs Field-sized limbs,
// but your Noir circuit expects u128 limbs. We need to either:
// 1. Modify the Noir circuit to accept Field-sized limbs
// 2. Use a different approach for handling RSA in Noir
// 3. Find a way to properly convert Field to u128 without breaking the math

function limbArrayToHexArray(limbArr) {
    if (!limbArr || !Array.isArray(limbArr)) {
        console.error("limbArrayToHexArray: input is not a valid array, got:", limbArr);
        return Array(RSA_2048_NUM_LIMBS).fill("0x0");
    }
    
    // WARNING: This truncation approach will break RSA verification!
    // The noir-jwt SDK is designed for Field-sized limbs, not u128.
    // You need to either modify your Noir circuit or use a different approach.
    
    return limbArr.map((limb, index) => {
        let hexLimb = "0x0";
        let limbBigInt;
        
        if (typeof limb === 'bigint') {
            limbBigInt = limb;
        } else if (typeof limb === 'string') {
            // The SDK might return decimal strings
            limbBigInt = BigInt(limb);
        } else if (typeof limb === 'number') {
            limbBigInt = BigInt(limb);
        } else {
            console.error(`limbArrayToHexArray: unexpected limb type for limb[${index}]`, limb);
            return "0x0";
        }
        
        // This truncation WILL break RSA verification
        const maxU128 = (BigInt(1) << BigInt(128)) - BigInt(1);
        if (limbBigInt > maxU128) {
            console.error(`CRITICAL: limb[${index}] value ${limbBigInt} cannot be safely truncated to u128!`);
            console.error("The noir-jwt SDK outputs Field-sized limbs, but your circuit expects u128.");
            console.error("You must either:");
            console.error("1. Modify your Noir circuit to accept Field parameters instead of u128");
            console.error("2. Use a different RSA implementation that works with u128 limbs");
        }
        
        hexLimb = `0x${limbBigInt.toString(16)}`;
        return hexLimb;
    });
}

async function getClientJwtInputs() {
    console.log("validTestData.js: Entering getClientJwtInputs");

    const rawJwtString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidXNlcl9jbGllbnRfMDA3IiwiaWF0IjoxNzQ3MDk4NTc0LCJleHAiOjE3NDcxMDIxNzR9.stopiFDzreNFxJdSV9G9zsZ-WarF9d0mdBcedHXthxQjtYraNmfnPtvkk4Ps0S9m90gCO6g1538HoNvo2kwv9Vmv9yG5I9y2qWH2defy5XM5eXb8-l2yFZ4M4nWA98BYvRVqCaMB_oyjmexugrk_6puxUq1kHRNfpK6EBR7T1K4FHbdLgFMPotW29NPukXKpu6JWDPvoV08U-FHafwBoK4BOJEPO0dzJR6hh_P8pFu-loeOliWArBHI2fgjc6xQJkgkJwDi5Hu-_v0M4DVOqSeCtxI2PeOubSi3Fgz5T8tk5RBOTEkE2ad8bd_pE2Gl9yqQIwSaIMJXZ_Mnl8lVlGg";

    const rsaPublicKeyJwk = {
        "kty":"RSA",
        "n":"1tFwEF_Dur7okXxLEtzalNsPr-ICUOABC6_i12ge__MeDGithQexmnCgd-CmBSPzm8m5gQ5piqyRs0VEm8RcRLFb5a69-J4FEauKsaWXjkCm7NrOhhAcyPsAOvdovbiLVt9CDMG_8QzV4JWpTVs1Qluj98iPq-g8fKyHpzIUqXjcQB2oMue3r4k91Fh5p20unwF3bCJksGr4-gOYcBJ8L-fiQR2IDc3TLWRwz30v_U7ImH1nPJ2G1iTcMKhHWm68l-SxzE6n8nWg3sXaS0kIZjfgNMs7K7RkT0Ew_2WcQH3WtVB3JrG2OtMpdvSYBRMSMWLFuVjOECL67RpNbq2Crw",
        "e":"AQAB"
    };

    const expectedUserIdString = "user_client_007";

    let noirJwtCircuitInputs;
    try {
        console.log("validTestData.js: Calling actual noir-jwt JS SDK's generateInputs with JWT and PubKey JWK...");
        noirJwtCircuitInputs = await generateNoirJwtCircuitInputs({
           jwt: rawJwtString,
           pubkey: rsaPublicKeyJwk,
           maxSignedDataLength: MAX_JWT_DATA_LENGTH,
        });
        console.log("validTestData.js: Actual noir-jwt SDK output received (raw object):", noirJwtCircuitInputs);
        
        // Debug the actual structure
        console.log("SDK output structure:");
        console.log("- data type:", typeof noirJwtCircuitInputs.data);
        console.log("- data value:", noirJwtCircuitInputs.data);
        if (noirJwtCircuitInputs.data && typeof noirJwtCircuitInputs.data === 'object') {
            console.log("- data.storage exists:", 'storage' in noirJwtCircuitInputs.data);
            console.log("- data.len exists:", 'len' in noirJwtCircuitInputs.data);
        }

        if (!noirJwtCircuitInputs ||
            typeof noirJwtCircuitInputs.data === 'undefined' ||
            !Array.isArray(noirJwtCircuitInputs.pubkey_modulus_limbs) ||
            typeof noirJwtCircuitInputs.base64_decode_offset === 'undefined') {
            console.error("validTestData.js: SDK output missing critical fields. Output:", noirJwtCircuitInputs);
            throw new Error("SDK did not return expected structure.");
        }
    } catch (sdkError) {
        console.error("validTestData.js: Error calling or processing output from actual noir-jwt JS SDK:", sdkError);
        throw sdkError;
    }

    const { storage: jwt_signed_data_storage, len: actualJwtDataLength } =
        processDataToArray(noirJwtCircuitInputs.data, MAX_JWT_DATA_LENGTH, "jwt_signed_data");

    let expected_user_id_storage_temp = [];
    for (let i = 0; i < expectedUserIdString.length; i++) {
        expected_user_id_storage_temp.push(expectedUserIdString.charCodeAt(i));
    }
    const { storage: expected_user_id_storage, len: actualUserIdLength } =
        processDataToArray(expected_user_id_storage_temp, MAX_USER_ID_LENGTH, "expected_user_id");

    const payloadOffset = Number(noirJwtCircuitInputs.base64_decode_offset);
    if (isNaN(payloadOffset)) {
        console.error("validTestData.js: payload_base64_decode_offset is NaN from SDK output:", noirJwtCircuitInputs.base64_decode_offset);
        throw new Error("payload_base64_decode_offset from SDK is invalid.");
    }

    // CRITICAL WARNING ABOUT THE LIMB SIZE MISMATCH
    console.warn("⚠️ CRITICAL ISSUE: The noir-jwt SDK outputs Field-sized limbs, but your Noir circuit expects u128 limbs!");
    console.warn("This mismatch will cause verification to fail. You need to:");
    console.warn("1. Modify your Noir circuit to use Field parameters instead of u128, OR");
    console.warn("2. Use a different JWT verification approach that works with u128 limbs");

    const result = {
        jwt_signed_data: { storage: jwt_signed_data_storage, len: actualJwtDataLength },
        payload_base64_decode_offset: payloadOffset,
        pubkey_modulus_limbs: limbArrayToHexArray(noirJwtCircuitInputs.pubkey_modulus_limbs),
        redc_params_limbs: limbArrayToHexArray(noirJwtCircuitInputs.redc_params_limbs),
        signature_limbs: limbArrayToHexArray(noirJwtCircuitInputs.signature_limbs),
        expected_user_id_in_jwt: { storage: expected_user_id_storage, len: actualUserIdLength },
    };
    console.log("validTestData.js: getClientJwtInputs returning formatted inputs from SDK.");
    return result;
}

// Rest of the file remains the same...
const getValidDeletionProofInputs = () => {
    const path = [];
    for (let i = 0; i < TREE_DEPTH_JS; i++) {
        path.push("0x" + (0x200 + i).toString(16));
    }
    return {
        current_nmt_root: "0x1a1ca84369d806125dfd3fdc26facd5b3aa48c3bcef1905543aa05dbf8a488ee",
        newly_deleted_message_nullifier: "0x96",
        low_nullifier_leaf_data_value: "0x64",
        low_nullifier_leaf_data_next_value: "0xc8",
        low_nullifier_leaf_data_next_index: "0xd1",
        low_nullifier_index: "0x00",
        low_nullifier_path: path,
    };
};

export async function generateCombinedTestInputs() {
    console.log("validTestData.js: Entering generateCombinedTestInputs.");
    let combinedInputs = {};
    try {
        const jwtInputs = await getClientJwtInputs();
        console.log("validTestData.js: jwtInputs received in generateCombinedTestInputs:", JSON.stringify(jwtInputs, null, 2));

        const deletionInputs = getValidDeletionProofInputs();
        combinedInputs = { ...jwtInputs, ...deletionInputs };

        console.log("Client (validTestData.js): Successfully created combinedInputs object (final):", JSON.stringify(combinedInputs, null, 2));
        return combinedInputs;
    } catch (error) {
        console.error("validTestData.js: CRITICAL Error caught in generateCombinedTestInputs:", error);
        return { error_in_generating_inputs: error.message || "Unknown error in generateCombinedTestInputs" };
    }
}