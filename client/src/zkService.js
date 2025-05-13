// ~/ephemeral-echo/client/src/zkService.js

import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js'; 

let noirInstance = null;
let backendInstance = null;
let circuitJsonGlobal = null; 

export async function initNoir() {
    if (noirInstance && backendInstance) {
        return { noir: noirInstance, backend: backendInstance };
    }
    try {
        console.log('zkService.js: Initializing Noir & Backend (Tutorial Versions)...');
        if (!circuitJsonGlobal) {
            const acirResponse = await fetch('/circuits/ephemeral_echo_circuits.json');
            if (!acirResponse.ok) throw new Error(`Failed to fetch ACIR: ${acirResponse.statusText}`);
            circuitJsonGlobal = await acirResponse.json(); 
            console.log('zkService.js: ACIR fetched successfully.');
        }
        if (!circuitJsonGlobal || !circuitJsonGlobal.bytecode) {
            throw new Error('ACIR JSON is missing or does not contain bytecode.');
        }
        noirInstance = new Noir(circuitJsonGlobal); 
        console.log('zkService.js: Noir instantiated.');
        backendInstance = new UltraHonkBackend(circuitJsonGlobal.bytecode); 
        console.log('zkService.js: UltraHonkBackend (bb.js) instantiated.');
        console.log('zkService.js: Noir & Backend initialized successfully (Tutorial Versions)!');
        return { noir: noirInstance, backend: backendInstance };
    } catch (error) {
        console.error('zkService.js: Error initializing Noir/Backend:', error);
        throw error; 
    }
}

// Simplified prepareMainInputs - essentially an identity function for now
function prepareMainInputs(inputData) {
    console.log("zkService.js: prepareMainInputs received (raw):", inputData); // Log raw object
    console.log("zkService.js: prepareMainInputs received (stringified):", JSON.stringify(inputData, null, 2));
    if (!inputData || Object.keys(inputData).length === 0) {
        console.error("zkService.js: prepareMainInputs received an empty or invalid object!");
        return {}; // Return empty to make downstream fail clearly
    }
    // No transformation, assuming validTestData.js provides perfectly formatted inputs
    console.log("zkService.js: prepareMainInputs returning (as is):", inputData);
    return inputData; 
}

export async function generateProof(rawInputs) { 
    const { noir, backend } = await initNoir(); 
    if (!noir || !backend) throw new Error('Noir/Backend not initialized for proof generation.');

    console.log("zkService.js: generateProof received rawInputs (direct):", rawInputs);
    console.log("zkService.js: generateProof received rawInputs (stringified):", JSON.stringify(rawInputs, null, 2));
    
    if (!rawInputs || !rawInputs.hasOwnProperty('payload_base64_decode_offset')) { // Check a JWT key
        console.error("zkService.js: CRITICAL - rawInputs to generateProof is MISSING JWT key 'payload_base64_decode_offset'!", rawInputs);
    }
    if (!rawInputs || !rawInputs.hasOwnProperty('current_nmt_root')) { // Check a deletion proof key
        console.error("zkService.js: CRITICAL - rawInputs to generateProof is MISSING deletion key 'current_nmt_root'!", rawInputs);
    }


    const inputs = prepareMainInputs(rawInputs); 

    console.log('zkService.js: Final inputs object being passed to noir.execute():', JSON.stringify(inputs, null, 2));
    if (!inputs || !inputs.hasOwnProperty('payload_base64_decode_offset')) {
        console.error('zkService.js: CRITICAL - Final inputs object is MISSING JWT key "payload_base64_decode_offset" right before noir.execute()!');
    }
     if (!inputs || !inputs.hasOwnProperty('current_nmt_root')) {
        console.error('zkService.js: CRITICAL - Final inputs object is MISSING deletion key "current_nmt_root" right before noir.execute()!');
    }
    
    try {
        console.log('zkService.js: Calling noir.execute()...');
        const { witness } = await noir.execute(inputs); 
        console.log('zkService.js: Witness generated:', witness);
        console.log('zkService.js: Generating proof with backend...');
        const proof = await backend.generateProof(witness);
        console.log('zkService.js: Proof generated:', proof); 
        return proof; 
    } catch (error) {
        console.error('zkService.js: Error during noir.execute() or backend.generateProof():', error);
        throw error;
    }
}

export async function verifyProof(proof) { 
    // ... (this function should be okay, keep as is) ...
    const { backend } = await initNoir(); 
    if (!backend) throw new Error('Backend not initialized for proof verification.');
    console.log('zkService.js: Verifying proof with backend...');
    try {
        const isValid = await backend.verifyProof(proof);
        console.log('zkService.js: Proof verification result:', isValid);
        return isValid;
    } catch (error) {
        console.error('zkService.js: Error verifying proof:', error);
        throw error;
    }
}
