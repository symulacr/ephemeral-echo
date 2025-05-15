import { Noir } from '@noir-lang/noir_js';

// pedersen hash fn to match noir impl
async function pedersenHash(inputs) {
    // just a mock lol gotta swap w/ real pedersen later
    // for now let's fake it w/ deterministic fn
    const sum = inputs.reduce((a, b) => {
        const numA = typeof a === 'string' ? parseInt(a, 16) : a;
        const numB = typeof b === 'string' ? parseInt(b, 16) : b;
        return numA + numB;
    }, 0);
    
    // convert to hex fmt 32bytes
    return '0x' + sum.toString(16).padStart(64, '0');
}

export async function generateValidMerkleTree(depth = 32) {
    // create leaf vals
    const leafValues = [
        { value: '0x' + '0'.repeat(62) + '03', next_value: '0x' + '0'.repeat(62) + '07', next_index: '0x' + '0'.repeat(62) + '0a' },
        { value: '0x' + '0'.repeat(62) + '07', next_value: '0x' + '0'.repeat(62) + '10', next_index: '0x' + '0'.repeat(62) + '0b' },
        { value: '0x' + '0'.repeat(62) + '10', next_value: '0x' + '0'.repeat(62) + '15', next_index: '0x' + '0'.repeat(62) + '0c' },
        { value: '0x' + '0'.repeat(62) + '15', next_value: '0x' + '0'.repeat(63) + '0', next_index: '0x' + '0'.repeat(62) + '00' }, // last elem
    ];

    // create tree layers
    const layers = [];
    
    // first layer hash leaf data
    const leafHashes = [];
    for (const leaf of leafValues) {
        const hash = await pedersenHash([leaf.value, leaf.next_value, leaf.next_index]);
        leafHashes.push(hash);
    }
    
    // pad to nearest pow2
    const treeSize = Math.pow(2, depth);
    const paddedLeafHashes = [...leafHashes];
    while (paddedLeafHashes.length < treeSize) {
        paddedLeafHashes.push('0x' + '0'.repeat(64)); // zero pad
    }
    
    layers.push(paddedLeafHashes);
    
    // build tree layers up to root
    let currentLayer = paddedLeafHashes;
    for (let level = 1; level <= depth; level++) {
        const newLayer = [];
        for (let i = 0; i < currentLayer.length; i += 2) {
            const left = currentLayer[i];
            const right = currentLayer[i + 1] || '0x' + '0'.repeat(64);
            const parent = await pedersenHash([left, right]);
            newLayer.push(parent);
        }
        layers.push(newLayer);
        currentLayer = newLayer;
    }
    
    // get root
    const root = layers[layers.length - 1][0];
    
    // gen path for first leaf idx0
    const path = [];
    let index = 0;
    for (let level = 0; level < depth; level++) {
        const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
        if (level < layers.length - 1 && siblingIndex < layers[level].length) {
            path.push(layers[level][siblingIndex]);
        } else {
            path.push('0x' + '0'.repeat(64));
        }
        index = Math.floor(index / 2);
    }
    
    return {
        root,
        leaves: leafValues,
        leafHashes,
        path,
        layers
    };
}

export function generateValidTestInputs() {
    // gimme formatted inputs asap
    const properRoot = '0x' + '1'.repeat(64);
    const properPath = [];
    
    for (let i = 0; i < 32; i++) {
        properPath.push('0x' + (i + 1).toString(16).padStart(64, '0'));
    }
    
    return {
        current_nmt_root: properRoot,
        newly_deleted_message_nullifier: '0x' + '0'.repeat(62) + '05',
        low_nullifier_leaf_data_value: '0x' + '0'.repeat(62) + '03',
        low_nullifier_leaf_data_next_value: '0x' + '0'.repeat(62) + '07',
        low_nullifier_leaf_data_next_index: '0x' + '0'.repeat(62) + '0a',
        low_nullifier_index: '0x' + '0'.repeat(63) + '0',
        low_nullifier_path: properPath,
    };
}
