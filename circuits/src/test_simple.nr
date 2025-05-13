// circuits/src/test_simple.nr
use std::hash::pedersen_hash;

pub global TREE_DEPTH: u32 = 3; // Much smaller for testing

pub fn main(
    root: pub Field,
    leaf: Field,
    index: Field,
    path: [Field; TREE_DEPTH]
) {
    // Simple Merkle proof verification
    let mut current = leaf;
    let mut idx = index;
    
    for i in 0..TREE_DEPTH {
        let bit = idx & 1;
        if bit == 0 {
            current = pedersen_hash([current, path[i]]);
        } else {
            current = pedersen_hash([path[i], current]);
        }
        idx = idx >> 1;
    }
    
    assert(current == root, "Merkle proof failed");
}
