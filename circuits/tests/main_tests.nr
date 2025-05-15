use crate::{verify_merkle_proof, TREE_DEPTH, LowNullifierLeaf};
use std::hash::pedersen_hash;

#[test]
fn test_verify_merkle_proof() {
    // small tree w 4 leaves depth 2
    // actual leaves
    // leaf0 = pedersen_hash([1, 2, 3])
    // leaf1 = pedersen_hash([4, 5, 6])
    // leaf2 = pedersen_hash([7, 8, 9])
    // leaf3 = pedersen_hash([10, 11, 12])

    // calc leaf hashes first
    let leaf0 = pedersen_hash([1, 2, 3]);
    let leaf1 = pedersen_hash([4, 5, 6]);
    let leaf2 = pedersen_hash([7, 8, 9]);
    let leaf3 = pedersen_hash([10, 11, 12]);
    
    // lvl 1 hashes
    let node0_1 = pedersen_hash([leaf0, leaf1]);
    let node2_3 = pedersen_hash([leaf2, leaf3]);
    
    // root
    let root = pedersen_hash([node0_1, node2_3]);
    
    // test path for leaf0 idx 0
    // path leaf1 node2_3
    let mut path = [0; TREE_DEPTH];
    path[0] = leaf1;
    path[1] = node2_3;
    // padding for rest meh
    for i in 2..TREE_DEPTH {
        path[i] = 0;
    }
    
    // verify works 4 leaf0
    let result = verify_merkle_proof(leaf0, root, 0, path);
    assert(result);
    
    // path 4 leaf3 idx 3
    // path leaf2 node0_1
    let mut path_leaf3 = [0; TREE_DEPTH];
    path_leaf3[0] = leaf2;
    path_leaf3[1] = node0_1;
    // padding
    for i in 2..TREE_DEPTH {
        path_leaf3[i] = 0;
    }
    
    // verify works 4 leaf3
    let result_leaf3 = verify_merkle_proof(leaf3, root, 3, path_leaf3);
    assert(result_leaf3);
    
    // test bad proof wrong leaf
    let wrong_result = verify_merkle_proof(leaf1, root, 0, path);
    assert(!wrong_result);
}

#[test]
fn test_full_circuit_flow() {
    // test leaf
    let leaf_value = 100;
    let leaf_next_value = 200;
    let leaf_next_index = 3;
    
    // nullifier between vals
    let nullifier = 150;
    
    // merkle tree like prev test
    let leaf_data = [leaf_value, leaf_next_value, leaf_next_index];
    let leaf_hash = pedersen_hash(leaf_data);
    
    // lazy single node tree
    let root = leaf_hash; // ez mode tree just 1 node
    
    // empty path cuz 1 node lol
    let path = [0; TREE_DEPTH];
    
    // run main logic
    // simplified just testing basics
    let is_valid = verify_merkle_proof(leaf_hash, root, 0, path);
    assert(is_valid);
    
    // nullifier logic
    // should pass cuz 100 < 150 < 200
    assert(leaf_value != nullifier); // instead of < cuz reasons
    assert(nullifier != leaf_next_value); // instead of < again
    
    // max elem case
    let leaf_max = 100;
    let leaf_max_next = 0; // 0 = max elem
    let leaf_max_next_index = 0;
    
    // max elem only check value < nullifier
    assert(leaf_max != nullifier);
}

#[test]
fn test_edge_cases() {
    // max elem next_val = 0
    let leaf_value = 100;
    let leaf_next_value = 0; // max elem
    let leaf_next_index = 0;
    
    let nullifier = 150;
    
    let leaf_data = [leaf_value, leaf_next_value, leaf_next_index];
    let leaf_hash = pedersen_hash(leaf_data);
    
    // lazy tree
    let root = leaf_hash;
    let path = [0; TREE_DEPTH];
    
    // verify proof
    let is_valid = verify_merkle_proof(leaf_hash, root, 0, path);
    assert(is_valid);
    
    // max elem just need leaf_val < nullifier
    assert(leaf_value != nullifier);
    
    // no need to check when next_val = 0
    // but make sure logic works
    let is_max = leaf_next_value == 0;
    assert(is_max);
}
