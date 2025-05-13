# ephemeral echo: verifiable message deletion with noir proofs

[![Noir](https://img.shields.io/badge/Built%20with-Noir-6B5ACD)](https://noir-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![NoirHack 2025](https://img.shields.io/badge/NoirHack-2025-orange)](https://github.com/symulacr/ephemeral-echo)

client-side noir proofs for cryptographically verifiable message deletion using [noir-jwt](https://github.com/zkemail/noir-jwt) auth and [zk-kit merkle trees](https://github.com/privacy-scaling-explorations/zk-kit.noir). part of [noir lab notebook](https://github.com/symulacr/noir-lab-notebook) research.

## [+] overview
ephemeral echo is made of noir circuits to handle complex crypto ops entirely in-browser, combining:
- jwt verification (rs256) with [noir-jwt](https://github.com/zkemail/noir-jwt)
- merkle tree non-membership proofs with [zk-kit](https://github.com/privacy-scaling-explorations/zk-kit.noir)  
- client-side proof gen/verification via [@noir-lang/noir_js](https://www.npmjs.com/package/@noir-lang/noir_js)
- ultrahonk backend using [@aztec/bb.js](https://www.npmjs.com/package/@aztec/bb.js)

### [✓] key features

- hybrid noir circuits: jwt + merkle proofs in single circuit
- no backend required atm: all proofs in wasm env
- gud crypto: rsa-2048 signatures + merkle verification  
- efficient constraints: 48k acir opcodes, sound math bounds

## [●] quick start

```bash
# clone repo
git clone https://github.com/symulacr/ephemeral-echo
cd ephemeral-echo

# install noir toolchain v0.22.0
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -v 0.22.0

# compile circuits
cd circuits
nargo compile

# run client app
cd ../client
npm install
npm run dev
```

navigate to `http://localhost:5173`

## [◆] architecture

for now, sys lev noir's capabilities for fully client-side proof sys:

```
browser env                     noir circuits                    proof sys
-----------                     -------------                    ---------
react ui     ────────────►     jwt verifier   ───┐             
             │                                    ├────►  proof gen
wasm noir    ◄────────────     merkle tree    ───┘         │
             │                                              ▼
bb backend   ◄─────────────────────────────────────────  verify
             │                                              │
             └──────────────────────────────────────────────┘
                                result
```

### components

**frontend (react + vite)**
- modern ui with real-time progress
- circuit input management  
- proof visualization

**noir circuits**
- `main.nr`: orchestrates jwt auth + deletion proof
- `auth.nr`: jwt rs256 sig verification
- `merkle_tree.nr`: merkle proof logic
- deps: zk-kit, noir-jwt libs

**proof backend**
- ultrahonk via @aztec/bb.js
- wasm-compiled noir circuits
- client-side gen/verification

## [▸] performance metrics

*wsl2 env on windows, intel processor*

| operation | time | details |
|-----------|------|---------|
| input prep | 17.1ms | jwt parse + merkle setup |
| noir exec | 16.61s | witness generation |
| proof gen | included | ultrahonk backend |
| verification | 8.25s | client-side verify |
| total e2e | 24.88s | complete flow |

### circuit complexity

- acir opcodes: over 48k
- brillig opcodes: over 14k  
- expression width: 8

## [►] technical implementation

### jwt auth in noir

verifies jwt tokens using rs256 sigs entirely within noir circuits:

```noir
// verify jwt sig and extract user_id claim
pub fn main_jwt_auth(
    jwt_signed_data: BoundedVec<u8, MAX_JWT_DATA_LENGTH>,
    payload_base64_decode_offset: u32,
    pubkey_modulus_limbs: [Field; RSA_2048_NUM_LIMBS],
    signature_limbs: [Field; RSA_2048_NUM_LIMBS],
    expected_user_id: BoundedVec<u8, MAX_USER_ID_LENGTH>
)
```

### merkle tree non-membership proof

implements indexed merkle tree approach for efficient non-membership:

```noir
// prove message nullifier NOT in tree
fn prove_message_deletion(
    current_nmt_root: pub Field,
    newly_deleted_message_nullifier: Field,
    low_nullifier_leaf_data: LowNullifierLeaf,
    low_nullifier_path: [Field; TREE_DEPTH]
)
```

### sound range constraints

uses noir's `assert_max_bit_size` for mathematically sound comparisons:

```noir
// ensure a < b for field types with proper bounds
fn assert_field_lt(a: Field, b: Field) {
    let diff_minus_one = b - a - 1;
    diff_minus_one.assert_max_bit_size::<LT_EFFECTIVE_BIT_SIZE>();
}
```

## [×] features

- **privacy-first**: no server sees messages or deletion requests
- **cryptographically sound**: mathematical proofs ensure deletion
- **user-friendly**: clean ui with real-time progress
- **fully auditable**: open-source circuits, transparent verification

## [!] current limitations & ongoing dev

project under active development with updates based on available time:

- jwt limb size compatibility (field vs u128) - fix in progress
- merkle tree state conceptual (not persistent between sessions)
- single-user demo mode  
- proof gen time optimization needed

dev continues at professional pace with priorities:
- optimize proof gen performance
- implement persistent nullifier storage
- add multi-user support
- aztec network deployment prep

## [□] tech stack

- **noir v0.22.0**: zk circuit language
- **react + vite**: modern frontend
- **@noir-lang/noir_js**: noir js integration
- **@aztec/bb.js**: ultrahonk proving backend  
- **[noir-jwt](https://github.com/zkemail/noir-jwt)**: jwt verification in noir
- **[zk-kit](https://github.com/privacy-scaling-explorations/zk-kit.noir)**: merkle tree implementations

## [↗] related projects

- [noir lab notebook](https://github.com/symulacr/noir-lab-notebook) - parent research project
- [aztec network](https://aztec.network) - target deployment network
- [awesome noir](https://github.com/noir-lang/awesome-noir) - curated noir resources

## [+] contributing

contributions welcome. submit issues or prs. for major changes, open issue first.

## [◊] license

mit license - see [LICENSE](LICENSE) file

## [■] acknowledgments

- built for noirhack 2025
- aztec labs for noir
- zk email team for noir-jwt lib  
- privacy scaling explorations for zk-kit

## [●] author

**symulacr**
- github: [@symulacr](https://github.com/symulacr)

---

*"noir is about control over what you share;  not hiding"*
