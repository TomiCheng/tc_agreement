# tc_jpake

[![crates.io](https://img.shields.io/crates/v/tc_jpake.svg)](https://crates.io/crates/tc_jpake)
[![docs.rs](https://docs.rs/tc_jpake/badge.svg)](https://docs.rs/tc_jpake)
[![CI](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

J-PAKE password-authenticated key exchange after Bouncy Castle's
`JPakeParticipant`: two peers that share a password reach the same keying
material over three rounds, without ever sending the password. `no_std` with
`alloc`, no `unsafe`, Rust 1.85 or later.

## Types

- `JPakeParticipant` — one party of the exchange, through all three rounds.
- `JPakeParams` — the participant ID, the password and the group.
- `JPakePrimeOrderGroup` — the group p, q and g; `standard_groups` has Bouncy Castle's.
- `JPakeRound1Payload`, `JPakeRound2Payload`, `JPakeRound3Payload` — what the parties send.
- `JPakeZeroKnowledgeProof` — the Schnorr proof inside the first two payloads.
- `JPakeState` — how far a participant has come.
- `JPakeError` — what the exchange turns down.

## Features

None; the crate always uses `alloc`.

## Usage

```rust
use tc_jpake::{JPakeParams, JPakeParticipant};

let mut alice = JPakeParticipant::new(rand::rng());
alice.init(&JPakeParams::new("alice", b"shared code"))?;
let round1 = alice.create_round1_payload_to_send()?;   // send to Bob
alice.validate_round1_payload_received(&bob_round1)?;
let round2 = alice.create_round2_payload_to_send()?;   // send to Bob
alice.validate_round2_payload_received(&bob_round2)?;
let keying_material = alice.calculate_keying_material()?;
```

## Security

Both parties must use the same password and different participant IDs. The
keying material is raw: derive keys from it with a KDF, and run the third
round to confirm that the partner reached it. Each attempt with a wrong
password costs an attacker a full exchange, so limit failures. The secret
exponents and the password are handled in constant time; the checks of
payloads and groups are variable time, for public values, and the key
confirmation shows the number of the keying material's leading zero bytes,
as Bouncy Castle's encoding does.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
