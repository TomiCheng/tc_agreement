# tc_dh

[![crates.io](https://img.shields.io/crates/v/tc_dh.svg)](https://crates.io/crates/tc_dh)
[![docs.rs](https://docs.rs/tc_dh/badge.svg)](https://docs.rs/tc_dh)
[![CI](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Diffie-Hellman key agreement after Bouncy Castle's `DHBasicAgreement` and
`DHAgreement`, over the parameters and keys of
[`tc_dh_key`](https://crates.io/crates/tc_dh_key). `no_std` with `alloc`, no
`unsafe`, Rust 1.85 or later.

## Types

- `DhBasicAgreement` — the shared secret y^x mod p, as bytes of the length of p.
- `DhAgreement` — the MTI/A0 agreement of RFC 2631, with static keys and a fresh message from each party.
- `DhAgreementError` — what the agreements turn down.

## Traits

`DhBasicAgreement` implements `Agreement` and `AgreementInit` of
[`tc_agreement`](https://crates.io/crates/tc_agreement).

## Features

None; the crate always uses `alloc` for its integers.

## Usage

```rust
use tc_agreement::{Agreement, AgreementInit};
use tc_dh::DhBasicAgreement;

let mut agreement = DhBasicAgreement::new();
agreement.init(&private_key)?;
let mut secret = vec![0; agreement.agreement_size()];
agreement.calculate_agreement(&peer_public_key, &mut secret)?;
```

## Security

Both agreements check the other party's public key, and the MTI/A0 message,
for range and subgroup membership, and turn down a secret of 1. They do not
test p and q for primality, so prefer the standard groups of `tc_dh_key`.
The secret is raw: derive keys from it with a KDF. The agreements are
constant time in the private values; the checks are variable time, for public
values.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
