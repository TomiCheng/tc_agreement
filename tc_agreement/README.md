# tc_agreement

[![crates.io](https://img.shields.io/crates/v/tc_agreement.svg)](https://crates.io/crates/tc_agreement)
[![docs.rs](https://docs.rs/tc_agreement/badge.svg)](https://docs.rs/tc_agreement)
[![CI](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Shared contracts for key agreement, after Bouncy Castle's `IRawAgreement`:
a private key and the other party's public key make a shared secret,
written as bytes of a fixed length. `no_std`, no allocator, no
dependencies, no `unsafe`, Rust 1.85 or later.

## Traits

- `Agreement` — `agreement_size` and `calculate_agreement`, which writes the shared secret with a public key.
- `AgreementInit<P>` — `init` with parameters of type `P`, by reference, holding the private key.

## Features

None; the crate needs neither `std` nor `alloc`.

## Usage

```rust
use tc_agreement::{Agreement, AgreementInit};

fn agree<A, K>(agreement: &mut A, private: &K, public: &A::PublicKey, secret: &mut [u8]) -> Option<usize>
where
    A: Agreement + AgreementInit<K>,
{
    agreement.init(private).ok()?;
    agreement.calculate_agreement(public, secret).ok()?;
    Some(agreement.agreement_size())
}
```

## Security

The traits make no timing promise. Accepted keys, the state left by a failed
call and whether an agreement runs in constant time are documented by each
implementation. The shared secret is raw: derive keys from it with a KDF.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
