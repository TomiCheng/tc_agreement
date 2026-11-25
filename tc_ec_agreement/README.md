# tc_ec_agreement

[![crates.io](https://img.shields.io/crates/v/tc_ec_agreement.svg)](https://crates.io/crates/tc_ec_agreement)
[![docs.rs](https://docs.rs/tc_ec_agreement/badge.svg)](https://docs.rs/tc_ec_agreement)
[![CI](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Key agreement over elliptic curves after Bouncy Castle: ECDH, ECDHC, EC-MQV
and GOST VKO, over the keys of
[`tc_ec_key`](https://crates.io/crates/tc_ec_key). `no_std` with `alloc`, no
`unsafe`, Rust 1.85 or later.

## Types

- `EcdhBasicAgreement` — ECDH: the x coordinate of d·Q.
- `EcdhcBasicAgreement` — ECDHC: the x coordinate of (h·d)·Q, with the cofactor h.
- `EcMqvBasicAgreement` — EC-MQV of SEC 1, from a static and an ephemeral key on each side.
- `MqvPrivateParams` — the own static and ephemeral private keys for EC-MQV.
- `MqvPublicParams` — the other party's static and ephemeral public keys for EC-MQV.
- `EcVkoAgreement` — GOST VKO of RFC 7836: the hashed shared point.
- `EcVkoParams` — the private key and the UKM for VKO.
- `EcdhError`, `EcMqvError`, `EcVkoError` — what each agreement turns down.

## Traits

Every agreement implements `Agreement` and `AgreementInit` of
[`tc_agreement`](https://crates.io/crates/tc_agreement).

## Features

None; the crate always uses `alloc`.

## Usage

```rust
use tc_agreement::{Agreement, AgreementInit};
use tc_ec_agreement::EcdhBasicAgreement;

let mut agreement = EcdhBasicAgreement::new();
agreement.init(&private_key)?;
let mut secret = vec![0; agreement.agreement_size()];
agreement.calculate_agreement(&peer_public_key, &mut secret)?;
```

## Security

The agreements check that the other party's keys are on the same domain and
are finite points of the curve, and turn down a shared point at infinity.
The secret is raw: derive keys from it with a KDF. They are as constant time
in the private keys as the curve's point multiplication, so use the
constant-time curve types for secret keys; the checks are variable time, for
public values.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
