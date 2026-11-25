# Changelog

All notable changes to `tc_ec_agreement` are documented in this file.

## 0.1.0 - 2026-11-25

Initial release.

### Added

- `EcdhBasicAgreement`, Bouncy Castle's `ECDHBasicAgreement`: the x
  coordinate of d·Q, with a cofactor other than one handled as Bouncy Castle
  does, by multiplying Q by h and d by its inverse modulo n.
- `EcdhcBasicAgreement`, Bouncy Castle's `ECDHCBasicAgreement`: the x
  coordinate of (h·d)·Q.
- `EcMqvBasicAgreement`, Bouncy Castle's `ECMqvBasicAgreement`, with
  `MqvPrivateParams` and `MqvPublicParams` for the static and ephemeral keys;
  an omitted ephemeral public key is computed by `init`.
- `EcVkoAgreement`, Bouncy Castle's `ECVkoAgreement`, the GOST VKO of
  RFC 7836, generic over the digest, with `EcVkoParams` for the private key
  and the UKM.
- `EcdhError`, `EcMqvError` and `EcVkoError`, for what each agreement turns
  down.
- All of them implement the `tc_agreement` traits, check that the other
  party's keys are on the same domain and are finite points of the curve,
  and turn down a shared point at infinity.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std` with `alloc`, and contains no `unsafe` code.
- Constant time in the private keys as far as the curve's point
  multiplication is; the checks on domains and public keys are variable time.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
