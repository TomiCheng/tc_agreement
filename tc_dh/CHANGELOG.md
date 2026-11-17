# Changelog

All notable changes to `tc_dh` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `DhBasicAgreement`, Bouncy Castle's `DHBasicAgreement`, which implements
  the `tc_agreement` traits and writes the secret y^x mod p as big-endian
  bytes of the length of p, leading zeros kept.
- `DhAgreement`, Bouncy Castle's `DHAgreement`: the MTI/A0 agreement of
  RFC 2631 through `init`, `calculate_message` and `calculate_agreement`.
- `DhAgreementError`, which wraps the `tc_dh_key` error of a rejected
  parameter set, public key or message.
- Both agreements validate the other party's public key, and the MTI/A0
  message, with `DhPublicKey::validate`, and turn down a secret of 1.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std` with `alloc`, and contains no `unsafe` code.
- Constant time in the private values; the checks on parameters and public
  values are variable time.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
