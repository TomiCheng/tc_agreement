# Changelog

All notable changes to `tc_agreement` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- The `Agreement` contract for `agreement_size` and `calculate_agreement`,
  which writes the shared secret with the other party's public key into a
  caller-provided buffer at a fixed length; the Rust form of Bouncy Castle's
  `IRawAgreement`, in place of `IBasicAgreement`'s integer.
- `AgreementInit`, which initializes an agreement from parameters of type
  `P`, by reference, holding the private key.
- A doctest that implements both traits on a toy agreement.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std`, needs no allocator, has no dependencies and contains no `unsafe`
  code.
- The traits make no timing promise; each implementation documents its own.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
