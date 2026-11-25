# Changelog

All notable changes to `tc_srp6` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Srp6Client` and `Srp6Server`, Bouncy Castle's `Srp6Client` and
  `Srp6Server`: SRP-6a of RFC 5054, through the credentials, the shared
  secret, the evidence messages M1 and M2, and the session key.
- `Srp6VerifierGenerator`, Bouncy Castle's `Srp6VerifierGenerator`, which
  makes the verifier v that the server keeps.
- `Srp6GroupParameters`, and `standard_groups` with the 1024- to 8192-bit
  groups of RFC 5054 appendix A.
- `utilities`, Bouncy Castle's `Srp6Utilities`: k, u, x, the private value,
  the check of a public value, M1, M2 and the session key.
- `Srp6Error`, for what the classes turn down. Where Bouncy Castle throws
  because a value is longer than N, the utilities return
  `Srp6Error::ValueTooLong`.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std` with `alloc`, and contains no `unsafe` code.
- Constant time in the password, x, the private values, v and S; the
  exponentiation needs no blinding, so Bouncy Castle's is left out. Checks
  on the group and on public values are variable time.
- M1, M2 and the session key keep the digest's bytes, leading zeros
  included, where Bouncy Castle turns them into integers.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
