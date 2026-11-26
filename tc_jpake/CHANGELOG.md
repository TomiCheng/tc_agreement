# Changelog

All notable changes to `tc_jpake` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `JPakeParticipant`, Bouncy Castle's `JPakeParticipant`, over SHA-256 by
  default or any digest, through the two rounds of payloads, the keying
  material and the optional third round of key confirmation, with
  `JPakeState` tracking its progress.
- `JPakeParams` for the participant ID, the password and the group.
- `JPakePrimeOrderGroup`, Bouncy Castle's `JPakePrimeOrderGroup`, with
  `validate` for its constructor's checks, and `standard_groups` with
  `sun_jce_1024`, `nist_2048` and `nist_3072`.
- `JPakeRound1Payload`, `JPakeRound2Payload`, `JPakeRound3Payload` and
  `JPakeZeroKnowledgeProof`.
- `JPakeError` for what the exchange turns down.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std` with `alloc`, and contains no `unsafe` code.
- Constant time in the password and the secret exponents; the checks of
  groups and payloads are variable time, for public values, and key
  confirmation shows the number of the keying material's leading zero bytes.
- Where Bouncy Castle crashes on a payload validated before the own first
  round, this returns `PrematureStep`; a participant ID of `2^32` bytes or
  more, which the proof's hash cannot encode, gives `ParticipantIdTooLong`
  rather than a panic; q must be odd, as the Montgomery arithmetic needs.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.
