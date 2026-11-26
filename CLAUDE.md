# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs are short and written for crates.io: the badge block, a
  sentence or two on what the crate is, the "Types", "Traits" and "Features"
  lists, a usage example of ten lines or fewer, a short security note and the
  license. Behaviour belongs in the rustdoc, and validation and release
  commands in the root README.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``).

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std`. `tc_agreement` needs no allocator; `tc_dh`, `tc_ec_agreement`,
`tc_jpake` and `tc_srp6` always use `alloc` for their integers.

The crates follow Bouncy Castle's key-agreement classes and keep their names
where they fit. `tc_agreement` holds the contracts alone: `Agreement`, after
`IRawAgreement`, which writes the shared secret into a caller-provided buffer
at a fixed length rather than returning `IBasicAgreement`'s integer, and
`AgreementInit<P>`, which takes the parameters holding the private key by
reference. Initialization and calculation are separate traits. The traits
make no timing promise; each implementation states its own. The crate has no
dependencies and needs no allocator. `agreement_size` never panics: an
agreement that learns the length from `init` reports 0 until then.

`tc_dh` holds Diffie-Hellman agreement over the parameters and keys of
`tc_dh_key`. `DhBasicAgreement`, after `DHBasicAgreement`, implements the
`tc_agreement` traits. `DhAgreement`, after `DHAgreement`, is the MTI/A0
agreement of RFC 2631; its extra `calculate_message` step does not fit the
traits, so it keeps its own methods, as Bouncy Castle's class implements no
agreement interface. Both validate the other party's public key, and the
MTI/A0 message, with `DhPublicKey::validate`, turn down a secret of 1, and
write the secret at the length of p. They are constant time in the private
values; the checks are variable time, for public values.

`tc_ec_agreement` holds the agreements over elliptic curves, over the keys
of `tc_ec_key`, in one module per algorithm: `EcdhBasicAgreement` and
`EcdhcBasicAgreement` (ECDH and ECDHC), `EcMqvBasicAgreement` with
`MqvPrivateParams` and `MqvPublicParams`, and `EcVkoAgreement`, the GOST VKO
of RFC 7836, generic over its digest, with `EcVkoParams`. All implement the
`tc_agreement` traits and are re-exported at the crate root; each module keeps
its own error type. Finite-field agreement stays in `tc_dh`. They are as
constant time in the private keys as the curve's point multiplication; the
checks on domains and public keys are variable time.

`tc_srp6` holds SRP-6a of RFC 5054: `Srp6Client`, `Srp6Server`,
`Srp6VerifierGenerator`, `Srp6GroupParameters` with `standard_groups`, and
the public `utilities` module after `Srp6Utilities`. Like `DhAgreement`, its
steps do not fit the `tc_agreement` traits, so it keeps Bouncy Castle's
methods and depends on no sibling. Where Bouncy Castle throws because a value
is longer than N, the utilities return `Srp6Error::ValueTooLong`, and they
pad every value before feeding the digest, so a rejected call leaves the
caller's digest untouched. The RFC 5054 appendix B vectors are a unit test in
`src/tests.rs`, since they need the crate-internal `credentials_with`.

`tc_jpake` holds J-PAKE: `JPakeParticipant` with `JPakeParams`, the payloads
of its three rounds, `JPakePrimeOrderGroup` with `standard_groups`, and
`JPakeState`. Like `tc_srp6`, its rounds do not fit the `tc_agreement`
traits, so it keeps Bouncy Castle's methods and depends on no sibling. Bouncy
Castle's `JPakeUtilities` stays private here. A participant ID is checked to
be shorter than `2^32` bytes at `init` and when the partner's first arrives,
so the proof's hash never meets a longer one.

`tc_dh`, `tc_ec_agreement`, `tc_jpake` and `tc_srp6` each have a
`tests/documentation.rs` that requires the declarations it lists to say
"constant time" or "variable time", exactly one, matched without case and
across wrapped lines; `tc_jpake` checks every function, private helpers
included. Keep the timing contract of each item stated in its doc comment,
and extend the list when adding declarations.

`unsafe` code is forbidden at every crate root.

Rust 1.85 is guaranteed for every build. Besides `tc_*` crates, the libraries
depend on `num-traits` and `rand_core`, and both build on 1.85;
dev-dependencies such as `rand` are exempt, so tests run on stable.
`.cargo/config.toml` sets `incompatible-rust-versions = "allow"` so
`Cargo.lock` tracks the latest releases. Adding a third-party dependency to a
library hands the 1.85 guarantee to that crate; raise it before doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans. An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in
each crate's `README.md` — and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
