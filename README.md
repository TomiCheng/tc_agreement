# tc_agreement

A Rust workspace for key agreement after Bouncy Castle: the contracts that a
key agreement implements, through which a private key and the other party's
public key make a shared secret, and Diffie-Hellman agreement over them. Each
crate is published separately and keeps its own README and changelog.

[![CI](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_agreement`](tc_agreement) | [![crates.io](https://img.shields.io/crates/v/tc_agreement.svg)](https://crates.io/crates/tc_agreement) [![docs.rs](https://docs.rs/tc_agreement/badge.svg)](https://docs.rs/tc_agreement) | The `Agreement` and `AgreementInit` contracts, the Rust form of Bouncy Castle's `IRawAgreement`, which write the shared secret as bytes of a fixed length. `no_std`, no allocator, no dependencies, no `unsafe`. The traits make no timing promise; each implementation states its own. |
| [`tc_dh`](tc_dh) | [![crates.io](https://img.shields.io/crates/v/tc_dh.svg)](https://crates.io/crates/tc_dh) [![docs.rs](https://docs.rs/tc_dh/badge.svg)](https://docs.rs/tc_dh) | Diffie-Hellman key agreement after Bouncy Castle's `DHBasicAgreement` and `DHAgreement`, the MTI/A0 agreement of RFC 2631, over the keys of `tc_dh_key`. `no_std` with `alloc`, no `unsafe`. Constant time in the private values; the checks are variable time, for public values. |

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std`.
`tc_agreement` needs no allocator; `tc_dh` always uses `alloc` for its
integers.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build. Besides `tc_*` crates, the libraries depend only on `num-traits`
and `rand_core`, both of which build on 1.85. Dev-dependencies used only by
tests are exempt. The workspace lock tracks the latest dependency releases,
so CI on stable tests what a user on a current toolchain resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, checks the `wasm32-unknown-unknown` and `aarch64-unknown-none`
targets and each crate's dependency set on each target, checks the build on
Rust 1.85.0, and verifies the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

Before a release, check each archive and run publication validation from a
committed checkout:

```text
cargo package -p <crate> --list --locked
cargo publish -p <crate> --dry-run --locked
```

Publish in dependency order: `tc_agreement`, then `tc_dh`. The archive
must include both license texts, the crate README, the changelog, the source
and, for `tc_dh`, the integration tests, and no `target/` or other build
artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
