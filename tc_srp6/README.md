# tc_srp6

[![crates.io](https://img.shields.io/crates/v/tc_srp6.svg)](https://crates.io/crates/tc_srp6)
[![docs.rs](https://docs.rs/tc_srp6/badge.svg)](https://docs.rs/tc_srp6)
[![CI](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_agreement/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

SRP-6a password-authenticated key exchange of RFC 5054, after Bouncy Castle:
a password login in which the password never crosses the network and the
server keeps only a verifier. `no_std` with `alloc`, no `unsafe`, Rust 1.85
or later.

## Types

- `Srp6VerifierGenerator` — makes the verifier v from the salt, identity and password at registration.
- `Srp6Client` — the client side: sends A and M1, checks M2, takes the session key.
- `Srp6Server` — the server side: sends B from v, checks M1, sends M2.
- `Srp6GroupParameters` — the group N and g; `standard_groups` has those of RFC 5054.
- `Srp6Error` — what the classes turn down.

## Features

None; the crate always uses `alloc`.

## Usage

```rust
let public_b = server.generate_server_credentials()?;
let public_a = client.generate_client_credentials(&salt, identity, password)?;
client.calculate_secret(&public_b)?;
let m1 = client.calculate_client_evidence_message()?;
server.calculate_secret(&public_a)?;
assert!(server.verify_client_evidence_message(&m1)?);
let m2 = server.calculate_server_evidence_message()?;
assert!(client.verify_server_evidence_message(&m2)?);
let key = client.calculate_session_key()?;
```

## Security

The verifier is as sensitive as a password hash: whoever holds it can test
guesses offline and impersonate the server. RFC 5054's x is a single fast
hash, so a slow password hash in front of it is an agreement between the
two ends, outside the standard. The server must check M1 before it sends
M2. The client and the server are constant time in the password, the
private values, v and S; the checks are variable time, for public values.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
