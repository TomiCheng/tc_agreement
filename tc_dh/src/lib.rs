//! Diffie-Hellman key agreement, after Bouncy Castle's `DHBasicAgreement`
//! and `DHAgreement`, over the parameters and keys of `tc_dh_key`.
//!
//! [`DhBasicAgreement`] implements the `tc_agreement` traits: each party
//! combines its private key with the other's public key. [`DhAgreement`] is
//! the MTI/A0 agreement of RFC 2631, in which the parties also exchange a
//! fresh message; it takes an extra step, so it has its own methods.
//!
//! Alice and Bob reach the same secret while exchanging only public keys:
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dh::DhBasicAgreement;
//! use tc_dh_key::standard_groups::rfc3526_2048;
//! use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};
//!
//! // Both use the same public parameters: the 2048-bit group of RFC 3526.
//! let mut rng = rand::rng();
//! let mut generator = DhKeyPairGenerator::new(&mut rng);
//! generator.init(&DhKeyGenerationParams::new(rfc3526_2048()))?;
//!
//! // Each generates a key pair and sends the public key to the other.
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // Alice combines her private key with Bob's public key...
//! let mut alice = DhBasicAgreement::new();
//! alice.init(&alice_private)?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! // ...and Bob the other way round; both pass the same secret to a KDF.
//! let mut bob = DhBasicAgreement::new();
//! bob.init(&bob_private)?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod agreement;
mod basic_agreement;
mod error;

pub use agreement::DhAgreement;
pub use basic_agreement::DhBasicAgreement;
pub use error::DhAgreementError;
