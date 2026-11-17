//! The key-agreement contracts, after Bouncy Castle's `IRawAgreement` and
//! `IBasicAgreement`.
//!
//! This crate defines how to initialize a key agreement with a private key
//! and how to turn the other party's public key into the shared secret; it
//! implements no algorithm. Diffie-Hellman, ECDH, X25519 and other
//! agreements implement the traits in their own crates.
//!
//! # Using an agreement
//!
//! Call [`AgreementInit::init`] with the parameters that hold the private
//! key, size a buffer with [`Agreement::agreement_size`], then write the
//! shared secret into it with [`Agreement::calculate_agreement`] and the
//! other party's public key. The secret is raw: derive keys from it with a
//! KDF rather than using it as a key.
//!
//! Accepted keys, the state left by a failed call and every timing
//! guarantee belong to the implementation, not to these traits.
//!
//! # Implementing an agreement
//!
//! An agreement implements [`AgreementInit`] for the parameters it accepts
//! and [`Agreement`] for the calculation. The toy agreement below multiplies
//! bytes, so both parties reach the same secret; it shows the contract and
//! is not secure.
//!
//! ```
//! use core::fmt;
//! use tc_agreement::{Agreement, AgreementInit};
//!
//! #[derive(Debug)]
//! struct ToyError;
//!
//! impl fmt::Display for ToyError {
//!     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//!         f.write_str("toy agreement failure")
//!     }
//! }
//!
//! impl core::error::Error for ToyError {}
//!
//! const GENERATOR: u8 = 7;
//!
//! #[derive(Default)]
//! struct ToyAgreement {
//!     private: Option<u8>,
//! }
//!
//! impl AgreementInit<u8> for ToyAgreement {
//!     type Error = ToyError;
//!
//!     fn init(&mut self, private: &u8) -> Result<(), ToyError> {
//!         self.private = Some(*private);
//!         Ok(())
//!     }
//! }
//!
//! impl Agreement for ToyAgreement {
//!     type PublicKey = u8;
//!     type Error = ToyError;
//!
//!     fn agreement_size(&self) -> usize {
//!         1
//!     }
//!
//!     fn calculate_agreement(&self, public_key: &u8, output: &mut [u8]) -> Result<(), ToyError> {
//!         let private = self.private.ok_or(ToyError)?;
//!         let secret = output.first_mut().ok_or(ToyError)?;
//!         *secret = private.wrapping_mul(*public_key);
//!         Ok(())
//!     }
//! }
//!
//! // Each party publishes GENERATOR · private.
//! let (alice_private, bob_private) = (3u8, 5u8);
//! let alice_public = GENERATOR.wrapping_mul(alice_private);
//! let bob_public = GENERATOR.wrapping_mul(bob_private);
//!
//! // Alice combines her private key with Bob's public key.
//! let mut alice = ToyAgreement::default();
//! alice.init(&alice_private)?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! // Bob does the same with his, and reaches the same secret.
//! let mut bob = ToyAgreement::default();
//! bob.init(&bob_private)?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), ToyError>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod traits;

pub use traits::{Agreement, AgreementInit};
