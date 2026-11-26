//! J-PAKE password-authenticated key exchange, after Bouncy Castle's
//! `JPakeParticipant`. The two parties share only a password; after two
//! rounds of payloads each calculates the same keying material, and an
//! optional third round confirms that both used the same password.
//! [`standard_groups`] is Bouncy Castle's `JPakePrimeOrderGroups`.
//!
//! The parties are peers: each runs the same steps, and neither keeps a
//! verifier, so J-PAKE suits pairing two devices or two people over a shared
//! code. A wrong guess of the password costs an attacker a whole exchange with
//! the other party, so short codes work when failures are limited.
//!
//! ```
//! use tc_jpake::{JPakeParams, JPakeParticipant};
//!
//! // Both share the password and use different participant IDs; the group is
//! // NIST's 3072-bit group by default.
//! let mut alice = JPakeParticipant::new(rand::rng());
//! alice.init(&JPakeParams::new("alice", b"password"))?;
//! let mut bob = JPakeParticipant::new(rand::rng());
//! bob.init(&JPakeParams::new("bob", b"password"))?;
//!
//! // Round one: each sends g^x1, g^x2 and zero-knowledge proofs, and checks
//! // the other's.
//! let alice_round1 = alice.create_round1_payload_to_send()?;
//! let bob_round1 = bob.create_round1_payload_to_send()?;
//! alice.validate_round1_payload_received(&bob_round1)?;
//! bob.validate_round1_payload_received(&alice_round1)?;
//!
//! // Round two: each sends A, which mixes in the password, and its proof.
//! let alice_round2 = alice.create_round2_payload_to_send()?;
//! let bob_round2 = bob.create_round2_payload_to_send()?;
//! alice.validate_round2_payload_received(&bob_round2)?;
//! bob.validate_round2_payload_received(&alice_round2)?;
//!
//! // Each calculates the keying material, which a KDF turns into a key.
//! let alice_key = alice.calculate_keying_material()?;
//! let bob_key = bob.calculate_keying_material()?;
//!
//! // Round three: each sends a MacTag, confirming the same password.
//! let alice_round3 = alice.create_round3_payload_to_send(&alice_key)?;
//! let bob_round3 = bob.create_round3_payload_to_send(&bob_key)?;
//! alice.validate_round3_payload_received(&bob_round3, &alice_key)?;
//! bob.validate_round3_payload_received(&alice_round3, &bob_key)?;
//!
//! assert_eq!(*alice_key, *bob_key);
//! # Ok::<(), tc_jpake::JPakeError>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
mod group;
mod params;
mod participant;
mod payloads;
pub mod standard_groups;
mod utilities;

pub use error::JPakeError;
pub use group::JPakePrimeOrderGroup;
pub use params::JPakeParams;
pub use participant::{JPakeParticipant, JPakeState};
pub use payloads::{
    JPakeRound1Payload, JPakeRound2Payload, JPakeRound3Payload, JPakeZeroKnowledgeProof,
};
