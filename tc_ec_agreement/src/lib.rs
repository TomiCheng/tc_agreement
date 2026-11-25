//! Key agreement over elliptic curves, after Bouncy Castle, through the
//! `tc_agreement` traits and over the keys of `tc_ec_key`.
//!
//! - [`EcdhBasicAgreement`] and [`EcdhcBasicAgreement`]: ECDH and its cofactor
//!   variant ECDHC, after IEEE P1363.
//! - [`EcMqvBasicAgreement`]: EC-MQV, after SEC 1 section 3.4.
//! - [`EcVkoAgreement`]: GOST VKO, after RFC 7836 section 4.3.
//!
//! All follow one shape: `new`, then `init` with the own private parameters,
//! then `calculate_agreement` with the other party's public parameters into a
//! buffer of `agreement_size` bytes. The secret is raw; derive keys from it
//! with a KDF. Each is as constant time in the private keys as the curve's
//! point multiplication, so use the constant-time curve types for secrets.
//!
//! # ECDH
//!
//! Alice and Bob reach the same secret while exchanging only public keys:
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::EcdhBasicAgreement;
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//!
//! // Both use the same constant-time curve and its generator G.
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
//!
//! // Each generates a key pair and sends the public key to the other.
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // Alice combines her private key with Bob's public key...
//! let mut alice = EcdhBasicAgreement::new();
//! alice.init(&alice_private)?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! // ...and Bob the other way round; both pass the same secret to a KDF.
//! let mut bob = EcdhBasicAgreement::new();
//! bob.init(&bob_private)?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(&alice_public, &mut bob_secret)?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # EC-MQV
//!
//! Each party holds a static key pair, makes an ephemeral one for each
//! agreement, and sends both public keys to the other:
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::{EcMqvBasicAgreement, MqvPrivateParams, MqvPublicParams};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//!
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
//!
//! // The static pairs exist beforehand; the ephemeral ones are new each time.
//! let (alice_static_public, alice_static) = generator.generate_key_pair()?;
//! let (bob_static_public, bob_static) = generator.generate_key_pair()?;
//! let (alice_ephemeral_public, alice_ephemeral) = generator.generate_key_pair()?;
//! let (bob_ephemeral_public, bob_ephemeral) = generator.generate_key_pair()?;
//!
//! let mut alice = EcMqvBasicAgreement::new();
//! alice.init(&MqvPrivateParams::new(alice_static, alice_ephemeral))?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(
//!     &MqvPublicParams::new(bob_static_public, bob_ephemeral_public),
//!     &mut alice_secret,
//! )?;
//!
//! let mut bob = EcMqvBasicAgreement::new();
//! bob.init(&MqvPrivateParams::new(bob_static, bob_ephemeral))?;
//! let mut bob_secret = vec![0; bob.agreement_size()];
//! bob.calculate_agreement(
//!     &MqvPublicParams::new(alice_static_public, alice_ephemeral_public),
//!     &mut bob_secret,
//! )?;
//!
//! assert_eq!(alice_secret, bob_secret);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # GOST VKO
//!
//! The parties exchange public keys and agree on a public UKM; each hashes the
//! same secret out of its private key and the other's public key:
//!
//! ```
//! use tc_agreement::{Agreement, AgreementInit};
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_ec_agreement::{EcVkoAgreement, EcVkoParams};
//! use tc_ec_key::{EcKeyGenerationParams, EcKeyPairGenerator};
//! use tc_fp_curve::FpCtCurve;
//! use tc_fp_curve::named_curves::SECP256R1;
//! use tc_gost3411::Gost3411_2012_256Digest;
//!
//! // In practice, a GOST R 34.10-2012 curve.
//! let field = SECP256R1.field();
//! let curve = SECP256R1.ct_curve(&field);
//! let g = SECP256R1.ct_generator(&curve);
//! let mut rng = rand::rng();
//! let mut generator = EcKeyPairGenerator::<&FpCtCurve<'_>, _>::new(&mut rng);
//! generator.init(&EcKeyGenerationParams::new(g))?;
//! let (alice_public, alice_private) = generator.generate_key_pair()?;
//! let (bob_public, bob_private) = generator.generate_key_pair()?;
//!
//! // The UKM is a public random value that both use.
//! let ukm = vec![0x1d, 0x80, 0x60, 0x3c, 0x85, 0x44, 0xc7, 0x27];
//!
//! let mut alice = EcVkoAgreement::new(Gost3411_2012_256Digest::default());
//! alice.init(&EcVkoParams::new(alice_private, ukm.clone()))?;
//! let mut alice_secret = vec![0; alice.agreement_size()];
//! alice.calculate_agreement(&bob_public, &mut alice_secret)?;
//!
//! let mut bob = EcVkoAgreement::new(Gost3411_2012_256Digest::default());
//! bob.init(&EcVkoParams::new(bob_private, ukm))?;
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

mod ecdh;
mod mqv;
mod vko;

pub use ecdh::{EcdhBasicAgreement, EcdhError, EcdhcBasicAgreement};
pub use mqv::{EcMqvBasicAgreement, EcMqvError, MqvPrivateParams, MqvPublicParams};
pub use vko::{EcVkoAgreement, EcVkoError, EcVkoParams};
