use crate::DhAgreementError;
use crate::basic_agreement::write_be;
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_constant_time::ConstantTimeEq;
use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator, DhPrivateKey, DhPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `DHAgreement`: the MTI/A0 agreement of RFC 2631, for two
/// parties who each hold a static key pair. Each sends the other a fresh
/// value from [`calculate_message`](Self::calculate_message), and the shared
/// secret is (the other's static public key)^(own ephemeral private value) ·
/// (the other's message)^(own static private value) mod p.
///
/// The agreement takes three steps, `init`, `calculate_message` and
/// `calculate_agreement`, so it has its own methods rather than the
/// `tc_agreement` traits; Bouncy Castle's class implements no agreement
/// interface either. As there, the ephemeral private value stays until the
/// next `calculate_message` or `init`, so `calculate_agreement` may use it
/// more than once.
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_dh::DhAgreement;
/// use tc_dh_key::standard_groups::rfc3526_2048;
/// use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};
///
/// // Each party already holds a static key pair and the other's static public key.
/// let mut rng = rand::rng();
/// let mut generator = DhKeyPairGenerator::new(&mut rng);
/// generator.init(&DhKeyGenerationParams::new(rfc3526_2048()))?;
/// let (alice_public, alice_private) = generator.generate_key_pair()?;
/// let (bob_public, bob_private) = generator.generate_key_pair()?;
///
/// // For each agreement, both work out a fresh message and send it to the other.
/// let mut alice = DhAgreement::new(rand::rng());
/// alice.init(&alice_private)?;
/// let alice_message = alice.calculate_message()?;
/// let mut bob = DhAgreement::new(rand::rng());
/// bob.init(&bob_private)?;
/// let bob_message = bob.calculate_message()?;
///
/// // With the other's static public key and message, both reach the same
/// // secret and pass it to a KDF.
/// let mut alice_secret = vec![0; alice.agreement_size()];
/// alice.calculate_agreement(&bob_public, &bob_message, &mut alice_secret)?;
/// let mut bob_secret = vec![0; bob.agreement_size()];
/// bob.calculate_agreement(&alice_public, &alice_message, &mut bob_secret)?;
/// assert_eq!(alice_secret, bob_secret);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct DhAgreement<R> {
    rng: R,
    state: Option<(DhPrivateKey, PaddedMontyParams)>,
    ephemeral: Option<DhPrivateKey>,
}

impl<R: CryptoRng> DhAgreement<R> {
    /// An agreement that is not initialized yet, which draws its ephemeral
    /// keys from `rng`. Constant time.
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            state: None,
            ephemeral: None,
        }
    }

    /// Keeps a copy of the static private key, whose x is wiped on drop, and
    /// drops any earlier ephemeral private value, after checking the
    /// parameters with `DhParameters::validate`; sets up Montgomery arithmetic
    /// modulo p. A rejected call leaves the agreement uninitialized. Variable
    /// time: it branches on the parameters alone, which are public.
    pub fn init(&mut self, key: &DhPrivateKey) -> Result<(), DhAgreementError> {
        self.state = None;
        self.ephemeral = None;
        key.params()
            .validate()
            .map_err(DhAgreementError::InvalidParameters)?;
        let p = Odd::new(key.params().p().clone()).ok_or(DhAgreementError::InvalidParameters(
            tc_dh_key::DhError::InvalidModulus,
        ))?;
        self.state = Some((key.clone(), PaddedMontyParams::new(p)));
        Ok(())
    }

    /// Bouncy Castle's `CalculateMessage`: generates an ephemeral key pair
    /// over the parameters, keeps its private value r in place of any earlier
    /// one, and returns g^r mod p to send to the other party. Constant time in
    /// r, as `DhKeyPairGenerator` is.
    pub fn calculate_message(&mut self) -> Result<PaddedBigUint, DhAgreementError> {
        let Self {
            rng,
            state,
            ephemeral,
        } = self;
        let (key, _) = state.as_ref().ok_or(DhAgreementError::NotInitialized)?;
        let mut generator = DhKeyPairGenerator::new(rng);
        generator
            .init(&DhKeyGenerationParams::new(key.params().clone()))
            .map_err(DhAgreementError::InvalidParameters)?;
        let (public_key, private_key) = generator
            .generate_key_pair()
            .map_err(DhAgreementError::InvalidParameters)?;
        *ephemeral = Some(private_key);
        Ok(public_key.y().clone())
    }

    /// The length of p in bytes, or 0 until `init` succeeds. Constant time.
    pub fn agreement_size(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, |(key, _)| (key.params().p().bits() as usize).div_ceil(8))
    }

    /// Bouncy Castle's `CalculateAgreement`. The other party's static public
    /// key must be on the same parameters; it and `message` must pass
    /// `DhPublicKey::validate`, or a peer could send elements of small order
    /// to learn a reused private value; and (the public key)^r must not be 1.
    /// The secret is written as big-endian bytes of the length of p, leading
    /// zeros kept.
    ///
    /// Constant time in the private values: the checks branch on public
    /// values, both exponentiations run in constant time, and whether the
    /// ephemeral half is 1 is compared in constant time and shows only
    /// through the error.
    pub fn calculate_agreement(
        &self,
        public_key: &DhPublicKey,
        message: &PaddedBigUint,
        output: &mut [u8],
    ) -> Result<(), DhAgreementError> {
        let (key, monty) = self
            .state
            .as_ref()
            .ok_or(DhAgreementError::NotInitialized)?;
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or(DhAgreementError::MessageNotCalculated)?;
        if public_key.params() != key.params() {
            return Err(DhAgreementError::WrongParameters);
        }
        DhPublicKey::new(message.clone(), key.params().clone())
            .validate()
            .map_err(DhAgreementError::InvalidMessage)?;
        public_key
            .validate()
            .map_err(DhAgreementError::InvalidPublicKey)?;
        let size = self.agreement_size();
        let output = output
            .get_mut(..size)
            .ok_or(DhAgreementError::BufferTooSmall)?;

        let partial =
            Zeroizing::new(PaddedMontyForm::new(public_key.y(), monty).pow(ephemeral.x()));
        let partial_value = Zeroizing::new(partial.retrieve());
        if partial_value.ct_eq(&PaddedBigUint::from(1u8)).unwrap_u8() == 1 {
            return Err(DhAgreementError::InvalidAgreement);
        }
        let mut shared = Zeroizing::new(PaddedMontyForm::new(message, monty).pow(key.x()));
        *shared *= &*partial;
        write_be(&Zeroizing::new(shared.retrieve()), output);
        Ok(())
    }
}
