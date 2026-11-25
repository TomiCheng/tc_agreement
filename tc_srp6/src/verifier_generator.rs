use crate::group::Group;
use crate::utilities;
use crate::{Srp6Error, Srp6GroupParameters};
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `Srp6VerifierGenerator`: makes the verifier
/// v = g^x mod N that the server keeps for a user. Authentication must later
/// use the same digest, which also sets the length of the session key.
///
/// Bouncy Castle takes a random source to blind its variable-time `ModPow`;
/// the exponentiation here is constant time, so it needs none.
pub struct Srp6VerifierGenerator<D> {
    digest: D,
    group: Option<Group>,
}

impl<D: Digest> Srp6VerifierGenerator<D> {
    /// A generator that hashes with `digest` and is not initialized yet.
    /// Constant time.
    pub fn new(digest: D) -> Self {
        Self {
            digest,
            group: None,
        }
    }

    /// Bouncy Castle's `Init`: sets the group, after checking that N is an odd
    /// number above 3 and g is in `[2, N - 2]`. Variable time: it branches on
    /// the public group alone.
    pub fn init(&mut self, group: &Srp6GroupParameters) -> Result<(), Srp6Error> {
        self.group = None;
        self.group = Some(Group::new(group)?);
        Ok(())
    }

    /// Bouncy Castle's `GenerateVerifier`: computes x from the salt, the
    /// identity and the password, and returns v = g^x mod N. The salt should
    /// be random and long enough. Constant time in the password and x, as far
    /// as the digest is; x is wiped.
    pub fn generate_verifier(
        &mut self,
        salt: &[u8],
        identity: &[u8],
        password: &[u8],
    ) -> Result<PaddedBigUint, Srp6Error> {
        let group = self.group.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let x = Zeroizing::new(utilities::calculate_x(
            &mut self.digest,
            salt,
            identity,
            password,
        ));
        let power = Zeroizing::new(PaddedMontyForm::new(&group.g, &group.monty).pow(&x));
        Ok(power.retrieve())
    }
}
