use crate::group::Group;
use crate::utilities::{self, evidence_matches, widened};
use crate::{Srp6Error, Srp6GroupParameters};
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `Srp6Client`: the client side of SRP-6a, in the message
/// order that Thomas Wu's 2002 paper optimizes. It keeps state, so start each
/// authentication with a new `init`.
///
/// Bouncy Castle adds a random multiple of N - 1 to the private exponent
/// before its variable-time `ModPow`; the exponentiation here is constant time
/// already, so the random source only draws a.
pub struct Srp6Client<D, R> {
    digest: D,
    rng: R,
    state: Option<ClientState>,
}

/// The state after `init`: each value appears at its step, and the secret
/// ones are wiped on drop.
struct ClientState {
    group: Group,
    x: Option<Zeroizing<PaddedBigUint>>,
    private_a: Option<Zeroizing<PaddedBigUint>>,
    public_a: Option<PaddedBigUint>,
    b: Option<PaddedBigUint>,
    s: Option<Zeroizing<PaddedBigUint>>,
    m1: Option<Vec<u8>>,
    m2: Option<Vec<u8>>,
}

impl<D: Digest, R> Srp6Client<D, R> {
    /// A client that hashes with `digest`, draws a from `rng`, and is not
    /// initialized yet. Constant time.
    pub fn new(digest: D, rng: R) -> Self {
        Self {
            digest,
            rng,
            state: None,
        }
    }

    /// Bouncy Castle's `Init`: starts a new authentication and drops the last
    /// one's state, after checking that N is an odd number above 3 and g is in
    /// `[2, N - 2]`. Variable time: it branches on the public group alone.
    pub fn init(&mut self, group: &Srp6GroupParameters) -> Result<(), Srp6Error> {
        self.state = None;
        self.state = Some(ClientState {
            group: Group::new(group)?,
            x: None,
            private_a: None,
            public_a: None,
            b: None,
            s: None,
            m1: None,
            m2: None,
        });
        Ok(())
    }

    /// Bouncy Castle's `GenerateClientCredentials`: computes x from the salt,
    /// the identity and the password, draws the private value a, and returns
    /// A = g^a mod N to send to the server.
    ///
    /// Constant time in the password, x and a, as far as the digest is; only
    /// the candidates for a that are thrown away show in the timing.
    pub fn generate_client_credentials(
        &mut self,
        salt: &[u8],
        identity: &[u8],
        password: &[u8],
    ) -> Result<PaddedBigUint, Srp6Error>
    where
        R: CryptoRng,
    {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let private_a = utilities::generate_private_value(&state.group.n, &mut self.rng)?;
        self.credentials_with(salt, identity, password, private_a)
    }

    /// [`generate_client_credentials`](Self::generate_client_credentials) with
    /// a given a, as Bouncy Castle's tests override `SelectPrivateValue`.
    /// Constant time in the password, x and a, as far as the digest is.
    pub(crate) fn credentials_with(
        &mut self,
        salt: &[u8],
        identity: &[u8],
        password: &[u8],
        private_a: PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let private_a = Zeroizing::new(private_a);
        let x = Zeroizing::new(utilities::calculate_x(
            &mut self.digest,
            salt,
            identity,
            password,
        ));
        let power = Zeroizing::new(
            PaddedMontyForm::new(&state.group.g, &state.group.monty).pow(&private_a),
        );
        let public_a = power.retrieve();
        state.x = Some(x);
        state.private_a = Some(private_a);
        state.public_a = Some(public_a.clone());
        Ok(public_a)
    }

    /// Bouncy Castle's `CalculateSecret`: checks the server's B and returns the
    /// shared secret S = (B - k·g^x)^(a + u·x) mod N, which the caller should
    /// wipe after use. Needs
    /// [`generate_client_credentials`](Self::generate_client_credentials)
    /// first.
    ///
    /// Constant time in x, a and S; the check of the public B branches on its
    /// value.
    pub fn calculate_secret(
        &mut self,
        server_b: &PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(x), Some(private_a), Some(public_a)) =
            (&state.x, &state.private_a, &state.public_a)
        else {
            return Err(Srp6Error::MissingValues);
        };
        let b = utilities::validate_public_value(&state.group.n, server_b)?;
        let s = client_secret(&mut self.digest, &state.group, x, private_a, public_a, &b)?;
        state.b = Some(b);
        state.s = Some(Zeroizing::new(s.clone()));
        Ok(s)
    }

    /// Bouncy Castle's `CalculateClientEvidenceMessage`:
    /// M1 = H(PAD(A) | PAD(B) | PAD(S)), to send to the server. Needs
    /// [`calculate_secret`](Self::calculate_secret) first. Constant time in S,
    /// as far as the digest is.
    pub fn calculate_client_evidence_message(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(public_a), Some(b), Some(s)) = (&state.public_a, &state.b, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let m1 = utilities::calculate_m1(&mut self.digest, &state.group.n, public_a, b, s)?;
        state.m1 = Some(m1.clone());
        Ok(m1)
    }

    /// Bouncy Castle's `VerifyServerEvidenceMessage`: whether the server's M2
    /// is right; only a right one is kept. Needs
    /// [`calculate_client_evidence_message`](Self::calculate_client_evidence_message)
    /// first. Like Bouncy Castle, which compares integers, it accepts an
    /// encoding without leading zeros.
    ///
    /// Constant time in S and M2; it branches on the public lengths alone.
    pub fn verify_server_evidence_message(&mut self, server_m2: &[u8]) -> Result<bool, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(public_a), Some(m1), Some(s)) = (&state.public_a, &state.m1, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let expected = utilities::calculate_m2(&mut self.digest, &state.group.n, public_a, m1, s)?;
        if !evidence_matches(&expected, server_m2) {
            return Ok(false);
        }
        state.m2 = Some(expected);
        Ok(true)
    }

    /// Bouncy Castle's `CalculateSessionKey`: the session key K = H(PAD(S))
    /// once both sides are verified, which the caller should wipe after use.
    /// Needs a verified M2 first. Constant time in S, as far as the digest is.
    pub fn calculate_session_key(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let (Some(s), Some(_), Some(_)) = (&state.s, &state.m1, &state.m2) else {
            return Err(Srp6Error::MissingValues);
        };
        utilities::calculate_key(&mut self.digest, &state.group.n, s)
    }
}

/// S = (B - k·g^x)^(a + u·x) mod N, with the exponent computed over the
/// integers rather than modulo anything.
///
/// Constant time in x and a: the multiplication and the exponentiations depend
/// on widths alone, and the intermediate values are wiped; k and u come from
/// public values.
fn client_secret<D: Digest>(
    digest: &mut D,
    group: &Group,
    x: &PaddedBigUint,
    private_a: &PaddedBigUint,
    public_a: &PaddedBigUint,
    b: &PaddedBigUint,
) -> Result<PaddedBigUint, Srp6Error> {
    let k = utilities::calculate_k(digest, &group.n, &group.g)?;
    let u = utilities::calculate_u(digest, &group.n, public_a, b)?;
    // A width that holds u·x + a, so neither the product nor the sum overflows.
    let width = (u.as_limbs().len() + x.as_limbs().len()).max(private_a.as_limbs().len()) + 1;
    let mut exponent = Zeroizing::new(widened(&u, width));
    *exponent *= x;
    *exponent += private_a;

    let monty = &group.monty;
    let gx = Zeroizing::new(PaddedMontyForm::new(&group.g, monty).pow(x));
    let kgx = Zeroizing::new(PaddedMontyForm::new(&k, monty) * &*gx);
    let base = Zeroizing::new(PaddedMontyForm::new(b, monty) - &*kgx);
    let power = Zeroizing::new(base.pow(&exponent));
    Ok(power.retrieve())
}
