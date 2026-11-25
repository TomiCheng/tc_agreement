use crate::group::Group;
use crate::utilities::{self, evidence_matches};
use crate::{Srp6Error, Srp6GroupParameters};
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `Srp6Server`: the server side of SRP-6a, in the message
/// order that Thomas Wu's 2002 paper optimizes. It keeps state, so start each
/// authentication with a new `init`.
///
/// Bouncy Castle adds a random multiple of N - 1 to the private exponent
/// before its variable-time `ModPow`, and notes that v is not protected yet;
/// the exponentiation here is constant time in both b and v already, so the
/// random source only draws b.
pub struct Srp6Server<D, R> {
    digest: D,
    rng: R,
    state: Option<ServerState>,
}

/// The state after `init`: each value appears at its step, and the secret
/// ones are wiped on drop.
struct ServerState {
    group: Group,
    v: Zeroizing<PaddedBigUint>,
    a: Option<PaddedBigUint>,
    private_b: Option<Zeroizing<PaddedBigUint>>,
    public_b: Option<PaddedBigUint>,
    s: Option<Zeroizing<PaddedBigUint>>,
    m1: Option<Vec<u8>>,
    m2: Option<Vec<u8>>,
}

impl<D: Digest, R> Srp6Server<D, R> {
    /// A server that hashes with `digest`, draws b from `rng`, and is not
    /// initialized yet. Constant time.
    pub fn new(digest: D, rng: R) -> Self {
        Self {
            digest,
            rng,
            state: None,
        }
    }

    /// Bouncy Castle's `Init`: starts a new authentication with the user's
    /// verifier v and drops the last one's state, after checking that N is an
    /// odd number above 3 and g is in `[2, N - 2]`; like Bouncy Castle, it does
    /// not check v. Variable time: it branches on the public group alone, and
    /// only copies v.
    pub fn init(
        &mut self,
        group: &Srp6GroupParameters,
        verifier: &PaddedBigUint,
    ) -> Result<(), Srp6Error> {
        self.state = None;
        self.state = Some(ServerState {
            group: Group::new(group)?,
            v: Zeroizing::new(verifier.clone()),
            a: None,
            private_b: None,
            public_b: None,
            s: None,
            m1: None,
            m2: None,
        });
        Ok(())
    }

    /// Bouncy Castle's `GenerateServerCredentials`: draws the private value b
    /// and returns B = (k·v + g^b) mod N to send to the client.
    ///
    /// Constant time in v and b; only the candidates for b that are thrown
    /// away show in the timing.
    pub fn generate_server_credentials(&mut self) -> Result<PaddedBigUint, Srp6Error>
    where
        R: CryptoRng,
    {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let private_b = utilities::generate_private_value(&state.group.n, &mut self.rng)?;
        self.credentials_with(private_b)
    }

    /// [`generate_server_credentials`](Self::generate_server_credentials) with
    /// a given b, as Bouncy Castle's tests override `SelectPrivateValue`.
    /// Constant time in v and b.
    pub(crate) fn credentials_with(
        &mut self,
        private_b: PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let private_b = Zeroizing::new(private_b);
        let group = &state.group;
        let monty = &group.monty;
        let k = utilities::calculate_k(&mut self.digest, &group.n, &group.g)?;
        let v = Zeroizing::new(PaddedMontyForm::new(&state.v, monty));
        let kv = Zeroizing::new(PaddedMontyForm::new(&k, monty) * &*v);
        let gb = Zeroizing::new(PaddedMontyForm::new(&group.g, monty).pow(&private_b));
        let public_b = (&*kv + &*gb).retrieve();
        state.private_b = Some(private_b);
        state.public_b = Some(public_b.clone());
        Ok(public_b)
    }

    /// Bouncy Castle's `CalculateSecret`: checks the client's A and returns the
    /// shared secret S = (A·v^u)^b mod N, which the caller should wipe after
    /// use. Needs
    /// [`generate_server_credentials`](Self::generate_server_credentials)
    /// first.
    ///
    /// Constant time in v, b and S; the check of the public A branches on its
    /// value.
    pub fn calculate_secret(
        &mut self,
        client_a: &PaddedBigUint,
    ) -> Result<PaddedBigUint, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(private_b), Some(public_b)) = (&state.private_b, &state.public_b) else {
            return Err(Srp6Error::MissingValues);
        };
        let a = utilities::validate_public_value(&state.group.n, client_a)?;
        let group = &state.group;
        let monty = &group.monty;
        let u = utilities::calculate_u(&mut self.digest, &group.n, &a, public_b)?;
        let v = Zeroizing::new(PaddedMontyForm::new(&state.v, monty));
        let vu = Zeroizing::new(v.pow(&u));
        let base = Zeroizing::new(PaddedMontyForm::new(&a, monty) * &*vu);
        let power = Zeroizing::new(base.pow(private_b));
        let s = power.retrieve();
        state.a = Some(a);
        state.s = Some(Zeroizing::new(s.clone()));
        Ok(s)
    }

    /// Bouncy Castle's `VerifyClientEvidenceMessage`: whether the client's M1
    /// is right; only a right one is kept. Needs
    /// [`calculate_secret`](Self::calculate_secret) first. Like Bouncy Castle,
    /// which compares integers, it accepts an encoding without leading zeros.
    ///
    /// Constant time in S and M1; it branches on the public lengths alone.
    pub fn verify_client_evidence_message(&mut self, client_m1: &[u8]) -> Result<bool, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(a), Some(public_b), Some(s)) = (&state.a, &state.public_b, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let expected = utilities::calculate_m1(&mut self.digest, &state.group.n, a, public_b, s)?;
        if !evidence_matches(&expected, client_m1) {
            return Ok(false);
        }
        state.m1 = Some(expected);
        Ok(true)
    }

    /// Bouncy Castle's `CalculateServerEvidenceMessage`:
    /// M2 = H(PAD(A) | PAD(M1) | PAD(S)), to send to the client. Needs a
    /// verified M1 first. Constant time in S, as far as the digest is.
    pub fn calculate_server_evidence_message(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_mut().ok_or(Srp6Error::NotInitialized)?;
        let (Some(a), Some(m1), Some(s)) = (&state.a, &state.m1, &state.s) else {
            return Err(Srp6Error::MissingValues);
        };
        let m2 = utilities::calculate_m2(&mut self.digest, &state.group.n, a, m1, s)?;
        state.m2 = Some(m2.clone());
        Ok(m2)
    }

    /// Bouncy Castle's `CalculateSessionKey`: the session key K = H(PAD(S))
    /// once both sides are verified, which the caller should wipe after use.
    /// Needs M2 first. Constant time in S, as far as the digest is.
    pub fn calculate_session_key(&mut self) -> Result<Vec<u8>, Srp6Error> {
        let state = self.state.as_ref().ok_or(Srp6Error::NotInitialized)?;
        let (Some(s), Some(_), Some(_)) = (&state.s, &state.m1, &state.m2) else {
            return Err(Srp6Error::MissingValues);
        };
        utilities::calculate_key(&mut self.digest, &state.group.n, s)
    }
}
