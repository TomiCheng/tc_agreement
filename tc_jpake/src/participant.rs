use crate::utilities::{
    Domain, calculate_s, mac_tag, validate_mac_tag, validate_not_one,
    validate_participant_id_length, validate_participant_ids_differ,
    validate_participant_ids_equal,
};
use crate::{JPakeError, JPakeParams, JPakeRound1Payload, JPakeRound2Payload, JPakeRound3Payload};
use alloc::string::String;
use rand_core::CryptoRng;
use tc_bigint::PaddedBigUint;
use tc_digest::Digest;
use tc_sha::Sha256Digest;
use tc_zeroize::Zeroizing;

/// The progress of a `JPakeParticipant`, in the order of the exchange;
/// Bouncy Castle's `STATE_*` constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JPakeState {
    /// Just initialized.
    Initialized,
    /// The first round's payload is created.
    Round1Created,
    /// The partner's first-round payload is validated.
    Round1Validated,
    /// The second round's payload is created.
    Round2Created,
    /// The partner's second-round payload is validated.
    Round2Validated,
    /// The keying material is calculated.
    KeyCalculated,
    /// The third round's payload is created.
    Round3Created,
    /// The partner's third-round payload is validated.
    Round3Validated,
}

/// Bouncy Castle's `JPakeParticipant`: one party of a J-PAKE exchange. The two
/// parties share only a password; each creates and sends the payloads of the
/// first and second rounds, validates the partner's, and calculates the same
/// keying material. The optional third round confirms that the partner used
/// the same password. The keying material must go through a KDF before it is a
/// session key.
///
/// Each step can be taken once and only after the one before it, or it returns
/// [`JPakeError::RepeatedStep`] or [`JPakeError::PrematureStep`]; Bouncy Castle
/// crashes on a null when the partner's payload is validated before the own
/// first-round payload is created, and this returns the latter instead. The
/// digest is SHA-256 by default.
pub struct JPakeParticipant<R, D = Sha256Digest> {
    digest: D,
    rng: R,
    session: Option<Session>,
}

/// The state after `init`. x1 is used in the first round alone and not kept.
struct Session {
    participant_id: String,
    domain: Domain,
    state: JPakeState,
    s: Option<Zeroizing<PaddedBigUint>>,
    x2: Option<Zeroizing<PaddedBigUint>>,
    gx1: Option<PaddedBigUint>,
    gx2: Option<PaddedBigUint>,
    partner_participant_id: Option<String>,
    gx3: Option<PaddedBigUint>,
    gx4: Option<PaddedBigUint>,
    b: Option<PaddedBigUint>,
}

impl<R: CryptoRng> JPakeParticipant<R, Sha256Digest> {
    /// A participant over SHA-256, Bouncy Castle's default, not initialized
    /// yet. Constant time.
    pub fn new(rng: R) -> Self {
        Self::with_digest(Sha256Digest::new(), rng)
    }
}

impl<R: CryptoRng, D: Digest + Clone> JPakeParticipant<R, D> {
    /// A participant over `digest`, drawing from `rng`, not initialized yet.
    /// Constant time.
    pub fn with_digest(digest: D, rng: R) -> Self {
        Self {
            digest,
            rng,
            session: None,
        }
    }

    /// The checks of Bouncy Castle's constructor: the password must not be
    /// empty, the group must pass `JPakePrimeOrderGroup::validate`, and the
    /// password must not be 0 modulo q (Bouncy Castle checks it in the second
    /// round). The participant ID must also be shorter than `2^32` bytes, the
    /// most the proof's hash encodes. It then returns to
    /// [`JPakeState::Initialized`].
    ///
    /// Variable time: it branches on the public group and ID alone; the
    /// password's reduction does not depend on its value, only its length
    /// shows.
    pub fn init(&mut self, params: &JPakeParams) -> Result<(), JPakeError> {
        self.session = None;
        if params.password().is_empty() {
            return Err(JPakeError::EmptyPassword);
        }
        validate_participant_id_length(params.participant_id())?;
        params.group().validate(&mut self.rng)?;
        let domain = Domain::new(params.group())?;
        let s = calculate_s(domain.q(), params.password())?;
        self.session = Some(Session {
            participant_id: params.participant_id().into(),
            domain,
            state: JPakeState::Initialized,
            s: Some(s),
            x2: None,
            gx1: None,
            gx2: None,
            partner_participant_id: None,
            gx3: None,
            gx4: None,
            b: None,
        });
        Ok(())
    }

    /// The progress so far, or `None` before `init`. Constant time.
    pub fn state(&self) -> Option<JPakeState> {
        self.session.as_ref().map(|session| session.state)
    }

    /// Bouncy Castle's `CreateRound1PayloadToSend`: draws x1 from `[0, q − 1]`
    /// and x2 from `[1, q − 1]`, and sends g^x1, g^x2 and their zero-knowledge
    /// proofs. Constant time in x1 and x2.
    pub fn create_round1_payload_to_send(&mut self) -> Result<JPakeRound1Payload, JPakeError> {
        let Self {
            digest,
            rng,
            session,
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round1Created, JPakeState::Initialized)?;
        let domain = &session.domain;
        let x1 = domain.generate_x1(rng);
        let x2 = domain.generate_x2(rng);
        let gx1 = domain.power(domain.g(), &x1);
        let gx2 = domain.power(domain.g(), &x2);
        let id = &session.participant_id;
        let proof1 = domain.prove(domain.g(), &gx1, &x1, id, digest, rng);
        let proof2 = domain.prove(domain.g(), &gx2, &x2, id, digest, rng);
        let payload = JPakeRound1Payload::new(id, gx1.clone(), gx2.clone(), proof1, proof2);
        session.x2 = Some(x2);
        session.gx1 = Some(gx1);
        session.gx2 = Some(gx2);
        session.state = JPakeState::Round1Created;
        Ok(payload)
    }

    /// Bouncy Castle's `ValidateRound1PayloadReceived`: the partner's ID must
    /// differ from the own and be shorter than `2^32` bytes, g^x4 must not be
    /// 1, and both zero-knowledge proofs must hold. Variable time: only for
    /// public values.
    pub fn validate_round1_payload_received(
        &mut self,
        payload: &JPakeRound1Payload,
    ) -> Result<(), JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round1Validated, JPakeState::Initialized)?;
        let domain = &session.domain;
        let partner = payload.participant_id();
        validate_participant_id_length(partner)?;
        validate_participant_ids_differ(&session.participant_id, partner)?;
        validate_not_one(payload.gx2(), JPakeError::GxIsOne)?;
        domain.verify(
            domain.g(),
            payload.gx1(),
            payload.knowledge_proof_for_x1(),
            partner,
            digest,
        )?;
        domain.verify(
            domain.g(),
            payload.gx2(),
            payload.knowledge_proof_for_x2(),
            partner,
            digest,
        )?;
        session.partner_participant_id = Some(partner.into());
        session.gx3 = Some(payload.gx1().clone());
        session.gx4 = Some(payload.gx2().clone());
        session.state = JPakeState::Round1Validated;
        Ok(())
    }

    /// Bouncy Castle's `CreateRound2PayloadToSend`: sends
    /// A = (g^x1·g^x3·g^x4)^(x2·s) and the zero-knowledge proof for x2·s, over
    /// the generator g^(x1 + x3 + x4). Constant time in x2 and s.
    pub fn create_round2_payload_to_send(&mut self) -> Result<JPakeRound2Payload, JPakeError> {
        let Self {
            digest,
            rng,
            session,
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round2Created, JPakeState::Round1Validated)?;
        let domain = &session.domain;
        let ga = domain.product(
            required(&session.gx1)?,
            required(&session.gx3)?,
            required(&session.gx4)?,
        );
        let x2s = domain.x2s(required(&session.x2)?, required(&session.s)?);
        let a = domain.power(&ga, &x2s);
        let proof = domain.prove(&ga, &a, &x2s, &session.participant_id, digest, rng);
        session.state = JPakeState::Round2Created;
        Ok(JPakeRound2Payload::new(&session.participant_id, a, proof))
    }

    /// Bouncy Castle's `ValidateRound2PayloadReceived`: the payload must come
    /// from the partner of the first round, the generator g^(x3 + x1 + x2) must
    /// not be 1, and the zero-knowledge proof for x4·s must hold. Variable
    /// time: only for public values.
    pub fn validate_round2_payload_received(
        &mut self,
        payload: &JPakeRound2Payload,
    ) -> Result<(), JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round2Validated, JPakeState::Round1Validated)?;
        let domain = &session.domain;
        let gb = domain.product(
            required(&session.gx3)?,
            required(&session.gx1)?,
            required(&session.gx2)?,
        );
        let partner = payload.participant_id();
        validate_participant_ids_differ(&session.participant_id, partner)?;
        validate_participant_ids_equal(required(&session.partner_participant_id)?, partner)?;
        validate_not_one(&gb, JPakeError::GaIsOne)?;
        domain.verify(
            &gb,
            payload.a(),
            payload.knowledge_proof_for_x2s(),
            partner,
            digest,
        )?;
        session.b = Some(payload.a().clone());
        session.state = JPakeState::Round2Validated;
        Ok(())
    }

    /// Bouncy Castle's `CalculateKeyingMaterial`: K = (B / g^(x2·x4·s))^x2 mod
    /// p, as wide as p. s, x2 and B are dropped afterwards. K must go through a
    /// KDF before it is a key, and only the third round confirms that both
    /// sides reached it. Constant time in x2 and s.
    pub fn calculate_keying_material(&mut self) -> Result<Zeroizing<PaddedBigUint>, JPakeError> {
        let session = self.session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::KeyCalculated, JPakeState::Round2Validated)?;
        let key = session.domain.keying_material(
            required(&session.gx4)?,
            required(&session.x2)?,
            required(&session.s)?,
            required(&session.b)?,
        );
        session.s = None;
        session.x2 = None;
        session.b = None;
        session.state = JPakeState::KeyCalculated;
        Ok(key)
    }

    /// Bouncy Castle's `CreateRound3PayloadToSend`: the MacTag of key
    /// confirmation from the keying material, to send to the partner. Variable
    /// time: the number of K's leading zero bytes shows, through Bouncy
    /// Castle's encoding of the MacTag's input.
    pub fn create_round3_payload_to_send(
        &mut self,
        keying_material: &PaddedBigUint,
    ) -> Result<JPakeRound3Payload, JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round3Created, JPakeState::KeyCalculated)?;
        let tag = mac_tag(
            &session.participant_id,
            required(&session.partner_participant_id)?,
            session.gx()?,
            keying_material,
            digest,
        );
        session.state = JPakeState::Round3Created;
        Ok(JPakeRound3Payload::new(&session.participant_id, tag))
    }

    /// Bouncy Castle's `ValidateRound3PayloadReceived`: the payload must come
    /// from the partner of the first round and its MacTag must match, compared
    /// without stopping early; g^x1 to g^x4 are dropped afterwards. Variable
    /// time: the number of K's leading zero bytes shows, as in
    /// [`create_round3_payload_to_send`](Self::create_round3_payload_to_send);
    /// the comparison shows only through its result.
    pub fn validate_round3_payload_received(
        &mut self,
        payload: &JPakeRound3Payload,
        keying_material: &PaddedBigUint,
    ) -> Result<(), JPakeError> {
        let Self {
            digest, session, ..
        } = self;
        let session = session.as_mut().ok_or(JPakeError::NotInitialized)?;
        session.check(JPakeState::Round3Validated, JPakeState::KeyCalculated)?;
        let partner = payload.participant_id();
        validate_participant_ids_differ(&session.participant_id, partner)?;
        validate_participant_ids_equal(required(&session.partner_participant_id)?, partner)?;
        validate_mac_tag(
            &session.participant_id,
            partner,
            session.gx()?,
            keying_material,
            digest,
            payload.mac_tag(),
        )?;
        session.gx1 = None;
        session.gx2 = None;
        session.gx3 = None;
        session.gx4 = None;
        session.state = JPakeState::Round3Validated;
        Ok(())
    }
}

impl Session {
    /// The check at the start of each of Bouncy Castle's steps: progress at
    /// `done` means the step was taken, progress before `needed` means the one
    /// before it was not. Constant time.
    fn check(&self, done: JPakeState, needed: JPakeState) -> Result<(), JPakeError> {
        if self.state >= done {
            Err(JPakeError::RepeatedStep)
        } else if self.state < needed {
            Err(JPakeError::PrematureStep)
        } else {
            Ok(())
        }
    }

    /// g^x1 to g^x4, missing when the first round's creation or validation was
    /// skipped. Constant time.
    fn gx(&self) -> Result<[&PaddedBigUint; 4], JPakeError> {
        Ok([
            required(&self.gx1)?,
            required(&self.gx2)?,
            required(&self.gx3)?,
            required(&self.gx4)?,
        ])
    }
}

/// A value an earlier step left, or [`JPakeError::PrematureStep`] when that
/// step was skipped. Constant time.
fn required<T>(value: &Option<T>) -> Result<&T, JPakeError> {
    value.as_ref().ok_or(JPakeError::PrematureStep)
}
