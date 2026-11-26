//! Bouncy Castle's `JPakeUtilities`: the basic operations of J-PAKE. Bouncy
//! Castle makes them public; here only `JPakeParticipant` uses them, and the
//! group's arithmetic sits in [`Domain`], which keeps the Montgomery
//! parameters.

use crate::{JPakeError, JPakePrimeOrderGroup, JPakeZeroKnowledgeProof};
use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint, RandomRange};
use tc_constant_time::{ConstantTimeEq, fixed_time_eq};
use tc_digest::Digest;
use tc_macs::{Hmac, KeyRef, Mac, MacInit};
use tc_modular::{ModMul, ModPow, NonZero, Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroizing;

/// The group's p, q and g, with the Montgomery parameters of p and q.
pub(crate) struct Domain {
    p: PaddedMontyParams,
    q: PaddedMontyParams,
    g: PaddedBigUint,
}

impl Domain {
    /// Sets up the Montgomery parameters of `group`; p and q must be odd.
    /// Variable time: it branches on the public group alone.
    pub(crate) fn new(group: &JPakePrimeOrderGroup) -> Result<Self, JPakeError> {
        let p = Odd::new(group.p().clone()).ok_or(JPakeError::ModulusNotPrime)?;
        let q = Odd::new(group.q().clone()).ok_or(JPakeError::OrderNotPrime)?;
        Ok(Self {
            p: PaddedMontyParams::new(p),
            q: PaddedMontyParams::new(q),
            g: group.g().clone(),
        })
    }

    /// The group's generator g. Constant time.
    pub(crate) fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// The Montgomery parameters of the subgroup's order q. Constant time.
    pub(crate) fn q(&self) -> &PaddedMontyParams {
        &self.q
    }

    /// Bouncy Castle's `GenerateX1`: uniform in `[0, q − 1]`, as wide as q.
    /// Constant time in the value drawn: only the candidates thrown away show
    /// in the timing.
    pub(crate) fn generate_x1<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Zeroizing<PaddedBigUint> {
        let zero = PaddedBigUint::from(0u8);
        Zeroizing::new(PaddedBigUint::random_range(rng, &zero, self.q.modulus()))
    }

    /// Bouncy Castle's `GenerateX2`: uniform in `[1, q − 1]`, as wide as q.
    /// Constant time in the value drawn: only the candidates thrown away show
    /// in the timing.
    pub(crate) fn generate_x2<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> Zeroizing<PaddedBigUint> {
        let one = PaddedBigUint::from(1u8);
        Zeroizing::new(PaddedBigUint::random_range(rng, &one, self.q.modulus()))
    }

    /// Bouncy Castle's `CalculateGx` and `CalculateA`: base^exponent mod p.
    /// Constant time in the exponent: the loop runs by its width alone.
    pub(crate) fn power(&self, base: &PaddedBigUint, exponent: &PaddedBigUint) -> PaddedBigUint {
        let base = Zeroizing::new(PaddedMontyForm::new(base, &self.p));
        let power = Zeroizing::new(base.pow(exponent));
        power.retrieve()
    }

    /// Bouncy Castle's `CalculateGA`: a·b·c mod p, of three public values.
    /// Constant time.
    pub(crate) fn product(
        &self,
        a: &PaddedBigUint,
        b: &PaddedBigUint,
        c: &PaddedBigUint,
    ) -> PaddedBigUint {
        let mut product = PaddedMontyForm::new(a, &self.p);
        product *= &PaddedMontyForm::new(b, &self.p);
        product *= &PaddedMontyForm::new(c, &self.p);
        product.retrieve()
    }

    /// Bouncy Castle's `CalculateX2s`: x2·s mod q, as wide as q. Constant time.
    pub(crate) fn x2s(&self, x2: &PaddedBigUint, s: &PaddedBigUint) -> Zeroizing<PaddedBigUint> {
        let mut product = Zeroizing::new(PaddedMontyForm::new(x2, &self.q));
        *product *= &*Zeroizing::new(PaddedMontyForm::new(s, &self.q));
        Zeroizing::new(product.retrieve())
    }

    /// Bouncy Castle's `CalculateZeroKnowledgeProof`: a Schnorr signature
    /// proving knowledge of the x of gx = generator^x. With v drawn from
    /// `[0, q − 1]`, it returns {generator^v, r = v − x·h mod q}, h as
    /// [`proof_hash`](Self::proof_hash) gives it. Constant time in x and v; the
    /// hash takes public values alone.
    pub(crate) fn prove<D: Digest, R: CryptoRng + ?Sized>(
        &self,
        generator: &PaddedBigUint,
        gx: &PaddedBigUint,
        x: &PaddedBigUint,
        participant_id: &str,
        digest: &mut D,
        rng: &mut R,
    ) -> JPakeZeroKnowledgeProof {
        let v = self.generate_x1(rng);
        let gv = self.power(generator, &v);
        let h = self.proof_hash(generator, &gv, gx, participant_id, digest);
        let mut r = Zeroizing::new(PaddedMontyForm::new(&v, &self.q));
        let mut xh = Zeroizing::new(PaddedMontyForm::new(x, &self.q));
        *xh *= &PaddedMontyForm::new(&h, &self.q);
        *r -= &*xh;
        JPakeZeroKnowledgeProof::new(gv, r.retrieve())
    }

    /// Bouncy Castle's `ValidateZeroKnowledgeProof`: gx is in `(0, p)`, gx^q
    /// mod p is 1, and generator^r · gx^h mod p equals g^v. Variable time: only
    /// for public values.
    pub(crate) fn verify<D: Digest>(
        &self,
        generator: &PaddedBigUint,
        gx: &PaddedBigUint,
        proof: &JPakeZeroKnowledgeProof,
        participant_id: &str,
        digest: &mut D,
    ) -> Result<(), JPakeError> {
        let h = BigUint::from(self.proof_hash(generator, proof.gv(), gx, participant_id, digest));
        let p = BigUint::from(self.p.modulus().clone());
        let q = BigUint::from(self.q.modulus().clone());
        let gx = BigUint::from(gx.clone());
        let modulus = NonZero::new(p.clone()).expect("p is odd");
        let one = BigUint::from(1u8);
        let valid = gx > BigUint::from(0u8) && gx < p && gx.mod_pow(&q, &modulus) == one && {
            let generator = BigUint::from(generator.clone());
            let r = BigUint::from(proof.r().clone());
            let gr = generator.mod_pow(&r, &modulus);
            gr.mod_mul(&gx.mod_pow(&h, &modulus), &modulus) == BigUint::from(proof.gv().clone())
        };
        if valid {
            Ok(())
        } else {
            Err(JPakeError::InvalidProof)
        }
    }

    /// Bouncy Castle's `CalculateHashForZeroKnowledgeProof`: the generator,
    /// g^v, gx and the participant ID, each after its length as four
    /// big-endian bytes, hashed together. Bouncy Castle reads the hash as a
    /// signed integer; this takes its value modulo q, which is the same in the
    /// proof because gx has order q. Variable time: only for public values.
    fn proof_hash<D: Digest>(
        &self,
        generator: &PaddedBigUint,
        gv: &PaddedBigUint,
        gx: &PaddedBigUint,
        participant_id: &str,
        digest: &mut D,
    ) -> PaddedBigUint {
        digest.reset();
        for value in [generator, gv, gx] {
            update_with_length(digest, &unsigned_bytes(value));
        }
        update_with_length(digest, participant_id.as_bytes());
        let mut output = vec![0u8; digest.digest_size()];
        digest.do_final(&mut output);

        let q = BigUint::from(self.q.modulus().clone());
        let Ok(unsigned) = BigUint::from_be(&output);
        let h = if output.first().is_some_and(|byte| byte & 0x80 != 0) {
            // Two's complement: h = unsigned − 2^(8·length), so
            // h mod q = q − ((2^(8·length) − unsigned) mod q).
            let wrap = BigUint::from(1u8) << (8 * output.len() as u32);
            let r = (wrap - unsigned) % &q;
            if r == BigUint::from(0u8) { r } else { &q - r }
        } else {
            unsigned % &q
        };
        PaddedBigUint::from(h)
    }

    /// Bouncy Castle's `CalculateKeyingMaterial`:
    /// (B / g^(x2·x4·s))^x2 = (gx4^(−x2·s mod q) · B)^x2 mod p, as wide as p.
    /// Constant time in x2 and s.
    pub(crate) fn keying_material(
        &self,
        gx4: &PaddedBigUint,
        x2: &PaddedBigUint,
        s: &PaddedBigUint,
        b: &PaddedBigUint,
    ) -> Zeroizing<PaddedBigUint> {
        let x2s = self.x2s(x2, s);
        let negated = Zeroizing::new(-&*Zeroizing::new(PaddedMontyForm::new(&x2s, &self.q)));
        let exponent = Zeroizing::new(negated.retrieve());
        let mut base = Zeroizing::new(PaddedMontyForm::new(gx4, &self.p).pow(&exponent));
        *base *= &PaddedMontyForm::new(b, &self.p);
        let key = Zeroizing::new(base.pow(x2));
        Zeroizing::new(key.retrieve())
    }
}

/// Bouncy Castle's `CalculateS`: the password as an unsigned big-endian
/// integer, modulo q, turned down when it is 0. Constant time in the password:
/// its length alone sets the width, and whether it is 0 shows only through the
/// error.
pub(crate) fn calculate_s(
    q: &PaddedMontyParams,
    password: &[u8],
) -> Result<Zeroizing<PaddedBigUint>, JPakeError> {
    let Ok(password) = PaddedBigUint::from_be(password);
    let password = Zeroizing::new(password);
    let s = Zeroizing::new(&*password % q.modulus());
    if s.ct_eq(&PaddedBigUint::from(0u8)).unwrap_u8() == 1 {
        return Err(JPakeError::InvalidPassword);
    }
    Ok(s)
}

/// Bouncy Castle's `ValidateGx4` and `ValidateGa`: `value` must not be 1, or
/// it returns `error`. Variable time: only for public values.
pub(crate) fn validate_not_one(value: &PaddedBigUint, error: JPakeError) -> Result<(), JPakeError> {
    if *value == PaddedBigUint::from(1u8) {
        Err(error)
    } else {
        Ok(())
    }
}

/// Bouncy Castle's `ValidateParticipantIdsDiffer`: the two participant IDs
/// must differ. Variable time: only for public values.
pub(crate) fn validate_participant_ids_differ(
    participant_id: &str,
    other_participant_id: &str,
) -> Result<(), JPakeError> {
    if participant_id == other_participant_id {
        Err(JPakeError::SameParticipantId)
    } else {
        Ok(())
    }
}

/// Bouncy Castle's `ValidateParticipantIdsEqual`: the payload must come from
/// the partner of the first round. Variable time: only for public values.
pub(crate) fn validate_participant_ids_equal(
    expected_participant_id: &str,
    actual_participant_id: &str,
) -> Result<(), JPakeError> {
    if expected_participant_id == actual_participant_id {
        Ok(())
    } else {
        Err(JPakeError::UnexpectedParticipant)
    }
}

/// A participant ID must be shorter than `2^32` bytes, since the proof's hash
/// writes its length in four bytes. Checking the own ID at `init` and the
/// partner's when it first arrives keeps [`update_with_length`] from meeting a
/// longer one. Variable time: only for public values.
pub(crate) fn validate_participant_id_length(participant_id: &str) -> Result<(), JPakeError> {
    u32::try_from(participant_id.len())
        .map(|_| ())
        .map_err(|_| JPakeError::ParticipantIdTooLong)
}

/// Bouncy Castle's `CalculateMacTag`, the unilateral key confirmation of NIST
/// SP 800-56A: MacKey = H(K ‖ "JPAKE_KC") and MacTag = HMAC(MacKey, "KC_1_U" ‖
/// own ID ‖ partner's ID ‖ g^x1 ‖ g^x2 ‖ g^x3 ‖ g^x4), every integer as its
/// shortest unsigned big-endian bytes. Both sides use "KC_1_U", since the
/// sender of the third round is always the initiator of the confirmation.
/// Variable time: the number of K's leading zero bytes shows in the length
/// hashed, which Bouncy Castle's encoding brings and nothing here can avoid;
/// the other inputs are public, and MacKey is wiped after use.
pub(crate) fn mac_tag<D: Digest + Clone>(
    participant_id: &str,
    partner_participant_id: &str,
    gx: [&PaddedBigUint; 4],
    keying_material: &PaddedBigUint,
    digest: &mut D,
) -> Vec<u8> {
    digest.reset();
    digest.update(&unsigned_bytes(keying_material));
    digest.update(b"JPAKE_KC");
    let mut mac_key = Zeroizing::new(vec![0u8; digest.digest_size()]);
    digest.do_final(&mut mac_key);

    let mut mac = Hmac::new(digest.clone());
    let Ok(()) = mac.init(&KeyRef::new(&mac_key));
    let mut update = |input: &[u8]| mac.update(input).expect("the MAC is initialized");
    update(b"KC_1_U");
    update(participant_id.as_bytes());
    update(partner_participant_id.as_bytes());
    for value in gx {
        update(&unsigned_bytes(value));
    }
    let mut tag = vec![0u8; mac.mac_size()];
    mac.do_final(&mut tag).expect("the tag fits");
    tag
}

/// Bouncy Castle's `ValidateMacTag`: the MacTag from the partner's side, with
/// the IDs swapped and g^x1, g^x2 swapped with g^x3, g^x4, compared with the
/// one received without stopping early. Variable time: as [`mac_tag`] for the
/// calculation; the comparison shows only through its result.
pub(crate) fn validate_mac_tag<D: Digest + Clone>(
    participant_id: &str,
    partner_participant_id: &str,
    gx: [&PaddedBigUint; 4],
    keying_material: &PaddedBigUint,
    digest: &mut D,
    partner_mac_tag: &[u8],
) -> Result<(), JPakeError> {
    let expected = mac_tag(
        partner_participant_id,
        participant_id,
        [gx[2], gx[3], gx[0], gx[1]],
        keying_material,
        digest,
    );
    if fixed_time_eq(&expected, partner_mac_tag) {
        Ok(())
    } else {
        Err(JPakeError::MacTagMismatch)
    }
}

/// The shortest unsigned big-endian bytes of `value`, Bouncy Castle's
/// `AsUnsignedByteArray`: leading zeros dropped, and nothing for 0. Variable
/// time: the number of leading zero bytes shows, which for a secret value is
/// all it discloses.
fn unsigned_bytes(value: &PaddedBigUint) -> Zeroizing<Vec<u8>> {
    let full = Zeroizing::new(ArrayEncoding::<u8>::to_be(value));
    let start = full
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(full.len());
    Zeroizing::new(full[start..].to_vec())
}

/// Bouncy Castle's `UpdateDigestIncludingSize`: the length as four big-endian
/// bytes, then the bytes. Variable time: only for public values.
fn update_with_length<D: Digest>(digest: &mut D, bytes: &[u8]) {
    // The integers are no wider than p, and every participant ID is checked by
    // validate_participant_id_length before it is hashed.
    let length = u32::try_from(bytes.len()).expect("a length below 2^32");
    digest.update(&length.to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standard_groups::{nist_3072, sun_jce_1024};
    use tc_sha::{Sha1Digest, Sha256Digest};

    fn domain() -> Domain {
        Domain::new(&sun_jce_1024()).unwrap()
    }

    #[test]
    fn one_is_refused_as_g_x4_or_ga() {
        let ten = PaddedBigUint::from(10u8);
        let one = PaddedBigUint::from(1u8);
        assert_eq!(validate_not_one(&ten, JPakeError::GxIsOne), Ok(()));
        assert_eq!(
            validate_not_one(&one, JPakeError::GxIsOne),
            Err(JPakeError::GxIsOne)
        );
        assert_eq!(
            validate_not_one(&one, JPakeError::GaIsOne),
            Err(JPakeError::GaIsOne)
        );
    }

    #[test]
    fn participant_ids_compare_case_sensitively() {
        assert_eq!(validate_participant_ids_differ("a", "b"), Ok(()));
        assert_eq!(validate_participant_ids_differ("a", "A"), Ok(()));
        assert_eq!(
            validate_participant_ids_differ("a", "a"),
            Err(JPakeError::SameParticipantId)
        );
        assert_eq!(validate_participant_ids_equal("a", "a"), Ok(()));
        assert_eq!(
            validate_participant_ids_equal("a", "b"),
            Err(JPakeError::UnexpectedParticipant)
        );
    }

    #[test]
    fn a_mac_tag_validates_only_from_the_partners_side() {
        let domain = domain();
        let mut rng = rand::rng();
        let mut digest = Sha256Digest::new();
        let x1 = domain.generate_x1(&mut rng);
        let x2 = domain.generate_x2(&mut rng);
        let x3 = domain.generate_x1(&mut rng);
        let x4 = domain.generate_x2(&mut rng);
        let gx1 = domain.power(domain.g(), &x1);
        let gx2 = domain.power(domain.g(), &x2);
        let gx3 = domain.power(domain.g(), &x3);
        let gx4 = domain.power(domain.g(), &x4);
        let gb = domain.product(&gx3, &gx1, &gx2);
        let s = calculate_s(domain.q(), b"password").unwrap();
        let x4s = domain.x2s(&x4, &s);
        let b = domain.power(&gb, &x4s);
        let key = domain.keying_material(&gx4, &x2, &s, &b);
        let gx = [&gx1, &gx2, &gx3, &gx4];
        let tag = mac_tag(
            "participantId",
            "partnerParticipantId",
            gx,
            &key,
            &mut digest,
        );

        let partner = [&gx3, &gx4, &gx1, &gx2];
        assert_eq!(
            validate_mac_tag(
                "partnerParticipantId",
                "participantId",
                partner,
                &key,
                &mut digest,
                &tag
            ),
            Ok(())
        );
        assert_eq!(
            validate_mac_tag(
                "participantId",
                "partnerParticipantId",
                gx,
                &key,
                &mut digest,
                &tag
            ),
            Err(JPakeError::MacTagMismatch),
            "its own tag"
        );
        assert_eq!(
            validate_mac_tag(
                "participantId",
                "partnerParticipantId",
                partner,
                &key,
                &mut digest,
                &tag
            ),
            Err(JPakeError::MacTagMismatch),
            "the ids switched"
        );
    }

    #[test]
    fn a_zero_knowledge_proof_holds_only_for_its_group_digest_participant_and_value() {
        let domain = domain();
        let mut rng = rand::rng();
        let mut digest = Sha256Digest::new();
        let g = domain.g();
        let x1 = domain.generate_x1(&mut rng);
        let gx1 = domain.power(g, &x1);
        let proof1 = domain.prove(g, &gx1, &x1, "participant1", &mut digest, &mut rng);
        assert_eq!(
            domain.verify(g, &gx1, &proof1, "participant1", &mut digest),
            Ok(())
        );

        let other = Domain::new(&nist_3072()).unwrap();
        let wrong = Err(JPakeError::InvalidProof);
        assert_eq!(
            other.verify(other.g(), &gx1, &proof1, "participant1", &mut digest),
            wrong,
            "another group"
        );
        assert_eq!(
            domain.verify(g, &gx1, &proof1, "participant1", &mut Sha1Digest::new()),
            wrong,
            "another digest"
        );
        assert_eq!(
            domain.verify(g, &gx1, &proof1, "participant2", &mut digest),
            wrong,
            "another participant"
        );

        let x2 = domain.generate_x2(&mut rng);
        let gx2 = domain.power(g, &x2);
        assert_eq!(
            domain.verify(g, &gx2, &proof1, "participant1", &mut digest),
            wrong,
            "another g^x"
        );
        let proof2 = domain.prove(g, &gx2, &x2, "participant1", &mut digest, &mut rng);
        assert_eq!(
            domain.verify(g, &gx1, &proof2, "participant1", &mut digest),
            wrong,
            "another proof"
        );

        let group = sun_jce_1024();
        for (gx, case) in [
            (PaddedBigUint::from(0u8), "g^x = 0"),
            (group.p().clone(), "g^x = p"),
            (group.q() + 1u32, "g^x = q + 1"),
        ] {
            assert_eq!(
                domain.verify(g, &gx, &proof1, "participant1", &mut digest),
                wrong,
                "{case}"
            );
        }
    }

    #[test]
    fn a_password_that_is_zero_modulo_q_is_refused() {
        let domain = domain();
        let q = ArrayEncoding::<u8>::to_be(domain.q().modulus());
        assert_eq!(
            calculate_s(domain.q(), &q).map(|_| ()),
            Err(JPakeError::InvalidPassword)
        );
        assert_eq!(
            *calculate_s(domain.q(), &[1]).unwrap(),
            PaddedBigUint::from(1u8)
        );
    }

    #[test]
    fn a_negative_hash_is_reduced_as_bouncy_castle_reads_it() {
        // q = 7 and the hash 0xff: Bouncy Castle reads −1, which is 6 modulo 7.
        let group = JPakePrimeOrderGroup::new(
            PaddedBigUint::from(29u8),
            PaddedBigUint::from(7u8),
            PaddedBigUint::from(16u8),
        );
        let domain = Domain::new(&group).unwrap();
        let mut digest = Fixed(0xff);
        let one = PaddedBigUint::from(1u8);
        let h = domain.proof_hash(&one, &one, &one, "", &mut digest);
        assert_eq!(h, PaddedBigUint::from(6u8));
        let mut digest = Fixed(0x7f);
        let h = domain.proof_hash(&one, &one, &one, "", &mut digest);
        assert_eq!(h, PaddedBigUint::from(0x7fu8 % 7));
    }

    /// A digest whose output is one fixed byte.
    #[derive(Clone)]
    struct Fixed(u8);

    impl tc_digest::TryDigest for Fixed {
        type Error = core::convert::Infallible;

        fn digest_size(&self) -> usize {
            1
        }

        fn byte_length(&self) -> usize {
            1
        }

        fn try_update(&mut self, _: &[u8]) -> Result<(), Self::Error> {
            Ok(())
        }

        fn try_do_final(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            output[0] = self.0;
            Ok(1)
        }

        fn try_reset(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
