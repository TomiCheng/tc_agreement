use crate::{EcVkoError, EcVkoParams};
use alloc::vec;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_digest::Digest;
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `ECVkoAgreement`, the GOST VKO of RFC 7836 section 4.3: the
/// coordinates of the shared point (h·UKM·d)·Q, each little-endian, are
/// hashed together, so the secret is as long as the digest.
///
/// RFC 7836 uses GOST R 34.11-2012 and the GOST curves. Initialize it with a
/// key on a constant-time curve to keep d secret.
pub struct EcVkoAgreement<C: Curve<Scalar = PaddedBigUint>, D> {
    digest: D,
    state: Option<State<C>>,
}

/// The private key that `init` received, and the UKM read as an integer.
struct State<C: Curve<Scalar = PaddedBigUint>> {
    key: EcPrivateKey<C>,
    ukm: PaddedBigUint,
}

impl<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone> EcVkoAgreement<C, D> {
    /// An agreement that hashes the shared point with `digest` and is not
    /// initialized yet. Constant time.
    pub fn new(digest: D) -> Self {
        Self {
            digest,
            state: None,
        }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone> AgreementInit<EcVkoParams<C>>
    for EcVkoAgreement<C, D>
{
    type Error = EcVkoError;

    /// Bouncy Castle's `Init`: keeps a copy of the private key, whose d is
    /// wiped on drop, and reads the UKM as a little-endian integer; the curve
    /// must have an order. A rejected call leaves the agreement uninitialized.
    /// Variable time: it branches on the public UKM and domain alone.
    fn init(&mut self, params: &EcVkoParams<C>) -> Result<(), EcVkoError> {
        self.state = None;
        params
            .key()
            .g()
            .curve()
            .order()
            .ok_or(EcVkoError::MissingOrder)?;
        let mut ukm = params.ukm().to_vec();
        ukm.reverse();
        let Ok(ukm) = PaddedBigUint::from_be(&ukm);
        self.state = Some(State {
            key: params.key().clone(),
            ukm,
        });
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>, D: Digest + Clone> Agreement for EcVkoAgreement<C, D> {
    type PublicKey = EcPublicKey<C>;
    type Error = EcVkoError;

    /// Bouncy Castle's `AgreementSize`: the length of the digest. Constant
    /// time.
    fn agreement_size(&self) -> usize {
        self.digest.digest_size()
    }

    /// Bouncy Castle's `CalculateAgreement`. The public key must be on the
    /// same domain and a finite point of the curve; P = (h·UKM·d mod n)·Q must
    /// not be infinity. The secret is H(x_P ‖ y_P), each coordinate
    /// little-endian at the length of the field.
    ///
    /// Constant time in d and P as far as the curve's multiplication is: h·UKM
    /// depends on public values alone, its product with d is a modular
    /// multiplication, and the checks branch on public values alone.
    fn calculate_agreement(
        &self,
        public_key: &EcPublicKey<C>,
        output: &mut [u8],
    ) -> Result<(), EcVkoError> {
        let state = self.state.as_ref().ok_or(EcVkoError::NotInitialized)?;
        let output = output
            .get_mut(..self.agreement_size())
            .ok_or(EcVkoError::BufferTooSmall)?;
        let g = state.key.g();
        if public_key.g() != g {
            return Err(EcVkoError::DomainMismatch);
        }
        let curve = g.curve();
        let n = NonZero::new(curve.order().ok_or(EcVkoError::MissingOrder)?.clone())
            .ok_or(EcVkoError::MissingOrder)?;
        let h = curve
            .cofactor()
            .cloned()
            .unwrap_or_else(|| PaddedBigUint::from(1u8));
        let hu = h.mod_mul(&state.ukm, &n);
        let hd = Zeroizing::new(hu.mod_mul(state.key.d(), &n));

        let q = clean_point(curve.clone(), public_key.q())
            .ok()
            .filter(|q| !q.is_infinity())
            .ok_or(EcVkoError::InvalidPublicKey)?;
        let p = C::multiply(&q, &hd).normalize();
        if p.is_infinity() {
            return Err(EcVkoError::InvalidAgreement);
        }

        let mut digest = self.digest.clone();
        digest.reset();
        for coordinate in [p.x(), p.y()] {
            let coordinate = coordinate.expect("a finite point");
            let mut bytes = Zeroizing::new(vec![0u8; coordinate.encoded_length()]);
            coordinate.encode_to(&mut bytes);
            bytes.reverse();
            digest.update(&bytes);
        }
        digest.do_final(output);
        Ok(())
    }
}
