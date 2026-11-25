use crate::EcdhError;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// Bouncy Castle's `ECDHBasicAgreement`, ECSVDP-DH of IEEE P1363: the shared
/// secret is the x coordinate of d·Q, for the private scalar d and the other
/// party's public point Q.
///
/// The secret is written as big-endian bytes of the length of a coordinate,
/// leading zeros kept. Initialize it with a key on a constant-time curve to
/// keep d secret.
pub struct EcdhBasicAgreement<C: Curve<Scalar = PaddedBigUint>> {
    key: Option<EcPrivateKey<C>>,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcdhBasicAgreement<C> {
    /// An agreement that is not initialized yet. Constant time.
    pub fn new() -> Self {
        Self { key: None }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Default for EcdhBasicAgreement<C> {
    /// The same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> AgreementInit<EcPrivateKey<C>> for EcdhBasicAgreement<C> {
    type Error = EcdhError;

    /// Keeps a copy of the private key, whose d is wiped on drop; like Bouncy
    /// Castle, it makes no other check. Constant time.
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcdhError> {
        self.key = Some(key.clone());
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Agreement for EcdhBasicAgreement<C> {
    type PublicKey = EcPublicKey<C>;
    type Error = EcdhError;

    /// Bouncy Castle's `GetFieldSize`: the length of a coordinate in bytes, or
    /// 0 until `init` succeeds. Constant time.
    fn agreement_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| key.g().curve().one().encoded_length())
    }

    /// Bouncy Castle's `CalculateAgreement`. The public key must be on the
    /// same domain and a finite point of the curve; the shared point must not
    /// be infinity. The x coordinate goes into the front of `output`.
    ///
    /// Constant time in d as far as the curve's multiplication is: the checks
    /// branch on public values alone.
    fn calculate_agreement(
        &self,
        public_key: &EcPublicKey<C>,
        output: &mut [u8],
    ) -> Result<(), EcdhError> {
        let key = self.key.as_ref().ok_or(EcdhError::NotInitialized)?;
        let x = agreement_x(key, public_key)?;
        let output = output
            .get_mut(..x.encoded_length())
            .ok_or(EcdhError::BufferTooSmall)?;
        x.encode_to(output);
        Ok(())
    }
}

/// Bouncy Castle's `CalculateAgreementFieldElement`. With a cofactor h other
/// than one, Q is first multiplied by h, which removes any small-subgroup
/// part, and d by the inverse of h modulo n, which leaves d·Q unchanged.
///
/// Constant time in d as far as the curve's multiplication is: d is scaled by
/// Montgomery multiplication, and the branches depend on the domain and Q
/// alone.
fn agreement_x<C: Curve<Scalar = PaddedBigUint>>(
    key: &EcPrivateKey<C>,
    public_key: &EcPublicKey<C>,
) -> Result<C::Field, EcdhError> {
    if key.g() != public_key.g() {
        return Err(EcdhError::WrongDomain);
    }
    let curve = key.g().curve();
    let mut q =
        clean_point(curve.clone(), public_key.q()).map_err(|_| EcdhError::InvalidPublicKey)?;
    if q.is_infinity() {
        return Err(EcdhError::InvalidPublicKey);
    }

    let mut scaled = None;
    if let Some(h) = curve.cofactor().filter(|h| **h != PaddedBigUint::from(1u8)) {
        // EcPrivateKey::new has checked that the curve has an order.
        let n = curve.order().expect("a private key's curve has an order");
        let n = Odd::new(n.clone()).ok_or(EcdhError::InvalidCofactor)?;
        let params = PaddedMontyParams::new(n);
        let h_inverse = PaddedMontyForm::new(h, &params)
            .invert()
            .ok_or(EcdhError::InvalidCofactor)?;
        let mut d = PaddedMontyForm::new(key.d(), &params);
        d *= &h_inverse;
        scaled = Some(Zeroizing::new(d.retrieve()));
        d.zeroize();
        q = C::multiply(&q, h);
    }

    let d = scaled.as_deref().unwrap_or(key.d());
    let p = C::multiply(&q, d);
    if p.is_infinity() {
        return Err(EcdhError::InvalidAgreement);
    }
    Ok(p.x().expect("a finite point"))
}
