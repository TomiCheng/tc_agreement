use crate::EcdhError;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::PaddedBigUint;
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::{EcPrivateKey, EcPublicKey};
use tc_modular::{ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `ECDHCBasicAgreement` and `ECDhcRawAgreement`, ECSVDP-DHC
/// of IEEE P1363: the shared secret is the x coordinate of (h·d)·Q, for the
/// cofactor h.
///
/// With h equal to one it matches [`EcdhBasicAgreement`](crate::EcdhBasicAgreement);
/// otherwise its shared point is h times that one, and the two do not
/// interoperate. Initialize it with a key on a constant-time curve to keep d
/// secret.
pub struct EcdhcBasicAgreement<C: Curve<Scalar = PaddedBigUint>> {
    key: Option<EcPrivateKey<C>>,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcdhcBasicAgreement<C> {
    /// An agreement that is not initialized yet. Constant time.
    pub fn new() -> Self {
        Self { key: None }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Default for EcdhcBasicAgreement<C> {
    /// The same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> AgreementInit<EcPrivateKey<C>> for EcdhcBasicAgreement<C> {
    type Error = EcdhError;

    /// Keeps a copy of the private key, whose d is wiped on drop; like Bouncy
    /// Castle, it makes no other check. Constant time.
    fn init(&mut self, key: &EcPrivateKey<C>) -> Result<(), EcdhError> {
        self.key = Some(key.clone());
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Agreement for EcdhcBasicAgreement<C> {
    type PublicKey = EcPublicKey<C>;
    type Error = EcdhError;

    /// Bouncy Castle's `GetFieldSize`: the length of a coordinate in bytes, or
    /// 0 until `init` succeeds. Constant time.
    fn agreement_size(&self) -> usize {
        self.key
            .as_ref()
            .map_or(0, |key| key.g().curve().one().encoded_length())
    }

    /// Bouncy Castle's `CalculateAgreementFieldElement`. The public key must
    /// be on the same domain and a finite point of the curve; P = (h·d mod n)·Q
    /// must not be infinity. The x coordinate of P goes into the front of
    /// `output`, big-endian.
    ///
    /// Constant time in d as far as the curve's multiplication is: h·d is a
    /// modular multiplication, and the checks branch on public values alone.
    fn calculate_agreement(
        &self,
        public_key: &EcPublicKey<C>,
        output: &mut [u8],
    ) -> Result<(), EcdhError> {
        let key = self.key.as_ref().ok_or(EcdhError::NotInitialized)?;
        if key.g() != public_key.g() {
            return Err(EcdhError::WrongDomain);
        }
        let curve = key.g().curve();
        // EcPrivateKey::new has checked that the curve has an order above d.
        let n = curve.order().expect("a private key's curve has an order");
        let n = NonZero::new(n.clone()).expect("the order is above d, so not zero");
        let h = curve
            .cofactor()
            .cloned()
            .unwrap_or_else(|| PaddedBigUint::from(1u8));
        let hd = Zeroizing::new(h.mod_mul(key.d(), &n));

        let q = clean_point(curve.clone(), public_key.q())
            .ok()
            .filter(|q| !q.is_infinity())
            .ok_or(EcdhError::InvalidPublicKey)?;
        let p = C::multiply(&q, &hd);
        if p.is_infinity() {
            return Err(EcdhError::InvalidAgreement);
        }
        let x = p.x().expect("a finite point");
        let output = output
            .get_mut(..x.encoded_length())
            .ok_or(EcdhError::BufferTooSmall)?;
        x.encode_to(output);
        Ok(())
    }
}
