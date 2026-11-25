use crate::{EcMqvError, MqvPrivateParams, MqvPublicParams};
use alloc::vec;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_ec_core::algo::clean_point;
use tc_ec_core::{Curve, FieldElement, Point};
use tc_ec_key::EcPrivateKey;
use tc_modular::{ModAdd, ModMul, NonZero};
use tc_zeroize::Zeroizing;

/// Bouncy Castle's `ECMqvBasicAgreement` and `ECMqvRawAgreement`: the ECMQV
/// primitive of SEC 1 section 3.4, whose secret is the x coordinate of the
/// shared point.
///
/// Each party brings a static and an ephemeral key pair. The secret is written
/// as big-endian bytes of the length of a coordinate, leading zeros kept.
/// Initialize it with keys on a constant-time curve to keep them secret.
pub struct EcMqvBasicAgreement<C: Curve<Scalar = PaddedBigUint>> {
    state: Option<State<C>>,
}

/// The two private keys that `init` checked, and the own ephemeral public
/// point.
struct State<C: Curve<Scalar = PaddedBigUint>> {
    static_key: EcPrivateKey<C>,
    ephemeral_key: EcPrivateKey<C>,
    ephemeral_point: C::Point,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcMqvBasicAgreement<C> {
    /// An agreement that is not initialized yet. Constant time.
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Default for EcMqvBasicAgreement<C> {
    /// The same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> AgreementInit<MqvPrivateParams<C>>
    for EcMqvBasicAgreement<C>
{
    type Error = EcMqvError;

    /// The checks of Bouncy Castle's `MqvPrivateParameters` constructor: the
    /// two private keys and a supplied ephemeral public key must be on one
    /// domain, whose curve has an order. An omitted ephemeral public key is
    /// computed as G times the ephemeral private key. Keeps copies of the
    /// private keys, whose d is wiped on drop. A rejected call leaves the
    /// agreement uninitialized.
    ///
    /// Constant time in the private keys as far as the curve's multiplication
    /// is: the checks branch on the domain alone.
    fn init(&mut self, params: &MqvPrivateParams<C>) -> Result<(), EcMqvError> {
        self.state = None;
        let g = params.static_key().g();
        if params.ephemeral_key().g() != g {
            return Err(EcMqvError::DomainMismatch);
        }
        g.curve().order().ok_or(EcMqvError::MissingOrder)?;
        let ephemeral_point = match params.ephemeral_public_key() {
            Some(key) if key.g() != g => return Err(EcMqvError::DomainMismatch),
            Some(key) => key.q().clone(),
            None => C::multiply(g, params.ephemeral_key().d()).normalize(),
        };
        self.state = Some(State {
            static_key: params.static_key().clone(),
            ephemeral_key: params.ephemeral_key().clone(),
            ephemeral_point,
        });
        Ok(())
    }
}

impl<C: Curve<Scalar = PaddedBigUint>> Agreement for EcMqvBasicAgreement<C> {
    type PublicKey = MqvPublicParams<C>;
    type Error = EcMqvError;

    /// Bouncy Castle's `GetFieldSize`: the length of a coordinate in bytes, or
    /// 0 until `init` succeeds. Constant time.
    fn agreement_size(&self) -> usize {
        self.state.as_ref().map_or(0, |state| {
            state.static_key.g().curve().one().encoded_length()
        })
    }

    /// Bouncy Castle's `CalculateAgreement`. The other party's two public keys
    /// must be on the same domain and finite points of the curve; the shared
    /// point must not be infinity. Its x coordinate goes into the front of
    /// `output`, big-endian.
    ///
    /// Constant time in the private keys as far as the curve's multiplication
    /// is; see `agreement_x`.
    fn calculate_agreement(
        &self,
        public_key: &MqvPublicParams<C>,
        output: &mut [u8],
    ) -> Result<(), EcMqvError> {
        let state = self.state.as_ref().ok_or(EcMqvError::NotInitialized)?;
        let x = agreement_x(state, public_key)?;
        let output = output
            .get_mut(..x.encoded_length())
            .ok_or(EcMqvError::BufferTooSmall)?;
        x.encode_to(output);
        Ok(())
    }
}

/// Bouncy Castle's `CalculateMqvAgreement`, SEC 1 section 3.4: with
/// e = ⌈bits(n) / 2⌉ and s = d₁ᵤ·Q̄₂ᵤ + d₂ᵤ, the shared point is
/// P = h·s·(Q₁ᵥ + Q̄₂ᵥ·Q₂ᵥ) mod n, computed as the sum of two point
/// multiplications.
///
/// Constant time in the private keys and P as far as the curve's
/// multiplication is: s, h·s and the coefficients come from modular addition
/// and multiplication, and Q̄ depends on the public ephemeral keys alone.
fn agreement_x<C: Curve<Scalar = PaddedBigUint>>(
    state: &State<C>,
    public_key: &MqvPublicParams<C>,
) -> Result<C::Field, EcMqvError> {
    let g = state.static_key.g();
    if public_key.static_key().g() != g || public_key.ephemeral_key().g() != g {
        return Err(EcMqvError::DomainMismatch);
    }
    let curve = g.curve();
    let n = NonZero::new(curve.order().ok_or(EcMqvError::MissingOrder)?.clone())
        .ok_or(EcMqvError::MissingOrder)?;
    let h = curve
        .cofactor()
        .cloned()
        .unwrap_or_else(|| PaddedBigUint::from(1u8));
    let e = n.bits().div_ceil(2);

    let clean = |point: &C::Point| {
        clean_point(curve.clone(), point)
            .ok()
            .filter(|point| !point.is_infinity())
            .ok_or(EcMqvError::InvalidPublicKey)
    };
    let q2u = clean(&state.ephemeral_point)?;
    let q1v = clean(public_key.static_key().q())?;
    let q2v = clean(public_key.ephemeral_key().q())?;

    let q2u_bar = reduce::<C>(&q2u, e);
    let product = Zeroizing::new(state.static_key.d().mod_mul(&q2u_bar, &n));
    let s = Zeroizing::new(product.mod_add(state.ephemeral_key.d(), &n));
    let hs = Zeroizing::new(h.mod_mul(&s, &n));
    let q2v_bar = reduce::<C>(&q2v, e);
    let k1 = Zeroizing::new(q2v_bar.mod_mul(&hs, &n));
    let p = C::multiply(&q1v, &k1)
        .add(&C::multiply(&q2v, &hs))
        .normalize();
    if p.is_infinity() {
        return Err(EcMqvError::InvalidAgreement);
    }
    Ok(p.x().expect("a finite point"))
}

/// Q̄ = 2^e + (x mod 2^e), for the x coordinate of the point. Variable time:
/// only for public ephemeral keys.
fn reduce<C: Curve>(point: &C::Point, e: u32) -> PaddedBigUint {
    let x = point.x().expect("a finite point");
    let mut bytes = vec![0u8; x.encoded_length()];
    x.encode_to(&mut bytes);
    let Ok(x) = BigUint::from_be(&bytes);
    let mut bound = BigUint::from(0u8);
    bound.set_bit(e, true);
    let mut reduced = x % &bound;
    reduced.set_bit(e, true);
    PaddedBigUint::from(reduced)
}
