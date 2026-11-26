use crate::JPakeError;
use rand_core::CryptoRng;
use tc_bigint::{BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;

// Bouncy Castle calls `IsProbablePrime` with certainty 20: 10 rounds of
// Miller-Rabin.
const MILLER_RABIN_ROUNDS: u32 = 10;

/// Bouncy Castle's `JPakePrimeOrderGroup`: a prime p, a prime q dividing
/// p − 1, and a generator g of order q.
///
/// It is a container alone and checks nothing when built;
/// [`validate`](Self::validate) makes the checks of Bouncy Castle's
/// constructor, and `JPakeParticipant::init` calls it. The groups of
/// [`standard_groups`](crate::standard_groups) skip the checks, as in Bouncy
/// Castle.
#[derive(Clone, Debug)]
pub struct JPakePrimeOrderGroup {
    p: PaddedBigUint,
    q: PaddedBigUint,
    g: PaddedBigUint,
    skip_checks: bool,
}

impl JPakePrimeOrderGroup {
    /// The group of p, q and g, unchecked. Constant time.
    pub fn new(p: PaddedBigUint, q: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            p,
            q,
            g,
            skip_checks: false,
        }
    }

    /// A group known to be sound, which `validate` need not check: Bouncy
    /// Castle's `skipChecks`. Constant time.
    pub(crate) fn trusted(p: PaddedBigUint, q: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            skip_checks: true,
            ..Self::new(p, q, g)
        }
    }

    /// The modulus p. Constant time.
    pub fn p(&self) -> &PaddedBigUint {
        &self.p
    }

    /// The order q of the subgroup. Constant time.
    pub fn q(&self) -> &PaddedBigUint {
        &self.q
    }

    /// The generator g. Constant time.
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// The checks of Bouncy Castle's constructor, in turn: q divides p − 1, g
    /// is in `[2, p − 1]`, g^q mod p is 1, and p and q each pass 10 rounds of
    /// Miller-Rabin (Bouncy Castle's certainty 20). q must also be odd, as the
    /// Montgomery arithmetic needs; Bouncy Castle accepts q = 2. The standard
    /// groups are not checked, as in Bouncy Castle. Variable time: only for
    /// public values.
    pub fn validate<R: CryptoRng + ?Sized>(&self, rng: &mut R) -> Result<(), JPakeError> {
        if self.skip_checks {
            return Ok(());
        }
        let zero = BigUint::from(0u8);
        let one = BigUint::from(1u8);
        let p = BigUint::from(self.p.clone());
        let q = BigUint::from(self.q.clone());
        let g = BigUint::from(self.g.clone());
        if q == zero {
            return Err(JPakeError::OrderNotPrime);
        }
        if p == zero {
            return Err(JPakeError::ModulusNotPrime);
        }
        if (&p - 1u32) % &q != zero {
            return Err(JPakeError::OrderNotDividing);
        }
        if g < BigUint::from(2u8) || g >= p {
            return Err(JPakeError::GeneratorOutOfRange);
        }
        let modulus = NonZero::new(p.clone()).expect("p is above g");
        if g.mod_pow(&q, &modulus) != one {
            return Err(JPakeError::GeneratorOrderMismatch);
        }
        if !p.is_probable_prime(MILLER_RABIN_ROUNDS, rng) {
            return Err(JPakeError::ModulusNotPrime);
        }
        if !q.bit(0) || !q.is_probable_prime(MILLER_RABIN_ROUNDS, rng) {
            return Err(JPakeError::OrderNotPrime);
        }
        Ok(())
    }
}
