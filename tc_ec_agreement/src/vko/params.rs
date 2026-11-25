use alloc::vec::Vec;
use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::EcPrivateKey;

/// The EC private key that Bouncy Castle wraps in `ParametersWithUkm`: the own
/// private key and the UKM, the user keying material, a public random value
/// both parties agree on.
///
/// It is a container alone; `init` reads it.
#[derive(Clone)]
pub struct EcVkoParams<C: Curve<Scalar = PaddedBigUint>> {
    key: EcPrivateKey<C>,
    ukm: Vec<u8>,
}

impl<C: Curve<Scalar = PaddedBigUint>> EcVkoParams<C> {
    /// The private key and the UKM, which is read as a little-endian integer.
    /// Constant time.
    pub fn new(key: EcPrivateKey<C>, ukm: Vec<u8>) -> Self {
        Self { key, ukm }
    }

    /// The private key. Constant time.
    pub fn key(&self) -> &EcPrivateKey<C> {
        &self.key
    }

    /// The UKM. Constant time.
    pub fn ukm(&self) -> &[u8] {
        &self.ukm
    }
}
