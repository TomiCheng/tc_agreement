use tc_bigint::PaddedBigUint;
use tc_ec_core::Curve;
use tc_ec_key::{EcPrivateKey, EcPublicKey};

/// Bouncy Castle's `MqvPrivateParameters`: the own static private key, this
/// agreement's ephemeral private key and, optionally, the ephemeral public
/// key.
///
/// It is a container alone: the domains are checked, and an omitted ephemeral
/// public key computed, by `init`; Bouncy Castle does both in the constructor.
#[derive(Clone)]
pub struct MqvPrivateParams<C: Curve<Scalar = PaddedBigUint>> {
    static_key: EcPrivateKey<C>,
    ephemeral_key: EcPrivateKey<C>,
    ephemeral_public_key: Option<EcPublicKey<C>>,
}

impl<C: Curve<Scalar = PaddedBigUint>> MqvPrivateParams<C> {
    /// The two private keys, with the ephemeral public key left for `init` to
    /// compute. Constant time.
    pub fn new(static_key: EcPrivateKey<C>, ephemeral_key: EcPrivateKey<C>) -> Self {
        Self {
            static_key,
            ephemeral_key,
            ephemeral_public_key: None,
        }
    }

    /// Supplies the ephemeral public key, which saves `init` a point
    /// multiplication. Like Bouncy Castle, nothing checks that it belongs to
    /// the ephemeral private key. Constant time.
    pub fn with_ephemeral_public_key(mut self, key: EcPublicKey<C>) -> Self {
        self.ephemeral_public_key = Some(key);
        self
    }

    /// The static private key. Constant time.
    pub fn static_key(&self) -> &EcPrivateKey<C> {
        &self.static_key
    }

    /// The ephemeral private key. Constant time.
    pub fn ephemeral_key(&self) -> &EcPrivateKey<C> {
        &self.ephemeral_key
    }

    /// The supplied ephemeral public key, or `None` when it is left to `init`.
    /// Constant time.
    pub fn ephemeral_public_key(&self) -> Option<&EcPublicKey<C>> {
        self.ephemeral_public_key.as_ref()
    }
}

/// Bouncy Castle's `MqvPublicParameters`: the other party's static and
/// ephemeral public keys.
///
/// It is a container alone: the domains are checked by `calculate_agreement`;
/// Bouncy Castle does it in the constructor.
#[derive(Clone)]
pub struct MqvPublicParams<C: Curve> {
    static_key: EcPublicKey<C>,
    ephemeral_key: EcPublicKey<C>,
}

impl<C: Curve> MqvPublicParams<C> {
    /// The other party's two public keys. Constant time.
    pub fn new(static_key: EcPublicKey<C>, ephemeral_key: EcPublicKey<C>) -> Self {
        Self {
            static_key,
            ephemeral_key,
        }
    }

    /// The other party's static public key. Constant time.
    pub fn static_key(&self) -> &EcPublicKey<C> {
        &self.static_key
    }

    /// The other party's ephemeral public key. Constant time.
    pub fn ephemeral_key(&self) -> &EcPublicKey<C> {
        &self.ephemeral_key
    }
}
