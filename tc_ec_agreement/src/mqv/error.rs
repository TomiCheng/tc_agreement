use core::fmt;

/// What the EC-MQV agreement turns down, after the exceptions of Bouncy
/// Castle's `ECMqvBasicAgreement` and `MqvPrivateParameters`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcMqvError {
    /// The agreement was used before `init` succeeded.
    NotInitialized,
    /// The keys are not on one domain: the own two private keys, the own
    /// ephemeral public key, or the other party's two public keys.
    DomainMismatch,
    /// The curve has no order n.
    MissingOrder,
    /// A public key is not a finite point of the curve.
    InvalidPublicKey,
    /// The shared point is infinity.
    InvalidAgreement,
    /// The output buffer is shorter than the shared secret.
    BufferTooSmall,
}

impl fmt::Display for EcMqvError {
    /// Writes the message, in Bouncy Castle's words where it has them.
    /// Constant time, apart from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "Agreement algorithm not initialised",
            Self::DomainMismatch => "ECMQV key components have different domain parameters",
            Self::MissingOrder => "the curve has no order",
            Self::InvalidPublicKey => "the public key is not a valid point of the curve",
            Self::InvalidAgreement => "Infinity is not a valid agreement value for MQV",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for EcMqvError {}
