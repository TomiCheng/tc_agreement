use core::fmt;

/// What the GOST VKO agreement turns down, after the exceptions of Bouncy
/// Castle's `ECVkoAgreement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcVkoError {
    /// The agreement was used before `init` succeeded.
    NotInitialized,
    /// The curve has no order n.
    MissingOrder,
    /// The other party's public key is on another domain than the private key.
    DomainMismatch,
    /// The other party's public key is not a finite point of the curve.
    InvalidPublicKey,
    /// The shared point is infinity, as when the UKM is zero.
    InvalidAgreement,
    /// The output buffer is shorter than the shared secret.
    BufferTooSmall,
}

impl fmt::Display for EcVkoError {
    /// Writes the message, in Bouncy Castle's words where it has them.
    /// Constant time, apart from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "Agreement algorithm not initialised",
            Self::MissingOrder => "the curve has no order",
            Self::DomainMismatch => "ECVKO public key has wrong domain parameters",
            Self::InvalidPublicKey => "Infinity is not a valid public key for ECVKO",
            Self::InvalidAgreement => "Infinity is not a valid agreement value for ECVKO",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for EcVkoError {}
