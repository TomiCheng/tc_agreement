use core::fmt;

/// What the ECDH and ECDHC agreements turn down, after the exceptions of
/// Bouncy Castle's `ECDHBasicAgreement` and `ECDHCBasicAgreement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcdhError {
    /// The agreement was used before `init` succeeded.
    NotInitialized,
    /// The public key is on another domain than the private key.
    WrongDomain,
    /// The public key is infinity or not a point of the private key's curve.
    InvalidPublicKey,
    /// The cofactor has no inverse modulo the order n, or n is even.
    InvalidCofactor,
    /// The shared point is infinity.
    InvalidAgreement,
    /// The output buffer is shorter than the shared secret.
    BufferTooSmall,
}

impl fmt::Display for EcdhError {
    /// Writes the message. Constant time, apart from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the agreement is not initialized",
            Self::WrongDomain => "the public key has another domain",
            Self::InvalidPublicKey => "the public key is not a valid point of the curve",
            Self::InvalidCofactor => "the cofactor is not invertible modulo the order",
            Self::InvalidAgreement => "the shared point is infinity",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for EcdhError {}
