use core::fmt;
use tc_dh_key::DhError;

/// What the Diffie-Hellman agreements turn down, after the exceptions of
/// Bouncy Castle's `DHBasicAgreement` and `DHAgreement`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhAgreementError {
    /// The agreement was used before `init` succeeded.
    NotInitialized,
    /// The parameters of the private key fail `DhParameters::validate`.
    InvalidParameters(DhError),
    /// The other party's public key is on other parameters than the private
    /// key: p, g or q differ.
    WrongParameters,
    /// The other party's public key fails `DhPublicKey::validate`: it is
    /// outside `[2, p - 2]` or the subgroup of order q, or p is too large.
    InvalidPublicKey(DhError),
    /// The other party's message fails the checks of a public key.
    InvalidMessage(DhError),
    /// [`DhAgreement::calculate_agreement`](crate::DhAgreement::calculate_agreement)
    /// was called before `calculate_message`.
    MessageNotCalculated,
    /// The shared secret, or in `DhAgreement` its ephemeral half, is 1.
    InvalidAgreement,
    /// The output buffer is shorter than the shared secret.
    BufferTooSmall,
}

impl fmt::Display for DhAgreementError {
    /// Writes the message, in Bouncy Castle's words where it has them.
    /// Constant time, apart from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("Agreement algorithm not initialised"),
            Self::InvalidParameters(error) => {
                write!(f, "invalid Diffie-Hellman parameters: {error}")
            }
            Self::WrongParameters => f.write_str("Diffie-Hellman public key has wrong parameters."),
            Self::InvalidPublicKey(error) => {
                write!(f, "Diffie-Hellman public key is weak: {error}")
            }
            Self::InvalidMessage(error) => {
                write!(f, "Diffie-Hellman message is weak: {error}")
            }
            Self::MessageNotCalculated => f.write_str("the message has not been calculated"),
            Self::InvalidAgreement => f.write_str("Shared key can't be 1"),
            Self::BufferTooSmall => f.write_str("the output buffer is too small"),
        }
    }
}

impl core::error::Error for DhAgreementError {}
