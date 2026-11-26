use core::fmt;

/// What a J-PAKE exchange turns down, after the exceptions of Bouncy Castle's
/// `JPakeParticipant`, `JPakePrimeOrderGroup` and `JPakeUtilities`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum JPakeError {
    /// A step was asked for before `init` succeeded.
    NotInitialized,
    /// The password is empty.
    EmptyPassword,
    /// The password is 0 modulo q.
    InvalidPassword,
    /// q does not divide p − 1.
    OrderNotDividing,
    /// g is outside `[2, p − 1]`.
    GeneratorOutOfRange,
    /// g^q mod p is not 1.
    GeneratorOrderMismatch,
    /// p is not prime.
    ModulusNotPrime,
    /// q is not an odd prime.
    OrderNotPrime,
    /// This step was already taken.
    RepeatedStep,
    /// A step before this one has not been taken.
    PrematureStep,
    /// The partner uses the same participant ID.
    SameParticipantId,
    /// A participant ID is `2^32` bytes or longer, more than the proof's hash
    /// can encode.
    ParticipantIdTooLong,
    /// The payload comes from another participant.
    UnexpectedParticipant,
    /// The partner's g^x4 is 1.
    GxIsOne,
    /// The generator of the second round, g^(x1 + x3 + x4), is 1.
    GaIsOne,
    /// A zero-knowledge proof does not hold.
    InvalidProof,
    /// The partner's MacTag does not match: the passwords, digests or MACs
    /// differ.
    MacTagMismatch,
}

impl fmt::Display for JPakeError {
    /// Writes the message, in Bouncy Castle's words where it has them.
    /// Constant time, apart from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "J-PAKE participant not initialised",
            Self::EmptyPassword => "Password must not be empty.",
            Self::InvalidPassword => "MUST ensure s is not equal to 0 modulo q",
            Self::OrderNotDividing => "p-1 must be evenly divisible by q",
            Self::GeneratorOutOfRange => "g must be in [2, p-1]",
            Self::GeneratorOrderMismatch => "g^q mod p must equal 1",
            Self::ModulusNotPrime => "p must be prime",
            Self::OrderNotPrime => "q must be an odd prime",
            Self::RepeatedStep => "this step of the exchange was already performed",
            Self::PrematureStep => "an earlier step of the exchange must be completed first",
            Self::SameParticipantId => "Both participants are using the same participantId",
            Self::ParticipantIdTooLong => "the participant ID is 2^32 bytes or longer",
            Self::UnexpectedParticipant => "Received payload from incorrect partner",
            Self::GxIsOne => "g^x validation failed.  g^x should not be 1.",
            Self::GaIsOne => "ga is equal to 1.  It should not be.",
            Self::InvalidProof => "Zero-knowledge proof validation failed",
            Self::MacTagMismatch => "Partner MacTag validation failed.",
        })
    }
}

impl core::error::Error for JPakeError {}
