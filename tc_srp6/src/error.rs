use core::fmt;

/// What the SRP-6a classes turn down, after the exceptions of Bouncy Castle's
/// `Srp6Client`, `Srp6Server`, `Srp6VerifierGenerator` and `Srp6Utilities`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Srp6Error {
    /// A calculation was asked for before `init` succeeded.
    NotInitialized,
    /// The group is unusable: N is not an odd number above 3, or g is outside
    /// `[2, N - 2]`.
    InvalidGroup,
    /// The other party's public value is 0 modulo N.
    InvalidPublicValue,
    /// A step before this one has not been taken, so a value it needs (A, B,
    /// S, M1 or M2) is missing.
    MissingValues,
    /// A value given to a `utilities` function is longer than N in bytes, so
    /// it cannot be padded to the length of N.
    ValueTooLong,
}

impl fmt::Display for Srp6Error {
    /// Writes the message, in Bouncy Castle's words where it has them.
    /// Constant time, apart from the formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "SRP-6 is not initialised",
            Self::InvalidGroup => "invalid SRP-6 group parameters",
            Self::InvalidPublicValue => "Invalid public value: 0",
            Self::MissingValues => "some data are missing from the previous operations",
            Self::ValueTooLong => "standard length exceeded",
        })
    }
}

impl core::error::Error for Srp6Error {}
