/// An initialized key agreement, the Rust form of Bouncy Castle's
/// `IRawAgreement`: it combines the private key given to
/// [`AgreementInit::init`] with the other party's public key into their
/// shared secret.
///
/// The secret is written as bytes of a fixed length, where Bouncy Castle's
/// `IBasicAgreement` returns an integer: an integer drops leading zero
/// bytes, which every caller then has to pad back.
///
/// The trait makes no timing promise. Accepted keys, the state left by a
/// failed call and whether an implementation runs in constant time are
/// documented by each implementation.
pub trait Agreement {
    /// The other party's public key.
    type PublicKey: ?Sized;

    /// The failure type, such as a public key off the curve or an output
    /// shorter than the secret.
    type Error: core::error::Error;

    /// The length of the shared secret in bytes, Bouncy Castle's
    /// `AgreementSize`, set by initialization rather than by any key's
    /// value.
    fn agreement_size(&self) -> usize;

    /// Writes the shared secret with `public_key` into the first
    /// [`agreement_size`](Self::agreement_size) bytes of `output`, Bouncy
    /// Castle's `CalculateAgreement`. Implementations report an `output`
    /// shorter than that through [`Error`](Self::Error) and leave the bytes
    /// past it untouched.
    fn calculate_agreement(
        &self,
        public_key: &Self::PublicKey,
        output: &mut [u8],
    ) -> Result<(), Self::Error>;
}

/// Initializes an agreement from parameters of type `P`, which hold the
/// private key and whatever else the agreement needs, by reference.
///
/// The trait makes no timing promise; each implementation documents its own.
pub trait AgreementInit<P: ?Sized> {
    /// The failure type, such as a private key out of range.
    type Error: core::error::Error;

    /// Takes the private key and parameters in `params`, replacing any that an
    /// earlier call took. Each implementation documents which parameters it
    /// accepts and the state a rejected call leaves.
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}
