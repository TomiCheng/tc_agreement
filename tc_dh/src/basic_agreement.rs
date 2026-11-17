use crate::DhAgreementError;
use tc_agreement::{Agreement, AgreementInit};
use tc_bigint::{ArrayEncoding, PaddedBigUint};
use tc_constant_time::ConstantTimeEq;
use tc_dh_key::{DhPrivateKey, DhPublicKey};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// Bouncy Castle's `DHBasicAgreement`: the shared secret is y^x mod p, for
/// the other party's public value y and the private value x.
///
/// The secret is written as big-endian bytes of the length of p, leading
/// zeros kept, as `tc_agreement` asks; Bouncy Castle returns an integer,
/// which drops them.
pub struct DhBasicAgreement {
    state: Option<(DhPrivateKey, PaddedMontyParams)>,
}

impl DhBasicAgreement {
    /// An agreement that is not initialized yet. Constant time.
    pub fn new() -> Self {
        Self { state: None }
    }
}

impl Default for DhBasicAgreement {
    /// The same as [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementInit<DhPrivateKey> for DhBasicAgreement {
    type Error = DhAgreementError;

    /// Keeps a copy of the private key, whose x is wiped on drop, after
    /// checking its parameters with `DhParameters::validate`, and sets up
    /// Montgomery arithmetic modulo p. A rejected call leaves the agreement
    /// uninitialized. Variable time: it branches on the parameters alone,
    /// which are public.
    fn init(&mut self, key: &DhPrivateKey) -> Result<(), DhAgreementError> {
        self.state = None;
        key.params()
            .validate()
            .map_err(DhAgreementError::InvalidParameters)?;
        let p = Odd::new(key.params().p().clone()).ok_or(DhAgreementError::InvalidParameters(
            tc_dh_key::DhError::InvalidModulus,
        ))?;
        self.state = Some((key.clone(), PaddedMontyParams::new(p)));
        Ok(())
    }
}

impl Agreement for DhBasicAgreement {
    type PublicKey = DhPublicKey;
    type Error = DhAgreementError;

    /// Bouncy Castle's `GetFieldSize`: the length of p in bytes, or 0 until
    /// `init` succeeds. Constant time.
    fn agreement_size(&self) -> usize {
        self.state
            .as_ref()
            .map_or(0, |(key, _)| (key.params().p().bits() as usize).div_ceil(8))
    }

    /// Bouncy Castle's `CalculateAgreement`. The public key must be on the
    /// same parameters and pass `DhPublicKey::validate`, in `[2, p - 2]` and,
    /// when the parameters have q, in its subgroup; the secret must not be 1.
    ///
    /// Constant time in x: the checks on the public key branch on public
    /// values, y^x runs in constant time and is compared with 1 in constant
    /// time, and only the error shows whether it was 1.
    fn calculate_agreement(
        &self,
        public_key: &DhPublicKey,
        output: &mut [u8],
    ) -> Result<(), DhAgreementError> {
        let (key, monty) = self
            .state
            .as_ref()
            .ok_or(DhAgreementError::NotInitialized)?;
        if public_key.params() != key.params() {
            return Err(DhAgreementError::WrongParameters);
        }
        public_key
            .validate()
            .map_err(DhAgreementError::InvalidPublicKey)?;
        let size = self.agreement_size();
        let output = output
            .get_mut(..size)
            .ok_or(DhAgreementError::BufferTooSmall)?;

        let power = Zeroizing::new(PaddedMontyForm::new(public_key.y(), monty).pow(key.x()));
        let shared = Zeroizing::new(power.retrieve());
        if shared.ct_eq(&PaddedBigUint::from(1u8)).unwrap_u8() == 1 {
            return Err(DhAgreementError::InvalidAgreement);
        }
        write_be(&shared, output);
        Ok(())
    }
}

/// Writes `value` big-endian into the whole of `output`, padded with leading
/// zeros; `value` must fit. Constant time in the value: only the widths
/// decide what is read and written.
pub(crate) fn write_be(value: &PaddedBigUint, output: &mut [u8]) {
    let mut bytes = ArrayEncoding::<u8>::to_be(value);
    let length = output.len().min(bytes.len());
    output.fill(0);
    let start = output.len() - length;
    output[start..].copy_from_slice(&bytes[bytes.len() - length..]);
    bytes.zeroize();
}
