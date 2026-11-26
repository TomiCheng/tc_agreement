use crate::JPakePrimeOrderGroup;
use crate::standard_groups::nist_3072;
use alloc::string::String;
use alloc::vec::Vec;
use tc_zeroize::Zeroize;

/// The parameters of Bouncy Castle's `JPakeParticipant` constructor: the
/// participant ID, the password and the group.
///
/// It is a container alone; `JPakeParticipant::init` checks it. The password
/// is wiped on drop. There is no `Debug` or `PartialEq`, so the password is
/// never printed or compared in variable time.
#[derive(Clone)]
pub struct JPakeParams {
    participant_id: String,
    password: Vec<u8>,
    group: JPakePrimeOrderGroup,
}

impl JPakeParams {
    /// Copies of the participant ID and the password, with Bouncy Castle's
    /// default group, the 3072-bit NIST group. Bouncy Castle takes the
    /// password as characters and encodes it as UTF-8; this takes the bytes.
    /// Constant time in the password: it is copied by its length alone.
    pub fn new(participant_id: &str, password: &[u8]) -> Self {
        Self {
            participant_id: participant_id.into(),
            password: password.to_vec(),
            group: nist_3072(),
        }
    }

    /// Uses `group` instead. Constant time.
    pub fn with_group(mut self, group: JPakePrimeOrderGroup) -> Self {
        self.group = group;
        self
    }

    /// The participant ID; the two parties must use different ones. Constant
    /// time.
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }

    /// The password. Constant time.
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    /// The group. Constant time.
    pub fn group(&self) -> &JPakePrimeOrderGroup {
        &self.group
    }
}

impl Drop for JPakeParams {
    /// Wipes the password. Constant time.
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
