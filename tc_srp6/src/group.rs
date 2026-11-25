use crate::Srp6Error;
use tc_bigint::PaddedBigUint;
use tc_modular::{Odd, PaddedMontyParams};

/// Bouncy Castle's `Srp6GroupParameters`: the safe prime N and the generator
/// g.
///
/// It is a container alone; the `init` of the client, the server and the
/// verifier generator checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srp6GroupParameters {
    n: PaddedBigUint,
    g: PaddedBigUint,
}

impl Srp6GroupParameters {
    /// The group of N and g. Constant time.
    pub fn new(n: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self { n, g }
    }

    /// The safe prime N. Constant time.
    pub fn n(&self) -> &PaddedBigUint {
        &self.n
    }

    /// The generator g. Constant time.
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }
}

/// A group that `init` checked, with the Montgomery parameters of N.
pub(crate) struct Group {
    pub(crate) n: PaddedBigUint,
    pub(crate) g: PaddedBigUint,
    pub(crate) monty: PaddedMontyParams,
}

impl Group {
    /// Checks that N is an odd number above 3 and g is in `[2, N - 2]`. Bouncy
    /// Castle does not check, but Montgomery arithmetic needs an odd N, and
    /// powers of a g outside the range are meaningless. Variable time: it
    /// branches on the public group alone.
    pub(crate) fn new(params: &Srp6GroupParameters) -> Result<Self, Srp6Error> {
        let n = params.n();
        let g = params.g();
        if n.bits() < 3 || *g < PaddedBigUint::from(2u8) || *g > n - 2u32 {
            return Err(Srp6Error::InvalidGroup);
        }
        let odd = Odd::new(n.clone()).ok_or(Srp6Error::InvalidGroup)?;
        Ok(Self {
            n: n.clone(),
            g: g.clone(),
            monty: PaddedMontyParams::new(odd),
        })
    }
}
