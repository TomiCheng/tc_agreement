//! Bouncy Castle's `Srp6Utilities`: the calculations of SRP-6a that the
//! client, the server and the verifier generator share.
//!
//! Numbers are [`PaddedBigUint`]s. M1, M2 and the session key are digests and
//! keep the digest's bytes, rather than becoming integers that drop leading
//! zeros as in Bouncy Castle. Where Bouncy Castle throws because a value is
//! longer than N, these functions return [`Srp6Error::ValueTooLong`].

use crate::Srp6Error;
use alloc::vec;
use alloc::vec::Vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, Limb, PaddedBigUint, RandomRange};
use tc_constant_time::fixed_time_eq;
use tc_digest::Digest;
use tc_zeroize::Zeroizing;

/// k = H(PAD(N) | PAD(g)).
///
/// # Errors
///
/// [`Srp6Error::ValueTooLong`] when g is longer than N.
///
/// Variable time: only for the public group.
pub fn calculate_k<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    g: &PaddedBigUint,
) -> Result<PaddedBigUint, Srp6Error> {
    let length = padded_length(n);
    let (n, g) = (pad(n, length)?, pad(g, length)?);
    digest.update(&n);
    digest.update(&g);
    Ok(finish_number(digest))
}

/// u = H(PAD(A) | PAD(B)).
///
/// # Errors
///
/// [`Srp6Error::ValueTooLong`] when A or B is longer than N; reduce them with
/// [`validate_public_value`] first.
///
/// Variable time: only for public values.
pub fn calculate_u<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    a: &PaddedBigUint,
    b: &PaddedBigUint,
) -> Result<PaddedBigUint, Srp6Error> {
    let length = padded_length(n);
    let (a, b) = (pad(a, length)?, pad(b, length)?);
    digest.update(&a);
    digest.update(&b);
    Ok(finish_number(digest))
}

/// x = H(s | H(I | ":" | P)), for the salt s, the identity I and the password
/// P. Bouncy Castle also takes N, which it does not use. Constant time in the
/// password, as far as the digest is; the lengths are public. The inner digest
/// is wiped.
pub fn calculate_x<D: Digest + ?Sized>(
    digest: &mut D,
    salt: &[u8],
    identity: &[u8],
    password: &[u8],
) -> PaddedBigUint {
    let mut inner = Zeroizing::new(vec![0u8; digest.digest_size()]);
    digest.update(identity);
    digest.update_byte(b':');
    digest.update(password);
    digest.do_final(&mut inner);
    digest.update(salt);
    digest.update(&inner);
    finish_number(digest)
}

/// The private value a or b, uniform in `[2^(m - 1), N - 1]`, where m is the
/// smaller of 256 and half the bit length of N. Bouncy Castle also takes the
/// digest and g, which it does not use.
///
/// # Errors
///
/// [`Srp6Error::InvalidGroup`] when N is below 4.
///
/// Constant time in the value drawn; N must be public.
pub fn generate_private_value<R: CryptoRng + ?Sized>(
    n: &PaddedBigUint,
    rng: &mut R,
) -> Result<PaddedBigUint, Srp6Error> {
    if n.bits() < 3 {
        return Err(Srp6Error::InvalidGroup);
    }
    let min_bits = 256u32.min(n.bits() / 2);
    let mut min = zero(n.as_limbs().len());
    min.set_bit(min_bits - 1, true);
    // `random_range` takes a half-open range; Bouncy Castle's
    // `CreateRandomInRange` includes its upper bound N - 1.
    Ok(PaddedBigUint::random_range(rng, &min, n))
}

/// The other party's public value modulo N, turned down when it is 0.
///
/// # Errors
///
/// [`Srp6Error::InvalidGroup`] when N is 0, and
/// [`Srp6Error::InvalidPublicValue`] when the value is 0 modulo N.
///
/// Variable time: only for public values.
pub fn validate_public_value(
    n: &PaddedBigUint,
    value: &PaddedBigUint,
) -> Result<PaddedBigUint, Srp6Error> {
    if *n == PaddedBigUint::from(0u8) {
        return Err(Srp6Error::InvalidGroup);
    }
    let value = value % n;
    if value == PaddedBigUint::from(0u8) {
        return Err(Srp6Error::InvalidPublicValue);
    }
    Ok(value)
}

/// The client's evidence M1 = H(PAD(A) | PAD(B) | PAD(S)).
///
/// # Errors
///
/// [`Srp6Error::ValueTooLong`] when A, B or S is longer than N.
///
/// Constant time in S, as far as the digest is.
pub fn calculate_m1<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    a: &PaddedBigUint,
    b: &PaddedBigUint,
    s: &PaddedBigUint,
) -> Result<Vec<u8>, Srp6Error> {
    let length = padded_length(n);
    let (a, b, s) = (pad(a, length)?, pad(b, length)?, pad(s, length)?);
    digest.update(&a);
    digest.update(&b);
    digest.update(&s);
    Ok(finish(digest))
}

/// The server's evidence M2 = H(PAD(A) | PAD(M1) | PAD(S)), with M1 padded to
/// the length of N like the other values.
///
/// # Errors
///
/// [`Srp6Error::ValueTooLong`] when A, M1 or S is longer than N.
///
/// Constant time in S, as far as the digest is.
pub fn calculate_m2<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    a: &PaddedBigUint,
    m1: &[u8],
    s: &PaddedBigUint,
) -> Result<Vec<u8>, Srp6Error> {
    let length = padded_length(n);
    let (a, m1, s) = (pad(a, length)?, pad_bytes(m1, length)?, pad(s, length)?);
    digest.update(&a);
    digest.update(&m1);
    digest.update(&s);
    Ok(finish(digest))
}

/// The session key K = H(PAD(S)).
///
/// # Errors
///
/// [`Srp6Error::ValueTooLong`] when S is longer than N.
///
/// Constant time in S, as far as the digest is.
pub fn calculate_key<D: Digest + ?Sized>(
    digest: &mut D,
    n: &PaddedBigUint,
    s: &PaddedBigUint,
) -> Result<Vec<u8>, Srp6Error> {
    let s = pad(s, padded_length(n))?;
    digest.update(&s);
    Ok(finish(digest))
}

/// Whether the evidence received equals the one calculated. Like Bouncy
/// Castle, which compares integers, it accepts an encoding without leading
/// zeros. The comparison is constant time; it branches on the public lengths
/// alone.
pub(crate) fn evidence_matches(expected: &[u8], received: &[u8]) -> bool {
    if received.len() > expected.len() {
        return false;
    }
    let mut padded = vec![0u8; expected.len()];
    padded[expected.len() - received.len()..].copy_from_slice(received);
    fixed_time_eq(expected, &padded)
}

/// `value` widened to `limbs` limbs, with the same value. Constant time.
pub(crate) fn widened(value: &PaddedBigUint, limbs: usize) -> PaddedBigUint {
    let mut wide = vec![Limb::new(0); limbs];
    wide[..value.as_limbs().len()].copy_from_slice(value.as_limbs());
    PaddedBigUint::new(wide.into_boxed_slice())
}

/// Zero, `limbs` limbs wide. Constant time.
fn zero(limbs: usize) -> PaddedBigUint {
    PaddedBigUint::new(vec![Limb::new(0); limbs].into_boxed_slice())
}

/// The length of N in bytes, which PAD pads to. Variable time: N is public.
fn padded_length(n: &PaddedBigUint) -> usize {
    (n.bits() as usize).div_ceil(8)
}

/// `value` big-endian, padded to `length` bytes: Bouncy Castle's
/// `AsUnsignedByteArray`, which throws when the value does not fit. Padding
/// every value before any reaches the digest keeps a rejected call from
/// leaving the caller's digest half fed. Constant time in the value apart from
/// whether it fits: the width alone decides where it reads and writes, and the
/// bytes are wiped.
fn pad(value: &PaddedBigUint, length: usize) -> Result<Zeroizing<Vec<u8>>, Srp6Error> {
    let bytes = Zeroizing::new(ArrayEncoding::<u8>::to_be(value));
    pad_bytes(&bytes, length)
}

/// Big-endian `bytes`, padded with zeros or stripped of leading zeros to
/// `length` bytes; [`Srp6Error::ValueTooLong`] when a stripped byte is not
/// zero. Constant time in the value apart from that outcome: the lengths
/// alone decide where it reads and writes, and the bytes are wiped.
fn pad_bytes(bytes: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>, Srp6Error> {
    let mut padded = Zeroizing::new(vec![0u8; length]);
    if bytes.len() > length {
        let excess = bytes.len() - length;
        let high = bytes[..excess].iter().fold(0u8, |acc, &byte| acc | byte);
        if high != 0 {
            return Err(Srp6Error::ValueTooLong);
        }
        padded.copy_from_slice(&bytes[excess..]);
    } else {
        padded[length - bytes.len()..].copy_from_slice(bytes);
    }
    Ok(padded)
}

/// Finishes the digest and returns its bytes. Constant time, as far as the
/// digest is.
fn finish<D: Digest + ?Sized>(digest: &mut D) -> Vec<u8> {
    let mut output = vec![0u8; digest.digest_size()];
    digest.do_final(&mut output);
    output
}

/// Finishes the digest and returns it as a big-endian integer, Bouncy Castle's
/// `new BigInteger(1, output)`. Constant time, as far as the digest is; the
/// scratch bytes are wiped.
fn finish_number<D: Digest + ?Sized>(digest: &mut D) -> PaddedBigUint {
    let output = Zeroizing::new(finish(digest));
    let Ok(value) = PaddedBigUint::from_be(&output);
    value
}
