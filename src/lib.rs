#![doc = include_str!("../README.md")]
#![no_std]
#![warn(clippy::missing_const_for_fn)]
#![warn(missing_docs)]

extern crate alloc;

use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests;

const HASH_SIZE: usize = 32;
const BITS_IN_HASH: usize = 32 * 8;

/// The array of bytes with size of output hash algorithm the library
/// uses.
pub type Hash = [u8; HASH_SIZE];

/// Possible preimage of hash function.
// Assumption here, that as secret for each bit,
// the 256 bit value (hash) used.
pub type Preimage = [u8; HASH_SIZE];

/// The secret for each bit of the messege.
pub type BitSecret = [Preimage; 2];

/// Seeded secret key of Lamport signature scheme.
///
/// The shorter version of [`SecretKey`] which holds only the seed for
/// standart (for current platform) PRG (pseudo-random generator), in
/// exchange for small amount of additiona computations during signing and
/// public key generation.
#[cfg_attr(test, derive(Clone, Debug))]
pub struct SeededSecretKey {
    seed: [u8; 32],
}

impl SeededSecretKey {
    /// Construct new [`SeededSecretKey`] from seed.
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Generate public key from secret one.
    pub fn public_key(&self) -> PublicKey {
        let mut rng = StdRng::from_seed(self.seed);

        SecretKey::generate(&mut rng).public_key()
    }

    /// Create a one-time signature from message and secret key.
    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Signature {
        let mut rng = StdRng::from_seed(self.seed);

        SecretKey::generate(&mut rng).sign(msg)
    }
}

/// Secret key of Lamport signature scheme.
///
/// Consists of pairs of secret values for each bit of the message.
/// As before signing message is hashed, the size of it is fixed to
/// 256 bits.
#[cfg_attr(test, derive(Clone, Debug))]
pub struct SecretKey([BitSecret; BITS_IN_HASH]);

impl SecretKey {
    /// Construct new [`SecretKey`] from bit secrets.
    pub const fn new(value: [BitSecret; BITS_IN_HASH]) -> Self {
        Self(value)
    }

    /// Generate random key from random generator.
    pub fn generate<Rng: rand::Rng>(mut rng: Rng) -> Self {
        let mut container = [BitSecret::default(); BITS_IN_HASH];

        for [ref mut x0, ref mut x1] in &mut container {
            rng.fill_bytes(x0);
            rng.fill_bytes(x1);
        }

        Self(container)
    }

    /// Return a public key derived from [`SecretKey`] by hashing each part.
    pub fn public_key(&self) -> PublicKey {
        let mut pubkey = [[[0u8; HASH_SIZE]; 2]; BITS_IN_HASH];

        for (idx, [ref mut y0, ref mut y1]) in pubkey.iter_mut().enumerate() {
            let [ref x0, ref x1] = self.0[idx];

            *y0 = Sha256::digest(x0).into();
            *y1 = Sha256::digest(x1).into();
        }

        PublicKey(pubkey)
    }

    /// Create a one-time signature from message and secret key.
    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Signature {
        let hash: Hash = Sha256::digest(msg).into();
        let hash_bits_iter = HashBitsIter::from(hash);

        let mut signature = [Preimage::default(); BITS_IN_HASH];

        for (idx, bit) in hash_bits_iter.enumerate() {
            signature[idx] = self.0[idx][bit as usize];
        }

        Signature(signature)
    }
}

type BitPublicKey = [Hash; 2];

/// Public key of Lamport signature scheme.
///
/// Consists of hashed by Sha256 parts of [`SecretKey`]. As message is
/// hashed before the signing the number of parts is fixed to [`MSG_SIZE`]
/// elements.
#[derive(Clone, Copy)]
pub struct PublicKey([BitPublicKey; BITS_IN_HASH]);

impl PublicKey {
    /// Verify the Lamport signature from message and public key.
    pub fn verify(&self, signature: &Signature, msg: impl AsRef<[u8]>) -> bool {
        let hash: Hash = Sha256::digest(msg).into();
        let hash_bits_iter = HashBitsIter::from(hash);

        for (idx, bit) in hash_bits_iter.enumerate() {
            let hashed_sig: Hash = Sha256::digest(signature.0[idx]).into();

            if hashed_sig != self.0[idx][bit as usize] {
                return false;
            }
        }

        true
    }
}

/// The signature of Lamport scheme.
///
/// Consists of parts from [`SecretKey`] dependings on the bit value of
/// the message.
pub struct Signature([Preimage; BITS_IN_HASH]);

/// Iterator over bits of message:
pub(crate) struct HashBitsIter {
    position: usize,
    container: [u8; HASH_SIZE],
}

impl Iterator for HashBitsIter {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position * 8 + 1 >= BITS_IN_HASH {
            return None;
        }

        let byte_pos = self.position / 8;
        let bit_pos = self.position % 8;

        let byte = self.container[byte_pos];
        let bit = (byte >> bit_pos) & 0x01;

        self.position += 1;

        Some(bit)
    }
}

impl From<Hash> for HashBitsIter {
    fn from(value: [u8; HASH_SIZE]) -> Self {
        HashBitsIter {
            position: 0,
            container: value,
        }
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for SecretKey {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut container = [BitSecret::default(); BITS_IN_HASH];

        for [ref mut x0, ref mut x1] in &mut container {
            for byte in x0 {
                *byte = quickcheck::Arbitrary::arbitrary(g);
            }
            for byte in x1 {
                *byte = quickcheck::Arbitrary::arbitrary(g);
            }
        }

        Self(container)
    }
}

#[cfg(test)]
impl quickcheck::Arbitrary for SeededSecretKey {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let mut seed = [0u8; 32];

        for byte in &mut seed {
            *byte = quickcheck::Arbitrary::arbitrary(g);
        }

        Self::from_seed(seed)
    }
}
