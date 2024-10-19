use alloc::vec::Vec;
use quickcheck_macros::quickcheck;

use crate::{HashBitsIter, SecretKey, SeededSecretKey, HASH_SIZE};

#[test]
fn test_hash_iter() {
    let hash = [0b00010001; HASH_SIZE];

    let mut iter = HashBitsIter::from(hash);

    assert_eq!(iter.next(), Some(1));
    assert_eq!(iter.next(), Some(0));
    assert_eq!(iter.next(), Some(0));
    assert_eq!(iter.next(), Some(0));
    assert_eq!(iter.next(), Some(1));
    assert_eq!(iter.next(), Some(0));
    assert_eq!(iter.next(), Some(0));
    assert_eq!(iter.next(), Some(0));
    assert_eq!(iter.next(), Some(1));
}

#[quickcheck]
fn test_singing(seckey: SecretKey, msg: Vec<u8>) -> bool {
    let pubkey = seckey.public_key();
    let signature = seckey.sign(&msg);
    pubkey.verify(&signature, msg)
}

#[quickcheck]
fn test_seeed_singing(seckey: SeededSecretKey, msg: Vec<u8>) -> bool {
    let pubkey = seckey.public_key();
    let signature = seckey.sign(&msg);
    pubkey.verify(&signature, msg)
}
