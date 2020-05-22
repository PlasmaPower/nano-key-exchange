use blake2::{Blake2b, VarBlake2b, digest::{Digest, Input, VariableOutput}};
use curve25519_dalek::{scalar::Scalar, edwards::CompressedEdwardsY};
use std::slice;

#[cfg(test)]
mod tests;

pub const ERROR_NONE: u8 = 0;
pub const ERROR_BAD_PUBLIC_KEY: u8 = 1;

const SHARED_KEY_HASH_PREFIX: &[u8] = b"nano-key-exchange\0";

pub(crate) fn expand_secret_key(secret_key: &[u8]) -> Scalar {
    let hasher = Blake2b::digest(secret_key);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.as_slice()[..32]);
    hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;
    Scalar::from_bits(hash)
}

pub unsafe extern "C" fn nano_get_shared_key(secret_key: *const u8, other_public_key: *const u8, shared_key_out: *mut u8) -> u8 {
    let secret_key = slice::from_raw_parts(secret_key, 32);
    let other_public_key = slice::from_raw_parts(other_public_key, 32);
    let shared_key_out = slice::from_raw_parts_mut(shared_key_out, 32);
    let mut other_pubkey_slice = [0u8; 32];
    other_pubkey_slice.copy_from_slice(other_public_key);
    let other_public_key = match CompressedEdwardsY(other_pubkey_slice).decompress() {
        Some(x) => x,
        None => return ERROR_BAD_PUBLIC_KEY,
    };
    let secret_key = expand_secret_key(secret_key);
    let shared_key = secret_key * other_public_key;
    let mut shared_key_hash = VarBlake2b::new(32).unwrap();
    shared_key_hash.input(SHARED_KEY_HASH_PREFIX);
    shared_key_hash.input(shared_key.compress().as_bytes());
    shared_key_hash.variable_result(|b| shared_key_out.copy_from_slice(b));
    ERROR_NONE
}
