use crate::nano_get_shared_key;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

#[test]
fn test_invalid_keys() {
    let skey = [1u8; 32];
    let pkey = [2u8; 32];
    let mut out = [3u8; 32];
    let res = unsafe { nano_get_shared_key(skey.as_ptr(), pkey.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(res, crate::ERROR_BAD_PUBLIC_KEY);
    assert_eq!(out, [3u8; 32]);
}

#[test]
fn test_real_keys() {
    let key1_bytes = [123u8; 32];
    let key2_bytes = [42u8; 32];
    let key1_scalar = crate::expand_secret_key(&key1_bytes);
    let key2_scalar = crate::expand_secret_key(&key2_bytes);
    assert!(key1_scalar != key2_scalar);
    let key1_pub = &key1_scalar * &ED25519_BASEPOINT_TABLE;
    let key2_pub = &key2_scalar * &ED25519_BASEPOINT_TABLE;
    let key1_pub_bytes = key1_pub.compress().to_bytes();
    let key2_pub_bytes = key2_pub.compress().to_bytes();
    let mut shared1 = [0u8; 32];
    let mut shared2 = [0u8; 32];
    unsafe {
        assert_eq!(nano_get_shared_key(key1_bytes.as_ptr(), key2_pub_bytes.as_ptr(), shared1.as_mut_ptr()), 0);
        assert_eq!(nano_get_shared_key(key2_bytes.as_ptr(), key1_pub_bytes.as_ptr(), shared2.as_mut_ptr()), 0);
    }
    assert_eq!(shared1, shared2);
    assert!(shared1 != [0u8; 32]);

    let key3_bytes = [9; 32];
    let key3_scalar = crate::expand_secret_key(&key3_bytes);
    let key3_pub = &key3_scalar * &ED25519_BASEPOINT_TABLE;
    let key3_pub_bytes = key3_pub.compress().to_bytes();
    let mut shared3 = [0u8; 32];
    let mut shared4 = [0u8; 32];
    unsafe {
        assert_eq!(nano_get_shared_key(key1_bytes.as_ptr(), key3_pub_bytes.as_ptr(), shared3.as_mut_ptr()), 0);
        assert_eq!(nano_get_shared_key(key3_bytes.as_ptr(), key1_pub_bytes.as_ptr(), shared4.as_mut_ptr()), 0);
    }
    assert_eq!(shared3, shared4);
    assert!(shared3 != [0u8; 32]);
    assert!(shared1 != shared3);
}
