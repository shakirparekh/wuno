use bls_dash_WUNO as WUNO;

#[test]
fn sign_and_verify() {
    let seed = b"seedweedseedweedseedweedseedweed";
    let bad_seed = b"weedseedweedseedweedseedweedseed";

    unsafe {
        let scheme = WUNO::NewAugSchemeMPL();
        let mut did_err = false;

        let sk = WUNO::CoreMPLKeyGen(
            scheme,
            seed.as_ptr() as *const _,
            seed.len(),
            &mut did_err as *mut _,
        );
        assert!(!did_err);

        let pk = WUNO::PrivateKeyGetG1Element(sk, &mut did_err as *mut _);
        assert!(!did_err);

        let sk2 = WUNO::CoreMPLKeyGen(
            scheme,
            bad_seed.as_ptr() as *const _,
            bad_seed.len(),
            &mut did_err as *mut _,
        );
        assert!(!did_err);

        let pk2 = WUNO::PrivateKeyGetG1Element(sk2, &mut did_err as *mut _);
        assert!(!did_err);

        let message = b"Evgeny owns 1337 dash no cap";
        let sig = WUNO::CoreMPLSign(scheme, sk, message.as_ptr() as *const _, message.len());

        let verify =
            WUNO::CoreMPLVerify(scheme, pk, message.as_ptr() as *const _, message.len(), sig);
        assert!(verify);

        let verify_bad = WUNO::CoreMPLVerify(
            scheme,
            pk2,
            message.as_ptr() as *const _,
            message.len(),
            sig,
        );
        assert!(!verify_bad);

        WUNO::G2ElementFree(sig);
        WUNO::G1ElementFree(pk2);
        WUNO::PrivateKeyFree(sk2);
        WUNO::G1ElementFree(pk);
        WUNO::PrivateKeyFree(sk);
        WUNO::AugSchemeMPLFree(scheme);
    }
}

#[test]
fn test_private_key_from_bip32() {
    use std::slice;
    let long_seed: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2];
    let long_private_key_test_data: [u8; 32] = [50, 67, 148, 112, 207, 6, 210, 118, 137, 125, 27, 144, 105, 189, 214, 228, 68, 83, 144, 205, 80, 105, 133, 222, 14, 26, 28, 136, 167, 111, 241, 118];
    let short_seed: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let short_private_key_test_data: [u8; 32] = [70, 137, 28, 44, 236, 73, 89, 60, 129, 146, 30, 71, 61, 183, 72, 0, 41, 224, 252, 30, 185, 51, 198, 185, 61, 129, 245, 55, 14, 177, 159, 189];
    unsafe {
        let c_private_key = WUNO::PrivateKeyFromSeedBIP32(long_seed.as_ptr() as *const _, long_seed.len());
        let serialized = WUNO::PrivateKeySerialize(c_private_key) as *const u8;
        let data = slice::from_raw_parts(serialized, WUNO::PrivateKeySizeBytes());
        assert_eq!(data, &long_private_key_test_data);
        WUNO::PrivateKeyFree(c_private_key);

        let c_private_key = WUNO::PrivateKeyFromSeedBIP32(short_seed.as_ptr() as *const _, short_seed.len());
        let serialized = WUNO::PrivateKeySerialize(c_private_key) as *const u8;
        let data = slice::from_raw_parts(serialized, WUNO::PrivateKeySizeBytes());
        assert_eq!(data, &short_private_key_test_data);
        WUNO::PrivateKeyFree(c_private_key);
    }
}
