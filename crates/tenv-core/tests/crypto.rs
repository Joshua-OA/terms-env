use tenv_core::crypto::{
    CryptoError, DeviceKeys, KdfParams, Mode, StreamOpen, StreamSeal, armor, dearmor, derive_key,
    fingerprint, kex, open, random_salt, seal, spake, verify,
};

const TEST_PARAMS: KdfParams = KdfParams::TEST;

#[test]
fn fingerprints_are_stable_display_groups() {
    let keys = DeviceKeys::generate();
    let fp = fingerprint(&keys.verifying_key());

    assert_eq!(fp.len(), 19);
    let parts: Vec<&str> = fp.split('-').collect();
    assert_eq!(parts.len(), 4);
    for part in &parts {
        assert_eq!(part.len(), 4);
        assert!(
            part.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        );
    }

    let rebuilt = DeviceKeys::from_seed(&keys.to_seed());
    assert_eq!(fingerprint(&rebuilt.verifying_key()), fp);
}

#[test]
fn kdf_is_deterministic_and_input_sensitive() {
    let salt = [7u8; 16];
    let a = *derive_key(b"correct horse", &salt, TEST_PARAMS);
    let b = *derive_key(b"correct horse", &salt, TEST_PARAMS);
    assert_eq!(a, b);

    let c = *derive_key(b"correct horse", &[8u8; 16], TEST_PARAMS);
    let d = *derive_key(b"incorrect pony", &salt, TEST_PARAMS);
    assert_ne!(a, c);
    assert_ne!(a, d);
}

#[test]
fn production_kdf_params_deterministic() {
    let salt = random_salt();
    let a = *derive_key(b"prod", &salt, KdfParams::PRODUCTION);
    let b = *derive_key(b"prod", &salt, KdfParams::PRODUCTION);
    assert_eq!(a, b);
}

#[test]
fn wrong_passphrase_cannot_decrypt_sealed_vault_blob() {
    let salt = random_salt();
    let good = derive_key(b"right", &salt, TEST_PARAMS);
    let sealed = seal(&good, &[9u8; 24], b"secret payload");

    let bad = derive_key(b"rong", &salt, TEST_PARAMS);
    assert_eq!(open(&bad, &[9u8; 24], &sealed), Err(CryptoError::Decrypt));
    assert!(open(&good, &[9u8; 24], &sealed).is_ok());
}

#[test]
fn aead_bitflip_anywhere_rejected() {
    let key = [42u8; 32];
    let nonce = [1u8; 24];
    let pt = b"attack at dawn";
    let ct = seal(&key, &nonce, pt);

    for flip_at in [0usize, ct.len() / 2, ct.len() - 1] {
        let mut tampered = ct.clone();
        tampered[flip_at] ^= 0x01;
        assert_eq!(
            open(&key, &nonce, &tampered),
            Err(CryptoError::Decrypt),
            "flip at byte {flip_at} was not rejected"
        );
    }
}

#[test]
fn aead_truncated_ciphertext_rejected() {
    let key = [1u8; 32];
    let nonce = [2u8; 24];
    let ct = seal(&key, &nonce, b"payload");
    assert_eq!(
        open(&key, &nonce, &ct[..ct.len() - 1]),
        Err(CryptoError::Decrypt)
    );
    assert_eq!(open(&key, &nonce, &[]), Err(CryptoError::Decrypt));
}

#[test]
fn same_plaintext_twice_produces_different_ciphertext() {
    let key = [3u8; 32];
    let mut n1 = [5u8; 24];
    n1[0] = 1;
    let mut n2 = [5u8; 24];
    n2[0] = 2;
    assert_ne!(seal(&key, &n1, b"x"), seal(&key, &n2, b"x"));
}

#[test]
fn chunk_stream_round_trips_in_order_only() {
    let key = [7u8; 32];
    let chunks: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8; (i + 1) * 11]).collect();
    let mut sealer = StreamSeal::new(key);
    let sealed: Vec<Vec<u8>> = chunks.iter().map(|c| sealer.seal_chunk(c)).collect();

    let mut opener = StreamOpen::new(key);
    for (i, chunk) in sealed.iter().enumerate() {
        assert_eq!(opener.open_chunk(chunk).unwrap(), chunks[i]);
    }

    let mut opener = StreamOpen::new(key);
    assert_eq!(opener.open_chunk(&sealed[1]), Err(CryptoError::Decrypt));

    let mut opener = StreamOpen::new(key);
    let mut flipped = sealed[0].clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0xFF;
    assert_eq!(opener.open_chunk(&flipped), Err(CryptoError::Decrypt));
}

#[test]
fn signatures_verify_and_tamper_fails() {
    let keys = DeviceKeys::generate();
    let vk = keys.verifying_key();
    let msg = b"acme/api|1719000000|hash-of-env";

    let sig = keys.sign(msg);
    assert!(verify(&vk, msg, &sig));

    let mut bad_msg = *msg;
    bad_msg[0] ^= 1;
    assert!(!verify(&vk, &bad_msg, &sig));

    let mut bad_sig_bytes = sig.to_bytes();
    bad_sig_bytes[10] ^= 1;
    let bad_sig = ed25519_dalek::Signature::from_bytes(&bad_sig_bytes);
    assert!(!verify(&vk, msg, &bad_sig));

    let other = DeviceKeys::generate().verifying_key();
    assert!(!verify(&other, msg, &sig));
}

#[test]
fn sealed_box_round_trip_wrong_recipient_and_tamper_fail() {
    let alice_sk = [11u8; 32];
    let alice_pk = kex::public_key(&alice_sk);

    let blob = kex::seal(&alice_pk, b"for your eyes only");
    assert_eq!(kex::open(&alice_sk, &blob).unwrap(), b"for your eyes only");

    let stranger_sk = [99u8; 32];
    assert_eq!(kex::open(&stranger_sk, &blob), Err(CryptoError::Decrypt));

    let mut tampered = blob.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x80;
    assert_eq!(kex::open(&alice_sk, &tampered), Err(CryptoError::Decrypt));

    assert_eq!(kex::open(&alice_sk, &blob[..40]), Err(CryptoError::Decrypt));
}

#[test]
fn spake_two_parties_derive_identical_session_key() {
    let (a, msg_a) = spake::begin(b"ember-falcon-lime").unwrap();
    let (b, msg_b) = spake::begin(b"ember-falcon-lime").unwrap();

    let key_a = a.finish(&msg_b).unwrap();
    let key_b = b.finish(&msg_a).unwrap();
    assert_eq!(*key_a, *key_b);
}

#[test]
fn spake_password_mismatch_derives_different_keys() {
    // Raw SPAKE2 never fails on a wrong password; it simply derives an
    // unrelated session key. Mismatch surfaces later when AEAD decryption
    // fails, which our transport layer treats as handshake failure.
    let (a, msg_a) = spake::begin(b"right code").unwrap();
    let (b, msg_b) = spake::begin(b"wrong code").unwrap();

    let key_a = a.finish(&msg_b).unwrap();
    let key_b = b.finish(&msg_a).unwrap();
    assert_ne!(*key_a, *key_b);
}

#[test]
fn spake_rejects_malformed_peer_message() {
    let (a, _msg_a) = spake::begin(b"some code").unwrap();
    assert!(a.finish(b"garbage").is_err());
}

#[test]
fn armor_round_trips_long_bodies() {
    let body: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
    let text = armor(Mode::Passphrase, &body);
    assert!(text.starts_with("TENV1 passphrase\n"));
    let lines: Vec<&str> = text.lines().skip(1).collect();
    assert!(lines.len() >= 3, "expected wrapping across multiple lines");
    assert!(lines.iter().all(|l| l.len() <= 76));

    let (mode, decoded) = dearmor(&text).unwrap();
    assert_eq!(mode, Mode::Passphrase);
    assert_eq!(decoded, body);
}

#[test]
fn armor_pubkey_mode_label_round_trips() {
    let text = armor(Mode::Pubkey, b"tiny");
    let (mode, decoded) = dearmor(&text).unwrap();
    assert_eq!(mode, Mode::Pubkey);
    assert_eq!(decoded, b"tiny");
}

#[test]
fn armor_rejects_bad_headers_garbage_and_empty() {
    assert!(matches!(
        dearmor("HELLO world\nYWJj\n"),
        Err(CryptoError::MalformedArmor(_))
    ));
    assert!(matches!(
        dearmor("TENV1 teleporter\nYWJj\n"),
        Err(CryptoError::MalformedArmor(_))
    ));
    assert!(matches!(
        dearmor("TENV1 passphrase\nnot base64!!\n"),
        Err(CryptoError::MalformedArmor(_))
    ));
    assert!(matches!(
        dearmor("TENV1 passphrase\n"),
        Err(CryptoError::MalformedArmor(_))
    ));
}
