use tenv_core::crypto::{DeviceKeys, kex};
use tenv_core::domain::EnvFile;
use tenv_core::share::{
    ShareError, build_for_peer, build_passphrase, build_payload, open_blob, payload_bytes,
    verify_payload,
};

fn fixture() -> (DeviceKeys, EnvFile) {
    let mut file = EnvFile::new();
    file.set("STRIPE_KEY", "sk_live_abc1234567890");
    file.set("DB_URL", "postgres://user:pass@host/db");
    (DeviceKeys::generate(), file)
}

#[test]
fn passphrase_blob_round_trips() {
    let (keys, file) = fixture();
    let blob = build_passphrase("acme/api", &file, &keys, None, "shared-secret-1").unwrap();

    let payload = open_blob(&blob, Some("shared-secret-1"), None).unwrap();
    assert_eq!(payload.project, "acme/api");
    assert_eq!(payload.vars.len(), 2);
    assert!(payload.expires_at.is_none());
}

#[test]
fn wrong_passphrase_rejected() {
    let (keys, file) = fixture();
    let blob = build_passphrase("p", &file, &keys, None, "right").unwrap();
    assert!(matches!(
        open_blob(&blob, Some("wrong"), None),
        Err(ShareError::WrongPassphrase)
    ));
}

#[test]
fn pubkey_blob_round_trips_to_correct_recipient_only() {
    let (keys, file) = fixture();
    let recipient_sk = [42u8; 32];
    let recipient_pk = kex::public_key(&recipient_sk);

    let blob = build_for_peer("globex/bot", &file, &keys, None, &recipient_pk).unwrap();

    let payload = open_blob(&blob, None, Some(&recipient_sk)).unwrap();
    assert_eq!(payload.vars[0].value, "sk_live_abc1234567890");

    let stranger = [7u8; 32];
    assert!(matches!(
        open_blob(&blob, None, Some(&stranger)),
        Err(ShareError::WrongPassphrase)
    ));
}

#[test]
fn tampered_checksum_is_caught_before_decryption() {
    let (keys, file) = fixture();
    let mut blob = build_passphrase("p", &file, &keys, None, "some passphrase").unwrap();

    // Flip the last base64 character's worth of bytes: corrupt the CRC.
    let mut raw = tenv_core::crypto::dearmor(&blob).unwrap().1;
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    blob = tenv_core::crypto::armor(tenv_core::crypto::Mode::Passphrase, &raw);

    assert!(matches!(
        open_blob(&blob, Some("some passphrase"), None),
        Err(ShareError::Malformed(m)) if m.contains("checksum")
    ));
}

#[test]
fn expired_share_is_refused() {
    let (keys, file) = fixture();
    let blob = build_passphrase("p", &file, &keys, Some(0), "a-pass-phrase").unwrap();
    // ttl 0 => already expired at build time.
    assert!(matches!(
        open_blob(&blob, Some("a-pass-phrase"), None),
        Err(ShareError::Expired { .. })
    ));
}

#[test]
fn signature_binds_sender_identity_and_content() {
    let (keys, mut file) = fixture();
    let payload = build_payload("p", &file, &keys, None);
    let bytes = payload_bytes(&payload);
    assert!(verify_payload(&bytes).is_ok());

    // Tamper with a var after signing.
    let mut forged = payload.clone();
    file.set("STRIPE_KEY", "sk_attacker");
    forged.vars = file.iter().cloned().collect();
    let forged_bytes = payload_bytes(&forged);
    assert!(matches!(
        verify_payload(&forged_bytes),
        Err(ShareError::BadSignature)
    ));

    // A different sender's key also fails against our signature.
    let other = DeviceKeys::generate();
    let mut swapped = payload;
    swapped.sender_pub = *other.verifying_key().as_bytes();
    assert!(matches!(
        verify_payload(&payload_bytes(&swapped)),
        Err(ShareError::BadSignature)
    ));
}

#[test]
fn live_payload_round_trip_through_verify() {
    let (keys, file) = fixture();
    let payload = build_payload("live/p", &file, &keys, Some(3600));
    let received = payload_bytes(&payload);
    let verified = verify_payload(&received).unwrap();
    assert_eq!(verified.project, "live/p");
    assert!(verified.expires_at.is_some());
}
