use std::time::Duration;

// Generous ceiling: this suite runs alongside Argon2-heavy vault tests that
// saturate all cores, so wall-clock here reflects scheduler pressure.
const TEST_BUDGET: Duration = Duration::from_secs(180);
use tenv_core::transport::{
    EndpointAddr, LiveShare, decode_code, generate_password, receive_direct,
};

fn loopback_target(code: &str, live: &LiveShare) -> (String, EndpointAddr) {
    let (password, endpoint_id) = decode_code(code).unwrap();
    let sock = live
        .local_ports()
        .first()
        .copied()
        .expect("sender bound a local socket");
    let addr = EndpointAddr::from_parts(endpoint_id, [tenv_core::transport::ip_transport(sock)]);
    (password, addr)
}

#[tokio::test]
async fn live_transfer_over_loopback_delivers_payload() {
    let password = generate_password();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();

    let live = LiveShare::start(&password, payload.clone(), None)
        .await
        .unwrap();
    let code = live.code().to_string();
    let (password, addr) = loopback_target(&code, &live);

    let receiver = tokio::spawn(async move {
        receive_direct(addr, &password, None, "RCVR-TEST-FINGERPRINT").await
    });

    let received = receiver.await.expect("receiver task");
    let received = match &received {
        Err(e) => panic!("receiver failed: {e}"),
        Ok(r) => r,
    };
    let receipt = tokio::time::timeout(Duration::from_secs(5), live.wait_done())
        .await
        .expect("receipt within timeout")
        .expect("sender sees success");
    assert_eq!(receipt.receiver_fingerprint, "RCVR-TEST-FINGERPRINT");
    assert_eq!(received.payload, payload);
}

#[tokio::test]
async fn wrong_password_fails_closed_on_both_sides() {
    let real_password = generate_password();
    let payload = b"top secret env bytes".to_vec();

    let live = LiveShare::start(&real_password, payload, None)
        .await
        .unwrap();
    let code = live.code().to_string();
    // Receiver uses a DIFFERENT password than the sender's code carries.
    let (_, addr) = {
        let (pw, id) = decode_code(&code).unwrap();
        let sock = live.local_ports().first().copied().unwrap();
        let addr = tenv_core::transport::EndpointAddr::from_parts(
            id,
            [tenv_core::transport::ip_transport(sock)],
        );
        (pw, addr)
    };

    let waiter = tokio::spawn(async move { live.wait_done().await });
    let impostor_password = generate_password();
    let outcome = receive_direct(addr, &impostor_password, None, "IMPOSTOR").await;

    assert!(outcome.is_err(), "wrong code must fail closed");
    let sender_outcome = tokio::time::timeout(TEST_BUDGET, waiter)
        .await
        .expect("no hang");
    // Sender must observe an error (handshake/decrypt failure), never success.
    match sender_outcome {
        Err(e) => panic!("waiter channel broke: {e}"),
        Ok(Err(_)) => {}
        Ok(Ok(receipt)) => panic!("impostor delivery must not succeed: {receipt:?}"),
    }
}
