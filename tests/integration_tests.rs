use zkp::{serialization, ZKP};

// Import the generated proto code
mod zkp_auth {
    include!("../src/zkp_auth.rs");
}

use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};

/// Convert password string to BigUint deterministically
fn password_to_biguint(password: &str, zkp: &ZKP) -> num_bigint::BigUint {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();

    let password_biguint = num_bigint::BigUint::from_bytes_be(&hash);

    // Reduce modulo q to ensure it's in valid range
    password_biguint % &zkp.q
}

/// Integration tests for the ZKP authentication system
#[tokio::test]
async fn test_full_authentication_flow() {
    // Note: This test requires the server to be running
    // Start the server in a separate terminal: cargo run --bin server

    // Skip this test if server is not running
    let client_result = AuthClient::connect("http://127.0.0.1:50051").await;
    if client_result.is_err() {
        println!("Skipping integration test - server not running");
        return;
    }

    let mut client = client_result.unwrap();
    let zkp = ZKP::new(None).unwrap();

    // Test data
    let username = format!("test_user_{}", chrono::Utc::now().timestamp());
    let password = "test_password_123";
    let password_biguint = password_to_biguint(password, &zkp);

    // Step 1: Registration
    let (y1, y2) = zkp.compute_pair(&password_biguint).unwrap();

    let register_request = RegisterRequest {
        user: username.clone(),
        y1: serialization::serialize_biguint(&y1),
        y2: serialization::serialize_biguint(&y2),
    };

    let register_response = client.register(register_request).await;
    assert!(register_response.is_ok(), "Registration should succeed");

    // Step 2: Authentication Challenge
    let k = ZKP::generate_random_number_below(&zkp.q).unwrap();
    let (r1, r2) = zkp.compute_pair(&k).unwrap();

    let challenge_request = AuthenticationChallengeRequest {
        user: username.clone(),
        r1: serialization::serialize_biguint(&r1),
        r2: serialization::serialize_biguint(&r2),
    };

    let challenge_response = client
        .create_authentication_challenge(challenge_request)
        .await
        .unwrap()
        .into_inner();

    assert!(!challenge_response.auth_id.is_empty());
    assert!(!challenge_response.c.is_empty());

    // Step 3: Authentication Answer
    let c = serialization::deserialize_biguint(&challenge_response.c).unwrap();
    let s = zkp.solve(&k, &c, &password_biguint).unwrap();

    let answer_request = AuthenticationAnswerRequest {
        auth_id: challenge_response.auth_id,
        s: serialization::serialize_biguint(&s),
    };

    let answer_response = client
        .verify_authentication(answer_request)
        .await
        .unwrap()
        .into_inner();

    assert!(!answer_response.session_id.is_empty());
    println!("✅ Full authentication flow completed successfully!");
}

#[tokio::test]
async fn test_invalid_registration() {
    let client_result = AuthClient::connect("http://127.0.0.1:50051").await;
    if client_result.is_err() {
        println!("Skipping integration test - server not running");
        return;
    }

    let mut client = client_result.unwrap();

    // Test empty username
    let register_request = RegisterRequest {
        user: "".to_string(),
        y1: vec![1, 2, 3],
        y2: vec![4, 5, 6],
    };

    let register_response = client.register(register_request).await;
    assert!(register_response.is_err(), "Empty username should fail");
}

#[tokio::test]
async fn test_authentication_without_registration() {
    let client_result = AuthClient::connect("http://127.0.0.1:50051").await;
    if client_result.is_err() {
        println!("Skipping integration test - server not running");
        return;
    }

    let mut client = client_result.unwrap();
    let zkp = ZKP::new(None).unwrap();

    let k = ZKP::generate_random_number_below(&zkp.q).unwrap();
    let (r1, r2) = zkp.compute_pair(&k).unwrap();

    let challenge_request = AuthenticationChallengeRequest {
        user: "non_existent_user".to_string(),
        r1: serialization::serialize_biguint(&r1),
        r2: serialization::serialize_biguint(&r2),
    };

    let challenge_response = client
        .create_authentication_challenge(challenge_request)
        .await;

    assert!(challenge_response.is_err(), "Non-existent user should fail");
}

#[tokio::test]
async fn test_wrong_password_authentication() {
    let client_result = AuthClient::connect("http://127.0.0.1:50051").await;
    if client_result.is_err() {
        println!("Skipping integration test - server not running");
        return;
    }

    let mut client = client_result.unwrap();
    let zkp = ZKP::new(None).unwrap();

    // Test data
    let username = format!("test_user_wrong_{}", chrono::Utc::now().timestamp());
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";

    let correct_password_biguint = password_to_biguint(correct_password, &zkp);
    let wrong_password_biguint = password_to_biguint(wrong_password, &zkp);

    // Register with correct password
    let (y1, y2) = zkp.compute_pair(&correct_password_biguint).unwrap();

    let register_request = RegisterRequest {
        user: username.clone(),
        y1: serialization::serialize_biguint(&y1),
        y2: serialization::serialize_biguint(&y2),
    };

    client.register(register_request).await.unwrap();

    // Try to authenticate with wrong password
    let k = ZKP::generate_random_number_below(&zkp.q).unwrap();
    let (r1, r2) = zkp.compute_pair(&k).unwrap();

    let challenge_request = AuthenticationChallengeRequest {
        user: username.clone(),
        r1: serialization::serialize_biguint(&r1),
        r2: serialization::serialize_biguint(&r2),
    };

    let challenge_response = client
        .create_authentication_challenge(challenge_request)
        .await
        .unwrap()
        .into_inner();

    let c = serialization::deserialize_biguint(&challenge_response.c).unwrap();
    let s = zkp.solve(&k, &c, &wrong_password_biguint).unwrap();

    let answer_request = AuthenticationAnswerRequest {
        auth_id: challenge_response.auth_id,
        s: serialization::serialize_biguint(&s),
    };

    let answer_response = client.verify_authentication(answer_request).await;

    assert!(
        answer_response.is_err(),
        "Wrong password should fail authentication"
    );
}
