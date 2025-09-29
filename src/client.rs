use num_bigint::BigUint;
use std::io::stdin;

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp::ZKP;
use zkp_auth::{
    AuthenticationAnswerRequest, AuthenticationChallengeRequest, RegisterRequest,
    auth_client::AuthClient,
};

#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP {
        alpha: alpha.clone(),
        beta: beta.clone(),
        p: p.clone(),
        q: q.clone(),
    };

    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("could not connect to the server");
    println!("✅ Connected to the server");

    println!("Please provide the username:");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let username = buf.trim().to_string();
    buf.clear();

    println!("Please provide the password:");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let (y1, y2) = zkp.compute_pair(&password);

    let request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    let _response = client
        .register(request)
        .await
        .expect("Could not register in server");

    println!("✅ Registration was successful");

    println!("Please provide the password (to login):");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let k = ZKP::generate_random_number_below(&q);
    let (r1, r2) = zkp.compute_pair(&k);

    let request = AuthenticationChallengeRequest {
        user: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let response = client
        .create_authentication_challenge(request)
        .await
        .expect("Could not request challenge to server")
        .into_inner();

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    let s = zkp.solve(&k, &c, &password);

    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    let response = client
        .verify_authentication(request)
        .await
        .expect("Could not verify authentication in server")
        .into_inner();

    println!("✅Logging successful! session_id: {}", response.session_id);
}
