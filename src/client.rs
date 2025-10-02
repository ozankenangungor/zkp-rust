use std::io::{self, Write};

use anyhow::Result;
use clap::Parser;
use num_bigint::BigUint;
use tracing::{error, info, instrument};

use zkp::{serialization, ZkpResult, ZKP};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};

/// Command line arguments for the ZKP client
#[derive(Parser, Debug)]
#[command(name = "zkp-client")]
#[command(about = "A Zero Knowledge Proof authentication client")]
struct Args {
    /// Server address to connect to
    #[arg(short, long, default_value = "http://127.0.0.1:50051")]
    server: String,

    /// Username for authentication
    #[arg(short, long)]
    username: Option<String>,

    /// Skip interactive mode and use provided values
    #[arg(long)]
    non_interactive: bool,
}

/// Secure password input without echoing to terminal
fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let password = rpassword::read_password()?;
    Ok(password)
}

/// Read input from user with a prompt
fn read_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Convert password string to BigUint deterministically
fn password_to_biguint(password: &str, zkp: &ZKP) -> BigUint {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let hash = hasher.finalize();

    let password_biguint = BigUint::from_bytes_be(&hash);

    // Reduce modulo q to ensure it's in valid range
    password_biguint % &zkp.q
}

/// Perform user registration
#[instrument(skip(client, zkp, password))]
async fn register_user(
    client: &mut AuthClient<tonic::transport::Channel>,
    zkp: &ZKP,
    username: &str,
    password: &str,
) -> ZkpResult<()> {
    info!("Starting registration for user: {}", username);

    let password_biguint = password_to_biguint(password, zkp);
    let (y1, y2) = zkp.compute_pair(&password_biguint)?;

    let request = RegisterRequest {
        user: username.to_string(),
        y1: serialization::serialize_biguint(&y1),
        y2: serialization::serialize_biguint(&y2),
    };

    client
        .register(request)
        .await
        .map_err(|e| zkp::ZkpError::ComputationError(format!("Registration failed: {}", e)))?;

    info!("✅ Registration successful for user: {}", username);
    Ok(())
}

/// Perform user authentication
#[instrument(skip(client, zkp, password))]
async fn authenticate_user(
    client: &mut AuthClient<tonic::transport::Channel>,
    zkp: &ZKP,
    username: &str,
    password: &str,
) -> ZkpResult<String> {
    info!("Starting authentication for user: {}", username);

    let password_biguint = password_to_biguint(password, zkp);
    let k = ZKP::generate_random_number_below(&zkp.q)?;
    let (r1, r2) = zkp.compute_pair(&k)?;

    // Request challenge
    let challenge_request = AuthenticationChallengeRequest {
        user: username.to_string(),
        r1: serialization::serialize_biguint(&r1),
        r2: serialization::serialize_biguint(&r2),
    };

    let challenge_response = client
        .create_authentication_challenge(challenge_request)
        .await
        .map_err(|e| zkp::ZkpError::ComputationError(format!("Challenge request failed: {}", e)))?
        .into_inner();

    let auth_id = challenge_response.auth_id;
    let c = serialization::deserialize_biguint(&challenge_response.c)?;

    // Solve challenge
    let s = zkp.solve(&k, &c, &password_biguint)?;

    // Submit solution
    let answer_request = AuthenticationAnswerRequest {
        auth_id,
        s: serialization::serialize_biguint(&s),
    };

    let answer_response = client
        .verify_authentication(answer_request)
        .await
        .map_err(|e| zkp::ZkpError::ComputationError(format!("Authentication failed: {}", e)))?
        .into_inner();

    info!("✅ Authentication successful for user: {}", username);
    Ok(answer_response.session_id)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();

    info!("Starting ZKP authentication client");

    // Initialize ZKP
    let zkp = ZKP::new(None).map_err(|e| anyhow::anyhow!("Failed to initialize ZKP: {}", e))?;

    // Connect to server
    let mut client = AuthClient::connect(args.server.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to server: {}", e))?;

    info!("✅ Connected to server at {}", args.server);

    // Get username
    let username = if let Some(username) = args.username {
        username
    } else if args.non_interactive {
        return Err(anyhow::anyhow!("Username required in non-interactive mode"));
    } else {
        read_input("Please enter your username: ")?
    };

    if username.is_empty() {
        return Err(anyhow::anyhow!("Username cannot be empty"));
    }

    // Registration phase
    let registration_password = if args.non_interactive {
        return Err(anyhow::anyhow!(
            "Non-interactive mode not fully supported yet"
        ));
    } else {
        read_password("Please enter a password for registration: ")?
    };

    if registration_password.is_empty() {
        return Err(anyhow::anyhow!("Password cannot be empty"));
    }

    match register_user(&mut client, &zkp, &username, &registration_password).await {
        Ok(_) => info!("Registration completed successfully"),
        Err(e) => {
            error!("Registration failed: {}", e);
            return Err(anyhow::anyhow!("Registration failed: {}", e));
        }
    }

    // Authentication phase
    let auth_password = if args.non_interactive {
        registration_password
    } else {
        read_password("Please enter your password to authenticate: ")?
    };

    match authenticate_user(&mut client, &zkp, &username, &auth_password).await {
        Ok(session_id) => {
            info!("🎉 Authentication successful!");
            println!("Session ID: {}", session_id);
            Ok(())
        }
        Err(e) => {
            error!("Authentication failed: {}", e);
            Err(anyhow::anyhow!("Authentication failed: {}", e))
        }
    }
}
