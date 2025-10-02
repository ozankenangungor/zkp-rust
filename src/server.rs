use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Result;
use config::{Config, ConfigError, Environment, File};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

use zkp::{serialization, ZkpResult, ZKP};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

/// Server configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_timeout_secs: u64,
    pub max_concurrent_streams: u32,
    pub enable_reflection: bool,
    pub log_level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 50051,
            request_timeout_secs: 30,
            max_concurrent_streams: 100,
            enable_reflection: false,
            log_level: "info".to_string(),
        }
    }
}

impl ServerConfig {
    /// Load configuration from environment variables and config files
    pub fn from_env() -> Result<Self, ConfigError> {
        let config = Config::builder()
            .add_source(File::with_name("config/server").required(false))
            .add_source(Environment::with_prefix("ZKP").separator("_"))
            .build()?;

        config.try_deserialize()
    }

    /// Get the socket address for the server
    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let addr = format!("{}:{}", self.host, self.port);
        Ok(addr.parse()?)
    }
}

/// Enhanced user information with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    pub registration_timestamp: chrono::DateTime<chrono::Utc>,

    // authorization
    pub r1: Option<BigUint>,
    pub r2: Option<BigUint>,
    pub last_challenge_timestamp: Option<chrono::DateTime<chrono::Utc>>,

    // verification
    pub c: Option<BigUint>,
    pub s: Option<BigUint>,
    pub session_id: Option<String>,
    pub last_successful_auth: Option<chrono::DateTime<chrono::Utc>>,
    pub failed_attempts: u32,
}

impl Default for UserInfo {
    fn default() -> Self {
        Self {
            user_name: String::new(),
            y1: BigUint::from(0u32),
            y2: BigUint::from(0u32),
            registration_timestamp: chrono::Utc::now(),
            r1: None,
            r2: None,
            last_challenge_timestamp: None,
            c: None,
            s: None,
            session_id: None,
            last_successful_auth: None,
            failed_attempts: 0,
        }
    }
}

/// Enhanced authentication service with better concurrency and error handling
#[derive(Debug)]
pub struct AuthImpl {
    pub user_info: Arc<RwLock<HashMap<String, UserInfo>>>,
    pub auth_id_to_user: Arc<RwLock<HashMap<String, String>>>,
    pub zkp: ZKP,
}

impl AuthImpl {
    /// Create a new authentication service instance
    pub fn new() -> ZkpResult<Self> {
        let zkp = ZKP::new(None)?;
        zkp.validate_parameters()?;

        Ok(Self {
            user_info: Arc::new(RwLock::new(HashMap::new())),
            auth_id_to_user: Arc::new(RwLock::new(HashMap::new())),
            zkp,
        })
    }
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    #[instrument(skip(self, request))]
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();
        let user_name = request.user;

        // Input validation
        if user_name.is_empty() {
            return Err(Status::invalid_argument("Username cannot be empty"));
        }

        if user_name.len() > 100 {
            return Err(Status::invalid_argument("Username too long"));
        }

        info!("Processing registration for user: {}", user_name);

        // Deserialize and validate y1, y2
        let y1 = serialization::deserialize_biguint(&request.y1)
            .map_err(|e| Status::invalid_argument(format!("Invalid y1: {}", e)))?;

        let y2 = serialization::deserialize_biguint(&request.y2)
            .map_err(|e| Status::invalid_argument(format!("Invalid y2: {}", e)))?;

        // Validate that y1 and y2 are within valid range
        if y1 >= self.zkp.p || y2 >= self.zkp.p {
            return Err(Status::invalid_argument("y1 and y2 must be less than p"));
        }

        if y1 <= BigUint::from(1u32) || y2 <= BigUint::from(1u32) {
            return Err(Status::invalid_argument("y1 and y2 must be greater than 1"));
        }

        let user_info = UserInfo {
            user_name: user_name.clone(),
            y1,
            y2,
            registration_timestamp: chrono::Utc::now(),
            ..Default::default()
        };

        // Check if user already exists
        {
            let user_info_map = self.user_info.read().await;
            if user_info_map.contains_key(&user_name) {
                warn!("Registration attempt for existing user: {}", user_name);
                return Err(Status::already_exists("User already registered"));
            }
        }

        // Register the user
        {
            let mut user_info_map = self.user_info.write().await;
            user_info_map.insert(user_name.clone(), user_info);
        }

        info!("✅ Successful registration for user: {}", user_name);
        Ok(Response::new(RegisterResponse {}))
    }

    #[instrument(skip(self, request))]
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let request = request.into_inner();
        let user_name = request.user;

        if user_name.is_empty() {
            return Err(Status::invalid_argument("Username cannot be empty"));
        }

        info!("Processing challenge request for user: {}", user_name);

        // Deserialize r1 and r2
        let r1 = serialization::deserialize_biguint(&request.r1)
            .map_err(|e| Status::invalid_argument(format!("Invalid r1: {}", e)))?;

        let r2 = serialization::deserialize_biguint(&request.r2)
            .map_err(|e| Status::invalid_argument(format!("Invalid r2: {}", e)))?;

        // Validate r1 and r2
        if r1 >= self.zkp.p || r2 >= self.zkp.p {
            return Err(Status::invalid_argument("r1 and r2 must be less than p"));
        }

        if r1 <= BigUint::from(1u32) || r2 <= BigUint::from(1u32) {
            return Err(Status::invalid_argument("r1 and r2 must be greater than 1"));
        }

        let mut user_info_map = self.user_info.write().await;

        if let Some(user_info) = user_info_map.get_mut(&user_name) {
            // Check rate limiting (simple implementation){}
            if let Some(last_challenge) = user_info.last_challenge_timestamp {
                let time_since_last = chrono::Utc::now() - last_challenge;
                if time_since_last < chrono::Duration::seconds(1) {
                    return Err(Status::resource_exhausted("Too many challenge requests"));
                }
            }

            let c = ZKP::generate_random_number_below(&self.zkp.q)
                .map_err(|e| Status::internal(format!("Failed to generate challenge: {}", e)))?;

            let auth_id = Uuid::new_v4().to_string();

            user_info.c = Some(c.clone());
            user_info.r1 = Some(r1);
            user_info.r2 = Some(r2);
            user_info.last_challenge_timestamp = Some(chrono::Utc::now());

            // Store auth_id mapping
            {
                let mut auth_id_map = self.auth_id_to_user.write().await;
                auth_id_map.insert(auth_id.clone(), user_name.clone());
            }

            info!("✅ Challenge created for user: {}", user_name);

            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id,
                c: serialization::serialize_biguint(&c),
            }))
        } else {
            warn!("Challenge request for non-existent user: {}", user_name);
            Err(Status::not_found(format!("User {} not found", user_name)))
        }
    }

    #[instrument(skip(self, request))]
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let request = request.into_inner();
        let auth_id = request.auth_id;

        if auth_id.is_empty() {
            return Err(Status::invalid_argument("Auth ID cannot be empty"));
        }

        info!(
            "Processing authentication verification for auth_id: {}",
            auth_id
        );

        // Find user by auth_id
        let user_name = {
            let auth_id_map = self.auth_id_to_user.read().await;
            auth_id_map.get(&auth_id).cloned()
        };

        let user_name = match user_name {
            Some(name) => name,
            None => {
                warn!("Verification attempt with invalid auth_id: {}", auth_id);
                return Err(Status::not_found("Invalid auth ID"));
            }
        };

        // Deserialize solution
        let s = serialization::deserialize_biguint(&request.s)
            .map_err(|e| Status::invalid_argument(format!("Invalid solution: {}", e)))?;

        if s >= self.zkp.q {
            return Err(Status::invalid_argument("Solution must be less than q"));
        }

        let mut user_info_map = self.user_info.write().await;
        let user_info = user_info_map
            .get_mut(&user_name)
            .ok_or_else(|| Status::internal("User info not found"))?;

        // Check if we have the required challenge data
        let (r1, r2, c) = match (&user_info.r1, &user_info.r2, &user_info.c) {
            (Some(r1), Some(r2), Some(c)) => (r1.clone(), r2.clone(), c.clone()),
            _ => {
                error!("Incomplete challenge data for user: {}", user_name);
                return Err(Status::failed_precondition(
                    "No active challenge for this user",
                ));
            }
        };

        user_info.s = Some(s.clone());

        // Verify the proof
        let verification_result = self
            .zkp
            .verify(&r1, &r2, &user_info.y1, &user_info.y2, &c, &s)
            .map_err(|e| Status::internal(format!("Verification error: {}", e)))?;

        if verification_result {
            let session_id = Uuid::new_v4().to_string();
            user_info.session_id = Some(session_id.clone());
            user_info.last_successful_auth = Some(chrono::Utc::now());
            user_info.failed_attempts = 0;

            // Clean up auth_id
            {
                let mut auth_id_map = self.auth_id_to_user.write().await;
                auth_id_map.remove(&auth_id);
            }

            info!("✅ Successful authentication for user: {}", user_name);
            Ok(Response::new(AuthenticationAnswerResponse { session_id }))
        } else {
            user_info.failed_attempts += 1;
            warn!(
                "❌ Failed authentication for user: {} (attempt {})",
                user_name, user_info.failed_attempts
            );

            // Clean up auth_id
            {
                let mut auth_id_map = self.auth_id_to_user.write().await;
                auth_id_map.remove(&auth_id);
            }

            Err(Status::permission_denied("Authentication failed"))
        }
    }
}

/// Initialize and run the ZKP authentication server
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load configuration
    let config = ServerConfig::from_env().unwrap_or_else(|e| {
        warn!("Failed to load config: {}. Using defaults.", e);
        ServerConfig::default()
    });

    info!(
        "Starting ZKP authentication server with config: {:?}",
        config
    );

    // Create authentication service
    let auth_impl =
        AuthImpl::new().map_err(|e| anyhow::anyhow!("Failed to create auth service: {}", e))?;

    let addr = config.socket_addr()?;
    info!("🚀 Starting server on {}", addr);

    // Build server with middleware
    let server = Server::builder()
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_grpc())
                .layer(TimeoutLayer::new(Duration::from_secs(
                    config.request_timeout_secs,
                )))
                .layer(CorsLayer::permissive()),
        )
        .max_concurrent_streams(Some(config.max_concurrent_streams))
        .add_service(AuthServer::new(auth_impl));

    // Start the server
    match server.serve(addr).await {
        Ok(_) => {
            info!("Server shutdown gracefully");
            Ok(())
        }
        Err(e) => {
            error!("Server error: {}", e);
            Err(e.into())
        }
    }
}
