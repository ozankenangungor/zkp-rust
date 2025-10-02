# Zero Knowledge Proof Authentication Server

Zero Knowledge Proof (ZKP) authentication system built with Rust and gRPC.

## Overview

This project implements the Schnorr identification protocol, allowing users to authenticate without revealing their passwords to the server. The server never stores or sees user passwords, only cryptographic commitments.

## Features

### 🔒 Security
- Zero Knowledge Proof authentication using Schnorr protocol
- No password storage on server
- Cryptographically secure random number generation
- Input validation and bounds checking
- Rate limiting for authentication attempts

- Structured logging with tracing
- Configuration management via environment variables and files
- Comprehensive error handling with custom error types
- Async/await with tokio for high performance
- Connection timeouts and rate limiting
- CORS and security middleware

### 🛠 Developer Experience
- CLI client with secure password input
- Comprehensive unit tests
- Benchmarking capabilities
- Docker support
- Detailed documentation

## Architecture

```
┌─────────────┐    gRPC/HTTP2    ┌─────────────┐
│   Client    ├─────────────────►│   Server    │
│             │                  │             │
│ - Register  │                  │ - Validate  │
│ - Auth      │                  │ - Store     │
│ - Prove     │                  │ - Verify    │
└─────────────┘                  └─────────────┘
```

## Protocol Flow

### Registration
1. Client computes `y1 = α^x mod p` and `y2 = β^x mod p`
2. Client sends `(username, y1, y2)` to server
3. Server stores user commitment values

### Authentication
1. Client generates random `k` and computes `r1 = α^k mod p`, `r2 = β^k mod p`
2. Client sends `(username, r1, r2)` to server
3. Server generates random challenge `c` and sends back `(auth_id, c)`
4. Client computes `s = k - c*x mod q` and sends `(auth_id, s)`
5. Server verifies: `r1 = α^s * y1^c mod p` and `r2 = β^s * y2^c mod p`
6. If valid, server returns session token

## Quick Start

### Prerequisites
- Rust 1.70+
- Protocol Buffers compiler (`protoc`)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd zkp-auth

# Install dependencies
cargo build --release

# Run tests
cargo test

# Run clippy for code quality
cargo clippy
```

### Running the Server

```bash
# Default configuration
cargo run --bin server

# With custom configuration
ZKP_HOST=0.0.0.0 ZKP_PORT=8080 cargo run --bin server

# With config file
cargo run --bin server
```

### Running the Client

```bash
# Interactive mode
cargo run --bin client

# Specify server
cargo run --bin client -- --server http://localhost:50051

# With username
cargo run --bin client -- --username alice
```

### Docker

```bash
# Build image
docker build -t zkp-auth .

# Run with docker-compose
docker-compose up

# Run server only
docker run -p 50051:50051 zkp-auth
```

## Configuration

The server can be configured via:

1. **Environment Variables** (prefix with `ZKP_`):
   ```bash
   ZKP_HOST=0.0.0.0
   ZKP_PORT=50051
   ZKP_LOG_LEVEL=debug
   ```

2. **Configuration File** (`config/server.toml`):
   ```toml
   host = "0.0.0.0"
   port = 50051
   log_level = "info"
   request_timeout_secs = 30
   max_concurrent_streams = 100
   ```

## API Reference

### Registration
```protobuf
rpc Register(RegisterRequest) returns (RegisterResponse)

message RegisterRequest {
    string user = 1;
    bytes y1 = 2;    // α^x mod p
    bytes y2 = 3;    // β^x mod p
}
```

### Authentication Challenge
```protobuf
rpc CreateAuthenticationChallenge(AuthenticationChallengeRequest) 
    returns (AuthenticationChallengeResponse)

message AuthenticationChallengeRequest {
    string user = 1;
    bytes r1 = 2;    // α^k mod p
    bytes r2 = 3;    // β^k mod p
}
```

### Authentication Verification
```protobuf
rpc VerifyAuthentication(AuthenticationAnswerRequest) 
    returns (AuthenticationAnswerResponse)

message AuthenticationAnswerRequest {
    string auth_id = 1;
    bytes s = 2;     // k - c*x mod q
}
```

## Security Considerations

1. **Parameter Validation**: All inputs are validated against cryptographic bounds
2. **Rate Limiting**: Prevents brute force attacks
3. **Secure Random Generation**: Uses cryptographically secure randomness
4. **Session Management**: Temporary auth IDs with cleanup
5. **Error Handling**: Prevents information leakage through error messages

## Performance

- **Async Architecture**: Built on Tokio for high concurrency
- **Connection Pooling**: Efficient resource usage
- **Timeouts**: Prevents resource exhaustion
- **Streaming**: gRPC HTTP/2 for efficient communication

## Development

### Code Quality
```bash
# Run all tests
cargo test

# Code formatting
cargo fmt

# Linting
cargo clippy

# Security audit
cargo audit
```

### Benchmarking
```bash
# Run benchmarks
cargo bench

# Profile performance
cargo profile generate
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure server is running and port is accessible
2. **Authentication Failed**: Check password consistency between registration and login
3. **Build Errors**: Ensure `protoc` is installed and in PATH

### Debugging

Enable debug logging:
```bash
RUST_LOG=debug cargo run --bin server
```

### Monitoring

The server provides structured logs compatible with common log aggregation tools:
- JSON formatted logs
- Correlation IDs for request tracing
- Performance metrics

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run quality checks
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Schnorr identification protocol
- RFC 3526 for standard cryptographic parameters
- Rust cryptography ecosystem