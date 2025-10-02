# Makefile for ZKP Authentication Project

.PHONY: help build test check clippy format bench docker-build docker-run clean server client

# Default target
help:
	@echo "Available targets:"
	@echo "  build         - Build the project"
	@echo "  test          - Run all tests"
	@echo "  check         - Check code compilation"
	@echo "  clippy        - Run clippy linter"
	@echo "  format        - Format code with rustfmt"
	@echo "  bench         - Run benchmarks"
	@echo "  server        - Run the server"
	@echo "  client        - Run the client"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run with Docker Compose"
	@echo "  clean         - Clean build artifacts"

# Build targets
build:
	cargo build --release

check:
	cargo check

test:
	cargo test

# Code quality
clippy:
	cargo clippy -- -D warnings

format:
	cargo fmt --all

# Performance
bench:
	cargo bench

# Run targets
server:
	RUST_LOG=info cargo run --bin server

client:
	cargo run --bin client

# Docker targets
docker-build:
	docker build -t zkp-auth .

docker-run:
	docker-compose up --build

# Utility targets
clean:
	cargo clean
	docker system prune -f

# Development workflow
dev-setup: format clippy test

# Production build
production: clean clippy test build

# Quick development check
quick-check: format check clippy