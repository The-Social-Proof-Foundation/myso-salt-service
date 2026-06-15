# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Clone myso-rust-sdk for path dependency (git dep fails in workspace)
RUN git clone https://github.com/The-Social-Proof-Foundation/myso-rust-sdk /app/myso-rust-sdk

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies including curl for healthcheck
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary
COPY --from=builder /app/target/release/myso-salt-service /app/
COPY --from=builder /app/migrations /app/migrations

# Create non-root user
RUN useradd -m -u 1001 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 3000

# Health check (respects Railway PORT at runtime)
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=5 \
    CMD sh -c 'curl -f "http://127.0.0.1:${PORT:-3000}/health" || exit 1'

# Run the binary
CMD ["./myso-salt-service"] 