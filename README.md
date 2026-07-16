 # MySocial Salt Service

A production-ready salt backup service for zkLogin.

## Overview

This service provides secure salt generation and storage for zkLogin authentication, ensuring that:
- User identities remain private and cannot be traced back to Web2 credentials
- Salts are deterministically generated per user (consistent across platforms)
- All operations are audited and rate-limited
- Data is encrypted at rest

## Features

- **Secure Salt Generation**: Deterministic salt generation using SHA-256 with domain separation
- **Encryption at Rest**: ChaCha20-Poly1305 encryption for stored salts
- **Multi-Provider Authentication**: Support for Google, Apple, Facebook, and Twitch OAuth providers
- **Flexible Token Formats**: Accepts both JWT tokens (Google/Apple) and access tokens (Facebook/Twitch)
- **Rate Limiting**: IP-based rate limiting to prevent abuse
- **Audit Logging**: Comprehensive audit trail for all operations
- **Health Monitoring**: Built-in health checks and metrics endpoints
- **Production Ready**: Graceful shutdown, structured logging, and error handling

## Related services

**Identity verification is intentionally not part of this service.** X/Twitter verification, ecosystem badges, share campaigns, and social graph import live in [`myso-identity-verification`](https://github.com/the-social-proof-foundation/myso-identity-verification) (`identity-verification.mysocial.network`). This salt service handles authentication only: OAuth salt backup, session tokens, and wallet address derivation.

## Architecture

```
┌─────────────┐     JWT      ┌──────────────┐
│   Client    │─────────────▶│ Salt Service │
└─────────────┘              └──────┬───────┘
                                    │
                              ┌─────▼───────┐
                              │  PostgreSQL │
                              └─────────────┘
```

## Setup

### Prerequisites

- Rust 1.70+
- PostgreSQL 14+
- Railway account (for deployment)

### Local Development

1. **Clone the repository**
   ```bash
   cd myso-salt-service
   ```

2. **Generate a master seed**
   ```bash
   cargo run --bin generate_seed
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run database migrations**
   ```bash
   cargo sqlx migrate run
   ```

5. **Start the service**
   ```bash
   cargo run
   ```

## Deployment on Railway

### 1. Create Railway Project

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Create new project
railway init
```

### 2. Add PostgreSQL Database

In Railway dashboard:
1. Click "New Service"
2. Select "Database" → "PostgreSQL"
3. Note the connection string

### 3. Configure Environment Variables

Set these in Railway dashboard:

```bash
DATABASE_URL=<your-postgresql-url>
MASTER_SEED=<base64-encoded-seed>
PORT=3000
ALLOWED_ORIGINS=https://wallet.mysocial.network
RATE_LIMIT=60
LOG_LEVEL=info

# Required for JWT validation (Google, Apple). Use same client ID for web+iOS.
ALLOWED_AUDIENCE_GOOGLE=<your-google-client-id>.apps.googleusercontent.com
ALLOWED_AUDIENCE_APPLE=<your-apple-service-id>

# Required when using Facebook/Twitch access-token flow
ALLOWED_AUDIENCE_FACEBOOK=<canonical-facebook-aud>
ALLOWED_AUDIENCE_TWITCH=<canonical-twitch-aud>

TWITCH_CLIENT_ID=<your-twitch-client-id>  # Required for Twitch authentication
FACEBOOK_APP_ID=<your-facebook-app-id>    # Required for Facebook authentication
FACEBOOK_APP_SECRET=<your-facebook-app-secret>

# Auth callback (POST /auth/provider/callback). Enabled when merged allowlist is non-empty.
# Hardcoded OAuth clients (JSON). Same client_id overrides indexer row after merge.
ALLOWED_CLIENTS='[{"client_id":"mysocial-auth-client-id","redirect_uri":"http://localhost:3000/callback"}]'
# Auth frontend OAuth callback URL — used when a client has no per-client redirect_uri (must match Google/Apple console for that flow)
AUTH_CALLBACK_URL=https://auth.testnet.mysocial.network/callback

# MySo indexer GraphQL — optional. Fetches `platforms(approvedOnly: true, limit, offset)`.
# Uses on-chain `redirectUri` when set; falls back to `links` keys from `PLATFORM_LINKS_REDIRECT_KEYS`.
# Merges with ALLOWED_CLIENTS; env wins on duplicate platformId/client_id.
# Startup fails if the URL is set and the GraphQL request errors (HTTP or top-level errors).
# If unset, only ALLOWED_CLIENTS is used.
# MYSO_INDEXER_GRAPHQL_URL=https://graphql.testnet.mysocial.network/graphql
# INDEXER_PLATFORMS_PAGE_LIMIT=200
# PLATFORM_STATUS_ALLOWLIST=Live
# PLATFORM_STATUS_DENYLIST=Shutdown,Sunset
# PLATFORM_LINKS_REDIRECT_KEYS=website,url,oauthRedirect
# REQUIRE_REDIRECT_URI_FROM_LINKS=false

# MySocial Auth (optional) – for validating JWTs issued by the auth backend
MYSOCIAL_AUTH_ISSUER=https://auth.testnet.mysocial.network
MYSOCIAL_AUTH_JWKS_URI=https://auth.testnet.mysocial.network/.well-known/jwks.json
# ALLOWED_AUDIENCE_MYSOCIAL=  # optional, for audience validation

# Provider credentials for token exchange (in-band; no external auth API)
GOOGLE_CLIENT_SECRET=<your-google-client-secret>
APPLE_TEAM_ID=<your-apple-team-id>
APPLE_KEY_IDENTIFIER=<your-apple-key-id>
APPLE_PRIVATE_KEY=<your-apple-private-key-pem>

# Required MySocial platform sessions. Startup fails if signing is unavailable.
# Generate JWT_SIGNING_KEY once with: openssl rand -base64 32
JWT_SIGNING_KEY=<base64-ed25519-private-seed>
JWT_ISSUER=https://salt.testnet.mysocial.network
JWT_KEY_ID=mysocial-salt
```

### 4. Deploy

```bash
railway up
```

## API Endpoints

### GET /salt/check
Validates the salt service is ready (DB connectivity, salt derivation). Returns `{ "status": "ready", "salt_endpoint": "/salt" }`.

### POST /auth/provider/callback
OAuth callback endpoint. Receives `{ client_id, code, provider?, state?, nonce?, code_verifier?, redirect_uri? }`. Looks up `client_id` in the merged list: indexer platforms (`platformId`) plus `ALLOWED_CLIENTS`, with env overriding duplicates. Token exchange uses `redirect_uri` from the request when valid, else each client’s stored `redirect_uri`, else `AUTH_CALLBACK_URL`. Exchanges code for tokens in-band (Google, Apple, Facebook, Twitch), fetches salt, returns `{ code, user?, salt, access_token? }`. Routes register when the merged allowlist is non-empty.

Register OAuth redirect URIs in Google (etc.) to match the exact `redirect_uri` used for that client — from on-chain `redirectUri` when indexed, else from `links` via `PLATFORM_LINKS_REDIRECT_KEYS`.

### GET /.well-known/jwks.json

Publishes the Ed25519 public key used to verify MySocial session JWTs. Platform backends cache this
JWKS and validate issuer, audience, expiry, and `wallet_address` without receiving private signing
material.

### POST /auth/refresh

Rotates a MySocial refresh token and returns `{ session_access_token, refresh_token, expires_in,
user }`. Reuse of a revoked refresh token revokes the remaining session family.

### POST /auth/logout

Revokes the supplied `{ refresh_token }`. The endpoint is idempotent so clients can always clear
local credentials after the request.

### POST /salt
Get or create salt for a user.

**Request Format 1: JWT Token (Google, Apple)**
```json
{
  "jwt": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Request Format 2: Provider + Access Token (Facebook, Twitch)**
```json
{
  "provider": "facebook",
  "token": "access_token_here"
}
```

or

```json
{
  "provider": "twitch",
  "token": "access_token_here"
}
```

**Request Format 3: MySocial Auth (provider + JWT)**
```json
{
  "provider": "mysocial",
  "token": "<mysocial-jwt>"
}
```

MySocial JWTs can also use the JWT format when the issuer is configured: `{ "jwt": "<mysocial-jwt>" }`.

**Supported Providers:**
- `google` - **JWT format only** (`{ "jwt": "id_token" }`)
- `apple` - **JWT format only** (`{ "jwt": "id_token" }`)
- `facebook` - **Provider + token format** (`{ "provider": "facebook", "token": "access_token" }`)
- `twitch` - **Provider + token format** (`{ "provider": "twitch", "token": "access_token" }`)
- `mysocial` - **Provider + JWT format** (`{ "provider": "mysocial", "token": "<mysocial-jwt>" }`) – requires `MYSOCIAL_AUTH_ISSUER` and `MYSOCIAL_AUTH_JWKS_URI`

**Important Notes:**
- Google and Apple use JWT ID tokens and must use the `jwt` field format
- Facebook and Twitch use OAuth access tokens and must use the `provider` + `token` format
- Attempting to use Apple with `{ "provider": "apple", "token": "..." }` will return an error

**Response:**
```json
{
  "salt": "12345678901234567890123456789012"
}
```

The salt is returned as a BigInt decimal string (for zkLogin compatibility).

### GET /health
Health check endpoint.

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "0.1.0"
}
```

### GET /metrics
Service metrics (consider protecting this endpoint in production).

Response:
```json
{
  "requests_total": 1000,
  "requests_success": 950,
  "requests_failed": 50,
  "jwt_validations_failed": 30,
  "salts_created": 100,
  "salts_retrieved": 850,
  "rate_limits_hit": 20,
  "uptime_seconds": 86400,
  "start_time": "2024-01-01T00:00:00Z"
}
```

## Security Considerations

1. **Master Seed Protection**
   - Store in Railway's encrypted environment variables
   - Never commit to version control
   - Use different seeds for dev/staging/production
   - Rotate every 90 days

2. **Database Security**
   - Enable SSL/TLS connections
   - Use connection pooling
   - Regular backups

3. **Network Security**
   - HTTPS only in production
   - Strict CORS policies
   - Rate limiting per IP

4. **Monitoring**
   - Set up alerts for failed JWT validations
   - Monitor rate limit violations
   - Track salt creation patterns

## Recovery Procedures

### Master Seed Recovery
1. Keep encrypted backup of master seed in secure storage
2. Document recovery process with multiple approvers
3. Test recovery quarterly

### Database Recovery
- Railway provides automatic daily backups
- Point-in-time recovery available
- Test restore procedures regularly

## Performance

- Handles 1000+ requests/second
- Sub-10ms response time for cached salts
- Automatic connection pooling
- Efficient rate limiting with database cleanup

## Monitoring

Set up monitoring for:
- Service uptime
- Response times
- Error rates
- Database connections
- Rate limit violations

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit pull request
