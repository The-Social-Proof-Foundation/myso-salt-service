 # MySocial Auth Service

OAuth identity and encrypted wallet-vault storage. The service never derives or stores a wallet signing key.

## Overview

This service:
- Verifies Google, Apple, Facebook, and Twitch logins and issues a MySocial session
- Stores only ciphertext for a wallet vault, keyed by the authenticated subject
- Rate-limits requests

## Features

- **OAuth identity only**: Provider tokens prove who the user is. They are not turned into a wallet key
- **Opaque vault storage**: `wallet_vaults` holds ciphertext the client encrypted. The server cannot open it
- **Multi-Provider Authentication**: Support for Google, Apple, Facebook, and Twitch OAuth providers
- **Flexible Token Formats**: Accepts both JWT tokens (Google/Apple) and access tokens (Facebook/Twitch)
- **Rate Limiting**: IP-based rate limiting to prevent abuse
- **Health Monitoring**: Built-in health checks and metrics endpoints
- **Production Ready**: Graceful shutdown, structured logging, and error handling

## Related services

**Identity verification is intentionally not part of this service.** X/Twitter verification, ecosystem badges, share campaigns, and social graph import live in [`myso-identity-verification`](https://github.com/the-social-proof-foundation/myso-identity-verification) (`identity-verification.mysocial.network`). This service handles authentication only: OAuth sessions and opaque wallet-vault storage.

## Architecture

```
┌─────────────┐     JWT      ┌──────────────┐
│   Client    │─────────────▶│ Auth Service │
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

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run database migrations**
   ```bash
   cargo sqlx migrate run
   ```

4. **Start the service**
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
# Hardcoded OAuth clients (JSON). Same client_id may list multiple redirect_uri values.
# Merge keys by client_id + normalized redirect_uri (env wins on the same key).
ALLOWED_CLIENTS='[{"client_id":"mysocial-auth-client-id","redirect_uri":"http://localhost:3000/auth/callback"},{"client_id":"mysocial-auth-client-id","redirect_uri":"https://mysocial.network/auth/callback"}]'
# Auth frontend OAuth callback URL — used when a client has no per-client redirect_uri (must match Google/Apple console for that flow)
AUTH_CALLBACK_URL=https://auth.testnet.mysocial.network/callback

# MySo indexer GraphQL — optional. Fetches `platforms(approvedOnly: true, limit, offset)`.
# Each platform contributes on-chain `redirectUri` AND every non-empty `PLATFORM_LINKS_REDIRECT_KEYS` value.
# Merges with ALLOWED_CLIENTS; all redirect URIs kept (keyed by client_id + URI).
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

### POST /auth/provider/callback
OAuth callback endpoint. Receives `{ client_id, code, provider?, state?, nonce?, code_verifier?, redirect_uri? }`. Looks up `client_id` in the merged list: indexer platforms (`platformId`) plus `ALLOWED_CLIENTS` (same `client_id` may appear with multiple consumer `redirect_uri`s; any matching row is enough). Token exchange uses `redirect_uri` from the request when valid, else each client’s stored `redirect_uri`, else `AUTH_CALLBACK_URL`. Exchanges code for tokens in-band (Google, Apple, Facebook, Twitch) and returns a MySocial session. Routes register when the merged allowlist is non-empty.

Register OAuth redirect URIs in Google (etc.) to match the auth frontend callback (`AUTH_CALLBACK_URL`). Consumer allowlist URIs come from on-chain `redirectUri` plus all `PLATFORM_LINKS_REDIRECT_KEYS` values, merged with `ALLOWED_CLIENTS`.

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

### GET /wallet-vault and PUT /wallet-vault

Reads and writes the opaque vault for the authenticated subject. The body is ciphertext. Possession of the wallet is proved to the service before a write; the service does not decrypt the vault.

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
  "rate_limits_hit": 20,
  "uptime_seconds": 86400,
  "start_time": "2024-01-01T00:00:00Z"
}
```

## Security Considerations

1. **Database Security**
   - Enable SSL/TLS connections
   - Use connection pooling
   - Regular backups

2. **Network Security**
   - HTTPS only in production
   - Strict CORS policies
   - Rate limiting per IP

3. **Monitoring**
   - Set up alerts for failed JWT validations
   - Monitor rate limit violations

## Recovery Procedures

### Database Recovery
- Railway provides automatic daily backups
- Point-in-time recovery available
- Test restore procedures regularly

## Performance

- Handles 1000+ requests/second
- Sub-10ms response time for session and vault reads
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
