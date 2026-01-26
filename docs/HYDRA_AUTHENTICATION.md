# Hydra Authentication Guide

This guide explains how to use Ory Hydra OAuth2 authentication with DID-based cryptographic signatures to secure your Bindu agents.

## Overview

Bindu implements **hybrid OAuth2 + DID authentication** providing dual-layer security:

**Layer 1 - OAuth2 Token Authentication:**
- **OAuth2/OIDC authentication** for securing API endpoints
- **Token-based access control** with introspection
- **Automatic agent registration** as OAuth clients
- **Self-hosted, open-source** solution with no vendor lock-in

**Layer 2 - DID Signature Verification:**
- **Cryptographic identity proof** using DID private keys
- **Request integrity verification** with digital signatures
- **Replay attack prevention** with timestamp validation
- **No shared secrets** - private keys never leave the agent
- **Decentralized trust** using W3C DID standards

This hybrid approach provides defense-in-depth: even if an OAuth token is compromised, requests cannot be forged without the agent's private key.

## Quick Start

### 1. Configure Environment Variables

Create a `.env` file with Hydra settings:

```bash
# Enable Hydra authentication
HYDRA__ENABLED=true
AUTH__ENABLED=true
AUTH__PROVIDER=hydra

# Hydra endpoints
HYDRA__ADMIN_URL=https://hydra-admin.getbindu.com
HYDRA__PUBLIC_URL=https://hydra.getbindu.com

# Connection settings
HYDRA__VERIFY_SSL=true
HYDRA__TIMEOUT=10

# Auto-register agents
HYDRA__AUTO_REGISTER_AGENTS=true
```

### 2. Configure Your Agent

Add authentication to your agent config:

```json
{
  "author": "you@example.com",
  "name": "my-agent",
  "deployment": {
    "url": "http://localhost:3773",
    "expose": true
  },
  "auth": {
    "enabled": true,
    "provider": "hydra"
  }
}
```

### 3. Run Your Agent

When you run `bindufy`, the agent will automatically:
1. Register as an OAuth client in Hydra
2. Save credentials to `.bindu/oauth_credentials.json`
3. Enable authentication middleware

```python
from bindu.penguin import bindufy

def my_handler(messages):
    return "Hello, authenticated user!"

manifest = bindufy(config, my_handler)
```

## Authentication Flow

### Hybrid OAuth2 + DID Authentication Flow

```
Agent A                    Hydra                     Agent B
   |                         |                          |
   |-- 1. Get Token -------->|                          |
   |    (client_credentials) |                          |
   |    DID as client_id     |                          |
   |                         |                          |
   |<-- 2. Access Token -----|                          |
   |                         |                          |
   |-- 3. Call API ---------------------------------------->|
   |    (Bearer token + DID signature)                     |
   |                         |                          |
   |                         |<-- 4. Introspect Token --|
   |                         |    (Layer 1: OAuth2)     |
   |                         |                          |
   |                         |-- 5. Token Valid ------->|
   |                         |                          |
   |                         |<-- 6. Get Public Key ----|
   |                         |    (from client metadata)|
   |                         |                          |
   |                         |-- 7. Public Key -------->|
   |                         |                          |
   |                         |    8. Verify Signature --|
   |                         |       (Layer 2: DID)     |
   |                         |                          |
   |<-- 9. Response (if both layers valid) ---------------|
```

### Dual-Layer Security

**Layer 1: OAuth2 Token (Authorization)**
- Validates WHAT the client can do (permissions/scopes)
- Token introspection with Hydra Admin API
- Token expiration and revocation support

**Layer 2: DID Signature (Authentication)**
- Validates WHO the client is (cryptographic proof)
- Digital signature verification using public key
- Timestamp validation prevents replay attacks
- Request body integrity verification

### Step-by-Step Flow

**1. Agent Registration (Automatic with DID)**
```bash
# When agent starts, it registers with Hydra using DID as client_id
POST https://hydra-admin.getbindu.com/admin/clients
{
  "client_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "client_secret": "generated-secret",
  "grant_types": ["client_credentials"],
  "scope": "agent:read agent:write"
}
```

**2. Get Access Token**
```bash
curl -X POST https://hydra.getbindu.com/oauth2/token \
  -u "agent-abc123:generated-secret" \
  -d "grant_type=client_credentials&scope=agent:read agent:write"

# Response:
{
  "access_token": "ory_at_...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**3. Call Protected API**
```bash
curl -X POST http://localhost:3773/ \
  -H "Authorization: Bearer ory_at_..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "message/send",
    "params": {"messages": [{"role": "user", "content": "Hello"}]},
    "id": 1
  }'
```

## OAuth Client Management

### Create OAuth Client

```bash
curl -X POST http://localhost:3773/admin/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-app",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "offline", "agent:read"]
  }'
```

### List OAuth Clients

```bash
curl http://localhost:3773/admin/oauth/clients?limit=10
```

### Get Client Details

```bash
curl http://localhost:3773/admin/oauth/clients/my-app
```

### Delete OAuth Client

```bash
curl -X DELETE http://localhost:3773/admin/oauth/clients/my-app
```

## Using Hybrid Authentication in Code

### Making Authenticated Requests with DID Signatures

**Option 1: Using HybridAuthClient (Recommended)**

```python
from bindu.utils.hybrid_auth_client import HybridAuthClient
from bindu.extensions.did import DIDExtension
from pathlib import Path

# Initialize DID extension
did_extension = DIDExtension(pki_dir=Path(".bindu"))

# Create hybrid auth client
client = HybridAuthClient(
    agent_id="my-agent",
    credentials_dir=Path(".bindu"),
    did_extension=did_extension
)

await client.initialize()

# Make authenticated request with both OAuth token and DID signature
response = await client.post(
    url="http://agent-b:3773/",
    data={
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {"messages": [{"role": "user", "content": "Hello"}]},
        "id": 1
    }
)

print(response)
```

**Option 2: Manual Request Signing**

```python
from bindu.utils.token_utils import get_client_credentials_token
from bindu.utils.did_signature import create_signed_request_headers
from bindu.extensions.did import DIDExtension
import aiohttp
import json

# Get OAuth token
token_response = await get_client_credentials_token(
    client_id="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    client_secret="your-secret",
    scope="agent:read agent:write"
)

# Initialize DID extension
did_extension = DIDExtension(pki_dir=Path(".bindu"))

# Prepare request body
request_body = {
    "jsonrpc": "2.0",
    "method": "message/send",
    "params": {"messages": [{"role": "user", "content": "Hello"}]},
    "id": 1
}

# Create signed headers (includes both OAuth token and DID signature)
headers = create_signed_request_headers(
    body=request_body,
    did=did_extension.did,
    did_extension=did_extension,
    bearer_token=token_response["access_token"]
)

# Make request
async with aiohttp.ClientSession() as session:
    async with session.post(
        "http://agent-b:3773/",
        headers=headers,
        json=request_body
    ) as response:
        result = await response.json()
        print(result)
```

### Agent-to-Agent Communication

```python
from bindu.utils.hybrid_auth_client import call_agent_with_hybrid_auth
from bindu.extensions.did import DIDExtension
from pathlib import Path

# Initialize DID extension
did_extension = DIDExtension(pki_dir=Path(".bindu"))

# Call another agent with hybrid authentication
response = await call_agent_with_hybrid_auth(
    from_agent_id="agent-a",
    from_credentials_dir=Path(".bindu"),
    from_did_extension=did_extension,
    to_agent_url="http://agent-b:3773/",
    messages=[
        {"role": "user", "content": "Hello from Agent A"}
    ]
)

print(response)
```

### Get Token Only (Without DID Signature)

```python
from bindu.utils.token_utils import get_client_credentials_token

# For backward compatibility, you can still get tokens without DID signatures
token_response = await get_client_credentials_token(
    client_id="did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    client_secret="your-secret",
    scope="agent:read agent:write"
)

access_token = token_response["access_token"]

# Note: Requests without DID signatures will still work for backward compatibility,
# but won't have the additional security layer of cryptographic verification
```

### Introspect Token

```python
from bindu.utils.token_utils import introspect_token

result = await introspect_token(access_token)

if result["active"]:
    print(f"Token valid for: {result['sub']}")
    print(f"Scopes: {result['scope']}")
else:
    print("Token is invalid or expired")
```

### Revoke Token

```python
from bindu.utils.token_utils import revoke_token

revoked = await revoke_token(access_token)
if revoked:
    print("Token revoked successfully")
```

## Configuration Reference

### Hydra Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `HYDRA__ENABLED` | `false` | Enable Hydra authentication |
| `HYDRA__ADMIN_URL` | `https://hydra-admin.getbindu.com` | Hydra Admin API URL |
| `HYDRA__PUBLIC_URL` | `https://hydra.getbindu.com` | Hydra Public API URL |
| `HYDRA__TIMEOUT` | `10` | Request timeout (seconds) |
| `HYDRA__VERIFY_SSL` | `true` | Verify SSL certificates |
| `HYDRA__MAX_RETRIES` | `3` | Max retry attempts |
| `HYDRA__CACHE_TTL` | `300` | Token cache TTL (seconds) |
| `HYDRA__AUTO_REGISTER_AGENTS` | `true` | Auto-register agents |
| `HYDRA__AGENT_CLIENT_PREFIX` | `agent-` | Prefix for agent client IDs |

### Public Endpoints

These endpoints bypass authentication:
- `/.well-known/agent.json` - Agent card
- `/did/resolve` - DID resolution
- `/docs` - Documentation
- `/favicon.ico` - Favicon
- `/oauth/*` - OAuth callbacks

## Security Benefits of Hybrid Authentication

### Defense Against Common Attacks

| Attack Type | OAuth2 Only | OAuth2 + DID |
|-------------|-------------|--------------|
| **Token Theft** | ❌ Vulnerable | ✅ Protected (need private key) |
| **Replay Attack** | ⚠️ Until token expires | ✅ Protected (timestamp validation) |
| **Request Tampering** | ❌ Vulnerable | ✅ Protected (signature verification) |
| **Man-in-Middle** | ⚠️ If HTTPS compromised | ✅ Protected (signature + encryption) |
| **Impersonation** | ❌ Anyone with token | ✅ Need private key (impossible to forge) |

### How Hybrid Authentication Protects You

**Scenario 1: Token Stolen**
```
Without DID Signature:
❌ Attacker steals OAuth token → Can make requests → System compromised

With DID Signature:
✅ Attacker steals OAuth token → Cannot sign requests → Requests rejected
```

**Scenario 2: Replay Attack**
```
Without Timestamp:
❌ Attacker captures valid request → Replays it later → Request succeeds

With Timestamp:
✅ Attacker captures valid request → Replays 10 min later → Rejected (expired)
```

**Scenario 3: Request Modification**
```
Without Signature:
❌ Attacker intercepts request → Modifies body → Modified request succeeds

With Signature:
✅ Attacker intercepts request → Modifies body → Signature invalid → Rejected
```

### Key Security Properties

1. **Cryptographic Identity Proof**: Private key proves WHO you are
2. **Request Integrity**: Signature ensures request wasn't tampered with
3. **Non-Repudiation**: Can't deny making a signed request
4. **Temporal Validity**: Timestamps prevent replay attacks
5. **No Shared Secrets**: Private keys never leave the agent

## Security Best Practices

### 1. Protect Private Keys

```bash
# DID private keys are stored in .bindu/pki/
# Ensure restrictive permissions
chmod 700 .bindu/pki/
chmod 600 .bindu/pki/*

# Add to .gitignore
echo ".bindu/pki/" >> .gitignore
echo ".bindu/oauth_credentials.json" >> .gitignore
```

### 2. Use HTTPS in Production

```bash
HYDRA__ADMIN_URL=https://hydra-admin.getbindu.com
HYDRA__PUBLIC_URL=https://hydra.getbindu.com
HYDRA__VERIFY_SSL=true
```

### 3. Monitor DID Signature Verification

```python
# Check if requests are using DID signatures
if request.state.user.get("signature_info", {}).get("did_verified"):
    logger.info(f"✅ Request verified with DID signature")
else:
    logger.warning(f"⚠️ Request without DID signature (backward compatibility)")
```

### 4. Set Appropriate Timestamp Tolerance

```python
# In production, use shorter tolerance for replay protection
# Default is 300 seconds (5 minutes)
# For high-security scenarios, reduce to 60 seconds (1 minute)
```

### 5. Rotate Client Secrets Regularly

```bash
# Delete old client
curl -X DELETE http://localhost:3773/admin/oauth/clients/did:key:z6Mk...

# Agent will auto-register with new credentials on restart
# DID and private key remain the same
```

### 6. Use Appropriate Scopes

Define minimal scopes for each client:
- `agent:read` - Read-only access
- `agent:write` - Write access
- `agent:admin` - Administrative access
- `openid` - OpenID Connect
- `offline` - Refresh tokens

## Troubleshooting

### Agent Registration Failed

**Problem:** Agent fails to register with Hydra

**Solutions:**
1. Check Hydra is accessible:
   ```bash
   curl https://hydra-admin.getbindu.com/admin/health/ready
   ```

2. Verify environment variables:
   ```bash
   echo $HYDRA__ADMIN_URL
   echo $HYDRA__ENABLED
   ```

3. Check logs for errors:
   ```bash
   tail -f logs/bindu_server.log
   ```

### Token Validation Failed

**Problem:** Valid token returns 401

**Solutions:**
1. Check token hasn't expired:
   ```python
   result = await introspect_token(token)
   print(result)
   ```

2. Verify token is active:
   ```bash
   curl -X POST https://hydra-admin.getbindu.com/admin/oauth2/introspect \
     -d "token=YOUR_TOKEN"
   ```

3. Clear token cache and retry

### Connection Refused

**Problem:** Cannot connect to Hydra

**Solutions:**
1. Check Hydra is running
2. Verify firewall rules
3. Check SSL certificate validity

### DID Signature Verification Failed

**Problem:** Request rejected with "Invalid DID signature" error

**Solutions:**

1. **Check DID matches token:**
   ```python
   # Ensure the DID in headers matches the client_id in token
   # DID in X-DID header must equal client_id from OAuth token
   ```

2. **Verify timestamp is recent:**
   ```python
   import time
   current_time = int(time.time())
   request_timestamp = int(headers["X-DID-Timestamp"])
   
   # Should be within 5 minutes (300 seconds)
   if abs(current_time - request_timestamp) > 300:
       print("Timestamp expired - request too old")
   ```

3. **Check public key is registered:**
   ```bash
   # Verify client has public key in metadata
   curl http://localhost:3773/admin/oauth/clients/did:key:z6Mk...
   
   # Should see:
   # "metadata": {
   #   "public_key": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
   #   "hybrid_auth": true
   # }
   ```

4. **Ensure request body matches signature:**
   ```python
   # The signature is computed over the exact request body
   # Any modification after signing will invalidate the signature
   # Don't modify the body between signing and sending
   ```

5. **Verify DID extension is initialized:**
   ```python
   from bindu.extensions.did import DIDExtension
   from pathlib import Path
   
   # Ensure DID extension can access private key
   did_ext = DIDExtension(pki_dir=Path(".bindu/pki"))
   print(f"DID: {did_ext.did}")
   print(f"Public Key: {did_ext.public_key_multibase}")
   ```

### Backward Compatibility Issues

**Problem:** Old clients without DID signatures fail

**Solution:** Hybrid authentication is backward compatible. Clients without DID signatures will still work:

```python
# Old client (OAuth only) - Still works
headers = {
    "Authorization": "Bearer token123"
}

# New client (OAuth + DID) - Enhanced security
headers = {
    "Authorization": "Bearer token123",
    "X-DID": "did:key:z6Mk...",
    "X-DID-Signature": "signature...",
    "X-DID-Timestamp": "1234567890"
}
```

The middleware only enforces DID signature verification when:
- Client ID starts with `did:`
- Client has `public_key` in metadata
- Request includes DID signature headers
4. Try with `HYDRA__VERIFY_SSL=false` for testing

## Migration from Auth0

If migrating from Auth0:

1. Update agent config:
   ```json
   {
     "auth": {
       "enabled": true,
       "provider": "hydra"  // Changed from "auth0"
     }
   }
   ```

2. Update environment variables:
   ```bash
   # Remove Auth0 vars
   # AUTH__DOMAIN=...
   # AUTH__AUDIENCE=...
   
   # Add Hydra vars
   AUTH__PROVIDER=hydra
   HYDRA__ENABLED=true
   ```

3. Restart agent - it will auto-register with Hydra

## Available Hydra Endpoints

### Public API (https://hydra.getbindu.com)
- `/health/ready` - Health check
- `/oauth2/auth` - Authorization endpoint
- `/oauth2/token` - Token endpoint
- `/oauth2/revoke` - Token revocation
- `/userinfo` - User info endpoint
- `/.well-known/jwks.json` - JSON Web Key Set

### Admin API (https://hydra-admin.getbindu.com)
- `/admin/health/ready` - Health check
- `/admin/clients` - OAuth2 client management
- `/admin/oauth2/introspect` - Token introspection
- `/admin/oauth2/auth/requests/login` - Login flow management
- `/admin/oauth2/auth/requests/consent` - Consent flow management

## Examples

See the `examples/` directory for complete examples:
- `agent_config_hydra.json` - Agent configuration with Hydra
- `.env.hydra.example` - Environment variable template
- `agno_simple_example.py` - Simple agent with authentication

## Support

For issues or questions:
- GitHub Issues: https://github.com/GetBindu/Bindu/issues
- Documentation: https://docs.getbindu.com
