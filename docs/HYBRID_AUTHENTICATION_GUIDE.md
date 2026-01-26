# Hybrid OAuth2 + DID Authentication Guide

## Quick Reference

### What is Hybrid Authentication?

Bindu's hybrid authentication combines two security layers:

1. **OAuth2 Tokens** (Layer 1) - Authorization: "What can you do?"
2. **DID Signatures** (Layer 2) - Authentication: "Who are you?"

### Why Use It?

| Security Feature | OAuth2 Only | Hybrid (OAuth2 + DID) |
|-----------------|-------------|----------------------|
| Token theft protection | ❌ | ✅ |
| Replay attack prevention | ⚠️ | ✅ |
| Request tampering detection | ❌ | ✅ |
| Cryptographic identity proof | ❌ | ✅ |
| No shared secrets | ❌ | ✅ |

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                    Request Flow                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Client gets OAuth token from Hydra                      │
│     ↓                                                        │
│  2. Client signs request with DID private key               │
│     ↓                                                        │
│  3. Client sends request with:                              │
│     • Authorization: Bearer <token>                         │
│     • X-DID: <client_did>                                   │
│     • X-DID-Signature: <signature>                          │
│     • X-DID-Timestamp: <timestamp>                          │
│     ↓                                                        │
│  4. Server validates OAuth token (Layer 1)                  │
│     ↓                                                        │
│  5. Server verifies DID signature (Layer 2)                 │
│     ↓                                                        │
│  6. Both layers valid → Request processed                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Enable Hybrid Authentication

```bash
# .env
AUTH__ENABLED=true
AUTH__PROVIDER=hydra
HYDRA__ENABLED=true
HYDRA__ADMIN_URL=https://hydra-admin.getbindu.com
HYDRA__PUBLIC_URL=https://hydra.getbindu.com
HYDRA__AUTO_REGISTER_AGENTS=true
```

### 2. Agent Configuration

```json
{
  "name": "my-agent",
  "auth": {
    "enabled": true,
    "provider": "hydra"
  }
}
```

### 3. Run Your Agent

```python
from bindu.penguin import bindufy

def handler(messages):
    return "Hello!"

manifest = bindufy(config, handler)
```

**What happens automatically:**
- ✅ Agent generates DID and keypair
- ✅ Agent registers with Hydra using DID as client_id
- ✅ Public key stored in Hydra metadata
- ✅ OAuth credentials saved to `.bindu/oauth_credentials.json`
- ✅ Middleware enabled for dual-layer verification

### 4. Make Authenticated Requests

```python
from bindu.utils.hybrid_auth_client import HybridAuthClient
from bindu.extensions.did import DIDExtension
from pathlib import Path

# Initialize
did_ext = DIDExtension(pki_dir=Path(".bindu/pki"))
client = HybridAuthClient("my-agent", Path(".bindu"), did_ext)
await client.initialize()

# Make request (automatically includes OAuth token + DID signature)
response = await client.post(
    "http://agent-b:3773/",
    {"jsonrpc": "2.0", "method": "message/send", "params": {...}, "id": 1}
)
```

## Security Guarantees

### 1. Token Theft Protection

**Scenario:** Attacker steals OAuth token

```
Without DID Signature:
❌ Attacker → Uses stolen token → Request succeeds → System compromised

With DID Signature:
✅ Attacker → Uses stolen token → Cannot sign request → Request rejected
```

**Why:** DID signature requires the private key, which never leaves the agent.

### 2. Replay Attack Prevention

**Scenario:** Attacker captures and replays valid request

```
Without Timestamp:
❌ Attacker → Captures request → Replays later → Request succeeds

With Timestamp:
✅ Attacker → Captures request → Replays 10 min later → Rejected (expired)
```

**Why:** Timestamps are validated (default: 5 minute tolerance).

### 3. Request Tampering Detection

**Scenario:** Attacker modifies request in transit

```
Without Signature:
❌ Attacker → Intercepts → Modifies body → Modified request succeeds

With Signature:
✅ Attacker → Intercepts → Modifies body → Signature invalid → Rejected
```

**Why:** Signature is computed over the exact request body.

## API Reference

### HybridAuthClient

```python
from bindu.utils.hybrid_auth_client import HybridAuthClient

client = HybridAuthClient(
    agent_id="my-agent",           # Your agent ID
    credentials_dir=Path(".bindu"), # OAuth credentials location
    did_extension=did_ext           # DID extension instance
)

await client.initialize()          # Load credentials, get token

# POST request
response = await client.post(url, data, headers)

# GET request
response = await client.get(url, headers)
```

### Manual Request Signing

```python
from bindu.utils.did_signature import create_signed_request_headers

headers = create_signed_request_headers(
    body=request_body,              # Request body (dict, str, or bytes)
    did=did_extension.did,          # Your DID
    did_extension=did_extension,    # DID extension for signing
    bearer_token=access_token       # OAuth token
)

# Returns:
# {
#     "Authorization": "Bearer <token>",
#     "Content-Type": "application/json",
#     "X-DID": "<did>",
#     "X-DID-Signature": "<signature>",
#     "X-DID-Timestamp": "<timestamp>"
# }
```

### Signature Verification

```python
from bindu.utils.did_signature import verify_signature

is_valid = verify_signature(
    body=request_body,
    signature=signature,
    did=client_did,
    timestamp=timestamp,
    public_key=public_key,
    max_age_seconds=300  # 5 minutes
)
```

## Configuration Options

### Timestamp Tolerance

Adjust replay attack prevention window:

```python
# Default: 300 seconds (5 minutes)
# High security: 60 seconds (1 minute)
# Testing: 600 seconds (10 minutes)

is_valid = verify_signature(
    ...,
    max_age_seconds=60  # Stricter for production
)
```

### Backward Compatibility

Hybrid authentication is fully backward compatible:

```python
# Old clients (OAuth only) - Still work
headers = {"Authorization": "Bearer token"}

# New clients (OAuth + DID) - Enhanced security
headers = {
    "Authorization": "Bearer token",
    "X-DID": "did:key:...",
    "X-DID-Signature": "...",
    "X-DID-Timestamp": "..."
}
```

**Enforcement rules:**
- DID signature required ONLY if:
  - Client ID starts with `did:`
  - Client has `public_key` in metadata
  - Request includes DID signature headers

## Best Practices

### 1. Protect Private Keys

```bash
# Ensure restrictive permissions
chmod 700 .bindu/pki/
chmod 600 .bindu/pki/*

# Never commit to git
echo ".bindu/pki/" >> .gitignore
echo ".bindu/oauth_credentials.json" >> .gitignore
```

### 2. Use Short Timestamp Tolerance in Production

```python
# Production: 60-120 seconds
max_age_seconds = 60

# Development: 300 seconds (default)
max_age_seconds = 300
```

### 3. Monitor Authentication Status

```python
def check_auth(request):
    user = request.state.user
    sig_info = user.get("signature_info", {})
    
    if sig_info.get("did_verified"):
        logger.info("✅ Full hybrid auth (OAuth + DID)")
    else:
        logger.warning("⚠️ OAuth only (no DID signature)")
```

### 4. Rotate OAuth Secrets Regularly

```bash
# Delete old client
curl -X DELETE http://localhost:3773/admin/oauth/clients/did:key:...

# Agent will auto-register on restart
# DID and private key remain the same
```

## Troubleshooting

### "Invalid DID signature" Error

**Check 1:** DID matches token
```python
# X-DID header must equal client_id from token
assert headers["X-DID"] == token_payload["client_id"]
```

**Check 2:** Timestamp is recent
```python
import time
age = abs(time.time() - int(headers["X-DID-Timestamp"]))
assert age < 300  # Within 5 minutes
```

**Check 3:** Public key is registered
```bash
curl http://localhost:3773/admin/oauth/clients/did:key:...
# Should have "public_key" in metadata
```

**Check 4:** Body not modified after signing
```python
# Sign first, then send - don't modify body in between
headers = sign_request(body, did, did_ext)
response = requests.post(url, headers=headers, json=body)
```

### "No public key found" Warning

Agent registered before hybrid auth was enabled:

```bash
# Delete old registration
curl -X DELETE http://localhost:3773/admin/oauth/clients/agent-xyz

# Restart agent - will re-register with public key
```

## Examples

See `examples/hybrid_auth_example.py` for complete working examples:

1. Using HybridAuthClient
2. Agent-to-agent communication
3. Manual request signing
4. Security properties demonstration
5. Monitoring authentication status

## Further Reading

- [Full Hydra Authentication Guide](./HYDRA_AUTHENTICATION.md)
- [W3C DID Specification](https://www.w3.org/TR/did-core/)
- [Ory Hydra Documentation](https://www.ory.sh/docs/hydra/)
