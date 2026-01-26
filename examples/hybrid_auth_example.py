"""Example: Using Hybrid OAuth2 + DID Authentication in Bindu.

This example demonstrates how to use the hybrid authentication approach
combining OAuth2 tokens with DID-based cryptographic signatures.
"""

import asyncio
from pathlib import Path

from bindu.extensions.did import DIDExtension
from bindu.utils.hybrid_auth_client import (
    HybridAuthClient,
    call_agent_with_hybrid_auth,
)


async def example_1_using_hybrid_auth_client():
    """Example 1: Using HybridAuthClient for authenticated requests."""
    print("\n=== Example 1: HybridAuthClient ===\n")

    # Initialize DID extension
    did_extension = DIDExtension(pki_dir=Path(".bindu/pki"))
    print(f"Agent DID: {did_extension.did}")

    # Create hybrid auth client
    client = HybridAuthClient(
        agent_id="my-agent",
        credentials_dir=Path(".bindu"),
        did_extension=did_extension,
    )

    # Initialize (loads credentials and gets token)
    await client.initialize()
    print(f"✅ Authenticated with client_id: {client.credentials.client_id}")

    # Make authenticated request with both OAuth token and DID signature
    response = await client.post(
        url="http://localhost:3774/",
        data={
            "jsonrpc": "2.0",
            "method": "message/send",
            "params": {
                "messages": [
                    {"role": "user", "content": "Hello from hybrid auth!"}
                ]
            },
            "id": 1,
        },
    )

    print(f"Response: {response}")


async def example_2_agent_to_agent_communication():
    """Example 2: Agent-to-agent communication with hybrid auth."""
    print("\n=== Example 2: Agent-to-Agent Communication ===\n")

    # Initialize DID extension for Agent A
    did_extension = DIDExtension(pki_dir=Path(".bindu/pki"))

    # Agent A calls Agent B with hybrid authentication
    response = await call_agent_with_hybrid_auth(
        from_agent_id="agent-a",
        from_credentials_dir=Path(".bindu"),
        from_did_extension=did_extension,
        to_agent_url="http://localhost:3774/",
        messages=[
            {"role": "user", "content": "Hello Agent B, this is Agent A"}
        ],
    )

    print(f"Agent B Response: {response}")


async def example_3_manual_request_signing():
    """Example 3: Manual request signing for custom scenarios."""
    print("\n=== Example 3: Manual Request Signing ===\n")

    import json

    import aiohttp

    from bindu.utils.did_signature import create_signed_request_headers
    from bindu.utils.token_utils import get_client_credentials_token

    # Initialize DID extension
    did_extension = DIDExtension(pki_dir=Path(".bindu/pki"))

    # Get OAuth token
    token_response = await get_client_credentials_token(
        client_id=did_extension.did,
        client_secret="your-client-secret",  # Load from credentials file
        scope="agent:read agent:write",
    )

    print(f"✅ Got OAuth token: {token_response['access_token'][:20]}...")

    # Prepare request body
    request_body = {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {"messages": [{"role": "user", "content": "Custom request"}]},
        "id": 1,
    }

    # Create signed headers (includes OAuth token + DID signature)
    headers = create_signed_request_headers(
        body=request_body,
        did=did_extension.did,
        did_extension=did_extension,
        bearer_token=token_response["access_token"],
    )

    print(f"✅ Request signed with DID: {did_extension.did[:30]}...")
    print(f"Headers: {list(headers.keys())}")

    # Make request
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://localhost:3774/", headers=headers, json=request_body
        ) as response:
            result = await response.json()
            print(f"Response: {result}")


async def example_4_verify_security_properties():
    """Example 4: Demonstrating security properties of hybrid auth."""
    print("\n=== Example 4: Security Properties Demo ===\n")

    import time

    from bindu.utils.did_signature import sign_request, verify_signature

    # Initialize DID extension
    did_extension = DIDExtension(pki_dir=Path(".bindu/pki"))

    # Create a signed request
    body = {"test": "data", "timestamp": int(time.time())}
    signature_headers = sign_request(body, did_extension.did, did_extension)

    print("✅ Request signed successfully")
    print(f"   DID: {signature_headers['X-DID'][:40]}...")
    print(f"   Signature: {signature_headers['X-DID-Signature'][:40]}...")
    print(f"   Timestamp: {signature_headers['X-DID-Timestamp']}")

    # Verify the signature
    is_valid = verify_signature(
        body=body,
        signature=signature_headers["X-DID-Signature"],
        did=signature_headers["X-DID"],
        timestamp=int(signature_headers["X-DID-Timestamp"]),
        public_key=did_extension.public_key_multibase,
        max_age_seconds=300,
    )

    print(f"\n✅ Signature verification: {'VALID' if is_valid else 'INVALID'}")

    # Demonstrate tampering detection
    print("\n--- Tampering Detection Demo ---")
    tampered_body = {"test": "modified_data", "timestamp": int(time.time())}

    is_valid_tampered = verify_signature(
        body=tampered_body,  # Different body
        signature=signature_headers["X-DID-Signature"],
        did=signature_headers["X-DID"],
        timestamp=int(signature_headers["X-DID-Timestamp"]),
        public_key=did_extension.public_key_multibase,
        max_age_seconds=300,
    )

    print(
        f"❌ Tampered request verification: {'VALID' if is_valid_tampered else 'INVALID'}"
    )
    print("   (As expected - tampering detected!)")

    # Demonstrate replay attack prevention
    print("\n--- Replay Attack Prevention Demo ---")
    old_timestamp = int(time.time()) - 600  # 10 minutes ago

    is_valid_old = verify_signature(
        body=body,
        signature=signature_headers["X-DID-Signature"],
        did=signature_headers["X-DID"],
        timestamp=old_timestamp,  # Old timestamp
        public_key=did_extension.public_key_multibase,
        max_age_seconds=300,  # 5 minute tolerance
    )

    print(
        f"❌ Old request verification: {'VALID' if is_valid_old else 'INVALID'}"
    )
    print("   (As expected - replay attack prevented!)")


async def example_5_monitoring_authentication():
    """Example 5: Monitoring authentication status in your agent."""
    print("\n=== Example 5: Monitoring Authentication ===\n")

    from starlette.requests import Request

    # In your agent's middleware or handler
    def check_authentication_status(request: Request):
        """Check authentication status of incoming request."""
        if not hasattr(request.state, "user"):
            print("❌ Request not authenticated")
            return

        user_info = request.state.user

        print(f"✅ Request authenticated")
        print(f"   Client ID: {user_info.get('client_id', 'N/A')}")
        print(f"   Scopes: {user_info.get('scope', [])}")
        print(f"   M2M: {user_info.get('is_m2m', False)}")

        # Check if DID signature was verified
        signature_info = user_info.get("signature_info", {})
        if signature_info.get("did_verified"):
            print(f"   ✅ DID Signature: VERIFIED")
            print(f"   DID: {signature_info.get('did', 'N/A')[:40]}...")
        else:
            reason = signature_info.get("reason", "not_provided")
            print(f"   ⚠️  DID Signature: NOT VERIFIED ({reason})")

    # Example request state
    mock_request = type("Request", (), {"state": type("State", (), {})()})()
    mock_request.state.user = {
        "client_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "scope": ["agent:read", "agent:write"],
        "is_m2m": True,
        "signature_info": {
            "did_verified": True,
            "did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "timestamp": int(time.time()),
        },
    }

    check_authentication_status(mock_request)


async def main():
    """Run all examples."""
    print("=" * 60)
    print("Hybrid OAuth2 + DID Authentication Examples")
    print("=" * 60)

    try:
        # Example 1: Using HybridAuthClient
        # await example_1_using_hybrid_auth_client()

        # Example 2: Agent-to-agent communication
        # await example_2_agent_to_agent_communication()

        # Example 3: Manual request signing
        # await example_3_manual_request_signing()

        # Example 4: Security properties demonstration
        await example_4_verify_security_properties()

        # Example 5: Monitoring authentication
        await example_5_monitoring_authentication()

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()

    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
