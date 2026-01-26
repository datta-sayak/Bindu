"""Integration tests for hybrid OAuth2 + DID authentication."""

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from bindu.server.middleware.auth.hydra import HydraMiddleware
from bindu.utils.did_signature import sign_request


@pytest.fixture
def mock_did_extension():
    """Create a mock DID extension."""
    mock_ext = MagicMock()
    mock_ext.did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    mock_ext.public_key_multibase = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    mock_ext.sign_message.return_value = "mock_signature_abc123"
    return mock_ext


@pytest.fixture
def mock_hydra_config():
    """Create mock Hydra configuration."""
    config = MagicMock()
    config.admin_url = "https://hydra-admin.example.com"
    config.public_url = "https://hydra.example.com"
    config.timeout = 10
    config.verify_ssl = True
    config.public_endpoints = ["/docs", "/.well-known/*"]
    return config


@pytest.fixture
def mock_request():
    """Create a mock Starlette request."""
    request = MagicMock(spec=Request)
    request.url.path = "/api/test"
    request.headers = {}
    request.body = AsyncMock(return_value=b'{"test": "data"}')
    request.state = MagicMock()
    return request


class TestHybridAuthenticationFlow:
    """Test complete hybrid authentication flow."""

    @pytest.mark.asyncio
    async def test_successful_hybrid_authentication(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test successful authentication with both token and DID signature."""
        # Setup
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)
        
        # Mock token validation
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read agent:write",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }
        
        with patch.object(middleware, "_validate_token", return_value=token_payload):
            with patch.object(
                middleware.hydra_client,
                "get_oauth_client",
                return_value={
                    "client_id": mock_did_extension.did,
                    "metadata": {
                        "public_key": mock_did_extension.public_key_multibase,
                        "hybrid_auth": True,
                    },
                },
            ):
                # Create signed request
                body = {"test": "data"}
                signature_headers = sign_request(
                    body, mock_did_extension.did, mock_did_extension
                )
                
                mock_request.headers = {
                    "Authorization": "Bearer test_token",
                    **signature_headers,
                }
                
                # Mock signature verification to return True
                with patch(
                    "bindu.utils.did_signature.DIDExtension.verify_signature_with_public_key",
                    return_value=True,
                ):
                    # Execute
                    call_next = AsyncMock(return_value=JSONResponse({"success": True}))
                    response = await middleware.dispatch(mock_request, call_next)
                    
                    # Verify
                    assert response.status_code == 200
                    assert mock_request.state.authenticated is True
                    assert mock_request.state.user["client_id"] == mock_did_extension.did
                    assert "signature_info" in mock_request.state.user
                    assert mock_request.state.user["signature_info"]["did_verified"] is True

    @pytest.mark.asyncio
    async def test_authentication_with_invalid_signature(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test that invalid DID signature is rejected."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)
        
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }
        
        with patch.object(middleware, "_validate_token", return_value=token_payload):
            with patch.object(
                middleware.hydra_client,
                "get_oauth_client",
                return_value={
                    "client_id": mock_did_extension.did,
                    "metadata": {
                        "public_key": mock_did_extension.public_key_multibase,
                    },
                },
            ):
                # Create request with invalid signature
                signature_headers = sign_request(
                    {"test": "data"}, mock_did_extension.did, mock_did_extension
                )
                
                mock_request.headers = {
                    "Authorization": "Bearer test_token",
                    **signature_headers,
                }
                
                # Mock signature verification to return False
                with patch(
                    "bindu.utils.did_signature.DIDExtension.verify_signature_with_public_key",
                    return_value=False,
                ):
                    call_next = AsyncMock()
                    response = await middleware.dispatch(mock_request, call_next)
                    
                    # Verify rejection
                    assert response.status_code == 403
                    call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_authentication_without_signature_backward_compatible(
        self, mock_hydra_config, mock_request
    ):
        """Test that requests without DID signature still work (backward compatibility)."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)
        
        # Non-DID client
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": "agent-legacy-client",
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }
        
        with patch.object(middleware, "_validate_token", return_value=token_payload):
            mock_request.headers = {
                "Authorization": "Bearer test_token",
            }
            
            call_next = AsyncMock(return_value=JSONResponse({"success": True}))
            response = await middleware.dispatch(mock_request, call_next)
            
            # Should succeed without DID verification
            assert response.status_code == 200
            assert mock_request.state.authenticated is True

    @pytest.mark.asyncio
    async def test_authentication_with_expired_timestamp(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test that expired timestamps are rejected."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)
        
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }
        
        with patch.object(middleware, "_validate_token", return_value=token_payload):
            with patch.object(
                middleware.hydra_client,
                "get_oauth_client",
                return_value={
                    "client_id": mock_did_extension.did,
                    "metadata": {
                        "public_key": mock_did_extension.public_key_multibase,
                    },
                },
            ):
                # Create request with old timestamp
                old_timestamp = int(time.time()) - 600  # 10 minutes ago
                signature_headers = sign_request(
                    {"test": "data"},
                    mock_did_extension.did,
                    mock_did_extension,
                    timestamp=old_timestamp,
                )
                
                mock_request.headers = {
                    "Authorization": "Bearer test_token",
                    **signature_headers,
                }
                
                call_next = AsyncMock()
                response = await middleware.dispatch(mock_request, call_next)
                
                # Should be rejected due to expired timestamp
                assert response.status_code == 403
                call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_authentication_with_did_mismatch(
        self, mock_hydra_config, mock_request, mock_did_extension
    ):
        """Test that DID mismatch between token and header is rejected."""
        middleware = HydraMiddleware(app=MagicMock(), auth_config=mock_hydra_config)
        
        token_payload = {
            "active": True,
            "sub": "test-user",
            "client_id": mock_did_extension.did,
            "scope": "agent:read",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "token_type": "access_token",
            "grant_type": "client_credentials",
        }
        
        with patch.object(middleware, "_validate_token", return_value=token_payload):
            # Create request with different DID in header
            different_did = "did:key:z6MkDifferentDID"
            signature_headers = sign_request(
                {"test": "data"}, different_did, mock_did_extension
            )
            
            mock_request.headers = {
                "Authorization": "Bearer test_token",
                **signature_headers,
            }
            
            call_next = AsyncMock()
            response = await middleware.dispatch(mock_request, call_next)
            
            # Should be rejected due to DID mismatch
            assert response.status_code == 403
            call_next.assert_not_called()


class TestHybridAuthClient:
    """Test hybrid auth client utilities."""

    @pytest.mark.asyncio
    async def test_hybrid_auth_client_initialization(self, mock_did_extension):
        """Test initializing hybrid auth client."""
        from bindu.utils.hybrid_auth_client import HybridAuthClient
        
        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=MagicMock(
                client_id=mock_did_extension.did,
                client_secret="test_secret",
                scopes=["agent:read", "agent:write"],
            ),
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                return_value={"access_token": "test_token", "expires_in": 3600},
            ):
                client = HybridAuthClient(
                    agent_id="test-agent",
                    credentials_dir=Path("/tmp/.bindu"),
                    did_extension=mock_did_extension,
                )
                
                await client.initialize()
                
                assert client.access_token == "test_token"
                assert client.credentials.client_id == mock_did_extension.did

    @pytest.mark.asyncio
    async def test_hybrid_auth_client_post_request(self, mock_did_extension):
        """Test making POST request with hybrid auth."""
        from bindu.utils.hybrid_auth_client import HybridAuthClient
        
        mock_credentials = MagicMock(
            client_id=mock_did_extension.did,
            client_secret="test_secret",
            scopes=["agent:read"],
        )
        
        with patch(
            "bindu.utils.hybrid_auth_client.load_agent_credentials",
            return_value=mock_credentials,
        ):
            with patch(
                "bindu.utils.hybrid_auth_client.get_client_credentials_token",
                return_value={"access_token": "test_token", "expires_in": 3600},
            ):
                with patch("aiohttp.ClientSession") as mock_session:
                    mock_response = AsyncMock()
                    mock_response.status = 200
                    mock_response.json = AsyncMock(return_value={"result": "success"})
                    
                    mock_session.return_value.__aenter__.return_value.post.return_value.__aenter__.return_value = (
                        mock_response
                    )
                    
                    client = HybridAuthClient(
                        agent_id="test-agent",
                        credentials_dir=Path("/tmp/.bindu"),
                        did_extension=mock_did_extension,
                    )
                    
                    await client.initialize()
                    
                    result = await client.post(
                        "http://localhost:3773/",
                        {"jsonrpc": "2.0", "method": "test", "id": 1},
                    )
                    
                    assert result == {"result": "success"}


class TestAgentRegistrationWithDID:
    """Test agent registration with DID-based client ID."""

    @pytest.mark.asyncio
    async def test_register_agent_with_did_extension(self, mock_did_extension):
        """Test registering agent with DID extension."""
        from bindu.auth.hydra_registration import register_agent_in_hydra
        
        with patch("bindu.auth.hydra_registration.app_settings") as mock_settings:
            mock_settings.hydra.auto_register_agents = True
            mock_settings.hydra.admin_url = "https://hydra-admin.example.com"
            mock_settings.hydra.public_url = "https://hydra.example.com"
            mock_settings.hydra.timeout = 10
            mock_settings.hydra.verify_ssl = True
            mock_settings.hydra.max_retries = 3
            mock_settings.hydra.default_grant_types = ["client_credentials"]
            mock_settings.hydra.default_agent_scopes = ["agent:read", "agent:write"]
            
            with patch(
                "bindu.auth.hydra_registration.load_agent_credentials", return_value=None
            ):
                with patch("bindu.auth.hydra_registration.HydraClient") as mock_hydra:
                    mock_hydra_instance = AsyncMock()
                    mock_hydra_instance.get_oauth_client.return_value = None
                    mock_hydra_instance.create_oauth_client.return_value = {
                        "client_id": mock_did_extension.did,
                        "client_name": "Test Agent",
                    }
                    mock_hydra.return_value.__aenter__.return_value = mock_hydra_instance
                    
                    with patch(
                        "bindu.auth.hydra_registration.save_agent_credentials"
                    ) as mock_save:
                        credentials = await register_agent_in_hydra(
                            agent_id="test-agent",
                            agent_name="Test Agent",
                            agent_url="http://localhost:3773",
                            did=mock_did_extension.did,
                            credentials_dir=Path("/tmp/.bindu"),
                            did_extension=mock_did_extension,
                        )
                        
                        # Verify client was created with DID as client_id
                        create_call = mock_hydra_instance.create_oauth_client.call_args
                        client_data = create_call[0][0]
                        
                        assert client_data["client_id"] == mock_did_extension.did
                        assert client_data["metadata"]["did"] == mock_did_extension.did
                        assert (
                            client_data["metadata"]["public_key"]
                            == mock_did_extension.public_key_multibase
                        )
                        assert client_data["metadata"]["hybrid_auth"] is True
                        
                        # Verify credentials were saved
                        mock_save.assert_called_once()
