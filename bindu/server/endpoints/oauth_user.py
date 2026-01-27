"""User OAuth connection endpoints (v0)."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from bindu.auth.oauth.providers import OAUTH_PROVIDERS, get_provider_config
from bindu.auth.vault.oauth_storage import OAuthVaultStorage
from bindu.settings import app_settings
from bindu.utils.http_client import http_client
from bindu.utils.logging import get_logger

logger = get_logger("bindu.server.endpoints.oauth_user")

# TODO: Replace with Redis in production
# For v0, using in-memory dict (will be lost on restart)
_oauth_states = {}


async def get_user_from_session(request: Request) -> str:
    """Extract user_id from Kratos session.

    Args:
        request: Starlette request

    Returns:
        User ID from Kratos session

    Raises:
        ValueError: If no session or invalid session

    Note:
        Accepts session token from either:
        - X-Session-Token header
        - Cookie: ory_kratos_session
    """
    # Try X-Session-Token header first
    session_token = request.headers.get("X-Session-Token")
    
    # Fall back to cookie
    if not session_token:
        session_token = request.cookies.get("ory_kratos_session")
    
    if not session_token:
        raise ValueError("No session token provided. Use X-Session-Token header or ory_kratos_session cookie.")

    # Verify session with Kratos
    from bindu.auth.kratos.client import KratosClient

    async with KratosClient(
        admin_url=app_settings.kratos.admin_url,
        public_url=app_settings.kratos.public_url,
        timeout=app_settings.kratos.timeout,
        verify_ssl=app_settings.kratos.verify_ssl,
    ) as kratos:
        session = await kratos.verify_session(session_token)

        if not session:
            raise ValueError("Invalid or expired session")

        # Extract user_id from identity
        user_id = session["identity"]["id"]
        if not user_id:
            raise ValueError("Session missing identity ID")

        return user_id


async def connect_oauth_provider(request: Request) -> RedirectResponse | JSONResponse:
    """Initiate OAuth connection flow.

    GET /oauth/connect/{provider}
    Headers:
        X-Session-Token: {kratos_session_token}
    OR Cookie:
        ory_kratos_session={kratos_session_token}

    Args:
        request: Starlette request with provider in path params

    Returns:
        Redirect to OAuth provider authorization page

    Example:
        GET /oauth/connect/notion
        X-Session-Token: MTYxNjk...
        
        → Redirects to Notion OAuth page
    """
    try:
        provider = request.path_params.get("provider")

        # Validate provider
        if provider not in OAUTH_PROVIDERS:
            return JSONResponse(
                {"error": f"Unknown provider: {provider}. Available: {list(OAUTH_PROVIDERS.keys())}"},
                status_code=400,
            )

        # Get provider config
        config = get_provider_config(provider)
        if not config:
            return JSONResponse(
                {"error": f"Provider {provider} not configured. Set client_id and client_secret in environment."},
                status_code=500,
            )

        # Get user_id from Kratos session
        user_id = await get_user_from_session(request)

        # Generate state token for CSRF protection
        state = secrets.token_urlsafe(32)
        _oauth_states[state] = {
            "user_id": user_id,
            "provider": provider,
            "created_at": datetime.now(),
        }

        # Build OAuth authorization URL
        redirect_uri = f"{app_settings.oauth.callback_base_url}/oauth/callback/{provider}"
        
        params = {
            "client_id": config["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": config["response_type"],
            "state": state,
        }
        
        # Add scope if provider uses it
        if config.get("scope"):
            params["scope"] = config["scope"]

        auth_url = f"{config['auth_url']}?{urlencode(params)}"

        logger.info(f"Initiating OAuth for user={user_id}, provider={provider}")
        return RedirectResponse(auth_url)

    except ValueError as e:
        logger.error(f"OAuth connect error: {e}")
        return JSONResponse({"error": str(e)}, status_code=401)
    except Exception as e:
        logger.error(f"Unexpected error in OAuth connect: {e}")
        return JSONResponse({"error": "Internal server error"}, status_code=500)


async def oauth_callback(request: Request) -> JSONResponse:
    """Handle OAuth callback from provider.

    GET /oauth/callback/{provider}?code={code}&state={state}

    Args:
        request: Starlette request with code and state in query params

    Returns:
        JSON response with success status

    Example:
        GET /oauth/callback/notion?code=abc123&state=xyz789
        
        → Exchanges code for tokens, stores in Vault
        → Returns {"success": true, "provider": "notion"}
    """
    try:
        provider = request.path_params.get("provider")
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        # Validate parameters
        if not code or not state:
            return JSONResponse(
                {"error": "Missing code or state parameter"},
                status_code=400,
            )

        # Verify state token
        state_data = _oauth_states.get(state)
        if not state_data:
            return JSONResponse(
                {"error": "Invalid or expired state token"},
                status_code=400,
            )

        # Remove state token (one-time use)
        del _oauth_states[state]

        # Verify provider matches
        if state_data["provider"] != provider:
            return JSONResponse(
                {"error": "Provider mismatch"},
                status_code=400,
            )

        user_id = state_data["user_id"]

        # Get provider config
        config = get_provider_config(provider)
        if not config:
            return JSONResponse(
                {"error": f"Provider {provider} not configured"},
                status_code=500,
            )

        # Exchange authorization code for tokens
        redirect_uri = f"{app_settings.oauth.callback_base_url}/oauth/callback/{provider}"
        
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
        }

        # Parse token URL
        parsed = urlparse(config["token_url"])
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        async with http_client(base_url=base_url) as client:
            response = await client.post(
                path,
                data=token_data,
                headers={"Accept": "application/json"},
            )

            if response.status != 200:
                error_text = await response.text()
                logger.error(f"Token exchange failed: {response.status} - {error_text}")
                return JSONResponse(
                    {"error": "Failed to exchange code for tokens"},
                    status_code=400,
                )

            tokens = await response.json()

        # Save tokens to Vault
        vault_storage = OAuthVaultStorage(
            vault_url=app_settings.vault.url,
            vault_token=app_settings.vault.token,
        )

        vault_storage.save_tokens(
            user_id=user_id,
            provider=provider,
            tokens={
                "access_token": tokens["access_token"],
                "refresh_token": tokens.get("refresh_token"),
                "expires_at": (
                    datetime.now() + timedelta(seconds=tokens.get("expires_in", 3600))
                ).isoformat(),
                "scope": tokens.get("scope", config.get("scope", "")),
            },
        )

        logger.info(f"Successfully connected {provider} for user={user_id}")

        return JSONResponse({
            "success": True,
            "provider": provider,
            "message": f"{config['name']} connected successfully",
        })

    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return JSONResponse(
            {"error": "Failed to complete OAuth connection"},
            status_code=500,
        )


async def list_oauth_providers(request: Request) -> JSONResponse:
    """List connected OAuth providers for user.

    GET /oauth/providers
    Headers:
        X-Session-Token: {kratos_session_token}
    OR Cookie:
        ory_kratos_session={kratos_session_token}

    Returns:
        JSON response with list of connected providers

    Example:
        GET /oauth/providers
        X-Session-Token: MTYxNjk...
        
        → {"providers": ["notion", "gmail"]}
    """
    try:
        # Get user_id from Kratos session
        user_id = await get_user_from_session(request)

        # Get connected providers from Vault
        vault_storage = OAuthVaultStorage(
            vault_url=app_settings.vault.url,
            vault_token=app_settings.vault.token,
        )

        providers = vault_storage.list_providers(user_id)

        return JSONResponse({"providers": providers})

    except ValueError as e:
        logger.error(f"List providers error: {e}")
        return JSONResponse({"error": str(e)}, status_code=401)
    except Exception as e:
        logger.error(f"Unexpected error listing providers: {e}")
        return JSONResponse({"error": "Internal server error"}, status_code=500)


async def disconnect_oauth_provider(request: Request) -> JSONResponse:
    """Disconnect OAuth provider for user.

    DELETE /oauth/providers/{provider}
    Headers:
        X-Session-Token: {kratos_session_token}
    OR Cookie:
        ory_kratos_session={kratos_session_token}

    Args:
        request: Starlette request with provider in path params

    Returns:
        JSON response with success status

    Example:
        DELETE /oauth/providers/notion
        X-Session-Token: MTYxNjk...
        
        → {"success": true, "provider": "notion"}
    """
    try:
        provider = request.path_params.get("provider")

        # Get user_id from Kratos session
        user_id = await get_user_from_session(request)

        # Delete tokens from Vault
        vault_storage = OAuthVaultStorage(
            vault_url=app_settings.vault.url,
            vault_token=app_settings.vault.token,
        )

        deleted = vault_storage.delete_tokens(user_id, provider)

        if not deleted:
            return JSONResponse(
                {"error": f"Provider {provider} not connected"},
                status_code=404,
            )

        logger.info(f"Disconnected {provider} for user={user_id}")

        return JSONResponse({
            "success": True,
            "provider": provider,
            "message": f"{provider} disconnected successfully",
        })

    except ValueError as e:
        logger.error(f"Disconnect provider error: {e}")
        return JSONResponse({"error": str(e)}, status_code=401)
    except Exception as e:
        logger.error(f"Unexpected error disconnecting provider: {e}")
        return JSONResponse({"error": "Internal server error"}, status_code=500)
