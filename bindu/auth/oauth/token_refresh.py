"""OAuth token refresh utility (v0)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from bindu.auth.oauth.providers import get_provider_config
from bindu.auth.vault.oauth_storage import OAuthVaultStorage
from bindu.settings import app_settings
from bindu.utils.http_client import http_client
from bindu.utils.logging import get_logger

logger = get_logger("bindu.auth.oauth.token_refresh")


async def get_valid_token(user_id: str, provider: str) -> str:
    """Get valid access token for user, refresh if expired.

    Args:
        user_id: User identifier
        provider: OAuth provider name

    Returns:
        Valid access token

    Raises:
        ValueError: If no tokens found or refresh fails

    Example:
        token = await get_valid_token("user-123", "notion")
        # Use token to call Notion API
    """
    # Get tokens from Vault
    vault_storage = OAuthVaultStorage(
        vault_url=app_settings.vault.url,
        vault_token=app_settings.vault.token,
    )

    tokens = vault_storage.get_tokens(user_id, provider)
    if not tokens:
        raise ValueError(f"No OAuth tokens found for user={user_id}, provider={provider}")

    # Check if token is still valid (with 5-minute buffer)
    expires_at = datetime.fromisoformat(tokens["expires_at"])
    if expires_at > datetime.now() + timedelta(minutes=5):
        logger.debug(f"Using cached token for user={user_id}, provider={provider}")
        return tokens["access_token"]

    # Token expired or expiring soon, refresh it
    logger.info(f"Refreshing expired token for user={user_id}, provider={provider}")
    new_token = await refresh_token(user_id, provider, tokens)
    return new_token


async def refresh_token(user_id: str, provider: str, current_tokens: Optional[dict] = None) -> str:
    """Refresh OAuth access token.

    Args:
        user_id: User identifier
        provider: OAuth provider name
        current_tokens: Current token data (optional, will fetch from Vault if not provided)

    Returns:
        New access token

    Raises:
        ValueError: If refresh fails

    Example:
        new_token = await refresh_token("user-123", "notion")
    """
    # Get current tokens if not provided
    if not current_tokens:
        vault_storage = OAuthVaultStorage(
            vault_url=app_settings.vault.url,
            vault_token=app_settings.vault.token,
        )
        current_tokens = vault_storage.get_tokens(user_id, provider)
        if not current_tokens:
            raise ValueError(f"No tokens found for user={user_id}, provider={provider}")

    # Check if we have a refresh token
    if not current_tokens.get("refresh_token"):
        raise ValueError(f"No refresh token available for user={user_id}, provider={provider}")

    # Get provider config
    config = get_provider_config(provider)
    if not config:
        raise ValueError(f"Provider {provider} not configured")

    # Request new tokens
    try:
        async with http_client(base_url=config["token_url"]) as client:
            # Parse token URL to get just the path
            from urllib.parse import urlparse
            parsed = urlparse(config["token_url"])
            path = parsed.path or "/"

            response = await client.post(
                path,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": current_tokens["refresh_token"],
                    "client_id": config["client_id"],
                    "client_secret": config["client_secret"],
                },
                headers={"Accept": "application/json"},
            )

            if response.status != 200:
                error_text = await response.text()
                logger.error(f"Token refresh failed: {response.status} - {error_text}")
                raise ValueError(f"Token refresh failed: {error_text}")

            new_tokens = await response.json()

    except Exception as e:
        logger.error(f"Failed to refresh token for user={user_id}, provider={provider}: {e}")
        raise ValueError(f"Token refresh failed: {str(e)}")

    # Update tokens in Vault
    vault_storage = OAuthVaultStorage(
        vault_url=app_settings.vault.url,
        vault_token=app_settings.vault.token,
    )

    updated_tokens = {
        "access_token": new_tokens["access_token"],
        "refresh_token": new_tokens.get("refresh_token", current_tokens["refresh_token"]),
        "expires_at": (
            datetime.now() + timedelta(seconds=new_tokens.get("expires_in", 3600))
        ).isoformat(),
        "scope": current_tokens.get("scope", ""),
    }

    vault_storage.save_tokens(user_id, provider, updated_tokens)

    logger.info(f"Successfully refreshed token for user={user_id}, provider={provider}")
    return updated_tokens["access_token"]
