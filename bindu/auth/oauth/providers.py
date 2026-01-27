"""OAuth provider configurations (v0 - hardcoded providers)."""

from __future__ import annotations

from typing import Optional

from bindu.settings import app_settings

# Hardcoded OAuth providers for v0
# In v1, these can be moved to database for dynamic configuration
OAUTH_PROVIDERS = {
    "notion": {
        "name": "Notion",
        "auth_url": "https://api.notion.com/v1/oauth/authorize",
        "token_url": "https://api.notion.com/v1/oauth/token",
        "scope": "",  # Notion doesn't use scope parameter
        "response_type": "code",
    },
    "gmail": {
        "name": "Gmail",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scope": "https://www.googleapis.com/auth/gmail.send",
        "response_type": "code",
    },
    "github": {
        "name": "GitHub",
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scope": "repo user",
        "response_type": "code",
    },
}


def get_provider_config(provider: str) -> Optional[dict]:
    """Get OAuth provider configuration with credentials from settings.

    Args:
        provider: Provider name (notion, gmail, github)

    Returns:
        Provider config dict with client_id and client_secret, or None if not found

    Example:
        config = get_provider_config("notion")
        if config:
            client_id = config["client_id"]
    """
    if provider not in OAUTH_PROVIDERS:
        return None

    base_config = OAUTH_PROVIDERS[provider].copy()

    # Add client credentials from settings
    if provider == "notion":
        base_config["client_id"] = app_settings.oauth.notion_client_id
        base_config["client_secret"] = app_settings.oauth.notion_client_secret
    elif provider == "gmail":
        base_config["client_id"] = app_settings.oauth.google_client_id
        base_config["client_secret"] = app_settings.oauth.google_client_secret
    elif provider == "github":
        base_config["client_id"] = app_settings.oauth.github_client_id
        base_config["client_secret"] = app_settings.oauth.github_client_secret

    # Validate credentials are configured
    if not base_config.get("client_id") or not base_config.get("client_secret"):
        return None

    return base_config


def is_provider_configured(provider: str) -> bool:
    """Check if OAuth provider is configured with credentials.

    Args:
        provider: Provider name

    Returns:
        True if provider has client_id and client_secret configured
    """
    config = get_provider_config(provider)
    return config is not None
