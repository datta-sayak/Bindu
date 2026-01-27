"""Vault storage for user OAuth tokens (v0 implementation)."""

from __future__ import annotations

import hvac
from datetime import datetime
from typing import Optional

from bindu.utils.logging import get_logger

logger = get_logger("bindu.auth.vault.oauth_storage")


class OAuthVaultStorage:
    """Vault-based storage for user OAuth tokens.
    
    Stores OAuth tokens at: secret/oauth/users/{user_id}/{provider}
    
    Example:
        storage = OAuthVaultStorage(vault_url="https://vault:8200", vault_token="token")
        storage.save_tokens("user-123", "notion", {
            "access_token": "token...",
            "refresh_token": "refresh...",
            "expires_at": "2026-01-28T12:00:00Z",
            "scope": "read:workspace"
        })
    """

    def __init__(self, vault_url: str, vault_token: str):
        """Initialize Vault storage client.

        Args:
            vault_url: Vault server URL (e.g., https://vault:8200)
            vault_token: Vault authentication token
        """
        self.client = hvac.Client(url=vault_url, token=vault_token)
        
        if not self.client.is_authenticated():
            raise ValueError("Vault authentication failed")
        
        logger.info(f"Vault OAuth storage initialized: {vault_url}")

    def save_tokens(self, user_id: str, provider: str, tokens: dict) -> None:
        """Save OAuth tokens to Vault.

        Args:
            user_id: User identifier (from Hydra token)
            provider: OAuth provider name (notion, gmail, etc.)
            tokens: Token data with access_token, refresh_token, expires_at, scope

        Example:
            storage.save_tokens("user-123", "notion", {
                "access_token": "token...",
                "refresh_token": "refresh...",
                "expires_at": "2026-01-28T12:00:00Z",
                "scope": "read:workspace"
            })
        """
        path = f"oauth/users/{user_id}/{provider}"
        
        data = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "expires_at": tokens["expires_at"],
            "scope": tokens.get("scope", ""),
            "updated_at": datetime.now().isoformat(),
        }
        
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path, secret=data
            )
            logger.info(f"Saved OAuth tokens for user={user_id}, provider={provider}")
        except Exception as e:
            logger.error(f"Failed to save tokens to Vault: {e}")
            raise

    def get_tokens(self, user_id: str, provider: str) -> Optional[dict]:
        """Get OAuth tokens from Vault.

        Args:
            user_id: User identifier
            provider: OAuth provider name

        Returns:
            Token data dict or None if not found

        Example:
            tokens = storage.get_tokens("user-123", "notion")
            if tokens:
                access_token = tokens["access_token"]
        """
        path = f"oauth/users/{user_id}/{provider}"
        
        try:
            response = self.client.secrets.kv.v2.read_secret_version(path=path)
            tokens = response["data"]["data"]
            logger.debug(f"Retrieved OAuth tokens for user={user_id}, provider={provider}")
            return tokens
        except hvac.exceptions.InvalidPath:
            logger.debug(f"No tokens found for user={user_id}, provider={provider}")
            return None
        except Exception as e:
            logger.error(f"Failed to read tokens from Vault: {e}")
            raise

    def list_providers(self, user_id: str) -> list[str]:
        """List connected OAuth providers for user.

        Args:
            user_id: User identifier

        Returns:
            List of provider names (e.g., ["notion", "gmail"])

        Example:
            providers = storage.list_providers("user-123")
            # ["notion", "gmail"]
        """
        path = f"oauth/users/{user_id}"
        
        try:
            response = self.client.secrets.kv.v2.list_secrets(path=path)
            providers = response["data"]["keys"]
            logger.debug(f"User {user_id} has {len(providers)} connected providers")
            return providers
        except hvac.exceptions.InvalidPath:
            logger.debug(f"No providers found for user={user_id}")
            return []
        except Exception as e:
            logger.error(f"Failed to list providers from Vault: {e}")
            raise

    def delete_tokens(self, user_id: str, provider: str) -> bool:
        """Delete OAuth tokens from Vault.

        Args:
            user_id: User identifier
            provider: OAuth provider name

        Returns:
            True if deleted, False if not found

        Example:
            storage.delete_tokens("user-123", "notion")
        """
        path = f"oauth/users/{user_id}/{provider}"
        
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)
            logger.info(f"Deleted OAuth tokens for user={user_id}, provider={provider}")
            return True
        except hvac.exceptions.InvalidPath:
            logger.debug(f"No tokens to delete for user={user_id}, provider={provider}")
            return False
        except Exception as e:
            logger.error(f"Failed to delete tokens from Vault: {e}")
            raise

    def has_provider(self, user_id: str, provider: str) -> bool:
        """Check if user has connected a specific provider.

        Args:
            user_id: User identifier
            provider: OAuth provider name

        Returns:
            True if provider is connected, False otherwise

        Example:
            if storage.has_provider("user-123", "notion"):
                print("User has Notion connected")
        """
        tokens = self.get_tokens(user_id, provider)
        return tokens is not None
