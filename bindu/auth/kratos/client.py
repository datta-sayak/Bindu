"""Ory Kratos client for user identity and session management."""

from __future__ import annotations

from typing import Optional

from bindu.settings import app_settings
from bindu.utils.http_client import AsyncHTTPClient
from bindu.utils.logging import get_logger

logger = get_logger("bindu.auth.kratos.client")


class KratosClient:
    """Client for interacting with Ory Kratos API.
    
    Handles user session verification and identity management.
    """

    def __init__(
        self,
        admin_url: str,
        public_url: str,
        timeout: int = 10,
        verify_ssl: bool = True,
    ):
        """Initialize Kratos client.

        Args:
            admin_url: Kratos Admin API URL (e.g., https://kratos-admin.getbindu.com)
            public_url: Kratos Public API URL (e.g., https://kratos.getbindu.com)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.admin_url = admin_url.rstrip("/")
        self.public_url = public_url.rstrip("/")
        
        self._admin_client = AsyncHTTPClient(
            base_url=self.admin_url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            default_headers={"Accept": "application/json"},
        )
        
        self._public_client = AsyncHTTPClient(
            base_url=self.public_url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            default_headers={"Accept": "application/json"},
        )
        
        logger.debug(f"Kratos client initialized: admin={admin_url}, public={public_url}")

    async def __aenter__(self) -> "KratosClient":
        """Async context manager entry."""
        await self._admin_client._ensure_session()
        await self._public_client._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close HTTP client sessions."""
        await self._admin_client.close()
        await self._public_client.close()

    async def verify_session(self, session_token: str) -> Optional[dict]:
        """Verify Kratos session token and get user identity.

        Args:
            session_token: Kratos session token (from Cookie or X-Session-Token header)

        Returns:
            Session data with identity information, or None if invalid

        Example:
            session = await kratos.verify_session(session_token)
            if session:
                user_id = session["identity"]["id"]
                email = session["identity"]["traits"]["email"]
        """
        try:
            response = await self._public_client.get(
                "/sessions/whoami",
                headers={"X-Session-Token": session_token},
            )

            if response.status == 200:
                session_data = await response.json()
                logger.debug(f"Session verified for user: {session_data['identity']['id']}")
                return session_data
            elif response.status == 401:
                logger.debug("Invalid or expired session token")
                return None
            else:
                error_text = await response.text()
                logger.error(f"Session verification failed: {response.status} - {error_text}")
                return None

        except Exception as e:
            logger.error(f"Error verifying session: {e}")
            return None

    async def get_identity(self, identity_id: str) -> Optional[dict]:
        """Get user identity by ID (Admin API).

        Args:
            identity_id: Kratos identity ID

        Returns:
            Identity data or None if not found

        Example:
            identity = await kratos.get_identity("user-123")
            if identity:
                email = identity["traits"]["email"]
        """
        try:
            response = await self._admin_client.get(f"/admin/identities/{identity_id}")

            if response.status == 200:
                identity_data = await response.json()
                logger.debug(f"Retrieved identity: {identity_id}")
                return identity_data
            elif response.status == 404:
                logger.debug(f"Identity not found: {identity_id}")
                return None
            else:
                error_text = await response.text()
                logger.error(f"Failed to get identity: {response.status} - {error_text}")
                return None

        except Exception as e:
            logger.error(f"Error getting identity: {e}")
            return None

    async def health_check(self) -> bool:
        """Check if Kratos is healthy.

        Returns:
            True if healthy, False otherwise
        """
        try:
            response = await self._public_client.get("/health/ready")
            return response.status == 200
        except Exception:
            return False
