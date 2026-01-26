"""Hydra OAuth client registration utilities for agents.

This module provides utilities to automatically register agents as OAuth clients
in Ory Hydra during the bindufy process.
"""

from __future__ import annotations as _annotations

import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from bindu.auth.hydra_client import HydraClient
from bindu.settings import app_settings
from bindu.utils.logging import get_logger

logger = get_logger("bindu.auth.hydra_registration")


class AgentCredentials:
    """Agent OAuth credentials storage."""

    def __init__(
        self,
        agent_id: str,
        client_id: str,
        client_secret: str,
        created_at: str,
        scopes: list[str],
    ):
        """Initialize agent credentials.

        Args:
            agent_id: Unique agent identifier
            client_id: OAuth client ID
            client_secret: OAuth client secret
            created_at: ISO timestamp of creation
            scopes: List of OAuth scopes
        """
        self.agent_id = agent_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.created_at = created_at
        self.scopes = scopes

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "created_at": self.created_at,
            "scopes": self.scopes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentCredentials":
        """Create from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            client_id=data["client_id"],
            client_secret=data["client_secret"],
            created_at=data["created_at"],
            scopes=data.get("scopes", []),
        )


def save_agent_credentials(
    credentials: AgentCredentials, credentials_dir: Path
) -> None:
    """Save agent OAuth credentials to .bindu directory.

    Args:
        credentials: Agent credentials to save
        credentials_dir: Directory to save credentials (typically .bindu)
    """
    credentials_dir.mkdir(exist_ok=True, parents=True)
    creds_file = credentials_dir / "oauth_credentials.json"

    # Load existing credentials if file exists
    existing_creds = {}
    if creds_file.exists():
        try:
            with open(creds_file, "r") as f:
                existing_creds = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load existing credentials: {e}")

    # Update with new credentials
    existing_creds[credentials.agent_id] = credentials.to_dict()

    # Save to file
    with open(creds_file, "w") as f:
        json.dump(existing_creds, f, indent=2)

    # Set restrictive permissions (owner read/write only)
    creds_file.chmod(0o600)

    logger.info(f"✅ OAuth credentials saved to {creds_file}")
    logger.warning(
        f"⚠️  Keep {creds_file} secure and add to .gitignore!"
    )


def load_agent_credentials(
    agent_id: str, credentials_dir: Path
) -> Optional[AgentCredentials]:
    """Load agent OAuth credentials from .bindu directory.

    Args:
        agent_id: Agent identifier
        credentials_dir: Directory containing credentials

    Returns:
        AgentCredentials if found, None otherwise
    """
    creds_file = credentials_dir / "oauth_credentials.json"

    if not creds_file.exists():
        return None

    try:
        with open(creds_file, "r") as f:
            all_creds = json.load(f)

        if agent_id in all_creds:
            return AgentCredentials.from_dict(all_creds[agent_id])
    except Exception as e:
        logger.error(f"Failed to load credentials for {agent_id}: {e}")

    return None


async def register_agent_in_hydra(
    agent_id: str,
    agent_name: str,
    agent_url: str,
    did: str,
    credentials_dir: Path,
    did_extension=None,
) -> Optional[AgentCredentials]:
    """Register agent as OAuth client in Hydra using DID-based authentication.

    Args:
        agent_id: Unique agent identifier
        agent_name: Human-readable agent name
        agent_url: Agent's deployment URL
        did: Agent's DID
        credentials_dir: Directory to save credentials
        did_extension: DIDExtension instance for public key extraction (optional)

    Returns:
        AgentCredentials if successful, None otherwise
    """
    # Check if auto-registration is enabled
    if not app_settings.hydra.auto_register_agents:
        logger.info("Hydra auto-registration disabled, skipping")
        return None

    # Check if credentials already exist
    existing_creds = load_agent_credentials(agent_id, credentials_dir)
    if existing_creds:
        logger.info(f"OAuth credentials already exist for agent: {agent_id}")
        return existing_creds

    # Use DID as client_id for hybrid authentication
    client_id = did
    client_secret = secrets.token_urlsafe(32)

    # Create OAuth client in Hydra
    try:
        async with HydraClient(
            admin_url=app_settings.hydra.admin_url,
            public_url=app_settings.hydra.public_url,
            timeout=app_settings.hydra.timeout,
            verify_ssl=app_settings.hydra.verify_ssl,
            max_retries=app_settings.hydra.max_retries,
        ) as hydra:
            # Check if client already exists in Hydra
            existing_client = await hydra.get_oauth_client(client_id)
            if existing_client:
                logger.info(f"OAuth client already exists in Hydra: {client_id}")
                # We don't have the secret for existing clients, so we can't return it
                logger.warning(
                    f"Client {client_id} exists but credentials not found locally. "
                    "You may need to delete and recreate the client."
                )
                return None

            # Extract public key from DID extension if available
            public_key = None
            key_type = None
            if did_extension:
                try:
                    public_key = did_extension.public_key_multibase
                    key_type = "Ed25519"
                    logger.info(f"Extracted public key from DID extension for {did}")
                except Exception as e:
                    logger.warning(f"Failed to extract public key from DID extension: {e}")

            # Create new OAuth client with DID metadata
            client_data = {
                "client_id": client_id,  # DID is the client_id
                "client_secret": client_secret,
                "client_name": agent_name,
                "grant_types": app_settings.hydra.default_grant_types,
                "response_types": ["code", "token"],
                "scope": " ".join(app_settings.hydra.default_agent_scopes),
                "token_endpoint_auth_method": "client_secret_basic",
                "metadata": {
                    "agent_id": agent_id,
                    "agent_url": agent_url,
                    "did": did,
                    "public_key": public_key,
                    "key_type": key_type,
                    "verification_method": "Ed25519VerificationKey2020" if key_type else None,
                    "registered_at": datetime.utcnow().isoformat(),
                    "hybrid_auth": True,  # Flag for hybrid OAuth2 + DID authentication
                },
            }

            client = await hydra.create_oauth_client(client_data)
            logger.info(f"✅ Agent registered in Hydra: {client_id}")

            # Create and save credentials
            credentials = AgentCredentials(
                agent_id=agent_id,
                client_id=client_id,
                client_secret=client_secret,
                created_at=datetime.utcnow().isoformat(),
                scopes=app_settings.hydra.default_agent_scopes,
            )

            save_agent_credentials(credentials, credentials_dir)

            return credentials

    except Exception as e:
        logger.error(f"Failed to register agent in Hydra: {e}")
        logger.warning(
            "Agent will start without OAuth credentials. "
            "Authentication may not work correctly."
        )
        return None


async def get_agent_token(credentials: AgentCredentials) -> Optional[str]:
    """Get access token for agent using client credentials flow.

    Args:
        credentials: Agent OAuth credentials

    Returns:
        Access token if successful, None otherwise
    """
    try:
        import aiohttp

        token_url = f"{app_settings.hydra.public_url}/oauth2/token"

        # Prepare basic auth
        import base64

        auth_string = f"{credentials.client_id}:{credentials.client_secret}"
        auth_bytes = auth_string.encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("utf-8")

        headers = {
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "client_credentials",
            "scope": " ".join(credentials.scopes),
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url, headers=headers, data=data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get("access_token")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to get token: {response.status} - {error_text}")
                    return None

    except Exception as e:
        logger.error(f"Failed to get agent token: {e}")
        return None
