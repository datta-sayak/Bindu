"""Client utilities for making requests with hybrid OAuth2 + DID authentication.

This module provides helper functions for clients to easily make authenticated
requests using both OAuth2 tokens and DID signatures.
"""

from __future__ import annotations as _annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp

from bindu.auth.hydra_registration import load_agent_credentials
from bindu.utils.did_signature import create_signed_request_headers
from bindu.utils.logging import get_logger
from bindu.utils.token_utils import get_client_credentials_token

logger = get_logger("bindu.utils.hybrid_auth_client")


class HybridAuthClient:
    """Client for making authenticated requests with OAuth2 + DID signatures.
    
    This client handles:
    - Getting OAuth2 tokens from Hydra
    - Signing requests with DID private key
    - Making HTTP requests with both authentication layers
    """

    def __init__(
        self,
        agent_id: str,
        credentials_dir: Path,
        did_extension,
    ):
        """Initialize hybrid auth client.

        Args:
            agent_id: Agent identifier
            credentials_dir: Directory containing oauth_credentials.json
            did_extension: DIDExtension instance with private key
        """
        self.agent_id = agent_id
        self.credentials_dir = credentials_dir
        self.did_extension = did_extension
        self.credentials = None
        self.access_token = None

    async def initialize(self):
        """Load credentials and get initial access token."""
        # Load OAuth credentials
        self.credentials = load_agent_credentials(self.agent_id, self.credentials_dir)
        if not self.credentials:
            raise ValueError(f"No credentials found for agent: {self.agent_id}")

        # Get access token
        await self.refresh_token()

    async def refresh_token(self):
        """Get a new access token from Hydra."""
        scope = " ".join(self.credentials.scopes)
        token_response = await get_client_credentials_token(
            self.credentials.client_id,
            self.credentials.client_secret,
            scope,
        )

        if not token_response:
            raise Exception("Failed to get access token")

        self.access_token = token_response["access_token"]
        logger.info(f"Access token obtained for {self.credentials.client_id}")

    async def post(
        self,
        url: str,
        data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make authenticated POST request with hybrid authentication.

        Args:
            url: Target URL
            data: Request body (will be JSON encoded)
            headers: Additional headers (optional)

        Returns:
            Response JSON
        """
        # Ensure we have a token
        if not self.access_token:
            await self.refresh_token()

        # Create signed request headers
        body_str = json.dumps(data)
        auth_headers = create_signed_request_headers(
            body=body_str,
            did=self.credentials.client_id,  # DID is the client_id
            did_extension=self.did_extension,
            bearer_token=self.access_token,
        )

        # Merge with additional headers
        if headers:
            auth_headers.update(headers)

        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, headers=auth_headers, data=body_str
            ) as response:
                if response.status == 401:
                    # Token might be expired, refresh and retry
                    logger.info("Token expired, refreshing...")
                    await self.refresh_token()
                    
                    # Update headers with new token
                    auth_headers = create_signed_request_headers(
                        body=body_str,
                        did=self.credentials.client_id,
                        did_extension=self.did_extension,
                        bearer_token=self.access_token,
                    )
                    if headers:
                        auth_headers.update(headers)
                    
                    # Retry request
                    async with session.post(
                        url, headers=auth_headers, data=body_str
                    ) as retry_response:
                        return await retry_response.json()

                return await response.json()

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Make authenticated GET request.

        Args:
            url: Target URL
            headers: Additional headers (optional)

        Returns:
            Response JSON
        """
        # Ensure we have a token
        if not self.access_token:
            await self.refresh_token()

        # For GET requests, we still sign an empty body
        auth_headers = create_signed_request_headers(
            body="",
            did=self.credentials.client_id,
            did_extension=self.did_extension,
            bearer_token=self.access_token,
        )

        # Merge with additional headers
        if headers:
            auth_headers.update(headers)

        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=auth_headers) as response:
                if response.status == 401:
                    # Token might be expired, refresh and retry
                    logger.info("Token expired, refreshing...")
                    await self.refresh_token()
                    
                    auth_headers["Authorization"] = f"Bearer {self.access_token}"
                    
                    async with session.get(url, headers=auth_headers) as retry_response:
                        return await retry_response.json()

                return await response.json()


async def make_authenticated_request(
    agent_id: str,
    credentials_dir: Path,
    did_extension,
    url: str,
    method: str = "POST",
    data: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Make a single authenticated request with hybrid authentication.

    Convenience function for one-off requests.

    Args:
        agent_id: Agent identifier
        credentials_dir: Directory containing oauth_credentials.json
        did_extension: DIDExtension instance
        url: Target URL
        method: HTTP method (POST or GET)
        data: Request body for POST requests
        headers: Additional headers

    Returns:
        Response JSON
    """
    client = HybridAuthClient(agent_id, credentials_dir, did_extension)
    await client.initialize()

    if method.upper() == "POST":
        return await client.post(url, data or {}, headers)
    elif method.upper() == "GET":
        return await client.get(url, headers)
    else:
        raise ValueError(f"Unsupported method: {method}")


async def call_agent_with_hybrid_auth(
    from_agent_id: str,
    from_credentials_dir: Path,
    from_did_extension,
    to_agent_url: str,
    messages: list[dict],
) -> Dict[str, Any]:
    """Call another agent with hybrid authentication.

    Args:
        from_agent_id: Calling agent's ID
        from_credentials_dir: Calling agent's credentials directory
        from_did_extension: Calling agent's DID extension
        to_agent_url: Target agent's URL
        messages: Messages to send

    Returns:
        Response from target agent
    """
    request_data = {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {"messages": messages},
        "id": 1,
    }

    return await make_authenticated_request(
        agent_id=from_agent_id,
        credentials_dir=from_credentials_dir,
        did_extension=from_did_extension,
        url=to_agent_url,
        method="POST",
        data=request_data,
    )
