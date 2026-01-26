"""OAuth client management endpoints for Hydra.

This module provides HTTP endpoints for managing OAuth clients in Hydra,
including creation, listing, and deletion of clients.
"""

from __future__ import annotations as _annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from bindu.auth.hydra_client import HydraClient
from bindu.settings import app_settings
from bindu.utils.logging import get_logger

logger = get_logger("bindu.server.endpoints.oauth")


async def create_oauth_client_endpoint(request: Request) -> JSONResponse:
    """Create a new OAuth client in Hydra.

    POST /admin/oauth/clients

    Request body:
    {
        "client_name": "my-app",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "offline", "agent:read"]
    }

    Returns:
        JSONResponse with client credentials
    """
    try:
        # Parse request body
        body = await request.json()

        client_name = body.get("client_name")
        if not client_name:
            return JSONResponse(
                {"error": "client_name is required"}, status_code=400
            )

        # Generate client_id from name
        import re
        client_id = re.sub(r"[^a-z0-9-]", "-", client_name.lower())

        # Generate secure client secret
        import secrets
        client_secret = secrets.token_urlsafe(32)

        # Prepare client data
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "grant_types": body.get(
                "grant_types", ["authorization_code", "refresh_token"]
            ),
            "redirect_uris": body.get("redirect_uris", []),
            "response_types": body.get("response_types", ["code"]),
            "scope": " ".join(
                body.get("scopes", ["openid", "offline", "agent:read"])
            ),
            "token_endpoint_auth_method": body.get(
                "token_endpoint_auth_method", "client_secret_basic"
            ),
        }

        # Create client in Hydra
        async with HydraClient(
            admin_url=app_settings.hydra.admin_url,
            public_url=app_settings.hydra.public_url,
            timeout=app_settings.hydra.timeout,
            verify_ssl=app_settings.hydra.verify_ssl,
        ) as hydra:
            client = await hydra.create_oauth_client(client_data)

        logger.info(f"OAuth client created: {client_id}")

        return JSONResponse(
            {
                "client_id": client.get("client_id"),
                "client_secret": client_secret,
                "client_name": client.get("client_name"),
                "grant_types": client.get("grant_types"),
                "redirect_uris": client.get("redirect_uris"),
                "scope": client.get("scope"),
                "message": "Client created successfully. Save the client_secret - it won't be shown again.",
            },
            status_code=201,
        )

    except ValueError as e:
        logger.error(f"Failed to create OAuth client: {e}")
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"Unexpected error creating OAuth client: {e}")
        return JSONResponse(
            {"error": "Internal server error"}, status_code=500
        )


async def list_oauth_clients_endpoint(request: Request) -> JSONResponse:
    """List OAuth clients in Hydra.

    GET /admin/oauth/clients?limit=100&offset=0

    Returns:
        JSONResponse with list of clients
    """
    try:
        # Parse query parameters
        limit = int(request.query_params.get("limit", 100))
        offset = int(request.query_params.get("offset", 0))

        # List clients from Hydra
        async with HydraClient(
            admin_url=app_settings.hydra.admin_url,
            public_url=app_settings.hydra.public_url,
            timeout=app_settings.hydra.timeout,
            verify_ssl=app_settings.hydra.verify_ssl,
        ) as hydra:
            clients = await hydra.list_oauth_clients(limit=limit, offset=offset)

        # Remove sensitive data
        safe_clients = []
        for client in clients:
            safe_clients.append(
                {
                    "client_id": client.get("client_id"),
                    "client_name": client.get("client_name"),
                    "grant_types": client.get("grant_types"),
                    "scope": client.get("scope"),
                    "created_at": client.get("created_at"),
                    "metadata": client.get("metadata"),
                }
            )

        return JSONResponse(
            {"clients": safe_clients, "count": len(safe_clients)}, status_code=200
        )

    except Exception as e:
        logger.error(f"Failed to list OAuth clients: {e}")
        return JSONResponse(
            {"error": "Internal server error"}, status_code=500
        )


async def get_oauth_client_endpoint(request: Request) -> JSONResponse:
    """Get OAuth client details.

    GET /admin/oauth/clients/{client_id}

    Returns:
        JSONResponse with client details
    """
    try:
        client_id = request.path_params.get("client_id")
        if not client_id:
            return JSONResponse(
                {"error": "client_id is required"}, status_code=400
            )

        # Get client from Hydra
        async with HydraClient(
            admin_url=app_settings.hydra.admin_url,
            public_url=app_settings.hydra.public_url,
            timeout=app_settings.hydra.timeout,
            verify_ssl=app_settings.hydra.verify_ssl,
        ) as hydra:
            client = await hydra.get_oauth_client(client_id)

        if not client:
            return JSONResponse(
                {"error": "Client not found"}, status_code=404
            )

        # Remove sensitive data
        safe_client = {
            "client_id": client.get("client_id"),
            "client_name": client.get("client_name"),
            "grant_types": client.get("grant_types"),
            "redirect_uris": client.get("redirect_uris"),
            "scope": client.get("scope"),
            "created_at": client.get("created_at"),
            "metadata": client.get("metadata"),
        }

        return JSONResponse(safe_client, status_code=200)

    except Exception as e:
        logger.error(f"Failed to get OAuth client: {e}")
        return JSONResponse(
            {"error": "Internal server error"}, status_code=500
        )


async def delete_oauth_client_endpoint(request: Request) -> JSONResponse:
    """Delete an OAuth client.

    DELETE /admin/oauth/clients/{client_id}

    Returns:
        JSONResponse with success message
    """
    try:
        client_id = request.path_params.get("client_id")
        if not client_id:
            return JSONResponse(
                {"error": "client_id is required"}, status_code=400
            )

        # Delete client from Hydra
        async with HydraClient(
            admin_url=app_settings.hydra.admin_url,
            public_url=app_settings.hydra.public_url,
            timeout=app_settings.hydra.timeout,
            verify_ssl=app_settings.hydra.verify_ssl,
        ) as hydra:
            deleted = await hydra.delete_oauth_client(client_id)

        if not deleted:
            return JSONResponse(
                {"error": "Client not found"}, status_code=404
            )

        logger.info(f"OAuth client deleted: {client_id}")

        return JSONResponse(
            {"message": f"Client {client_id} deleted successfully"},
            status_code=200,
        )

    except Exception as e:
        logger.error(f"Failed to delete OAuth client: {e}")
        return JSONResponse(
            {"error": "Internal server error"}, status_code=500
        )


async def get_token_endpoint(request: Request) -> JSONResponse:
    """Get access token using client credentials.

    POST /oauth/token

    Request body:
    {
        "client_id": "my-client",
        "client_secret": "secret",
        "grant_type": "client_credentials",
        "scope": "agent:read agent:write"
    }

    Returns:
        JSONResponse with access token
    """
    try:
        # Parse request body
        body = await request.json()

        client_id = body.get("client_id")
        client_secret = body.get("client_secret")
        grant_type = body.get("grant_type", "client_credentials")
        scope = body.get("scope", "")

        if not client_id or not client_secret:
            return JSONResponse(
                {"error": "client_id and client_secret are required"},
                status_code=400,
            )

        # Get token from Hydra
        import aiohttp
        import base64

        token_url = f"{app_settings.hydra.public_url}/oauth2/token"

        # Prepare basic auth
        auth_string = f"{client_id}:{client_secret}"
        auth_bytes = auth_string.encode("utf-8")
        auth_b64 = base64.b64encode(auth_bytes).decode("utf-8")

        headers = {
            "Authorization": f"Basic {auth_b64}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": grant_type,
            "scope": scope,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url, headers=headers, data=data
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return JSONResponse(result, status_code=200)
                else:
                    error_text = await response.text()
                    logger.error(
                        f"Failed to get token: {response.status} - {error_text}"
                    )
                    return JSONResponse(
                        {"error": "Failed to get token", "details": error_text},
                        status_code=response.status,
                    )

    except Exception as e:
        logger.error(f"Failed to get token: {e}")
        return JSONResponse(
            {"error": "Internal server error"}, status_code=500
        )
