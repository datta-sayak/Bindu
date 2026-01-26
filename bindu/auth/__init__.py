"""Authentication package for Bindu.

This package provides authentication clients and utilities for Ory Hydra and Kratos.
"""

from __future__ import annotations as _annotations

from .hydra_client import HydraClient, TokenIntrospectionResult, OAuthClient
from .hydra_registration import (
    AgentCredentials,
    register_agent_in_hydra,
    load_agent_credentials,
    save_agent_credentials,
    get_agent_token,
)

__all__ = [
    # Hydra
    "HydraClient",
    "TokenIntrospectionResult",
    "OAuthClient",
    # Hydra Registration
    "AgentCredentials",
    "register_agent_in_hydra",
    "load_agent_credentials",
    "save_agent_credentials",
    "get_agent_token"
]
