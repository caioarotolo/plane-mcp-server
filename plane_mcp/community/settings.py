"""Explicit configuration for the optional Community deployment."""

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    origin: str
    discovery_url: str
    client_id: str
    client_secret: str
    encryption_key: str
    signing_key: str
    redis_url: str
    workspace: str

    @classmethod
    def from_env(cls):
        if os.getenv("PLANE_API_KEY") or os.getenv("PLANE_ACCESS_TOKEN"):
            raise ValueError("Shared Plane credentials must not be configured")
        names = {
            "origin": "COMMUNITY_PUBLIC_URL",
            "discovery_url": "COMMUNITY_OIDC_DISCOVERY_URL",
            "client_id": "COMMUNITY_OIDC_CLIENT_ID",
            "client_secret": "COMMUNITY_OIDC_CLIENT_SECRET",
            "encryption_key": "COMMUNITY_ENCRYPTION_KEY",
            "signing_key": "COMMUNITY_SIGNING_KEY",
            "redis_url": "REDIS_URL",
            "workspace": "MCP_DEFAULT_WORKSPACE_SLUG",
        }
        values = {key: os.environ[name] for key, name in names.items()}
        values["origin"] = values["origin"].rstrip("/")
        origin = urlsplit(values["origin"])
        if origin.scheme != "https" or origin.path or origin.query or origin.fragment or origin.username:
            raise ValueError("COMMUNITY_PUBLIC_URL must be an HTTPS origin")
        if not values["discovery_url"].startswith("https://"):
            raise ValueError("OIDC discovery requires HTTPS")
        if any(not value for value in values.values()):
            raise ValueError("Community settings must not be empty")
        if len(values["signing_key"]) < 32:
            raise ValueError("Use a randomly generated signing key of at least 32 characters")
        return cls(**values)
