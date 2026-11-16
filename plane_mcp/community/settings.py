"""Configuration for the optional Community OAuth adapter."""

import os
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    origin: str
    encryption_key: str
    redis_url: str
    workspace: str

    @property
    def resource(self):
        return self.origin + "/mcp"

    @classmethod
    def from_env(cls):
        if os.getenv("PLANE_API_KEY") or os.getenv("PLANE_ACCESS_TOKEN"):
            raise ValueError("Shared Plane credentials must not be configured")
        names = {
            "origin": "COMMUNITY_PUBLIC_URL",
            "encryption_key": "COMMUNITY_ENCRYPTION_KEY",
            "redis_url": "REDIS_URL",
            "workspace": "MCP_DEFAULT_WORKSPACE_SLUG",
        }
        values = {key: os.environ[name] for key, name in names.items()}
        values["origin"] = values["origin"].rstrip("/")
        origin = urlsplit(values["origin"])
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.path
            or origin.query
            or origin.fragment
            or origin.username
        ):
            raise ValueError("COMMUNITY_PUBLIC_URL must be an HTTPS origin")
        if any(not value for value in values.values()):
            raise ValueError("Community settings must not be empty")
        return cls(**values)
