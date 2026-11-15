"""Encrypted records and atomic single-use OAuth state in dedicated Redis."""

import hashlib
import json

from cryptography.fernet import Fernet
from redis.asyncio import Redis


def identity_key(claims: dict) -> str:
    issuer, subject = claims.get("iss"), claims.get("sub")
    if not isinstance(issuer, str) or not issuer or not isinstance(subject, str) or not subject:
        raise ValueError("Verified OIDC issuer and subject are required")
    return hashlib.sha256(json.dumps([issuer, subject]).encode()).hexdigest()


class Vault:
    def __init__(self, redis: Redis, encryption_key: str):
        self.redis = redis
        self.cipher = Fernet(encryption_key.encode())

    async def put(self, kind: str, key: str, value: dict, ttl: int | None = None):
        sealed = self.cipher.encrypt(json.dumps(value).encode())
        await self.redis.set(f"community:{kind}:{key}", sealed, ex=ttl)

    async def get(self, kind: str, key: str, *, consume: bool = False) -> dict | None:
        redis_key = f"community:{kind}:{key}"
        raw = await self.redis.getdel(redis_key) if consume else await self.redis.get(redis_key)
        return json.loads(self.cipher.decrypt(raw)) if raw else None

    async def delete(self, kind: str, key: str):
        await self.redis.delete(f"community:{kind}:{key}")
