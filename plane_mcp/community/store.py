"""Encrypted Redis records; bearer credentials appear only as SHA-256 keys."""

import hashlib
import json

from cryptography.fernet import Fernet
from redis.asyncio import Redis
from redis.exceptions import WatchError


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Vault:
    def __init__(self, redis: Redis, encryption_key: str):
        self.redis, self.cipher = redis, Fernet(encryption_key.encode())

    def key(self, kind, key):
        return f"community-direct:{kind}:{digest(key)}"

    async def put(self, kind, key, value, ttl):
        await self.redis.set(self.key(kind, key), self.cipher.encrypt(json.dumps(value).encode()), ex=ttl)

    async def get(self, kind, key, *, consume=False):
        name = self.key(kind, key)
        raw = await self.redis.getdel(name) if consume else await self.redis.get(name)
        return json.loads(self.cipher.decrypt(raw)) if raw else None

    async def delete(self, kind, key):
        await self.redis.delete(self.key(kind, key))

    async def consume_refresh(self, key):
        # Atomically retain a replay marker for the remaining grant lifetime.
        name = self.key("refresh", key)
        async with self.redis.pipeline() as pipe:
            while True:
                try:
                    await pipe.watch(name)
                    raw = await pipe.get(name)
                    if raw is None:
                        return None
                    ttl = max(1, await pipe.ttl(name))
                    pipe.multi()
                    pipe.delete(name)
                    pipe.set(self.key("spent", key), raw, ex=ttl)
                    await pipe.execute()
                    return json.loads(self.cipher.decrypt(raw))
                except WatchError:
                    continue
