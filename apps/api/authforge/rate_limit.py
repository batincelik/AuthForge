import hashlib
from dataclasses import dataclass

from redis.asyncio import Redis

from .config import Settings


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after: int


class RateLimiter:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)

    async def check(self, action: str, dimensions: list[str], limit: int) -> RateLimitResult:
        digest = hashlib.sha256("\x00".join(dimensions).encode()).hexdigest()
        key = f"authforge:rl:{action}:{digest}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.ttl(key)
            count, ttl = await pipe.execute()
        if count == 1 or ttl < 0:
            await self.redis.expire(key, self.settings.rate_limit_window_seconds)
            ttl = self.settings.rate_limit_window_seconds
        return RateLimitResult(count <= limit, max(1, int(ttl)))

    async def close(self) -> None:
        await self.redis.aclose()

