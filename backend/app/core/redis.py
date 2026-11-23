import json
from typing import Any, Optional
import redis
from app.core.config import settings

redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=5,
)


def get_cache(key: str) -> Optional[Any]:
    try:
        raw = redis_client.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw
    except redis.RedisError:
        return None


def set_cache(key: str, value: Any, ttl: int = 604800) -> bool:
    try:
        payload = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
        redis_client.setex(key, ttl, payload)
        return True
    except redis.RedisError:
        return False


def delete_cache(key: str) -> bool:
    try:
        redis_client.delete(key)
        return True
    except redis.RedisError:
        return False
