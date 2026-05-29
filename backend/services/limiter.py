# limitez cate cereri poate face un IP, tinut in memorie
import time
from collections import defaultdict
from fastapi import HTTPException, Request


class RateLimiter:
    def __init__(self, max_requests: int = 20, window_seconds: int = 60):
        self._hits: dict[str, list[float]] = defaultdict(list)
        self.max_requests = max_requests
        self.window = window_seconds

    def check(self, ip: str):
        now = time.time()
        cutoff = now - self.window
        # arunc intrarile vechi inainte sa numar
        self._hits[ip] = [t for t in self._hits[ip] if t > cutoff]
        if len(self._hits[ip]) >= self.max_requests:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: max {self.max_requests} requests per {self.window}s",
            )
        self._hits[ip].append(now)


limiter = RateLimiter(max_requests=20, window_seconds=60)


def rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    limiter.check(ip)
