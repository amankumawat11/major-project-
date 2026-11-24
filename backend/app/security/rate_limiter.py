import time
from collections import defaultdict
from fastapi import HTTPException, status

class SimpleRateLimiter:
    """
    In-memory rate limiter per IP address using a sliding time window.
    """
    def __init__(self, requests_per_minute: int = 20):
        self.requests_per_minute = requests_per_minute
        self.history = defaultdict(list)

    def check(self, client_ip: str):
        now = time.time()
        window_start = now - 60.0
        
        # Clean older requests
        recent = [t for t in self.history[client_ip] if t > window_start]
        self.history[client_ip] = recent

        if len(recent) >= self.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({self.requests_per_minute} requests/minute). Please wait a moment."
            )

        self.history[client_ip].append(now)

rate_limiter = SimpleRateLimiter()
