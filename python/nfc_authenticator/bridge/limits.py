"""Process-local resource bounds; edge per-client limits remain recommended."""
from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class ResourceLimitsMiddleware:
    def __init__(self, app: ASGIApp, *, maximum_body_bytes: int = 65536, requests_per_minute: int = 600,
                 body_timeout_seconds: float = 10, clock: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self.maximum_body_bytes = maximum_body_bytes
        self.requests_per_minute = requests_per_minute
        self.body_timeout_seconds = body_timeout_seconds
        self.clock = clock
        self.requests: deque[float] = deque()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        now = self.clock()
        while self.requests and self.requests[0] <= now - 60:
            self.requests.popleft()
        if len(self.requests) >= self.requests_per_minute:
            return await JSONResponse({"detail": "Request rate exceeded"}, status_code=429,
                                      headers={"Retry-After": "60"})(scope, receive, send)
        self.requests.append(now)
        if len(scope.get("query_string", b"")) > 8192:
            return await JSONResponse({"detail": "Query too large"}, status_code=414)(scope, receive, send)
        body = bytearray()
        try:
            async with asyncio.timeout(self.body_timeout_seconds):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > self.maximum_body_bytes:
                        return await JSONResponse({"detail": "Request body too large"}, status_code=413)(
                            scope, receive, send)
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await JSONResponse({"detail": "Request body timed out"}, status_code=408)(scope, receive, send)

        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
