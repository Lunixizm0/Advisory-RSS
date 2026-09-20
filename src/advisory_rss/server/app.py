#FastAPI app factory

from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from advisory_rss.auth.pat import load_token
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings, get_settings
from advisory_rss.github.client import GitHubClient
from advisory_rss.rss.builder import build_rss
from advisory_rss.server.headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)
TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_-]+)")


def _redact(s: str) -> str:
    return TOKEN_RE.sub("***", s)


# 20 KiB max for POST bodies
MAX_POST_BYTES = 20 * 1024

class LimitedSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  
        if request.method == "POST":
            length = request.headers.get("content-length")
            if length is not None:
                if length.isdigit():
                    if int(length) > MAX_POST_BYTES:
                        return JSONResponse(
                            status_code=413, content={"detail": "Payload too large"}
                        )
                else:
                    return JSONResponse(
                        status_code=400, content={"detail": "Invalid Content-Length"}
                    )
            else:
                pass
        return await call_next(request)


def create_app(settings: Settings | None = None, cache: CacheStore | None = None) -> FastAPI:
    if settings is None:
        settings = get_settings()
    if cache is None:
        cache = CacheStore(settings.resolved_cache_path)

    from advisory_rss.server.bind import assert_loopback

    assert_loopback(settings.effective_bind_address())

    app = FastAPI(
        title="Advisory RSS",
        version="0.2.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(LimitedSizeMiddleware)

    # Shared state
    app.state.settings = settings
    app.state.cache = cache
    app.state.bg_task = None

    @app.get("/health")
    async def health() -> JSONResponse:
        meta = cache.get_cache_meta()
        return JSONResponse(
            content={
                "status": "ok" if not meta.rate_limited_until else "rate_limited",
                "advisories_count": meta.advisories_count,
                "last_successful_sync": meta.last_successful_sync,
                "next_scheduled_sync": meta.next_scheduled_sync,
                "rate_limited_until": meta.rate_limited_until,
                "last_error": meta.last_error,
                "authenticated_user": meta.authenticated_user,
                "bind_address": f"{settings.effective_bind_address()}:{settings.port}",
                "rss_url": settings.rss_url(),
                "cache_path": str(settings.resolved_cache_path),
                "filter_mode": settings.filter_mode,
                "max_items": settings.max_items,
                "refresh_interval": settings.refresh_interval,
            },
            headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
        )

    @app.get("/rss.xml")
    @app.get("/rss")
    async def rss(request: Request) -> Response:
        if request.query_params:
            raise HTTPException(status_code=422, detail="Query parameters not allowed")
        # Serve from cache only - never call GitHub here
        advisories = cache.load_sorted(limit=None)  # load all sorted, builder caps by max_items
        feed_user = cache.get_meta("authenticated_user") or "user"
        ttl_minutes = max(1, settings.refresh_interval // 60)
        xml = build_rss(
            advisories,
            feed_title=f"GitHub Security Advisories - @{feed_user}",
            feed_link=f"https://github.com/{feed_user}",
            feed_description=f"Security advisories created by {feed_user} (author={feed_user}) via GitHub API - localhost-only feed",
            max_items=settings.max_items,
            ttl_minutes=ttl_minutes,
            authenticated_user=feed_user,
        )
        return Response(
            content=xml.encode("utf-8"),
            media_type="application/rss+xml; charset=utf-8",
            headers={
                "Cache-Control": f"private, max-age={settings.refresh_interval}, must-revalidate",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/")
    async def root() -> JSONResponse:
        # Minimal hint, not directory listing
        return JSONResponse(
            content={
                "message": "Advisory RSS - localhost-only. See /rss.xml and /health",
                "rss": settings.rss_url(),
                "health": f"http://{settings.effective_bind_address()}:{settings.port}/health",
            }
        )

    @app.post("/refresh")
    async def refresh(request: Request) -> JSONResponse:
        if not settings.enable_refresh_endpoint:
            raise HTTPException(status_code=404, detail="Not found")
        # Require token when endpoint is enabled - deny unauthenticated refresh if no token configured
        if not settings.refresh_token:
            logger.warning(
                "POST /refresh rejected - refresh endpoint enabled but REFRESH_TOKEN not set (secure default requires token)"
            )
            raise HTTPException(
                status_code=403,
                detail="Refresh token not configured - set REFRESH_TOKEN in .env",
            )
        # Guard refresh with required token
        provided = (
            request.headers.get("x-refresh-token") or request.headers.get("authorization") or ""
        )
        # support Bearer as refresh
        if provided.startswith("Bearer "):
            provided = provided[7:].strip()
        else:
            # Header x-refresh-token raw
            provided = provided.strip()
        # Also check x-refresh-token header directly (prefer explicit header)
        hdr = request.headers.get("x-refresh-token", "").strip()
        if hdr:
            provided = hdr
        if provided != settings.refresh_token:
            raise HTTPException(status_code=403, detail="Invalid refresh token")
        # Enforce streaming body size even for chunked (defense in depth)
        body = await request.body()
        if len(body) > MAX_POST_BYTES:
            raise HTTPException(status_code=413, detail="Payload too large")
        # Trigger sync background
        token = load_token(settings)
        if not token:
            raise HTTPException(status_code=401, detail="GitHub token not configured")
        # Run sync inline but bounded
        try:
            client = GitHubClient(settings, token, cache=cache)
            try:
                advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
                count = cache.upsert_advisories(advs)
                cache.mark_success(user=diag.get("authenticated_login"))
                # next sync
                nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
                cache.set_meta("next_scheduled_sync", nxt)
                return JSONResponse(
                    content={
                        "status": "refreshed",
                        "count": count,
                        "diag": {k: v for k, v in diag.items() if k != "errors" or v},
                    }
                )
            finally:
                await client.close()
        except Exception as e:  
            msg = _redact(str(e))
            logger.warning("Refresh failed: %s", msg)
            cache.mark_error(msg)
            raise HTTPException(status_code=502, detail=f"Refresh failed: {msg[:200]}")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  
        # Never leak stack trace; log redacted
        logger.error(
            "Unhandled error on %s: %s",
            request.url.path,
            _redact(str(exc)),
            exc_info=False,
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
            headers={"Cache-Control": "no-store"},
        )

    return app


async def background_refresh_loop(settings: Settings, cache: CacheStore) -> None:
    while True:
        await asyncio.sleep(settings.refresh_interval)
        token = load_token(settings)
        if not token:
            logger.info("Background refresh skipped - no token")
            continue
        try:
            client = GitHubClient(settings, token, cache=cache)
            try:
                advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
                cache.upsert_advisories(advs)
                cache.mark_success(user=diag.get("authenticated_login"))
                nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
                cache.set_meta("next_scheduled_sync", nxt)
                logger.info("Background refresh OK: %d advisories", len(advs))
            finally:
                await client.close()
        except Exception as e:  
            msg = _redact(str(e))
            logger.warning("Background refresh failed, keeping stale cache: %s", msg)
            cache.mark_error(msg)
            # schedule next retry sooner (backoff handled elsewhere)
            nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
            cache.set_meta("next_scheduled_sync", nxt)
