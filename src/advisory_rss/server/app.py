# FastAPI app factory

from __future__ import annotations

import asyncio
import hmac
import logging
import re as _re
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from advisory_rss import __version__
from advisory_rss.auth.pat import load_token
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.constants import TOKEN_REDACT_PATTERN
from advisory_rss.config.settings import Settings, get_settings
from advisory_rss.github.client import GitHubClient
from advisory_rss.rss.builder import build_rss
from advisory_rss.server.headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)
TOKEN_RE = _re.compile(TOKEN_REDACT_PATTERN)


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
                        logger.warning(
                            "POST %s rejected: Content-Length %s exceeds %d",
                            request.url.path,
                            length,
                            MAX_POST_BYTES,
                        )
                        return JSONResponse(
                            status_code=413, content={"detail": "Payload too large"}
                        )
                else:
                    logger.warning(
                        "POST %s rejected: invalid Content-Length %r",
                        request.url.path,
                        _redact(str(length)[:200]),
                    )
                    return JSONResponse(
                        status_code=400, content={"detail": "Invalid Content-Length"}
                    )

        return await call_next(request)


async def _read_limited_body(request: Request, limit: int = MAX_POST_BYTES) -> bytes:
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            logger.warning("POST %s body exceeds %d bytes - rejecting", request.url.path, limit)
            raise HTTPException(status_code=413, detail="Payload too large")
    return body


def create_app(
    settings: Settings | None = None,
    cache: CacheStore | None = None,
    lifespan: Any | None = None,
) -> FastAPI:
    if settings is None:
        settings = get_settings()
    if cache is None:
        cache = CacheStore(settings.resolved_cache_path)

    from advisory_rss.server.bind import assert_loopback

    assert_loopback(settings.effective_bind_address())
    logger.info(
        "create_app bind=%s:%s cache=%s",
        settings.effective_bind_address(),
        settings.port,
        settings.resolved_cache_path,
    )

    app = FastAPI(
        title="Advisory RSS",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
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
        # per-source counts
        try:
            all_advs = cache.load_all()
            github_count = sum(
                1 for a in all_advs if (getattr(a, "source", "github") or "github") == "github"
            )
            cert_tr_count = sum(1 for a in all_advs if getattr(a, "source", "") == "cert-tr")
        except (OSError, ValueError, RuntimeError, AttributeError) as e:
            logger.debug("Failed to load per-source counts: %s", e)
            github_count = None
            cert_tr_count = None
        # cert_tr diag
        cert_tr_diag = None
        try:
            import json

            raw = cache.get_meta("cert_tr_diag")
            if raw:
                cert_tr_diag = json.loads(raw)
        except (OSError, ValueError, TypeError, RuntimeError) as e:
            logger.debug("Failed to load cert_tr_diag: %s", e)
        return JSONResponse(
            content={
                "status": "ok" if not meta.rate_limited_until else "rate_limited",
                "advisories_count": meta.advisories_count,
                "github_count": github_count,
                "cert_tr_count": cert_tr_count,
                "cert_tr_enabled": settings.enable_cert_tr,
                "cert_tr_accounts": len(settings.get_cert_tr_accounts())
                if settings.enable_cert_tr
                else 0,
                "cert_tr_diag": cert_tr_diag,
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
        # Optional source filter: ?source=all|github|cert-tr  (default all = mixed)
        src_filter = (request.query_params.get("source") or "all").lower().strip()
        if src_filter not in ("all", "github", "cert-tr", "cert_tr"):
            src_filter = "all"
        if src_filter == "cert_tr":
            src_filter = "cert-tr"
        if request.query_params and "source" not in request.query_params:
            logger.debug(
                "RSS query params ignored (no source): %s path=%s",
                _redact(str(request.query_params)),
                request.url.path,
            )
        logger.debug(
            "RSS request path=%s source=%s user_agent=%s",
            request.url.path,
            src_filter,
            _redact(request.headers.get("user-agent", "")[:200]),
        )
        # Serve from cache only - never call GitHub/IMAP here
        advisories = cache.load_sorted(limit=None)  # load all sorted, builder caps by max_items
        if src_filter != "all":
            advisories = [
                a for a in advisories if (getattr(a, "source", "github") or "github") == src_filter
            ]
        feed_user = cache.get_meta("authenticated_user") or "user"
        ttl_minutes = max(1, settings.refresh_interval // 60)
        # Mixed feed title when both sources present
        has_github = any(
            (getattr(a, "source", "github") or "github") == "github" for a in advisories
        )
        has_cert = any(getattr(a, "source", "") == "cert-tr" for a in advisories)
        if has_github and has_cert and src_filter == "all":
            feed_title = f"Security Advisories (GitHub + CERT-TR) - @{feed_user}"
            feed_desc = f"Mixed feed: GitHub advisories by @{feed_user} + CERT-TR via Proton Mail"
        elif src_filter == "cert-tr":
            feed_title = "CERT-TR / Siber Güvenlik Başkanlığı Advisories"
            feed_desc = "CERT-TR advisories via Proton Mail (siberguvenlik.gov.tr)"
        else:
            feed_title = f"GitHub Security Advisories - @{feed_user}"
            feed_desc = f"Security advisories created by {feed_user} (author={feed_user}) via GitHub API - localhost-only feed"
        # Keep feed_link sensible
        feed_link = (
            f"https://github.com/{feed_user}"
            if src_filter != "cert-tr"
            else "https://siberguvenlik.gov.tr"
        )
        xml = build_rss(
            advisories,
            feed_title=feed_title,
            feed_link=feed_link,
            feed_description=feed_desc,
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
        logger.info("POST /refresh from %s", request.client.host if request.client else "unknown")
        if not settings.enable_refresh_endpoint:
            logger.warning("POST /refresh rejected - endpoint disabled")
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
        # Guard refresh with required token - prefer explicit x-refresh-token, fallback to Authorization: Bearer
        hdr_explicit = request.headers.get("x-refresh-token", "").strip()
        if hdr_explicit:
            provided = hdr_explicit
        else:
            auth = request.headers.get("authorization") or ""
            if auth.startswith("Bearer "):
                provided = auth[7:].strip()
            else:
                provided = auth.strip()
        if not hmac.compare_digest(provided, settings.refresh_token or ""):
            logger.warning(
                "POST /refresh invalid token from %s",
                request.client.host if request.client else "unknown",
            )
            raise HTTPException(status_code=403, detail="Invalid refresh token")
        # Enforce streaming body size even for chunked (defense in depth)
        await _read_limited_body(request, MAX_POST_BYTES)
        # Optional ?source= filter
        q_source = (request.query_params.get("source") or "all").lower().strip()
        if q_source not in ("all", "github", "cert-tr", "cert_tr"):
            q_source = "all"
        if q_source == "cert_tr":
            q_source = "cert-tr"
        # Trigger sync background
        token = load_token(settings)
        # Refresh allows mixed: if no GitHub token but cert-tr enabled, still refresh cert-tr
        need_github = q_source in ("all", "github")
        if need_github and not token and settings.enable_cert_tr and q_source == "all":
            need_github = False
        elif need_github and not token:
            raise HTTPException(status_code=401, detail="GitHub token not configured")
        # Run sync inline but bounded
        try:
            all_advs = []
            diag_comb: dict[str, Any] = {"errors": []}
            if need_github and token:
                client = GitHubClient(settings, token, cache=cache)
                try:
                    advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
                    all_advs.extend(advs)
                    diag_comb["github"] = diag
                    diag_comb["errors"].extend(diag.get("errors") or [])
                finally:
                    await client.close()
            if q_source in ("all", "cert-tr") and settings.enable_cert_tr:
                from advisory_rss.cert_tr.source import CertTrSource

                src = CertTrSource(settings)
                advs_ct, diag_ct = src.fetch_all()
                all_advs.extend(advs_ct)
                diag_comb["cert_tr"] = diag_ct
                diag_comb["errors"].extend(diag_ct.get("errors") or [])
            if not all_advs:
                if diag_comb.get("errors"):
                    # Redact and log for operators, but don't send to client
                    redacted_errors = [_redact(str(e))[:200] for e in diag_comb["errors"][:2]]
                    logger.warning(
                        "Refresh: no advisories, errors=%s q_source=%s",
                        redacted_errors,
                        q_source,
                    )
                raise HTTPException(
                    status_code=502,
                    detail="Refresh: no advisories - see server logs",
                )
            count = cache.upsert_advisories(all_advs)
            # keep user from GitHub if present
            user = None
            if diag_comb.get("github"):
                user = diag_comb["github"].get("authenticated_login")
            cache.mark_success(user=user)
            nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
            cache.set_meta("next_scheduled_sync", nxt)
            try:
                import json

                if diag_comb.get("cert_tr"):
                    cache.set_meta(
                        "cert_tr_diag", json.dumps(diag_comb["cert_tr"], ensure_ascii=False)
                    )
            except (OSError, ValueError, TypeError, RuntimeError) as e:
                logger.debug("Failed to persist cert_tr_diag: %s", e)
            logger.info("POST /refresh ok: count=%d", count, extra={"diag": diag_comb})
            return JSONResponse(
                content={
                    "status": "refreshed",
                    "count": count,
                    "diag": {k: v for k, v in diag_comb.items() if k != "errors" or v},
                }
            )
        except HTTPException:
            raise
        except (OSError, ValueError, RuntimeError) as e:
            msg = _redact(str(e))
            logger.warning("Refresh failed: %s", msg, exc_info=True)
            cache.mark_error(msg)
            raise HTTPException(
                status_code=502, detail="Refresh failed - see server logs"
            ) from None

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        # Never leak stack trace to client (CWE-209/497). Log redacted
        # server-side with full trace for operators (RedactFilter scrubs tokens).
        logger.error(
            "Unhandled error on %s: %s",
            request.url.path,
            _redact(str(exc)),
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
            headers={"Cache-Control": "no-store"},
        )

    return app


async def background_refresh_loop(settings: Settings, cache: CacheStore) -> None:
    # Run an immediate refresh on startup (after short grace) then periodic
    # Mixed: GitHub + CERT-TR (IMAP is sync, wrap in thread)
    logger.info(
        "background_refresh_loop starting interval=%ds filter=%s cert_tr=%s",
        settings.refresh_interval,
        settings.filter_mode,
        settings.enable_cert_tr,
    )
    first = True
    while True:
        if not first:
            await asyncio.sleep(settings.refresh_interval)
        else:
            # Small grace to let server finish startup
            await asyncio.sleep(2)
            first = False
        token = load_token(settings)
        # If neither source is usable, skip
        if not token and not settings.enable_cert_tr:
            logger.info("Background refresh skipped - no token and CERT-TR disabled")
            continue
        # Also skip if CERT-TR enabled but no IMAP accounts and no token => nothing to do
        if not token and settings.enable_cert_tr and not settings.get_cert_tr_accounts():
            logger.info(
                "Background refresh skipped - CERT-TR enabled but no IMAP accounts and no GitHub token"
            )
            continue
        try:
            all_advs = []
            github_diag = None
            cert_diag = None
            errors: list[str] = []
            # GitHub (async)
            if token:
                client = GitHubClient(settings, token, cache=cache)
                try:
                    advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
                    all_advs.extend(advs)
                    github_diag = diag
                    errors.extend(diag.get("errors") or [])
                except (OSError, ValueError, RuntimeError) as e:
                    msg = _redact(str(e))
                    logger.warning("Background GitHub refresh failed: %s", msg, exc_info=True)
                    errors.append(msg)
                    # keep stale, don't abort cert-tr
                finally:
                    await client.close()
            # CERT-TR (sync IMAP -> run in thread)
            if settings.enable_cert_tr:
                try:
                    from advisory_rss.cert_tr.source import CertTrSource

                    def _fetch_ct():
                        src = CertTrSource(settings)
                        return src.fetch_all()

                    advs_ct, diag_ct = await asyncio.to_thread(_fetch_ct)
                    cert_diag = diag_ct
                    errors.extend(diag_ct.get("errors") or [])
                    if advs_ct:
                        all_advs.extend(advs_ct)
                except (OSError, ValueError, RuntimeError) as e:
                    msg = _redact(str(e))
                    logger.warning("Background CERT-TR refresh failed: %s", msg, exc_info=True)
                    errors.append(msg)
            if not all_advs and errors:
                # Report but keep stale
                msg = "; ".join(errors[:3])
                cache.mark_error(msg)
                logger.warning("Background refresh: no advisories, errors=%s", msg)
            elif all_advs:
                # Dedup already done per source; final merge dedup by ghsa_id
                cache.upsert_advisories(all_advs)
                user = (github_diag or {}).get("authenticated_login") if github_diag else None
                cache.mark_success(user=user or cache.get_meta("authenticated_user"))
                try:
                    import json

                    if cert_diag is not None:
                        cache.set_meta("cert_tr_diag", json.dumps(cert_diag, ensure_ascii=False))
                except (OSError, ValueError, TypeError, RuntimeError) as e:
                    logger.debug("Failed to persist cert_diag in background: %s", e)
                gh_count = 0
                if isinstance(github_diag, dict):
                    try:
                        gh_count = int(github_diag.get("filtered_count") or 0)
                    except (ValueError, TypeError) as e:
                        logger.debug("Failed to parse gh_count: %s", e)
                        gh_count = 0
                ct_count = int(cert_diag.get("parsed") or 0) if isinstance(cert_diag, dict) else 0
                logger.info(
                    "Background refresh OK: total=%d github=%d cert_tr=%d errors=%d",
                    len(all_advs),
                    gh_count,
                    ct_count,
                    len(errors),
                )
            else:
                logger.info("Background refresh: no new advisories")
            nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
            cache.set_meta("next_scheduled_sync", nxt)
        except (OSError, ValueError, RuntimeError) as e:
            msg = _redact(str(e))
            logger.warning("Background refresh failed, keeping stale cache: %s", msg, exc_info=True)
            cache.mark_error(msg)
            # schedule next retry sooner (backoff handled elsewhere)
            nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
            cache.set_meta("next_scheduled_sync", nxt)
