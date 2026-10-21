from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from urllib.parse import parse_qs, urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from advisory_rss.cache.models import NormalizedAdvisory, is_cert_tr
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.web.render import STYLESHEET, render_detail, render_index

logger = logging.getLogger(__name__)

# HTML pages need the stylesheet from the same origin; no scripts at all.
UI_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
UI_HEADERS = {
    "Content-Security-Policy": UI_CSP,
    "Cache-Control": "no-store, must-revalidate",
    "X-Content-Type-Options": "nosniff",
}


def _csrf_secret(cache: CacheStore) -> str:
    """Persistent per-installation secret used to sign UI forms."""
    secret = cache.get_meta("ui_csrf_secret")
    if not secret:
        secret = secrets.token_urlsafe(32)
        cache.set_meta("ui_csrf_secret", secret)
        logger.info("Generated UI CSRF secret")
    return secret


def _csrf_token(cache: CacheStore, ghsa_id: str) -> str:
    return hmac.new(
        _csrf_secret(cache).encode("utf-8"),
        ghsa_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]


def _check_origin(request: Request) -> None:
    """Reject cross-origin form posts (CSRF)."""
    origin = request.headers.get("origin")
    if not origin:
        return
    host = request.headers.get("host")
    if not host:
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        origin_netloc = urlparse(origin).netloc
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden") from None
    if origin_netloc != host:
        logger.warning("Rejected cross-origin UI request origin=%s host=%s", origin, host)
        raise HTTPException(status_code=403, detail="Forbidden")


def _find_advisory(cache: CacheStore, ghsa_id: str) -> NormalizedAdvisory | None:
    for adv in cache.load_all():
        if adv.ghsa_id == ghsa_id:
            return adv
    return None


async def _read_form(request: Request) -> dict[str, str]:
    """Parse an urlencoded form body.

    Done manually on purpose: Starlette's form parser requires the extra
    ``python-multipart`` dependency, which is not needed for our own forms.
    """
    body = await request.body()
    try:
        parsed = parse_qs(body.decode("utf-8", errors="replace"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return {key: values[0] for key, values in parsed.items() if values}


def build_index_response(request: Request, cache: CacheStore) -> HTMLResponse:
    """Render the advisory list page."""
    source_filter = (request.query_params.get("source") or "all").lower().strip()
    if source_filter not in ("all", "github", "cert-tr", "cert_tr"):
        source_filter = "all"
    if source_filter == "cert_tr":
        source_filter = "cert-tr"
    state_filter = (request.query_params.get("state") or "all").lower().strip()
    if state_filter not in ("all", "pending"):
        state_filter = "all"

    advisories = cache.load_sorted(limit=None)
    confirmed_ids = cache.load_confirmed_ids()

    github_count = sum(
        1 for a in advisories if (getattr(a, "source", "github") or "github") == "github"
    )
    cert_tr_count = sum(1 for a in advisories if is_cert_tr(a))
    pending_count = sum(1 for a in advisories if is_cert_tr(a) and a.ghsa_id not in confirmed_ids)

    if source_filter != "all":
        advisories = [
            a for a in advisories if (getattr(a, "source", "github") or "github") == source_filter
        ]
    if state_filter == "pending":
        advisories = [a for a in advisories if a.ghsa_id not in confirmed_ids]

    counts = {
        "total": github_count + cert_tr_count,
        "github": github_count,
        "cert_tr": cert_tr_count,
        "pending": pending_count,
    }
    body = render_index(
        advisories=advisories,
        confirmed_ids=confirmed_ids,
        source_filter=source_filter,
        state_filter=state_filter,
        counts=counts,
    )
    return HTMLResponse(content=body, headers=dict(UI_HEADERS))


def build_detail_response(
    request: Request,
    cache: CacheStore,
    ghsa_id: str,
) -> HTMLResponse:
    """Render the detail page (full mail + publication state)."""
    adv = _find_advisory(cache, ghsa_id)
    if adv is None:
        raise HTTPException(status_code=404, detail="Advisory not found")
    confirmed_ids = cache.load_confirmed_ids()
    confirmations = cache.load_confirmations()

    flash: str | None = None
    flash_kind = "ok"
    ok = request.query_params.get("ok")
    if ok == "confirmed":
        flash = "Kayıt NVD'de yayınlandı olarak işaretlendi. RSS bağlantısı artık NVD'ye gidiyor."
    elif ok == "unconfirmed":
        flash = "Onay kaldırıldı; kayıt yeniden 'yayınlanmadı' durumuna döndü."
    elif ok == "error":
        flash = "İşlem tamamlanamadı."
        flash_kind = "err"

    body = render_detail(
        adv=adv,
        confirmed_ids=confirmed_ids,
        confirmations=confirmations,
        csrf_token=_csrf_token(cache, ghsa_id),
        flash=flash,
        flash_kind=flash_kind,
    )
    return HTMLResponse(content=body, headers=dict(UI_HEADERS))


def register_ui_routes(app: FastAPI, settings: Settings, cache: CacheStore) -> None:

    @app.get("/ui/style.css", include_in_schema=False)
    async def ui_style() -> Response:
        return Response(
            content=STYLESHEET,
            media_type="text/css; charset=utf-8",
            headers={
                "Content-Security-Policy": "default-src 'none'",
                "Cache-Control": "private, max-age=300",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/ui/feed", include_in_schema=False)
    async def ui_feed() -> RedirectResponse:
        return RedirectResponse(url="/rss.xml", status_code=302)

    @app.get("/ui/a/{ghsa_id}", include_in_schema=False)
    async def ui_detail(ghsa_id: str, request: Request) -> HTMLResponse:
        return build_detail_response(request, cache, ghsa_id)

    @app.post("/ui/a/{ghsa_id}/confirm", include_in_schema=False)
    async def ui_confirm(ghsa_id: str, request: Request) -> Response:
        _check_origin(request)
        adv = _find_advisory(cache, ghsa_id)
        if adv is None:
            raise HTTPException(status_code=404, detail="Advisory not found")
        if not is_cert_tr(adv):
            raise HTTPException(status_code=400, detail="Only CERT-TR advisories can be confirmed")

        try:
            form = await _read_form(request)
        except (ValueError, TypeError) as e:
            logger.warning("UI confirm form parse failed: %s", e)
            raise HTTPException(status_code=400, detail="Bad request") from None
        provided = str(form.get("token") or "")
        expected = _csrf_token(cache, ghsa_id)
        if not provided or not hmac.compare_digest(provided, expected):
            logger.warning("UI confirm rejected - invalid CSRF token for %s", ghsa_id)
            raise HTTPException(status_code=403, detail="Invalid token")

        action = str(form.get("action") or "confirm").strip().lower()
        if action == "unconfirm":
            cache.unconfirm_publication(ghsa_id)
            logger.info("CERT-TR publication unconfirmed ghsa_id=%s", ghsa_id)
            return RedirectResponse(url=f"/ui/a/{ghsa_id}?ok=unconfirmed", status_code=303)
        cache.confirm_publication(ghsa_id)
        logger.info("CERT-TR publication confirmed ghsa_id=%s", ghsa_id)
        return RedirectResponse(url=f"/ui/a/{ghsa_id}?ok=confirmed", status_code=303)
