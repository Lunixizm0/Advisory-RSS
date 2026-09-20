from __future__ import annotations

import logging

from advisory_rss.config.settings import Settings

logger = logging.getLogger(__name__)


def load_token(settings: Settings) -> str | None:
    tok = settings.token
    if tok:
        logger.debug(
            "token loaded preview=%s", tok[:4] + "..." + tok[-4:] if len(tok) > 8 else "***"
        )
    else:
        logger.debug("no token configured")
    return tok


def token_preview(token: str | None) -> str:
    if not token:
        return "not set"
    t = token.strip()
    if len(t) <= 8:
        return "***"
    return f"{t[:4]}...{t[-4:]}"


def is_token_set(settings: Settings) -> bool:
    return load_token(settings) is not None
