from __future__ import annotations

from advisory_rss.config.settings import Settings


def load_token(settings: Settings) -> str | None:
    return settings.token


def token_preview(token: str | None) -> str:
    if not token:
        return "not set"
    t = token.strip()
    if len(t) <= 8:
        return "***"
    return f"{t[:4]}...{t[-4:]}"


def is_token_set(settings: Settings) -> bool:
    return load_token(settings) is not None
