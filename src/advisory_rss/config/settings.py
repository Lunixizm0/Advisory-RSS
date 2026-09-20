from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from advisory_rss.config.constants import (
    DEFAULT_BIND_ADDRESS,
    DEFAULT_CACHE_PATH,
    DEFAULT_FILTER_MODE,
    DEFAULT_GITHUB_API_BASE,
    DEFAULT_LOG_FORMAT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_PAGES_PER_REPO,
    DEFAULT_MAX_REPOS,
    DEFAULT_PORT,
    DEFAULT_REFRESH_INTERVAL,
)
from advisory_rss.server.bind import validate_bind_address

_UNSET = object()  # type: ignore[var-annotated]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        populate_by_name=True,
    )

    def __init__(
        self,
        _env_file: str | Path | tuple[str | Path, ...] | list[str | Path] | None = _UNSET,  # type: ignore[assignment]
        _env_file_encoding: str | None = _UNSET,  # type: ignore[assignment]
        _secrets_dir: str | Path | None = _UNSET,  # type: ignore[assignment]
        **kwargs: Any,
    ) -> None:
        init_kwargs: dict[str, Any] = {}
        if _env_file is not _UNSET:
            init_kwargs["_env_file"] = _env_file
        if _env_file_encoding is not _UNSET:
            init_kwargs["_env_file_encoding"] = _env_file_encoding
        if _secrets_dir is not _UNSET:
            init_kwargs["_secrets_dir"] = _secrets_dir
        super().__init__(**init_kwargs, **kwargs)

    # GitHub
    github_token: str | None = Field(default=None, validation_alias="GITHUB_TOKEN")
    github_pat: str | None = Field(default=None, validation_alias="GITHUB_PAT")
    github_client_id: str | None = Field(default=None, validation_alias="GITHUB_CLIENT_ID")
    github_api_base: str = Field(
        default=DEFAULT_GITHUB_API_BASE, validation_alias="GITHUB_API_BASE"
    )

    # Server
    bind_address: str = Field(default=DEFAULT_BIND_ADDRESS, validation_alias="BIND_ADDRESS")
    port: int = Field(default=DEFAULT_PORT, validation_alias="PORT")
    # Alias HOST -> BIND_ADDRESS if present (old minimal service used HOST)
    host: str | None = Field(default=None, validation_alias="HOST")

    # Behaviour
    refresh_interval: int = Field(
        default=DEFAULT_REFRESH_INTERVAL, validation_alias="REFRESH_INTERVAL"
    )
    max_items: int = Field(default=DEFAULT_MAX_ITEMS, validation_alias="MAX_ITEMS")
    filter_mode: Literal["author", "author_or_publisher", "author_or_collaborator"] = Field(
        default=DEFAULT_FILTER_MODE, validation_alias="FILTER_MODE"
    )
    log_level: str = Field(default=DEFAULT_LOG_LEVEL, validation_alias="LOG_LEVEL")
    log_format: str = Field(default=DEFAULT_LOG_FORMAT, validation_alias="LOG_FORMAT")
    log_file: str | None = Field(default=None, validation_alias="LOG_FILE")
    cache_path: str = Field(default=DEFAULT_CACHE_PATH, validation_alias="CACHE_PATH")

    # Optional hardening
    enable_refresh_endpoint: bool = Field(default=False, validation_alias="ENABLE_REFRESH_ENDPOINT")
    refresh_token: str | None = Field(default=None, validation_alias="REFRESH_TOKEN")

    # Optional extra repos/orgs (comma-separated)
    github_repos: str | None = Field(default=None, validation_alias="GITHUB_REPOS")
    github_org: str | None = Field(default=None, validation_alias="GITHUB_ORG")
    # alias for github_repos
    extra_repos: str | None = Field(default=None, validation_alias="EXTRA_REPOS")

    # When true, skip scanning all owned repos; only scan GITHUB_REPOS / GITHUB_ORG
    skip_full_scan: bool = Field(default=False, validation_alias="SKIP_FULL_SCAN")

    # Caps
    max_repos: int = Field(default=DEFAULT_MAX_REPOS, validation_alias="MAX_REPOS")
    max_pages_per_repo: int = Field(
        default=DEFAULT_MAX_PAGES_PER_REPO, validation_alias="MAX_PAGES_PER_REPO"
    )

    def extra_repo_list(self) -> list[str]:
        import logging

        raw = self.github_repos or self.extra_repos or ""
        if not raw.strip():
            return []
        # comma or whitespace separated
        parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        # filter valid owner/repo
        out = []
        for p in parts:
            if "/" in p:
                out.append(p)
            else:
                logger = logging.getLogger(__name__)
                logger.warning("Ignoring invalid repo %r (expected owner/repo)", p)
        return out

    def extra_org_list(self) -> list[str]:
        raw = self.github_org or ""
        if not raw.strip():
            return []
        return [p.strip() for p in raw.replace(",", " ").split() if p.strip()]

    @field_validator("bind_address")
    @classmethod
    def _validate_bind(cls, v: str) -> str:
        from advisory_rss.server.bind import is_loopback

        if not is_loopback(v):
            raise ValueError(
                f"BIND_ADDRESS={v!r} is not loopback - must be 127.0.0.1 or ::1. Refusing to start."
            )
        return v.strip().strip("[]")

    @field_validator("port")
    @classmethod
    def _validate_port(cls, v: int) -> int:
        if v == 0:
            # allow ephemeral for tests
            return v
        if not (1 <= v <= 65535):
            raise ValueError("PORT must be 1..65535")
        if v < 1024:
            # allow but warn via log elsewhere; not fatal
            pass
        return v

    @field_validator("refresh_interval")
    @classmethod
    def _validate_refresh(cls, v: int) -> int:
        if v < 60:
            raise ValueError("REFRESH_INTERVAL must be >= 60 seconds")
        return v

    @field_validator("max_items")
    @classmethod
    def _validate_max_items(cls, v: int) -> int:
        if v < 1 or v > 10000:
            raise ValueError("MAX_ITEMS must be 1..10000")
        return v

    @field_validator("github_api_base")
    @classmethod
    def _validate_github_api_base(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("GITHUB_API_BASE must be a valid https:// URL")
        raw = v.strip()
        parsed = urlparse(raw)
        if parsed.scheme not in ("https", "http"):
            raise ValueError(
                "GITHUB_API_BASE must be https:// (http allowed only for GHES testing)"
            )
        # http is only allowed for GHES testing - warn if used with api.github.com
        if parsed.scheme == "http" and parsed.hostname == "api.github.com":
            raise ValueError(
                "GITHUB_API_BASE for api.github.com must be https:// (http downgrade not allowed)"
            )
        host = parsed.hostname
        if not host:
            raise ValueError("GITHUB_API_BASE must contain a hostname")
        # Only treat as IP if hostname is a literal IP address
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None  # hostname, not IP - not subject to private range check
        if ip is not None and (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        ):
            raise ValueError(f"GITHUB_API_BASE host {host!r} is private/loopback - not allowed")
        if parsed.username or parsed.password:
            raise ValueError("GITHUB_API_BASE must not contain credentials")
        return raw.rstrip("/")

    @field_validator("cache_path")
    @classmethod
    def _validate_cache_path(cls, v: str) -> str:
        p = Path(v)
        try:
            resolved = (Path.cwd() / p).resolve() if not p.is_absolute() else p.resolve()
        except (OSError, ValueError, RuntimeError) as e:
            raise ValueError(f"CACHE_PATH {v!r} is not resolvable: {e}") from e
        cwd = Path.cwd().resolve()
        tmp = Path("/tmp").resolve()
        allowed_prefixes = [cwd, tmp, cwd / "cache"]
        # Use Path.is_relative_to to avoid prefix-collision bypass (e.g. /tmp-evil vs /tmp)
        if not any(resolved.is_relative_to(ap) for ap in allowed_prefixes):
            raise ValueError(
                f"CACHE_PATH {v!r} must be under project directory or /tmp (got {resolved})"
            )
        return v

    @field_validator("log_level")
    @classmethod
    def _validate_log(cls, v: str) -> str:
        lvl = v.upper().strip()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if lvl not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed} (got {v!r})")
        return lvl

    @field_validator("log_format")
    @classmethod
    def _validate_log_format(cls, v: str) -> str:
        fmt = v.lower().strip()
        if fmt not in ("text", "json"):
            raise ValueError(f"LOG_FORMAT must be 'text' or 'json' (got {v!r})")
        return fmt

    @field_validator("log_file")
    @classmethod
    def _validate_log_file(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        p = Path(v)
        try:
            resolved = (Path.cwd() / p).resolve() if not p.is_absolute() else p.resolve()
        except (OSError, ValueError, RuntimeError) as e:
            raise ValueError(f"LOG_FILE {v!r} is not resolvable: {e}") from e
        cwd = Path.cwd().resolve()
        tmp = Path("/tmp").resolve()
        allowed_prefixes = [cwd, tmp, cwd / "cache", cwd / "logs"]
        if not any(resolved.is_relative_to(ap) for ap in allowed_prefixes):
            raise ValueError(
                f"LOG_FILE {v!r} must be under project directory, cache/, logs/ or /tmp (got {resolved})"
            )
        return str(v).strip()

    def effective_bind_address(self) -> str:
        if self.host and self.bind_address == DEFAULT_BIND_ADDRESS:
            validate_bind_address(self.host)
            return self.host.strip().strip("[]")
        return self.bind_address.strip().strip("[]")

    @property
    def token(self) -> str | None:
        # Priority: GITHUB_TOKEN > GITHUB_PAT > GITHUB_CLIENT_ID
        for t in (self.github_token, self.github_pat, self.github_client_id):
            if t and t.strip() and t.strip() != "ghp_your_token_here":
                return t.strip()
        return None

    def rss_url(self) -> str:
        return f"http://{self.effective_bind_address()}:{self.port}/rss.xml"

    @property
    def resolved_cache_path(self) -> Path:
        # Validated in _validate_cache_path - just return Path
        return Path(self.cache_path)

    def validate_token_present(self) -> None:
        if not self.token:
            raise SystemExit(
                "GITHUB_TOKEN is not set. Set it in .env (GITHUB_TOKEN=ghp_...) or via "
                "`app auth login` or environment. See README 'GitHub PAT privileges'."
            )


def get_settings() -> Settings:
    return Settings()
