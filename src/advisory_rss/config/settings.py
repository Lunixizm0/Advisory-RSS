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
    DEFAULT_CERT_TR_ENABLED,
    DEFAULT_CERT_TR_SENDER_ALLOWLIST,
    DEFAULT_FILTER_MODE,
    DEFAULT_GITHUB_API_BASE,
    DEFAULT_GMAIL_FOLDER,
    DEFAULT_GMAIL_IMAP_HOST,
    DEFAULT_GMAIL_IMAP_PORT,
    DEFAULT_GMAIL_IMAP_SECURITY,
    DEFAULT_LOG_FORMAT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MAX_ITEMS,
    DEFAULT_MAX_PAGES_PER_REPO,
    DEFAULT_MAX_REPOS,
    DEFAULT_PORT,
    DEFAULT_PROTON_FOLDER,
    DEFAULT_PROTON_IMAP_HOST,
    DEFAULT_PROTON_IMAP_PORT,
    DEFAULT_PROTON_IMAP_SECURITY,
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

    # Cert-TR / Proton Mail (multi-account, per-mailbox folder)
    enable_cert_tr: bool = Field(
        default=DEFAULT_CERT_TR_ENABLED, validation_alias="ENABLE_CERT_TR"
    )
    proton_bridge_email: str | None = Field(default=None, validation_alias="PROTON_BRIDGE_EMAIL")
    proton_bridge_password: str | None = Field(
        default=None, validation_alias="PROTON_BRIDGE_PASSWORD"
    )
    proton_bridge_host: str = Field(
        default=DEFAULT_PROTON_IMAP_HOST, validation_alias="PROTON_BRIDGE_HOST"
    )
    proton_imap_port: int = Field(
        default=DEFAULT_PROTON_IMAP_PORT, validation_alias="PROTON_IMAP_PORT"
    )
    proton_imap_security: str = Field(
        default=DEFAULT_PROTON_IMAP_SECURITY, validation_alias="PROTON_IMAP_SECURITY"
    )
    proton_imap_folder: str = Field(
        default=DEFAULT_PROTON_FOLDER, validation_alias="PROTON_IMAP_FOLDER"
    )
    # Multi-account overrides (comma/space separated)
    proton_bridge_emails: str | None = Field(
        default=None, validation_alias="PROTON_BRIDGE_EMAILS"
    )
    proton_bridge_passwords: str | None = Field(
        default=None, validation_alias="PROTON_BRIDGE_PASSWORDS"
    )
    proton_imap_folders: str | None = Field(
        default=None, validation_alias="PROTON_IMAP_FOLDERS"
    )
    # Gmail (alternative IMAP for CERT-TR, e.g., imap.gmail.com)
    gmail_email: str | None = Field(default=None, validation_alias="GMAIL_EMAIL")
    gmail_app_password: str | None = Field(
        default=None, validation_alias="GMAIL_APP_PASSWORD"
    )
    gmail_password: str | None = Field(default=None, validation_alias="GMAIL_PASSWORD")
    gmail_imap_host: str = Field(
        default=DEFAULT_GMAIL_IMAP_HOST, validation_alias="GMAIL_IMAP_HOST"
    )
    gmail_imap_port: int = Field(
        default=DEFAULT_GMAIL_IMAP_PORT, validation_alias="GMAIL_IMAP_PORT"
    )
    gmail_imap_security: str = Field(
        default=DEFAULT_GMAIL_IMAP_SECURITY, validation_alias="GMAIL_IMAP_SECURITY"
    )
    gmail_imap_folder: str = Field(
        default=DEFAULT_GMAIL_FOLDER, validation_alias="GMAIL_IMAP_FOLDER"
    )
    gmail_emails: str | None = Field(default=None, validation_alias="GMAIL_EMAILS")
    gmail_app_passwords: str | None = Field(
        default=None, validation_alias="GMAIL_APP_PASSWORDS"
    )
    gmail_imap_folders: str | None = Field(
        default=None, validation_alias="GMAIL_IMAP_FOLDERS"
    )
    # Optional: per-account JSON-like override not needed; plural fields suffice
    cert_tr_sender_allowlist: str = Field(
        default=DEFAULT_CERT_TR_SENDER_ALLOWLIST,
        validation_alias="CERT_TR_SENDER_ALLOWLIST",
    )
    cert_tr_max_mails: int = Field(default=200, validation_alias="CERT_TR_MAX_MAILS")
    cert_tr_search_days: int | None = Field(
        default=None, validation_alias="CERT_TR_SEARCH_DAYS"
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

    @field_validator("proton_imap_security")
    @classmethod
    def _validate_proton_security(cls, v: str) -> str:
        lvl = (v or DEFAULT_PROTON_IMAP_SECURITY).strip().upper()
        if lvl not in {"STARTTLS", "SSL", "NONE"}:
            raise ValueError("PROTON_IMAP_SECURITY must be STARTTLS|SSL|NONE")
        return lvl

    @field_validator("proton_imap_folder")
    @classmethod
    def _validate_proton_folder(cls, v: str) -> str:
        fv = (v or DEFAULT_PROTON_FOLDER).strip()
        if not fv:
            return DEFAULT_PROTON_FOLDER
        # Allow IMAP hierarchy chars: letters, digits, /, ., -, _, space, brackets for Gmail
        import re

        if len(fv) > 100:
            raise ValueError("PROTON_IMAP_FOLDER too long")
        if not re.match(r"^[\w .\-/\[\]]+$", fv):
            raise ValueError(f"PROTON_IMAP_FOLDER {fv!r} contains invalid chars")
        return fv

    @field_validator("proton_imap_folders")
    @classmethod
    def _validate_proton_folders(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return v
        import re

        raw = str(v).strip()
        if len(raw) > 500:
            raise ValueError("PROTON_IMAP_FOLDERS too long")
        # split only on comma/semicolon to preserve spaces/brackets inside folder names
        parts = [p.strip() for p in re.split(r"[;,]+", raw) if p.strip()]
        # if no comma/semicolon but spaces, fallback to comma/whitespace split for backward compat
        if len(parts) == 1 and "," not in raw and ";" not in raw:
            parts = [p.strip() for p in re.split(r"[,\s;]+", raw) if p.strip()]
        for p in parts:
            if len(p) > 100 or not re.match(r"^[\w .\-/\[\]]+$", p):
                raise ValueError(f"PROTON_IMAP_FOLDERS entry {p!r} invalid")
        return v

    @field_validator("gmail_imap_security")
    @classmethod
    def _validate_gmail_security(cls, v: str) -> str:
        lvl = (v or DEFAULT_GMAIL_IMAP_SECURITY).strip().upper()
        if lvl not in {"STARTTLS", "SSL", "NONE"}:
            raise ValueError("GMAIL_IMAP_SECURITY must be STARTTLS|SSL|NONE")
        return lvl

    @field_validator("gmail_imap_folder")
    @classmethod
    def _validate_gmail_folder(cls, v: str) -> str:
        fv = (v or DEFAULT_GMAIL_FOLDER).strip()
        if not fv:
            return DEFAULT_GMAIL_FOLDER
        import re

        if len(fv) > 100:
            raise ValueError("GMAIL_IMAP_FOLDER too long")
        if not re.match(r"^[\w .\-/\[\]]+$", fv):
            raise ValueError(f"GMAIL_IMAP_FOLDER {fv!r} contains invalid chars")
        return fv

    @field_validator("gmail_imap_folders")
    @classmethod
    def _validate_gmail_folders(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return v
        import re

        raw = str(v).strip()
        if len(raw) > 500:
            raise ValueError("GMAIL_IMAP_FOLDERS too long")
        parts = [p.strip() for p in re.split(r"[;,]+", raw) if p.strip()]
        if len(parts) == 1 and "," not in raw and ";" not in raw:
            parts = [p.strip() for p in re.split(r"[,\s;]+", raw) if p.strip()]
        for p in parts:
            if len(p) > 100 or not re.match(r"^[\w .\-/\[\]]+$", p):
                raise ValueError(f"GMAIL_IMAP_FOLDERS entry {p!r} invalid")
        return v

    @field_validator("cert_tr_max_mails")
    @classmethod
    def _validate_cert_tr_max(cls, v: int) -> int:
        if not (1 <= v <= 5000):
            raise ValueError("CERT_TR_MAX_MAILS must be 1..5000")
        return v

    @field_validator("cert_tr_search_days")
    @classmethod
    def _validate_search_days(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (0 <= v <= 3650):
            raise ValueError("CERT_TR_SEARCH_DAYS must be 0..3650 or empty (all)")
        return v

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

    def _split_list(self, raw: str | None) -> list[str]:
        if not raw or not raw.strip():
            return []
        # comma, whitespace or semicolon separated, keep non-empty
        import re

        parts = re.split(r"[,\s;]+", raw.strip())
        return [p.strip() for p in parts if p.strip()]

    def get_proton_accounts(self) -> list[dict[str, str]]:
        """Resolve multi-account Proton config.

        Supports:
          - Single: PROTON_BRIDGE_EMAIL + PROTON_BRIDGE_PASSWORD + PROTON_IMAP_FOLDER
          - Multi:  PROTON_BRIDGE_EMAILS= a@proton.me,b@proton.me
                    PROTON_BRIDGE_PASSWORDS= pass1,pass2
                    PROTON_IMAP_FOLDERS= INBOX,INBOX.CERT-TR
                    Indices aligned; missing values fallback to single/defaults.
        Each account is {email, password, folder, host, port, security}.
        Folder defaults to PROTON_IMAP_FOLDER / INBOX if not per-account.
        """
        emails: list[str] = []
        passwords: list[str] = []
        folders: list[str] = []

        if self.proton_bridge_emails and self.proton_bridge_emails.strip():
            emails = self._split_list(self.proton_bridge_emails)
            if self.proton_bridge_passwords:
                passwords = self._split_list(self.proton_bridge_passwords)
            if self.proton_imap_folders:
                folders = self._split_list(self.proton_imap_folders)
        elif self.proton_bridge_email and self.proton_bridge_email.strip():
            emails = [self.proton_bridge_email.strip()]
            if self.proton_bridge_password:
                passwords = [self.proton_bridge_password.strip()]
            # folder for single: use explicit plural if set else singular
            if self.proton_imap_folders and self.proton_imap_folders.strip():
                folders = self._split_list(self.proton_imap_folders)
            else:
                folders = [self.proton_imap_folder.strip() or DEFAULT_PROTON_FOLDER]
        else:
            return []

        # Align lengths: pad passwords/folders with defaults
        out: list[dict[str, str]] = []
        default_folder = (self.proton_imap_folder or DEFAULT_PROTON_FOLDER).strip() or DEFAULT_PROTON_FOLDER
        # If single password provided but multiple emails, reuse it
        if len(passwords) == 1 and len(emails) > 1:
            passwords = passwords * len(emails)
        for idx, email in enumerate(emails):
            if not email or "@" not in email:
                continue
            pw = ""
            if idx < len(passwords):
                pw = passwords[idx]
            elif passwords:
                pw = passwords[0]
            elif self.proton_bridge_password:
                pw = self.proton_bridge_password
            folder = default_folder
            if idx < len(folders) and folders[idx]:
                folder = folders[idx]
            # Normalize folder: strip but keep case (IMAP case-sensitive usually)
            folder = folder.strip() or default_folder
            out.append(
                {
                    "email": email.strip(),
                    "password": pw.strip() if pw else "",
                    "folder": folder,
                    "host": (self.proton_bridge_host or DEFAULT_PROTON_IMAP_HOST).strip(),
                    "port": str(self.proton_imap_port),
                    "security": (self.proton_imap_security or DEFAULT_PROTON_IMAP_SECURITY).strip().upper(),
                }
            )
        return out

    def get_gmail_accounts(self) -> list[dict[str, str]]:
        """Resolve Gmail IMAP accounts for CERT-TR.

        Supports single (GMAIL_EMAIL + GMAIL_APP_PASSWORD) and
        multi (GMAIL_EMAILS, GMAIL_APP_PASSWORDS comma-separated,
        GMAIL_IMAP_FOLDERS).  Host/port/security are shared per Gmail
        config (defaults imap.gmail.com:993 SSL).
        Each account is {email,password,folder,host,port,security,provider}.
        """
        emails: list[str] = []
        passwords: list[str] = []
        folders: list[str] = []

        # Helper to split passwords preserving internal spaces (comma-only)
        def _split_passwords(raw: str | None) -> list[str]:
            if not raw or not raw.strip():
                return []
            # split only on comma, keep internal spaces
            parts = [p.strip() for p in raw.split(",")]
            return [p for p in parts if p]

        if self.gmail_emails and self.gmail_emails.strip():
            emails = self._split_list(self.gmail_emails)
            if self.gmail_app_passwords:
                passwords = _split_passwords(self.gmail_app_passwords)
            elif self.gmail_app_password or self.gmail_password:
                # single fallback handled later
                pass
            if self.gmail_imap_folders:
                folders = self._split_list(self.gmail_imap_folders)
        elif self.gmail_email and self.gmail_email.strip():
            emails = [self.gmail_email.strip()]
            # Prefer app password, fallback to GMAIL_PASSWORD alias
            pw = self.gmail_app_password or self.gmail_password
            if pw:
                passwords = [pw.strip()]
            if self.gmail_imap_folders and self.gmail_imap_folders.strip():
                folders = self._split_list(self.gmail_imap_folders)
            else:
                folders = [self.gmail_imap_folder.strip() or DEFAULT_GMAIL_FOLDER]
        else:
            return []

        out: list[dict[str, str]] = []
        default_folder = (self.gmail_imap_folder or DEFAULT_GMAIL_FOLDER).strip() or DEFAULT_GMAIL_FOLDER
        if len(passwords) == 1 and len(emails) > 1:
            passwords = passwords * len(emails)
        for idx, email in enumerate(emails):
            if not email or "@" not in email:
                continue
            pw = ""
            if idx < len(passwords):
                pw = passwords[idx]
            elif passwords:
                pw = passwords[0]
            else:
                # fallback single
                single_pw = self.gmail_app_password or self.gmail_password
                pw = single_pw or ""
            folder = default_folder
            if idx < len(folders) and folders[idx]:
                folder = folders[idx]
            folder = folder.strip() or default_folder
            out.append(
                {
                    "email": email.strip(),
                    "password": pw.strip() if pw else "",
                    "folder": folder,
                    "host": (self.gmail_imap_host or DEFAULT_GMAIL_IMAP_HOST).strip(),
                    "port": str(self.gmail_imap_port),
                    "security": (self.gmail_imap_security or DEFAULT_GMAIL_IMAP_SECURITY).strip().upper(),
                    "provider": "gmail",
                }
            )
        return out

    def get_cert_tr_accounts(self) -> list[dict[str, str]]:
        """Unified CERT-TR IMAP accounts: Proton + Gmail.

        Each entry is {email,password,folder,host,port,security,provider}.
        Proton entries have provider 'proton', Gmail 'gmail'.
        """
        proton = self.get_proton_accounts()
        for p in proton:
            p.setdefault("provider", "proton")
        gmail = self.get_gmail_accounts()
        # gmail already has provider
        return proton + gmail

    def cert_tr_sender_list(self) -> list[str]:
        if not self.cert_tr_sender_allowlist or not self.cert_tr_sender_allowlist.strip():
            return [DEFAULT_CERT_TR_SENDER_ALLOWLIST]
        return [s.strip().lower() for s in self._split_list(self.cert_tr_sender_allowlist) if s.strip()]

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
