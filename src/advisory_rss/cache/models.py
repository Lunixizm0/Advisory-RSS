"""Normalized advisory dataclass and cache meta."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class NormalizedAdvisory:
    ghsa_id: str
    cve_id: str | None = None
    summary: str = ""
    description: str = ""
    severity: str | None = None
    package_ecosystem: str | None = None
    package_name: str | None = None
    vulnerable_version_range: str | None = None
    patched_versions: str | None = None
    affected_versions: str | None = None  # alias of vulnerable_version_range for legacy
    published_at: datetime | None = None
    updated_at: datetime | None = None
    withdrawn_at: datetime | None = None
    created_at: datetime | None = None
    state: str = "published"
    html_url: str = ""
    repository_url: str | None = None
    repository_full_name: str | None = None
    references: list[str] = field(default_factory=list)
    author_login: str | None = None
    publisher_login: str | None = None
    identifiers: list[dict[str, str]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def sort_key(self) -> datetime:
        # Use updated_at > published_at > created_at > distant past
        for dt in (self.updated_at, self.published_at, self.created_at):
            if dt is not None:
                # ensure tz aware
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
        return datetime(1970, 1, 1, tzinfo=UTC)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # serialize datetimes as ISO
        for k in ("published_at", "updated_at", "withdrawn_at", "created_at"):
            v = d[k]
            if isinstance(v, datetime):
                d[k] = v.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NormalizedAdvisory:
        def _parse(v: str | None) -> datetime | None:
            if not v:
                return None
            try:
                # handle Z suffix
                if v.endswith("Z"):
                    v = v[:-1] + "+00:00"
                dt = datetime.fromisoformat(v)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except (ValueError, TypeError, AttributeError):
                return None

        adv = cls(
            ghsa_id=data.get("ghsa_id", ""),
            cve_id=data.get("cve_id"),
            summary=data.get("summary", ""),
            description=data.get("description", ""),
            severity=data.get("severity"),
            package_ecosystem=data.get("package_ecosystem"),
            package_name=data.get("package_name"),
            vulnerable_version_range=data.get("vulnerable_version_range"),
            patched_versions=data.get("patched_versions"),
            affected_versions=data.get("affected_versions"),
            published_at=_parse(data.get("published_at")),
            updated_at=_parse(data.get("updated_at")),
            withdrawn_at=_parse(data.get("withdrawn_at")),
            created_at=_parse(data.get("created_at")),
            state=data.get("state", "published"),
            html_url=data.get("html_url", ""),
            repository_url=data.get("repository_url"),
            repository_full_name=data.get("repository_full_name"),
            references=list(data.get("references") or []),
            author_login=data.get("author_login"),
            publisher_login=data.get("publisher_login"),
            identifiers=list(data.get("identifiers") or []),
            raw=data.get("raw") or {},
        )
        return adv


@dataclass
class CacheMeta:
    last_successful_sync: str | None = None  # ISO
    next_scheduled_sync: str | None = None
    advisories_count: int = 0
    rate_limited_until: str | None = None
    last_error: str | None = None
    authenticated_user: str | None = None
