# Normalize raw GitHub advisory JSON to NormalizedAdvisory - tolerant to missing field

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from advisory_rss.cache.models import NormalizedAdvisory

logger = logging.getLogger(__name__)


def _parse_dt(v: Any) -> datetime | None:
    if not v or not isinstance(v, str):
        return None
    try:
        s = v.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError, AttributeError):
        return None


def _get_first_vuln(vulns: Any) -> dict[str, Any] | None:
    if not isinstance(vulns, list) or not vulns:
        return None
    for v in vulns:
        if isinstance(v, dict):
            return v
    return None


def normalize_advisory(raw: dict[str, Any]) -> NormalizedAdvisory | None:
    try:
        ghsa = raw.get("ghsa_id") or raw.get("ghsaId") or ""
        if not ghsa:
            ghsa = raw.get("id") or ""
        ghsa = str(ghsa).strip()
        if not ghsa:
            logger.warning("Skipping advisory with no GHSA id: keys=%s", list(raw.keys())[:10])
            return None

        # cve
        cve = raw.get("cve_id")
        if cve is not None:
            cve = str(cve).strip() or None

        summary = str(raw.get("summary") or raw.get("title") or ghsa).strip()
        # guard length? summary max 1024 but just keep
        description = str(raw.get("description") or "").strip()

        severity = raw.get("severity")
        if severity is not None:
            severity = str(severity).lower().strip() or None
            # normalize: high / moderate etc
            if severity not in {
                "critical",
                "high",
                "medium",
                "moderate",
                "low",
                "unknown",
            }:
                # keep as is but lowercase
                pass
            if severity == "moderate":
                severity = "medium"  # REST uses medium vs GraphQL MODERATE

        # vulnerabilities
        vulns = raw.get("vulnerabilities")
        vuln = _get_first_vuln(vulns)
        package_ecosystem = None
        package_name = None
        vulnerable_range = None
        patched = None
        if vuln:
            pkg = vuln.get("package") or {}
            if isinstance(pkg, dict):
                package_ecosystem = pkg.get("ecosystem")
                package_name = pkg.get("name")
                if package_ecosystem:
                    package_ecosystem = str(package_ecosystem).lower().strip()
                if package_name:
                    package_name = str(package_name).strip() or None
            vulnerable_range = vuln.get("vulnerable_version_range")
            if vulnerable_range is not None:
                vulnerable_range = str(vulnerable_range).strip() or None
            # patched_versions can be under patched_versions or first_patched_version
            patched = (
                vuln.get("patched_versions")
                or vuln.get("patched_version")
                or vuln.get("first_patched_version")
            )
            if isinstance(patched, dict):
                patched = patched.get("identifier")
            if patched is not None:
                patched = str(patched).strip() or None
            # vulnerable_functions not needed for RSS but keep raw

        # dates
        published = _parse_dt(raw.get("published_at") or raw.get("publishedAt"))
        updated = _parse_dt(raw.get("updated_at") or raw.get("updatedAt"))
        withdrawn = _parse_dt(raw.get("withdrawn_at") or raw.get("withdrawnAt"))
        created = _parse_dt(raw.get("created_at") or raw.get("createdAt"))

        state = str(raw.get("state") or "published").strip().lower()

        # urls
        html_url = str(raw.get("html_url") or raw.get("url") or "").strip()
        if not html_url and ghsa:
            html_url = f"https://github.com/advisories/{ghsa}"

        # repository URL - repo may be under raw["private_fork"] or not present. Prefer repository info if listed
        repo_url = None
        repo_full = None
        # raw may have been fetched via /repos/{owner}/{repo} - we can inject repo_full via caller
        # Check private_fork
        pf = raw.get("private_fork")
        if isinstance(pf, dict):
            repo_url = pf.get("html_url") or repo_url
            repo_full = pf.get("full_name") or repo_full
        # Check source_code_location for global advisories
        scl = raw.get("source_code_location")
        if isinstance(scl, str) and scl and not repo_url:
            repo_url = scl
        # _injected_repo fallback set by client
        if "_injected_repo" in raw:
            repo_full = repo_full or raw.get("_injected_repo")

        references = []
        refs = raw.get("references")
        if isinstance(refs, list):
            for r in refs:
                if isinstance(r, str) and r.strip():
                    references.append(r.strip())
                elif isinstance(r, dict) and r.get("url"):
                    references.append(str(r["url"]))
        elif isinstance(refs, str) and refs.strip():
            references.append(refs.strip())

        # repository_advisory_url for global
        repo_adv_url = raw.get("repository_advisory_url")
        if (
            isinstance(repo_adv_url, str)
            and repo_adv_url.strip()
            and (not html_url or "advisories" not in html_url)
        ):
            # Keep html_url as primary but add repo_advisory_url as reference if not already present
            clean = repo_adv_url.strip()
            if clean not in references:
                references.append(clean)

        author_login = None
        author = raw.get("author")
        if isinstance(author, dict):
            author_login = author.get("login")
            if author_login:
                author_login = str(author_login).strip() or None

        publisher_login = None
        publisher = raw.get("publisher")
        if isinstance(publisher, dict):
            publisher_login = publisher.get("login")
            if publisher_login:
                publisher_login = str(publisher_login).strip() or None

        identifiers = raw.get("identifiers") or []
        if not isinstance(identifiers, list):
            identifiers = []

        return NormalizedAdvisory(
            ghsa_id=ghsa,
            cve_id=cve,
            summary=summary,
            description=description,
            severity=severity,
            package_ecosystem=package_ecosystem,
            package_name=package_name,
            vulnerable_version_range=vulnerable_range,
            patched_versions=patched,
            affected_versions=vulnerable_range,
            published_at=published,
            updated_at=updated,
            withdrawn_at=withdrawn,
            created_at=created,
            state=state,
            html_url=html_url,
            repository_url=repo_url,
            repository_full_name=repo_full,
            references=references,
            author_login=author_login,
            publisher_login=publisher_login,
            identifiers=identifiers,
            raw=raw,
        )
    except (ValueError, TypeError, AttributeError, KeyError, RuntimeError) as e:
        logger.warning("normalize_advisory failed for ghsa=%s: %s", raw.get("ghsa_id"), e)
        return None


def normalize_list(raw_list: list[dict[str, Any]]) -> list[NormalizedAdvisory]:
    logger.debug("normalize_list input=%d", len(raw_list))
    out: list[NormalizedAdvisory] = []
    skipped = 0
    for raw in raw_list:
        try:
            if not isinstance(raw, dict):
                skipped += 1
                continue
            adv = normalize_advisory(raw)
            if adv:
                out.append(adv)
            else:
                skipped += 1
        except (ValueError, TypeError, AttributeError, KeyError, RuntimeError) as e:
            logger.warning("Skipping malformed advisory: %s", e)
            skipped += 1
            continue
    logger.info(
        "normalize_list done input=%d normalized=%d skipped=%d", len(raw_list), len(out), skipped
    )
    return out
