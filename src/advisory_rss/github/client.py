# GitHub API client

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.constants import (
    CONNECT_TIMEOUT,
    DEFAULT_PER_PAGE,
    GITHUB_API_VERSION,
    POOL_TIMEOUT,
    READ_TIMEOUT,
    TOKEN_REDACT_PATTERN,
    WRITE_TIMEOUT,
)
from advisory_rss.config.settings import Settings
from advisory_rss.github.filter import filter_advisories
from advisory_rss.github.normalize import normalize_list
from advisory_rss.github.paginate import get_next_url

logger = logging.getLogger(__name__)

_ALLOWED_HOSTS = {"api.github.com"}

TOKEN_RE = re.compile(TOKEN_REDACT_PATTERN)


def _redact(msg: str) -> str:
    return TOKEN_RE.sub("***", msg)


class GitHubError(RuntimeError):
    pass


class AuthError(GitHubError):
    pass


class RateLimitError(GitHubError):
    def __init__(self, msg: str, retry_after: float | None = None):
        super().__init__(msg)
        self.retry_after = retry_after


def _is_rate_limit_response(resp: httpx.Response) -> bool:
    if resp.status_code == 429:
        return True
    if resp.status_code == 403:
        # GitHub returns 403 with X-RateLimit-Remaining 0 or message contains rate
        if resp.headers.get("x-ratelimit-remaining") == "0":
            return True
        try:
            body = resp.text.lower()
            if "rate limit" in body or "secondary rate limit" in body:
                return True
        except (ValueError, RuntimeError, UnicodeDecodeError) as e:
            logger.debug("rate limit body check failed: %s", _redact(str(e)))
    return False


def _parse_retry_after(resp: httpx.Response) -> float | None:
    val = resp.headers.get("retry-after")
    if val:
        try:
            return float(val)
        except ValueError:
            pass
    reset = resp.headers.get("x-ratelimit-reset")
    if reset:
        try:
            reset_ts = float(reset)
            now = time.time()
            delta = reset_ts - now
            if delta > 0:
                return min(delta + 1.0, 900.0)
        except ValueError:
            pass
    return None


class GitHubClient:
    def __init__(self, settings: Settings, token: str, cache: CacheStore | None = None):
        self.settings = settings
        self.token = token
        self.cache = cache
        self.base = settings.github_api_base.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base,
            timeout=httpx.Timeout(
                connect=CONNECT_TIMEOUT,
                read=READ_TIMEOUT,
                write=WRITE_TIMEOUT,
                pool=POOL_TIMEOUT,
            ),
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "advisory-rss/0.2.0",
                "Authorization": f"Bearer {token}",
            },
            follow_redirects=False,
            max_redirects=0,
        )

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except (OSError, RuntimeError, httpx.HTTPError) as e:
            logger.debug("client close failed: %s", _redact(str(e)))

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        max_retries: int = 3,
        use_etag: bool = True,
    ) -> httpx.Response | None:
        parsed = urlparse(url if url.startswith("http") else self.base + url)
        host = parsed.hostname or ""
        base_host = urlparse(self.base).hostname or ""
        if host and host not in _ALLOWED_HOSTS and host != base_host:
            logger.warning("SSRF guard: refusing to fetch non-GitHub host %s", _redact(host))
            raise GitHubError(f"Refusing to fetch non-GitHub host {host}")

        req_headers: dict[str, str] = {}
        if headers:
            req_headers.update(headers)

        should_use_etag = bool(
            use_etag
            and method.upper() == "GET"
            and self.cache is not None
            and "security-advisories" in url
        )

        for attempt in range(max_retries + 1):
            # Prepare headers with ETag if present
            hdrs = dict(req_headers)
            try:
                # Recompute etag key from final URL (including params)
                tmp_req = self._client.build_request(method, url, params=params, headers=hdrs)
                etag_key = str(tmp_req.url)
                if should_use_etag and self.cache is not None:
                    etag = self.cache.get_etag(etag_key)
                    if etag:
                        hdrs["If-None-Match"] = etag
            except (ValueError, RuntimeError, httpx.HTTPError) as e:
                logger.debug("etag key build failed: %s", _redact(str(e)))
                etag_key = url
                hdrs = dict(req_headers)

            try:
                resp = await self._client.request(method, url, params=params, headers=hdrs)
            except (
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.ConnectTimeout,
                httpx.PoolTimeout,
            ) as e:
                if attempt < max_retries:
                    sleep = (0.5 * (2**attempt)) + random.uniform(0, 0.3)
                    logger.warning(
                        "Network error (%s) - retry %d/%d after %.1fs",
                        _redact(str(e)),
                        attempt + 1,
                        max_retries,
                        sleep,
                    )
                    await asyncio.sleep(sleep)
                    continue
                logger.warning("Network failure after retries: %s", _redact(str(e)))
                raise GitHubError(f"Network failure: {e}") from e
            except httpx.TimeoutException as e:
                if attempt < max_retries:
                    sleep = (0.5 * (2**attempt)) + random.uniform(0, 0.3)
                    logger.warning("Timeout (%s) - retry %d", _redact(str(e)), attempt + 1)
                    await asyncio.sleep(sleep)
                    continue
                raise GitHubError(f"Timeout: {e}") from e

            # 304 Not Modified - keep cache
            if resp.status_code == 304:
                # Update meta but return None to signal no new data
                if self.cache is not None:
                    # Keep etag
                    pass
                return None

            # Store ETag if present
            if should_use_etag and resp.status_code == 200 and self.cache is not None:
                etag_resp = resp.headers.get("etag") or resp.headers.get("ETag")
                if etag_resp:
                    try:
                        # Need full URL key as above
                        key = etag_key
                        self.cache.set_etag(key, etag_resp)
                    except (OSError, ValueError, RuntimeError) as e:
                        logger.debug("set_etag failed: %s", _redact(str(e)))

            # Rate limit handling
            if _is_rate_limit_response(resp):
                retry_after = _parse_retry_after(resp)
                sleep = (
                    retry_after
                    if retry_after is not None
                    else (2.0 * (attempt + 1) + random.uniform(0, 0.5))
                )
                if attempt < max_retries:
                    logger.warning(
                        "Rate limited (%d) - sleeping %.1fs (attempt %d/%d)",
                        resp.status_code,
                        sleep,
                        attempt + 1,
                        max_retries,
                    )
                    # Persist rate_limited_until
                    if self.cache is not None:
                        until = datetime.now(UTC).timestamp() + sleep
                        self.cache.set_meta(
                            "rate_limited_until",
                            datetime.fromtimestamp(until, tz=UTC).isoformat(),
                        )
                    await asyncio.sleep(
                        min(sleep, 60.0)
                    )  # don't block too long in single retry loop; will retry
                    continue
                # Out of retries
                raise RateLimitError(_redact(f"Rate limited: {resp.text[:500]}"), retry_after=sleep)

            # Auth errors
            if resp.status_code == 401:
                raise AuthError(
                    _redact(f"401 Unauthorized - invalid or expired token: {resp.text[:300]}")
                )
            if resp.status_code == 403 and not _is_rate_limit_response(resp):
                logger.warning(
                    "403 Forbidden for %s - check PAT scopes (needs repository_advisories:read): %s",
                    _redact(url),
                    _redact(resp.text[:400]),
                )
                return resp

            if resp.status_code == 422:
                logger.warning("422 Validation for %s: %s", _redact(url), _redact(resp.text[:500]))
                return resp

            if 500 <= resp.status_code < 600:
                if attempt < max_retries:
                    sleep = (0.5 * (2**attempt)) + random.uniform(0, 0.3)
                    logger.warning(
                        "GitHub 5xx %d for %s - retry after %.1fs",
                        resp.status_code,
                        _redact(url),
                        sleep,
                    )
                    await asyncio.sleep(sleep)
                    continue
                logger.warning(
                    "GitHub 5xx %d still after retries for %s", resp.status_code, _redact(url)
                )
                raise GitHubError(f"GitHub server error {resp.status_code}: {resp.text[:500]}")

            # Other codes including 200/404 - return
            return resp

        # Should not reach
        raise GitHubError("Exhausted retries")

    async def get_user(self) -> dict[str, Any]:
        # Never use ETag for /user - need fresh login each time
        resp = await self._request_with_retry("GET", "/user", use_etag=False)
        if resp is None:
            # If somehow 304 despite use_etag=False, retry without etag
            resp = await self._request_with_retry("GET", "/user", use_etag=False)
            if resp is None:
                raise GitHubError("Unexpected 304 on /user after retry")
        if resp.status_code != 200:
            raise GitHubError(f"Failed to get user: {resp.status_code} {_redact(resp.text[:500])}")
        try:
            return resp.json()
        except (ValueError, RuntimeError) as e:
            raise GitHubError(f"Malformed /user JSON: {e}") from e

    async def list_repos(self) -> list[dict[str, Any]]:
        # List all repos for authenticated user where affiliation=owner + organization_member.
        # fetch both owner and organization_member to cover personal and org repos.
        seen_full: set[str] = set()
        aggregated: list[dict[str, Any]] = []
        for affiliation in ("owner", "organization_member"):
            url: str | None = "/user/repos"
            params: dict[str, Any] | None = {
                "per_page": DEFAULT_PER_PAGE,
                "affiliation": affiliation,
                "sort": "updated",
                "visibility": "all",
            }
            page = 0
            while url and page < self.settings.max_pages_per_repo * 10:  # bound overall
                resp = await self._request_with_retry(
                    "GET", url, params=params if page == 0 else None, use_etag=False
                )
                # On first paginated Link URL, params already encoded in next_url
                if resp is None:
                    # Should not happen with use_etag=False
                    break
                if resp.status_code == 401:
                    raise AuthError(_redact(f"401 on list_repos: {resp.text[:300]}"))
                if resp.status_code == 404:
                    logger.warning("404 on /user/repos")
                    break
                if resp.status_code != 200:
                    # 403 permission or other
                    logger.warning(
                        "list_repos got %d: %s",
                        resp.status_code,
                        _redact(resp.text[:300]),
                    )
                    break
                try:
                    data = resp.json()
                except (ValueError, RuntimeError) as e:
                    logger.warning("Malformed JSON on /user/repos: %s", e)
                    break
                if not isinstance(data, list):
                    logger.warning("Unexpected repos payload type %s", type(data))
                    break
                for repo in data:
                    full = repo.get("full_name") if isinstance(repo, dict) else None
                    if isinstance(full, str) and full not in seen_full:
                        aggregated.append(repo)
                        seen_full.add(full)
                    elif not isinstance(full, str):
                        aggregated.append(repo)
                if len(aggregated) >= self.settings.max_repos:
                    logger.warning(
                        "Hit MAX_REPOS=%d - truncating (set MAX_REPOS higher if needed)",
                        self.settings.max_repos,
                    )
                    break
                # pagination via Link
                next_url = get_next_url(resp.headers.get("link") or resp.headers.get("Link"))
                if next_url:
                    url = next_url
                    params = None  # already in next_url
                    page += 1
                else:
                    break
            if len(aggregated) >= self.settings.max_repos:
                break
        return aggregated

    async def list_user_orgs(self) -> list[dict[str, Any]]:
        resp = await self._request_with_retry(
            "GET", "/user/orgs", params={"per_page": DEFAULT_PER_PAGE}, use_etag=False
        )
        if resp is None or resp.status_code != 200:
            return []
        try:
            data = resp.json()
            return data if isinstance(data, list) else []
        except (ValueError, RuntimeError) as e:
            logger.debug("list_user_orgs json failed: %s", _redact(str(e)))
            return []

    async def list_repo_advisories_for_repo(
        self, owner: str, repo: str, *, states: list[str] | None = None
    ) -> list[dict[str, Any]]:
        if states is None:
            states = ["triage", "draft", "published", "closed"]
        all_raw: list[dict[str, Any]] = []
        for state in states:
            url = f"/repos/{owner}/{repo}/security-advisories"
            params = {
                "per_page": DEFAULT_PER_PAGE,
                "sort": "updated",
                "direction": "desc",
                "state": state,
            }
            # pagination loop for this state shard
            shard_url: str | None = url
            shard_params: dict[str, Any] | None = params
            page = 0
            while shard_url and page < self.settings.max_pages_per_repo:
                resp = await self._request_with_retry("GET", shard_url, params=shard_params)
                if resp is None:
                    # 304 - treat as no new data for this shard; but we already have cache, so skip
                    break
                if resp.status_code == 401:
                    raise AuthError(_redact(f"401 on repo {owner}/{repo} state={state}"))
                if resp.status_code in (403, 404):
                    # 404 = repo not found or no access; 403 = insufficient scopes / PAT repo access
                    if resp.status_code == 404:
                        logger.debug(
                            "No advisories or repo not found: %s/%s state=%s (404)",
                            owner,
                            repo,
                            state,
                        )
                    else:
                        # 403 often means fine-grained PAT does not include this repo/organization
                        # body contains "Resource not accessible by personal access token"
                        body = _redact(resp.text[:400])
                        logger.warning(
                            "403 for %s/%s state=%s - check PAT scopes and Repository Access (needs that repo in fine-grained PAT's Selected repositories): %s",
                            owner,
                            repo,
                            state,
                            body,
                        )
                    break
                if resp.status_code != 200:
                    logger.warning(
                        "Unexpected %d for %s/%s state=%s: %s",
                        resp.status_code,
                        owner,
                        repo,
                        state,
                        _redact(resp.text[:300]),
                    )
                    break
                try:
                    data = resp.json()
                except (ValueError, RuntimeError) as e:
                    logger.warning("Malformed JSON for %s/%s state=%s: %s", owner, repo, state, e)
                    break
                if not isinstance(data, list):
                    logger.warning("Unexpected payload type for %s/%s state=%s", owner, repo, state)
                    break
                # inject repo identifier for normalization
                for item in data:
                    if isinstance(item, dict) and "_injected_repo" not in item:
                        item["_injected_repo"] = f"{owner}/{repo}"
                if not data:
                    break
                all_raw.extend(data)
                next_url = get_next_url(resp.headers.get("link") or resp.headers.get("Link"))
                if next_url:
                    shard_url = next_url
                    shard_params = None
                    page += 1
                else:
                    break
            # per-state done
        return all_raw

    async def list_org_advisories(self, org: str) -> list[dict[str, Any]]:
        all_raw: list[dict[str, Any]] = []
        for state in ["triage", "draft", "published", "closed"]:
            url = f"/orgs/{org}/security-advisories"
            params = {
                "per_page": DEFAULT_PER_PAGE,
                "sort": "updated",
                "direction": "desc",
                "state": state,
            }
            shard_url: str | None = url
            shard_params: dict[str, Any] | None = params
            page = 0
            while shard_url and page < self.settings.max_pages_per_repo:
                resp = await self._request_with_retry("GET", shard_url, params=shard_params)
                if resp is None:
                    break
                if resp.status_code in (403, 404):
                    # Not authorized as org owner - expected fallback to repo enumeration
                    if page == 0:
                        logger.debug(
                            "Org %s not accessible for state=%s (%d) - falling back to repo list",
                            org,
                            state,
                            resp.status_code,
                        )
                    break
                if resp.status_code != 200:
                    logger.warning(
                        "Org advisory %d for %s state=%s: %s",
                        resp.status_code,
                        org,
                        state,
                        _redact(resp.text[:300]),
                    )
                    break
                try:
                    data = resp.json()
                except (ValueError, RuntimeError) as e:
                    logger.warning("Malformed JSON org %s state=%s: %s", org, state, e)
                    break
                if not isinstance(data, list) or not data:
                    if not data:
                        break
                    break
                for item in data:
                    if isinstance(item, dict) and "_injected_repo" not in item:
                        # org advisories may not map 1:1 to repo_full; keep org hint
                        item["_injected_repo"] = f"{org}/*"
                all_raw.extend(data)
                next_url = get_next_url(resp.headers.get("link") or resp.headers.get("Link"))
                if next_url:
                    shard_url = next_url
                    shard_params = None
                    page += 1
                else:
                    break
        return all_raw

    async def sync_all(
        self, *, authenticated_login: str | None = None, filter_mode: str = "author"
    ) -> tuple[list[NormalizedAdvisory], dict[str, Any]]:
        diag: dict[str, Any] = {
            "repos_scanned": 0,
            "orgs_scanned": 0,
            "raw_count": 0,
            "errors": [],
        }
        # Resolve login if not provided
        if not authenticated_login:
            user = await self.get_user()
            authenticated_login = user.get("login") or user.get("name") or ""
            if not authenticated_login:
                raise GitHubError("Cannot resolve authenticated user login")
        # List orgs and repos
        # Attempt org-wide first to reduce per-repo calls
        orgs_raw = await self.list_user_orgs()
        org_names = [o.get("login") for o in orgs_raw if isinstance(o, dict) and o.get("login")]
        # Collect from org advisories
        aggregated_raw: list[dict[str, Any]] = []
        for org in org_names:
            if not org:
                continue
            try:
                raw = await self.list_org_advisories(org)
                diag["orgs_scanned"] += 1
                if raw:
                    aggregated_raw.extend(raw)
            except (AuthError, RateLimitError):
                raise
            except (OSError, ValueError, RuntimeError, httpx.HTTPError) as e:
                diag["errors"].append(_redact(f"org {org}: {e}"))

        if self.settings.skip_full_scan:
            repos: list[dict[str, Any]] = []
            logger.info(
                "SKIP_FULL_SCAN=true - skipping full owner/member enumeration, only scanning GITHUB_REPOS/GITHUB_ORG"
            )
        else:
            repos = await self.list_repos()
        # Also include extra repos/orgs from config (e.g., your-org/your-repo if not in affiliation list)
        extra_repos = self.settings.extra_repo_list()
        extra_orgs = self.settings.extra_org_list()
        if self.settings.skip_full_scan and not extra_repos and not extra_orgs:
            msg = "SKIP_FULL_SCAN=true but no GITHUB_REPOS/GITHUB_ORG set - nothing to scan"
            logger.error(msg)
            diag["errors"].append(msg)
            # Persist error to cache for observability
            if self.cache is not None:
                try:
                    self.cache.mark_error(msg)
                except (OSError, ValueError, RuntimeError) as e:
                    logger.debug("mark_error failed: %s", _redact(str(e)))
            diag["repos_scanned"] = 0
            diag["raw_count"] = 0
            diag["normalized_count"] = 0
            diag["filtered_count"] = 0
            diag["authenticated_login"] = authenticated_login
            return [], diag
        # Expand extra orgs into repo list via /orgs/{org}/repos?per_page=100
        for org in extra_orgs:
            try:
                # Re-use _request_with_retry for org repos (no etag)
                org_repos = []
                url = f"/orgs/{org}/repos"
                params = {"per_page": DEFAULT_PER_PAGE, "sort": "updated"}
                page = 0
                nxt: str | None = url
                p: dict[str, Any] | None = params
                while nxt and page < self.settings.max_pages_per_repo:
                    resp = await self._request_with_retry("GET", nxt, params=p, use_etag=False)
                    if resp is None or resp.status_code != 200:
                        break
                    try:
                        data = resp.json()
                    except (ValueError, RuntimeError) as e:
                        logger.debug("org repos json failed %s: %s", org, _redact(str(e)))
                        break
                    if not isinstance(data, list):
                        break
                    org_repos.extend(data)
                    nxt = get_next_url(resp.headers.get("link") or resp.headers.get("Link"))
                    p = None
                    page += 1
                for gr in org_repos:
                    full = gr.get("full_name") if isinstance(gr, dict) else None
                    if isinstance(full, str) and not any(r.get("full_name") == full for r in repos):
                        repos.append(gr)
            except (OSError, ValueError, RuntimeError, httpx.HTTPError) as e:
                diag["errors"].append(_redact(f"extra org {org}: {e}"))
        # Add explicit extra repos (even if not in affiliation list) - fetch repo object minimal
        for full in extra_repos:
            if any(r.get("full_name") == full for r in repos):
                continue
            # need to ensure repo exists - we create minimal stub; advisory fetch will 404 if not accessible and be skipped
            if "/" in full:
                owner, name = full.split("/", 1)
                repos.append({"full_name": full, "owner": {"login": owner}, "name": name})
        diag["repos_scanned"] = len(repos)
        if extra_repos or extra_orgs:
            logger.info("Including extra repos %s and orgs %s", extra_repos, extra_orgs)
        # For each repo, fetch advisories
        # Deduplicate by owner/repo to avoid duplicates from org+repo scans? We'll dedup later by ghsa_id
        for r in repos:
            if not isinstance(r, dict):
                continue
            full = r.get("full_name") or ""
            if "/" not in full:
                continue
            owner, repo = full.split("/", 1)
            # Bound overall repos
            if len(aggregated_raw) > 20000:
                logger.warning("Aggregated raw advisories exceeded 20k - bounding")
                break
            try:
                raws = await self.list_repo_advisories_for_repo(owner, repo)
                if raws:
                    aggregated_raw.extend(raws)
            except (AuthError, RateLimitError):
                raise
            except (OSError, ValueError, RuntimeError, httpx.HTTPError) as e:
                diag["errors"].append(_redact(f"repo {full}: {e}"))
                continue
            # small cooperative yield
            await asyncio.sleep(0)

        diag["raw_count"] = len(aggregated_raw)
        # Normalize with error tolerance (one bad advisory doesn't kill sync)
        normalized = normalize_list(aggregated_raw)
        # Filter by author
        filtered = filter_advisories(normalized, authenticated_login, mode=filter_mode)
        # Dedup by ghsa_id (keep most recent updated_at)
        seen: dict[str, NormalizedAdvisory] = {}
        for adv in filtered:
            prev = seen.get(adv.ghsa_id)
            if prev is None or adv.sort_key() > prev.sort_key():
                seen[adv.ghsa_id] = adv
        deduped = list(seen.values())
        # Sort updated_at DESC for cache ordering
        deduped.sort(key=lambda a: a.sort_key(), reverse=True)
        diag["normalized_count"] = len(normalized)
        diag["filtered_count"] = len(deduped)
        diag["authenticated_login"] = authenticated_login
        return deduped, diag
