#!/usr/bin/env python3
"""Generate real GitHub API fixtures into tests/fixtures/ using token from .env.

Usage:
    # from project root, with .env containing GITHUB_TOKEN or GITHUB_PAT
    python scripts/fixtures_generator.py
    python scripts/fixtures_generator.py --ghsa GHSA- --repo bla/bla
    python scripts/fixtures_generator.py --all --limit 20

Output:
    tests/fixtures/real_*.json + tests/fixtures/manifest.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

# Ensure src on path when running as script
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import get_settings
from advisory_rss.github.client import GitHubClient

TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9_-]+|github_pat_[A-Za-z0-9_-]+)")

logger = logging.getLogger(__name__)


def _redact(s: str) -> str:
    return TOKEN_RE.sub("***", s)


def _safe_write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # pretty, sorted keys for diff stability
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(text)} bytes)")


async def _fetch_one_ghsa(client: GitHubClient, ghsa: str, repo: str | None) -> dict | None:
    # Try repo-specific if repo given (no ETag for direct GHSA fetch)
    if repo and "/" in repo:
        owner, name = repo.split("/", 1)
        try:
            resp = await client._request_with_retry(
                "GET",
                f"/repos/{owner}/{name}/security-advisories/{ghsa}",
                use_etag=False,
            )
            if resp is not None and resp.status_code == 200:
                try:
                    return resp.json()
                except (ValueError, json.JSONDecodeError, RuntimeError) as e:
                    print(f"  warn: repo GHSA {ghsa} json parse failed: {_redact(str(e))}")
            elif resp is not None and resp.status_code == 304:
                # stale cache - try without etag
                resp2 = await client._request_with_retry(
                    "GET",
                    f"/repos/{owner}/{name}/security-advisories/{ghsa}",
                    use_etag=False,
                )
                if resp2 is not None and resp2.status_code == 200:
                    return resp2.json()
        except (httpx.HTTPError, OSError, ValueError, RuntimeError) as e:
            print(f"  warn: repo GHSA fetch failed {ghsa} @ {repo}: {_redact(str(e))}")

    # Try global (no ETag)
    try:
        resp = await client._request_with_retry("GET", f"/advisories/{ghsa}", use_etag=False)
        if resp is not None and resp.status_code == 200:
            return resp.json()
    except (httpx.HTTPError, OSError, ValueError, RuntimeError) as e:
        print(f"  warn: global GHSA fetch failed {ghsa}: {_redact(str(e))}")

    # Try GraphQL
    try:
        payload = {
            "query": f'query {{ securityAdvisory(ghsaId:"{ghsa}") {{ ghsaId summary severity publishedAt identifiers {{ type value }} }} }}'
        }
        resp = await client._request_with_retry(
            "POST", "/graphql", headers={"Content-Type": "application/json"}
        )

        r = await client._client.post(
            "https://api.github.com/graphql",
            json=payload,
            headers={"Authorization": f"Bearer {client.token}"},
        )
        if r.status_code == 200:
            j = r.json()
            if j.get("data", {}).get("securityAdvisory"):
                return j["data"]["securityAdvisory"]
    except (httpx.HTTPError, OSError, ValueError, RuntimeError, json.JSONDecodeError) as e:
        print(f"  warn: graphql GHSA fetch failed {ghsa}: {_redact(str(e))}")
    return None


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    token = settings.token
    if not token:
        print(
            "ERROR: GITHUB_TOKEN / GITHUB_PAT not set in .env or env. Set it in .env:\n  GITHUB_TOKEN=github_pat_...  or ghp_...",
            file=sys.stderr,
        )
        return 1

    fixtures_dir = (
        (ROOT / args.fixtures_dir).resolve()
        if not Path(args.fixtures_dir).is_absolute()
        else Path(args.fixtures_dir).resolve()
    )

    fixtures_dir.mkdir(parents=True, exist_ok=True)

    # auto-clean old real fixtures + tmp cache unless --no-clean
    if not args.no_clean:
        for pat in ["real_*.json", "manifest.json", ".tmp-cache.db", ".tmp-cache.db-*"]:
            for p in fixtures_dir.glob(pat):
                try:
                    p.unlink()
                    print(f"cleaned {p.relative_to(ROOT)}")
                except OSError as e:
                    logger.debug("cleanup failed %s: %s", p, _redact(str(e)))

    # Use temp cache (isolated so we don't pollute real cache/cache/advisories.db)
    tmp_cache = Path(args.cache).resolve() if args.cache else fixtures_dir / ".tmp-cache.db"
    if args.force and tmp_cache.exists():
        tmp_cache.unlink(missing_ok=True)
        for p in fixtures_dir.glob(".tmp-cache.*"):
            try:
                p.unlink()
            except OSError as e:
                logger.debug("cleanup tmp cache failed %s: %s", p, _redact(str(e)))
    cache = CacheStore(tmp_cache)
    client = GitHubClient(settings, token, cache=cache)

    # Auto-detect from .env (GITHUB_REPOS/GITHUB_ORG/SKIP_FULL_SCAN) - sync_all already respects settings
    if not args.ghsa and not args.repo:
        extra = settings.extra_repo_list()
        orgs = settings.extra_org_list()
        if extra or orgs or settings.skip_full_scan:
            print(
                f"Auto-detected from .env: GITHUB_REPOS={extra or '-'} GITHUB_ORG={orgs or '-'} SKIP_FULL_SCAN={settings.skip_full_scan}"
            )

    manifest: dict = {
        "generated_at": datetime.now(UTC).isoformat(),
        "github_api_base": settings.github_api_base,
        "filter_mode": settings.filter_mode,
        "args": vars(args),
    }

    try:
        # 1) Resolve authenticated user
        user = await client.get_user()
        login = user.get("login", "unknown")
        print(f"Authenticated as @{login} (id={user.get('id')})")
        _safe_write_json(fixtures_dir / "real_user.json", user)
        manifest["authenticated_user"] = login

        # 2) Fetch specific GHSA(s) if requested
        if args.ghsa:
            ghsas = [g.strip() for g in args.ghsa.replace(",", " ").split() if g.strip()]
            for ghsa in ghsas:
                print(f"Fetching GHSA {ghsa} (repo={args.repo or 'global'}) ...")
                raw = await _fetch_one_ghsa(client, ghsa, args.repo)
                if raw:
                    out = fixtures_dir / f"real_ghsa_{ghsa}.json"
                    _safe_write_json(out, raw)
                    try:
                        rel = str(out.relative_to(ROOT))
                    except ValueError:
                        rel = str(out)
                    manifest.setdefault("ghsas", []).append(
                        {"ghsa": ghsa, "file": rel, "repo": args.repo}
                    )
                else:
                    print(
                        f"  -> GHSA {ghsa} not found via REST/GraphQL (private, draft, or ID typo). List endpoint may still have it."
                    )
                    manifest.setdefault("ghsas", []).append(
                        {"ghsa": ghsa, "file": None, "error": "not found"}
                    )

        # 3) Fetch repo advisories via sync_all (filtered) or direct list for extra repos
        if args.all or not args.ghsa:
            # Use existing sync logic to get filtered advisories (author == login)
            print(
                f"Syncing advisories (filter_mode={settings.filter_mode}, skip_full_scan={settings.skip_full_scan}) ..."
            )
            # Respect GITHUB_REPOS / SKIP_FULL_SCAN from settings; also allow override via args
            if args.repo and not settings.extra_repo_list():
                # If user passed --repo but settings has no GITHUB_REPOS, we still want to scan that repo
                original_extra = settings.github_repos
                settings.github_repos = args.repo
                # re-run sync with that injection
                owner, name = args.repo.split("/", 1) if "/" in (args.repo or "") else (None, None)
                if owner and name:
                    raws = await client.list_repo_advisories_for_repo(owner, name)
                    print(f"  Direct list for {args.repo}: {len(raws)} raw advisories")
                    for i, raw in enumerate(raws[: args.limit]):
                        ghsa = raw.get("ghsa_id", f"unknown_{i}")
                        _safe_write_json(
                            fixtures_dir / f"real_repo_{owner}_{name}_{ghsa}.json", raw
                        )
                    manifest["direct_repo_list"] = {
                        "repo": args.repo,
                        "raw_count": len(raws),
                    }
                # restore
                settings.github_repos = original_extra
            else:
                advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
                print(
                    f"  sync_all: repos_scanned={diag.get('repos_scanned')} raw={diag.get('raw_count')} filtered={diag.get('filtered_count')}"
                )
                manifest["sync_diag"] = diag
                # Save up to --limit filtered advisories as fixtures
                for adv in advs[: args.limit]:
                    # Save normalized + raw
                    raw = adv.raw
                    _safe_write_json(fixtures_dir / f"real_filtered_{adv.ghsa_id}.json", raw)
                    # Also save normalized form for reference
                    _safe_write_json(
                        fixtures_dir / f"real_normalized_{adv.ghsa_id}.json",
                        adv.to_dict(),
                    )
                # Also save a combined list for quick inspection
                _safe_write_json(
                    fixtures_dir / "real_sync_filtered_list.json",
                    [a.to_dict() for a in advs[: args.limit]],
                )

        # 4) Also fetch a global advisory sample for reference (public)
        if args.fetch_global_sample:
            sample_ghsa = args.fetch_global_sample
            print(f"Fetching global sample {sample_ghsa} ...")
            resp = await client._request_with_retry("GET", f"/advisories/{sample_ghsa}")
            if resp is not None and resp.status_code == 200:
                _safe_write_json(fixtures_dir / f"real_global_{sample_ghsa}.json", resp.json())
            else:
                print(f"  global sample {sample_ghsa} not found or not 200")

        _safe_write_json(fixtures_dir / "manifest.json", manifest)
        print(f"\nDone. Manifest: {fixtures_dir / 'manifest.json'}")
        # Always clean tmp cache afterwards unless --no-clean (keeps fixtures dir tidy; .tmp-cache.db is not a fixture)
        if not args.no_clean and tmp_cache.exists() and args.cache is None:
            try:
                tmp_cache.unlink()
                for p in fixtures_dir.glob(".tmp-cache.*"):
                    p.unlink(missing_ok=True)
                print(f"cleaned {tmp_cache.relative_to(ROOT)}")
            except OSError as e:
                logger.debug("tmp cache cleanup failed: %s", _redact(str(e)))
        elif args.clean_cache and tmp_cache.exists():
            tmp_cache.unlink(missing_ok=True)
            for p in fixtures_dir.glob(".tmp-cache.*"):
                p.unlink(missing_ok=True)
        return 0
    except (httpx.HTTPError, OSError, ValueError, RuntimeError) as e:
        print(f"ERROR: {_redact(str(e))}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1
    finally:
        await client.close()
        try:
            cache.close()
        except (OSError, RuntimeError) as e:
            logger.debug("cache close failed: %s", _redact(str(e)))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate real GitHub API fixtures into tests/fixtures/ using token from .env"
    )
    ap.add_argument(
        "--ghsa",
        help="GHSA id(s) to fetch, comma or space separated, e.g. GHSA-xxxx-xxxx-xxxx",
    )
    ap.add_argument(
        "--repo",
        help="Repo for GHSA fetch, e.g. your-org/your-repo (needed for private repo advisories)",
    )
    ap.add_argument(
        "--all",
        action="store_true",
        help="Also run full sync_all and save filtered advisories (default if no --ghsa)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max number of advisories to save from sync (default 20)",
    )
    ap.add_argument(
        "--fixtures-dir",
        default="tests/fixtures",
        help="Output dir (default tests/fixtures)",
    )
    ap.add_argument("--cache", help="Cache db path for ETag (default tests/fixtures/.tmp-cache.db)")
    ap.add_argument("--force", action="store_true", help="Force fresh fetch (delete tmp cache)")
    ap.add_argument("--clean-cache", action="store_true", help="Delete tmp cache after run")
    ap.add_argument(
        "--no-clean",
        action="store_true",
        help="Do not delete old real_*.json/manifest.json/.tmp-cache.db before run",
    )
    ap.add_argument(
        "--fetch-global-sample",
        help="Also fetch a global advisory, e.g. GHSA-abcd-1234-efgh",
    )
    args = ap.parse_args()
    # Default: if no --ghsa and no --all, do --all (one-shot based on .env)
    if not args.ghsa and not args.all:
        args.all = True
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
