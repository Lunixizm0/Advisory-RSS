# Advisory-RSS - GitHub Security Advisories - Local RSS

Security-first local service that lists **all GitHub Security Advisories created/owned by the authenticated account** and exposes them as an **RSS 2.0 feed** for Zen Browser's RSS Live Folder.
What the hell is 'Zen Browser's Live Folder?' == `https://github.com/zen-browser/desktop/releases/tag/1.19b`

GitHub API - authenticated PAT - fetch advisories owned/created by account - normalize + cache - RSS 2.0 on 127.0.0.1 - Zen Browser's Live Folder

**Endpoints:**

```
http://127.0.0.1:PORT/rss.xml
http://127.0.0.1:PORT/health
```

---

## 1. Prerequisites

- **Python 3.12+**
- `uv` **or** `pip` + venv
- A GitHub account that **owns/creates advisories** (i.e., you are `author` of advisories)
- A GitHub PAT (see below)

---

## 2. Installation

```bash
git clone https://github.com/Lunixizm0/advisory-rss
cd advisory-rss

# with uv (recommended)
uv sync
# or with pip
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

# verify
app --help
pytest -q
```

---

## 3. GitHub PAT
The service uses **official GitHub REST API**
| PAT type | Where to create | Scopes / Permissions required | When needed |
|---|---|---|---|
| **Fine-grained PAT (recommended)** | <https://github.com/settings/personal-access-tokens/new> | Resource owner: *your user + relevant orgs* - Repository access: *All repositories* (or select repos) - **Repository permissions - Security advisories: Read-only** + **Metadata: Read-only** (implied). For org-wide bulk fetch: **Organization permissions - Security advisories: Read-only** (requires org owner/security-manager). | Preferred - short expiry (30–90 days), no read to code. |
| **Classic PAT fallback** | <https://github.com/settings/tokens/new> | `repo` **or** at minimum `public_repo` (but **private/draft advisories require `repo`**). Docs: `repo` or `repository_advisories:read` (`docs.github.com/en/rest/security-advisories/repository-advisories`). | If fine-grained is unavailable. Note: `repo` grants read to code - broader than needed. |

**No other scopes are needed.** Do not grant `admin:org`, `delete_repo`, `workflow`, etc.

**GitHub API endpoints used:**

- `GET /user` - resolves authenticated `login`
- `GET /user/repos?affiliation=owner&visibility=all&per_page=100&sort=updated` - paginated enumerates repos you own
- `GET /user/orgs` - lists orgs you belong to
- `GET /orgs/{org}/security-advisories?per_page=100&sort=updated&state={triage,draft,published,closed}` - org-wide bulk (requires owner/security-manager, else 403/404 and we fall back to per-repo)
- `GET /repos/{owner}/{repo}/security-advisories?per_page=100&sort=updated&direction=desc&state={triage,draft,published,closed}` - primary fetch, paginated via `Link: <…after=…>; rel="next"` until exhaustion
- `GET /advisories/{ghsa_id}` - optional enrichment for published global view (not used for discovery)

**Why GraphQL is rejected for ownership:** `docs.github.com/en/graphql/reference/security-advisories` lists `securityAdvisories{ghsaId,summary,severity,…}` with args `classifications, epss*, first/last, identifier, orderBy, publishedSince` - **no `author` field and no author filter**, so it cannot identify "created by me" reliably. We use REST `author.login` and filter client-side.

---

## 4. First Sync

```bash
cp .env.example .env
# edit .env - set at least GITHUB_TOKEN
$EDITOR .env
# e.g. GITHUB_TOKEN=github_pat_…  or ghp_…
# leave BIND_ADDRESS=127.0.0.1 and PORT=8765 - do NOT change to 0.0.0.0

# validate PAT (only checks GET /user, never saves to file - .env is the only source)
app auth login
# Paste PAT -> "+ Validated as @you" -> then set GITHUB_TOKEN in .env as instructed

# manual fetch - writes cache/advisories.db
app sync

# inspect
app status
# - Authenticated user: @octocat
# - Cached advisories: 12
# - RSS URL: http://127.0.0.1:8765/rss.xml
```

**Direct fetch for advisories in repos you don't own** (you authored GHSA in `other-org/other-repo` but `affiliation=owner` doesn't list it - GitHub has no `author` filter, see Known Limitations):
```bash
# .env
GITHUB_REPOS=your-org/your-repo,other-org/other-repo   # comma-separated, always scanned
GITHUB_ORG=your-org                          # expands via /orgs/{org}/repos
SKIP_FULL_SCAN=true   # optional: skip scanning all owned repos, only scan GITHUB_REPOS/GITHUB_ORG (fast)
# PAT must have Repository access -> Selected repositories covering those repos (fine-grained)
LOG_LEVEL=INFO app sync
```

`FILTER_MODE` semantics (`PLAN.md:31`, `.env.example:22`):

- `author` **(default)** - only `advisory.author.login == your_login` (precise "created by me")
- `author_or_publisher` - also matches `publisher.login`
- `author_or_collaborator` - also matches `collaborating_users[]` (covers advisories where you are collaborator but not author)

Do not equate "advisories in repos I own" with "created by me" - they are different.

---

## 5. Starting the Server

```bash
app serve
# binds 127.0.0.1:8765, background refresh every REFRESH_INTERVAL (default 600s = 10 min)
# health: curl http://127.0.0.1:8765/health
# feed  : curl http://127.0.0.1:8765/rss.xml | xmllint --noout -
```

## 6. RSS URL

Canonical for Zen Browser:

```
http://127.0.0.1:8765/rss.xml
```

Do not use HTTPS. Also, no auth on `/rss.xml` (Zen has no RSS auth)

---

## 7. Adding the Feed to Zen Browser RSS Dynamic Folder

1. Start the feed: `app serve` and verify `curl http://127.0.0.1:8765/rss.xml | head` returns `<rss version="2.0">`.
2. Open Zen Browser - **Right Click - Live Folder - Add RSS Feed**
3. Paste **`http://127.0.0.1:8765/rss.xml`** as the feed source. Leave protocol HTTP (not HTTPS).
4. Save. Advisories appear sorted `updated_at DESC`, newest first. Withdrawn advisories remain with `[WITHDRAWN]` prefix - not deleted.
5. If Zen shows empty folder: `curl http://127.0.0.1:8765/health | jq .advisories_count` should be >0; if 0, re-run `app sync` and check `app status` for rate-limit/auth errors.

---

## 8. Changing the Refresh Interval

```bash
# .env
REFRESH_INTERVAL=300   # 5 minutes, min 60
# and optionally
MAX_ITEMS=500          # RSS truncation (cache still retains all to avoid missing advisories)
```

Restart `app serve` to apply. The feed `Cache-Control: private, max-age=300, must-revalidate` and `<ttl>5</ttl>` update automatically. `app status` shows `Next scheduled sync`.

## 8b. Keep running after closing the terminal (`--daemon`)

Normal `app serve` dies when the terminal closes (SIGHUP). If you want it to keep running in the background:

```bash
# easiest — daemonize (double-fork + setsid, like nohup but with pid/log management)
app serve --daemon
# → pid: cache/advisory-rss.pid , log: cache/serve.log
# verification
cat cache/advisory-rss.pid
ps -p $(cat cache/advisory-rss.pid) -o pid,cmd
curl http://127.0.0.1:8765/health
tail -f cache/serve.log
app stop                # SIGTERM + pid cleanup
app stop --pid-file cache/advisory-rss.pid

# alternatives (without daemon):
nohup app serve > cache/serve.log 2>&1 & disown
# or
tmux new -s rss "app serve"
# or systemd user service (persistent)
# ~/.config/systemd/user/advisory-rss.service:
# [Unit] Description=Advisory RSS localhost-only
# [Service] ExecStart=%h/Belgeler/Projeler/Advisory-RSS/.venv/bin/python -m advisory_rss.cli serve
#           Restart=always
#           Environment=GITHUB_TOKEN=ghp_...
# [Install] WantedBy=default.target
# systemctl --user daemon-reload && systemctl --user enable --now advisory-rss
```

Background behaviour: RSS reads cache only; a background task polls GitHub every `REFRESH_INTERVAL`, uses `If-None-Match`/`ETag` conditional requests, and **keeps stale cache on transient GitHub errors** (requirement: feed stays available if GitHub is down).

---

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `401 Unauthorized` at `app sync` | PAT expired/revoked or empty. Re-run `app auth login`; verify at <https://github.com/settings/tokens>. See Health `last_error`. |
| `403 Forbidden` | PAT scopes missing `repository_advisories:read` or org role insufficient (org bulk needs owner/security-manager - falls back to per-repo). Log shows scope hint. |
| `429 / rate limited` | `health.rate_limited_until` set, `app status` shows it. Wait or raise `MAX_REPOS`/reduce `REFRESH_INTERVAL` frequency. Logs include `Retry-After`/`X-RateLimit-Reset`. |
| `404` for a repo | Repo not found or no advisories - skipped, not fatal. |
| `422 Validation` | GitHub rejected params (e.g., bad state) - logged and skipped. |
| Feed empty but advisories exist | Check `FILTER_MODE`. Default `author` requires you are `author`. Try `FILTER_MODE=author_or_publisher`. Also ensure `authenticated_user` in `app status` equals your advisory author. |
| `pip-audit` failure | `pip install pip-audit && pip-audit` - fix by bumping pinned dep in `pyproject.toml`. |

View logs: `LOG_LEVEL=DEBUG app serve` for detail (still redacted).

Verify feed: `xmllint --noout <(curl -s http://127.0.0.1:8765/rss.xml)` - no output means valid.

---

## Architecture Explanation

```
GitHub REST API (api.github.com)
   │
   │ PAT (Authorization: Bearer, X-GitHub-Api-Version: 2022-11-28)
   ▼
get_user - list_user_orgs - list_user_repos (paginated, Link:max 100/page)  [skipped if SKIP_FULL_SCAN=true]
   │               │
   │               └─► orgs/{org}/security-advisories?state=… (bulk where authorized)
   └─► repos/{owner}/{repo}/security-advisories?state=…&after=… (per-repo, per-state)
        ▲ plus GITHUB_REPOS/GITHUB_ORG direct fetch (always scanned, even if SKIP_FULL_SCAN)
                                │  handle 401/403/404/422/429/5xx, ETag/If-None-Match, 304
                                ▼
                        normalize (github/normalize.py - tolerant, never crashes on one bad advisory)
                                │
                        filter by author (github/filter.py - author | author_or_publisher | author_or_collaborator)
                                │
                        dedup by GHSA, sort updated_at DESC
                                │
                        upsert - cache/advisories.db (SQLite WAL, parameterized, ETag map, cache fallback)
                                │
           background_refresh_loop (asyncio every REFRESH_INTERVAL, stale kept on GitHub outage)
                                │
   RSS request (no GitHub call) ◄┘
           │
           ▼
   GET http://127.0.0.1:8765/rss.xml - builder (xml_util escaping, RFC822 pubDate, stable GHSA GUID, withdrawn kept)
           │
           ▼
   Zen Browser RSS Dynamic Folder
```

Key invariants: RSS reads cache only; GH enumeration is exhaustive; failures keep stale cache.

---

## Required GitHub Scopes/Permissions (Recap)

- **Fine-grained:** `Repository security advisories: Read`, `Metadata: Read`, (org bulk: `Organization security advisories: Read`)
- **Classic:** `repo` (or `public_repo` for public advisories only, but private/draft need `repo` / `repository_advisories:read`)

---

## Known GitHub API Limitations

- **No server-side "created by me" filter** - all filtering is client-side after listing advisories per repo/state. Costs API calls (~1 per repo × 4 states + org bulk) and is rate-limited; mitigated with ETag 304, pagination caps, and background polling rather than per-RSS-call.
- **Enumeration requires listing all owned repos** (`GET /user/repos`) - large accounts (thousands of repos) need many pages; `MAX_REPOS`/`MAX_PAGES_PER_REPO` cap prevents runaway, `app status` reports caps hit.
- **Org bulk requires owner/security-manager** - else 403/404 per org and we fall back to per-repo enumeration (expected).
- **Global `GET /advisories` cannot tell ownership** - it is the public advisory database; ignored for discovery, used only as optional enrichment if needed.
- **GHSA != chronological** - must sort by `updated_at`, not ID.
- **GraphQL `SecurityAdvisory` has no `author`** - verified; cannot replace REST for this use case.
- **Global enrichment 404 for draft/private** - expected; we treat missing as not-enriched.
- **Withdrawn state** differs between global (`withdrawn_at`/`is_withdrawn`) and repo (`state: closed/withdrawn` + `withdrawn_at`) - normalized into single `withdrawn_at`/`state`.

---

## Development & Tests

```bash
pytest -q                     # all 60 tests
pytest tests/unit -q -v
pytest tests/integration -v   # starts ephemeral server on 127.0.0.1:0, validates RSS & headers
pip-audit                     # audit scan

# Regenerate real fixtures from live GitHub API (uses GITHUB_TOKEN from .env, auto-detects GITHUB_REPOS/GITHUB_ORG/SKIP_FULL_SCAN)
python scripts/fixtures_generator.py
python scripts/fixtures_generator.py --ghsa GHSA-xxxx-xxxx-xxxx --repo bla/bla  # single GHSA

# Lint / type-check (standard, line-based ignores only - no config-based ignore)
ruff check                    # All checks passed!
pyright                       # 0 errors, typeCheckingMode: standard, extraPaths: ["src"]
```

---

## License

GNU 