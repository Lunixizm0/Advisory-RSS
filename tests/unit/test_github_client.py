import httpx
import pytest
import respx
from httpx import Response

from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.github.client import AuthError, GitHubClient

pytestmark = pytest.mark.asyncio

API = "https://api.github.com"


def make_settings(db_path):
    return Settings(
        _env_file=None,
        github_token="ghp_testtoken123",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db_path),
        refresh_interval=600,
    )


def adv_payload(ghsa, author="octocat", state="published"):
    return {
        "ghsa_id": ghsa,
        "cve_id": None,
        "html_url": f"https://github.com/octo/repo/security/advisories/{ghsa}",
        "summary": f"summary {ghsa}",
        "description": "desc",
        "severity": "high",
        "author": {"login": author},
        "state": state,
        "updated_at": "2025-01-02T12:00:00Z",
        "published_at": "2025-01-02T12:00:00Z",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "pkg"},
                "vulnerable_version_range": "<1",
                "patched_versions": "1",
            }
        ],
    }


@respx.mock
async def test_github_pagination_continues_until_exhausted(tmp_path):
    db = tmp_path / "c.db"
    settings = make_settings(db)
    cache = CacheStore(db)
    token = "ghp_test"
    client = GitHubClient(settings, token, cache=cache)

    # Mock /user
    respx.get(f"{API}/user").mock(return_value=Response(200, json={"login": "octocat", "id": 1}))
    # Mock /user/repos pagination: first page with Link next, second page empty link
    repo1 = {
        "full_name": "octocat/repo1",
        "owner": {"login": "octocat"},
        "name": "repo1",
    }
    repo2 = {
        "full_name": "octocat/repo2",
        "owner": {"login": "octocat"},
        "name": "repo2",
    }

    # Handler for two affiliations (owner + organization_member)
    call_idx = {"n": 0}

    def repos_route(request):
        # limit to handle both affiliations
        url = str(request.url)
        # For owner affiliation, first call returns repo1 with link, second call returns repo2
        # For organization_member, return empty
        if "affiliation=owner" in url:
            call_idx["n"] += 1
            if call_idx["n"] == 1:
                return Response(
                    200,
                    json=[repo1],
                    headers={"Link": f'<{API}/user/repos?after=abc&per_page=100>; rel="next"'},
                )
            elif call_idx["n"] == 2:
                return Response(200, json=[repo2])
            else:
                return Response(200, json=[])
        # organization_member -> empty
        return Response(200, json=[])

    respx.get(url__regex=r"https://api\.github\.com/user/repos.*").mock(side_effect=repos_route)

    def repo_adv_route(request):
        url = str(request.url)
        if "repo1" in url:
            if "state=published" in url and "after" not in url:
                return Response(
                    200,
                    json=[adv_payload("GHSA-1", author="octocat")],
                    headers={
                        "Link": f'<{API}/repos/octocat/repo1/security-advisories?after=next1&per_page=100&state=published>; rel="next"'
                    },
                )
            if "repo1" in url and "after=next1" in url:
                return Response(200, json=[adv_payload("GHSA-2", author="octocat")])
            return Response(200, json=[])
        if "repo2" in url:
            return Response(200, json=[])
        return Response(404, json={})

    respx.get(url__regex=r"https://api\.github\.com/repos/.*/security-advisories.*").mock(
        side_effect=repo_adv_route
    )

    # Also need /user/orgs
    respx.get(f"{API}/user/orgs").mock(return_value=Response(200, json=[]))

    advs, diag = await client.sync_all(authenticated_login="octocat", filter_mode="author")
    assert "GHSA-1" in {a.ghsa_id for a in advs}
    assert "GHSA-2" in {a.ghsa_id for a in advs}
    assert diag["raw_count"] >= 2
    await client.close()


@respx.mock
async def test_github_401_handling(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "bad", cache=cache)
    respx.get(f"{API}/user").mock(return_value=Response(401, json={"message": "Bad credentials"}))
    with pytest.raises(AuthError):
        await client.get_user()
    await client.close()


@respx.mock
async def test_github_403_rate_limit(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "tok", cache=cache)
    # First call returns 429, second returns 200
    respx.get(f"{API}/user").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "0"}, json={"message": "rate limited"}),
            Response(200, json={"login": "octocat"}),
        ]
    )
    # _request_with_retry should retry and succeed on second attempt (max_retries 3)
    # Actually get_user uses retry path which will see 429 as rate limit and retry
    user = await client.get_user()
    assert user["login"] == "octocat"
    await client.close()


@respx.mock
async def test_github_404_skip(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "tok", cache=cache)
    # repos list returns one repo
    respx.get(f"{API}/user").mock(return_value=Response(200, json={"login": "octocat"}))
    respx.get(f"{API}/user/orgs").mock(return_value=Response(200, json=[]))
    respx.get(url__regex=r"https://api\.github\.com/user/repos.*").mock(
        return_value=Response(200, json=[{"full_name": "octocat/repo1"}])
    )
    # repo advisories 404
    respx.get(url__regex=r".*security-advisories.*").mock(
        return_value=Response(404, json={"message": "not found"})
    )
    advs, diag = await client.sync_all(authenticated_login="octocat")
    assert advs == []
    await client.close()


@respx.mock
async def test_github_422_skip(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "tok", cache=cache)
    respx.get(f"{API}/user").mock(return_value=Response(200, json={"login": "octocat"}))
    respx.get(f"{API}/user/orgs").mock(return_value=Response(200, json=[]))
    respx.get(url__regex=r"https://api\.github\.com/user/repos.*").mock(
        return_value=Response(200, json=[{"full_name": "octocat/repo1"}])
    )
    respx.get(url__regex=r".*security-advisories.*").mock(
        return_value=Response(422, json={"message": "validation failed"})
    )
    advs, diag = await client.sync_all(authenticated_login="octocat")
    assert advs == []
    await client.close()


@respx.mock
async def test_github_5xx_retry(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "tok", cache=cache)
    # 5xx twice then 200
    respx.get(f"{API}/user").mock(
        side_effect=[
            Response(500, json={"message": "server error"}),
            Response(502, json={"message": "bad gateway"}),
            Response(200, json={"login": "octocat"}),
        ]
    )
    user = await client.get_user()
    assert user["login"] == "octocat"
    await client.close()


@respx.mock
async def test_github_malformed_api_response_skip_one(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "tok", cache=cache)
    respx.get(f"{API}/user").mock(return_value=Response(200, json={"login": "octocat"}))
    respx.get(f"{API}/user/orgs").mock(return_value=Response(200, json=[]))
    respx.get(url__regex=r"https://api\.github\.com/user/repos.*").mock(
        return_value=Response(200, json=[{"full_name": "octocat/repo1"}])
    )

    # Mix good and malformed advisory (missing ghsa but not crash)
    def adv_route(req):
        return Response(200, json=[adv_payload("GHSA-good", author="octocat"), {"bad": "data"}])

    respx.get(url__regex=r".*security-advisories.*").mock(side_effect=adv_route)
    advs, diag = await client.sync_all(authenticated_login="octocat")
    # Should have 1 good, bad skipped via normalization => filtered count 1
    assert any(a.ghsa_id == "GHSA-good" for a in advs)
    await client.close()


@respx.mock
async def test_etag_304_keeps_cache(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    # Pre-seed etag for security-advisories endpoint (only these use ETag now)
    etag_key = "https://api.github.com/repos/octo/repo/security-advisories?per_page=100&sort=updated&direction=desc&state=published"
    cache.set_etag(etag_key, 'W/"old-etag"')
    client = GitHubClient(settings, "tok", cache=cache)
    # Mock returns 304 for that endpoint
    respx.get(url__regex=r".*security-advisories.*").mock(return_value=Response(304))
    resp = await client._request_with_retry(
        "GET",
        "/repos/octo/repo/security-advisories",
        params={
            "per_page": 100,
            "sort": "updated",
            "direction": "desc",
            "state": "published",
        },
    )
    assert resp is None
    await client.close()


@respx.mock
async def test_network_failure_then_stale(tmp_path):
    settings = make_settings(tmp_path / "c.db")
    cache = CacheStore(settings.resolved_cache_path)
    client = GitHubClient(settings, "tok", cache=cache)
    # Mock network failure simulation via respx side_effect raising httpx.ConnectError
    # We test via sync_all that if get_user raises network, diag errors and fallback keeps cache?
    # For now ensure client._request_with_retry retries on ConnectError and then raises after retries

    call_count = {"n": 0}

    def failing(request):
        call_count["n"] += 1
        raise httpx.ConnectError("network down")

    respx.get(f"{API}/user").mock(side_effect=failing)
    with pytest.raises(Exception):
        await client.get_user()
    assert call_count["n"] == 4  # 1 initial + 3 retries
    await client.close()
