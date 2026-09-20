import pytest
import respx
from httpx import Response

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.github.client import GitHubClient

pytestmark = pytest.mark.asyncio
API = "https://api.github.com"


def make_settings(db_path):
    return Settings(
        _env_file=None,  
        github_token="ghp_test",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db_path),
    )  # 


@respx.mock
async def test_cache_fallback_on_github_down(tmp_path):
    db = tmp_path / "c.db"
    settings = make_settings(db)
    cache = CacheStore(db)
    # Pre-populate cache with stale entry
    adv = NormalizedAdvisory(
        ghsa_id="GHSA-stale-1",
        summary="stale",
        html_url="https://github.com/advisories/GHSA-stale-1",
    )
    cache.upsert_advisories([adv])
    assert cache.count() == 1

    client = GitHubClient(settings, "tok", cache=cache)
    # Make GitHub always 500 after retries (client will retry 3 times)
    respx.get(f"{API}/user").mock(return_value=Response(500, json={"message": "server error"}))
    respx.get(url__regex=r".*api\.github\.com.*").mock(return_value=Response(500, json={}))

    with pytest.raises(Exception): 
        await client.get_user()
    # Cache still has stale
    assert cache.count() == 1
    loaded = cache.load_all()
    assert loaded[0].ghsa_id == "GHSA-stale-1"
    await client.close()


@respx.mock
async def test_cache_persists_across_restart(tmp_path):
    db = tmp_path / "persist.db"
    settings = make_settings(db) 
    cache = CacheStore(db)
    adv = NormalizedAdvisory(ghsa_id="GHSA-persist-1", summary="persist")
    cache.upsert_advisories([adv])
    cache.set_meta("authenticated_user", "octocat")
    cache.set_meta("last_successful_sync", "2025-01-01T00:00:00Z")
    cache.close()
    # Reopen
    cache2 = CacheStore(db)
    assert cache2.count() == 1
    assert cache2.get_meta("authenticated_user") == "octocat"
    loaded = cache2.load_all()
    assert loaded[0].ghsa_id == "GHSA-persist-1"
    cache2.close()
