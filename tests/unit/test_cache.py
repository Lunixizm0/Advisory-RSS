import tempfile
from datetime import UTC, datetime
from pathlib import Path

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore


def make_adv(ghsa, updated=None):
    if updated is None:
        updated = datetime.now(UTC)
    return NormalizedAdvisory(
        ghsa_id=ghsa,
        summary=f"summary {ghsa}",
        description="desc",
        state="published",
        html_url=f"https://github.com/advisories/{ghsa}",
        updated_at=updated,
        author_login="octocat",
    )


def test_cache_persist_and_load(tmp_path):
    db = tmp_path / "cache.db"
    store = CacheStore(db)
    adv1 = make_adv("GHSA-1")
    adv2 = make_adv("GHSA-2")
    store.upsert_advisories([adv1, adv2])
    assert store.count() == 2
    loaded = store.load_all()
    assert len(loaded) == 2
    ids = {a.ghsa_id for a in loaded}
    assert ids == {"GHSA-1", "GHSA-2"}
    store.close()
    # reopen should persist
    store2 = CacheStore(db)
    assert store2.count() == 2
    store2.close()


def test_cache_sorted_limit():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "a.db"
        store = CacheStore(db)

        old = make_adv("GHSA-old", updated=datetime(2025, 1, 1, tzinfo=UTC))
        new = make_adv("GHSA-new", updated=datetime(2025, 6, 1, tzinfo=UTC))
        store.upsert_advisories([old, new])
        sorted_all = store.load_sorted()
        assert sorted_all[0].ghsa_id == "GHSA-new"
        limited = store.load_sorted(limit=1)
        assert len(limited) == 1
        assert limited[0].ghsa_id == "GHSA-new"
        store.close()


def test_cache_etag_persist(tmp_path):
    db = tmp_path / "c.db"
    store = CacheStore(db)
    store.set_etag(
        "https://api.github.com/repos/o/r/security-advisories?state=published",
        'W/"abc"',
    )
    assert (
        store.get_etag("https://api.github.com/repos/o/r/security-advisories?state=published")
        == 'W/"abc"'
    )
    # persist
    store.close()
    store2 = CacheStore(db)
    assert (
        store2.get_etag("https://api.github.com/repos/o/r/security-advisories?state=published")
        == 'W/"abc"'
    )
    store2.close()


def test_cache_meta():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "m.db"
        store = CacheStore(db)
        store.set_meta("last_successful_sync", "2025-01-01T00:00:00Z")
        assert store.get_meta("last_successful_sync") == "2025-01-01T00:00:00Z"
        meta = store.get_cache_meta()
        assert meta.last_successful_sync == "2025-01-01T00:00:00Z"
        store.close()


def test_cache_stale_remains_on_error(tmp_path):
    db = tmp_path / "s.db"
    store = CacheStore(db)
    adv = make_adv("GHSA-keep")
    store.upsert_advisories([adv])
    # Simulate error mark but advisories remain
    store.mark_error("network failure")
    assert store.count() == 1
    assert store.get_meta("last_error") == "network failure"
    store.close()
