"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from advisory_rss.cache.store import CacheStore


@pytest.fixture(autouse=True)
def _close_cache_stores(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every CacheStore opened by a test so sqlite3 does not warn on GC."""
    created: list[CacheStore] = []
    original_init = CacheStore.__init__

    def init(self: CacheStore, *args: object, **kwargs: object) -> None:
        original_init(self, *args, **kwargs)  # type: ignore[arg-type]
        created.append(self)

    monkeypatch.setattr(CacheStore, "__init__", init)
    yield
    for store in created:
        store.close()
