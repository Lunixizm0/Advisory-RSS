"""Persistent cache SQLite with WAL, parameterized queries, ETag map, stale fallback."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from advisory_rss.cache.models import CacheMeta, NormalizedAdvisory

logger = logging.getLogger(__name__)

_lock = threading.Lock()

# Never log token — this store never touches token


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0, check_same_thread=False, isolation_level=None)
    # Safety pragmas
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
    except sqlite3.Error:
        pass
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories(
    ghsa_id TEXT PRIMARY KEY,
    raw_json TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    updated_at TEXT,
    state TEXT,
    html_url TEXT,
    author_login TEXT
);
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS etags(
    url TEXT PRIMARY KEY,
    etag TEXT,
    updated_at TEXT
);
"""


class CacheStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._conn = _connect(self.db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        try:
            self._conn.executescript(SCHEMA)
        except sqlite3.Error as e:
            logger.warning("Cache schema init failed: %s", e)

    def upsert_advisories(self, advisories: list[NormalizedAdvisory]) -> int:
        """Upsert list; returns count. Uses parameterized queries."""
        if not advisories:
            return 0
        count = 0
        with _lock:
            try:
                cur = self._conn.cursor()
                cur.execute("BEGIN IMMEDIATE")
                for adv in advisories:
                    try:
                        normalized_json = json.dumps(adv.to_dict(), ensure_ascii=False)
                        raw_json = json.dumps(adv.raw or {}, ensure_ascii=False)
                        updated_iso = adv.updated_at.isoformat() if adv.updated_at else None
                        cur.execute(
                            """
                            INSERT INTO advisories(ghsa_id, raw_json, normalized_json, updated_at, state, html_url, author_login)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(ghsa_id) DO UPDATE SET
                                raw_json=excluded.raw_json,
                                normalized_json=excluded.normalized_json,
                                updated_at=excluded.updated_at,
                                state=excluded.state,
                                html_url=excluded.html_url,
                                author_login=excluded.author_login
                            """,
                            (
                                adv.ghsa_id,
                                raw_json,
                                normalized_json,
                                updated_iso,
                                adv.state,
                                adv.html_url,
                                adv.author_login,
                            ),
                        )
                        count += 1
                    except Exception as e:
                        logger.warning("Failed to upsert %s: %s", adv.ghsa_id, e)
                cur.execute("COMMIT")
            except sqlite3.Error as e:
                logger.warning("Cache upsert transaction failed: %s", e)
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
        return count

    def load_all(self) -> list[NormalizedAdvisory]:
        try:
            cur = self._conn.execute("SELECT normalized_json FROM advisories")
            rows = cur.fetchall()
            out: list[NormalizedAdvisory] = []
            for (j,) in rows:
                try:
                    data = json.loads(j)
                    out.append(NormalizedAdvisory.from_dict(data))
                except Exception as e:
                    logger.warning("Corrupt cache row skipped: %s", e)
            return out
        except sqlite3.Error as e:
            logger.warning("Cache load failed: %s", e)
            return []

    def load_sorted(self, limit: int | None = None) -> list[NormalizedAdvisory]:
        all_adv = self.load_all()
        # sort updated_at DESC
        all_adv.sort(key=lambda a: a.sort_key(), reverse=True)
        if limit is not None:
            return all_adv[:limit]
        return all_adv

    def count(self) -> int:
        try:
            cur = self._conn.execute("SELECT COUNT(*) FROM advisories")
            return int(cur.fetchone()[0])
        except sqlite3.Error:
            return 0

    def clear(self) -> None:
        try:
            self._conn.execute("DELETE FROM advisories")
            self._conn.execute("DELETE FROM meta WHERE key LIKE 'etag%'")
            self._conn.execute("DELETE FROM etags")
        except sqlite3.Error as e:
            logger.warning("Cache clear failed: %s", e)

    # --- meta ---
    def get_meta(self, key: str) -> str | None:
        try:
            cur = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,))
            row = cur.fetchone()
            return row[0] if row else None
        except sqlite3.Error:
            return None

    def set_meta(self, key: str, value: str | None) -> None:
        try:
            if value is None:
                self._conn.execute("DELETE FROM meta WHERE key=?", (key,))
            else:
                self._conn.execute(
                    "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value),
                )
        except sqlite3.Error as e:
            logger.warning("set_meta failed %s: %s", key, e)

    def get_cache_meta(self) -> CacheMeta:
        return CacheMeta(
            last_successful_sync=self.get_meta("last_successful_sync"),
            next_scheduled_sync=self.get_meta("next_scheduled_sync"),
            advisories_count=self.count(),
            rate_limited_until=self.get_meta("rate_limited_until"),
            last_error=self.get_meta("last_error"),
            authenticated_user=self.get_meta("authenticated_user"),
        )

    def set_cache_meta(self, meta: CacheMeta) -> None:
        self.set_meta("last_successful_sync", meta.last_successful_sync)
        self.set_meta("next_scheduled_sync", meta.next_scheduled_sync)
        self.set_meta("rate_limited_until", meta.rate_limited_until)
        self.set_meta("last_error", meta.last_error)
        self.set_meta("authenticated_user", meta.authenticated_user)

    # --- etags ---
    def get_etag(self, url: str) -> str | None:
        try:
            cur = self._conn.execute("SELECT etag FROM etags WHERE url=?", (url,))
            row = cur.fetchone()
            return row[0] if row else None
        except sqlite3.Error:
            return None

    def set_etag(self, url: str, etag: str | None) -> None:
        try:
            if etag is None:
                self._conn.execute("DELETE FROM etags WHERE url=?", (url,))
            else:
                now = datetime.now(timezone.utc).isoformat()
                self._conn.execute(
                    "INSERT INTO etags(url, etag, updated_at) VALUES (?, ?, ?) ON CONFLICT(url) DO UPDATE SET etag=excluded.etag, updated_at=excluded.updated_at",
                    (url, etag, now),
                )
        except sqlite3.Error as e:
            logger.warning("set_etag failed: %s", e)

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    # Helpers for status
    def mark_success(self, user: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.set_meta("last_successful_sync", now)
        self.set_meta("last_error", None)
        self.set_meta("rate_limited_until", None)
        if user:
            self.set_meta("authenticated_user", user)
        # compute next
        # caller sets next_scheduled via interval; but also set here roughly
        self.set_meta("advisories_count", str(self.count()))

    def mark_error(self, err: str) -> None:
        # truncate error
        self.set_meta("last_error", err[:500])
