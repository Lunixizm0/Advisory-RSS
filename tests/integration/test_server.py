import socket
import threading
import time
import xml.etree.ElementTree as ET

import httpx
import pytest
import uvicorn

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.server.app import create_app


def test_integration_rss_returns_valid_200(tmp_path):
    db = tmp_path / "c.db"
    settings = Settings(
        _env_file=None,
        github_token="ghp_dummy",
        bind_address="127.0.0.1",
        port=0,
        cache_path=str(db),
    )

    # Find free port
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    settings.port = port

    cache = CacheStore(db)
    # Seed cache with two advisories
    advs = [
        NormalizedAdvisory(
            ghsa_id="GHSA-testid-0001",
            summary="First",
            description="desc 1",
            severity="high",
            state="published",
            html_url="https://github.com/advisories/GHSA-testid-0001",
            author_login="octocat",
            updated_at=None,
        ),
        NormalizedAdvisory(
            ghsa_id="GHSA-testid-0002",
            summary="Second",
            description="desc 2",
            severity="critical",
            state="published",
            html_url="https://github.com/advisories/GHSA-testid-0002",
            author_login="octocat",
        ),
    ]
    cache.upsert_advisories(advs)
    cache.set_meta("authenticated_user", "octocat")

    app = create_app(settings, cache)

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait for server start
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        pytest.fail("Server did not start")

    try:
        # GET /rss.xml
        r = httpx.get(f"http://127.0.0.1:{port}/rss.xml", timeout=5)
        assert r.status_code == 200
        assert "application/rss+xml" in r.headers.get("content-type", "")
        # Validate XML
        root = ET.fromstring(r.text.encode("utf-8"))
        assert root.tag == "rss"
        assert root.attrib["version"] == "2.0"
        channel = root.find("channel")
        assert channel is not None
        items = channel.findall("item")
        assert len(items) >= 2
        for item in items:
            assert item.find("guid") is not None
            assert item.find("guid").attrib["isPermaLink"] == "false"
            assert item.find("title") is not None
            assert item.find("link") is not None
            assert item.find("link").text.startswith("https://github.com/")
            assert item.find("description") is not None
            assert item.find("pubDate") is not None

        # GET /health
        rh = httpx.get(f"http://127.0.0.1:{port}/health", timeout=5)
        assert rh.status_code == 200
        j = rh.json()
        assert j["advisories_count"] >= 2
        assert "rss_url" in j
        assert "127.0.0.1" in j["bind_address"]

        # Security headers present
        for h in [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
        ]:
            assert h.lower() in {k.lower(): v for k, v in r.headers.items()}

        assert config.host == "127.0.0.1"

        # Query params should be rejected 422
        rq = httpx.get(f"http://127.0.0.1:{port}/rss.xml?foo=bar", timeout=5)
        assert rq.status_code == 422

        # CORS not present (no Access-Control-Allow-Origin)
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers}

        # Docs disabled
        for path in ["/docs", "/openapi.json", "/redoc"]:
            rd = httpx.get(f"http://127.0.0.1:{port}{path}", timeout=5)
            assert rd.status_code == 404

    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_integration_does_not_listen_on_0_0_0_0(tmp_path):
    # Verify that using non-loopback setting refuses to start (startup assertion)
    from pydantic import ValidationError

    from advisory_rss.server.bind import assert_loopback

    # Validation happens at Settings creation (ValueError -> ValidationError) as well as assert_loopback (SystemExit)
    with pytest.raises((SystemExit, ValidationError)):
        s = Settings(
            _env_file=None,
            bind_address="0.0.0.0",
            port=8765,
            cache_path=str(tmp_path / "c2.db"),
        )
        assert_loopback(s.bind_address)

    # also verify other non-loopback IPs are rejected
    with pytest.raises((SystemExit, ValidationError)):
        Settings(
            _env_file=None,
            bind_address="192.168.1.1",
            port=8765,
            cache_path=str(tmp_path / "c3.db"),
        )
