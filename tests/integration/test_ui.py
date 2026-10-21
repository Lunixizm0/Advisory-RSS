import socket
import threading
import time

import httpx
import pytest
import uvicorn

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.server.app import create_app


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def server(tmp_path):
    db = tmp_path / "ui-int.db"
    port = _free_port()
    settings = Settings(
        _env_file=None,
        github_token="ghp_dummy",
        bind_address="127.0.0.1",
        port=port,
        cache_path=str(db),
    )
    cache = CacheStore(db)
    cache.upsert_advisories(
        [
            NormalizedAdvisory(
                ghsa_id="CERT-TR-CVE-2026-55555",
                cve_id="CVE-2026-55555",
                summary="urdum: CVE-2026-55555",
                description="CVE-2026-55555 kodu tahsis edilmiştir.",
                html_url="https://nvd.nist.gov/vuln/detail/CVE-2026-55555",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2026-55555"],
                state="cve_assigned",
                source="cert-tr",
            )
        ]
    )
    app = create_app(settings, cache)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        pytest.fail("Server did not start")
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.should_exit = True
        thread.join(timeout=5)


def test_ui_index_and_detail_over_http(server):
    r = httpx.get(f"{server}/", timeout=5)
    assert r.status_code == 200
    assert "urdum" in r.text

    d = httpx.get(f"{server}/ui/a/CERT-TR-CVE-2026-55555", timeout=5)
    assert d.status_code == 200
    assert "CVE-2026-55555 kodu tahsis edilmiştir" in d.text

    # feed points to the local page while not published
    feed = httpx.get(f"{server}/rss.xml", timeout=5)
    assert "http://127.0.0.1" in feed.text
    assert "/ui/a/CERT-TR-CVE-2026-55555" in feed.text


def test_ui_feed_redirect_over_http(server):
    r = httpx.get(f"{server}/ui/feed", timeout=5, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get("location") == "/rss.xml"


def test_ui_style_endpoint_over_http(server):
    r = httpx.get(f"{server}/ui/style.css", timeout=5)
    assert r.status_code == 200
    assert "text/css" in r.headers.get("content-type", "")
