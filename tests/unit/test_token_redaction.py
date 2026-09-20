import logging

from fastapi.testclient import TestClient

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.rss.builder import build_rss
from advisory_rss.server.app import create_app


def test_no_token_in_rss():
    adv = NormalizedAdvisory(
        ghsa_id="GHSA-testid-0001",
        summary="test",
        description="desc",
        html_url="https://github.com/advisories/GHSA-testid-0001",
        author_login="octocat",
    )
    xml = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    assert "ghp_" not in xml
    assert "github_pat_" not in xml
    # ensure GHSA still present
    assert "GHSA-testid-0001" in xml


def test_no_token_in_logs(caplog):
    caplog.set_level(logging.WARNING)
    logger = logging.getLogger("advisory_rss.github.client")  
    # Simulate redaction via client helper: we check log doesn't contain token via _redact in client
    from advisory_rss.github.client import _redact

    redacted = _redact("Bearer ghp_abc123XYZ and github_pat_123_abc")
    assert "ghp_" not in redacted
    assert "github_pat_" not in redacted
    assert "***" in redacted


def test_no_token_in_health_and_rss_via_server(tmp_path):
    db = tmp_path / "c.db"
    settings = Settings(
        _env_file=None,  # 
        github_token="ghp_supersecrettokenXYZ",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db),
    )
    cache = CacheStore(db)
    # Insert dummy advisory that contains no token
    adv = NormalizedAdvisory(
        ghsa_id="GHSA-1", summary="s", html_url="https://github.com/advisories/GHSA-1"
    )
    cache.upsert_advisories([adv])
    cache.set_meta("authenticated_user", "octocat")
    app = create_app(settings, cache)
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.text
    assert "ghp_" not in body
    assert "github_pat_" not in body
    r2 = client.get("/rss.xml")
    assert r2.status_code == 200
    assert "ghp_" not in r2.text


def test_no_token_in_error_response(tmp_path):
    settings = Settings(
        _env_file=None,  
        github_token="ghp_tok",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(tmp_path / "c2.db"),
    )  # 
    cache = CacheStore(settings.resolved_cache_path)
    app = create_app(settings, cache)
    client = TestClient(app, raise_server_exceptions=False)
    # POST to /refresh when disabled should be 404 not leak token
    r = client.post("/refresh")
    assert r.status_code == 404
    assert "ghp_" not in r.text
