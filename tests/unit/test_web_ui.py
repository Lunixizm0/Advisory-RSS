"""Minimal web UI: list page, detail page (full mail) and publication confirmation."""

import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import Settings
from advisory_rss.server.app import create_app

MAIL_BODY = (
    'Merhaba,\n\nTUBITAK BILGEM firmasının "pardus-update" ürününde tespit edilen '
    "CWE-494 zafiyetine ilişkin CVE-2026-114350 kodu tahsis edilmiştir.\n"
)


def _cert_tr_adv() -> NormalizedAdvisory:
    return NormalizedAdvisory(
        ghsa_id="CERT-TR-CVE-2026-114350",
        cve_id="CVE-2026-114350",
        summary="pardus-update: CVE-2026-114350 (CWE-494)",
        description=MAIL_BODY,
        severity=None,
        package_name="pardus-update",
        published_at=datetime(2026, 10, 21, 8, 44, tzinfo=UTC),
        updated_at=datetime(2026, 10, 21, 8, 44, tzinfo=UTC),
        html_url="https://nvd.nist.gov/vuln/detail/CVE-2026-114350",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2026-114350",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-114350",
        ],
        author_login="cve@siberguvenlik.gov.tr",
        identifiers=[{"type": "CWE", "value": "CWE-494"}],
        state="cve_assigned",
        source="cert-tr",
        raw={
            "message_id": "<abc@siberguvenlik.gov.tr>",
            "subject": "Zafiyet Bildiriminiz Hakkında (CVE-2026-114350)",
            "from": "Ürün Güvenliği Koordinasyon Ekibi <cve@siberguvenlik.gov.tr>",
            "reply_to": "cve@siberguvenlik.gov.tr",
            "date": "Wed, 21 Oct 2026 08:44:36 +0000",
            "in_reply_to": "",
            "references": [],
            "cves": ["CVE-2026-114350"],
            "cwe": "CWE-494",
            "product": "pardus-update",
            "html_raw_snippet": "<html><body>Merhaba</body></html>",
            "plain_snippet": MAIL_BODY,
        },
    )


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "ui.db"
    settings = Settings(
        _env_file=None,
        github_token="ghp_dummy",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db),
    )
    cache = CacheStore(db)
    cache.upsert_advisories([_cert_tr_adv()])
    app = create_app(settings, cache)
    return TestClient(app)


def _token(html: str) -> str:
    m = re.search(r'name="token" value="([0-9a-f]+)"', html)
    assert m, "no CSRF token in page"
    return m.group(1)


def test_index_lists_advisories_and_links_rss(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "pardus-update" in r.text
    # link to the feed
    assert 'href="/rss.xml"' in r.text
    # not published yet
    assert "yay" in r.text.lower()
    assert "CERT-TR" in r.text


def test_index_has_content_security_policy(client):
    r = client.get("/")
    csp = r.headers.get("content-security-policy", "")
    assert "default-src 'none'" in csp
    assert "style-src 'self'" in csp


def test_detail_shows_full_mail(client):
    r = client.get("/ui/a/CERT-TR-CVE-2026-114350")
    assert r.status_code == 200
    # full body (not truncated)
    assert "CVE-2026-114350 kodu tahsis edilmiştir" in r.text
    # headers
    assert "Zafiyet Bildiriminiz" in r.text
    assert "abc@siberguvenlik.gov.tr" in r.text
    # no invented "başvuru id"
    assert "2026-4242" not in r.text
    assert "Ba&#351;vuru id" not in r.text
    # confirmation UI
    assert "token" in r.text


def test_detail_404_for_unknown(client):
    assert client.get("/ui/a/NOPE").status_code == 404


def test_confirm_requires_valid_token(client):
    r = client.post(
        "/ui/a/CERT-TR-CVE-2026-114350/confirm",
        data={"action": "confirm", "token": "deadbeef"},
    )
    assert r.status_code == 403


def test_confirm_then_rss_points_to_nvd(client):
    page = client.get("/ui/a/CERT-TR-CVE-2026-114350")
    token = _token(page.text)
    r = client.post(
        "/ui/a/CERT-TR-CVE-2026-114350/confirm",
        data={"action": "confirm", "token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "ok=confirmed" in r.headers.get("location", "")

    # detail now offers the NVD link
    page2 = client.get("/ui/a/CERT-TR-CVE-2026-114350")
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-114350" in page2.text

    # and the feed points to NVD again
    rss = client.get("/rss.xml")
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-114350" in rss.text
    assert "[YAYINLANMADI]" not in rss.text


def test_unconfirmed_rss_points_to_local_detail(client):
    rss = client.get("/rss.xml")
    assert "http://127.0.0.1:8765/ui/a/CERT-TR-CVE-2026-114350" in rss.text
    # dead NVD link must not be advertised while unpublished
    assert "<link>https://nvd.nist.gov/vuln/detail/CVE-2026-114350</link>" not in rss.text
    assert "nvd:pending" in rss.text


def test_unconfirm_reverts_to_pending(client):
    page = client.get("/ui/a/CERT-TR-CVE-2026-114350")
    token = _token(page.text)
    client.post(
        "/ui/a/CERT-TR-CVE-2026-114350/confirm",
        data={"action": "confirm", "token": token},
    )
    r = client.post(
        "/ui/a/CERT-TR-CVE-2026-114350/confirm",
        data={"action": "unconfirm", "token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    rss = client.get("/rss.xml")
    assert "http://127.0.0.1:8765/ui/a/CERT-TR-CVE-2026-114350" in rss.text


def test_confirm_rejects_cross_origin(client):
    page = client.get("/ui/a/CERT-TR-CVE-2026-114350")
    token = _token(page.text)
    r = client.post(
        "/ui/a/CERT-TR-CVE-2026-114350/confirm",
        data={"action": "confirm", "token": token},
        headers={"Origin": "http://evil.example.com"},
    )
    assert r.status_code == 403


def test_confirm_rejects_github_advisory(client, tmp_path):
    db = tmp_path / "gh.db"
    settings = Settings(
        _env_file=None,
        github_token="ghp_dummy",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db),
    )
    cache = CacheStore(db)
    cache.upsert_advisories(
        [
            NormalizedAdvisory(
                ghsa_id="GHSA-test-0001",
                summary="gh",
                source="github",
                html_url="https://github.com/advisories/GHSA-test-0001",
            )
        ]
    )
    app = create_app(settings, cache)
    with TestClient(app) as c:
        r = c.post("/ui/a/GHSA-test-0001/confirm", data={"action": "confirm", "token": "x"})
        assert r.status_code == 400


def test_mail_html_is_escaped(tmp_path):
    db = tmp_path / "xss.db"
    settings = Settings(
        _env_file=None,
        github_token="ghp_dummy",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db),
    )
    cache = CacheStore(db)
    adv = _cert_tr_adv()
    adv.description = "<script>alert(1)</script>\n" + MAIL_BODY
    cache.upsert_advisories([adv])
    app = create_app(settings, cache)
    with TestClient(app) as c:
        r = c.get("/ui/a/CERT-TR-CVE-2026-114350")
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;" in r.text


def test_ui_feed_redirects_to_rss(client):
    r = client.get("/ui/feed", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get("location") == "/rss.xml"


def test_health_reports_pending(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["cert_tr_count"] == 1
    assert data["cert_tr_pending_count"] == 1
    assert data["web_ui_enabled"] is True


def test_web_ui_can_be_disabled(tmp_path):
    db = tmp_path / "off.db"
    settings = Settings(
        _env_file=None,
        github_token="ghp_dummy",
        bind_address="127.0.0.1",
        port=8765,
        cache_path=str(db),
        enable_web_ui=False,
    )
    cache = CacheStore(db)
    cache.upsert_advisories([_cert_tr_adv()])
    app = create_app(settings, cache)
    with TestClient(app) as c:
        r = c.get("/")
        assert r.status_code == 200
        assert "application/json" in r.headers.get("content-type", "")
        assert c.get("/ui/a/CERT-TR-CVE-2026-114350").status_code == 404
        # the feed still works
        assert c.get("/rss.xml").status_code == 200
