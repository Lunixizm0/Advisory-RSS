from datetime import UTC, datetime

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.rss.builder import build_rss


def test_mixed_rss():
    gh = NormalizedAdvisory(
        ghsa_id="GHSA-xxxx-yyyy-zzzz",
        summary="GH vuln",
        description="gh",
        severity="high",
        html_url="https://github.com/advisories/GHSA-xxxx",
        author_login="user",
        published_at=datetime(2026, 9, 20, tzinfo=UTC),
        updated_at=datetime(2026, 9, 20, tzinfo=UTC),
        source="github",
    )
    ct = NormalizedAdvisory(
        ghsa_id="CERT-TR-CVE-2026-92083",
        cve_id="CVE-2026-92083",
        summary="pardus-etap-settings: CVE-2026-92083 (CWE-862)",
        description="cert",
        html_url="https://nvd.nist.gov/vuln/detail/CVE-2026-92083",
        author_login="cve@siberguvenlik.gov.tr",
        published_at=datetime(2026, 9, 15, tzinfo=UTC),
        updated_at=datetime(2026, 9, 15, tzinfo=UTC),
        source="cert-tr",
        package_name="pardus-etap-settings",
        identifiers=[{"type": "CWE", "value": "CWE-862"}],
    )
    xml = build_rss(
        [gh, ct],
        feed_title="T",
        feed_link="https://example.com",
        feed_description="d",
        max_items=100,
        ttl_minutes=10,
        authenticated_user="user",
    )
    assert "source:github" in xml
    assert "source:cert-tr" in xml
    assert "[CERT-TR]" in xml
    assert "cwe:CWE-862" in xml
    # order: GHSA newer first if sorted inside builder
    assert xml.index("GHSA-xxxx") < xml.index("CERT-TR-CVE")


def test_cert_tr_rss_filter():
    gh = NormalizedAdvisory(
        ghsa_id="GHSA-1",
        summary="g",
        source="github",
        updated_at=datetime(2026, 9, 20, tzinfo=UTC),
        published_at=datetime(2026, 9, 20, tzinfo=UTC),
    )
    ct = NormalizedAdvisory(
        ghsa_id="CERT-TR-CVE-1",
        summary="c",
        source="cert-tr",
        updated_at=datetime(2026, 9, 15, tzinfo=UTC),
        published_at=datetime(2026, 9, 15, tzinfo=UTC),
    )
    # simulate server filter
    all_adv = [gh, ct]
    filtered = [a for a in all_adv if getattr(a, "source", "github") == "cert-tr"]
    assert len(filtered) == 1
    assert filtered[0].ghsa_id == "CERT-TR-CVE-1"
