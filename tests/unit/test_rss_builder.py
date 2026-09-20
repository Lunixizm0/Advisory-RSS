import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.rss.builder import build_rss


def make_adv(ghsa, updated_offset_hours=0, withdrawn=False, summary="Test < & >"):
    dt = datetime(2025, 1, 10, 10, 0, 0, tzinfo=UTC) + timedelta(hours=updated_offset_hours)
    return NormalizedAdvisory(
        ghsa_id=ghsa,
        cve_id="CVE-2025-0001" if "abcd" in ghsa else None,
        summary=summary,
        description="Desc with & <script> and ]]> break",
        severity="high",
        package_ecosystem="npm",
        package_name="foo",
        vulnerable_version_range="< 1.0",
        patched_versions="1.0",
        published_at=dt - timedelta(days=1),
        updated_at=dt,
        withdrawn_at=dt if withdrawn else None,
        state="published",
        html_url=f"https://github.com/octo/repo/security/advisories/{ghsa}",
        repository_url="https://github.com/octo/repo",
        repository_full_name="octo/repo",
        references=["https://example.com"],
        author_login="octocat",
    )


def test_rss_valid_xml_and_required_elements():
    advs = [
        make_adv("GHSA-abcd-1234-efgh"),
        make_adv("GHSA-2222-3333-4444", updated_offset_hours=5),
    ]
    xml = build_rss(
        advs,
        feed_title="Test Feed",
        feed_link="https://example.com",
        feed_description="desc",
        max_items=100,
        ttl_minutes=10,
        authenticated_user="tester",
    )
    # valid xml
    root = ET.fromstring(xml.encode("utf-8"))
    assert root.tag == "rss"
    assert root.attrib["version"] == "2.0"  
    channel = root.find("channel")  
    assert channel is not None
    assert channel.find("title") is not None  
    assert channel.find("link") is not None  
    assert channel.find("description") is not None  
    items = channel.findall("item")  
    assert len(items) == 2
    for item in items:
        assert item.find("guid") is not None  
        assert item.find("guid").attrib["isPermaLink"] == "false"  
        assert item.find("title") is not None  
        assert item.find("link") is not None  
        assert item.find("description") is not None  
        assert item.find("pubDate") is not None  
        assert item.find("author") is not None  
        assert item.find("category") is not None  


def test_rss_sorted_by_updated_desc():
    a_old = make_adv("GHSA-old", updated_offset_hours=0)
    a_new = make_adv("GHSA-new", updated_offset_hours=10)
    xml = build_rss(
        [a_old, a_new],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    root = ET.fromstring(xml.encode("utf-8"))
    guids = [i.find("guid").text for i in root.find("channel").findall("item")]  
    assert guids[0] == "GHSA-new"
    assert guids[1] == "GHSA-old"


def test_rss_stable_guid():
    adv = make_adv("GHSA-abcd-1234-efgh")
    xml1 = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    xml2 = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    import re

    def guids(xml):
        return re.findall(r"<guid[^>]*>(.*?)</guid>", xml)

    assert guids(xml1) == guids(xml2) == ["GHSA-abcd-1234-efgh"]


def test_rss_escaping():
    adv = make_adv("GHSA-xss-0003", summary='XSS <script>alert(1)</script> & "quotes"')
    xml = build_rss(
        [adv],
        feed_title="t & <b>",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    # Should be valid and escaped - title should not contain raw <script> outside CDATA
    assert "&lt;script&gt;" in xml
    # description CDATA should contain safe break
    assert "<![CDATA[" in xml
    # The ]]> in description should be escaped via CDATA split
    # Make sure xml parses
    ET.fromstring(xml.encode("utf-8"))
    # Ensure no raw unescaped & in title outside entities
    assert '& "quotes"' not in xml  # should be escaped


def test_rss_withdrawn_present():
    adv = make_adv("GHSA-withdrawn", withdrawn=True)
    xml = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    root = ET.fromstring(xml.encode("utf-8"))
    item = root.find("channel").find("item")  
    title = item.find("title").text  
    assert "[WITHDRAWN]" in title 
    cats = [c.text for c in item.findall("category")]  
    assert "withdrawn" in cats


def test_rss_empty_list_valid():
    xml = build_rss(
        [],
        feed_title="Empty",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    root = ET.fromstring(xml.encode("utf-8"))
    assert len(root.find("channel").findall("item")) == 0  
    assert root.find("channel").find("ttl") is not None  


def test_rss_pubdate_rfc822():
    dt = datetime(2025, 1, 10, 12, 34, 56, tzinfo=UTC)
    adv = NormalizedAdvisory(
        ghsa_id="GHSA-pub-1",
        summary="s",
        published_at=dt,
        updated_at=dt,
        state="published",
        html_url="https://github.com/advisories/GHSA-pub-1",
    )
    xml = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    # RFC822 e.g., Fri, 10 Jan 2025 12:34:56 GMT
    assert "Fri, 10 Jan 2025 12:34:56 GMT" in xml
    # dc:date iso
    assert "2025-01-10T12:34:56Z" in xml


def test_rss_content_encoded_present():
    adv = make_adv("GHSA-c-1")
    xml = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    assert "content:encoded" in xml
    assert "dc:date" in xml


def test_rss_link_points_to_github_not_internal():
    adv = make_adv("GHSA-link-1")
    xml = build_rss(
        [adv],
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        authenticated_user="u",
    )
    root = ET.fromstring(xml.encode("utf-8"))
    link = root.find("channel").find("item").find("link").text  
    assert link is not None and link.startswith("https://github.com/")  
    assert "127.0.0.1" not in link


def test_rss_max_items_truncates():
    advs = [make_adv(f"GHSA-{i:04d}-0000", updated_offset_hours=i) for i in range(5)]
    xml = build_rss(
        advs,
        feed_title="t",
        feed_link="https://a",
        feed_description="d",
        max_items=2,
        authenticated_user="u",
    )
    root = ET.fromstring(xml.encode("utf-8"))
    assert len(root.find("channel").findall("item")) == 2  
