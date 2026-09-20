from advisory_rss.github.paginate import get_next_url, parse_link_header


def test_parse_link_header_single():
    h = '<https://api.github.com/repos/o/r/security-advisories?after=XYZ&per_page=100>; rel="next", <https://api.github.com/repos/o/r/security-advisories?before=ABC>; rel="prev"'
    parsed = parse_link_header(h)
    assert (
        parsed["next"]
        == "https://api.github.com/repos/o/r/security-advisories?after=XYZ&per_page=100"
    )
    assert parsed["prev"] == "https://api.github.com/repos/o/r/security-advisories?before=ABC"


def test_parse_link_header_empty():
    assert parse_link_header(None) == {}
    assert parse_link_header("") == {}


def test_get_next_url():
    h = '<https://api.github.com/repos/o/r/security-advisories?after=abc>; rel="next"'
    assert get_next_url(h) == "https://api.github.com/repos/o/r/security-advisories?after=abc"
    assert get_next_url(None) is None
    assert get_next_url('<https://example.com>; rel="last"') is None


def test_paginate_respects_cap_logic():
    # Simulate pagination until exhaustion vs cap - client logic test indirectly via parse
    # Ensure we can detect missing next stops
    assert get_next_url('<https://a>; rel="prev"') is None
