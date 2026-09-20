from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.github.filter import filter_advisories, matches_filter


def make_adv(ghsa, author, publisher=None, collab=None):
    raw = {}
    if collab:
        raw["collaborating_users"] = [{"login": c} for c in collab]
    return NormalizedAdvisory(
        ghsa_id=ghsa,
        author_login=author,
        publisher_login=publisher,
        summary="test",
        raw=raw,
    )


def test_filter_author_exact():
    adv = make_adv("GHSA-1", "octocat")
    assert matches_filter(adv, "octocat", "author") is True
    assert matches_filter(adv, "other", "author") is False


def test_filter_case_insensitive():
    adv = make_adv("GHSA-1", "OctoCat")
    assert matches_filter(adv, "octocat", "author") is True
    assert matches_filter(adv, "OCTOCAT", "author") is True


def test_filter_author_or_publisher():
    adv = make_adv("GHSA-1", "other", publisher="octocat")
    assert matches_filter(adv, "octocat", "author") is False
    assert matches_filter(adv, "octocat", "author_or_publisher") is True


def test_filter_author_or_collaborator():
    adv = make_adv("GHSA-1", "other", collab=["other", "octocat"])
    assert matches_filter(adv, "octocat", "author") is False
    assert matches_filter(adv, "octocat", "author_or_collaborator") is True
    # publisher also counts in collaborator mode
    adv2 = make_adv("GHSA-2", "other", publisher="octocat")
    assert matches_filter(adv2, "octocat", "author_or_collaborator") is True


def test_filter_distinguishes_owned_vs_authored():
    # Advisory in repo owned by user but authored by someone else - should NOT match author mode
    adv = make_adv("GHSA-owned", "eve")
    adv.repository_full_name = "octocat/repo"  # owned but not authored
    assert matches_filter(adv, "octocat", "author") is False
    assert matches_filter(adv, "octocat", "author_or_publisher") is False


def test_filter_non_author_excluded():
    advs = [
        make_adv("GHSA-1", "octocat"),
        make_adv("GHSA-2", "eve"),
        make_adv("GHSA-3", "OCTOCAT"),
    ]
    filtered = filter_advisories(advs, "octocat", "author")
    assert len(filtered) == 2
    assert {a.ghsa_id for a in filtered} == {"GHSA-1", "GHSA-3"}


def test_filter_empty_login_returns_none():
    adv = make_adv("GHSA-1", "octocat")
    assert matches_filter(adv, "", "author") is False
    assert filter_advisories([adv], "", "author") == []
