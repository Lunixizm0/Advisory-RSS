import copy
import json
from pathlib import Path

from advisory_rss.github.normalize import normalize_advisory, normalize_list


def load_fixture(name):
    p = Path(__file__).parent.parent / "fixtures" / name
    return json.loads(p.read_text())


def _synthetic_fixture():
    """
    Real fixtures (real_filtered_GHSA-*.json) are per-user and gitignored.
    This synthetic mimics the same shape so tests pass for everyone without
    needing a personal PAT or `python scripts/fixtures_generator.py`.
    """
    return {
        "ghsa_id": "GHSA-synth-0001-0001",
        "cve_id": None,
        "summary": "Synthetic test advisory",
        "description": "Synthetic description for testing normalize.",
        "severity": "medium",
        "author": {"login": "testauthor"},
        "publisher": None,
        "state": "draft",
        "html_url": "https://github.com/example/repo/security/advisories/GHSA-synth-0001-0001",
        "url": "https://api.github.com/repos/example/repo/security-advisories/GHSA-synth-0001-0001",
        "published_at": None,
        "updated_at": "2026-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z",
        "withdrawn_at": None,
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "example-pkg"},
                "vulnerable_version_range": ">= 1.0.0",
                "patched_versions": ">= 1.0.1",
            }
        ],
        "identifiers": [{"type": "GHSA", "value": "GHSA-synth-0001-0001"}],
        "references": [],
        "_injected_repo": "example/repo",
    }


def load_real():
    # Primary real fixture generated from live GitHub API via scripts/fixtures_generator.py
    # Uses .env token and auto-detects GITHUB_REPOS / SKIP_FULL_SCAN
    # For open-source: real fixtures are gitignored (per-user), so fallback to synthetic.
    # Try any user-generated real_filtered_*.json first (covers personal GHSA without hardcoding)
    try:
        globs = list((Path(__file__).parent.parent / "fixtures").glob("real_filtered_GHSA-*.json"))
        if globs:
            # Prefer most recently modified
            globs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            return json.loads(globs[0].read_text())
    except Exception:
        pass
    # No real fixture found (common for open-source contributors) -> synthetic
    return _synthetic_fixture()


def test_normalize_full():
    raw = load_real()
    adv = normalize_advisory(raw)
    assert adv is not None
    assert adv.ghsa_id == raw.get("ghsa_id")
    assert adv.ghsa_id.startswith("GHSA-")
    # cve may be None for synthetic/draft
    assert adv.cve_id == raw.get("cve_id")
    assert adv.severity == (raw.get("severity") or "medium").lower()
    assert adv.summary == raw.get("summary")
    # author is per-user - compare to fixture, not hardcoded Lunixizm0
    expected_author = (raw.get("author") or {}).get("login") if isinstance(raw.get("author"), dict) else None
    assert adv.author_login == expected_author
    assert adv.state == raw.get("state")
    # html_url should contain GHSA id and be a github URL
    assert adv.ghsa_id in adv.html_url
    assert adv.html_url.startswith("https://github.com/")
    # package extraction is tolerant - compare to fixture if present
    vulns = raw.get("vulnerabilities") or []
    if vulns and isinstance(vulns[0], dict):
        expected_pkg = vulns[0].get("package", {}).get("name") if isinstance(vulns[0].get("package"), dict) else None
        expected_range = vulns[0].get("vulnerable_version_range")
        if expected_pkg:
            assert adv.package_name == expected_pkg
        if expected_range:
            assert adv.vulnerable_version_range == expected_range
    assert adv.updated_at is not None


def test_normalize_minimal_missing_fields():
    # Derive minimal from real by stripping optional fields
    raw = load_real()
    minimal = {
        "ghsa_id": raw["ghsa_id"],
        "summary": "Minimal",
        "description": None,
        "severity": None,
        "author": None,
        "state": "draft",
        "html_url": None,
        "updated_at": None,
        "published_at": None,
    }
    adv = normalize_advisory(minimal)
    assert adv is not None
    assert adv.ghsa_id == raw["ghsa_id"]
    assert adv.summary == "Minimal"
    assert adv.description == ""
    assert adv.severity is None
    assert adv.html_url == f"https://github.com/advisories/{raw['ghsa_id']}"  # fallback
    assert adv.author_login is None
    assert adv.state == "draft"


def test_normalize_nulls_and_missing():
    adv = normalize_advisory({})
    assert adv is None
    adv2 = normalize_advisory({"ghsa_id": "", "summary": "x"})
    assert adv2 is None


def test_normalize_withdrawn():
    raw = load_real()
    withdrawn = copy.deepcopy(raw)
    withdrawn["withdrawn_at"] = "2025-02-03T10:00:00Z"
    withdrawn["state"] = "published"
    adv = normalize_advisory(withdrawn)
    assert adv is not None
    assert adv.withdrawn_at is not None
    assert adv.state == "published"


def test_normalize_tolerates_bad_vuln():
    raw = {
        "ghsa_id": "GHSA-bad-0001",
        "vulnerabilities": "not-a-list",
        "summary": "bad",
    }
    adv = normalize_advisory(raw)
    assert adv is not None
    assert adv.package_name is None


def test_normalize_list_skips_malformed():
    real = load_real()
    lst = [
        real,
        {"not": "advisory"},
        None,
        {"ghsa_id": "GHSA-minimal-0001", "summary": "Minimal", "state": "draft"},
        {"ghsa_id": "GHSA-good-0005", "summary": "good"},
    ]
    out = normalize_list(lst)
    assert len(out) >= 3  # real, minimal, good
    ids = {a.ghsa_id for a in out}
    assert real["ghsa_id"] in ids
    assert "GHSA-good-0005" in ids


def test_normalize_xss_not_crash():
    raw = load_real()
    xss = copy.deepcopy(raw)
    xss["summary"] = 'XSS <script>alert(1)</script> & "quotes"'
    xss["description"] = "Desc with & < > \" ' and ]]> cdata break"
    adv = normalize_advisory(xss)
    assert adv is not None
    assert "<script>" in adv.summary
