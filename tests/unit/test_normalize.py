import copy
import json
from pathlib import Path

from advisory_rss.github.normalize import normalize_advisory, normalize_list


def load_fixture(name):
    p = Path(__file__).parent.parent / "fixtures" / name
    return json.loads(p.read_text())


def load_real():
    # Primary real fixture generated from live GitHub API via scripts/fixtures_generator.py
    # Uses .env token and auto-detects GITHUB_REPOS / SKIP_FULL_SCAN
    return load_fixture("real_filtered_GHSA-xxxv-2649-f3xc.json")


def test_normalize_full():
    raw = load_real()
    adv = normalize_advisory(raw)
    assert adv is not None
    assert adv.ghsa_id == "GHSA-xxxv-2649-f3xc"
    assert adv.cve_id is None
    assert adv.severity == "medium"
    assert adv.summary == "blablbalabalbalba"
    assert adv.author_login == "Lunixizm0"
    assert adv.state == "draft"
    assert (
        adv.html_url == "https://github.com/AppFuton/Futon/security/advisories/GHSA-xxxv-2649-f3xc"
    )
    # Real fixture has package ecosystem as pkg:apk/... but normalize lowercases it
    assert adv.package_name == "io.github.landwarderer.futon"
    assert adv.vulnerable_version_range == ">= 9.8.1"
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
    assert adv.ghsa_id == "GHSA-xxxv-2649-f3xc"
    assert adv.summary == "Minimal"
    assert adv.description == ""
    assert adv.severity is None
    assert adv.html_url == "https://github.com/advisories/GHSA-xxxv-2649-f3xc"  # fallback
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
    assert "GHSA-xxxv-2649-f3xc" in ids
    assert "GHSA-good-0005" in ids


def test_normalize_xss_not_crash():
    raw = load_real()
    xss = copy.deepcopy(raw)
    xss["summary"] = 'XSS <script>alert(1)</script> & "quotes"'
    xss["description"] = "Desc with & < > \" ' and ]]> cdata break"
    adv = normalize_advisory(xss)
    assert adv is not None
    assert "<script>" in adv.summary
