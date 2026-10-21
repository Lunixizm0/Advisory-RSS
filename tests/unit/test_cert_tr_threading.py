"""Conversation grouping for CERT-TR mails (thread headers + CVE set)."""

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cert_tr.threading import (
    case_reference_id,
    conversation_key,
    conversation_label,
    cve_set,
    group_by_conversation,
    thread_root_id,
)


def _adv(**kwargs) -> NormalizedAdvisory:
    raw = kwargs.pop("raw", {})
    return NormalizedAdvisory(
        ghsa_id=kwargs.pop("ghsa_id", "CERT-TR-CVE-2026-1"),
        cve_id=kwargs.pop("cve_id", "CVE-2026-1"),
        source="cert-tr",
        raw=raw,
        **kwargs,
    )


def test_thread_root_from_references():
    raw = {"references": ["<a@x>", "<b@x>"], "in_reply_to": "<b@x>"}
    assert thread_root_id(raw) == "<a@x>"


def test_thread_root_from_in_reply_to():
    raw = {"references": [], "in_reply_to": "<b@x>"}
    assert thread_root_id(raw) == "<b@x>"


def test_thread_root_none():
    assert thread_root_id({}) is None
    assert thread_root_id(None) is None


def test_case_reference_id_is_empty():
    # not extractable from the mails today
    assert case_reference_id({"reference_no": "2026-1234"}) is None
    assert case_reference_id({}) is None


def test_cve_set_includes_extra_cves():
    adv = _adv(cve_id="CVE-2026-2", extra_cves=["CVE-2026-1", "CVE-2026-2"])
    assert cve_set(adv) == ("CVE-2026-1", "CVE-2026-2")


def test_conversation_key_thread_and_cves():
    adv = _adv(raw={"references": ["<root@x>"]})
    assert conversation_key(adv) == "<root@x>|CVE-2026-1"


def test_conversation_key_falls_back_to_cves_only():
    adv = _adv()
    assert conversation_key(adv) == "cve:CVE-2026-1"
    assert conversation_label(adv) == ""


def test_conversation_key_only_cves():
    adv = _adv()
    assert conversation_key(adv) == "cve:CVE-2026-1"


def test_group_by_conversation_groups_same_thread_and_cves():
    # Same thread root + same CVE set -> same conversation
    a = _adv(ghsa_id="CERT-TR-CVE-2026-1", cve_id="CVE-2026-1", raw={"references": ["<root@x>"]})
    b = _adv(ghsa_id="CERT-TR-CVE-2026-1", cve_id="CVE-2026-1", raw={"references": ["<root@x>"]})
    c = _adv(ghsa_id="CERT-TR-CVE-2026-3", cve_id="CVE-2026-3", raw={"references": ["<other@x>"]})
    groups = group_by_conversation([a, b, c])
    assert len(groups) == 2
    assert len(groups["<root@x>|CVE-2026-1"]) == 2
    assert len(groups["<other@x>|CVE-2026-3"]) == 1


def test_group_by_conversation_keeps_unknown_separate():
    a = _adv(ghsa_id="CERT-TR-CVE-2026-1", cve_id=None, raw={})
    groups = group_by_conversation([a])
    assert list(groups.keys()) == ["id:CERT-TR-CVE-2026-1"]
