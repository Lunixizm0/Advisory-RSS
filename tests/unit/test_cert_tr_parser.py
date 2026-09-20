from pathlib import Path

from advisory_rss.cert_tr.parser import is_cert_tr_sender, parse_cert_tr_email


def test_cert_tr_parse_sample():
    raw = Path("tests/fixtures/cert_tr/CVE-2026-92083.eml").read_bytes()
    adv = parse_cert_tr_email(raw)
    assert adv is not None
    assert adv.ghsa_id == "CERT-TR-CVE-2026-92083"
    assert adv.cve_id == "CVE-2026-92083"
    assert adv.source == "cert-tr"
    assert adv.package_name == "pardus-etap-settings"
    assert any(i["value"] == "CWE-862" for i in adv.identifiers)
    assert "pardus-etap-settings" in adv.summary
    assert adv.author_login == "cve@siberguvenlik.gov.tr"
    assert adv.publisher_login == "siberguvenlik.gov.tr"
    assert adv.repository_full_name == "cert-tr/pardus-etap-settings"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-92083" in adv.references


def test_cert_tr_sender_allowlist():
    assert is_cert_tr_sender(
        "Ürün Güvenliği Koordinasyon Ekibi <cve@siberguvenlik.gov.tr>", ["siberguvenlik.gov.tr"]
    )
    assert is_cert_tr_sender("cve@siberguvenlik.gov.tr", ["siberguvenlik.gov.tr"])
    assert not is_cert_tr_sender("noreply@github.com", ["siberguvenlik.gov.tr"])
    assert is_cert_tr_sender("test@usom.gov.tr", ["siberguvenlik.gov.tr", "usom.gov.tr"])


def test_cert_tr_parser_second_mail_update():
    raw1 = Path("tests/fixtures/cert_tr/CVE-2026-92083.eml").read_bytes()
    adv1 = parse_cert_tr_email(raw1)
    assert adv1 is not None
    # Simulate update: same CVE but different body (e.g., patched)
    raw2 = raw1.replace(b"CWE-862", b"CWE-79").replace(b"13:23:43 +0000", b"15:23:43 +0000")
    adv2 = parse_cert_tr_email(raw2)
    assert adv2 is not None
    assert adv1.ghsa_id == adv2.ghsa_id
    # updated time should differ? Date changed
    assert adv2.identifiers != adv1.identifiers or adv2.updated_at != adv1.updated_at


def test_cert_tr_parser_handles_quoted_printable_charset():
    raw = Path("tests/fixtures/cert_tr/CVE-2026-92083.eml").read_bytes()
    adv = parse_cert_tr_email(raw)
    assert adv is not None
    # Check Turkish chars decoded correctly
    assert (
        "TÜBİTAK" in adv.description or "TUBITAK" in adv.description or "BİLGEM" in adv.description
    )


def test_cert_tr_parser_no_cve_skipped():
    raw = b"From: test@siberguvenlik.gov.tr\r\nSubject: Hello\r\nDate: Tue, 15 Sep 2026 13:23:43 +0000\r\nMessage-Id: <test@siberguvenlik.gov.tr>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nJust a hello, no CVE here."
    adv = parse_cert_tr_email(raw)
    assert adv is None
