from pathlib import Path

from advisory_rss.cert_tr.parser import is_cert_tr_sender, parse_cert_tr_email

SAMPLE_EMAIL = (
    Path(__file__).resolve().parent.parent / "fixtures" / "cert_tr" / "sample_cert_tr.eml"
)


def _sample_email() -> bytes:
    return SAMPLE_EMAIL.read_bytes()


def test_cert_tr_parse_sample():
    raw = _sample_email()
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


def test_cert_tr_state_is_cve_assigned_not_published():
    # A CVE ID allocation is NOT a publication
    adv = parse_cert_tr_email(_sample_email())
    assert adv is not None
    assert adv.state == "cve_assigned"


def test_cert_tr_parser_extracts_thread_headers():
    raw = (
        b"From: cve@siberguvenlik.gov.tr\r\n"
        b"To: test@example.com\r\n"
        b"Subject: Zafiyet Bildiriminiz Hakkinda (CVE-2026-99999)\r\n"
        b"Date: Tue, 15 Sep 2026 13:23:43 +0000\r\n"
        b"Message-Id: <second@siberguvenlik.gov.tr>\r\n"
        b"In-Reply-To: <first@siberguvenlik.gov.tr>\r\n"
        b"References: <first@siberguvenlik.gov.tr> <second@siberguvenlik.gov.tr>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"CVE-2026-99999 kodu tahsis edilmistir.\r\n"
    )
    adv = parse_cert_tr_email(raw)
    assert adv is not None
    assert adv.raw["in_reply_to"] == "<first@siberguvenlik.gov.tr>"
    assert adv.raw["references"] == [
        "<first@siberguvenlik.gov.tr>",
        "<second@siberguvenlik.gov.tr>",
    ]


def test_cert_tr_parser_ignores_proton_internal_ids():
    raw = (
        b"From: cve@siberguvenlik.gov.tr\r\n"
        b"To: test@example.com\r\n"
        b"Subject: Zafiyet Bildiriminiz Hakkinda (CVE-2026-77777)\r\n"
        b"Date: Tue, 15 Sep 2026 13:23:43 +0000\r\n"
        b"Message-Id: <real@siberguvenlik.gov.tr>\r\n"
        b"References: <CH-abc==@protonmail.internalid>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"CVE-2026-77777 kodu tahsis edilmistir.\r\n"
    )
    adv = parse_cert_tr_email(raw)
    assert adv is not None
    # Proton's own internal id is not a thread reference
    assert adv.raw["references"] == []
    assert adv.raw["in_reply_to_ids"] == []


def test_cert_tr_parser_does_not_invent_reference_no():
    # The mails carry no parsable "başvuru id" - we must not invent one
    raw = (
        b"From: cve@siberguvenlik.gov.tr\r\n"
        b"To: test@example.com\r\n"
        b"Subject: Zafiyet Bildiriminiz Hakkinda (CVE-2026-88888)\r\n"
        b"Date: Tue, 15 Sep 2026 13:23:43 +0000\r\n"
        b"Message-Id: <ref@siberguvenlik.gov.tr>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"CVE-2026-88888 kodu tahsis edilmistir, ilan edilecektir.\r\n"
    )
    adv = parse_cert_tr_email(raw)
    assert adv is not None
    assert "reference_no" not in adv.raw


def test_cert_tr_sender_allowlist():
    assert is_cert_tr_sender(
        "Ürün Güvenliği Koordinasyon Ekibi <cve@siberguvenlik.gov.tr>", ["siberguvenlik.gov.tr"]
    )
    assert is_cert_tr_sender("cve@siberguvenlik.gov.tr", ["siberguvenlik.gov.tr"])
    assert not is_cert_tr_sender("noreply@github.com", ["siberguvenlik.gov.tr"])
    assert is_cert_tr_sender("test@usom.gov.tr", ["siberguvenlik.gov.tr", "usom.gov.tr"])


def test_cert_tr_parser_second_mail_update():
    raw1 = _sample_email()
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
    raw = _sample_email()
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
