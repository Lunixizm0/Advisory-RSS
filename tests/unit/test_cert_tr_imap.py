import imaplib
from unittest.mock import MagicMock, patch

from advisory_rss.cert_tr.imap import fetch_raw_emails

SAMPLE_RAW = (
    b"From: cve@siberguvenlik.gov.tr\r\nSubject: Test CVE-2026-0001\r\n\r\nBody CVE-2026-0001"
)


def _mock_imap(data_bytes_list):
    """Create mock IMAP object that returns uids and fetches."""
    mock = MagicMock()
    # select
    mock.select.return_value = ("OK", [b"1"])
    # search returns uids
    mock.search.return_value = ("OK", [b"1 2"])

    # fetch returns tuple per uid
    def fetch_side(uid, _what):
        # uid can be bytes like b"2" or b"1"
        if isinstance(uid, bytes):
            uid_s = uid.decode()
        else:
            uid_s = str(uid)
        # map uid to sample
        idx = 0 if uid_s == "2" else 1
        raw = data_bytes_list[idx] if idx < len(data_bytes_list) else data_bytes_list[0]
        return ("OK", [(b"1 (BODY[] {10}", raw)])

    mock.fetch.side_effect = fetch_side
    return mock


def test_fetch_never_marks_read():
    acc = {
        "email": "a@proton.me",
        "password": "p",
        "folder": "INBOX",
        "host": "127.0.0.1",
        "port": "1143",
        "security": "STARTTLS",
    }
    with patch("advisory_rss.cert_tr.imap.connect_imap") as mock_connect:
        mock = _mock_imap([SAMPLE_RAW, SAMPLE_RAW])
        mock_connect.return_value = mock
        raws = fetch_raw_emails(acc, ["siberguvenlik.gov.tr"], max_mails=2)
        # Should have used BODY.PEEK[]
        assert mock.fetch.called
        for call_args in mock.fetch.call_args_list:
            args, _kwargs = call_args
            assert "BODY.PEEK" in args[1]
        # Should have selected readonly=True
        assert mock.select.called
        for c in mock.select.call_args_list:
            args, kwargs = c
            assert kwargs.get("readonly") is True
        assert len(raws) == 2


def test_fetch_multi_account_distinct_folders():
    from advisory_rss.config.settings import Settings

    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        PROTON_BRIDGE_EMAILS="a@proton.me,b@proton.me",
        PROTON_BRIDGE_PASSWORDS="p1,p2",
        PROTON_IMAP_FOLDERS="INBOX,INBOX.CERT-TR",
        _env_file_encoding="utf-8",
    )
    accs = s.get_proton_accounts()
    assert accs[0]["folder"] == "INBOX"
    assert accs[1]["folder"] == "INBOX.CERT-TR"
    # ensure each fetch would select its folder
    with patch("advisory_rss.cert_tr.imap.connect_imap") as mock_connect:
        m1 = _mock_imap([SAMPLE_RAW])
        m2 = _mock_imap([SAMPLE_RAW])
        mock_connect.side_effect = [m1, m2]
        assert fetch_raw_emails(accs[0], ["siberguvenlik.gov.tr"], max_mails=1) is not None
        assert fetch_raw_emails(accs[1], ["siberguvenlik.gov.tr"], max_mails=1) is not None
        assert m1.select.call_args[0][0] == "INBOX"
        assert m2.select.call_args[0][0] == "INBOX.CERT-TR"


def test_gmail_host_allowed_and_proton_loopback():
    from advisory_rss.cert_tr.imap import ALLOWED_HOSTS, _is_host_allowed, connect_imap


    assert _is_host_allowed("imap.gmail.com")
    assert _is_host_allowed("127.0.0.1")
    assert ALLOWED_HOSTS.issuperset({"imap.gmail.com"})
    assert ALLOWED_HOSTS.issuperset({"127.0.0.1"})
    # Also verify exact-set property without using `in` on a URL-like literal
    assert any(h == "imap.gmail.com" for h in ALLOWED_HOSTS)
    assert any(h == "127.0.0.1" for h in ALLOWED_HOSTS)
    # Substring / suffix bypasses must be rejected - exact match only
    assert not _is_host_allowed("evil.com")
    assert not _is_host_allowed("evil.com/imap.gmail.com")
    assert not _is_host_allowed("imap.gmail.com.evil.com")
    assert not _is_host_allowed("benign-prefix-imap.gmail.com")
    assert not _is_host_allowed("imap.gmail.com:999")
    assert not _is_host_allowed("https://imap.gmail.com")
    assert not _is_host_allowed("")
    assert not _is_host_allowed(" ")
    # Case-insensitive exact match should pass (DNS lower)
    assert _is_host_allowed("IMAP.GMAIL.COM")
    assert _is_host_allowed("  imap.gmail.com  ")

    # Gmail host should be allowed (mock network to avoid real connection)
    with patch("advisory_rss.cert_tr.imap.imaplib.IMAP4_SSL") as mock_ssl:
        mock_inst = MagicMock()
        mock_inst.login.side_effect = imaplib.IMAP4.error("mock auth fail")
        mock_ssl.return_value = mock_inst
        try:
            connect_imap(
                {
                    "host": "imap.gmail.com",
                    "port": "993",
                    "security": "SSL",
                    "email": "test@gmail.com",
                    "password": "bad",
                }
            )
        except imaplib.IMAP4.error:
            pass  # expected login failure, host was allowed
        except ValueError as ve:
            raise AssertionError(f"imap.gmail.com should be allowed, got {ve}") from ve

    # Evil host should be rejected before network
    try:
        connect_imap(
            {
                "host": "evil.com",
                "port": "993",
                "security": "SSL",
                "email": "test@gmail.com",
                "password": "bad",
            }
        )
        raise AssertionError("evil host should be rejected")
    except ValueError as ve:
        assert "IMAP host" in str(ve)

    # Substring bypasses via evil hosts containing allowed host must be rejected
    for evil in [
        "evil.com/imap.gmail.com",
        "imap.gmail.com.evil.com",
        "benign-prefix-imap.gmail.com",
        "imap.gmail.com:999",
        "https://imap.gmail.com",
    ]:
        try:
            connect_imap(
                {
                    "host": evil,
                    "port": "993",
                    "security": "SSL",
                    "email": "test@gmail.com",
                    "password": "bad",
                }
            )
            raise AssertionError(f"evil host {evil!r} should be rejected")
        except ValueError as ve:
            assert "IMAP host" in str(ve)


def test_starttls_failure_does_not_fallback_to_plaintext():
    """STARTTLS failure must not fallback to plaintext - must raise."""
    from advisory_rss.cert_tr.imap import connect_imap

    # Mock IMAP4 to simulate STARTTLS failure, ensure no login is attempted
    with patch("advisory_rss.cert_tr.imap.imaplib.IMAP4") as mock_imap:
        mock_inst = MagicMock()
        mock_inst.starttls.side_effect = OSError("STARTTLS failed")
        # Ensure we can detect if plaintext login would have been attempted
        mock_inst.login = MagicMock()
        mock_inst.shutdown = MagicMock()
        mock_inst.close = MagicMock()
        mock_imap.return_value = mock_inst
        try:
            connect_imap(
                {
                    "host": "127.0.0.1",
                    "port": "1143",
                    "security": "STARTTLS",
                    "email": "test@proton.me",
                    "password": "bad",
                }
            )
            raise AssertionError("STARTTLS failure should raise, not fallback")
        except ValueError as ve:
            assert "STARTTLS failed" in str(ve)
            # Must not have tried plaintext login
            mock_inst.login.assert_not_called()
        except OSError:
            # Also acceptable if original OSError propagates, but we wrap to ValueError
            raise AssertionError("Should raise ValueError wrapping STARTTLS failure")


def test_plaintext_not_allowed_for_gmail():
    """Plaintext (NONE) must be rejected for Gmail hosts."""
    from advisory_rss.cert_tr.imap import connect_imap

    for host in ["imap.gmail.com", "imap.googlemail.com"]:
        try:
            connect_imap(
                {
                    "host": host,
                    "port": "143",
                    "security": "NONE",
                    "email": "test@gmail.com",
                    "password": "bad",
                }
            )
            raise AssertionError(f"NONE should be rejected for {host}")
        except ValueError as ve:
            assert "Plaintext" in str(ve) or "IMAP host" in str(ve)
