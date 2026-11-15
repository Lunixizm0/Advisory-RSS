"""CertTrSource: credential handling and CVE-based publication auto-confirm."""

from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

from advisory_rss.cache.store import CacheStore
from advisory_rss.cert_tr.source import CertTrSource
from advisory_rss.config.settings import Settings

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "cert_tr"
PUBLICATION_EMAIL = FIXTURES / "sample_publication.eml"
ALLOCATION_EMAIL = FIXTURES / "sample_cert_tr.eml"


def _settings(accounts: list[dict[str, Any]]) -> MagicMock:
    settings = MagicMock()
    settings.enable_cert_tr = True
    settings.get_cert_tr_accounts.return_value = accounts
    settings.cert_tr_sender_list.return_value = ["siberguvenlik.gov.tr"]
    settings.cert_tr_max_mails = 10
    settings.cert_tr_search_days = None
    settings.cert_tr_auto_confirm = True
    return settings


OAUTH_ACCOUNT = {
    "email": "a@gmail.com",
    "password": "",
    "folder": "INBOX",
    "provider": "gmail",
    "auth_method": "oauth",
    "oauth_refresh_token": "refresh-token",
    "oauth_client_id": "client-id",
    "oauth_client_secret": "client-secret",
}

PASSWORDLESS_ACCOUNT = {
    "email": "a@proton.me",
    "password": "",
    "folder": "INBOX",
    "provider": "proton",
    "auth_method": "password",
}


def _run(monkeypatch, raw_mails: list[bytes], *, auto_confirm: bool = True):
    settings = _settings([OAUTH_ACCOUNT])
    settings.cert_tr_auto_confirm = auto_confirm
    cache = MagicMock()
    cache.auto_confirm_publication.return_value = True

    def fake_fetch(account, allowlist, **kwargs):
        return raw_mails

    monkeypatch.setattr("advisory_rss.cert_tr.source.cert_imap.fetch_raw_emails", fake_fetch)
    advs, diag = CertTrSource(cast(Settings, settings), cache=cast(CacheStore, cache)).fetch_all()
    return advs, diag, cache


def test_oauth_only_account_is_not_skipped(monkeypatch):
    settings = _settings([OAUTH_ACCOUNT])
    fetched: list[dict[str, Any]] = []

    def fake_fetch(account, allowlist, **kwargs):
        fetched.append(account)
        return []

    monkeypatch.setattr("advisory_rss.cert_tr.source.cert_imap.fetch_raw_emails", fake_fetch)
    advs, diag = CertTrSource(cast(Settings, settings)).fetch_all()

    assert advs == []
    assert diag["accounts"] == 1
    assert diag["errors"] == []
    assert fetched and fetched[0]["auth_method"] == "oauth"


def test_account_without_any_secret_is_skipped(monkeypatch):
    settings = _settings([PASSWORDLESS_ACCOUNT])
    fetched: list[dict[str, Any]] = []

    def fake_fetch(account, allowlist, **kwargs):
        fetched.append(account)
        return []

    monkeypatch.setattr("advisory_rss.cert_tr.source.cert_imap.fetch_raw_emails", fake_fetch)
    advs, diag = CertTrSource(cast(Settings, settings)).fetch_all()

    assert advs == []
    assert diag["accounts"] == 0
    assert fetched == []
    assert any("missing credentials" in e for e in diag["errors"])


def test_publication_mail_auto_confirms_by_cve(monkeypatch):
    advs, diag, cache = _run(monkeypatch, [PUBLICATION_EMAIL.read_bytes()])

    # Match is by CVE even though CERT-TR changed the product name in this mail.
    cache.auto_confirm_publication.assert_called_once_with("CERT-TR-CVE-2026-92083")
    assert diag["auto_confirmed"] == ["CERT-TR-CVE-2026-92083"]
    assert advs[0].ghsa_id == "CERT-TR-CVE-2026-92083"
    assert advs[0].package_name == "pardus-image-writer"


def test_allocation_mail_does_not_auto_confirm(monkeypatch):
    advs, diag, cache = _run(monkeypatch, [ALLOCATION_EMAIL.read_bytes()])

    cache.auto_confirm_publication.assert_not_called()
    assert diag["auto_confirmed"] == []
    assert advs[0].ghsa_id == "CERT-TR-CVE-2026-92083"


def test_auto_confirm_can_be_disabled(monkeypatch):
    _, diag, cache = _run(monkeypatch, [PUBLICATION_EMAIL.read_bytes()], auto_confirm=False)

    cache.auto_confirm_publication.assert_not_called()
    assert diag["auto_confirmed"] == []
