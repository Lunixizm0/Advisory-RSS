from advisory_rss.config.settings import Settings


def test_single_account():
    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        PROTON_BRIDGE_EMAIL="a@proton.me",
        PROTON_BRIDGE_PASSWORD="p1",
        PROTON_IMAP_FOLDER="INBOX",
        _env_file_encoding="utf-8",
    )
    accs = s.get_proton_accounts()
    assert len(accs) == 1
    assert accs[0]["email"] == "a@proton.me"
    assert accs[0]["folder"] == "INBOX"
    assert accs[0]["password"] == "p1"


def test_multi_account_emails_folders():
    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        PROTON_BRIDGE_EMAILS="a@proton.me, b@proton.me",
        PROTON_BRIDGE_PASSWORDS="p1,p2",
        PROTON_IMAP_FOLDERS="INBOX,INBOX.CERT-TR",
        _env_file_encoding="utf-8",
    )
    accs = s.get_proton_accounts()
    assert len(accs) == 2
    assert accs[0]["folder"] == "INBOX"
    assert accs[1]["folder"] == "INBOX.CERT-TR"
    assert accs[1]["password"] == "p2"


def test_multi_account_fallback_single_password():
    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        PROTON_BRIDGE_EMAILS="a@proton.me, b@proton.me",
        PROTON_BRIDGE_PASSWORD="single",
        PROTON_IMAP_FOLDER="INBOX",
        _env_file_encoding="utf-8",
    )
    accs = s.get_proton_accounts()
    assert len(accs) == 2
    assert accs[0]["password"] == "single"
    assert accs[1]["password"] == "single"


def test_folder_validation():
    s = Settings(
        _env_file="/dev/null", PROTON_IMAP_FOLDER="INBOX.CERT-TR", _env_file_encoding="utf-8"
    )
    assert s.proton_imap_folder == "INBOX.CERT-TR"


def test_sender_allowlist():
    s = Settings(
        _env_file="/dev/null",
        CERT_TR_SENDER_ALLOWLIST="siberguvenlik.gov.tr, usom.gov.tr",
        _env_file_encoding="utf-8",
    )
    assert "siberguvenlik.gov.tr" in s.cert_tr_sender_list()
    assert "usom.gov.tr" in s.cert_tr_sender_list()


def test_gmail_single():
    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        GMAIL_EMAIL="a@gmail.com",
        GMAIL_APP_PASSWORD="abcd efgh ijkl mnop",
        GMAIL_IMAP_FOLDER="INBOX",
        _env_file_encoding="utf-8",
    )
    accs = s.get_gmail_accounts()
    assert len(accs) == 1
    assert accs[0]["email"] == "a@gmail.com"
    assert accs[0]["password"] == "abcd efgh ijkl mnop"
    assert accs[0]["host"] == "imap.gmail.com"
    assert accs[0]["security"] == "SSL"


def test_gmail_multi_with_spaces():
    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        GMAIL_EMAILS="a@gmail.com,b@gmail.com",
        GMAIL_APP_PASSWORDS="pass1,pass2 with spaces",
        GMAIL_IMAP_FOLDERS="INBOX,INBOX.CERT",
        _env_file_encoding="utf-8",
    )
    accs = s.get_gmail_accounts()
    assert len(accs) == 2
    assert accs[0]["password"] == "pass1"
    assert accs[1]["password"] == "pass2 with spaces"
    assert accs[1]["folder"] == "INBOX.CERT"


def test_mixed_proton_gmail_unified():
    s = Settings(
        _env_file="/dev/null",
        ENABLE_CERT_TR="true",
        PROTON_BRIDGE_EMAIL="p@proton.me",
        PROTON_BRIDGE_PASSWORD="pp",
        GMAIL_EMAIL="g@gmail.com",
        GMAIL_APP_PASSWORD="gp",
        _env_file_encoding="utf-8",
    )
    accs = s.get_cert_tr_accounts()
    assert len(accs) == 2
    providers = {a["provider"] for a in accs}
    assert providers == {"proton", "gmail"}
    # proton should be loopback, gmail imap.gmail.com
    proton = next(a for a in accs if a["provider"] == "proton")
    gmail = next(a for a in accs if a["provider"] == "gmail")
    assert proton["host"] == "127.0.0.1"
    assert gmail["host"] == "imap.gmail.com"
