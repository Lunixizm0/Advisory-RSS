#IMAP fetcher for CERT-TR mails via Proton Bridge and Gmail

from __future__ import annotations

import imaplib
import logging
import ssl
import time
from datetime import UTC, datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

# Allowed IMAP hosts: Proton Bridge loopback + Gmail
ALLOWED_HOSTS = {
    "127.0.0.1",
    "::1",
    "localhost",
    "imap.gmail.com",
    "imap.googlemail.com",
}

def _ssl_context_for_host(host: str) -> ssl.SSLContext:
    # Proton Bridge uses self-signed cert -> no verification
    if host in {"127.0.0.1", "::1", "localhost"}:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    # Gmail and others -> verify
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def connect_imap(account: dict[str, str]) -> imaplib.IMAP4:
    host = account.get("host", "127.0.0.1")
    port = int(account.get("port", 1143))
    security = (account.get("security") or "STARTTLS").upper()
    email = account.get("email", "")
    password = account.get("password", "")
    auth_method = account.get("auth_method", "password")
    oauth_refresh_token = account.get("oauth_refresh_token", "")
    oauth_client_id = account.get("oauth_client_id", "")
    oauth_client_secret = account.get("oauth_client_secret", "")

    if host not in ALLOWED_HOSTS:
        raise ValueError(f"IMAP host must be one of {sorted(ALLOWED_HOSTS)}, got {host!r}")

    ctx = _ssl_context_for_host(host)
    if security == "SSL":
        mail = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    elif security == "STARTTLS":
        mail = imaplib.IMAP4(host, port)
        try:
            mail.starttls(ssl_context=ctx)
        except (OSError, imaplib.IMAP4.error, ssl.SSLError) as e:
            logger.warning("STARTTLS failed for %s:%s - trying without TLS: %s", host, port, e)
    else:  # NONE
        mail = imaplib.IMAP4(host, port)

    # Gmail OAuth if configured
    if auth_method == "oauth" and oauth_refresh_token:
        # Need client_id/secret
        if not oauth_client_id or not oauth_client_secret:
            raise ValueError(f"Gmail OAuth for {email} missing client_id/secret")
        try:
            from advisory_rss.auth.gmail import build_xoauth2_string, fetch_access_token

            access_token, _ = fetch_access_token(
                oauth_refresh_token, oauth_client_id, oauth_client_secret
            )
            xoauth2 = build_xoauth2_string(email, access_token)

            def _auth_cb(_: bytes) -> str:
                return xoauth2

            mail.authenticate("XOAUTH2", _auth_cb)  # type: ignore[arg-type]
        except (
            OSError,
            ValueError,
            RuntimeError,
            imaplib.IMAP4.error,
            httpx.HTTPError,
            ImportError,
        ) as e:
            logger.error("IMAP XOAUTH2 failed for %s: %s", email, e)
            raise
    else:
        # Regular password login (Proton Bridge or Gmail App Password)
        try:
            mail.login(email, password)
        except imaplib.IMAP4.error as e:
            logger.error("IMAP login failed for %s: %s", email, e)
            raise
    logger.debug("IMAP connected %s folder will be selected later", email)
    return mail


def _encode_modified_utf7(s: str) -> str:
    import base64

    res: list[str] = []
    in_non_ascii = False
    buf: list[str] = []

    def _b64(buf_chars: list[str]) -> str:
        b = "".join(buf_chars).encode("utf-16be")
        b64 = base64.b64encode(b).decode("ascii")
        b64 = b64.replace("/", ",").rstrip("=")
        return "&" + b64 + "-"

    for ch in s:
        o = ord(ch)
        if 0x20 <= o <= 0x7E and ch != "&":
            if in_non_ascii:
                res.append(_b64(buf))
                buf = []
                in_non_ascii = False
            res.append(ch)
        elif ch == "&":
            if in_non_ascii:
                res.append(_b64(buf))
                buf = []
                in_non_ascii = False
            res.append("&-")
        else:
            if not in_non_ascii:
                in_non_ascii = True
            buf.append(ch)
    if in_non_ascii:
        res.append(_b64(buf))
    return "".join(res)


def _select_folder_imap(
    mail: imaplib.IMAP4, folder: str, readonly: bool = True
) -> tuple[str, list[bytes]]:
    orig_enc = getattr(mail, "_encoding", "ascii")
    # First try: enable UTF8 if possible
    try:
        try:
            mail.enable("UTF8=ACCEPT")
        except (imaplib.IMAP4.error, OSError, ValueError):
            pass
    except (AttributeError, OSError):
        pass
    # Try UTF-8
    try:
        mail._encoding = "utf-8"  # type: ignore[attr-defined]
        return mail.select(folder, readonly=readonly)  # type: ignore[arg-type]
    except UnicodeEncodeError:
        pass
    except imaplib.IMAP4.error:
        # Pass to fallback
        pass
    # Fallback: modified UTF-7 (ASCII)
    try:
        encoded = _encode_modified_utf7(folder)
        mail._encoding = "ascii"  # type: ignore[attr-defined]
        return mail.select(encoded, readonly=readonly)  # type: ignore[arg-type]
    except (UnicodeEncodeError, imaplib.IMAP4.error):
        # Restore original encoding and re-raise
        try:
            mail._encoding = orig_enc  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
        raise
    finally:
        # Restore encoding to utf-8 for subsequent commands (search/fetch use ascii criteria)
        try:
            mail._encoding = "utf-8"  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass


def _build_search_criteria(allowlist: list[str], search_days: int | None) -> list[str]:
    parts: list[str] = []
    if allowlist:
        domain = allowlist[0]
        parts.append(f'FROM "{domain}"')
    if search_days is not None and search_days >= 0:
        since_date = (datetime.now(UTC) - timedelta(days=search_days)).strftime("%d-%b-%Y")
        parts.append(f'SINCE "{since_date}"')
    if not parts:
        parts.append("ALL")
    return parts


def fetch_raw_emails(
    account: dict[str, str],
    allowlist: list[str],
    max_mails: int = 200,
    search_days: int | None = None,
) -> list[bytes]:
    folder = account.get("folder", "INBOX") or "INBOX"
    email = account.get("email", "unknown")
    raw_list: list[bytes] = []

    mail = None
    try:
        mail = connect_imap(account)
        typ: str = ""
        data: list[bytes] = []
        try:
            typ, data = _select_folder_imap(mail, folder, readonly=True)
        except (imaplib.IMAP4.error, UnicodeEncodeError, ValueError) as e:
            logger.warning("IMAP select folder %r failed for %s: %s", folder, email, e)
            if folder.upper() != "INBOX":
                try:
                    typ2, _data2 = _select_folder_imap(mail, "INBOX", readonly=True)
                    if typ2 == "OK":
                        logger.info("Fallback to INBOX for %s", email)
                        folder = "INBOX"
                        typ, data = typ2, _data2  # type: ignore[assignment]
                    else:
                        return []
                except (OSError, imaplib.IMAP4.error, UnicodeEncodeError, ValueError) as fallback_e:
                    logger.debug("Fallback select failed for %s: %s", email, fallback_e)
                    return []
            else:
                return []
        if typ != "OK":
            logger.warning("IMAP select %r returned %s for %s: %s", folder, typ, email, data)
            return []

        criteria = _build_search_criteria(allowlist, search_days)
        search_query = " ".join(criteria) if len(criteria) == 1 else "(" + " ".join(criteria) + ")"
        if len(allowlist) > 1:
            if search_days is not None:
                search_query = f'SINCE "{(datetime.now(UTC) - timedelta(days=search_days)).strftime("%d-%b-%Y")}"'
            else:
                search_query = "ALL"

        logger.debug("IMAP search %s folder=%r criteria=%r", email, folder, search_query)
        try:
            typ, data = mail.search(None, search_query)
        except imaplib.IMAP4.error as e:
            logger.warning("IMAP search failed %s/%r: %s - trying ALL", email, folder, e)
            typ, data = mail.search(None, "ALL")
        if typ != "OK" or not data or not data[0]:
            logger.info("IMAP search empty %s/%r", email, folder)
            return []
        uids = data[0].split()
        if not uids:
            return []
        uids = list(reversed(uids))
        if len(uids) > max_mails:
            uids = uids[:max_mails]

        batch_size = 25
        fetched = 0
        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            if i > 0:
                try:
                    mail.logout()
                except (OSError, imaplib.IMAP4.error) as e:
                    logger.debug("Logout during reconnect failed for %s: %s", email, e)
                time.sleep(0.3)
                try:
                    mail = connect_imap(account)
                    _select_folder_imap(mail, folder, readonly=True)
                except (
                    OSError,
                    imaplib.IMAP4.error,
                    ssl.SSLError,
                    ValueError,
                    UnicodeEncodeError,
                ) as e:
                    logger.warning("IMAP reconnect failed %s batch %d: %s", email, i, e)
                    break

            for uid in batch:
                try:
                    uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                    typ, fdata = mail.fetch(uid_str, "(BODY.PEEK[])")
                    if typ != "OK" or not fdata:
                        continue
                    for item in fdata:
                        if (
                            isinstance(item, tuple)
                            and len(item) == 2
                            and isinstance(item[1], bytes)
                        ):
                            raw_list.append(item[1])
                            fetched += 1
                        elif isinstance(item, bytes) and len(item) > 100:
                            raw_list.append(item)
                            fetched += 1
                except imaplib.IMAP4.error as e:
                    try:
                        uid_s = uid.decode(errors="ignore") if isinstance(uid, bytes) else str(uid)
                    except (ValueError, UnicodeDecodeError) as de:
                        uid_s = str(uid)
                        logger.debug("UID decode failed: %s", de)
                    logger.debug("IMAP fetch uid %s failed %s: %s", uid_s, email, e)
                    continue
                except (OSError, ValueError, RuntimeError) as e:
                    logger.warning("IMAP fetch unexpected %s: %s", email, e)
                    continue

        logger.info(
            "IMAP fetch done %s/%r: requested %d, fetched %d raw",
            email,
            folder,
            len(uids),
            len(raw_list),
        )
        return raw_list

    except (OSError, imaplib.IMAP4.error, ssl.SSLError, ValueError, RuntimeError) as e:
        logger.warning("IMAP fetch_raw_emails failed %s/%r: %s", email, folder, e, exc_info=True)
        return []
    finally:
        if mail is not None:
            try:
                mail.logout()
            except (OSError, imaplib.IMAP4.error) as e:
                logger.debug("Final logout failed for %s: %s", email, e)
                try:
                    mail.close()
                except (OSError, imaplib.IMAP4.error) as close_e:
                    logger.debug("Final close failed for %s: %s", email, close_e)
