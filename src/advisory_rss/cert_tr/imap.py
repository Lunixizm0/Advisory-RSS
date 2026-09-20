"""Proton Bridge IMAP fetcher - localhost only, never marks read."""
# ruff: noqa: BLE001, DTZ003, S110, RUF059

from __future__ import annotations

import imaplib
import logging
import ssl
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Never mark read: we always use BODY.PEEK and SELECT readonly=True


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def connect_imap(account: dict[str, str]) -> imaplib.IMAP4:
    host = account.get("host", "127.0.0.1")
    port = int(account.get("port", 1143))
    security = (account.get("security") or "STARTTLS").upper()
    email = account.get("email", "")
    password = account.get("password", "")

    # Loopback guard - only allow loopback
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError(f"Proton IMAP host must be loopback, got {host!r}")

    ctx = _ssl_context()
    if security == "SSL":
        mail = imaplib.IMAP4_SSL(host, port, ssl_context=ctx)
    elif security == "STARTTLS":
        mail = imaplib.IMAP4(host, port)
        try:
            mail.starttls(ssl_context=ctx)
        except Exception as e:
            logger.warning("STARTTLS failed for %s:%s - trying without TLS: %s", host, port, e)
            # already connected without TLS; still try login
    else:  # NONE
        mail = imaplib.IMAP4(host, port)

    # Login - Bridge password is not Proton account password
    try:
        mail.login(email, password)
    except imaplib.IMAP4.error as e:
        logger.error("IMAP login failed for %s: %s", email, e)
        raise
    logger.debug("IMAP connected %s folder will be selected later", email)
    return mail


def _build_search_criteria(allowlist: list[str], search_days: int | None) -> list[str]:
    parts: list[str] = []
    # FROM filter - build OR chain if multiple
    if allowlist:
        # Use first allowlist entry for server-side filter; rest filtered client-side to keep simple
        # Or build OR for 2 entries max? We'll use first dominant domain
        domain = allowlist[0]
        # IMAP FROM search is substring match; domain is enough
        parts.append(f'FROM "{domain}"')
    if search_days is not None and search_days >= 0:
        # SINCE date is inclusive
        since_date = (datetime.utcnow() - timedelta(days=search_days)).strftime("%d-%b-%Y")
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
    """Fetch raw RFC822 bytes for one Proton account, never marking as read.

    Returns list of raw bytes, newest first (reverse UID).
    Handles reconnect every 25 to avoid Bridge drops.
    """
    folder = account.get("folder", "INBOX") or "INBOX"
    email = account.get("email", "unknown")
    raw_list: list[bytes] = []

    mail = None
    try:
        mail = connect_imap(account)
        # Select readonly to guarantee no \Seen flag can be set even on bug
        typ: str = ""
        data: list[bytes] = []
        try:
            typ, data = mail.select(folder, readonly=True)  # type: ignore[assignment]
        except imaplib.IMAP4.error as e:  # noqa: BLE001
            logger.warning("IMAP select folder %r failed for %s: %s", folder, email, e)
            # try INBOX fallback
            if folder.upper() != "INBOX":
                try:
                    typ2, _data2 = mail.select("INBOX", readonly=True)  # type: ignore[assignment]
                    if typ2 == "OK":
                        logger.info("Fallback to INBOX for %s", email)
                        folder = "INBOX"
                        typ, data = typ2, _data2  # type: ignore[assignment]
                    else:
                        return []
                except Exception:  # noqa: BLE001
                    return []
            else:
                return []
        if typ != "OK":
            logger.warning("IMAP select %r returned %s for %s: %s", folder, typ, email, data)
            return []

        # Build search
        criteria = _build_search_criteria(allowlist, search_days)
        # IMAP search: join with space (AND)
        search_query = " ".join(criteria) if len(criteria) == 1 else "(" + " ".join(criteria) + ")"
        # Actually need to handle OR case; simplified to single FROM
        if len(allowlist) > 1:
            # Client-side filter fallback: search with SINCE only or ALL, then filter
            if search_days is not None:
                search_query = f'SINCE "{(datetime.utcnow() - timedelta(days=search_days)).strftime("%d-%b-%Y")}"'
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
        # Newest first: reverse UID list (UIDs increase)
        uids = list(reversed(uids))
        # Respect max_mails (per account)
        if len(uids) > max_mails:
            uids = uids[:max_mails]

        # Client-side allowlist filtering if we used ALL fallback
        # We'll still fetch and filter by From header later in parser, but to avoid fetching too many,
        # we can peek headers first for From? Simpler: fetch all and let parser filter.
        # For >1 allowlist and fallback ALL, we will filter after fetch via From header check.

        # Batch fetch with reconnect every 25
        batch_size = 25
        fetched = 0
        for i in range(0, len(uids), batch_size):
            batch = uids[i : i + batch_size]
            # reconnect every batch after first to avoid Bridge drops
            if i > 0:
                try:
                    mail.logout()
                except Exception:
                    pass
                time.sleep(0.3)
                try:
                    mail = connect_imap(account)
                    mail.select(folder, readonly=True)
                except Exception as e:
                    logger.warning("IMAP reconnect failed %s batch %d: %s", email, i, e)
                    break

            for uid in batch:
                try:
                    uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                    typ, fdata = mail.fetch(uid_str, "(BODY.PEEK[])")
                    if typ != "OK" or not fdata:
                        continue
                    # fdata is list of tuples; extract raw bytes
                    for item in fdata:
                        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
                            raw_list.append(item[1])
                            fetched += 1
                        elif isinstance(item, bytes) and len(item) > 100:
                            raw_list.append(item)
                            fetched += 1
                except imaplib.IMAP4.error as e:
                    logger.debug("IMAP fetch uid %s failed %s: %s", uid.decode(errors="ignore"), email, e)
                    continue
                except Exception as e:
                    logger.warning("IMAP fetch unexpected %s: %s", email, e)
                    continue

        logger.info("IMAP fetch done %s/%r: requested %d, fetched %d raw", email, folder, len(uids), len(raw_list))
        return raw_list

    except Exception as e:
        logger.warning("IMAP fetch_raw_emails failed %s/%r: %s", email, folder, e, exc_info=True)
        return []
    finally:
        if mail is not None:
            try:
                mail.logout()
            except Exception:
                try:
                    mail.close()
                except Exception:
                    pass
