# CERT-TR source orchestrator: IMAP fetch -> parser -> NormalizedAdvisory list.

from __future__ import annotations

import imaplib
import logging
import sqlite3
from typing import Any

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cache.store import CacheStore
from advisory_rss.cert_tr import imap as cert_imap
from advisory_rss.cert_tr.parser import is_cert_tr_sender, parse_cert_tr_email
from advisory_rss.config.settings import Settings

logger = logging.getLogger(__name__)


class CertTrSource:
    def __init__(self, settings: Settings, cache: CacheStore | None = None):
        self.settings = settings
        self.cache = cache

    def _auto_confirm(self, adv: NormalizedAdvisory, diag: dict[str, Any]) -> None:
        """Record NVD publication when the official mail is matched by CVE.

        The publication mail may change the product name and wording, so only
        the CVE identifiers from the subject are used; an item the user
        manually unconfirmed is left alone.
        """
        if self.cache is None or not self.settings.cert_tr_auto_confirm:
            return
        raw = adv.raw or {}
        publication_cves = list(raw.get("subject_cves") or [])
        if not publication_cves and adv.cve_id:
            publication_cves = [adv.cve_id]
        for cve in publication_cves:
            ghsa_id = f"CERT-TR-{str(cve).upper()}"
            try:
                inserted = self.cache.auto_confirm_publication(ghsa_id)
            except sqlite3.Error as e:
                msg = f"auto-confirm {ghsa_id} failed: {e}"
                logger.warning(msg)
                diag["errors"].append(msg)
                continue
            if inserted:
                diag["auto_confirmed"].append(ghsa_id)
                logger.info("CERT-TR auto-confirmed from publication mail ghsa_id=%s", ghsa_id)

    def fetch_all(self) -> tuple[list[NormalizedAdvisory], dict[str, Any]]:
        # Fetch from all configured Proton accounts.
        diag: dict[str, Any] = {
            "accounts": 0,
            "raw_fetched": 0,
            "parsed": 0,
            "filtered_sender": 0,
            "auto_confirmed": [],
            "errors": [],
        }
        if not self.settings.enable_cert_tr:
            logger.debug("CERT-TR disabled (ENABLE_CERT_TR=false)")
            return [], diag

        accounts = self.settings.get_cert_tr_accounts()
        if not accounts:
            msg = "ENABLE_CERT_TR=true but no PROTON_BRIDGE_EMAIL/EMAILS or GMAIL_EMAIL/EMAILS configured"
            logger.warning(msg)
            diag["errors"].append(msg)
            return [], diag

        allowlist = self.settings.cert_tr_sender_list()
        max_mails = self.settings.cert_tr_max_mails
        search_days = self.settings.cert_tr_search_days

        all_advs: list[NormalizedAdvisory] = []
        per_account_max = max_mails
        if len(accounts) > 1:
            per_account_max = max(20, max_mails // len(accounts))

        for acc in accounts:
            email = acc.get("email", "unknown")
            folder = acc.get("folder", "INBOX")
            provider = acc.get("provider", "unknown")
            auth_method = (acc.get("auth_method") or "password").lower()
            has_secret = bool(acc.get("password")) or (
                auth_method == "oauth" and bool(acc.get("oauth_refresh_token"))
            )
            if not has_secret:
                msg = (
                    f"{provider} account {email}/{folder}: missing credentials "
                    "(password/app-password or OAuth refresh token) - skipping"
                )
                logger.warning(msg)
                diag["errors"].append(msg)
                continue
            diag["accounts"] += 1
            try:
                raw_list = cert_imap.fetch_raw_emails(
                    acc, allowlist, max_mails=per_account_max, search_days=search_days
                )
            except (OSError, ValueError, RuntimeError, imaplib.IMAP4.error) as e:
                msg = f"IMAP error {email}/{folder} ({provider}): {e}"
                logger.warning(msg)
                diag["errors"].append(msg)
                continue
            diag["raw_fetched"] += len(raw_list)

            for raw in raw_list:
                try:
                    adv = parse_cert_tr_email(raw)
                    if not adv:
                        continue
                    from_hdr = adv.raw.get("from") or adv.author_login or ""
                    if allowlist and not is_cert_tr_sender(from_hdr, allowlist):
                        diag["filtered_sender"] += 1
                        continue
                    all_advs.append(adv)
                    diag["parsed"] += 1
                    if (adv.raw or {}).get("publication"):
                        self._auto_confirm(adv, diag)
                except (ValueError, TypeError, AttributeError) as e:
                    logger.debug("parse_cert_tr_email failed: %s", e, exc_info=True)
                    continue

        # Dedup by ghsa_id keep newest updated_at
        seen: dict[str, NormalizedAdvisory] = {}
        for adv in all_advs:
            prev = seen.get(adv.ghsa_id)
            if prev is None or adv.sort_key() > prev.sort_key():
                seen[adv.ghsa_id] = adv

        deduped = list(seen.values())
        deduped.sort(key=lambda a: a.sort_key(), reverse=True)

        logger.info(
            "CERT-TR fetch done accounts=%d raw=%d parsed=%d deduped=%d filtered_sender=%d errors=%d",
            diag["accounts"],
            diag["raw_fetched"],
            diag["parsed"],
            len(deduped),
            diag["filtered_sender"],
            len(diag["errors"]),
        )
        return deduped, diag
