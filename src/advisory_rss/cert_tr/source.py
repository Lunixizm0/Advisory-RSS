"""CERT-TR source orchestrator: IMAP fetch -> parser -> NormalizedAdvisory list."""

from __future__ import annotations

import imaplib
import logging
from typing import Any

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.cert_tr import imap as cert_imap
from advisory_rss.cert_tr.parser import is_cert_tr_sender, parse_cert_tr_email
from advisory_rss.config.settings import Settings

logger = logging.getLogger(__name__)


class CertTrSource:
    def __init__(self, settings: Settings):
        self.settings = settings

    def fetch_all(self) -> tuple[list[NormalizedAdvisory], dict[str, Any]]:
        """Fetch from all configured Proton accounts.

        Returns (advisories, diag). Never raises (errors go to diag).
        Dedup by ghsa_id (CERT-TR-CVE-...) keep newest (by updated_at).
        """
        diag: dict[str, Any] = {
            "accounts": 0,
            "raw_fetched": 0,
            "parsed": 0,
            "filtered_sender": 0,
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
            if not acc.get("password"):
                msg = f"{provider} account {email}/{folder}: missing password/app-password - skipping"
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
