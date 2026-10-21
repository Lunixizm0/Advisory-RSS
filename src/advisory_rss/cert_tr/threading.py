"""Conversation grouping for CERT-TR mails.

A CERT-TR case produces several mails over time (CVE allocation, record filled,
published, fixed...).  They are grouped with the signals we can extract today:

  1. mail thread headers - ``References`` / ``In-Reply-To`` (root message id)
  2. the set of CVE IDs mentioned in the mail

The grouping key is ``<thread-root>|<cve-set>`` so two mails belong to the same
conversation when they belong to the same thread *and* talk about the same CVEs.

The CERT-TR "başvuru id" (case reference number) is **not** used: the mails do not
carry it in a form we can parse reliably, so there is nothing to anchor on yet.
"""

from __future__ import annotations

import re

from advisory_rss.cache.models import NormalizedAdvisory


def is_internal_msg_id(value: str) -> bool:
    """True for Proton's internal ids - they are not real message ids.

    Proton puts ``<…@protonmail.internalid>`` in the ``References`` header of every
    mail; using it as a thread reference would be wrong.
    """
    v = value.strip().strip("<>")
    if "@" not in v:
        return True
    domain = v.rsplit("@", 1)[1].lower()
    return domain.endswith((".internalid", ".internal"))


def extract_message_ids(value: str | None) -> list[str]:
    """Split a References/In-Reply-To header into real message ids."""
    if not value:
        return []
    out: list[str] = []
    for part in re.split(r"[\s,]+", value.strip()):
        part = part.strip("<>")
        if not part:
            continue
        if "@" not in part or "." not in part:
            continue
        if is_internal_msg_id(part):
            continue
        out.append(f"<{part}>")
    return out


def thread_root_id(raw: dict[str, object] | None) -> str | None:
    """Root message id of the mail thread, if the headers carry one."""
    if not raw:
        return None
    refs = raw.get("references")
    if isinstance(refs, list) and refs:
        first = str(refs[0]).strip()
        if first:
            return first
    in_reply_to = raw.get("in_reply_to")
    if isinstance(in_reply_to, str) and in_reply_to.strip():
        # strip angle brackets / trailing ids -> keep the first id
        first = in_reply_to.strip().split()[0].strip("<>")
        if first:
            return f"<{first}>"
    return None


def case_reference_id(raw: dict[str, object] | None) -> str | None:
    """CERT-TR "başvuru id" - not extractable from the mails today, always None.

    Kept as an explicit placeholder so the conversation key has a stable place
    to anchor on once the case reference becomes parsable.
    """
    return None


def cve_set(adv: NormalizedAdvisory) -> tuple[str, ...]:
    """Sorted tuple of all CVE ids mentioned by the advisory."""
    cves: set[str] = set()
    if adv.cve_id:
        cves.add(adv.cve_id.upper())
    for extra in adv.extra_cves or []:
        if extra:
            cves.add(str(extra).upper())
    raw_cves = (adv.raw or {}).get("cves")
    if isinstance(raw_cves, list):
        for c in raw_cves:
            if c:
                cves.add(str(c).upper())
    return tuple(sorted(cves))


def conversation_key(adv: NormalizedAdvisory) -> str:
    """Stable conversation key for a CERT-TR advisory ('' when nothing is known)."""
    raw = adv.raw or {}
    anchor = thread_root_id(raw) or case_reference_id(raw)
    cves = ",".join(cve_set(adv))
    if not anchor and not cves:
        return ""
    if not anchor:
        return f"cve:{cves}"
    return f"{anchor}|{cves}"


def conversation_label(adv: NormalizedAdvisory) -> str:
    """Short human readable conversation label (thread root id)."""
    root = thread_root_id(adv.raw or {})
    if root:
        return root.strip("<>")
    return ""


def group_by_conversation(
    advisories: list[NormalizedAdvisory],
) -> dict[str, list[NormalizedAdvisory]]:
    """Group advisories by conversation key (advisories without a key keep their own group)."""
    groups: dict[str, list[NormalizedAdvisory]] = {}
    for adv in advisories:
        key = conversation_key(adv) or f"id:{adv.ghsa_id}"
        groups.setdefault(key, []).append(adv)
    return groups
