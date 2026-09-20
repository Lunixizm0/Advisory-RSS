"""Parse SGB/CERT-TR Proton Mail messages into NormalizedAdvisory.

Handles:
  - RFC2047 encoded headers (Subject, From)
  - quoted-printable / base64 + charset windows-1254 fallback
  - CVE/CWE/product extraction from HTML or plain body
  - CVE-dedup ID: CERT-TR-CVE-YYYY-NNNNN or fallback to Message-Id hash
  - Never marks as read (parser only)
"""

from __future__ import annotations

import html
import logging
import re
from datetime import UTC, datetime
from email import policy
from email.header import decode_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from typing import Any

from advisory_rss.cache.models import NormalizedAdvisory

logger = logging.getLogger(__name__)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
# product heuristic: “pardus-etap-settings” ürünü -> group 1
PRODUCT_RE = re.compile(r"[“\"']([^”\"']{2,80})[”\"']\s*ürün", re.IGNORECASE)
# fallback: quoted strings list
QUOTED_RE = re.compile(r"[“\"]([^”\"]{2,80})[”\"]")

# Sender allowlist check is done outside but parser also extracts domain

def decode_rfc2047(s: str | None) -> str:
    if not s:
        return ""
    try:
        parts = decode_header(s)
        out = ""
        for raw, enc in parts:
            if isinstance(raw, bytes):
                try:
                    out += raw.decode(enc or "utf-8", errors="replace")
                except LookupError:
                    out += raw.decode("utf-8", errors="replace")
            else:
                out += raw
        return out
    except (LookupError, ValueError, UnicodeDecodeError, AttributeError) as e:
        logger.debug("decode_rfc2047 failed %r: %s", s[:80], e)
        return str(s)

def _extract_domain(from_header: str) -> str:
    # from_header already decoded may contain <addr>
    m = re.search(r"<([^>]+)>", from_header or "")
    addr = m.group(1) if m else (from_header or "")
    addr = addr.strip().lower()
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return addr

def _parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        if dt and dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError, AttributeError) as e:
        logger.debug("date parse failed %r: %s", date_str, e)
        return None

def _html_to_text(html_body: str) -> str:
    # Lightweight html -> text: strip tags, decode entities, keep line breaks
    # Replace <br>, <p>, <div> with newlines before stripping
    if not html_body:
        return ""
    # normalize quoted-printable already decoded to string
    s = html_body
    # Replace block tags with newline
    s = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", s)
    s = re.sub(r"(?i)</\s*p\s*>", "\n\n", s)
    s = re.sub(r"(?i)</\s*div\s*>", "\n", s)
    # Remove all tags
    s = re.sub(r"<[^>]+>", " ", s)
    # Decode html entities
    s = html.unescape(s)
    # Collapse whitespace but keep single newlines
    s = s.replace("\r", "")
    # Collapse multiple spaces
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = re.sub(r" *\n *", "\n", s)
    return s.strip()

def _extract_body(msg: EmailMessage) -> tuple[str, str | None]:
    # Walk parts; prefer html then plain; handle multipart
    plain: str | None = None
    html_raw: str | None = None

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            # skip containers
            if ctype in ("multipart/alternative", "multipart/mixed", "multipart/related"):
                continue
            disp = (part.get_content_disposition() or "").lower()
            if disp == "attachment":
                continue
            payload = part.get_payload(decode=True)  # type: ignore[assignment]
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            # try charset fallback chain
            text = None
            assert isinstance(payload, (bytes, bytearray))
            for enc in (charset, "utf-8", "windows-1254", "iso-8859-9", "iso-8859-1"):
                try:
                    text = payload.decode(enc, errors="replace")  # type: ignore[union-attr]
                    break
                except LookupError:
                    continue
                except (ValueError, UnicodeDecodeError):
                    continue
            if text is None:
                text = payload.decode("utf-8", errors="replace")  # type: ignore[union-attr]
            if ctype == "text/html" and html_raw is None:
                html_raw = text
            elif ctype == "text/plain" and plain is None:
                plain = text
        # fallback: if html but no plain, convert html to plain
        if html_raw and not plain:
            plain = _html_to_text(html_raw)
        if plain and not html_raw:
            # keep html_raw None
            pass
        return plain or "", html_raw
    else:
        ctype = msg.get_content_type()
        payload = msg.get_payload(decode=True)  # type: ignore[assignment]
        if payload is None:
            # get_payload may return str
            payload_str = msg.get_payload()
            if isinstance(payload_str, str):
                # quoted-printable already?
                return payload_str, None
            return "", None
        charset = msg.get_content_charset() or "utf-8"
        text = None
        assert isinstance(payload, (bytes, bytearray))
        for enc in (charset, "utf-8", "windows-1254", "iso-8859-9"):
            try:
                text = payload.decode(enc, errors="replace")  # type: ignore[union-attr]
                break
            except LookupError:
                continue
        if text is None:
            text = payload.decode("utf-8", errors="replace")  # type: ignore[union-attr]
        if ctype == "text/html":
            return _html_to_text(text), text
        return text, None

def _extract_cves(text: str) -> list[str]:
    found = CVE_RE.findall(text or "")
    # normalize upper
    norm = [c.upper() for c in found]
    # dedup preserve order
    seen = set()
    out = []
    for c in norm:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out

def _extract_cwe(text: str) -> str | None:
    m = CWE_RE.search(text or "")
    return m.group(0).upper() if m else None

def _extract_product(text: str) -> str | None:
    if not text:
        return None
    m = PRODUCT_RE.search(text)
    if m:
        prod = m.group(1).strip()
        # cleanup quotes artifacts
        prod = prod.strip("“”\"' ")
        if prod and len(prod) > 1:
            return prod
    # fallback: find quoted strings containing dash or lowercase + not CWE/CVE
    quoted = QUOTED_RE.findall(text)
    candidates = []
    for q in quoted:
        q = q.strip()
        if not q or q.upper().startswith("CWE") or q.upper().startswith("CVE"):
            continue
        if "TÜBİTAK" in q or "Siber" in q or len(q) > 40:
            continue
        # product usually contains - or _
        if "-" in q or "_" in q or q.islower() or "/" in q:
            candidates.append(q)
    if candidates:
        # shortest that looks like package name
        candidates.sort(key=len)
        return candidates[0].strip()
    return None

def _build_summary(
    subject_decoded: str, product: str | None, cve: str | None, cwe: str | None
) -> str:
    # If product + CVE, build canonical summary, else decoded subject
    if product and cve:
        base = f"{product}: {cve}"
        if cwe:
            base += f" ({cwe})"
        return base
    if cve and cwe:
        return f"{cve} - {cwe}"
    if cve:
        return f"Zafiyet Bildirimi {cve}"
    # fallback to subject trimmed
    s = (subject_decoded or "").strip()
    if s:
        # Remove excessive prefix "Zafiyet Bildiriminiz Hakkında"
        s = re.sub(r"^\s*Zafiyet Bildiriminiz Hakkında\s*[:\-]?\s*", "", s, flags=re.IGNORECASE)
        s = s.strip(" ()")
        if s:
            return s
    return subject_decoded.strip() or "CERT-TR Zafiyet Bildirimi"

def parse_cert_tr_email(raw_bytes: bytes) -> NormalizedAdvisory | None:
    """Parse raw RFC822 bytes from Proton/Bridge or Gmail into NormalizedAdvisory.

    Returns None if no CVE is assigned (strict filter to avoid false positives).
    Uses CVE-based id for dedup (CERT-TR-CVE-...).
    Never marks mail read.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except (ValueError, TypeError, AttributeError) as e:
        logger.warning("Failed to parse email bytes: %s", e)
        return None

    # Headers
    subject_raw = msg.get("Subject") or ""
    subject = decode_rfc2047(str(subject_raw))
    from_raw = msg.get("From") or ""
    from_decoded = decode_rfc2047(str(from_raw))
    reply_to = decode_rfc2047(str(msg.get("Reply-To") or ""))
    message_id = (msg.get("Message-Id") or msg.get("Message-ID") or "").strip()
    # also X-Pm-External-Id fallback
    if not message_id:
        message_id = (msg.get("X-Pm-External-Id") or "").strip()
    date_hdr = msg.get("Date") or msg.get("X-Pm-Date") or ""
    date_dt = _parse_date(str(date_hdr))

    # Body
    plain_text, html_raw = _extract_body(msg)
    # Combine subject + plain for CVE search (subject often contains CVE)
    combined_text = f"{subject}\n{plain_text}"
    if html_raw:
        combined_text += f"\n{html_raw}"

    cves = _extract_cves(combined_text)
    cve_primary = cves[0] if cves else None
    cwe = _extract_cwe(combined_text)
    product = _extract_product(combined_text)

    if not cve_primary and message_id:
        m = CVE_RE.search(message_id)
        if m:
            cve_primary = m.group(0).upper()
            if cve_primary not in cves:
                cves.append(cve_primary)

    if not cve_primary:
        logger.debug(
            "Skipping CERT-TR mail without CVE subject=%r from=%r",
            subject[:60],
            from_decoded[:60],
        )
        return None

    ghsa_id = f"CERT-TR-{cve_primary.upper()}"

    # Extra CVEs beyond primary
    extra_cves = [c for c in cves if c != cve_primary]

    # Summary & description
    summary = _build_summary(subject, product, cve_primary, cwe)
    # Description: plain_text truncated 8000 chars for RSS, keep full
    description = plain_text.strip()
    if not description and html_raw:
        description = _html_to_text(html_raw)
    if not description:
        description = combined_text[:2000]

    # References
    refs: list[str] = []
    if cve_primary:
        refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_primary}")
        refs.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_primary}")
    # also include siberguvenlik portal (generic)
    refs.append("https://siberguvenlik.gov.tr")

    # Links: CVE-based NVD link
    html_url = f"https://nvd.nist.gov/vuln/detail/{cve_primary}"

    # Severity: try to infer from text (kritik/yüksek/orta/düşük)
    severity = None
    low_text = (plain_text or "").lower()
    if "kritik" in low_text or "critical" in low_text:
        severity = "critical"
    elif "yüksek" in low_text or "high" in low_text:
        severity = "high"
    elif "orta" in low_text or "medium" in low_text or "moderate" in low_text:
        severity = "medium"
    elif "düşük" in low_text or "low" in low_text:
        severity = "low"

    # Package extraction: ecosystem maybe?
    # infer ecosystem from product name: pardus => deb? keep None
    package_ecosystem = None
    package_name = product

    # State: CERT-TR mails are allocations; consider "published" but note awaiting patch
    state = "published"

    # Updated/published = date
    published_at = date_dt
    updated_at = date_dt
    created_at = date_dt

    # Author/publisher
    author_login = from_decoded or "cve@siberguvenlik.gov.tr"
    # Try to extract email addr only
    m = re.search(r"<([^>]+@[^>]+)>", author_login)
    if m:
        author_login = m.group(1).strip()
    publisher_login = "siberguvenlik.gov.tr"

    # identifiers list
    identifiers = []
    for c in cves:
        identifiers.append({"type": "CVE", "value": c})
    if cwe:
        identifiers.append({"type": "CWE", "value": cwe})

    # raw preservation (redacted password not in raw)
    raw: dict[str, Any] = {
        "message_id": message_id,
        "subject": subject,
        "from": from_decoded,
        "reply_to": reply_to,
        "date": str(date_hdr),
        "cves": cves,
        "cwe": cwe,
        "product": product,
        "html_raw_snippet": (html_raw[:2000] if html_raw else "")[:2000],
        "plain_snippet": plain_text[:2000],
        "x_pm_external_id": str(msg.get("X-Pm-External-Id") or ""),
        "x_pm_internal_id": str(msg.get("X-Pm-Internal-Id") or ""),
    }

    adv = NormalizedAdvisory(
        ghsa_id=ghsa_id,
        cve_id=cve_primary,
        summary=summary,
        description=description,
        severity=severity,
        package_ecosystem=package_ecosystem,
        package_name=package_name,
        vulnerable_version_range=None,
        patched_versions=None,
        affected_versions=None,
        published_at=published_at,
        updated_at=updated_at,
        withdrawn_at=None,
        created_at=created_at,
        state=state,
        html_url=html_url,
        repository_url=None,
        repository_full_name=f"cert-tr/{product}" if product else "cert-tr/siberguvenlik",
        references=refs,
        author_login=author_login,
        publisher_login=publisher_login,
        identifiers=identifiers,
        raw=raw,
        source="cert-tr",
        extra_cves=extra_cves,
    )
    logger.debug("Parsed CERT-TR mail ghsa_id=%s cve=%s product=%r", ghsa_id, cve_primary, product)
    return adv


def is_cert_tr_sender(from_header: str, allowlist: list[str]) -> bool:
    if not from_header:
        return False
    decoded = decode_rfc2047(from_header)
    domain = _extract_domain(decoded)
    if not domain:
        # fallback raw lower
        domain = from_header.lower()
    for allowed in allowlist:
        allowed = allowed.lower().strip()
        if not allowed:
            continue
        if domain == allowed or domain.endswith("." + allowed) or allowed in domain:
            return True
        # also substring check for safety
        if allowed in from_header.lower():
            return True
    return False
