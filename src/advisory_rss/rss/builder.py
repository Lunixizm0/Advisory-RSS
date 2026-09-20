#RSS 2.0 builder

from __future__ import annotations

import html
import logging
from datetime import UTC, datetime
from email.utils import format_datetime

from advisory_rss.cache.models import NormalizedAdvisory
from advisory_rss.config.constants import RSS_MAX_BYTES
from advisory_rss.rss.xml_util import cdata_wrap, escape_text

logger = logging.getLogger(__name__)


def _rfc822(dt: datetime | None) -> str:
    if dt is None:
        dt = datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    # Convert to UTC
    dt_utc = dt.astimezone(UTC)
    return format_datetime(dt_utc, usegmt=True)


def _iso_dc(dt: datetime | None) -> str:
    if dt is None:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _pub_date_for_adv(adv: NormalizedAdvisory) -> datetime:
    # Prefer published_at if published state, else updated_at, else created_at
    if adv.state in ("published", "closed") and adv.published_at:
        return adv.published_at
    if adv.updated_at:
        return adv.updated_at
    if adv.published_at:
        return adv.published_at
    if adv.created_at:
        return adv.created_at
    return datetime.now(UTC)


def _severity_label(sev: str | None) -> str:
    if not sev:
        return "unknown"
    return sev.lower()


def _is_safe_url(url: str) -> bool:
    if not url:
        return False
    u = url.strip().lower()
    # allow only http/https, reject javascript:, data:, vbscript:, file:, etc
    return u.startswith(("http://", "https://"))


def _build_item_xml(adv: NormalizedAdvisory) -> str:
    # Title logic
    severity = _severity_label(adv.severity)
    is_withdrawn = bool(adv.withdrawn_at) or adv.state.lower() == "withdrawn"
    prefix = ""
    if is_withdrawn:
        prefix = "[WITHDRAWN] "
    elif severity not in ("unknown", "n/a"):
        prefix = f"[{severity.upper()}] "
    base_title = adv.summary.strip() or adv.ghsa_id
    title = f"{prefix}{base_title} ({adv.ghsa_id})"
    title_esc = escape_text(title)

    link = adv.html_url.strip() or f"https://github.com/advisories/{adv.ghsa_id}"
    link_esc = escape_text(link)

    guid = escape_text(adv.ghsa_id)

    pub_dt = _pub_date_for_adv(adv)
    pub_str = escape_text(_rfc822(pub_dt))
    dc_date = escape_text(_iso_dc(adv.updated_at or adv.published_at or pub_dt))

    author = escape_text(adv.author_login or "unknown")
    # categories
    cats: list[str] = []
    cats.append(f"severity:{severity}")
    if adv.package_ecosystem:
        cats.append(f"ecosystem:{adv.package_ecosystem}")
    if adv.package_name:
        cats.append(f"package:{adv.package_name}")
    if is_withdrawn:
        cats.append("withdrawn")
    if adv.state:
        cats.append(f"state:{adv.state}")
    # also cve if present
    if adv.cve_id:
        cats.append(f"cve:{adv.cve_id}")

    cat_xml = "\n".join(f"      <category>{escape_text(c)}</category>" for c in cats)

    # Description: build HTML summary + metadata table
    # Keep bounded: truncate description if huge
    desc_html = _build_description_html(adv)
    content_html = _build_content_html(adv)

    # Use CDATA for description/content so HTML is preserved but safely escaped via cdata_wrap
    desc_cdata = cdata_wrap(desc_html)
    content_cdata = cdata_wrap(content_html)

    return f"""    <item>
      <guid isPermaLink="false">{guid}</guid>
      <title>{title_esc}</title>
      <link>{link_esc}</link>
      <description>{desc_cdata}</description>
      <pubDate>{pub_str}</pubDate>
      <author>{author}</author>
{cat_xml}
      <dc:date>{dc_date}</dc:date>
      <content:encoded>{content_cdata}</content:encoded>
    </item>"""


def _build_description_html(adv: NormalizedAdvisory) -> str:
    parts: list[str] = []
    # summary
    if adv.summary:
        parts.append(f"<p><strong>{html.escape(adv.summary)}</strong></p>")
    # severity
    sev = _severity_label(adv.severity)
    parts.append(
        f"<p><em>Severity:</em> {html.escape(sev)} &nbsp; <em>State:</em> {html.escape(adv.state)} &nbsp; <em>GHSA:</em> {html.escape(adv.ghsa_id)}"
    )
    if adv.cve_id:
        parts[-1] += f" &nbsp; <em>CVE:</em> {html.escape(adv.cve_id)}"
    parts[-1] += "</p>"

    if adv.package_name or adv.package_ecosystem:
        eco = html.escape(adv.package_ecosystem or "")
        name = html.escape(adv.package_name or "")
        pkg_line = f"<p><em>Package:</em> {eco + ('/' if eco and name else '') + name}</p>"
        parts.append(pkg_line)

    if adv.vulnerable_version_range:
        parts.append(
            f"<p><em>Vulnerable:</em> <code>{html.escape(adv.vulnerable_version_range)}</code></p>"
        )
    if adv.patched_versions:
        parts.append(f"<p><em>Patched:</em> <code>{html.escape(adv.patched_versions)}</code></p>")

    # truncated description (first 800 chars
    desc = adv.description or ""
    # escape but also keep line breaks as <br>
    if desc:
        # truncate for description (full stays in content:encoded)
        short = desc[:800]
        if len(desc) > 800:
            short += "…"
        # basic handling: escape then replace \n with <br>
        short_esc = html.escape(short).replace("\n", "<br/>")
        parts.append(f"<p>{short_esc}</p>")

    if adv.withdrawn_at:
        parts.append(f"<p><strong>Withdrawn:</strong> {html.escape(adv.withdrawn_at.isoformat())}</p>")

    if adv.repository_full_name or adv.repository_url:
        repo = html.escape(adv.repository_full_name or adv.repository_url or "")
        raw_link = adv.repository_url or adv.html_url
        link = html.escape(raw_link) if _is_safe_url(raw_link) else "#"
        parts.append(f'<p><em>Repository:</em> <a href="{link}">{repo}</a></p>')

    # references small - only http/https allowed
    if adv.references:
        safe_refs = [r for r in adv.references[:5] if _is_safe_url(r)]
        refs_html = "".join(
            f'<li><a href="{html.escape(r)}">{html.escape(r)}</a></li>' for r in safe_refs
        )
        parts.append(f"<ul>{refs_html}</ul>")

    combined = "\n".join(parts)
    # Bound description size
    if len(combined.encode("utf-8")) > 8000:
        # truncate more aggressively
        combined = combined[:6000] + "<p><em>… truncated</em></p>"
    return combined


def _build_content_html(adv: NormalizedAdvisory) -> str:
    parts: list[str] = []
    parts.append(f"<h2>{html.escape(adv.summary)}</h2>")
    parts.append("<table>")
    parts.append(f"<tr><th>GHSA</th><td>{html.escape(adv.ghsa_id)}</td></tr>")
    if adv.cve_id:
        parts.append(f"<tr><th>CVE</th><td>{html.escape(adv.cve_id)}</td></tr>")
    parts.append(f"<tr><th>Severity</th><td>{html.escape(_severity_label(adv.severity))}</td></tr>")
    parts.append(f"<tr><th>State</th><td>{html.escape(adv.state)}</td></tr>")
    if adv.package_ecosystem:
        parts.append(f"<tr><th>Ecosystem</th><td>{html.escape(adv.package_ecosystem)}</td></tr>")
    if adv.package_name:
        parts.append(f"<tr><th>Package</th><td>{html.escape(adv.package_name)}</td></tr>")
    if adv.vulnerable_version_range:
        parts.append(
            f"<tr><th>Vulnerable versions</th><td><code>{html.escape(adv.vulnerable_version_range)}</code></td></tr>"
        )
    if adv.patched_versions:
        parts.append(
            f"<tr><th>Patched versions</th><td><code>{html.escape(adv.patched_versions)}</code></td></tr>"
        )
    if adv.published_at:
        parts.append(
            f"<tr><th>Published</th><td>{html.escape(adv.published_at.isoformat())}</td></tr>"
        )
    if adv.updated_at:
        parts.append(f"<tr><th>Updated</th><td>{html.escape(adv.updated_at.isoformat())}</td></tr>")
    if adv.withdrawn_at:
        parts.append(
            f"<tr><th>Withdrawn</th><td>{html.escape(adv.withdrawn_at.isoformat())}</td></tr>"
        )
    if adv.repository_full_name:
        parts.append(
            f"<tr><th>Repository</th><td>{html.escape(adv.repository_full_name)}</td></tr>"
        )
    parts.append("</table>")

    if adv.description:
        desc_esc = html.escape(adv.description).replace("\n", "<br/>")
        parts.append(f"<div>{desc_esc}</div>")

    if adv.references:
        parts.append("<h3>References</h3><ul>")
        for r in adv.references:
            if not _is_safe_url(r):
                continue
            er = html.escape(r)
            parts.append(f'<li><a href="{er}">{er}</a></li>')
        parts.append("</ul>")

    view_link = adv.html_url if _is_safe_url(adv.html_url) else "#"
    parts.append(f'<p><a href="{html.escape(view_link)}">View on GitHub</a></p>')

    html_str = "\n".join(parts)
    # Bound content size per item
    if len(html_str.encode("utf-8")) > 30000:
        html_str = html_str[:25000] + "<p><em>… content truncated</em></p>"
    return html_str


def build_rss(
    advisories: list[NormalizedAdvisory],
    *,
    feed_title: str,
    feed_link: str,
    feed_description: str,
    max_items: int = 1000,
    ttl_minutes: int = 10,
    authenticated_user: str | None = None,
) -> str:
    # Sort ensured by caller but re-sort
    sorted_adv = sorted(advisories, key=lambda a: a.sort_key(), reverse=True)
    if max_items is not None:
        sorted_adv = sorted_adv[:max_items]

    # Channel dates
    now = datetime.now(UTC)
    last_build = _rfc822(now)
    if sorted_adv:
        # lastBuildDate could be latest updated_at
        latest = max((a.updated_at or a.published_at or now) for a in sorted_adv)
        last_build = _rfc822(latest if isinstance(latest, datetime) else now)

    title_esc = escape_text(
        feed_title or f"GitHub Security Advisories - @{authenticated_user or 'user'}"
    )
    link_esc = escape_text(
        feed_link or f"https://github.com/{authenticated_user}"
        if authenticated_user
        else "https://github.com/"
    )
    desc_esc = escape_text(
        feed_description
        or f"Security advisories created by {authenticated_user or 'authenticated user'}"
    )
    lang = "en-us"

    items_xml = "\n".join(_build_item_xml(a) for a in sorted_adv)

    # Namespaces for dc and content
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>{title_esc}</title>
    <link>{link_esc}</link>
    <description>{desc_esc}</description>
    <language>{lang}</language>
    <ttl>{ttl_minutes}</ttl>
    <lastBuildDate>{escape_text(last_build)}</lastBuildDate>
    <generator>advisory-rss 0.2.0 (localhost-only)</generator>
{items_xml}
  </channel>
</rss>"""

    # Bounded response size guard - binary search for max fitting items
    raw_bytes = xml.encode("utf-8")
    if len(raw_bytes) > RSS_MAX_BYTES:
        logger.warning(
            "RSS exceeds %d bytes (%d) - truncating items",
            RSS_MAX_BYTES,
            len(raw_bytes),
        )
        # binary search for largest prefix that fits
        lo, hi = 0, len(sorted_adv)
        best_xml = xml
        while lo <= hi:
            mid = (lo + hi) // 2
            cand = sorted_adv[:mid]
            cand_items = "\n".join(_build_item_xml(a) for a in cand)
            cand_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>{title_esc}</title>
    <link>{link_esc}</link>
    <description>{desc_esc}</description>
    <language>{lang}</language>
    <ttl>{ttl_minutes}</ttl>
    <lastBuildDate>{escape_text(last_build)}</lastBuildDate>
    <generator>advisory-rss 0.2.0 (localhost-only)</generator>
{cand_items}
  </channel>
</rss>"""
            if len(cand_xml.encode("utf-8")) <= RSS_MAX_BYTES:
                best_xml = cand_xml
                lo = mid + 1
            else:
                hi = mid - 1
        xml = best_xml
    return xml
