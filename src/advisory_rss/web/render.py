from __future__ import annotations

import hashlib
import html
from datetime import UTC, datetime
from urllib.parse import quote

from advisory_rss.cache.models import (
    CERT_TR_STATE_ASSIGNED,
    CERT_TR_STATE_PUBLISHED,
    NormalizedAdvisory,
    effective_state,
    is_cert_tr,
)
from advisory_rss.cert_tr.threading import conversation_label

STYLESHEET = """
:root {
  color-scheme: light dark;
  --bg: #f4f1e8;
  --bg-elevated: #ece8dc;
  --surface: #fffdf8;
  --ink: #1c1d19;
  --ink-soft: #50524a;
  --muted: #77786e;
  --line: #d9d4c6;
  --line-strong: #b5af9e;
  --accent: #a33a2b;
  --accent-soft: #f3e1dc;
  --github-bg: #24292f;
  --github-fg: #ffffff;
  --cert-bg: #f0e4ce;
  --cert-fg: #754611;
  --ok: #1c6b45;
  --ok-bg: #dfefe5;
  --warn: #87500b;
  --warn-bg: #f7e8d0;
  --crit: #a3261b;
  --high: #9a4f17;
  --med: #75600c;
  --low: #2e6a47;
  --radius: 3px;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --bg: #101210;
    --bg-elevated: #171a16;
    --surface: #1b1e19;
    --ink: #e9e6dc;
    --ink-soft: #b2ae9f;
    --muted: #918d7f;
    --line: #30342b;
    --line-strong: #4a4e42;
    --accent: #e07a5f;
    --accent-soft: #33201b;
    --github-bg: #e9e6dc;
    --github-fg: #171a16;
    --cert-bg: #2c2213;
    --cert-fg: #e7b979;
    --ok: #7fd39b;
    --ok-bg: #142b1e;
    --warn: #f0bd72;
    --warn-bg: #2e2313;
    --crit: #f18b7c;
    --high: #eab273;
    --med: #ded17a;
    --low: #8bd0a5;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.55 var(--sans);
}
::selection { background: var(--accent); color: #fff; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; text-underline-offset: .18em; }
a:focus-visible, button:focus-visible, summary:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}
code, .mono { font-family: var(--mono); font-size: .86em; }
h1, h2, h3, h4 { letter-spacing: -.02em; }
.shell { width: min(100% - 40px, 1220px); margin: 0 auto; padding: 26px 0 64px; }
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

/* Masthead */
.masthead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--line-strong);
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 11px;
  color: var(--ink);
  text-decoration: none;
}
.brand:hover { text-decoration: none; }
.brand-mark {
  display: grid;
  place-items: center;
  width: 34px;
  height: 34px;
  background: var(--ink);
  color: var(--surface);
  font: 700 11px/1 var(--mono);
  letter-spacing: -.04em;
  border-radius: var(--radius);
}
.brand-copy { display: grid; gap: 2px; }
.brand-name { font: 650 15px/1.1 var(--sans); letter-spacing: -.02em; }
.brand-sub {
  color: var(--muted);
  font: 10px/1.2 var(--mono);
  text-transform: uppercase;
  letter-spacing: .12em;
}
.utility {
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
  font: 11px/1 var(--mono);
  text-transform: uppercase;
  letter-spacing: .1em;
}
.utility a { color: var(--ink-soft); }
.utility a:hover { color: var(--accent); text-decoration: none; }

/* Index */
.page-head { margin: 32px 0 24px; }
.eyebrow {
  margin: 0 0 8px;
  color: var(--muted);
  font: 10px/1.2 var(--mono);
  text-transform: uppercase;
  letter-spacing: .16em;
}
.page-head h1 {
  margin: 0 0 10px;
  font-size: clamp(30px, 4.3vw, 48px);
  line-height: 1;
  font-weight: 650;
  letter-spacing: -.045em;
}
.lede {
  max-width: 58ch;
  margin: 0;
  color: var(--ink-soft);
  font-size: 14px;
}
.statline {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 1px 0 20px;
  border: 1px solid var(--line-strong);
  background: var(--surface);
  border-radius: var(--radius);
  overflow: hidden;
}
.stat {
  display: grid;
  gap: 5px;
  padding: 13px 16px;
  border-right: 1px solid var(--line);
}
.stat:last-child { border-right: 0; }
.stat-label {
  color: var(--muted);
  font: 10px/1.2 var(--mono);
  text-transform: uppercase;
  letter-spacing: .11em;
}
.stat-value {
  font: 650 24px/1 var(--sans);
  letter-spacing: -.04em;
  font-variant-numeric: tabular-nums;
}
.stat-value.warn { color: var(--warn); }
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 14px 28px;
  margin-bottom: 14px;
}
.filter-set { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; }
.filter-label {
  color: var(--muted);
  font: 10px/1 var(--mono);
  text-transform: uppercase;
  letter-spacing: .12em;
}
.segmented {
  display: inline-flex;
  overflow: hidden;
  border: 1px solid var(--line-strong);
  background: var(--surface);
  border-radius: var(--radius);
}
.segmented a {
  padding: 7px 11px;
  border-right: 1px solid var(--line);
  color: var(--ink-soft);
  font: 11px/1 var(--mono);
  letter-spacing: .03em;
}
.segmented a:last-child { border-right: 0; }
.segmented a:hover { background: var(--bg-elevated); color: var(--ink); text-decoration: none; }
.segmented a.active { background: var(--ink); color: var(--surface); }
.segmented .count { margin-left: 5px; color: inherit; opacity: .7; }

/* Ledger */
.ledger {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}
.ledger th {
  padding: 0 12px 9px;
  border-bottom: 1px solid var(--line-strong);
  color: var(--muted);
  font: 10px/1 var(--mono);
  text-align: left;
  text-transform: uppercase;
  letter-spacing: .12em;
  font-weight: 500;
}
.ledger td {
  padding: 14px 12px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
.ledger tbody tr { transition: background .12s ease; }
.ledger tbody tr:hover { background: var(--bg-elevated); }
.ledger .cell-title { width: 46%; }
.badge-stack { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 7px;
  border: 1px solid transparent;
  border-radius: var(--radius);
  font: 10px/1.15 var(--mono);
  text-transform: uppercase;
  letter-spacing: .07em;
  white-space: nowrap;
}
.badge::before {
  content: "";
  width: 5px;
  height: 5px;
  flex: none;
  border-radius: 50%;
  background: currentColor;
  opacity: .8;
}
.badge.src-github { background: var(--github-bg); color: var(--github-fg); }
.badge.src-cert-tr { background: var(--cert-bg); color: var(--cert-fg); }
.badge.ok { background: var(--ok-bg); color: var(--ok); }
.badge.pending { background: var(--warn-bg); color: var(--warn); }
.badge.neutral { background: var(--bg-elevated); color: var(--ink-soft); border-color: var(--line); }
.advisory-link {
  color: var(--ink);
  font-size: 15px;
  line-height: 1.4;
  font-weight: 600;
  text-decoration: none;
}
.advisory-link:hover { color: var(--accent); text-decoration: none; }
.idline {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 10px;
  margin-top: 5px;
  color: var(--muted);
  font: 11px/1.4 var(--mono);
}
.idline code { font-size: 11px; }
.conv {
  padding: 2px 6px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  color: var(--muted);
  font: 10px/1.2 var(--mono);
}
.product { color: var(--ink-soft); }
.sev {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--muted);
  font: 10px/1 var(--mono);
  text-transform: uppercase;
  letter-spacing: .08em;
  white-space: nowrap;
}
.sev::before {
  content: "";
  width: 6px;
  height: 6px;
  flex: none;
  background: currentColor;
  border-radius: 50%;
}
.sev.critical { color: var(--crit); }
.sev.high { color: var(--high); }
.sev.medium { color: var(--med); }
.sev.low { color: var(--low); }
td time { color: var(--ink-soft); font: 11px/1.3 var(--mono); white-space: nowrap; }
td time .time { color: var(--muted); }
.empty {
  padding: 48px 16px;
  border: 1px dashed var(--line-strong);
  border-radius: var(--radius);
  color: var(--muted);
  text-align: center;
}

/* Detail */
.crumb { margin: 26px 0 20px; font: 11px/1 var(--mono); text-transform: uppercase; letter-spacing: .08em; }
.crumb a { color: var(--muted); }
.crumb a:hover { color: var(--accent); }
.detail-head {
  padding-bottom: 22px;
  margin-bottom: 24px;
  border-bottom: 1px solid var(--line-strong);
}
.detail-head h1 {
  max-width: 30ch;
  margin: 0 0 14px;
  font-size: clamp(26px, 3.8vw, 43px);
  line-height: 1.06;
  font-weight: 640;
  letter-spacing: -.045em;
}
.badge-row { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 11px; }
.detail-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 24px;
  align-items: start;
}
.detail-side { position: sticky; top: 24px; }
.panel {
  margin-bottom: 24px;
  border: 1px solid var(--line-strong);
  border-radius: var(--radius);
  background: var(--surface);
}
.panel-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elevated);
}
.panel-head h2 {
  margin: 0;
  font: 500 10px/1.2 var(--mono);
  text-transform: uppercase;
  letter-spacing: .13em;
}
.panel-note { color: var(--muted); font: 10px/1.2 var(--mono); }
.panel-body { padding: 16px; }
.subhead {
  margin: 18px 0 8px;
  color: var(--muted);
  font: 10px/1.2 var(--mono);
  text-transform: uppercase;
  letter-spacing: .12em;
}
.notice {
  margin: 0 0 24px;
  padding: 15px 18px;
  border: 1px solid var(--line-strong);
  border-left-width: 4px;
  border-radius: var(--radius);
  background: var(--surface);
}
.notice.ok { border-left-color: var(--ok); background: var(--ok-bg); }
.notice.pending { border-left-color: var(--warn); background: var(--warn-bg); }
.notice.neutral { border-left-color: var(--muted); background: var(--bg-elevated); }
.notice-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 5px;
}
.notice-title { font-weight: 650; }
.notice p { margin: 0 0 12px; font-size: 13px; }
.notice p:last-child { margin-bottom: 0; }
.notice-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.button {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 8px 12px;
  border: 1px solid var(--ink);
  border-radius: var(--radius);
  background: var(--ink);
  color: var(--surface);
  font: 600 11px/1 var(--mono);
  text-transform: uppercase;
  letter-spacing: .06em;
  text-decoration: none;
  cursor: pointer;
}
.button:hover { background: var(--accent); border-color: var(--accent); color: #fff; text-decoration: none; }
.button.danger { background: transparent; color: var(--accent); border-color: var(--accent); }
.button.danger:hover { background: var(--accent); color: #fff; }
.inline-form { display: inline; margin: 0; }
.flash {
  margin: 0 0 20px;
  padding: 10px 14px;
  border: 1px solid var(--ok);
  border-left-width: 4px;
  border-radius: var(--radius);
  background: var(--ok-bg);
  color: var(--ok);
  font-size: 13px;
}
.flash.err { border-color: var(--warn); background: var(--warn-bg); color: var(--warn); }
dl.meta {
  display: grid;
  grid-template-columns: 118px minmax(0, 1fr);
  gap: 5px 14px;
  margin: 0;
}
dl.meta dt {
  color: var(--muted);
  font: 10px/1.5 var(--mono);
  text-transform: uppercase;
  letter-spacing: .07em;
}
dl.meta dd {
  min-width: 0;
  margin: 0;
  color: var(--ink-soft);
  font-size: 13px;
  overflow-wrap: anywhere;
}
.side-meta { grid-template-columns: 82px minmax(0, 1fr); }
pre.mail {
  max-height: 540px;
  overflow: auto;
  margin: 0;
  padding: 13px 14px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--bg);
  color: var(--ink-soft);
  font: 12px/1.55 var(--mono);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
details.raw { margin-top: 14px; }
details.raw summary {
  color: var(--muted);
  font: 11px/1.4 var(--mono);
  cursor: pointer;
}
details.raw summary:hover { color: var(--ink); }
details.raw pre.mail { margin-top: 9px; max-height: 320px; }
ul.refs { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
ul.refs li { min-width: 0; }
ul.refs a {
  display: block;
  overflow: hidden;
  color: var(--ink-soft);
  font: 11px/1.45 var(--mono);
  text-overflow: ellipsis;
  white-space: nowrap;
}
ul.refs a:hover { color: var(--accent); }

/* Footer */
.site-footer {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 10px 20px;
  margin-top: 56px;
  padding-top: 14px;
  border-top: 1px solid var(--line-strong);
  color: var(--muted);
  font: 10px/1.4 var(--mono);
  text-transform: uppercase;
  letter-spacing: .1em;
}
.site-footer nav { display: flex; gap: 16px; }
.site-footer a { color: var(--muted); }
.site-footer a:hover { color: var(--accent); text-decoration: none; }

@media (max-width: 900px) {
  .detail-grid { grid-template-columns: minmax(0, 1fr); }
  .detail-side { position: static; }
}
@media (max-width: 760px) {
  .shell { width: min(100% - 28px, 1220px); padding-top: 18px; }
  .masthead { align-items: flex-start; }
  .utility { gap: 12px; }
  .statline { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .stat:nth-child(2) { border-right: 0; }
  .stat:nth-child(-n + 2) { border-bottom: 1px solid var(--line); }
  .ledger thead { display: none; }
  .ledger, .ledger tbody, .ledger tr, .ledger td { display: block; width: 100%; }
  .ledger tr {
    margin-bottom: 10px;
    padding: 14px 15px;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: var(--surface);
  }
  .ledger td { padding: 5px 0; border: 0; }
  .ledger td::before {
    content: attr(data-label);
    display: block;
    margin-bottom: 2px;
    color: var(--muted);
    font: 9px/1.2 var(--mono);
    text-transform: uppercase;
    letter-spacing: .12em;
  }
  .ledger td.cell-title { padding-top: 0; }
  .ledger td.cell-title::before { display: none; }
  .badge-stack { flex-direction: row; flex-wrap: wrap; }
  .page-head h1 { font-size: 34px; }
  .detail-head h1 { font-size: 30px; }
}
@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; }
}
"""


def esc(value: object) -> str:
    """Escape any value for safe HTML output."""
    return html.escape("" if value is None else str(value), quote=True)


def _fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _fmt_day(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%d.%m.%Y")


def _fmt_time(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%H:%M UTC")


def _severity_class(severity: str | None) -> str:
    value = (severity or "").strip().lower()
    return value if value in {"critical", "high", "medium", "low"} else "unknown"


def _severity_text(severity: str | None) -> str:
    value = (severity or "").strip().upper()
    return esc(value) if value else "—"


def _clean_body(text: str) -> str:
    """Normalize mail display whitespace without touching the stored raw mail."""
    if not text:
        return ""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    out: list[str] = []
    blank = False
    for line in lines:
        if not line.strip():
            if blank:
                continue
            blank = True
            out.append("")
        else:
            blank = False
            out.append(line)
    return "\n".join(out).strip()


def detail_url(ghsa_id: str) -> str:
    """Canonical detail page URL for an advisory id (percent-encoded)."""
    return f"/ui/a/{quote(ghsa_id, safe='')}"


def _state_badge(adv: NormalizedAdvisory, confirmed_ids: set[str]) -> str:
    if is_cert_tr(adv):
        if adv.ghsa_id in confirmed_ids:
            return '<span class="badge ok">Published on NVD</span>'
        return '<span class="badge pending">CVE ID allocated</span>'
    state = effective_state(adv, confirmed_ids)
    return f'<span class="badge neutral">{esc(state)}</span>'


def _source_badge(adv: NormalizedAdvisory) -> str:
    src = getattr(adv, "source", "github") or "github"
    label = "CERT-TR" if src == "cert-tr" else "GitHub"
    return f'<span class="badge src-{esc(src)}">{esc(label)}</span>'


def _severity_badge(adv: NormalizedAdvisory) -> str:
    label = _severity_text(adv.severity)
    return f'<span class="sev {_severity_class(adv.severity)}">{label}</span>'


def _header() -> str:
    return """<header class="masthead">
<a class="brand" href="/">
<span class="brand-mark" aria-hidden="true">AR</span>
<span class="brand-copy">
<span class="brand-name">Advisory RSS</span>
<span class="brand-sub">localhost security feed</span>
</span>
</a>
<nav class="utility" aria-label="Site">
<a href="/">Advisories</a>
<a href="/rss.xml">RSS</a>
<a href="/health">Health</a>
</nav>
</header>"""


def _page(title: str, body: str) -> str:
    style_href = f"/ui/style.css?v={hashlib.sha256(STYLESHEET.encode()).hexdigest()[:10]}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{esc(title)}</title>
<link rel="stylesheet" href="{style_href}">
</head>
<body>
<div class="shell">
{_header()}
<main>
{body}
</main>
<footer class="site-footer">
<span>advisory-rss · localhost-only</span>
<nav aria-label="Secondary links">
<a href="/rss.xml">RSS</a>
<a href="/health">Health</a>
</nav>
</footer>
</div>
</body>
</html>
"""


def nvd_url(adv: NormalizedAdvisory) -> str:
    if adv.cve_id:
        return f"https://nvd.nist.gov/vuln/detail/{quote(adv.cve_id, safe='')}"
    return "https://siberguvenlik.gov.tr"


def _list_link(adv: NormalizedAdvisory, confirmed_ids: set[str]) -> tuple[str, str]:
    """Return (href, extra_attrs) for the advisory title in the list.

    A CERT-TR item confirmed as published on NVD opens the NVD record directly
    instead of the local mail page.
    """
    if is_cert_tr(adv) and adv.ghsa_id in confirmed_ids:
        return nvd_url(adv), ' target="_blank" rel="noopener noreferrer"'
    return detail_url(adv.ghsa_id), ""


def _updated_html(adv: NormalizedAdvisory) -> str:
    dt = adv.updated_at or adv.published_at
    if dt is None:
        return '<span class="muted">-</span>'
    return (
        f'<time datetime="{esc(dt.isoformat())}">{esc(_fmt_day(dt))} · '
        f'<span class="time">{esc(_fmt_time(dt))}</span></time>'
    )


def render_index(
    *,
    advisories: list[NormalizedAdvisory],
    confirmed_ids: set[str],
    source_filter: str,
    state_filter: str,
    counts: dict[str, int],
) -> str:
    """Render the advisory list page."""
    rows: list[str] = []
    for adv in advisories:
        cve = adv.cve_id or ""
        package = adv.package_name or ""
        conversation = conversation_label(adv)
        conv_html = f'<span class="conv">{esc(conversation)}</span>' if conversation else ""
        title_href, title_attrs = _list_link(adv, confirmed_ids)
        sev = _severity_class(adv.severity)
        sev_label = _severity_text(adv.severity)
        rows.append(
            "<tr>"
            f'<td data-label="Source"><div class="badge-stack">'
            f"{_source_badge(adv)}{_state_badge(adv, confirmed_ids)}</div></td>"
            f'<td class="cell-title" data-label="Record">'
            f'<a href="{esc(title_href)}"{title_attrs} class="advisory-link">'
            f"{esc(adv.summary or adv.ghsa_id)}</a>"
            f'<div class="idline"><code>{esc(adv.ghsa_id)}</code>{conv_html}</div></td>'
            f'<td data-label="CVE"><span class="mono">{esc(cve) if cve else "-"}</span></td>'
            f'<td data-label="Product"><span class="product">'
            f"{esc(package) if package else '-'}</span></td>"
            f'<td data-label="Severity"><span class="sev {sev}">{esc(sev_label)}</span></td>'
            f'<td data-label="Updated">{_updated_html(adv)}</td>'
            "</tr>"
        )

    if rows:
        table = (
            '<table class="ledger">'
            '<caption class="sr-only">Security advisory list</caption>'
            "<thead><tr>"
            "<th>Source</th><th>Record</th><th>CVE</th><th>Product</th>"
            "<th>Severity</th><th>Updated</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    else:
        table = (
            '<p class="empty">No records match this filter. '
            '<a href="/">Back to all records</a>.</p>'
        )

    def seg(source: str, state: str, label: str, active: bool, count: int | None = None) -> str:
        cls = ' class="active" aria-current="page"' if active else ""
        count_html = f' <span class="count">{count}</span>' if count is not None else ""
        return f'<a href="/?source={source}&state={state}"{cls}>{esc(label)}{count_html}</a>'

    filters = f"""<section class="toolbar" aria-label="Filters">
<div class="filter-set">
<span class="filter-label">Source</span>
<span class="segmented">
{seg("all", state_filter, "All", source_filter == "all")}
{seg("github", state_filter, "GitHub", source_filter == "github")}
{seg("cert-tr", state_filter, "CERT-TR", source_filter == "cert-tr")}
</span>
</div>
<div class="filter-set">
<span class="filter-label">Status</span>
<span class="segmented">
{seg(source_filter, "all", "All", state_filter == "all")}
{seg(source_filter, "pending", "Pending confirmation", state_filter == "pending", counts.get("pending", 0))}
</span>
</div>
</section>"""

    body = f"""<section class="page-head">
<p class="eyebrow">Local feed</p>
<h1>Security bulletin</h1>
<p class="lede">GitHub and CERT-TR records in a single list. For CERT-TR, CVE ID
allocation and NVD publication are kept separate; confirmed records open NVD directly.</p>
</section>
<section class="statline" aria-label="Summary">
<div class="stat"><span class="stat-label">Total</span>
<span class="stat-value">{counts.get("total", 0)}</span></div>
<div class="stat"><span class="stat-label">GitHub</span>
<span class="stat-value">{counts.get("github", 0)}</span></div>
<div class="stat"><span class="stat-label">CERT-TR</span>
<span class="stat-value">{counts.get("cert_tr", 0)}</span></div>
<div class="stat"><span class="stat-label">Pending confirmation</span>
<span class="stat-value warn">{counts.get("pending", 0)}</span></div>
</section>
{filters}
{table}"""
    return _page("Advisory RSS", body)


def render_detail(
    *,
    adv: NormalizedAdvisory,
    confirmed_ids: set[str],
    confirmations: dict[str, str],
    csrf_token: str,
    flash: str | None = None,
    flash_kind: str = "ok",
) -> str:
    """Render the detail page with the full mail and the publish confirmation."""
    raw = adv.raw or {}
    confirmed = adv.ghsa_id in confirmed_ids
    confirmed_at = confirmations.get(adv.ghsa_id, "")
    src = getattr(adv, "source", "github") or "github"
    conversation = conversation_label(adv)
    conv_html = f'<span class="conv">{esc(conversation)}</span>' if conversation else ""

    # --- publication state card ---
    if is_cert_tr(adv):
        if confirmed:
            state_card = f"""<div class="notice ok">
<div class="notice-head">
<span class="notice-title">Published on NVD</span>
<span class="badge ok">Confirmed</span>
</div>
<p class="muted">Confirmed at: {esc(_fmt_dt(_parse_iso(confirmed_at)))}</p>
<div class="notice-actions">
<a class="button" href="{esc(nvd_url(adv))}" target="_blank" rel="noopener noreferrer">NVD record</a>
<form class="inline-form" method="post" action="{esc(detail_url(adv.ghsa_id))}/confirm">
<input type="hidden" name="action" value="unconfirm">
<input type="hidden" name="token" value="{esc(csrf_token)}">
<button class="button danger" type="submit">Revoke confirmation</button>
</form>
</div>
</div>"""
        else:
            state_card = f"""<div class="notice pending">
<div class="notice-head">
<span class="notice-title">CVE ID allocated</span>
<span class="badge pending">Not published on NVD</span>
</div>
<p class="muted">A CERT-TR e-mail only allocates a CVE ID; it does not mean the
advisory is published. Once you confirm publication, the record links to NVD.</p>
<form class="inline-form" method="post" action="{esc(detail_url(adv.ghsa_id))}/confirm">
<input type="hidden" name="action" value="confirm">
<input type="hidden" name="token" value="{esc(csrf_token)}">
<button class="button" type="submit">Mark as published on NVD</button>
</form>
</div>"""
    else:
        state_card = f"""<div class="notice neutral">
<div class="notice-head">
<span class="notice-title">GitHub advisory</span>
<span class="badge neutral">{esc(effective_state(adv, confirmed_ids))}</span>
</div>
<p class="muted">This record comes from the GitHub Security Advisories feed.</p>
</div>"""

    # --- mail block ---
    headers = [
        ("Subject", raw.get("subject")),
        ("From", raw.get("from")),
        ("Reply-To", raw.get("reply_to")),
        ("Date", raw.get("date")),
        ("Message-Id", raw.get("message_id")),
        ("In-Reply-To", raw.get("in_reply_to")),
        ("References", " ".join(raw.get("references") or []) or None),
        ("Product", raw.get("product")),
        ("CWE", raw.get("cwe")),
    ]
    header_rows = "".join(
        f"<dt>{label}</dt><dd>{esc(value) if value else '-'}</dd>"
        for label, value in headers
        if value
    )

    body_text = _clean_body(adv.description or raw.get("plain_snippet") or "")
    html_body = raw.get("html_raw_snippet") or ""
    html_block = ""
    if html_body:
        html_block = f"""<details class="raw">
<summary>Original HTML body · {len(html_body)} characters</summary>
<pre class="mail">{esc(html_body)}</pre>
</details>"""

    meta_rows = "".join(
        f"<dt>{label}</dt><dd>{esc(value) if value else '-'}</dd>"
        for label, value in [
            ("ID", adv.ghsa_id),
            ("CVE", adv.cve_id),
            ("Source", src),
            ("Status", effective_state(adv, confirmed_ids)),
            ("Severity", adv.severity),
            ("Product", adv.package_name),
            ("Updated", _fmt_dt(adv.updated_at)),
            ("Created", _fmt_dt(adv.published_at or adv.created_at)),
            ("Author", adv.author_login),
            ("Conversation", conversation),
        ]
    )

    refs = [r for r in (adv.references or []) if str(r).startswith(("http://", "https://"))]
    if is_cert_tr(adv) and not confirmed:
        refs = [r for r in refs if "nvd.nist.gov" not in r]
    refs_panel = ""
    if refs:
        refs_panel = f"""<section class="panel">
<div class="panel-head"><h2>References</h2><span class="panel-note">{len(refs)}</span></div>
<div class="panel-body"><ul class="refs">"""
        refs_panel += "".join(
            f'<li><a href="{esc(r)}" target="_blank" rel="noopener noreferrer">{esc(r)}</a></li>'
            for r in refs
        )
        refs_panel += "</ul></div></section>"

    flash_html = ""
    if flash:
        kind = "flash err" if flash_kind == "err" else "flash"
        flash_html = f'<div class="{kind}">{esc(flash)}</div>'

    body = f"""<p class="crumb"><a href="/">← All advisories</a></p>
<header class="detail-head">
<p class="eyebrow">{_source_badge(adv)}{" · " + esc(adv.cve_id) if adv.cve_id else ""}</p>
<h1>{esc(adv.summary or adv.ghsa_id)}</h1>
<div class="badge-row">
{_state_badge(adv, confirmed_ids)}
{_severity_badge(adv)}
</div>
<p class="idline"><code>{esc(adv.ghsa_id)}</code>{conv_html}</p>
</header>
<div class="detail-grid">
<div class="detail-main">
{flash_html}
{state_card}
<section class="panel">
<div class="panel-head"><h2>Mail</h2><span class="panel-note">{len(body_text)} characters</span></div>
<div class="panel-body">
<dl class="meta">{header_rows}</dl>
<h3 class="subhead">Body</h3>
<pre class="mail">{esc(body_text)}</pre>
{html_block}
</div>
</section>
</div>
<aside class="detail-side">
<section class="panel">
<div class="panel-head"><h2>Record</h2></div>
<div class="panel-body"><dl class="meta side-meta">{meta_rows}</dl></div>
</section>
{refs_panel}
</aside>
</div>"""
    return _page(adv.summary or adv.ghsa_id, body)


def _parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


__all__ = [
    "CERT_TR_STATE_ASSIGNED",
    "CERT_TR_STATE_PUBLISHED",
    "STYLESHEET",
    "esc",
    "nvd_url",
    "render_detail",
    "render_index",
]
