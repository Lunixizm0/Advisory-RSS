"""HTML rendering for the minimal web UI.

Everything is escaped - mail bodies are attacker controlled (HTML mail from an
external sender), so nothing from a mail is ever injected as markup.
"""

from __future__ import annotations

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
  --fg: #16181d;
  --bg: #ffffff;
  --muted: #5b6472;
  --line: #d8dee9;
  --card: #f6f8fa;
  --accent: #0b5fff;
  --warn-bg: #fff4e5;
  --warn-fg: #8a4b00;
  --ok-bg: #e7f6ec;
  --ok-fg: #14682f;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e6e9ef;
    --bg: #14171c;
    --muted: #9aa4b2;
    --line: #2b313a;
    --card: #1b1f26;
    --accent: #7aa2ff;
    --warn-bg: #3a2c14;
    --warn-fg: #f2c078;
    --ok-bg: #16301f;
    --ok-fg: #7fd39b;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 24px 16px 64px; }
header.top { border-bottom: 1px solid var(--line); margin-bottom: 20px; padding-bottom: 12px; }
header.top h1 { margin: 0 0 8px; font-size: 20px; }
nav a { margin-right: 14px; font-size: 14px; }
nav a.active { font-weight: 600; text-decoration: underline; }
.counts { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
table.list { width: 100%; border-collapse: collapse; font-size: 14px; }
table.list th, table.list td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
table.list th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; border: 1px solid var(--line); background: var(--card); white-space: nowrap; }
.badge.src-github { background: #24292f; color: #fff; border-color: #24292f; }
.badge.src-cert-tr { background: #6d28d9; color: #fff; border-color: #6d28d9; }
.badge.pending { background: var(--warn-bg); color: var(--warn-fg); border-color: var(--warn-fg); }
.badge.ok { background: var(--ok-bg); color: var(--ok-fg); border-color: var(--ok-fg); }
.muted { color: var(--muted); }
.card { border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; background: var(--card); margin: 16px 0; }
.card.pending { background: var(--warn-bg); border-color: var(--warn-fg); }
.card.ok { background: var(--ok-bg); border-color: var(--ok-fg); }
dl.meta { display: grid; grid-template-columns: 200px 1fr; gap: 4px 14px; margin: 0; }
dl.meta dt { color: var(--muted); font-size: 13px; }
dl.meta dd { margin: 0; font-size: 14px; word-break: break-word; }
pre.mail { white-space: pre-wrap; word-wrap: break-word; background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 12px; font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
button { font: inherit; padding: 6px 14px; border-radius: 6px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); cursor: pointer; }
button:hover { border-color: var(--accent); color: var(--accent); }
.flash { border: 1px solid var(--ok-fg); background: var(--ok-bg); color: var(--ok-fg); border-radius: 6px; padding: 8px 12px; margin: 12px 0; font-size: 14px; }
.flash.err { border-color: var(--warn-fg); background: var(--warn-bg); color: var(--warn-fg); }
details { margin-top: 10px; }
summary { cursor: pointer; font-size: 14px; color: var(--muted); }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 12px; }
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


def _detail_url(ghsa_id: str) -> str:
    return f"/ui/a/{quote(ghsa_id, safe='')}"


def _state_badge(adv: NormalizedAdvisory, confirmed_ids: set[str]) -> str:
    if is_cert_tr(adv):
        if adv.ghsa_id in confirmed_ids:
            return '<span class="badge ok">NVD&#39;de yay&#305;nland&#305;</span>'
        return '<span class="badge pending">CVE ID tahsis - yay&#305;nlanmad&#305;</span>'
    state = effective_state(adv, confirmed_ids)
    return f'<span class="badge">{esc(state)}</span>'


def _source_badge(adv: NormalizedAdvisory) -> str:
    src = getattr(adv, "source", "github") or "github"
    label = "CERT-TR" if src == "cert-tr" else "GitHub"
    return f'<span class="badge src-{esc(src)}">{esc(label)}</span>'


def _page(title: str, body: str, nav: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<link rel="stylesheet" href="/ui/style.css">
</head>
<body>
<div class="wrap">
{nav}
{body}
<footer>advisory-rss &middot; localhost-only &middot; <a href="/rss.xml">RSS</a> &middot; <a href="/health">health</a></footer>
</div>
</body>
</html>
"""


def _nav(source_filter: str, state_filter: str) -> str:
    def active(current: str, wanted: str) -> str:
        return ' class="active"' if current == wanted else ""

    src = esc(source_filter)
    st = esc(state_filter)
    return f"""<header class="top">
<h1>Advisory RSS</h1>
<nav>
<a href="/?source=all&amp;state={st}"{active(src, "all")}>T&uuml;m&uuml;</a>
<a href="/?source=github&amp;state={st}"{active(src, "github")}>GitHub</a>
<a href="/?source=cert-tr&amp;state={st}"{active(src, "cert-tr")}>CERT-TR</a>
<a href="/?source={src}&amp;state=pending"{active(st, "pending")}>Onay bekleyen</a>
<a href="/rss.xml">RSS feed</a>
<a href="/health">health</a>
</nav>
</header>"""


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
        cve = adv.cve_id or "-"
        package = adv.package_name or "-"
        severity = adv.severity or "-"
        conversation = conversation_label(adv)
        conv_cell = f'<span class="badge">{esc(conversation)}</span>' if conversation else "-"
        rows.append(
            "<tr>"
            f"<td>{_source_badge(adv)}<br>{_state_badge(adv, confirmed_ids)}</td>"
            f'<td><a href="{esc(_detail_url(adv.ghsa_id))}">{esc(adv.summary or adv.ghsa_id)}</a>'
            f'<div class="muted">{esc(adv.ghsa_id)}</div></td>'
            f"<td>{esc(cve)}</td>"
            f"<td>{esc(package)}</td>"
            f"<td>{esc(severity)}</td>"
            f"<td>{conv_cell}</td>"
            f"<td>{esc(_fmt_dt(adv.updated_at or adv.published_at))}</td>"
            "</tr>"
        )

    if rows:
        table = (
            '<table class="list"><thead><tr>'
            "<th>Kaynak / Durum</th><th>Ba&#351;l&#305;k</th><th>CVE</th><th>&#220;r&#252;n</th>"
            "<th>Seviye</th><th>Konu&#351;ma</th><th>Tarih</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    else:
        table = '<p class="muted">Bu filtreyle e&#351;le&#351;en kay&#305;t yok.</p>'

    counts_line = (
        f"Toplam {counts.get('total', 0)} &middot; "
        f"GitHub {counts.get('github', 0)} &middot; "
        f"CERT-TR {counts.get('cert_tr', 0)} &middot; "
        f"Onay bekleyen {counts.get('pending', 0)}"
    )

    body = f"""<p class="counts">{counts_line}</p>
{table}"""
    return _page("Advisory RSS", body, _nav(source_filter, state_filter))


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

    # --- publication state card ---
    if is_cert_tr(adv):
        if confirmed:
            state_card = f"""<div class="card ok">
<strong>NVD&#39;de yay&#305;nland&#305; olarak i&#351;aretlendi</strong>
<div class="muted">Onay zaman&#305;: {esc(_fmt_dt(_parse_iso(confirmed_at)))}</div>
<p>
<a href="https://nvd.nist.gov/vuln/detail/{esc(adv.cve_id or "")}">NVD kayd&#305;n&#305; a&#351;</a>
&nbsp;&middot;&nbsp;
<form method="post" action="{esc(_detail_url(adv.ghsa_id))}/confirm" style="display:inline">
<input type="hidden" name="action" value="unconfirm">
<input type="hidden" name="token" value="{esc(csrf_token)}">
<button type="submit">Onay&#305; geri al</button>
</form>
</p>
</div>"""
        else:
            state_card = f"""<div class="card pending">
<strong>CVE ID tahsis edildi - NVD&#39;de yay&#305;nlanmad&#305;</strong>
<div class="muted">CERT-TR e-postas&#305; yaln&#305;zca CVE ID tahsisi yapar; yay&#305;n anlam&#305;na gelmez.
Yay&#305;nland&#305;&#287;&#305;n&#305; do&#287;rulad&#305;&#287;&#305;n&#305;zda kay&#305;t NVD&#39;ye y&#246;nlendirilir.</div>
<p>
<form method="post" action="{esc(_detail_url(adv.ghsa_id))}/confirm">
<input type="hidden" name="action" value="confirm">
<input type="hidden" name="token" value="{esc(csrf_token)}">
<button type="submit">NVD&#39;de yay&#305;nland&#305; olarak i&#351;aretle</button>
</form>
</p>
</div>"""
    else:
        state_card = (
            '<div class="card"><strong>GitHub kayd&#305;</strong>'
            f'<div class="muted">Durum: {esc(effective_state(adv, confirmed_ids))}</div></div>'
        )

    # --- mail block ---
    headers = [
        ("Konu", raw.get("subject")),
        ("G&ouml;nderen", raw.get("from")),
        ("Yan&#305;t", raw.get("reply_to")),
        ("Tarih", raw.get("date")),
        ("Message-Id", raw.get("message_id")),
        ("In-Reply-To", raw.get("in_reply_to")),
        ("References", " ".join(raw.get("references") or []) or None),
        ("&#220;r&#252;n", raw.get("product")),
        ("CWE", raw.get("cwe")),
    ]
    header_rows = "".join(
        f"<dt>{label}</dt><dd>{esc(value) if value else '-'}</dd>"
        for label, value in headers
        if value
    )

    body_text = adv.description or raw.get("plain_snippet") or ""
    html_body = raw.get("html_raw_snippet") or ""
    html_block = ""
    if html_body:
        html_block = f"""<details>
<summary>Orijinal HTML g&#246;vde ({len(html_body)} karakter)</summary>
<pre class="mail">{esc(html_body)}</pre>
</details>"""

    conversation = conversation_label(adv)

    meta_rows = "".join(
        f"<dt>{label}</dt><dd>{esc(value) if value else '-'}</dd>"
        for label, value in [
            ("GHSA / kimlik", adv.ghsa_id),
            ("CVE", adv.cve_id),
            ("Kaynak", src),
            ("Durum", effective_state(adv, confirmed_ids)),
            ("Seviye", adv.severity),
            ("&#220;r&#252;n", adv.package_name),
            ("G&#252;ncellenme", _fmt_dt(adv.updated_at)),
            ("Olu&#351;turma", _fmt_dt(adv.published_at or adv.created_at)),
            ("Yazar", adv.author_login),
            ("Konu&#351;ma", conversation),
        ]
    )

    refs = [r for r in (adv.references or []) if str(r).startswith(("http://", "https://"))]
    if is_cert_tr(adv) and not confirmed:
        refs = [r for r in refs if "nvd.nist.gov" not in r]
    refs_html = ""
    if refs:
        refs_html = (
            "<h3>Referanslar</h3><ul>"
            + "".join(f'<li><a href="{esc(r)}">{esc(r)}</a></li>' for r in refs)
            + "</ul>"
        )

    flash_html = ""
    if flash:
        kind = "flash err" if flash_kind == "err" else "flash"
        flash_html = f'<div class="{kind}">{esc(flash)}</div>'

    body = f"""<p><a href="/">&larr; Listeye d&ouml;n</a></p>
<h2>{esc(adv.summary or adv.ghsa_id)}</h2>
<p>{_source_badge(adv)} {_state_badge(adv, confirmed_ids)}</p>
{flash_html}
{state_card}
<div class="card">
<dl class="meta">
{meta_rows}
</dl>
</div>
<div class="card">
<h3>Mail</h3>
<dl class="meta">
{header_rows}
</dl>
<h4>G&ouml;vde</h4>
<pre class="mail">{esc(body_text)}</pre>
{html_block}
</div>
{refs_html}"""

    nav = """<header class="top">
<h1><a href="/">Advisory RSS</a></h1>
<nav><a href="/">&larr; Liste</a><a href="/rss.xml">RSS feed</a><a href="/health">health</a></nav>
</header>"""
    return _page(adv.summary or adv.ghsa_id, body, nav)


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
    "render_detail",
    "render_index",
]
