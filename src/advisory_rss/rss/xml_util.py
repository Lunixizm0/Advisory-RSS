from __future__ import annotations

import html
import re

CDATA_END = "]]>"
CDATA_SAFE = "]]]]><![CDATA[>"
# XML 1.0 disallows most C0 controls except tab, newline, carriage return.
_XML_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def _strip_illegal_xml(s: str) -> str:
    return _XML_ILLEGAL_RE.sub("", s or "")


def escape_text(s: str) -> str:
    if not s:
        return ""
    # html.escape with quote=True handles & < > " '
    return html.escape(_strip_illegal_xml(s), quote=True)


def escape_attr(s: str) -> str:
    return escape_text(s)


def cdata_wrap(s: str) -> str:
    if s is None:
        s = ""
    # Replace any occurrence of ]]> to break it safely
    safe = _strip_illegal_xml(s).replace(CDATA_END, CDATA_SAFE)
    return f"<![CDATA[{safe}]]>"


def sanitize_tag(s: str) -> str:
    # Remove control chars (kept for callers; escape_text/cdata_wrap also sanitize)
    return _strip_illegal_xml(s)
