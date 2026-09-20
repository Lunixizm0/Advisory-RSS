from __future__ import annotations

import html
import re

CDATA_END = "]]>"
CDATA_SAFE = "]]]]><![CDATA[>"


def escape_text(s: str) -> str:
    if not s:
        return ""
    # html.escape with quote=True handles & < > " '
    return html.escape(s, quote=True)


def escape_attr(s: str) -> str:
    return escape_text(s)


def cdata_wrap(s: str) -> str:
    if s is None:
        s = ""
    # Replace any occurrence of ]]> to break it safely
    safe = s.replace(CDATA_END, CDATA_SAFE)
    return f"<![CDATA[{safe}]]>"


def sanitize_tag(s: str) -> str:
    # Remove control chars
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", s or "")
