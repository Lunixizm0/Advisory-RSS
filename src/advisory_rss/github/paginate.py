from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

# Example: <https://api.github.com/repos/owner/repo/security-advisories?after=XYZ&per_page=100>; rel="next", <...>; rel="last"
_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*[^,]*rel="([^"]+)"[^,]*')


def parse_link_header(value: str | None) -> dict[str, str]:
    """Parse Link header into dict rel -> url."""
    if not value:
        return {}
    out: dict[str, str] = {}
    for m in _LINK_RE.finditer(value):
        url, rel = m.group(1), m.group(2)
        out[rel] = url
    return out


def extract_cursor(url: str, cursor_name: str = "after") -> str | None:
    try:
        qs = parse_qs(urlparse(url).query)
        vals = qs.get(cursor_name)
        if vals:
            return vals[0]
        return None
    except Exception:
        return None


def get_next_url(link_header: str | None) -> str | None:
    links = parse_link_header(link_header)
    # GitHub uses rel="next"
    return links.get("next")
