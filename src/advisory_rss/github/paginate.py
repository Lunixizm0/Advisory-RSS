from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)

# Example: <https://api.github.com/repos/owner/repo/security-advisories?after=XYZ&per_page=100>; rel="next", <...>; rel="last"
# More precise than previous [^,]* variant - split by comma first, then parse each segment
_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*[^,]*?rel="([^"]+)"')


def parse_link_header(value: str | None) -> dict[str, str]:
    """Parse Link header into dict rel -> url."""
    if not value:
        return {}
    out: dict[str, str] = {}
    found = 0
    for m in _LINK_RE.finditer(value):
        url, rel = m.group(1), m.group(2)
        out[rel] = url
        found += 1
    if found == 0 and value.strip():
        logger.warning("malformed Link header (no rel found): %r", value[:500])
    else:
        logger.debug("parse_link_header %r -> %s", value[:300], out)
    return out


def extract_cursor(url: str, cursor_name: str = "after") -> str | None:
    try:
        qs = parse_qs(urlparse(url).query)
        vals = qs.get(cursor_name)
        if vals:
            return vals[0]
        return None
    except (ValueError, AttributeError, TypeError) as e:
        logger.debug("extract_cursor failed url=%r cursor=%s: %s", url[:300], cursor_name, e)
        return None


def get_next_url(link_header: str | None) -> str | None:
    links = parse_link_header(link_header)
    nxt = links.get("next")
    if nxt:
        logger.debug("get_next_url found %s", nxt[:300])
    elif link_header:
        logger.debug("get_next_url no next in %r", link_header[:500])
    # GitHub uses rel="next"
    return nxt
