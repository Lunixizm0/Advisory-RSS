from __future__ import annotations

import logging

from advisory_rss.cache.models import NormalizedAdvisory

logger = logging.getLogger(__name__)


def matches_filter(
    adv: NormalizedAdvisory,
    authenticated_login: str,
    mode: str = "author",
) -> bool:
    """Return True if adv should be kept for given mode.

    - author: only author.login == authenticated_login
    - author_or_publisher: author OR publisher matches
    - author_or_collaborator: author OR publisher OR collaborating users (publisher already covers some) -
      but NormalizedAdvisory currently only stores author/publisher; to support collaborator check,
      caller must inspect raw['collaborating_users'] if present.

    Matching is case-insensitive.
    """
    if not authenticated_login or not adv.ghsa_id:
        return False
    target = authenticated_login.strip().lower()
    if not target:
        return False
    mode = (mode or "author").lower()

    def _eq(a: str | None) -> bool:
        return bool(a and a.strip().lower() == target)

    if _eq(adv.author_login):
        return True
    if mode in ("author_or_publisher", "author_or_collaborator") and _eq(adv.publisher_login):
        return True
    if mode == "author_or_collaborator":
        # check raw collaborating_users
        collab = adv.raw.get("collaborating_users")
        if isinstance(collab, list):
            for u in collab:
                if isinstance(u, dict):
                    login = u.get("login")
                    if login and str(login).strip().lower() == target:
                        return True
                elif isinstance(u, str) and u.strip().lower() == target:
                    return True
        # also collaborating_teams not user-specific - ignore
    return False


def filter_advisories(
    advisories: list[NormalizedAdvisory],
    authenticated_login: str,
    mode: str = "author",
) -> list[NormalizedAdvisory]:
    if not authenticated_login:
        logger.warning("filter_advisories called without authenticated_login - returning empty")
        return []
    filtered = [a for a in advisories if matches_filter(a, authenticated_login, mode)]
    logger.debug(
        "filter_advisories login=%s mode=%s total=%d kept=%d",
        authenticated_login,
        mode,
        len(advisories),
        len(filtered),
    )
    if not filtered and advisories:
        logger.info(
            "filter_advisories produced empty result total=%d login=%s mode=%s",
            len(advisories),
            authenticated_login,
            mode,
        )
    return filtered
