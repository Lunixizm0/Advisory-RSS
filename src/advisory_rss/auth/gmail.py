"""Gmail OAuth helpers for CERT-TR IMAP (XOAUTH2)."""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

import httpx

from advisory_rss.config.constants import (
    DEFAULT_GMAIL_OAUTH_CACHE,
    GMAIL_OAUTH_SCOPES,
    GMAIL_OAUTH_TOKEN_URI,
)

logger = logging.getLogger(__name__)


def _load_oauth_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError) as e:
        logger.debug("Failed to load Gmail OAuth file %s: %s", path, e)
        return {}


def _save_oauth_file(path: str | Path, data: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Restrict permissions (600) for token file
    try:
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        try:
            p.chmod(0o600)
        except OSError as e:
            logger.debug("chmod failed for %s: %s", p, e)
    except OSError as e:
        logger.warning("Failed to save Gmail OAuth file %s: %s", p, e)
        raise


def save_gmail_oauth_token(
    token_file: str | Path,
    email: str,
    refresh_token: str,
    client_id: str,
    client_secret: str,
    access_token: str | None = None,
    expiry: str | None = None,
) -> None:
    data = _load_oauth_file(token_file)
    # Preserve top-level client_id/secret if not per-account
    if client_id:
        data["client_id"] = client_id
    if client_secret:
        data["client_secret"] = client_secret
    if "accounts" not in data or not isinstance(data["accounts"], dict):
        data["accounts"] = {}
    acct = data["accounts"].get(email, {})
    if not isinstance(acct, dict):
        acct = {}
    acct["refresh_token"] = refresh_token
    if access_token:
        acct["access_token"] = access_token
    if expiry:
        acct["expiry"] = expiry
    data["accounts"][email] = acct
    _save_oauth_file(token_file, data)
    logger.info("Saved Gmail OAuth token for %s to %s", email, token_file)


def get_refresh_token_for_email(
    email: str,
    settings: Any,
) -> tuple[str | None, str | None, str | None]:
    """Return (refresh_token, client_id, client_secret) for email.

    Checks env vars first (GMAIL_OAUTH_REFRESH_TOKEN etc), then file.
    For multi-account, checks GMAIL_OAUTH_REFRESH_TOKENS aligned with GMAIL_EMAILS.
    """
    # Check env single/multi
    # settings may have gmail_oauth_refresh_token(s) and client_id/secret
    try:
        # Use get_gmail_accounts logic? But we can directly check settings
        # Check file first for per-account
        file_data = _load_oauth_file(getattr(settings, "gmail_oauth_token_file", DEFAULT_GMAIL_OAUTH_CACHE))
        # Try file per-account
        accounts = file_data.get("accounts") if isinstance(file_data, dict) else None
        if isinstance(accounts, dict) and email in accounts:
            info = accounts[email]
            if isinstance(info, dict) and info.get("refresh_token"):
                cid = file_data.get("client_id") or getattr(settings, "gmail_oauth_client_id", None)
                csec = file_data.get("client_secret") or getattr(settings, "gmail_oauth_client_secret", None)
                return str(info["refresh_token"]), str(cid or "") if cid else None, str(csec or "") if csec else None
            if isinstance(info, str):
                cid = file_data.get("client_id") or getattr(settings, "gmail_oauth_client_id", None)
                csec = file_data.get("client_secret") or getattr(settings, "gmail_oauth_client_secret", None)
                return info, str(cid or "") if cid else None, str(csec or "") if csec else None
        # Check flat file
        if isinstance(file_data, dict) and email in file_data and isinstance(file_data[email], str):
            cid = file_data.get("client_id") or getattr(settings, "gmail_oauth_client_id", None)
            csec = file_data.get("client_secret") or getattr(settings, "gmail_oauth_client_secret", None)
            return str(file_data[email]), str(cid or "") if cid else None, str(csec or "") if csec else None

        # Check env multi
        gmail_emails = getattr(settings, "gmail_emails", None)
        gmail_refresh_tokens = getattr(settings, "gmail_oauth_refresh_tokens", None)
        if gmail_emails and gmail_refresh_tokens:
            # _split_list is private, but we can emulate
            import re

            emails = [e.strip() for e in re.split(r"[,\s;]+", gmail_emails) if e.strip()]
            # For refresh tokens, split on comma only (preserve spaces? refresh tokens have no spaces)
            rts = [r.strip() for r in gmail_refresh_tokens.split(",") if r.strip()]
            try:
                idx = [e.lower() for e in emails].index(email.lower())
                if idx < len(rts):
                    cid = getattr(settings, "gmail_oauth_client_id", None)
                    csec = getattr(settings, "gmail_oauth_client_secret", None)
                    return rts[idx], str(cid or "") if cid else None, str(csec or "") if csec else None
            except ValueError:
                pass

        # Check env single
        single_rt = getattr(settings, "gmail_oauth_refresh_token", None)
        if single_rt and single_rt.strip():
            # If single email matches or only one email configured
            # If settings has single gmail_email matching, use it; else if only one refresh token and email matches gmail_email
            gmail_email = getattr(settings, "gmail_email", None)
            if gmail_email and gmail_email.strip().lower() == email.lower():
                cid = getattr(settings, "gmail_oauth_client_id", None)
                csec = getattr(settings, "gmail_oauth_client_secret", None)
                return single_rt.strip(), str(cid or "") if cid else None, str(csec or "") if csec else None
            # If no specific email, but we have refresh token and email is the one being queried, return it
            # This handles case where get_gmail_accounts already built with refresh token
            cid = getattr(settings, "gmail_oauth_client_id", None)
            csec = getattr(settings, "gmail_oauth_client_secret", None)
            # Only return if email is in gmail accounts list or if no list
            # For safety, return if we have a refresh token and no other mapping
            if not gmail_emails:
                return single_rt.strip(), str(cid or "") if cid else None, str(csec or "") if csec else None
    except (OSError, ValueError, AttributeError) as e:
        logger.debug("get_refresh_token failed for %s: %s", email, e)
    return None, None, None


def fetch_access_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    token_uri: str = GMAIL_OAUTH_TOKEN_URI,
) -> tuple[str, int | None]:
    """Exchange refresh token for access token via Google OAuth2.

    Returns (access_token, expires_in_seconds).
    Raises on failure.
    """
    if not refresh_token or not client_id or not client_secret:
        raise ValueError("Missing OAuth credentials (refresh_token/client_id/secret)")

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    try:
        resp = httpx.post(token_uri, data=data, timeout=15.0)
        resp.raise_for_status()
        j = resp.json()
        access_token = j.get("access_token")
        expires_in = j.get("expires_in")
        if not access_token:
            raise ValueError(f"No access_token in response: {j}")
        return str(access_token), int(expires_in) if expires_in else None
    except httpx.HTTPError as e:
        logger.warning("Failed to fetch Gmail access token: %s", e)
        raise
    except (ValueError, TypeError) as e:
        logger.warning("Invalid token response: %s", e)
        raise


def build_xoauth2_string(email: str, access_token: str) -> str:
    """Build base64-encoded XOAUTH2 string for IMAP AUTHENTICATE."""
    # Format: user=<email>\x01auth=Bearer <token>\x01\x01
    raw = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
    return base64.b64encode(raw.encode("utf-8")).decode("utf-8")


def run_gmail_oauth_flow(
    client_id: str,
    client_secret: str,
    email: str | None = None,
) -> tuple[str, str, str | None]:
    """Run InstalledAppFlow to obtain refresh token.

    Returns (refresh_token, access_token, expiry).
    Requires google-auth-oauthlib to be installed.
    Opens browser for user consent.
    """
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as e:
        raise ImportError(
            "google-auth-oauthlib is required for Gmail OAuth. Install with: pip install google-auth google-auth-oauthlib"
        ) from e

    # Use the same scopes as constants
    client_config = {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": GMAIL_OAUTH_TOKEN_URI,
            "redirect_uris": ["http://localhost", "urn:ietf:wg:oauth:2.0:oob"],
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, scopes=GMAIL_OAUTH_SCOPES)
    # Optional: set login hint if email provided
    # The flow will open browser; we use local server
    # Use port 0 to get random available port, or 8080
    # prompt=consent to ensure refresh_token is returned
    creds = flow.run_local_server(
        port=0,
        prompt="consent",
        access_type="offline",
        include_granted_scopes="true",
    )
    refresh_token = getattr(creds, "refresh_token", None)
    access_token = getattr(creds, "token", None)
    expiry = getattr(creds, "expiry", None)
    expiry_str = expiry.isoformat() if expiry else None
    if not refresh_token:
        # Sometimes refresh_token is only returned on first consent; if not, we try to use existing
        # But we should warn
        logger.warning("OAuth flow did not return a refresh_token (maybe already consented). Try revoking access and retrying.")
        # Fallback: try to use current refresh token if available? For now, raise
        raise ValueError("No refresh_token returned from OAuth flow. Ensure you revoke previous consent in Google Account and retry with prompt=consent.")
    return str(refresh_token), str(access_token or ""), expiry_str
