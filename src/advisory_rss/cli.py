from __future__ import annotations

import asyncio
import getpass
import logging
import os
import re as _re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click
import httpx

from advisory_rss import __version__
from advisory_rss.auth.pat import load_token, token_preview
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.constants import TOKEN_REDACT_PATTERN
from advisory_rss.config.settings import get_settings
from advisory_rss.github.client import AuthError, GitHubClient, RateLimitError
from advisory_rss.logging_config import setup_logging as _setup_logging

TOKEN_RE = _re.compile(TOKEN_REDACT_PATTERN)

logger = logging.getLogger(__name__)


def _redact(s: str) -> str:
    return TOKEN_RE.sub("***", s)


def configure_logging(
    level: str,
    *,
    log_file: str | None = None,
    log_format: str = "text",
    force: bool = False,
    use_stderr: bool = True,
) -> None:
    try:
        settings = get_settings()
        # Prefer explicit args, else settings
        lf = log_file if log_file is not None else getattr(settings, "log_file", None)
        fmt = log_format if log_format != "text" else getattr(settings, "log_format", "text")
    except (OSError, ValueError, RuntimeError, AttributeError) as e:
        logger.debug("Failed to load settings for logging config: %s", e)
        lf = log_file
        fmt = log_format
    _setup_logging(level, log_file=lf, log_format=fmt, force=force, use_stderr=use_stderr)


@click.group()
@click.version_option(__version__)
def cli() -> None:
    pass


@cli.group()
def auth() -> None:
    pass


def _upsert_env_file(key: str, value: str, env_path: str = ".env") -> None:
    import re as _re2

    p = Path(env_path)
    lines: list[str] = []
    if p.exists():
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            logger.debug("Failed to read %s: %s", env_path, e)
            lines = []
    # Find existing key
    found = False
    new_lines: list[str] = []
    pattern = _re2.compile(rf"^\s*{_re2.escape(key)}\s*=", _re.IGNORECASE)
    for line in lines:
        if pattern.match(line):
            if not found:
                new_lines.append(f"{key}={value}")
                found = True
            # skip duplicate
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={value}")
    try:
        p.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        logger.info("Updated %s with %s", env_path, key)
    except OSError as e:
        logger.warning("Failed to write %s: %s", env_path, e)
        click.echo(f"Warning: could not write {env_path}: {e}", err=True)


def _prompt_provider(default: str | None = None) -> str:
    choice = click.prompt(
        "Hangi kaynak için giriş yapmak istiyorsun?",
        type=click.Choice(["github", "proton", "gmail"], case_sensitive=False),
        default=default or "github",
        show_choices=True,
    )
    return str(choice).lower()


def _prompt_gmail_method(default: str | None = None) -> str:
    choice = click.prompt(
        "Gmail için hangi yöntem? [oauth/app-password]",
        type=click.Choice(["oauth", "app-password", "app"], case_sensitive=False),
        default=default or "oauth",
        show_choices=True,
    )
    c = str(choice).lower()
    return "oauth" if c == "oauth" else "app-password"


@auth.command("login")
@click.option(
    "--provider",
    type=click.Choice(["github", "proton", "gmail"], case_sensitive=False),
    default=None,
    help="Hangi kaynak için login (github/proton/gmail). Belirtilmezse interaktif sorulur.",
)
@click.option(
    "--method",
    type=click.Choice(["oauth", "app-password"], case_sensitive=False),
    default=None,
    help="Gmail için yöntem (oauth veya app-password). Sadece gmail için.",
)
@click.option("--email", default=None, help="E-posta adresi (proton/gmail için)")
def auth_login(
    provider: str | None = None, method: str | None = None, email: str | None = None
) -> None:
    settings = get_settings()
    _setup_logging(settings.log_level, log_file=settings.log_file, log_format=settings.log_format)
    logger.info("auth login started provider=%s method=%s email=%s", provider, method, email)

    # Determine provider interactively if not provided
    if not provider:
        provider = _prompt_provider()
    provider = provider.lower()

    if provider == "github":
        click.echo(
            "GitHub PAT: fine-grained 'Repository security advisories: Read' is recommended."
        )
        click.echo(
            "Token must be set in .env as GITHUB_TOKEN - credentials file is no longer used."
        )
        existing_env = settings.token
        if existing_env:
            click.echo(f"Note: GITHUB_TOKEN already set via env ({token_preview(existing_env)}).")
            click.echo("If you want to rotate, edit .env directly: GITHUB_TOKEN=...")
        try:
            token = getpass.getpass("Paste GitHub PAT (input hidden): ").strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("\nCancelled.", err=True)
            sys.exit(1)
        if not token:
            click.echo("No token entered - abort.", err=True)
            sys.exit(1)

        async def _validate() -> dict:
            s = get_settings()
            cache = CacheStore(s.resolved_cache_path)
            client = GitHubClient(s, token, cache=cache)
            try:
                user = await client.get_user()
                return user
            finally:
                await client.close()

        try:
            user = asyncio.run(_validate())
            login = user.get("login", "unknown")
            click.echo(f"+ Validated as @{login}")
        except AuthError as e:
            click.echo(f"- Authentication failed: {_redact(str(e))}", err=True)
            click.echo(
                "Check token value, expiry, and scopes (repository_advisories:read).",
                err=True,
            )
            sys.exit(1)
        except (OSError, ValueError, RuntimeError, httpx.HTTPError) as e:
            click.echo(f"- Validation error: {_redact(str(e))}", err=True)
            sys.exit(1)

        click.echo("")
        click.echo("Token is VALID but NOT saved to disk by this command.")
        if click.confirm("Token .env dosyasına yazılsın mı?", default=False):
            _upsert_env_file("GITHUB_TOKEN", token)
            click.echo("Wrote GITHUB_TOKEN to .env")
        else:
            click.echo("Set it in .env:")
            click.echo("  echo 'GITHUB_TOKEN=YOUR_TOKEN_HERE' >> .env")
        click.echo("Then: app sync && app serve")
        click.echo("Never commit .env (gitignored).")
        return

    if provider == "proton":
        # Proton Bridge: email + bridge password
        if not email:
            email = click.prompt(
                "Proton e-posta adresi", type=str, default=settings.proton_bridge_email or ""
            )
            email = email.strip()
        if not email or "@" not in email:
            click.echo("Geçersiz e-posta", err=True)
            sys.exit(1)
        # Ask for bridge password (hidden)
        try:
            bridge_pw = getpass.getpass(
                f"Proton Bridge şifresi ({email}) (Bridge > Mailbox details, NOT account password): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("\nCancelled.", err=True)
            sys.exit(1)
        if not bridge_pw:
            click.echo("Şifre girilmedi - abort.", err=True)
            sys.exit(1)
        # Validate via IMAP
        from advisory_rss.cert_tr.imap import connect_imap

        acc = {
            "email": email,
            "password": bridge_pw,
            "folder": settings.proton_imap_folder or "INBOX",
            "host": settings.proton_bridge_host or "127.0.0.1",
            "port": str(settings.proton_imap_port),
            "security": settings.proton_imap_security or "STARTTLS",
        }
        try:
            mail = connect_imap(acc)
            try:
                mail.select(acc["folder"], readonly=True)
                # Try to list folders to verify
                mail.list()
            finally:
                try:
                    mail.logout()
                except (OSError, ValueError, RuntimeError) as e:
                    logger.debug("Proton logout failed: %s", e)
            click.echo(
                f"+ Proton IMAP doğrulandı: {email} -> {acc['folder']} @ {acc['host']}:{acc['port']}"
            )
        except (OSError, ValueError, RuntimeError) as e:
            click.echo(f"- Proton IMAP hatası: {_redact(str(e))}", err=True)
            click.echo(
                "Bridge çalışıyor mu? Host/port doğru mu? Şifre Bridge şifresi mi?", err=True
            )
            sys.exit(1)

        # Save to .env - handle multi
        # If PROTON_BRIDGE_EMAILS already has multiple, append
        existing_emails = settings.proton_bridge_emails
        if existing_emails and email not in [e.strip() for e in existing_emails.split(",")]:
            # Append to multi
            new_emails = existing_emails.strip() + f",{email}"
            _upsert_env_file("PROTON_BRIDGE_EMAILS", new_emails)
            # Passwords
            existing_pw = settings.proton_bridge_passwords or ""
            if existing_pw.strip():
                new_pw = existing_pw.strip() + f",{bridge_pw}"
            else:
                # If single was set, migrate to multi
                single_pw = settings.proton_bridge_password or ""
                if single_pw and single_pw.strip() != bridge_pw:
                    new_pw = f"{single_pw.strip()},{bridge_pw}"
                else:
                    new_pw = bridge_pw
            _upsert_env_file("PROTON_BRIDGE_PASSWORDS", new_pw)
            click.echo(
                f"Wrote PROTON_BRIDGE_EMAILS and PROTON_BRIDGE_PASSWORDS to .env (appended {email})"
            )
        else:
            _upsert_env_file("PROTON_BRIDGE_EMAIL", email)
            _upsert_env_file("PROTON_BRIDGE_PASSWORD", bridge_pw)
            click.echo("Wrote PROTON_BRIDGE_EMAIL and PROTON_BRIDGE_PASSWORD to .env")
        click.echo("ENABLE_CERT_TR=true olduğundan emin olun, sonra: app sync --source cert-tr")
        return

    if provider == "gmail":
        # Gmail: ask oauth vs app-password
        gmail_method = method
        if not gmail_method:
            gmail_method = _prompt_gmail_method()
        gmail_method = gmail_method.lower()
        if gmail_method not in ("oauth", "app-password", "app"):
            gmail_method = "oauth"
        if gmail_method == "app":
            gmail_method = "app-password"

        if not email:
            default_email = settings.gmail_email or (
                settings.gmail_emails.split(",")[0].strip() if settings.gmail_emails else ""
            )
            email = click.prompt("Gmail e-posta adresi", type=str, default=default_email)
            email = email.strip()
        if not email or "@" not in email:
            click.echo("Geçersiz e-posta", err=True)
            sys.exit(1)

        if gmail_method == "app-password":
            try:
                app_pw = getpass.getpass(
                    f"Gmail App Password ({email}) (16 haneli, Google Hesabı > Güvenlik > 2FA > Uygulama şifreleri): "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                click.echo("\nCancelled.", err=True)
                sys.exit(1)
            if not app_pw:
                click.echo("App Password girilmedi", err=True)
                sys.exit(1)
            # Validate via IMAP (Gmail SSL)
            from advisory_rss.cert_tr.imap import connect_imap

            acc = {
                "email": email,
                "password": app_pw,
                "folder": settings.gmail_imap_folder or "INBOX",
                "host": settings.gmail_imap_host or "imap.gmail.com",
                "port": str(settings.gmail_imap_port),
                "security": settings.gmail_imap_security or "SSL",
            }
            try:
                mail = connect_imap(acc)
                try:
                    mail.select(acc["folder"], readonly=True)
                finally:
                    try:
                        mail.logout()
                    except (OSError, ValueError, RuntimeError) as e:
                        logger.debug("Gmail logout failed: %s", e)
                click.echo(f"+ Gmail IMAP (App Password) doğrulandı: {email}")
            except (OSError, ValueError, RuntimeError) as e:
                click.echo(f"- Gmail hatası: {_redact(str(e))}", err=True)
                click.echo(
                    "App Password doğru mu? 2FA açık mı? IMAP enabled mi? (Gmail > Ayarlar > Yönlendirme ve POP/IMAP)",
                    err=True,
                )
                sys.exit(1)

            # Save to .env (handle multi)
            existing_emails = settings.gmail_emails
            if existing_emails and email not in [e.strip() for e in existing_emails.split(",")]:
                new_emails = existing_emails.strip() + f",{email}"
                _upsert_env_file("GMAIL_EMAILS", new_emails)
                existing_pw = settings.gmail_app_passwords or ""
                # App passwords may contain spaces, so we join with comma
                if existing_pw.strip():
                    new_pw = existing_pw.strip() + f",{app_pw}"
                else:
                    single_pw = settings.gmail_app_password or settings.gmail_password or ""
                    if single_pw and single_pw.strip() != app_pw:
                        new_pw = f"{single_pw.strip()},{app_pw}"
                    else:
                        new_pw = app_pw
                _upsert_env_file("GMAIL_APP_PASSWORDS", new_pw)
                click.echo(
                    f"Wrote GMAIL_EMAILS and GMAIL_APP_PASSWORDS to .env (appended {email}, spaces preserved)"
                )
            else:
                _upsert_env_file("GMAIL_EMAIL", email)
                _upsert_env_file("GMAIL_APP_PASSWORD", app_pw)
                click.echo("Wrote GMAIL_EMAIL and GMAIL_APP_PASSWORD to .env")
            click.echo("ENABLE_CERT_TR=true olduğundan emin olun, sonra: app sync --source cert-tr")
            return

        # OAuth path
        # Need client_id/secret
        client_id = settings.gmail_oauth_client_id
        client_secret = settings.gmail_oauth_client_secret
        if not client_id or not client_secret:
            click.echo("Gmail OAuth için Google Cloud OAuth Client ID/Secret gerekli.")
            click.echo(
                "Oluştur: https://console.cloud.google.com/ -> APIs & Services -> Credentials -> Create Credentials -> OAuth Client ID (Desktop)"
            )
            click.echo("Redirect URI: http://localhost (InstalledAppFlow otomatik)")
            click.echo("Scopes: https://mail.google.com/")
            if not client_id:
                client_id = click.prompt(
                    "OAuth Client ID", type=str, default=client_id or ""
                ).strip()
            if not client_secret:
                try:
                    client_secret = getpass.getpass("OAuth Client Secret (hidden): ").strip()
                except (EOFError, KeyboardInterrupt):
                    click.echo("\nCancelled.", err=True)
                    sys.exit(1)
            if not client_id or not client_secret:
                click.echo("Client ID/Secret gerekli", err=True)
                sys.exit(1)
            # Save to .env
            _upsert_env_file("GMAIL_OAUTH_CLIENT_ID", client_id)
            _upsert_env_file("GMAIL_OAUTH_CLIENT_SECRET", client_secret)
            click.echo("Wrote GMAIL_OAUTH_CLIENT_ID/SECRET to .env")

        # Run OAuth flow
        click.echo(f"Tarayıcı açılacak, Gmail hesabı {email} ile onay verin...")
        click.echo("Eğer tarayıcı açılmazsa, terminaldeki URL'yi manuel açın.")
        try:
            from advisory_rss.auth.gmail import run_gmail_oauth_flow, save_gmail_oauth_token
        except ImportError as e:
            click.echo(f"Gerekli paket eksik: {e}", err=True)
            click.echo("Şunu çalıştır: pip install google-auth google-auth-oauthlib", err=True)
            sys.exit(1)

        try:
            refresh_token, access_token, expiry = run_gmail_oauth_flow(
                client_id, client_secret, email
            )
            click.echo(f"+ OAuth başarılı: refresh_token alındı ({refresh_token[:8]}...)")
        except (OSError, ValueError, RuntimeError) as e:
            click.echo(f"- OAuth hatası: {_redact(str(e))}", err=True)
            sys.exit(1)

        # Validate via XOAUTH2 IMAP
        from advisory_rss.cert_tr.imap import connect_imap

        acc = {
            "email": email,
            "password": "",
            "folder": settings.gmail_imap_folder or "INBOX",
            "host": settings.gmail_imap_host or "imap.gmail.com",
            "port": str(settings.gmail_imap_port),
            "security": settings.gmail_imap_security or "SSL",
            "auth_method": "oauth",
            "oauth_refresh_token": refresh_token,
            "oauth_client_id": client_id,
            "oauth_client_secret": client_secret,
        }
        try:
            mail = connect_imap(acc)
            try:
                mail.select(acc["folder"], readonly=True)
            finally:
                try:
                    mail.logout()
                except (OSError, ValueError, RuntimeError) as e:
                    logger.debug("Gmail OAuth logout failed: %s", e)
            click.echo(f"+ Gmail IMAP (OAuth) doğrulandı: {email}")
        except (OSError, ValueError, RuntimeError) as e:
            click.echo(f"- Gmail OAuth hatası: {_redact(str(e))}", err=True)
            sys.exit(1)

        # Save refresh token
        # Prefer file cache plus env
        token_file = settings.gmail_oauth_token_file or "cache/gmail_oauth.json"
        try:
            save_gmail_oauth_token(
                token_file, email, refresh_token, client_id, client_secret, access_token, expiry
            )
            click.echo(f"Wrote OAuth token to {token_file} (600 perms)")
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Failed to save to file: %s", e)

        # Also save to .env for convenience (single or multi)
        existing_emails = settings.gmail_emails
        existing_rts = settings.gmail_oauth_refresh_tokens
        if existing_emails and email not in [e.strip() for e in existing_emails.split(",")]:
            new_emails = existing_emails.strip() + f",{email}"
            _upsert_env_file("GMAIL_EMAILS", new_emails)
            if existing_rts and existing_rts.strip():
                new_rts = existing_rts.strip() + f",{refresh_token}"
            else:
                single_rt = settings.gmail_oauth_refresh_token or ""
                if single_rt and single_rt.strip() != refresh_token:
                    new_rts = f"{single_rt.strip()},{refresh_token}"
                else:
                    new_rts = refresh_token
            _upsert_env_file("GMAIL_OAUTH_REFRESH_TOKENS", new_rts)
            click.echo(
                f"Wrote GMAIL_EMAILS and GMAIL_OAUTH_REFRESH_TOKENS to .env (appended {email})"
            )
        elif existing_emails:
            # Update existing entry
            # Find index and replace
            emails = [e.strip() for e in existing_emails.split(",")]
            rts = [r.strip() for r in (existing_rts or "").split(",")] if existing_rts else []
            # Pad rts
            while len(rts) < len(emails):
                rts.append("")
            try:
                idx = [e.lower() for e in emails].index(email.lower())
                rts[idx] = refresh_token
                _upsert_env_file("GMAIL_OAUTH_REFRESH_TOKENS", ",".join(rts))
                click.echo("Updated GMAIL_OAUTH_REFRESH_TOKENS in .env")
            except ValueError:
                _upsert_env_file("GMAIL_OAUTH_REFRESH_TOKEN", refresh_token)
                click.echo("Wrote GMAIL_OAUTH_REFRESH_TOKEN to .env")
        else:
            # Single
            if settings.gmail_email and settings.gmail_email.strip().lower() != email.lower():
                # Migrate single to multi
                prev_email = settings.gmail_email.strip()
                prev_rt = settings.gmail_oauth_refresh_token or ""
                _upsert_env_file("GMAIL_EMAILS", f"{prev_email},{email}")
                _upsert_env_file("GMAIL_OAUTH_REFRESH_TOKENS", f"{prev_rt},{refresh_token}")
                click.echo("Migrated single Gmail to multi (GMAIL_EMAILS)")
            else:
                _upsert_env_file("GMAIL_EMAIL", email)
                _upsert_env_file("GMAIL_OAUTH_REFRESH_TOKEN", refresh_token)
                click.echo("Wrote GMAIL_EMAIL and GMAIL_OAUTH_REFRESH_TOKEN to .env")

        click.echo(
            "OAuth tamamlandı. ENABLE_CERT_TR=true olduğundan emin olun, sonra: app sync --source cert-tr"
        )
        click.echo(
            "Not: Access token otomatik yenilenecek (refresh_token saklandı). İptal için Google Hesabı > Güvenlik > Üçüncü taraf erişimi'nden kaldırın."
        )
        return

    click.echo(f"Bilinmeyen provider: {provider}", err=True)
    sys.exit(1)


@auth.command("status")
def auth_status() -> None:
    _status()


@cli.command()
@click.option(
    "--source",
    type=click.Choice(["all", "github", "cert-tr"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Which source to sync (all includes GitHub + CERT-TR)",
)
def sync(source: str = "all") -> None:
    settings = get_settings()
    _setup_logging(settings.log_level, log_file=settings.log_file, log_format=settings.log_format)
    logger.info(
        "sync started source=%s",
        source,
        extra={
            "filter_mode": settings.filter_mode,
            "cache_path": str(settings.resolved_cache_path),
            "enable_cert_tr": settings.enable_cert_tr,
        },
    )
    source = source.lower()
    token = load_token(settings)
    # Allow cert-tr only sync without GitHub token
    need_github = source in ("all", "github")
    if need_github and not token:
        # If CERT-TR is enabled and user asked all, still allow cert-tr part to run
        if settings.enable_cert_tr and source == "all":
            click.echo(
                "Warning: GITHUB_TOKEN not set - GitHub sync will be skipped, CERT-TR only.",
                err=True,
            )
            logger.warning("sync without GitHub token - GitHub skipped, CERT-TR only")
            need_github = False
        else:
            click.echo("No token set. Set GITHUB_TOKEN in .env or run `app auth login`.", err=True)
            sys.exit(1)

    cache = CacheStore(settings.resolved_cache_path)

    async def _run() -> int:
        all_advisories = []
        combined_diag: dict = {
            "github": None,
            "cert_tr": None,
            "errors": [],
        }
        # --- GitHub ---
        if need_github and token:
            client = GitHubClient(settings, token, cache=cache)
            try:
                advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
                all_advisories.extend(advs)
                combined_diag["github"] = diag
                combined_diag["errors"].extend(diag.get("errors") or [])
                logger.info(
                    "GitHub sync ok: upserted=%d filtered=%s raw=%s repos=%s orgs=%s",
                    len(advs),
                    diag.get("filtered_count"),
                    diag.get("raw_count"),
                    diag.get("repos_scanned"),
                    diag.get("orgs_scanned"),
                    extra={"diag": diag},
                )
                click.echo(
                    f"GitHub sync OK - {len(advs)} advisories (filtered {diag.get('filtered_count')} from {diag.get('raw_count')} raw, {diag.get('repos_scanned')} repos)"
                )
                if advs:
                    click.echo(f"Latest GitHub: {advs[0].ghsa_id} - {advs[0].summary[:80]}")
            except AuthError as e:
                msg = _redact(str(e))
                logger.exception("GitHub sync auth error: %s", msg)
                click.echo(f"GitHub Auth error (401): {msg}", err=True)
                cache.mark_error(msg)
                if source == "github":
                    sys.exit(1)
                combined_diag["errors"].append(msg)
            except RateLimitError as e:
                msg = _redact(str(e))
                logger.warning("GitHub rate limited retry_after=%s: %s", e.retry_after, msg)
                click.echo(f"GitHub rate limited - retry after {e.retry_after}: {msg}", err=True)
                if e.retry_after:
                    cache.set_meta(
                        "rate_limited_until",
                        (datetime.now(UTC) + timedelta(seconds=e.retry_after)).isoformat(),
                    )
                cache.mark_error(msg)
                if source == "github":
                    sys.exit(1)
                combined_diag["errors"].append(msg)
            except (OSError, ValueError, RuntimeError, httpx.HTTPError) as e:
                msg = _redact(str(e))
                logger.exception("GitHub sync failed: %s", msg)
                click.echo(f"GitHub sync failed: {msg}", err=True)
                cache.mark_error(msg)
                if source == "github":
                    sys.exit(1)
                combined_diag["errors"].append(msg)
            finally:
                await client.close()
        elif source in ("all", "github"):
            click.echo("GitHub sync skipped (no token).")

        # --- CERT-TR (Proton) ---
        if source in ("all", "cert-tr") and settings.enable_cert_tr:
            try:
                from advisory_rss.cert_tr.source import CertTrSource

                src = CertTrSource(settings)
                advs_ct, diag_ct = src.fetch_all()
                combined_diag["cert_tr"] = diag_ct
                combined_diag["errors"].extend(diag_ct.get("errors") or [])
                if advs_ct:
                    all_advisories.extend(advs_ct)
                    click.echo(
                        f"CERT-TR sync OK - {len(advs_ct)} advisories from {diag_ct.get('accounts')} account(s) (raw {diag_ct.get('raw_fetched')})"
                    )
                    click.echo(f"Latest CERT-TR: {advs_ct[0].ghsa_id} - {advs_ct[0].summary[:80]}")
                else:
                    click.echo(
                        f"CERT-TR sync: no advisories (raw {diag_ct.get('raw_fetched')}, filtered_sender {diag_ct.get('filtered_sender')})"
                    )
                    if diag_ct.get("errors"):
                        for e in diag_ct["errors"][:3]:
                            click.echo(f"  CERT-TR warn: {_redact(e)}", err=True)
            except (OSError, ValueError, RuntimeError) as e:
                msg = _redact(str(e))
                logger.exception("CERT-TR sync failed: %s", msg)
                click.echo(f"CERT-TR sync failed: {msg}", err=True)
                cache.mark_error(msg)
                if source == "cert-tr":
                    sys.exit(1)
                combined_diag["errors"].append(msg)
        elif source in ("all", "cert-tr") and not settings.enable_cert_tr:
            click.echo("CERT-TR disabled (ENABLE_CERT_TR=false) - skipping.", err=True)

        # --- Upsert combined ---
        if not all_advisories:
            # Check if both sources were skipped vs empty result
            click.echo(
                "No advisories from any source - cache unchanged. Check GITHUB_TOKEN / PROTON_* settings."
            )
            # Still mark success if no error (to update next sync)
            if not combined_diag["errors"]:
                cache.mark_success(user=cache.get_meta("authenticated_user"))
                nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
                cache.set_meta("next_scheduled_sync", nxt)
            else:
                cache.mark_error("; ".join(combined_diag["errors"][:3]))
            return 0

        # Dedup across sources (GitHub GHSA-* vs CERT-TR-* no collision, but keep logic)
        # CERT-TR already deduped by CVE; GitHub deduped too; cross-source no overlap
        count = cache.upsert_advisories(all_advisories)
        # keep authenticated_user from GitHub if present, else cert-tr
        user = None
        if combined_diag.get("github"):
            user = combined_diag["github"].get("authenticated_login")
        if not user:
            user = cache.get_meta("authenticated_user")
        cache.mark_success(user=user)
        nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
        cache.set_meta("next_scheduled_sync", nxt)
        # Store cert-tr diag for health
        try:
            import json

            if combined_diag.get("cert_tr"):
                cache.set_meta(
                    "cert_tr_diag", json.dumps(combined_diag["cert_tr"], ensure_ascii=False)
                )
        except (OSError, ValueError, TypeError, RuntimeError) as e:
            logger.debug("Failed to persist cert_tr_diag: %s", e)
        click.echo(
            f"Sync OK - {count} advisories upserted total ({len(all_advisories)} fetched before dedup)"
        )
        if combined_diag["errors"]:
            click.echo(f"Warnings ({len(combined_diag['errors'])}):", err=True)
            for e in combined_diag["errors"][:5]:
                click.echo(f"  - {_redact(e)}", err=True)
        return count

    asyncio.run(_run())


def _daemonize(pid_file: str | None = None, log_file: str | None = None) -> None:
    import os as _os

    # Flush std
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except OSError as e:
        logger.debug("flush failed: %s", _redact(str(e)))

    # First fork
    try:
        pid = _os.fork()
        if pid > 0:
            # Parent exits
            _os._exit(0)
    except OSError as e:
        click.echo(f"Daemon fork failed: {e}", err=True)
        sys.exit(1)

    # Decouple from parent env
    try:
        _os.setsid()
    except OSError as e:
        logger.debug("setsid failed: %s", _redact(str(e)))

    # Second fork
    try:
        pid = _os.fork()
        if pid > 0:
            _os._exit(0)
    except OSError as e:
        click.echo(f"Daemon second fork failed: {e}", err=True)
        sys.exit(1)

    # Redirect std fds
    log_path = log_file or "cache/serve.log"
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", buffering=1, encoding="utf-8") as lf:
            # Also keep fd open via file object - avoid GC closing
            _os.dup2(lf.fileno(), sys.stdout.fileno())
            _os.dup2(lf.fileno(), sys.stderr.fileno())
            # stdin -> /dev/null
            with open(os.devnull, "r", encoding="utf-8") as dn:
                _os.dup2(dn.fileno(), sys.stdin.fileno())
    except OSError as e:
        logger.debug("daemon log redirect failed: %s", _redact(str(e)))
        # Fallback to /dev/null
        try:
            with open(os.devnull, "w", encoding="utf-8") as dn:
                _os.dup2(dn.fileno(), sys.stdout.fileno())
                _os.dup2(dn.fileno(), sys.stderr.fileno())
        except OSError as e2:
            logger.debug("fallback dup2 failed: %s", _redact(str(e2)))

    # Write pid file
    if pid_file:
        try:
            Path(pid_file).parent.mkdir(parents=True, exist_ok=True)
            Path(pid_file).write_text(str(_os.getpid()), encoding="utf-8")
        except (OSError, ValueError, RuntimeError) as e:
            click.echo(f"Warning: could not write pid file {pid_file}: {e}", err=True)


@cli.command()
@click.option(
    "--daemon",
    "-d",
    is_flag=True,
    help="Run in background - survives terminal close (daemonize, setsid, pid/log in cache/)",
)
@click.option(
    "--pid-file", default="cache/advisory-rss.pid", show_default=True, help="PID file when --daemon"
)
@click.option(
    "--log-file",
    default="cache/serve.log",
    show_default=True,
    help="Log file when --daemon (stdout/stderr)",
)
def serve(
    daemon: bool = False,
    pid_file: str = "cache/advisory-rss.pid",
    log_file: str = "cache/serve.log",
) -> None:
    settings = get_settings()
    # Use CLI log_file if --daemon else settings LOG_FILE if set; otherwise daemon default
    effective_log_file = log_file if daemon else (settings.log_file or None)
    # Pre-daemon file: only use settings file if not daemon; daemon path will re-setup after fork
    pre_log_file = None if daemon else effective_log_file
    _setup_logging(settings.log_level, log_file=pre_log_file, log_format=settings.log_format)
    logger.info(
        "serve init daemon=%s log_file=%s log_format=%s",
        daemon,
        effective_log_file,
        settings.log_format,
        extra={"bind": settings.effective_bind_address(), "port": settings.port},
    )
    # Validate bind address
    from advisory_rss.server.bind import assert_loopback

    bind = settings.effective_bind_address()
    assert_loopback(bind)
    port = settings.port
    token = load_token(settings)
    cache = CacheStore(settings.resolved_cache_path)

    # Inform but do not print token
    click.echo(f"Advisory RSS v{__version__}")
    click.echo(f"Binding to {bind}:{port} (localhost-only)")
    click.echo(f"RSS URL: {settings.rss_url()}")
    click.echo(f"Health : http://{bind}:{port}/health")
    click.echo(f"Cache  : {settings.resolved_cache_path} ({cache.count()} advisories cached)")
    if not token:
        click.echo(
            "Warning: GITHUB_TOKEN not set - RSS will serve stale cache only; run `app sync` after setting token.",
            err=True,
        )
        logger.warning("serve without token - RSS will serve stale cache only")
    else:
        click.echo(f"GitHub authentication: set ({token_preview(token)})")
        authenticated_user = cache.get_meta("authenticated_user")
        if authenticated_user:
            click.echo(f"Authenticated user: @{authenticated_user}")
        logger.info(
            "serve token set preview=%s user=%s",
            token_preview(token),
            cache.get_meta("authenticated_user") or "unknown",
        )

    logger.info(
        "serve config bind=%s:%s cache=%s filter=%s refresh=%ds max_items=%s log_level=%s log_format=%s",
        bind,
        port,
        settings.resolved_cache_path,
        settings.filter_mode,
        settings.refresh_interval,
        settings.max_items,
        settings.log_level,
        settings.log_format,
    )
    # Verify listening socket note
    click.echo(
        f"Verify binding:  ss -tlnp | grep {port}   (expect {bind}:{port}, never 0.0.0.0:{port})"
    )
    click.echo(
        f"Filter mode: {settings.filter_mode}  Refresh: {settings.refresh_interval}s  Max items: {settings.max_items}"
    )
    logger.debug(
        "serve details url=%s health=http://%s:%s/health count=%s",
        settings.rss_url(),
        bind,
        port,
        cache.count(),
    )

    if daemon:
        # Check stale pid with cmdline verification to avoid PID reuse false positives
        pf = Path(pid_file)
        if pf.exists():
            try:
                pid = int(pf.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                # Verify cmdline contains advisory-rss to detect PID reuse
                try:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_text(
                        encoding="utf-8", errors="ignore"
                    )
                    if "advisory" not in cmdline.lower() and "uvicorn" not in cmdline.lower():
                        raise ProcessLookupError  # treat as stale
                except FileNotFoundError:
                    raise ProcessLookupError
                except (OSError, ValueError):
                    pass  # if /proc not available, fall back to kill(0) check
                click.echo(
                    f"Already running (pid {pid} from {pf}), abort. Use `app stop` first.", err=True
                )
                sys.exit(1)
            except (OSError, ValueError, ProcessLookupError):
                try:
                    pf.unlink(missing_ok=True)
                except OSError as e:
                    logger.debug("stale pid cleanup failed: %s", _redact(str(e)))
        click.echo(
            f"Daemonizing - pid: {pid_file}, log: {log_file} (terminal kapanınca da yaşar, nohup/setsid)"
        )
        _daemonize(pid_file, log_file)
        # Child continues; stdout/stderr now goes to log file
        # Reconfigure logging to use rotating file after daemon fork (use only file handler to avoid duplicate writes to same file)
        try:
            _setup_logging(
                settings.log_level,
                log_file=log_file,
                log_format=settings.log_format,
                force=True,
                use_stderr=False,
            )
            logger.info("daemon child logging reconfigured file=%s", log_file)
        except (OSError, ValueError, RuntimeError) as e:
            print(f"daemon logging reconfigure failed: {e}", file=sys.stderr)

    # Import uvicorn late
    from contextlib import asynccontextmanager

    import uvicorn

    from advisory_rss.server.app import background_refresh_loop, create_app

    @asynccontextmanager
    async def lifespan(app):  # type: ignore[no-untyped-def]
        # startup
        nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
        if not cache.get_meta("next_scheduled_sync"):
            cache.set_meta("next_scheduled_sync", nxt)
        app.state.bg_task = asyncio.create_task(background_refresh_loop(settings, cache))
        bg_logger = logging.getLogger("advisory_rss")
        bg_logger.info("Background refresh scheduled every %ds", settings.refresh_interval)
        try:
            yield
        finally:
            # shutdown
            task = getattr(app.state, "bg_task", None)
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            logger.info("server shutdown")

    app = create_app(settings=settings, cache=cache, lifespan=lifespan)

    config = uvicorn.Config(
        app,
        host=bind,
        port=port,
        log_level=settings.log_level.lower(),
        access_log=True,
        loop="auto",
        log_config=None,  # use our setup_logging, not uvicorn's default
    )
    server = uvicorn.Server(config)
    try:
        server.run()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        click.echo("\nShutting down…")


@cli.command()
@click.option(
    "--pid-file", default="cache/advisory-rss.pid", show_default=True, help="PID file of daemon"
)
def stop(pid_file: str = "cache/advisory-rss.pid") -> None:
    settings = get_settings()
    _setup_logging(settings.log_level, log_file=settings.log_file, log_format=settings.log_format)
    logger.info("stop called pid_file=%s", pid_file)
    pf = Path(pid_file)
    if not pf.exists():
        click.echo(f"No pid file {pf} - not running ?", err=True)
        sys.exit(1)
    try:
        pid = int(pf.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as e:
        click.echo(f"Bad pid file {pf}: {e}", err=True)
        sys.exit(1)
    try:
        os.kill(pid, 15)  # SIGTERM
        click.echo(f"Sent SIGTERM to {pid} ({pf})")
        # Wait a bit and clean pid file if process gone
        import time as _time

        for _ in range(20):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            _time.sleep(0.2)
        else:
            click.echo(f"Process {pid} still alive, try `kill -9 {pid}`", err=True)
            sys.exit(1)
        try:
            pf.unlink(missing_ok=True)
        except OSError as e:
            logger.debug("pid cleanup failed: %s", _redact(str(e)))
        click.echo("Stopped and cleaned pid file.")
    except ProcessLookupError:
        click.echo(f"Process {pid} not found - cleaning stale pid file {pf}")
        try:
            pf.unlink(missing_ok=True)
        except OSError as e:
            logger.debug("stale pid cleanup failed: %s", _redact(str(e)))
    except PermissionError as e:
        click.echo(f"Permission denied killing {pid}: {e}", err=True)
        sys.exit(1)


@cli.command()
def status() -> None:
    _status()


def _status() -> None:
    settings = get_settings()
    _setup_logging(settings.log_level, log_file=settings.log_file, log_format=settings.log_format)
    logger.debug(
        "status called bind=%s port=%s",
        settings.effective_bind_address(),
        settings.port,
    )
    cache = CacheStore(settings.resolved_cache_path)
    token = load_token(settings)
    meta = cache.get_cache_meta()
    click.echo("Advisory RSS status")
    click.echo("------------------")
    click.echo(f"RSS URL:        {settings.rss_url()}")
    click.echo(f"Bind address:   {settings.effective_bind_address()}:{settings.port}")
    click.echo(f"Cache path:     {settings.resolved_cache_path}")
    click.echo(f"Cached advisories: {meta.advisories_count}")
    # Per-source breakdown
    try:
        all_adv = cache.load_all()
        github_c = sum(
            1 for a in all_adv if (getattr(a, "source", "github") or "github") == "github"
        )
        cert_c = sum(1 for a in all_adv if getattr(a, "source", "") == "cert-tr")
        click.echo(f"  - GitHub: {github_c}")
        click.echo(f"  - CERT-TR: {cert_c}")
    except (OSError, ValueError, RuntimeError) as e:
        logger.debug("Failed to load per-source breakdown: %s", e)
    click.echo(f"Last sync:      {meta.last_successful_sync or 'never'}")
    click.echo(f"Next sync:      {meta.next_scheduled_sync or 'not scheduled'}")
    click.echo(f"Rate limited until: {meta.rate_limited_until or 'no'}")
    click.echo(f"Last error:     {meta.last_error or 'none'}")
    click.echo(f"Auth user:      {meta.authenticated_user or 'unknown'}")
    click.echo(f"GitHub token:   {token_preview(token)}")
    click.echo(f"Filter mode:    {settings.filter_mode}")
    click.echo(f"Refresh interval: {settings.refresh_interval}s")
    click.echo(f"Max items (RSS): {settings.max_items}")
    click.echo(f"CERT-TR enabled: {settings.enable_cert_tr}")
    if settings.enable_cert_tr:
        accs = settings.get_cert_tr_accounts()
        click.echo(f"CERT-TR accounts: {len(accs)}")
        for a in accs:
            # Never show password
            prov = a.get("provider", "unknown")
            click.echo(
                f"  - [{prov}] {a['email']} -> folder={a['folder']} host={a['host']}:{a['port']} sec={a['security']}"
            )
        click.echo(f"CERT-TR allowlist: {settings.cert_tr_sender_allowlist}")
        click.echo(
            f"CERT-TR max mails: {settings.cert_tr_max_mails}  search_days: {settings.cert_tr_search_days or 'all'}"
        )
        diag_raw = cache.get_meta("cert_tr_diag")
        if diag_raw:
            click.echo(f"CERT-TR last diag: {diag_raw[:300]}")
    # Also try to infer loopback status
    from advisory_rss.server.bind import is_loopback

    bind_ok = is_loopback(settings.effective_bind_address())
    click.echo(f"Bind is loopback: {bind_ok}")
    if not bind_ok:
        click.echo("WARNING: bind address is NOT loopback - will refuse to start", err=True)
    if not token and not settings.enable_cert_tr:
        click.echo("Hint: set GITHUB_TOKEN in .env or run `app auth login`", err=True)
    elif not token:
        click.echo("Note: GITHUB_TOKEN not set - GitHub source disabled, CERT-TR only", err=True)


# Also support `app auth login` already; add root-level `app login` alias for convenience
@cli.command("login")
def login_alias() -> None:
    """Alias for `app auth login`."""
    auth_login()


if __name__ == "__main__":
    cli()
