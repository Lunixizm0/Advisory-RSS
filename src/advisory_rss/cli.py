from __future__ import annotations

import asyncio
import getpass
import logging
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click

from advisory_rss import __version__
from advisory_rss.auth.pat import load_token, token_preview
from advisory_rss.cache.store import CacheStore
from advisory_rss.config.settings import get_settings
from advisory_rss.github.client import AuthError, GitHubClient, RateLimitError

TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)")


def _redact(s: str) -> str:
    return TOKEN_RE.sub("***", s)


def configure_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    # Ensure token never appears via custom filter
    class RedactFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if isinstance(record.msg, str):
                record.msg = _redact(record.msg)
            if record.args:
                try:
                    # redact args if strings
                    new_args = []
                    for a in record.args: 
                        if isinstance(a, str):
                            new_args.append(_redact(a))
                        else:
                            new_args.append(a)
                    record.args = tuple(new_args)  
                except Exception:  
                    pass
            return True

    for h in logging.getLogger().handlers:
        h.addFilter(RedactFilter())


@click.group()
@click.version_option(__version__)
def cli() -> None:
    pass


@cli.group()
def auth() -> None:
    pass


@auth.command("login")
def auth_login() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    click.echo(
        "GitHub PAT: fine-grained 'Repository security advisories: Read' is recommended."
    )
    click.echo("Token must be set in .env as GITHUB_TOKEN - credentials file is no longer used.")
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
    except Exception as e:  
        click.echo(f"- Validation error: {_redact(str(e))}", err=True)
        sys.exit(1)

    click.echo("")
    click.echo("Token is VALID but NOT saved to disk by this command.")
    click.echo("Set it in .env:")
    click.echo("  echo 'GITHUB_TOKEN=YOUR_TOKEN_HERE' >> .env")
    click.echo("  # or edit .env: GITHUB_TOKEN=github_pat_... / ghp_...")
    click.echo("Then: app sync && app serve")
    click.echo("Never commit .env (gitignored).")


@auth.command("status")
def auth_status() -> None:
    _status()


@cli.command()
def sync() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    token = load_token(settings)
    if not token:
        click.echo("No token set. Set GITHUB_TOKEN in .env or run `app auth login`.", err=True)
        sys.exit(1)

    cache = CacheStore(settings.resolved_cache_path)

    async def _run() -> int:
        client = GitHubClient(settings, token, cache=cache)
        try:
            advs, diag = await client.sync_all(filter_mode=settings.filter_mode)
            count = cache.upsert_advisories(advs)
            cache.mark_success(user=diag.get("authenticated_login"))
            nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
            cache.set_meta("next_scheduled_sync", nxt)
            click.echo(
                f"Sync OK - {count} advisories upserted (filtered {diag.get('filtered_count')} from {diag.get('raw_count')} raw, {diag.get('repos_scanned')} repos, {diag.get('orgs_scanned')} orgs)"
            )
            if diag.get("errors"):
                click.echo(f"Warnings ({len(diag['errors'])}):", err=True)
                for e in diag["errors"][:5]:
                    click.echo(f"  - {_redact(e)}", err=True)
            if advs:
                click.echo(f"Latest: {advs[0].ghsa_id} - {advs[0].summary[:80]}")
            else:
                click.echo(
                    "No advisories matched filter - cache remains empty. Check FILTER_MODE or author login."
                )
            return count
        except AuthError as e:
            click.echo(f"Auth error (401): {_redact(str(e))}", err=True)
            cache.mark_error(_redact(str(e)))
            sys.exit(1)
        except RateLimitError as e:
            click.echo(
                f"Rate limited - retry after {e.retry_after}: {_redact(str(e))}",
                err=True,
            )
            if e.retry_after:
                cache.set_meta(
                    "rate_limited_until",
                    (datetime.now(UTC) + timedelta(seconds=e.retry_after)).isoformat(),
                )
            cache.mark_error(_redact(str(e)))
            sys.exit(1)
        except Exception as e:  
            click.echo(f"Sync failed: {_redact(str(e))}", err=True)
            cache.mark_error(_redact(str(e)))
            sys.exit(1)
        finally:
            await client.close()

    asyncio.run(_run())


def _daemonize(pid_file: str | None = None, log_file: str | None = None) -> None:
    import os as _os

    # Flush std
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:  
        pass

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
    except Exception:  
        pass

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
        lf = open(log_path, "a", buffering=1, encoding="utf-8") 
        # Also keep fd open via file object — avoid GC closing
        _os.dup2(lf.fileno(), sys.stdout.fileno())
        _os.dup2(lf.fileno(), sys.stderr.fileno())
        # stdin -> /dev/null
        with open(os.devnull, "r", encoding="utf-8") as dn:
            _os.dup2(dn.fileno(), sys.stdin.fileno())
    except Exception:  
        # Fallback to /dev/null
        try:
            with open(os.devnull, "w", encoding="utf-8") as dn:
                _os.dup2(dn.fileno(), sys.stdout.fileno())
                _os.dup2(dn.fileno(), sys.stderr.fileno())
        except Exception:  
            pass

    # Write pid file
    if pid_file:
        try:
            Path(pid_file).parent.mkdir(parents=True, exist_ok=True)
            Path(pid_file).write_text(str(_os.getpid()), encoding="utf-8")
        except Exception as e:  
            click.echo(f"Warning: could not write pid file {pid_file}: {e}", err=True)


@cli.command()
@click.option("--daemon", "-d", is_flag=True, help="Run in background — survives terminal close (daemonize, setsid, pid/log in cache/)")
@click.option("--pid-file", default="cache/advisory-rss.pid", show_default=True, help="PID file when --daemon")
@click.option("--log-file", default="cache/serve.log", show_default=True, help="Log file when --daemon (stdout/stderr)")
def serve(daemon: bool = False, pid_file: str = "cache/advisory-rss.pid", log_file: str = "cache/serve.log") -> None:  
    settings = get_settings()
    configure_logging(settings.log_level)
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
    else:
        click.echo(f"GitHub authentication: set ({token_preview(token)})")
        authenticated_user = cache.get_meta("authenticated_user")
        if authenticated_user:
            click.echo(f"Authenticated user: @{authenticated_user}")

    # Verify listening socket note
    click.echo(
        f"Verify binding:  ss -tlnp | grep {port}   (expect {bind}:{port}, never 0.0.0.0:{port})"
    )
    click.echo(
        f"Filter mode: {settings.filter_mode}  Refresh: {settings.refresh_interval}s  Max items: {settings.max_items}"
    )

    if daemon:
        # Check stale pid
        pf = Path(pid_file)
        if pf.exists():
            try:
                pid = int(pf.read_text(encoding="utf-8").strip())
                os.kill(pid, 0)
                click.echo(f"Already running (pid {pid} from {pf}), abort. Use `app stop` first.", err=True)
                sys.exit(1)
            except (OSError, ValueError, ProcessLookupError):
                try:
                    pf.unlink(missing_ok=True)
                except Exception:  
                    pass
        click.echo(f"Daemonizing → pid: {pid_file}, log: {log_file} (terminal kapanınca da yaşar, nohup/setsid)")
        _daemonize(pid_file, log_file)
        # Child continues; stdout/stderr now goes to log file

    # Import uvicorn late
    import uvicorn  

    from advisory_rss.server.app import background_refresh_loop, create_app

    app = create_app(settings=settings, cache=cache)

    @app.on_event("startup")
    async def _startup() -> None:  
        # Mark next sync time
        nxt = (datetime.now(UTC) + timedelta(seconds=settings.refresh_interval)).isoformat()
        if not cache.get_meta("next_scheduled_sync"):
            cache.set_meta("next_scheduled_sync", nxt)
        # Fire background task
        app.state.bg_task = asyncio.create_task(background_refresh_loop(settings, cache))
        logger = logging.getLogger("advisory_rss")
        logger.info("Background refresh scheduled every %ds", settings.refresh_interval)

    @app.on_event("shutdown")
    async def _shutdown() -> None:  
        task = getattr(app.state, "bg_task", None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    config = uvicorn.Config(
        app,
        host=bind,
        port=port,
        log_level=settings.log_level.lower(),
        access_log=True,
        loop="auto",
    )
    server = uvicorn.Server(config)
    try:
        server.run()
    except SystemExit:
        raise
    except KeyboardInterrupt:
        click.echo("\nShutting down…")


@cli.command()
@click.option("--pid-file", default="cache/advisory-rss.pid", show_default=True, help="PID file of daemon")
def stop(pid_file: str = "cache/advisory-rss.pid") -> None:
    pf = Path(pid_file)
    if not pf.exists():
        click.echo(f"No pid file {pf} — not running ?", err=True)
        sys.exit(1)
    try:
        pid = int(pf.read_text(encoding="utf-8").strip())
    except Exception as e:  
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
        except Exception:  
            pass
        click.echo("Stopped and cleaned pid file.")
    except ProcessLookupError:
        click.echo(f"Process {pid} not found — cleaning stale pid file {pf}")
        try:
            pf.unlink(missing_ok=True)
        except Exception:  
            pass
    except PermissionError as e:
        click.echo(f"Permission denied killing {pid}: {e}", err=True)
        sys.exit(1)


@cli.command()
def status() -> None:
    _status()


def _status() -> None:
    settings = get_settings()
    cache = CacheStore(settings.resolved_cache_path)
    token = load_token(settings)
    meta = cache.get_cache_meta()
    click.echo("Advisory RSS status")
    click.echo("------------------")
    click.echo(f"RSS URL:        {settings.rss_url()}")
    click.echo(f"Bind address:   {settings.effective_bind_address()}:{settings.port}")
    click.echo(f"Cache path:     {settings.resolved_cache_path}")
    click.echo(f"Cached advisories: {meta.advisories_count}")
    click.echo(f"Last sync:      {meta.last_successful_sync or 'never'}")
    click.echo(f"Next sync:      {meta.next_scheduled_sync or 'not scheduled'}")
    click.echo(f"Rate limited until: {meta.rate_limited_until or 'no'}")
    click.echo(f"Last error:     {meta.last_error or 'none'}")
    click.echo(f"Auth user:      {meta.authenticated_user or 'unknown'}")
    click.echo(f"GitHub token:   {token_preview(token)}")
    click.echo(f"Filter mode:    {settings.filter_mode}")
    click.echo(f"Refresh interval: {settings.refresh_interval}s")
    click.echo(f"Max items (RSS): {settings.max_items}")
    # Also try to infer loopback status
    from advisory_rss.server.bind import is_loopback

    bind_ok = is_loopback(settings.effective_bind_address())
    click.echo(f"Bind is loopback: {bind_ok}")
    if not bind_ok:
        click.echo("WARNING: bind address is NOT loopback - will refuse to start", err=True)
    if not token:
        click.echo("Hint: set GITHUB_TOKEN in .env or run `app auth login`", err=True)


# Also support `app auth login` already; add root-level `app login` alias for convenience
@cli.command("login")
def login_alias() -> None:
    """Alias for `app auth login`."""
    auth_login()


if __name__ == "__main__":
    cli()
