from __future__ import annotations

import json
import logging
import re
import sys
import traceback
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from advisory_rss.config.constants import (
    LOG_BACKUP_COUNT,
    LOG_MAX_BYTES,
    TOKEN_REDACT_PATTERN,
)

_TOKEN_RE = re.compile(TOKEN_REDACT_PATTERN)

logger = logging.getLogger(__name__)


def _redact(s: str) -> str:
    return _TOKEN_RE.sub("***", s)


class RedactFilter(logging.Filter):
    """Redact GitHub tokens from every log record field."""

    def filter(self, record: logging.LogRecord) -> bool:
        # msg
        if isinstance(record.msg, str):
            record.msg = _redact(record.msg)
        # args - tuple may contain strings; also handle dict-style %()s
        if record.args:
            try:
                if isinstance(record.args, dict):
                    redacted: dict[Any, Any] = {}
                    for k, v in record.args.items():
                        redacted[k] = _redact(v) if isinstance(v, str) else v
                    record.args = redacted  # type: ignore[assignment]
                else:
                    new_args: list[Any] = []
                    for a in record.args:  # type: ignore[union-attr]
                        if isinstance(a, str):
                            new_args.append(_redact(a))
                        else:
                            new_args.append(a)
                    record.args = tuple(new_args)
            except (AttributeError, TypeError, ValueError, RuntimeError):
                # Never break logging on redact failure
                pass

        # exc_info - format traceback, redact, store as exc_text, wipe exc_info to avoid leak via unredacted formatting
        if record.exc_info and record.exc_info[1] is not None:
            try:
                exc_text = "".join(traceback.format_exception(*record.exc_info))
                exc_text = _redact(exc_text)
                # Preserve original exc_text if already present append, else set
                if record.exc_text:
                    record.exc_text = _redact(str(record.exc_text)) + "\n" + exc_text
                else:
                    record.exc_text = exc_text
                # Clear exc_info so handler won't re-format unredacted version
                record.exc_info = None  # type: ignore[assignment]
            except (AttributeError, TypeError, ValueError, RuntimeError):
                record.exc_info = None  # type: ignore[assignment]

        if record.exc_text and isinstance(record.exc_text, str):
            record.exc_text = _redact(record.exc_text)

        if record.stack_info and isinstance(record.stack_info, str):
            record.stack_info = _redact(record.stack_info)

        return True


def _utc_time(*_args: Any) -> Any:
    return datetime.now(UTC).timetuple()


class UTCFormatter(logging.Formatter):
    converter = staticmethod(_utc_time)  # type: ignore[assignment]

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=UTC)
        if datefmt:
            s = dt.strftime(datefmt)
        else:
            s = dt.isoformat().replace("+00:00", "Z")
        return s


class JsonFormatter(logging.Formatter):
    converter = staticmethod(_utc_time)  # type: ignore[assignment]

    def format(self, record: logging.LogRecord) -> str:
        # Ensure message formatting happens before redaction (filter already did)
        try:
            msg = record.getMessage()
        except (ValueError, TypeError):
            msg = str(record.msg)

        # Base payload
        dt = datetime.fromtimestamp(record.created, tz=UTC)
        payload: dict[str, Any] = {
            "timestamp": dt.isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": _redact(msg),
        }
        # Include extras (anything not in standard LogRecord attrs)
        standard = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
            "asctime",
        }
        extras: dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k not in standard and not k.startswith("_"):
                try:
                    # Redact string extras
                    if isinstance(v, str):
                        extras[k] = _redact(v)
                    else:
                        extras[k] = v
                except (AttributeError, TypeError, ValueError, RuntimeError) as e:
                    logger.debug("Redact extra %s failed: %s", k, e)
                    extras[k] = str(v)
        if extras:
            payload["extra"] = extras

        if record.exc_text:
            payload["exc"] = _redact(str(record.exc_text))
        # Also handle stack_info
        if record.stack_info:
            payload["stack"] = _redact(str(record.stack_info))

        # Caller info for debug
        if record.levelno <= logging.DEBUG:
            payload["caller"] = f"{record.filename}:{record.lineno} {record.funcName}"

        try:
            return json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            # Fallback
            payload["message"] = _redact(str(payload.get("message", "")))
            return json.dumps({k: str(v) for k, v in payload.items()}, ensure_ascii=False)


# Global state to make setup idempotent
_configured = False
_configured_level: str | None = None
_configured_format: str | None = None
_configured_log_file: str | None = None


def _is_already_configured(level: str, log_file: str | None, log_format: str) -> bool:
    return (
        _configured
        and _configured_level == level.upper()
        and _configured_format == log_format
        and _configured_log_file == (log_file or "")
    )


def setup_logging(
    level: str = "INFO",
    *,
    log_file: str | None = None,
    log_format: str = "text",
    force: bool = False,
    use_stderr: bool = True,
) -> None:
    """Configure root + advisory_rss loggers.

    Args:
        level: DEBUG|INFO|WARNING|ERROR|CRITICAL (case-insensitive).
               Invalid value falls back to INFO with a warning.
        log_file: path to rotating file (e.g. cache/serve.log). If None/empty, only StreamHandler.
        log_format: "text" or "json"
        force: reconfigure even if already configured with same params
        use_stderr: if False, don't add StreamHandler (useful after daemon dup2 to avoid duplicate file writes)
    """
    global _configured, _configured_level, _configured_format, _configured_log_file

    lvl_str = (level or "INFO").upper()
    lvl = getattr(logging, lvl_str, None)
    if not isinstance(lvl, int):
        # Warn once via print to stderr (logger not yet configured)
        print(f"Invalid LOG_LEVEL {level!r} - falling back to INFO", file=sys.stderr)
        lvl_str = "INFO"
        lvl = logging.INFO

    fmt_str = (log_format or "text").lower()
    if fmt_str not in ("text", "json"):
        print(f"Invalid LOG_FORMAT {log_format!r} - falling back to text", file=sys.stderr)
        fmt_str = "text"

    # Normalize log_file empty string -> None
    normalized_log_file = (log_file or "").strip() or None

    if not force and _is_already_configured(lvl_str, normalized_log_file, fmt_str):
        return

    root = logging.getLogger()

    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Handler close failed: %s", e)

    # Choose formatter
    if fmt_str == "json":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = UTCFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )

    redact_filter = RedactFilter()

    # StreamHandler to stderr (so stdout can be used for CLI output)
    if use_stderr:
        stream_handler = logging.StreamHandler(stream=sys.stderr)
        stream_handler.setFormatter(formatter)
        stream_handler.addFilter(redact_filter)
        root.addHandler(stream_handler)

    # Optional rotating file
    if normalized_log_file:
        try:
            p = Path(normalized_log_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                str(p),
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            file_handler.addFilter(redact_filter)
            root.addHandler(file_handler)
        except (OSError, ValueError, RuntimeError) as e:
            # Don't crash on file handler failure; keep stream handler
            print(f"Failed to setup file logging {normalized_log_file}: {e}", file=sys.stderr)

    root.setLevel(lvl)

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers = []  # let them propagate to root (or keep but filtered)
        lg.propagate = True

    # Httpx noise suppression: WARNING unless root is DEBUG
    httpx_level = logging.DEBUG if lvl <= logging.DEBUG else logging.WARNING
    for name in ("httpx", "httpcore"):
        lg = logging.getLogger(name)
        lg.setLevel(httpx_level)
        # Don't add handler; propagate to root
        lg.propagate = True

    # Mark configured
    _configured = True
    _configured_level = lvl_str
    _configured_format = fmt_str
    _configured_log_file = normalized_log_file or ""

def get_uvicorn_log_config(level: str = "INFO") -> dict[str, Any]:
    lvl = (level or "INFO").upper()
    if lvl not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        lvl = "INFO"
    # Uvicorn expects lower-case for its own, but dictConfig uses upper
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {"redact": {"()": RedactFilter}},
        "formatters": {
            "default": {
                "()": UTCFormatter,
                "fmt": "%(asctime)s %(levelname)s %(name)s: %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%SZ",
            },
            "access": {
                "()": UTCFormatter,
                "fmt": '%(asctime)s %(levelname)s %(name)s: %(client_addr)s - "%(request_line)s" %(status_code)s',
                "datefmt": "%Y-%m-%dT%H:%M:%SZ",
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["redact"],
                "stream": "ext://sys.stderr",
            },
            "access": {
                "class": "logging.StreamHandler",
                "formatter": "access",
                "filters": ["redact"],
                "stream": "ext://sys.stderr",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": lvl, "propagate": False},
            "uvicorn.error": {"handlers": ["default"], "level": lvl, "propagate": False},
            "uvicorn.access": {"handlers": ["access"], "level": lvl, "propagate": False},
        },
    }


def reset_logging_for_tests() -> None:
    """Helper to reset global configured flag between tests."""
    global _configured, _configured_level, _configured_format, _configured_log_file
    _configured = False
    _configured_level = None
    _configured_format = None
    _configured_log_file = None
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
        try:
            h.close()
        except (OSError, ValueError, RuntimeError) as e:
            logger.debug("Handler close failed in reset: %s", e)
