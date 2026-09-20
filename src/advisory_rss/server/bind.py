import ipaddress
import logging

logger = logging.getLogger(__name__)


def is_loopback(addr: str | None) -> bool:
    if not addr or not isinstance(addr, str):
        return False
    raw = addr.strip().strip("[]").strip()
    if not raw:
        return False
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return ip.is_loopback


def assert_loopback(addr: str) -> None:
    if not is_loopback(addr):
        logger.error("BIND_ADDRESS=%r is not loopback - refusing to start", addr)
        raise SystemExit(
            f"FATAL: BIND_ADDRESS={addr!r} is not loopback. "
            f"Refusing to start - this service must bind only to 127.0.0.1 or ::1. "
            f"See README 'Verifying localhost-only binding'. "
            f"Do NOT change 127.0.0.1 to 0.0.0.0 unless you redesign the security model."
        )
    logger.debug("bind address %r validated as loopback", addr)


# Also expose helper for validation in settings
def validate_bind_address(addr: str) -> str:
    assert_loopback(addr)
    return addr.strip().strip("[]")
