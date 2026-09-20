# Secure storage helpers - Fernet encryption at rest for local credential caches
# Used by cli._upsert_env_file (.env) and auth.gmail._save_oauth_file
# Provides 0600 + 0700 directory hardening and optional encryption via cryptography.

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default key location - next to cache dir, 0600, gitignored via cache/ already ignored
DEFAULT_KEY_PATH = Path("cache/.advisory_rss.key")


def _get_fernet(key_path: Path | str | None = None):
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.debug("cryptography not available - secure storage will use 0600 only")
        return None

    kp = Path(key_path) if key_path else DEFAULT_KEY_PATH
    try:
        if kp.exists():
            raw = kp.read_bytes().strip()
            if raw:
                try:
                    return Fernet(raw)
                except (ValueError, TypeError) as e:
                    logger.debug("Invalid Fernet key at %s: %s - regenerating", kp, e)
        # Generate new key
        key = Fernet.generate_key()
        # Ensure parent 0700
        kp.parent.mkdir(parents=True, exist_ok=True)
        try:
            if "cache" in kp.parent.parts or kp.parent.name == "cache":
                try:
                    os.chmod(kp.parent, 0o700)
                except OSError:
                    pass
        except OSError:
            pass
        # Atomic 0600 write
        fd = None
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(dir=str(kp.parent), prefix=f".{kp.name}.tmp.")
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                fd = None
                f.write(key.decode("utf-8"))
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            Path(tmp_path).replace(kp)
            try:
                kp.chmod(0o600)
            except OSError:
                pass
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except OSError:
                    pass
        return Fernet(key)
    except (OSError, ValueError, ImportError) as e:
        logger.debug("Failed to init Fernet at %s: %s", kp, e)
        return None


def encrypt_value(value: str, key_path: Path | str | None = None) -> str:
    if not value or not isinstance(value, str):
        return value
    f = _get_fernet(key_path)
    if f is None:
        return value
    try:
        token = f.encrypt(value.encode("utf-8")).decode("utf-8")
        return f"enc:{token}"
    except Exception as e:  # noqa: BLE001 - encrypt may raise cryptography-specific
        logger.debug("Encrypt failed: %s", e)
        return value


def decrypt_value(value: str | None, key_path: Path | str | None = None) -> str | None:
    if not value or not isinstance(value, str):
        return value
    if not value.startswith("enc:"):
        # Also handle raw Fernet token without prefix (starts with gAAAA)
        if not value.startswith("gAAAA"):
            return value
        # treat as raw token
        token = value
    else:
        token = value[4:]
    f = _get_fernet(key_path)
    if f is None:
        # No fernet - cannot decrypt, return as is (might be plaintext)
        logger.debug("No Fernet available to decrypt value")
        return value
    try:
        raw = f.decrypt(token.encode("utf-8"))
        return raw.decode("utf-8")
    except Exception as e:  # noqa: BLE001
        logger.debug("Decrypt failed: %s", e)
        return value


def encrypt_dict(data: dict[str, Any], key_path: Path | str | None = None) -> str:
    f = _get_fernet(key_path)
    if f is None:
        return json.dumps(data, indent=2, ensure_ascii=False)
    try:
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        token = f.encrypt(raw).decode("utf-8")
        envelope = {"_encrypted": True, "payload": token}
        return json.dumps(envelope, indent=2, ensure_ascii=False)
    except Exception as e:  # noqa: BLE001
        logger.debug("Dict encrypt failed: %s", e)
        return json.dumps(data, indent=2, ensure_ascii=False)


def decrypt_dict_text(text: str, key_path: Path | str | None = None) -> dict[str, Any] | None:
    #Try to decrypt envelope produced by encrypt_dict. Returns dict or None if not encrypted
    if not text or not text.strip():
        return None
    try:
        obj = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict) or not obj.get("_encrypted"):
        return None
    token = obj.get("payload")
    if not isinstance(token, str) or not token:
        return None
    f = _get_fernet(key_path)
    if f is None:
        return None
    try:
        raw = f.decrypt(token.encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except Exception as e:  # noqa: BLE001
        logger.debug("Dict decrypt failed: %s", e)
        return None


def secure_write_text(path: Path | str, content: str, key_path: Path | str | None = None) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Harden parent
    try:
        if "cache" in p.parent.parts or p.parent.name == "cache":
            try:
                os.chmod(p.parent, 0o700)
            except OSError as e:
                logger.debug("chmod parent failed for %s: %s", p.parent, e)
    except OSError:
        pass

    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.tmp.")
        try:
            os.fchmod(fd, 0o600)
        except OSError as e:
            logger.debug("fchmod failed for %s: %s", tmp_path, e)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None
            f.write(content)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError as se:
                logger.debug("fsync failed for %s: %s", tmp_path, se)
        Path(tmp_path).replace(p)
        try:
            p.chmod(0o600)
        except OSError as e:
            logger.debug("chmod failed for %s: %s", p, e)
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
