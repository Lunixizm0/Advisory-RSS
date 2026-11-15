"""CLI sync exit codes for explicitly requested sources."""

from unittest.mock import MagicMock

from click.testing import CliRunner

from advisory_rss import cli as cli_module
from advisory_rss.config.settings import Settings


def test_sync_cert_tr_disabled_exits_nonzero(monkeypatch, tmp_path):
    settings = Settings(
        _env_file=None,
        enable_cert_tr=False,
        cache_path=str(tmp_path / "cli.db"),
    )
    monkeypatch.setattr(cli_module, "get_settings", lambda: settings)
    monkeypatch.setattr(cli_module, "CacheStore", lambda *a, **k: MagicMock())

    result = CliRunner().invoke(cli_module.sync, ["--source", "cert-tr"])

    assert result.exit_code == 1
    assert "CERT-TR disabled" in result.stderr
