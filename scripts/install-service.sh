#!/usr/bin/env bash
# Install (or remove) Advisory-RSS as a systemd *user* service.
#
#   ./scripts/install-service.sh              # install, enable and start
#   ./scripts/install-service.sh --uninstall  # stop, disable and remove
#
# The service starts when the user logs in (WantedBy=default.target).
# To run it before login: loginctl enable-linger "$USER"
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
UNIT_NAME="advisory-rss.service"
TEMPLATE="$PROJECT_DIR/contrib/systemd/advisory-rss.service.in"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT_PATH="$UNIT_DIR/$UNIT_NAME"
VENV_APP="$PROJECT_DIR/.venv/bin/app"

info() { printf '  %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v systemctl >/dev/null 2>&1 || die "systemctl not found - this script needs systemd"
[[ -d "$UNIT_DIR" ]] || mkdir -p "$UNIT_DIR"

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl --user disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH"
    systemctl --user daemon-reload
    systemctl --user reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true
    echo "Removed $UNIT_PATH"
    exit 0
fi

[[ -f "$TEMPLATE" ]] || die "missing unit template: $TEMPLATE"
[[ -x "$VENV_APP" ]] || die "missing $VENV_APP - run: uv sync --extra dev"
if [[ ! -f "$PROJECT_DIR/.env" ]]; then
    echo "warning: $PROJECT_DIR/.env not found - the service will start without credentials" >&2
fi

# Escape sed replacement metacharacters in the project path.
escaped="$PROJECT_DIR"
escaped="${escaped//\\/\\\\}"
escaped="${escaped//&/\\&}"
escaped="${escaped//|/\\|}"

sed -e "s|@PROJECT_DIR@|$escaped|g" "$TEMPLATE" >"$UNIT_PATH"
chmod 0644 "$UNIT_PATH"

systemctl --user daemon-reload
systemctl --user enable --now "$UNIT_NAME"

echo
echo "Installed: $UNIT_PATH"
info "RSS      http://127.0.0.1:8765/rss.xml"
info "Health   http://127.0.0.1:8765/health"
info "Status   systemctl --user status $UNIT_NAME"
info "Journal  journalctl --user -u $UNIT_NAME -f"
info "File log $PROJECT_DIR/cache/serve.log"
info "Remove   $0 --uninstall"
echo
echo "The service starts at login. For boot-before-login: loginctl enable-linger \"$USER\""
