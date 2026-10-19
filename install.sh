#!/usr/bin/env bash
#
# Gilgamesh installer — Raspberry Pi 4 on Raspberry Pi OS / Debian 13 (trixie), aarch64.
#
# What it does, in order:
#   1. creates the two service accounts (systemd-sysusers)
#   2. copies the application to the install prefix and builds its virtualenv with uv
#   3. writes /etc/gilgamesh/gilgamesh.env — only when it does not exist yet, so local
#      edits survive an upgrade
#   4. installs the systemd units, the journald caps and (if Suricata is present) the
#      Suricata drop-in
#   5. enables the units and (re)starts the web UI and the sensor
#
# It is idempotent and non-interactive: re-running it *is* the upgrade path. It does not
# install OS packages, never touches the network configuration, and never changes the
# capture interface — creating the bridge is a separate documented step. The only
# network access is uv resolving the locked Python dependencies.
#
# Usage:
#   sudo ./install.sh                install or upgrade
#   sudo ./install.sh --offline      build from the uv cache / vendor/wheels, no network
#   sudo ./install.sh --no-start     install everything, touch no running services
#   sudo ./install.sh --prefix DIR   install somewhere other than /opt/gilgamesh
#
set -euo pipefail

PREFIX=/opt/gilgamesh
OFFLINE=0
START=1
SRC_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

usage() {
	sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
	exit 0
}

while (($# > 0)); do
	case "$1" in
	--prefix)
		(($# >= 2)) || die "--prefix needs a directory"
		PREFIX=$2
		shift 2
		;;
	--offline)
		OFFLINE=1
		shift
		;;
	--no-start)
		START=0
		shift
		;;
	-h | --help) usage ;;
	*) die "unknown argument: $1 (try --help)" ;;
	esac
done

[[ $EUID -eq 0 ]] || die "run me as root: sudo $0"
[[ -f $SRC_DIR/pyproject.toml ]] || die "run me from the Gilgamesh checkout (no pyproject.toml in $SRC_DIR)"
[[ -d /run/systemd/system ]] || die "systemd is required; this is the supported install path"
case "$PREFIX" in
/*) ;;
*) die "--prefix must be an absolute path" ;;
esac

# uv may have been installed for root rather than for the invoking user.
for candidate in /usr/local/bin/uv /root/.local/bin/uv "${HOME:-/root}/.local/bin/uv"; do
	if [[ -x $candidate ]]; then
		PATH="$(dirname -- "$candidate"):$PATH"
		break
	fi
done
command -v uv >/dev/null 2>&1 || die \
	"uv is not installed for root. Install it first (https://docs.astral.sh/uv/getting-started/installation/)
     and run this script again — Gilgamesh manages Python with uv only."

# ---------------------------------------------------------------------------
# 1. Service accounts
# ---------------------------------------------------------------------------
# `u!` creates fully locked accounts; the membership edge (sensor -> gilgamesh group) is
# how the sensor writes into the web user's state directory. See the file's own comments.
log "creating service accounts"
install -m 0644 "$SRC_DIR/deploy/sysusers.d/gilgamesh.conf" /etc/sysusers.d/gilgamesh.conf
systemd-sysusers /etc/sysusers.d/gilgamesh.conf >/dev/null

# ---------------------------------------------------------------------------
# 2. Application code and virtualenv
# ---------------------------------------------------------------------------
log "installing the application into $PREFIX"
install -d -m 0755 "$PREFIX" /etc/gilgamesh
# The shared database directory: owned by the web user, group-readable/writable by the
# sensor. systemd's StateDirectory= also maintains it, but it must exist before the
# sensor's ReadWritePaths= is resolved at start-up.
install -d -m 0770 -o gilgamesh -g gilgamesh /var/lib/gilgamesh

# Copy the checkout, excluding development scratch. The lockfile and .python-version go
# along, so the build is the same one CI and the developer machine used.
tar -C "$SRC_DIR" \
	--exclude=./.git \
	--exclude=./.venv \
	--exclude=./.superpowers \
	--exclude=./.ruff_cache \
	--exclude=./.pytest_cache \
	--exclude=./docs/audit-screenshots \
	--exclude='__pycache__' \
	--exclude='*.pyc' \
	-cf - . | tar -C "$PREFIX" -xf -

log "building the virtualenv (uv sync --frozen --no-dev)"
uv_args=(sync --frozen --no-dev --directory "$PREFIX")
if ((OFFLINE)); then
	uv_args+=(--offline)
	if [[ -d $PREFIX/vendor/wheels ]]; then
		uv_args+=(--find-links "$PREFIX/vendor/wheels")
	else
		warn "no $PREFIX/vendor/wheels: offline builds need a warm uv cache"
	fi
fi
uv "${uv_args[@]}"

# The services run as two unprivileged users; whatever root's umask was, they must be
# able to read and execute the interpreter and the installed packages.
chmod -R a+rX "$PREFIX/.venv"

# ---------------------------------------------------------------------------
# 3. Environment file
# ---------------------------------------------------------------------------
ENV_FILE=/etc/gilgamesh/gilgamesh.env
if [[ -e $ENV_FILE ]]; then
	log "$ENV_FILE exists — leaving it untouched"
else
	log "writing $ENV_FILE"
	install -m 0640 -o root -g gilgamesh "$SRC_DIR/deploy/gilgamesh.env.example" "$ENV_FILE"
fi

# ---------------------------------------------------------------------------
# 4. systemd units
# ---------------------------------------------------------------------------
# The unit files name /opt/gilgamesh in ExecStart= and WorkingDirectory=; a custom
# --prefix is substituted on the way in so the shipped files stay readable.
log "installing systemd units"
for unit in "$SRC_DIR"/deploy/systemd/*.service "$SRC_DIR"/deploy/systemd/*.timer; do
	sed "s#/opt/gilgamesh#$PREFIX#g" "$unit" >"/etc/systemd/system/$(basename -- "$unit")"
	chmod 0644 "/etc/systemd/system/$(basename -- "$unit")"
done

journald_conf=/etc/systemd/journald.conf.d/10-gilgamesh.conf
journald_changed=0
if ! cmp -s "$SRC_DIR/deploy/journald/10-gilgamesh.conf" "$journald_conf"; then
	install -D -m 0644 "$SRC_DIR/deploy/journald/10-gilgamesh.conf" "$journald_conf"
	journald_changed=1
fi

if systemctl list-unit-files --no-legend suricata.service 2>/dev/null | grep -q '^suricata\.service'; then
	install -D -m 0644 "$SRC_DIR/deploy/suricata/10-gilgamesh.conf" \
		/etc/systemd/system/suricata.service.d/10-gilgamesh.conf
else
	log "Suricata is not installed — skipping its drop-in (install Suricata, then re-run)"
fi

systemctl daemon-reload
if ((journald_changed)); then
	systemctl restart systemd-journald
fi

# ---------------------------------------------------------------------------
# 5. Services
# ---------------------------------------------------------------------------
if ((START)); then
	log "enabling units"
	systemctl enable gilgamesh-web.service gilgamesh-sensor.service >/dev/null
	systemctl enable --now gilgamesh-rules-update.timer >/dev/null

	log "starting the web UI and the sensor"
	restarted=1
	systemctl restart gilgamesh-web.service || restarted=0
	systemctl restart gilgamesh-sensor.service || restarted=0
	if ((restarted == 0)); then
		warn "a service failed to start — check 'journalctl -u gilgamesh-sensor -n 30'."
		warn "the usual cause is GILGAMESH_INTERFACE in $ENV_FILE naming an interface that does not exist yet."
	fi
fi

# ---------------------------------------------------------------------------
# 6. What to do next
# ---------------------------------------------------------------------------
interface=$(sed -n 's/^GILGAMESH_INTERFACE=\(.*\)$/\1/p' "$ENV_FILE" | tail -n 1)
if [[ -n ${interface:-} ]] && command -v ip >/dev/null 2>&1 && ! ip link show dev "$interface" >/dev/null 2>&1; then
	warn "capture interface '$interface' does not exist on this machine yet."
	warn "interfaces present:"
	ip -br link show | awk '{printf "    %s\n", $1}' >&2
	warn "create the bridge as documented, then: sudo systemctl restart gilgamesh-sensor"
fi

cat <<EOF

Gilgamesh is installed.

  Open the UI     http://<this-pi-address>:8080   (the first visit shows the setup wizard)
  Setup token     journalctl -u gilgamesh-web | grep 'setup token'
  Logs            journalctl -u gilgamesh-web -u gilgamesh-sensor -f
  Configuration   $ENV_FILE
  Upgrade         sudo $SRC_DIR/install.sh
  Uninstall       see the README ("Uninstalling" section)

EOF
