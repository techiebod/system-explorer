#!/usr/bin/env bash
# Install the agent on a non-NixOS host the way a stranger would, and leave it
# running under systemd.
#
# This is the documented install path (README: "Outside Nix it is an ordinary
# Python distribution") actually exercised, on the disposable guests of
# test/vm-lab. It deliberately lives here and not in the lab: the lab's contract
# ends at "a booted guest with ssh and passwordless sudo", and it does not know
# how this package is built or installed.
#
# Distro packages for the dependencies, a venv with --system-site-packages for
# the wheel. That combination is the one the portability work measured: every
# runtime dependency is packaged on all six targets, so nothing is vendored and
# pip resolves nothing from the network.
#
# Usage:
#   SE_SSH_OPTS="-F test/vm-lab/.state/ssh_config" \
#     install-on-guest.sh se-test-debian dist/system_explorer-0.4.0-py3-none-any.whl
#
# ssh options go in SE_SSH_OPTS rather than being parsed out of the destination:
# the first version tried to split them apart with awk and broke on the very
# first call, for no benefit.
set -euo pipefail

DEST="${1:?ssh destination (host or alias)}"
WHEEL="${2:?path to a system_explorer wheel}"
BIND="${3:-0.0.0.0}"
# shellcheck disable=SC2206  # deliberately word-split into an array
SSH_OPTS=(${SE_SSH_OPTS:-})

# 0.0.0.0 by default because the point is to browse these from a workstation.
# Safe here and nowhere else: these guests hold nothing, sit on an isolated NAT
# segment, and are destroyed by `vm-lab reset`. SPEC section 7 is unchanged —
# the network you bind to IS the trust boundary, and this one is disposable.

# A wheel's FILENAME is metadata — name, version, python tag, abi, platform —
# and pip rejects anything that does not parse as those five parts. Copying it
# to a convenient short name has now broken an install twice, so refuse it here
# rather than discover it three layers down inside a venv on a remote host.
WHEEL_NAME="$(basename "${WHEEL}")"
case "${WHEEL_NAME}" in
  *-*-*-*-*.whl) ;;
  *) echo "refusing ${WHEEL_NAME}: a wheel must keep its canonical filename" >&2
     echo "(name-version-pythontag-abitag-platformtag.whl) — pip parses it" >&2
     exit 2 ;;
esac

echo "==> ${DEST}: staging ${WHEEL_NAME}"
scp -q "${SSH_OPTS[@]}" "${WHEEL}" "${DEST}:/tmp/${WHEEL_NAME}"

ssh "${SSH_OPTS[@]}" "${DEST}" 'bash -s' <<REMOTE
set -euo pipefail
. /etc/os-release

echo "==> \${PRETTY_NAME}: dependencies from the distro"
if command -v apt-get >/dev/null; then
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    python3-venv python3-fastapi python3-uvicorn python3-httpx python3-anyio \
    python3-dbus-fast python3-starlette >/dev/null 2>&1 || true
elif command -v dnf >/dev/null; then
  sudo -n dnf install -y -q python3-fastapi python3-uvicorn python3-httpx \
    python3-anyio python3-dbus-fast python3-starlette >/dev/null 2>&1 || true
fi

echo "==> installing into /opt/system-explorer"
sudo -n rm -rf /opt/system-explorer
sudo -n python3 -m venv --system-site-packages /opt/system-explorer
sudo -n /opt/system-explorer/bin/pip install -q --no-deps --no-index "/tmp/${WHEEL_NAME}"
sudo -n /opt/system-explorer/bin/se-agent --version

echo "==> systemd unit"
# A static user via sysusers rather than DynamicUser: Debian does not install
# libnss-systemd, so a dynamic user's name does not resolve (ROADMAP phase 3
# recorded this before it was tried). systemd-journal for the logs adapter.
sudo -n useradd --system --no-create-home --shell /usr/sbin/nologin \
  system-explorer 2>/dev/null || true
sudo -n tee /etc/systemd/system/system-explorer.service >/dev/null <<UNIT
[Unit]
Description=System Explorer host agent (read-only observation API)
After=network.target

[Service]
Type=simple
User=system-explorer
SupplementaryGroups=systemd-journal
ExecStart=/opt/system-explorer/bin/se-agent --host ${BIND} --port 8091
Restart=on-failure
RestartSec=2
# The same posture as nix/module.nix, minus what a non-Nix host cannot assume.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=
StateDirectory=system-explorer
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now system-explorer.service >/dev/null 2>&1

# The host firewall, which the NixOS module handles with openFirewall and a
# non-Nix install has no equivalent for. A real portability finding rather than
# a lab detail: Fedora ships firewalld ENABLED, so the agent answered perfectly
# on loopback and was invisible from the network, while Debian and Ubuntu ship
# nothing enabled and worked immediately. Whatever ships as a .deb or .rpm has to
# say this out loud, because the failure looks like a broken service.
if command -v firewall-cmd >/dev/null && sudo -n firewall-cmd --state >/dev/null 2>&1; then
  echo "==> firewalld: opening 8091/tcp"
  sudo -n firewall-cmd --quiet --permanent --add-port=8091/tcp || true
  sudo -n firewall-cmd --quiet --reload || true
elif command -v ufw >/dev/null && sudo -n ufw status 2>/dev/null | grep -q "^Status: active"; then
  echo "==> ufw: opening 8091/tcp"
  sudo -n ufw allow 8091/tcp >/dev/null || true
fi

sleep 3
sudo -n systemctl is-active system-explorer.service
curl -s -m5 -o /dev/null -w "  health HTTP %{http_code}\n" http://127.0.0.1:8091/health
rm -f "/tmp/${WHEEL_NAME}"
REMOTE
echo "==> ${DEST}: done"
