#!/usr/bin/env bash
# Install the skeleton stack — se-collate + the socket-activated system
# collector, under system-explorer.slice — on a disposable guest, the way a
# stranger with a tarball would, and leave it running under systemd.
#
# This exercises the non-Nix install path for the units in
# packaging/systemd/ (the NixOS spelling of the same units is
# nix/skeleton-module.nix). The lab's contract ends at "a booted guest with
# ssh and passwordless sudo"; this script owns everything after that.
#
# Usage:
#   test/skeleton-on-guest.sh <ssh-destination> <ssh-config> <bindir>
#
#   <bindir> must already hold se-collate and se-collect-system built for
#   the guest (GOOS=linux GOARCH=amd64 CGO_ENABLED=0). Building is not this
#   script's job: the same prebuilt pair should be installable on every
#   guest, and a script that rebuilds per guest can silently test two
#   different binaries.
#
# Idempotent by construction: every step either overwrites its previous
# result or is a no-op the second time, and the service is RESTARTED, not
# `enable --now`-ed — `--now` does nothing to a running unit, which once
# left deleted code running and cost two false diagnoses (see
# install-on-guest.sh, same lesson).
set -euo pipefail

DEST="${1:?ssh destination (host or alias)}"
SSH_CONFIG="${2:?path to an ssh config}"
BINDIR="${3:?directory holding prebuilt se-collate and se-collect-system}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_DIR="${REPO_ROOT}/packaging/systemd"

# What ships. Enumerated here, not globbed: a glob would happily ship a
# partial set and the install would fail three layers down on the guest,
# or worse, not fail — a socket without its template activates nothing.
BINARIES=(se-collate se-collect-system)
UNITS=(system-explorer.slice se-collate.service
       se-collect-system.socket se-collect-system@.service)
FRAGMENTS=(system-explorer-skeleton.sysusers.conf
           system-explorer-skeleton.tmpfiles.conf)

# Refuse a missing or wrong-platform binary HERE, where the message names
# the actual problem. The deploy target is linux/amd64 ELF; a Mach-O
# binary from a `go build` without GOOS=linux would ship, install, enable
# — and then fail as "exec format error" inside a per-connection unit,
# which reads like a protocol bug. Deny-by-default: exactly the ELF magic
# passes, everything else is refused.
for bin in "${BINARIES[@]}"; do
  path="${BINDIR}/${bin}"
  [ -f "${path}" ] || { echo "missing binary: ${path}" >&2; exit 2; }
  magic="$(head -c 4 "${path}" | od -An -tx1 | tr -d ' \n')"
  if [ "${magic}" != "7f454c46" ]; then
    echo "refusing ${path}: not an ELF binary (magic ${magic})." >&2
    echo "Build with: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build" >&2
    exit 2
  fi
done
for unit in "${UNITS[@]}" "${FRAGMENTS[@]}"; do
  [ -f "${UNIT_DIR}/${unit}" ] || { echo "missing unit source: ${UNIT_DIR}/${unit}" >&2; exit 2; }
done

STAGE=/tmp/se-skeleton-stage

echo "==> ${DEST}: staging binaries and units"
ssh -F "${SSH_CONFIG}" "${DEST}" "rm -rf ${STAGE} && mkdir -p ${STAGE}"
scp -q -F "${SSH_CONFIG}" \
  "${BINDIR}/se-collate" "${BINDIR}/se-collect-system" \
  "${UNIT_DIR}/system-explorer.slice" \
  "${UNIT_DIR}/se-collate.service" \
  "${UNIT_DIR}/se-collect-system.socket" \
  "${UNIT_DIR}/se-collect-system@.service" \
  "${UNIT_DIR}/system-explorer-skeleton.sysusers.conf" \
  "${UNIT_DIR}/system-explorer-skeleton.tmpfiles.conf" \
  "${DEST}:${STAGE}/"

ssh -F "${SSH_CONFIG}" "${DEST}" 'bash -s' <<'REMOTE'
set -euo pipefail
STAGE=/tmp/se-skeleton-stage

echo "==> user and socket directory (sysusers + tmpfiles)"
# -D: stock images ship without /etc/sysusers.d — the directory is admin
# droppings, created by whoever drops the first fragment.
sudo -n install -D -m 0644 "${STAGE}/system-explorer-skeleton.sysusers.conf" \
  /etc/sysusers.d/system-explorer-skeleton.conf
sudo -n install -D -m 0644 "${STAGE}/system-explorer-skeleton.tmpfiles.conf" \
  /etc/tmpfiles.d/system-explorer-skeleton.conf
sudo -n systemd-sysusers
# tmpfiles exits 65 when unrelated lines elsewhere fail; scoping to our one
# fragment keeps this step's exit code about our one directory.
sudo -n systemd-tmpfiles --create /etc/tmpfiles.d/system-explorer-skeleton.conf

echo "==> binaries into /opt/system-explorer-skeleton/bin"
# tmp + mv, not install-in-place: overwriting a running binary is ETXTBSY;
# rename swaps the inode and the running process keeps the old one.
sudo -n mkdir -p /opt/system-explorer-skeleton/bin
for bin in se-collate se-collect-system; do
  sudo -n install -m 0755 "${STAGE}/${bin}" "/opt/system-explorer-skeleton/bin/.${bin}.new"
  sudo -n mv -f "/opt/system-explorer-skeleton/bin/.${bin}.new" \
    "/opt/system-explorer-skeleton/bin/${bin}"
done

echo "==> units into /etc/systemd/system"
for unit in system-explorer.slice se-collate.service \
            se-collect-system.socket se-collect-system@.service; do
  sudo -n install -m 0644 "${STAGE}/${unit}" "/etc/systemd/system/${unit}"
done

echo "==> systemd-analyze verify"
# Read-only static check before anything restarts: a typo'd directive is a
# journal warning at runtime but a named failure here. Verify loads the
# whole dependency graph, so it runs after the files land and would catch a
# socket whose template is missing. set -e makes a failed verify abort the
# install rather than start broken units.
sudo -n systemd-analyze verify \
  /etc/systemd/system/system-explorer.slice \
  /etc/systemd/system/se-collate.service \
  /etc/systemd/system/se-collect-system.socket \
  /etc/systemd/system/se-collect-system@.service

echo "==> enable + restart"
# Fingerprint of what is already applied, taken BEFORE the restart. The
# collator acquires on start and a fresh acquisition always takes a new
# generation (DESIGN 19), so a working install MUST move these — while a
# broken one leaves the durable store's prior state answering. A bare "is
# anything there" check mistook exactly that for green when a deliberately
# broken collector was redeployed over a good store (seen live 2026-08-18);
# the generation is the fact that discriminates this install from the last
# one. Field order (name, then generation) is Go encoding/json struct
# order — a language guarantee, which is what makes the grep stable.
prev_gens="$(curl -sf -m 2 http://127.0.0.1:8095/v1/collections \
  | grep -o '"name":"[^"]*","generation":[0-9]*' | sort || true)"
sudo -n systemctl daemon-reload
sudo -n systemctl enable se-collect-system.socket se-collate.service >/dev/null 2>&1
# Socket first, then the collator: the collator dials on start, and a
# restart of both in this order means its first acquisition finds the new
# socket rather than burning the one-minute no-declaration retry.
sudo -n systemctl restart se-collect-system.socket
sudo -n systemctl restart se-collate.service

echo "==> waiting for the first acquisition"
# Gate on the deliverable — a committed collection, with objects, at a
# generation this restart produced — not on /v1/health. Health answers the
# moment the listener is up, which is BEFORE the first acquisition commits
# (each socket exchange took ~1s on a systemd 259 guest), and gating on it
# printed "[]" and "unknown collection" as a green install: emptiness
# reported as success, observed live 2026-08-18. The window is bounded and
# running out of it is a red install, with the collator's journal as the
# diagnosis, never a shrug.
applied=""
for _ in $(seq 1 30); do
  body="$(curl -sf -m 2 http://127.0.0.1:8095/v1/collections || true)"
  gens="$(printf %s "${body}" \
    | grep -o '"name":"[^"]*","generation":[0-9]*' | sort || true)"
  if [ -n "${gens}" ] && [ "${gens}" != "${prev_gens}" ] \
      && printf %s "${body}" | grep -q '"object_count":[1-9]'; then
    applied=yes; break
  fi
  sleep 1
done
if [ -z "${applied}" ]; then
  echo "no NEW generation applied within 30s: prior state answering is not a green install" >&2
  sudo -n journalctl -u se-collate.service --no-pager -n 20 >&2 || true
  exit 1
fi

echo "==> GET /v1/health"
curl -sS -m 5 http://127.0.0.1:8095/v1/health
echo "==> GET /v1/collections"
curl -sS -m 5 http://127.0.0.1:8095/v1/collections
echo "==> GET /v1/collections/identity/objects"
curl -sS -m 5 http://127.0.0.1:8095/v1/collections/identity/objects

echo "==> slice accounting (the envelope, measured by the kernel)"
systemctl show system-explorer.slice -p MemoryCurrent -p CPUUsageNSec

rm -rf "${STAGE}"
REMOTE
echo "==> ${DEST}: done"
