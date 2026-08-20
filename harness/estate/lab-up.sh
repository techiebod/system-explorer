#!/usr/bin/env bash
# Stand the rewrite up on two lab guests and leave it running, so a
# person can open it.
#
# The gates are judged by suites; this exists for the thing a suite
# cannot do. A page can pass every assertion in conformance and still be
# unreadable, and the only way to find that out is to look at it.
#
#   ./harness/estate/lab-up.sh            # both guests, hub on the second
#   ./harness/estate/lab-up.sh down       # stop everything, leave guests up
#
# Assumes test/vm-lab guests are already running. It creates nothing and
# destroys nothing: bringing guests up or down is vm-lab's job and the
# owner's decision.
set -Eeuo pipefail

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB="${REPO}/test/vm-lab"
SSH_CONFIG="${LAB}/.state/ssh_config"
# No default, deliberately: this repository is public and a hypervisor's
# name is one estate's topology. vm-lab reads the same variable.
VM_HOST="${VM_LAB_VM_HOST:?set VM_LAB_VM_HOST to your KVM host, as vm-lab wants}"
GUEST_A="${SE_LAB_GUEST_A:-se-test-debian}"
GUEST_B="${SE_LAB_GUEST_B:-se-test-ubuntu2604}"
HOST_A="${SE_LAB_HOST_A:-lab-a}"
HOST_B="${SE_LAB_HOST_B:-lab-b}"
SESSION_PORT=9600
HTTP_PORT=9601
COLLATOR_PORT=8095

say() { printf '[lab-up] %s\n' "$*" >&2; }
on()  { ssh -F "${SSH_CONFIG}" -o BatchMode=yes "$1" "${@:2}"; }

if [[ "${1:-up}" == "down" ]]; then
  for guest in "${GUEST_A}" "${GUEST_B}"; do
    say "stopping on ${guest}"
    on "${guest}" 'pkill -f lab-serve.py || true; pkill -f se-collate || true' || true
  done
  say "stopped. The guests are still up; use vm-lab down to destroy them."
  exit 0
fi

[[ -r "${SSH_CONFIG}" ]] || { say "no ${SSH_CONFIG}; is the lab up?"; exit 1; }

say "building linux/amd64 binaries"
STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT
( cd "${REPO}/go"
  for cmd in se-collate se-collect-system se-collect-nix; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "${STAGE}/${cmd}" "./cmd/${cmd}"
  done )

# The hub is stdlib-only, so a guest needs no dependencies at all.
mkdir -p "${STAGE}/sehub"
cp "${REPO}"/src/system_explorer/hub/{checkpoint,session,rollup,intent,answer,listener,federation,resolution,lifecycle,routes,http,mqtt,mcp_surface}.py "${STAGE}/sehub/"
mkdir -p "${STAGE}/sehub/surface"
cp "${REPO}"/src/system_explorer/surface/{__init__,render}.py "${STAGE}/sehub/surface/"
cp "${REPO}/src/system_explorer/surface/tokens.css" "${STAGE}/sehub/surface/"
printf '"""The rewrite hub, as a guest runs it."""\n' > "${STAGE}/sehub/__init__.py"
# render.py imports ..surface; on a guest the package is flat, so the
# import is rewritten here rather than the module being made aware of a
# deployment shape it should not know about.
sed -i.bak 's/^from \.\.surface import render$/from .surface import render/' "${STAGE}/sehub/http.py"
rm -f "${STAGE}/sehub/http.py.bak"
cp "${REPO}/harness/estate/lab-serve.py" "${STAGE}/"

cat > "${STAGE}/intent.json" <<JSON
{
  "schema": "se.intent/1",
  "estate": "lab",
  "revision": 1,
  "reviewed": "2026-08-20",
  "estate_hub": "site-a",
  "membership": {"hosts": {"${HOST_A}": {"roles": ["host"]}, "${HOST_B}": {"roles": ["host"]}}}
}
JSON

for guest in "${GUEST_A}" "${GUEST_B}"; do
  say "shipping to ${guest}"
  on "${guest}" 'rm -rf ~/se-lab && mkdir -p ~/se-lab'
  scp -F "${SSH_CONFIG}" -q -r "${STAGE}/." "${guest}:se-lab/"
  on "${guest}" 'chmod +x ~/se-lab/se-collate ~/se-lab/se-collect-* ~/se-lab/lab-serve.py'
done

# NixOS-only collector: on a guest that is not NixOS it would decline on
# every sweep, which is honest but noisy for someone looking at a page.
on "${GUEST_A}" 'grep -qi nixos /etc/os-release || rm -f ~/se-lab/se-collect-nix'
on "${GUEST_B}" 'grep -qi nixos /etc/os-release || rm -f ~/se-lab/se-collect-nix'

say "starting the hub on ${GUEST_B}"
on "${GUEST_B}" "cd ~/se-lab && setsid nohup python3 lab-serve.py hub ${SESSION_PORT} ${HTTP_PORT} > ~/se-lab/hub.log 2>&1 < /dev/null & sleep 1"

IP_B="$(on "${GUEST_B}" "hostname -I | awk '{print \$1}'" | tr -d '\r')"
IP_A="$(on "${GUEST_A}" "hostname -I | awk '{print \$1}'" | tr -d '\r')"

for pair in "${GUEST_A}:${HOST_A}" "${GUEST_B}:${HOST_B}"; do
  guest="${pair%%:*}"; host="${pair##*:}"
  say "starting the collator on ${guest} as ${host}"
  on "${guest}" "cd ~/se-lab && setsid nohup python3 lab-serve.py collator ${host} ${IP_B}:${SESSION_PORT} 0.0.0.0:${COLLATOR_PORT} > ~/se-lab/collator.log 2>&1 < /dev/null & sleep 1"
done

say "waiting for the first checkpoint"
sleep 6
on "${GUEST_B}" 'tail -n 4 ~/se-lab/hub.log' || true

cat <<TXT

── open it ────────────────────────────────────────────────────────────
One tunnel through the hypervisor gives you all three pages:

  ssh -N \\
    -L 8080:${IP_B}:${HTTP_PORT} \\
    -L 8081:${IP_B}:${COLLATOR_PORT} \\
    -L 8082:${IP_A}:${COLLATOR_PORT} \\
    ${VM_HOST}

Then, in a browser:

  http://127.0.0.1:8080/   the ESTATE page   — both hosts, reach, coverage
  http://127.0.0.1:8081/   ${HOST_B}'s own page
  http://127.0.0.1:8082/   ${HOST_A}'s own page

Worth doing while you are in there, because each shows something a test
can only assert:

  · Stop the hub  (ssh ${GUEST_B} 'pkill -f "lab-serve.py hub"')  and
    reload 8081. The host page still answers. That is the founding
    invariant — aggregation is never a precondition for observation.
  · Reload 8080 after that and watch the hosts go DARK rather than the
    page going blank or green.
  · curl http://127.0.0.1:8080/v1/routes  — every tool MCP would expose.

  ./harness/estate/lab-up.sh down   stops the processes, leaves the guests
── ────────────────────────────────────────────────────────────────────
TXT
