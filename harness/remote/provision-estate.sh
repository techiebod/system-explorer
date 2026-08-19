#!/usr/bin/env bash
# The venues that are not containers: unbound's control socket, kea's, and the
# protection manifest.
#
# Runs ON the guest, shipped as a FILE. Appends to the receipts file that
# provision-apps.sh writes, so run that one first.
#
# STATED COVERAGE: this makes three collectors reach their positive path. It
# does NOT settle what any of them should do when the receipt is missing —
# unbound declining `absent` while unbound is installed and running is the
# open class-1 question, and provisioning it here removes the symptom from
# this host without answering it.
set -euo pipefail

RECEIPTS=/tmp/se-lab/receipts.env
PAYLOADS=/tmp/se-lab/protection-payloads

mkdir -p /tmp/se-lab
touch "$RECEIPTS"

say() { printf '  %s\n' "$*" >&2; }
emit() { printf 'export %s=%s\n' "$1" "$2" >>"$RECEIPTS"; }

# Drop any prior line for this name before re-emitting, so a re-run replaces a
# receipt rather than appending a second one that a later `source` would win.
forget() { sed -i "/^export $1=/d" "$RECEIPTS"; }

# ---------------------------------------------------------------- zfs pool
# The storage collector's venue, and specifically the one shape the reference
# has lost on three times: a pool carrying a mirror AND a spare, where the
# group-vdev blindness was found after four layers had agreed it was fine.
# File-backed vdevs, because the collector reads the POOL and this guest has
# one disk.
#
# The vdev files live under /var/tmp and not /tmp deliberately: /tmp is cleared
# on boot, so a pool built there would come back after every guest restart as a
# set of missing devices rather than as an importable pool.
if ! command -v zpool >/dev/null 2>&1; then
    say "installing zfsutils-linux"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q zfsutils-linux \
        >/dev/null 2>&1 || say "zfs install failed"
fi
if command -v zpool >/dev/null 2>&1; then
    VDEVS=/var/tmp/vdevs
    sudo mkdir -p "$VDEVS"
    if sudo zpool list tank >/dev/null 2>&1; then
        say "tank already imported"
    elif sudo zpool import -d "$VDEVS" tank >/dev/null 2>&1; then
        # The ordinary state after a guest reboot, and the step this script did
        # not used to take: the pool exists on disk and nothing imported it.
        say "tank imported from $VDEVS"
    else
        for disk in d1 d2 d3; do
            [ -f "$VDEVS/$disk" ] || sudo truncate -s 512M "$VDEVS/$disk"
        done
        sudo zpool create -f tank \
            mirror "$VDEVS/d1" "$VDEVS/d2" \
            spare "$VDEVS/d3" \
            && say "tank created: one mirror, one spare"
    fi
    # Without the pool in the cache nothing imports it at boot, so every guest
    # restart silently loses the storage venue and the collector reads a host
    # with no pools — a truthful reading of a broken lab, and indistinguishable
    # from a deliberate absence variant.
    #
    # Do NOT verify this by reading the property back: `zpool get cachefile`
    # answers `-` on success, because `-` MEANS the default location and the
    # default is the path set here. The signal is the cache file itself naming
    # the pool, which is what is checked.
    sudo zpool set cachefile=/etc/zfs/zpool.cache tank
    if sudo grep -qa tank /etc/zfs/zpool.cache 2>/dev/null; then
        say "tank is in the boot cache ($(systemctl is-enabled zfs-import-cache.service 2>&1))"
    else
        say "tank is NOT in /etc/zfs/zpool.cache — it will not survive a reboot"
    fi
    say "tank: $(sudo zpool list -H -o health tank)"
fi

# ---------------------------------------------------------------- unbound
# A unix control socket, not the TCP interface: over TCP unbound-control wants
# a key pair, and the adapter connects to a socket path.
if command -v unbound >/dev/null 2>&1; then
    sudo mkdir -p /etc/unbound/unbound.conf.d
    sudo tee /etc/unbound/unbound.conf.d/se-lab-control.conf >/dev/null <<'CONF'
# Lab only. Written by harness/remote/provision-estate.sh so the unbound
# collector has a control socket to read; not a configuration to copy.
remote-control:
    control-enable: yes
    control-interface: /run/unbound.ctl
CONF
    sudo systemctl restart unbound || say "unbound restart failed"
    for _ in $(seq 20); do
        [ -S /run/unbound.ctl ] && break
        sleep 1
    done
    if [ -S /run/unbound.ctl ]; then
        # Connectable, not merely present: the adapter distinguishes a missing
        # socket from one that refuses, and so should the receipt.
        if sudo unbound-control -s /run/unbound.ctl status >/dev/null 2>&1; then
            forget SE_UNBOUND_SOCKET
            emit SE_UNBOUND_SOCKET /run/unbound.ctl
            say "unbound control socket answered"
        else
            say "unbound.ctl exists but did not answer status — receipt omitted"
        fi
    else
        say "no /run/unbound.ctl appeared — receipt omitted"
    fi
else
    say "unbound is not installed — receipt omitted"
fi

# ---------------------------------------------------------------- kea
if ! command -v kea-dhcp4 >/dev/null 2>&1; then
    say "installing kea-dhcp4-server"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q kea-dhcp4-server \
        >/dev/null 2>&1 || say "kea install failed"
fi
if command -v kea-dhcp4 >/dev/null 2>&1; then
    sudo mkdir -p /run/kea /var/lib/kea
    # lease4-get-all lives in the lease_cmds hook, which Ubuntu ships but does
    # not load. Without it the reference raises and loses ALL FOUR collections
    # while the port declines `leases: unsupported` and serves the other three
    # — measured here on 2026-08-19, and a kea with no hooks is an ordinary
    # kea rather than a broken one. Loaded here so the readings can be
    # compared; the disagreement about the unhooked case is recorded in
    # docs/PARITY-REPORT.md and is not repaired by this line.
    HOOK=$(\ls /usr/lib/*/kea/hooks/libdhcp_lease_cmds.so 2>/dev/null | head -1)
    if [ -n "$HOOK" ]; then
        HOOKS="\"hooks-libraries\": [ { \"library\": \"$HOOK\" } ],"
    else
        HOOKS=""
        say "no libdhcp_lease_cmds.so — kea leases will decline unsupported"
    fi
    # A minimal but real server: one subnet, one reservation, one pool, so the
    # subnets and reservations collections have something to report. The
    # interface is deliberately none — this must never answer DHCP on the lab
    # network, only hold a control socket.
    sudo tee /etc/kea/kea-dhcp4.conf >/dev/null <<CONF
{
"Dhcp4": {
    "interfaces-config": { "interfaces": [ ] },
    $HOOKS
    "control-socket": {
        "socket-type": "unix",
        "socket-name": "/run/kea/kea4-ctrl-socket"
    },
    "lease-database": {
        "type": "memfile",
        "persist": true,
        "name": "/var/lib/kea/kea-leases4.csv"
    },
    "valid-lifetime": 3600,
    "subnet4": [
        {
            "id": 1,
            "subnet": "192.0.2.0/24",
            "pools": [ { "pool": "192.0.2.100 - 192.0.2.200" } ],
            "reservations": [
                {
                    "hw-address": "02:00:00:00:00:01",
                    "ip-address": "192.0.2.50",
                    "hostname": "lab-reserved"
                }
            ]
        }
    ],
    "loggers": [ {
        "name": "kea-dhcp4",
        "severity": "ERROR",
        "output_options": [ { "output": "stdout" } ]
    } ]
}
}
CONF
    sudo systemctl restart kea-dhcp4-server || say "kea restart failed"
    # Tested through sudo, deliberately. /run/kea is 0750 owned by _kea, so a
    # bare `[ -S ... ]` as the login user cannot stat inside it and returns
    # false for a socket that is present and working — reporting "not there"
    # for "could not look", which is the one confusion this whole repository
    # exists to prevent. It cost a run here on 2026-08-19.
    for _ in $(seq 20); do
        sudo test -S /run/kea/kea4-ctrl-socket && break
        sleep 1
    done
    if sudo test -S /run/kea/kea4-ctrl-socket; then
        forget SE_KEA_SOCKET
        emit SE_KEA_SOCKET /run/kea/kea4-ctrl-socket
        say "kea control socket present"
        # Leases planted through kea's own lease4-add, which ships in the same
        # hook as lease4-get-all — so a guest that can be READ for leases can
        # be staged with them, and no file is edited behind the daemon's back.
        # The set is chosen to reach every fact the leases collection declares:
        # all three State words, a lease with no Hostname, and an infinite
        # valid lifetime, which is the one that renders ExpiresAt as `never`.
        # Addresses are RFC 5737 documentation space and the MACs are
        # locally-administered, because this corpus is published.
        sudo python3 - <<'PLANT' || say "planting leases failed"
import json, socket, sys

LEASES = [
    # ip, mac, hostname, valid-lft, state
    ("192.0.2.100", "02:00:00:00:00:10", "lab-alpha", 3600, 0),
    ("192.0.2.101", "02:00:00:00:00:11", "lab-beta", 4294967295, 0),
    ("192.0.2.102", "02:00:00:00:00:12", None, 1800, 1),
    ("192.0.2.103", "02:00:00:00:00:13", "lab-delta", 900, 2),
]


def call(command, arguments=None):
    """One command on kea-dhcp4's own socket.

    No `service` member and a list-or-dict reply, matching se-capture-guest's
    client: `service` is the Control Agent's framing and this talks to the
    daemon directly, which answers with a bare object.
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect("/run/kea/kea4-ctrl-socket")
    body = {"command": command}
    if arguments:
        body["arguments"] = arguments
    sock.sendall(json.dumps(body).encode())
    sock.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    sock.close()
    answer = json.loads(b"".join(chunks))
    return answer[0] if isinstance(answer, list) else answer


planted = 0
for ip, mac, host, lifetime, state in LEASES:
    args = {"ip-address": ip, "hw-address": mac, "subnet-id": 1,
            "valid-lft": lifetime, "state": state}
    if host:
        args["hostname"] = host
    answer = call("lease4-add", args)
    if answer.get("result") != 0:
        # kea answers result 1 for a duplicate, the same code it uses for a
        # real rejection, so the add cannot be made idempotent by reading the
        # code alone. Updating unconditionally after a failed add is what
        # makes a re-run converge on the same table rather than on whatever
        # the previous run happened to leave.
        answer = call("lease4-update", args)
    if answer.get("result") == 0:
        planted += 1
    else:
        print(f"  lease4-add/update {ip}: {answer.get('text')}", file=sys.stderr)

back = call("lease4-get-all", {"subnets": [1]})
count = len((back.get("arguments") or {}).get("leases") or [])
print(f"  planted {planted} leases, daemon reports {count}", file=sys.stderr)
# Read back, not assumed: a plant nobody confirmed is how a capture of an
# empty table gets committed as coverage of a full one.
if count == 0:
    raise SystemExit("kea reports no leases after planting")
PLANT
    elif sudo test -e /run/kea; then
        say "kea is up but no control socket appeared — receipt omitted"
    else
        say "no /run/kea at all — receipt omitted"
    fi
fi

# ---------------------------------------------------------------- protection
# Not a service: three documents at fixed paths. The bytes come from the
# committed corpus, whose provenance is `authored` — an estate that was read
# once for its SHAPES and whose content is fiction. Installing them here is
# what gives the port a positive path to be compared on; it asserts nothing
# about this guest, which protects nothing.
if [ -d "$PAYLOADS" ]; then
    # Cleared, not merged. A receipt the staging no longer produces must not
    # survive from a previous run: copying over the top leaves it in place and
    # the next comparison reads a job state nothing staged.
    sudo rm -rf /var/lib/homelab/protection/receipts
    sudo mkdir -p /etc/homelab /var/lib/homelab/protection/receipts
    sudo cp "$PAYLOADS/manifest.json" /etc/homelab/protection-manifest.json
    sudo cp "$PAYLOADS/status.json" /var/lib/homelab/protection/status.json
    if compgen -G "$PAYLOADS/receipts/*" >/dev/null; then
        sudo cp "$PAYLOADS"/receipts/* /var/lib/homelab/protection/receipts/
    fi
    say "protection documents installed: $(sudo \ls /var/lib/homelab/protection/receipts | wc -l) receipts"
else
    say "no protection payloads staged at $PAYLOADS — skipped"
fi

say "receipts now:"
sed 's/=.*/=<set>/' "$RECEIPTS" >&2
