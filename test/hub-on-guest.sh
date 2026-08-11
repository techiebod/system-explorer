#!/usr/bin/env bash
# Run se-hub on a non-NixOS guest, fronting the whole lab.
# Deliberately on a GUEST rather than on silo: the hub deployable had only ever
# run on NixOS, so this is the first time it is exercised anywhere else.
set -euo pipefail
DEST="${1:?ssh destination}"; AGENTS="${2:?name=url,name=url}"
# shellcheck disable=SC2206
SSH_OPTS=(${SE_SSH_OPTS:-})
ssh "${SSH_OPTS[@]}" "${DEST}" 'bash -s' <<REMOTE
set -euo pipefail
sudo -n tee /etc/systemd/system/system-explorer-hub.service >/dev/null <<UNIT
[Unit]
Description=System Explorer lab hub (read-only proxy + UI)
After=network.target

[Service]
Type=simple
User=system-explorer
Environment=SE_HUB_SITE=lab
Environment=SE_HUB_AGENTS=${AGENTS}
ExecStart=/opt/system-explorer/bin/se-hub --host 0.0.0.0 --port 8090
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now system-explorer-hub.service >/dev/null 2>&1
if command -v firewall-cmd >/dev/null && sudo -n firewall-cmd --state >/dev/null 2>&1; then
  sudo -n firewall-cmd --quiet --permanent --add-port=8090/tcp || true
  sudo -n firewall-cmd --quiet --reload || true
fi
sleep 3
sudo -n systemctl is-active system-explorer-hub
curl -s -m6 -o /dev/null -w "  hub health HTTP %{http_code}\n" http://127.0.0.1:8090/health
REMOTE
