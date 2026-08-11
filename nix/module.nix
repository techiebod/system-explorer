# System Explorer host agent — read-only observation service.
# This is the canonical NixOS module: consumers get it as the flake's
# nixosModules.default, or by importing this file directly. Spec:
# ../docs/SPEC.md (section 7 defines this unit's security posture).
{ config, lib, pkgs, ... }:

let
  cfg = config.services.systemExplorer;
in
{
  options.services.systemExplorer = {
    enable = lib.mkEnableOption "System Explorer host agent";

    package = lib.mkOption {
      type = lib.types.package;
      # python3Packages.callPackage, not pkgs.callPackage: package.nix is a
      # buildPythonApplication and names its dependencies individually.
      default = pkgs.python3Packages.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.python3Packages.callPackage ./package.nix { }";
      description = "System Explorer agent package (bin/se-agent).";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Bind address. The default is loopback; the network you bind to
        becomes the trust boundary, because there is no application
        authentication (SPEC section 7). Widening this is a per-host
        decision and should be justified where it is made.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8091;
      description = "TCP port for the agent API.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the agent port in the NixOS firewall.";
    };

    allowedHosts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "host-a" "host-a.example.internal" "localhost" "127.0.0.1" ];
      description = ''
        Host-header allow-list (DNS-rebinding defence). Must contain every
        name and address clients dial the agent by: the MCP aggregator's
        configured URL host, browser bookmarks, localhost. Requests with any
        other Host header are rejected with 400. Empty list disables the
        check. Ports are ignored in the comparison.
      '';
    };

    enableDockerAdapter = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Grant the agent the docker group so the docker adapter can issue
        read-only Engine API requests. Note the caveat in SPEC section 7:
        docker group membership is root-equivalent on the host; the agent
        only ever issues GET requests by construction.
      '';
    };

    grantNetAdmin = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Grant CAP_NET_ADMIN so the network adapter can read the nftables
        ruleset (and later conntrack). Links, routes and resolver facts need
        no capability; without this only nft-tables reports unavailable.
      '';
    };

    grantDiskAccess = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Run a root SMART collector (fixed smartctl --json invocations on a
        five-minute timer, snapshots under /run/system-explorer-smart) that
        the unprivileged agent reads. This is what surfaces NVMe endurance
        (percentage used), available spare, media errors, and the overall
        verdict: udisks2 has no endurance property, and the kernel demands
        CAP_SYS_ADMIN for the admin ioctls smartctl issues, so group
        membership alone cannot reach them. The agent itself keeps zero
        raw device access; root runs exactly one fixed command per device.
      '';
    };

    grantTailscaleAccess = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Run a root tailscale collector (one fixed `tailscale status --json`
        invocation on a one-minute timer, snapshot under
        /run/system-explorer-tailscale) that the unprivileged agent reads.
        This is what surfaces the node's tailnet identity, key expiry, DERP
        home, and per-peer reachability (direct vs relayed). The agent
        itself never talks to tailscaled and gains no new privilege; root
        runs exactly one fixed command, and the agent reads the snapshot
        and reports its age.
      '';
    };

    hubUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "http://hub.example.internal:8090/";
      description = ''
        Where this host's site view lives, if there is one. Purely a display
        hint: the agent never contacts it, because aggregation must not be a
        precondition for observation — a host reachable by nobody but its
        operator stays fully useful. Set it and the single-host UI offers a
        link to the site; leave it unset and the UI says nothing rather than
        implying this host stands alone.
      '';
    };

    site = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "site-a";
      description = ''
        Name of the site this host belongs to, shown beside the hubUrl link.
        Cosmetic; the hub is authoritative for its own site label.
      '';
    };

    deploymentReceipts = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/example/deployments";
      description = ''
        Directory holding one deployment receipt per system generation, named
        <generation>.json, if the estate's deployment workflow writes them. Read
        only: the agent reports what a receipt says about how a generation came
        to be, and reports a generation that expects one and has none.

        There is deliberately no default. An estate that keeps no receipts must
        not have the agent inventing a path, finding nothing, and then reporting
        the nothing as a deployment that bypassed a workflow which never existed.
        A generation only participates at all if its own closure carries
        se-generation.json saying receipts are expected, so enabling this cannot
        retroactively accuse older generations.

        The directory and the receipts must be readable by an unprivileged
        process: the agent runs under DynamicUser and has no group to grant it.
      '';
    };

    extraPackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = "Extra packages on the agent's PATH (e.g. zfs on ZFS hosts).";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    # SMART/health facts in the hardware subsystem come from udisks2 over
    # D-Bus (the agent deliberately has no raw device access); without the
    # daemon those facts are silently absent, so the agent brings its source.
    services.udisks2.enable = true;

    # SMART depth collector: root runs one fixed smartctl per device on a
    # timer; the agent only ever reads the JSON snapshots. Tried and
    # rejected: disk-group + udev on /dev/ng* — smartctl's admin ioctls
    # need CAP_SYS_ADMIN regardless of file permission (kernel 6.18).
    systemd.services.system-explorer-smart = lib.mkIf cfg.grantDiskAccess {
      description = "System Explorer SMART collector (root smartctl snapshots)";
      path = [ pkgs.smartmontools ];
      serviceConfig = {
        Type = "oneshot";
        RuntimeDirectory = "system-explorer-smart";
        RuntimeDirectoryPreserve = "yes";
        # A hung drive must not wedge the collector forever: oneshot's
        # default start timeout is infinity, and the OnUnitActiveSec timer
        # never refires while the unit is active. SMART exists precisely
        # for the drives that hang.
        TimeoutStartSec = "2min";
      };
      script = ''
        out=/run/system-explorer-smart

        # smartctl emits a well-formed JSON document even when it refuses to
        # run: an invalid argument or an unsupported transport still produces a
        # file carrying nothing but messages[]. A size test cannot tell a
        # reading from a refusal, so `[ -s ]` installed the refusal — and
        # because it ran every five minutes, it overwrote the last good
        # snapshot with a stub. Five raidz1 members read a vouched-for "ok"
        # for days on no measurement at all.
        #
        # smart_status is the object smartctl emits only when it really
        # interrogated the drive, so require it. A sleeping drive left alone
        # by -n standby writes no smart_status either, which is exactly right:
        # the previous snapshot survives and the agent reports its age.
        has_reading() { grep -q '"smart_status"' "$1"; }

        # Why there was no reading, in smartctl's own words — "Device is in
        # STANDBY mode", an unsupported transport, a permission failure. The
        # first version of this guard threw that away, so the agent could only
        # offer the operator a three-way guess (wedged / not installed /
        # asleep) about something the collector already knew. A spun-down bulk
        # disk is normal operation and must not read like a fault.
        install_reason() {
          sed -n 's/.*"string":"\([^"]*\)".*/\1/p' "$1" | head -1 > "$2.tmp" || true
          if [ -s "$2.tmp" ]; then mv "$2.tmp" "$2"; else rm -f "$2.tmp" "$2"; fi
        }

        # A snapshot that itself carries no reading is not a last-known-good
        # one worth protecting; it is residue. Keeping it forever is what made
        # 475-byte refusals from the `-n standby,q` era outlive the fix and go
        # on driving a staleness warning off a file containing only error text.
        install_outcome() {
          tmp="$1"; final="$2"; reason="$3"
          if has_reading "$tmp"; then
            mv "$tmp" "$final"; rm -f "$reason"
          else
            install_reason "$tmp" "$reason"
            if [ -e "$final" ] && ! has_reading "$final"; then rm -f "$final"; fi
            rm -f "$tmp"
          fi
        }

        for ctrl in /sys/class/nvme/nvme*; do
          [ -e "$ctrl" ] || continue
          name=$(basename "$ctrl")
          smartctl --json=c -d nvme -H -A "/dev/$name" > "$out/.$name.tmp" 2>/dev/null || true
          install_outcome "$out/.$name.tmp" "$out/$name.json" "$out/$name.reason"
        done

        # -n standby: never spin up a sleeping drive for a snapshot. It was
        # `-n standby,q` here, which smartctl 7.5 rejects outright —
        # "INVALID ARGUMENT TO -n" — so every sd* snapshot on the estate was
        # 475 bytes of error text. The valid spelling takes an optional exit
        # STATUS, not a "q"; verified live, the fix turns a 475-byte refusal
        # into an 812-byte reading carrying smart_status, temperature and
        # power_on_time.
        for disk in /sys/block/sd*; do
          [ -e "$disk" ] || continue
          name=$(basename "$disk")
          smartctl --json=c -H -A -n standby "/dev/$name" > "$out/.$name.tmp" 2>/dev/null || true
          install_outcome "$out/.$name.tmp" "$out/$name.json" "$out/$name.reason"
        done
      '';
    };
    systemd.timers.system-explorer-smart = lib.mkIf cfg.grantDiskAccess {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = "5min";
      };
    };

    # Tailscale collector: the SMART collector's shape exactly — root runs
    # one fixed `tailscale status --json` on a timer; the agent only ever
    # reads the JSON snapshot and reports its age (SPEC rule 12). tmp+mv on
    # non-empty output, so a failed run preserves the last good snapshot
    # (visible as age) instead of replacing it with an empty file.
    systemd.services.system-explorer-tailscale = lib.mkIf cfg.grantTailscaleAccess {
      description = "System Explorer tailscale collector (root status snapshots)";
      path = [ pkgs.tailscale ];
      serviceConfig = {
        Type = "oneshot";
        RuntimeDirectory = "system-explorer-tailscale";
        RuntimeDirectoryPreserve = "yes";
        # A wedged tailscaled must not wedge the collector forever: oneshot's
        # default start timeout is infinity, and the OnUnitActiveSec timer
        # never refires while the unit is active.
        TimeoutStartSec = "30s";
      };
      script = ''
        out=/run/system-explorer-tailscale
        if tailscale status --json > "$out/.status.tmp" 2>/dev/null; [ -s "$out/.status.tmp" ]; then
          mv "$out/.status.tmp" "$out/status.json"
        fi
      '';
    };
    systemd.timers.system-explorer-tailscale = lib.mkIf cfg.grantTailscaleAccess {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "30s";
        OnUnitActiveSec = "1min";
      };
    };

    systemd.services.system-explorer = {
      description = "System Explorer host agent (read-only observation API)";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      # journalctl, lsblk/lscpu, findmnt, ip, udevadm — structured-output
      # paths only; nft joins under the capability that makes it useful.
      path = [ pkgs.systemd pkgs.util-linux pkgs.iproute2 ]
        ++ lib.optional cfg.grantNetAdmin pkgs.nftables
        ++ cfg.extraPackages;

      environment =
        lib.optionalAttrs (cfg.allowedHosts != [ ]) {
          SE_ALLOWED_HOSTS = lib.concatStringsSep "," cfg.allowedHosts;
        }
        // lib.optionalAttrs (cfg.hubUrl != null) { SE_HUB_URL = cfg.hubUrl; }
        // lib.optionalAttrs (cfg.site != null) { SE_SITE = cfg.site; }
        // lib.optionalAttrs (cfg.deploymentReceipts != null) {
          SE_DEPLOYMENT_RECEIPTS = cfg.deploymentReceipts;
        };

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} --host ${cfg.listenAddress} --port ${toString cfg.port}";
        Restart = "on-failure";
        RestartSec = 2;

        # SPEC section 7: unprivileged by construction.
        DynamicUser = true;
        SupplementaryGroups = [ "systemd-journal" ]
          ++ lib.optional cfg.enableDockerAdapter "docker";
        CapabilityBoundingSet = if cfg.grantNetAdmin then [ "CAP_NET_ADMIN" ] else [ "" ];
        AmbientCapabilities = lib.mkIf cfg.grantNetAdmin [ "CAP_NET_ADMIN" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        StateDirectory = "system-explorer";
        UMask = "0077";
      };
    };
  };
}
