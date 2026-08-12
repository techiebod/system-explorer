# se-hub — per-site hub service (ROADMAP slice 1). One URL fronting a
# site's agents: proxies GETs verbatim and serves the operator UI. Needs
# nothing but HTTP reach to the agents. The only state it keeps is
# metadata in SPEC section 6.1's sense — the findings lifecycle registry
# under its StateDirectory — so losing it loses convenience (first_seen,
# acknowledgements), never an observation and never truth about a host.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.systemExplorerHub;
in
{
  options.services.systemExplorerHub = {
    enable = lib.mkEnableOption "System Explorer per-site hub";

    package = lib.mkOption {
      type = lib.types.package;
      # One distribution, three console scripts (nix/package.nix): the hub
      # proxies HTTP and has no use for libvirt or the MCP SDK.
      default = pkgs.python3Packages.callPackage ./package.nix {
        pname = "system-explorer-hub";
        mainProgram = "se-hub";
        withVms = false;
      };
      defaultText = lib.literalExpression
        "pkgs.python3Packages.callPackage ./package.nix { pname = \"system-explorer-hub\"; mainProgram = \"se-hub\"; withVms = false; }";
      description = "se-hub package (bin/se-hub).";
    };

    agents = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      example = { host-a = "http://localhost:8091"; host-b = "http://host-b.example.internal:8091"; };
      description = "Host agents to front: name → base URL.";
    };

    views = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/etc/system-explorer/views";
      description = ''
        Directory of view documents (SPEC section 6.2) served at /hub/views —
        operator-authored projections of the graph, JSON files matching
        se.views/1's view shape. No default deliberately: views are the
        operator's judgement, and an unset option honestly means none were
        made. Point se-mcp's `views` at the same path for parity.
      '';
    };

    site = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "site-a";
      description = ''
        This site's label. Set it wherever siblings are used: the UI reaches a
        sibling's host through a site-scoped proxy route, so an unnamed site can
        only serve its own agents.
      '';
    };

    siblings = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      example = { site-b = "http://hub-b.example.internal:8090"; };
      description = ''
        Peer hubs, site name → base URL. Naming them turns this address into an
        estate view: one URL reaches every host the operator runs, grouped by
        site, without a central service anywhere.

        Deliberately federation and not centralisation. A site whose siblings
        are unreachable keeps working alone and shows the rest as unreachable,
        because nothing it needs lives at a sibling — an estate-wide hub would
        instead be one box whose loss costs visibility of everything (ROADMAP
        section 6).

        Federation is one hop: a sibling's host is forwarded to that sibling's
        own local route, which cannot forward again, so no wiring mistake can
        build a loop. Each hub still needs its own reachable URL for the others
        — for a multi-site estate that usually means a tailnet address, and the
        far hub's allowedHosts must contain whatever name this one dials it by.
      '';
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Bind address; widening is a per-host decision.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8090;
      description = "TCP port for the hub.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the hub port in the NixOS firewall.";
    };

    allowedHosts = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "hub.example.internal" "localhost" "127.0.0.1" ];
      description = ''
        Host-header allow-list (DNS-rebinding defence, SPEC section 7). Must
        contain every name and address clients dial the hub by. Requests
        with any other Host header are rejected with 400. Empty list
        disables the check. Ports are ignored in the comparison.
      '';
    };

    findingsWrites = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Register the findings transition route (SPEC section 6.3) — the
        product's only write, and a grant in the grantDiskAccess idiom:
        explicit, documented, per-deployment. Off, the hub's route table
        has no write verb at all. The posture caveat lives here because the
        grant does: until authentication exists, an enabled route trusts
        the network the hub is bound to, so enable it only behind loopback
        or a tailnet bind, never on a LAN the operator does not control. A
        transition is appended and attributed, never a deletion, and
        acknowledgement styles a finding without ever removing it from any
        roll-up.
      '';
    };

    findingsSweepSeconds = lib.mkOption {
      type = lib.types.numbers.positive;
      default = 60;
      description = ''
        How often the hub's background task sweeps every agent's
        /v1/findings into the registry. The read side serves the latest
        completed sweep instantly with its swept_at stamped — the founding
        rule's "last-known-good belongs with findings": staleness lives
        where it is honest, on records that carry their own timestamps,
        never on observations served as current.
      '';
    };

    findingsRetentionDays = lib.mkOption {
      type = lib.types.numbers.positive;
      default = 90;
      description = ''
        How long a finding's lifecycle record (first_seen and its
        acknowledgement history) outlives the finding's last sighting.
        Reappearance within this window is the same finding recurring;
        beyond it, the record and its transitions age out together — but
        only where the estate could look. A frozen finding (unswept host,
        unobserved collection) is never pruned on the strength of absence
        nobody observed. Longer than snapshot retention deliberately:
        these records are tiny and their value is forensic.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Caught at build time because the failure is otherwise a puzzle: the UI
    # would reach every local host fine and 404 on every sibling's, since the
    # site-scoped proxy route has no site to match against.
    assertions = [{
      assertion = cfg.siblings == { } || cfg.site != null;
      message = "services.systemExplorerHub.siblings needs services."
                + "systemExplorerHub.site set — a hub with no site label cannot"
                + " serve a sibling's hosts, only its own.";
    }];

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.system-explorer-hub = {
      description = "System Explorer per-site hub (read-only proxy + UI)";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        SE_HUB_AGENTS = lib.concatStringsSep ","
          (lib.mapAttrsToList (name: url: "${name}=${url}") cfg.agents);
        SE_HUB_FINDINGS_RETENTION_DAYS = toString cfg.findingsRetentionDays;
        SE_HUB_FINDINGS_SWEEP_SECONDS = toString cfg.findingsSweepSeconds;
      } // lib.optionalAttrs cfg.findingsWrites {
        SE_HUB_FINDINGS_WRITES = "1";
      } // lib.optionalAttrs (cfg.site != null) {
        SE_HUB_SITE = cfg.site;
      } // lib.optionalAttrs (cfg.views != null) {
        # Interpolation imports a path literal into the store WITH context,
        # so the directory joins the closure and exists on the target.
        # toString handed the BUILD host's raw source path to a machine
        # that never had it, and /hub/views answered an honest-looking
        # empty list from a directory that was not there (first estate
        # deploy, 2026-08-12). A string-typed runtime path interpolates
        # to itself, which is also right.
        SE_HUB_VIEWS = "${cfg.views}";
      } // lib.optionalAttrs (cfg.siblings != { }) {
        SE_HUB_SIBLINGS = lib.concatStringsSep ","
          (lib.mapAttrsToList (name: url: "${name}=${url}") cfg.siblings);
      } // lib.optionalAttrs (cfg.allowedHosts != [ ]) {
        SE_HUB_ALLOWED_HOSTS = lib.concatStringsSep "," cfg.allowedHosts;
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe cfg.package} --host ${cfg.listenAddress} --port ${toString cfg.port}";
        Restart = "on-failure";
        RestartSec = 2;

        # The findings lifecycle registry (SPEC section 6.3) — the agent
        # history arrangement. Always present: the registry is useful with
        # writes off (first_seen and last_seen need no grant), and a later
        # findingsWrites=true must not orphan lifecycle already accrued.
        StateDirectory = "se-hub";

        # Pure HTTP client/server: same posture as the mcp module — no
        # journal group, no capabilities, no netlink.
        DynamicUser = true;
        CapabilityBoundingSet = [ "" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        UMask = "0077";
      };
    };
  };
}
