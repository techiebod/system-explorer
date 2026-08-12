# se-hub — per-site hub service (ROADMAP slice 1). One URL fronting a
# site's agents: proxies GETs verbatim and serves the operator UI. Needs
# nothing but HTTP reach to the agents; stateless by design, so losing it
# loses convenience, never data.
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
