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

    site = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "site-a";
      description = "Optional site label surfaced in /hub/hosts.";
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
