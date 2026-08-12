# se-mcp — MCP aggregator service. Runs beside (or apart from) the host
# agents and needs nothing but HTTP reach to them; authentication is the
# deployment's edge concern, so front it with an authenticated edge rather
# than publishing it bare (SPEC section 7).
{ config, lib, pkgs, ... }:

let
  cfg = config.services.systemExplorerMcp;
in
{
  options.services.systemExplorerMcp = {
    enable = lib.mkEnableOption "System Explorer MCP aggregator";

    package = lib.mkOption {
      type = lib.types.package;
      # One distribution, three console scripts (nix/package.nix): the
      # aggregator needs the MCP SDK and has no use for libvirt.
      default = pkgs.python3Packages.callPackage ./package.nix {
        pname = "system-explorer-mcp";
        mainProgram = "se-mcp";
        withVms = false;
        withMcp = true;
      };
      defaultText = lib.literalExpression
        "pkgs.python3Packages.callPackage ./package.nix { pname = \"system-explorer-mcp\"; mainProgram = \"se-mcp\"; withVms = false; withMcp = true; }";
      description = "se-mcp package (bin/se-mcp).";
    };

    views = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/etc/system-explorer/views";
      description = ''
        Directory of view documents served by the get_views tool — the SAME
        path the hub's `views` option names, so both consumers see one set
        of projections without the MCP surface depending on the hub.
      '';
    };

    agents = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      example = { host-a = "http://localhost:8091"; host-b = "http://host-b.example.internal:8091"; };
      description = "Host agents to aggregate: name → base URL.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Bind address; widening is a per-host decision.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8092;
      description = "TCP port for the MCP endpoint.";
    };

    transport = lib.mkOption {
      type = lib.types.enum [ "streamable-http" "sse" ];
      default = "streamable-http";
      description = ''
        MCP transport. streamable-http serves /mcp; sse serves the legacy
        /sse + /messages/ pair that older brokers and hostname-per-backend
        proxy layouts expect.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the MCP port in the NixOS firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.system-explorer-mcp = {
      description = "System Explorer MCP aggregator (read-only)";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        SE_MCP_AGENTS = lib.concatStringsSep ","
          (lib.mapAttrsToList (name: url: "${name}=${url}") cfg.agents);
        SE_MCP_HOST = cfg.listenAddress;
        SE_MCP_PORT = toString cfg.port;
        SE_MCP_TRANSPORT = cfg.transport;
      } // lib.optionalAttrs (cfg.views != null) {
        SE_MCP_VIEWS = toString cfg.views;
      };

      serviceConfig = {
        Type = "simple";
        ExecStart = lib.getExe cfg.package;
        Restart = "on-failure";
        RestartSec = 2;

        # Pure HTTP client/server: tighter than the agent — no journal
        # group, no capabilities, no netlink.
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
