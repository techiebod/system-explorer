{
  description = "System Explorer — read-only infrastructure observation: host agent, envelope API, operator UI";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forEach = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # One distribution, three console scripts, three closures. The variants
      # differ only in which optional dependencies they carry: the hub and the
      # aggregator have no business pulling libvirt, and only the aggregator
      # needs the MCP SDK. mainProgram keeps `lib.getExe` pointing at the
      # right script so the NixOS modules did not have to change.
      packages = forEach (pkgs: rec {
        system-explorer = pkgs.python3Packages.callPackage ./nix/package.nix { };
        se-hub = pkgs.python3Packages.callPackage ./nix/package.nix {
          pname = "system-explorer-hub";
          mainProgram = "se-hub";
          withVms = false;
        };
        se-mcp = pkgs.python3Packages.callPackage ./nix/package.nix {
          pname = "system-explorer-mcp";
          mainProgram = "se-mcp";
          withVms = false;
          withMcp = true;
        };
        default = system-explorer;
      });

      # import <this flake>.nixosModules.default and set
      # services.systemExplorer.enable = true; the package defaults to this
      # flake's build but stays overridable. nixosModules.mcp carries the
      # aggregator (services.systemExplorerMcp) and nixosModules.hub the
      # per-site hub (services.systemExplorerHub) the same way.
      nixosModules.default = { pkgs, lib, ... }: {
        imports = [ ./nix/module.nix ];
        services.systemExplorer.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      };
      nixosModules.mcp = { pkgs, lib, ... }: {
        imports = [ ./nix/mcp-module.nix ];
        services.systemExplorerMcp.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.se-mcp;
      };
      nixosModules.hub = { pkgs, lib, ... }: {
        imports = [ ./nix/hub-module.nix ];
        services.systemExplorerHub.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.se-hub;
      };

      # The conformance suite (SPEC section 11) already runs inside every
      # package build via pytestCheckHook, so the check is the build — this
      # keeps `nix flake check` meaningful without running the suite twice
      # against a different sys.path than the installed package sees.
      checks = forEach (pkgs: {
        conformance = self.packages.${pkgs.stdenv.hostPlatform.system}.system-explorer;
      });

      devShells = forEach (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [
              ps.anyio
              ps.dbus-fast
              ps.fastapi
              ps.httpx
              ps.jsonschema
              ps.libvirt
              ps.mcp
              ps.pytest
              ps.starlette
              ps.uvicorn
            ]))
          ];
        };
      });
    };
}
