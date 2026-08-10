{
  description = "Disposable cloud-init VMs for System Explorer install testing";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      checkSystems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];
    in
    {
      nixosConfigurations.vm-lab = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./nixos/cloud-image.nix ];
      };

      packages.${system}.nixos-image =
        self.nixosConfigurations.vm-lab.config.system.build.images.qcow;

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          bash
          coreutils
          curl
          gawk
          gnugrep
          jq
          libvirt
          openssh
          qemu
          shellcheck
          virt-manager
        ];
      };

      checks = nixpkgs.lib.genAttrs checkSystems (
        checkSystem:
        let
          checkPkgs = nixpkgs.legacyPackages.${checkSystem};
        in
        {
          shell = checkPkgs.runCommand "vm-lab-shell-check" { } ''
            ${checkPkgs.bash}/bin/bash -n ${./bin/vm-lab}
            ${checkPkgs.shellcheck}/bin/shellcheck ${./bin/vm-lab}
            touch "$out"
          '';
        }
      );

      formatter = nixpkgs.lib.genAttrs checkSystems (
        checkSystem: nixpkgs.legacyPackages.${checkSystem}.nixfmt-tree
      );
    };
}
