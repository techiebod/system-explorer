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

      # `qemu`, not `qcow`. nixpkgs' image variants are a fixed table in
      # nixos/modules/image/images.nix, and the BIOS-booting disk image it
      # builds with qemu-img is called `qemu` there — there has never been a
      # `qcow` key. Naming one did not fail as an unknown attribute, because
      # `image.modules` is an open attrset of deferred modules: asking for
      # `qcow` silently DEFINED a new variant carrying only the diskSize this
      # lab set, with nothing importing disk-image.nix to supply
      # `system.build.image`. The error surfaced 200 lines into a module trace
      # rather than at the name, so it is spelled out here instead.
      packages.${system}.nixos-image =
        self.nixosConfigurations.vm-lab.config.system.build.images.qemu;

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
