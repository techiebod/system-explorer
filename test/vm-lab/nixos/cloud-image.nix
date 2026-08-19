{
  lib,
  pkgs,
  modulesPath,
  ...
}:
{
  # Without this the guest boots a kernel that cannot see its own disk. The
  # image variant supplies the disk and the bootloader and nothing else —
  # nixpkgs' disk-image.nix imports only the size and file-name options — so
  # virtio_blk is absent from the initrd, /dev/disk/by-label/nixos never
  # appears, and stage 1 waits 1m30s for a device that no driver was loaded to
  # find. Every guest this lab starts runs under QEMU/KVM, so the profile
  # belongs in the base configuration rather than in any one variant.
  imports = [ "${modulesPath}/profiles/qemu-guest.nix" ];

  # cloud-init owns first-boot identity and access, exactly as it does for the
  # other images in the matrix. No test user's key is baked into this image.
  services.cloud-init = {
    enable = true;
    network.enable = true;
    settings.datasource_list = [ "NoCloud" ];
  };

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  # A guest that fails to boot must be able to SAY so. virt-install gives this
  # domain no graphics device, so `virsh screenshot` answers "no screens to take
  # screenshot from" and a guest that never reaches the network is indis-
  # tinguishable from one that never reaches userspace — which is exactly the
  # state this image was found in. The serial console is the only channel left,
  # and it is worth its one line permanently rather than being added each time
  # somebody needs it: `virsh console se-test-nixos` now shows the boot.
  boot.kernelParams = [ "console=ttyS0,115200n8" ];

  services.qemuGuest.enable = true;
  security.sudo.enable = true;
  users.mutableUsers = true;

  networking = {
    useDHCP = lib.mkDefault true;
    useNetworkd = true;
    firewall.allowedTCPPorts = [ 22 ];
  };

  # Keep the base nixosConfiguration independently evaluable. These two are
  # also declared by the `qemu` variant, to the same values, so the merge is a
  # no-op — the point of restating them is that this configuration evaluates on
  # its own. What the comment here used to claim — that the variant "refines
  # these with its QEMU guest profile" — was never true of any variant, and the
  # cost of the claim was a guest that could not see its own disk with nothing
  # in the file admitting it; see the qemu-guest import above.
  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };
  boot.loader.grub.devices = [ "/dev/vda" ];

  environment.systemPackages = [ pkgs.cloud-init ];

  # The image grows on first boot; the per-run overlay is resized by the lab
  # before libvirt starts it. `qemu` is the variant that builds a BIOS-booting
  # qcow2 — matching boot.loader.grub.devices above — and it must be one of
  # the names nixpkgs' image table defines, because an unknown one declares a
  # new variant with nothing behind it rather than failing.
  image.modules.qemu.virtualisation.diskSize = 8192;

  system.stateVersion = "26.05";
}
