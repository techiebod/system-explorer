{
  lib,
  pkgs,
  ...
}:
{
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

  services.qemuGuest.enable = true;
  security.sudo.enable = true;
  users.mutableUsers = true;

  networking = {
    useDHCP = lib.mkDefault true;
    useNetworkd = true;
    firewall.allowedTCPPorts = [ 22 ];
  };

  # Keep the base nixosConfiguration independently evaluable. The qcow image
  # variant refines these with its QEMU guest profile when system.build.images
  # instantiates it.
  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };
  boot.loader.grub.devices = [ "/dev/vda" ];

  environment.systemPackages = [ pkgs.cloud-init ];

  # The qcow image grows on first boot; the per-run overlay is resized by the
  # lab before libvirt starts it.
  image.modules.qcow.virtualisation.diskSize = 8192;

  system.stateVersion = "26.05";
}
