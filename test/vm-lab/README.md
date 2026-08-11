# System Explorer VM Lab

> Lives in this repository because its only consumer is this project's
> packaging test matrix, and the two need to stay co-versioned. It is
> MIT-licensed (the LICENSE beside this file) while the rest of the
> repository is GPL-3.0-or-later; it imports nothing else here and can be
> lifted out unchanged if it ever grows users of its own.

Disposable, clean Linux VMs for testing the lifecycle of a future
`system-explorer` package. The lab deliberately does not know how that package
is built or installed. Its contract ends when each guest is:

- booted from a clean copy-on-write overlay of an upstream cloud image;
- configured by cloud-init with the same non-root user and selected SSH key;
- reachable from another machine; and
- verified to allow `sudo -n` (passwordless sudo).

The current x86-64 matrix is Fedora 44, Debian 13, Ubuntu 24.04 LTS, Ubuntu
26.04 LTS, and NixOS 26.05. Fedora, Debian, and Ubuntu use their upstream cloud images. The NixOS
image is built reproducibly from the included flake with cloud-init enabled.

## Why this small project exists

[Virt-Lightning](https://virt-lightning.org/) is the closest existing project:
it is a good cloud-image/libvirt/cloud-init VM manager and can export Ansible
inventory. This lab is intentionally narrower. It guarantees one identical
non-root SSH/passwordless-sudo contract across the matrix, creates a fresh
overlay on reset, and emits stable OpenSSH and JSON interfaces for a separate
package test controller. Those details are the purpose of this repository.

## Driving it from a workstation

Set `VM_LAB_VM_HOST` to an ssh destination and the lab runs where you work,
driving a remote KVM host. Everything that touches the hypervisor — image
download, overlay creation, libvirt, virt-install — happens over there; the
cloud-init seed is rendered *here*, so your keys and agent never leave this
machine, and guests are reached by jumping through the VM host:

```sh
export VM_LAB_VM_HOST=user@vmhost
export VM_LAB_NETWORK="network=default,model=virtio"
export VM_LAB_MEMORY_MIB=1536
./bin/vm-lab up debian
ssh -F .state/ssh_config se-test-debian   # ProxyJump is in the generated config
```

No key material is written to the VM host and none is generated there. The
public half comes from your own OpenSSH identity (or your agent, if it holds
exactly one key); the private half never moves. The VM host needs
`virt-install`, `cloud-localds`, `qemu-img`, `virsh`, `curl` and coreutils on
its non-interactive PATH — preflight checks them there and names the host if
one is missing. For the `nixos` guest it also needs a checkout of this
repository, since that image is built for the guest's architecture on a
machine that can build it (`VM_LAB_REMOTE_ROOT`, default
`system-explorer/test/vm-lab`).

## Host prerequisites

Run it on an x86-64 Linux KVM host with libvirt, with room for the whole
matrix — roughly 8 GiB of disk for the cached base images and the overlays
built from them. Over libvirt NAT rather than a bridge:

```sh
export VM_LAB_NETWORK="network=default,model=virtio"
export VM_LAB_MEMORY_MIB=1536
```

NAT keeps disposable guests off a LAN the operator may not administer, at the
cost of only being routable from the VM host — reach them with `ssh -J <vmhost>`
or run the test controller there. A bridge (`bridge=br0,model=virtio`, the
default) is right when the guests should be first-class LAN citizens.

There is a third option that keeps NAT's isolation and drops the jump: route
the guest segment to the operator's machine out of band — a tailnet subnet
route advertised by the VM host, a static route, a VPN. Then set
`VM_LAB_SSH_PROXY_JUMP=` (explicitly empty) and the generated `ssh_config`
addresses guests directly, so nothing depends on the VM host's sshd being up
to reach a guest running on it.

Enter the pinned tool environment:

```sh
nix develop
```

The invoking user needs passwordless `sudo` (or equivalent) for libvirt and
the image directory. Override `VM_LAB_PRIVILEGE_COMMAND` with `doas`, or set it
to an empty string when the account already has direct access.

## SSH identity defaults

The public key is the only credential injected into a guest. Password SSH and
root SSH are disabled. By default, the guest user is the invoking `$USER` and
the lab asks OpenSSH for the effective identity list with
`ssh -G se-test-fedora`. It injects the first readable corresponding `.pub`
file. This respects normal `IdentityFile` entries and OpenSSH's standard
identity search without guessing a filename:

```sh
./bin/vm-lab up fedora
```

If no configured identity has a readable public file, the lab uses
`ssh-add -L` when the agent exposes exactly one key. Multiple agent keys are
ambiguous, so in that case select the intended SSH configuration alias or
override only the public side:

```sh
export VM_LAB_SSH_CONFIG_HOST=my-configured-host
# or
export VM_LAB_SSH_PUBLIC_KEY="$HOME/.ssh/id_ed25519.pub"
```

The matching private key must be discoverable through the normal OpenSSH
defaults or `ssh-agent`. The lab never reads, accepts, or records a private-key
path. `VM_LAB_USER` remains available when the guest username should differ
from `$USER`.

## Create and consume the matrix

```sh
./bin/vm-lab up all
./bin/vm-lab status
```

Successful `up` does not return until SSH, cloud-init, and `sudo -n true` all
work. It writes two controller-facing files:

- `.state/ssh_config`, with aliases `se-test-fedora`, `se-test-debian`,
  `se-test-ubuntu`, `se-test-ubuntu2604`, and `se-test-nixos`;
- `.state/inventory.json`, keyed by distro with address, port, user, and SSH
  alias.

An external package test controller can use standard SSH without knowing any
libvirt details:

```sh
ssh -F .state/ssh_config se-test-fedora 'sudo -n true'
jq -r '.debian.host' .state/inventory.json
```

Or drive a guest through the convenience command:

```sh
./bin/vm-lab exec ubuntu sudo systemctl status system-explorer
./bin/vm-lab ssh nixos
```

## Fresh install and lifecycle tests

`reset` destroys the domain and its writable disk, then creates a new overlay
from the cached base image. Base images are downloaded or built once.

```sh
./bin/vm-lab reset fedora

# External controller now tests install -> upgrade -> remove -> reinstall.
ssh -F .state/ssh_config se-test-fedora 'rpm -q system-explorer || true'
```

Remove one guest or the whole matrix:

```sh
./bin/vm-lab down debian
./bin/vm-lab down all
```

Writable disks live under
`/var/lib/libvirt/images/system-explorer-vm-lab/run`. Cached, checksum-verified
base images live beside them under `base`. State and generated controller files
live in `.state/` and are ignored by Git.

## Useful overrides

| Variable | Default | Purpose |
|---|---|---|
| `VM_LAB_VM_HOST` | *(empty: local)* | ssh destination of a remote KVM host |
| `VM_LAB_SSH_PROXY_JUMP` | *(the KVM host)* | bastion for reaching guests; set empty to connect direct |
| `VM_LAB_NETWORK` | `bridge=br0,model=virtio` | libvirt network or bridge |
| `VM_LAB_STORAGE_DIR` | `/var/lib/libvirt/images/system-explorer-vm-lab` | base and overlay storage |
| `VM_LAB_MEMORY_MIB` | `2048` | memory per guest |
| `VM_LAB_VCPUS` | `2` | vCPUs per guest |
| `VM_LAB_DISK_GIB` | `16` | resized writable disk |
| `VM_LAB_TIMEOUT_SECONDS` | `600` | boot/readiness deadline |
| `VM_LAB_DOMAIN_PREFIX` | `se-test` | domain and SSH alias prefix |

Image URLs and checksums can also be overridden with the distro-specific
`VM_LAB_<DISTRO>_IMAGE_URL`, `..._CHECKSUM_URL`, and Fedora `..._SHA256`
variables in `bin/vm-lab`.

## Validation

Fast checks do not download images or start VMs:

```sh
make check
```

This runs Bash syntax checking, ShellCheck, and Nix flake evaluation. A real
smoke test is `./bin/vm-lab up <distro>` on a KVM host, followed by `reset` and
`down`.
