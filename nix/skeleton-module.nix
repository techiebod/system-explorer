# System Explorer skeleton — the new stack's collator + socket-activated
# collectors (DESIGN 06/18), as a NixOS module. This module and
# packaging/systemd/ are TWO SPELLINGS OF ONE SOURCE OF TRUTH: every
# directive here is generated to match those unit files exactly (only the
# ExecStart store paths and the values SE_* carry differ), and every file
# there carries the same callout back. A directive changed in one place and
# not the other is drift between install paths — change both or neither.
#
# Deliberately separate from module.nix: the repo ships the old product
# until the cut (DESIGN 06 — big-bang cutover, not a strangler), so the old
# module stays untouched and this one stands beside it.
{ config, lib, pkgs, ... }:

let
  cfg = config.system-explorer-skeleton;

  # Mirrors the collector-name grammar the request line enforces
  # (se.stream.1.json, and cmd/se-collect-system's collectionName): a name
  # outside it could never travel the stream legally, and here it also
  # becomes a unit name and a socket path — deny at eval, not at first boot.
  validName = name: builtins.match "[a-z][a-z0-9-]*" name != null;

  socketPath = name: "/run/system-explorer/collect-${name}.sock";

  # Sorted for a deterministic SE_COLLECTORS (the collator sorts too; a
  # stable spelling keeps the unit file diffable across rebuilds).
  collectors = lib.naturalSort cfg.collectors;

  # The hardening block shared by both unit kinds — one attrset so the
  # mirror with packaging/systemd stays reviewable in one screenful.
  commonHardening = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    ProtectClock = true;
    ProtectKernelLogs = true;
    ProtectKernelModules = true;
    ProtectKernelTunables = true;
    ProtectControlGroups = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    # Pure Go: no JIT, no W+X mapping to lose.
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
  };
in
{
  options.system-explorer-skeleton = {
    enable = lib.mkEnableOption
      "System Explorer skeleton (collator + socket-activated collectors)";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        Package providing bin/se-collate and bin/se-collect-<name> for each
        entry in collectors (static Go binaries). No default on purpose:
        the Go build is not packaged for Nix yet, and a default that
        evaluated to the old Python product would put the wrong binary in a
        unit that would then fail in ways that look like protocol bugs.
      '';
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8095";
      description = ''
        SE_LISTEN — the collator's read-API bind address. Loopback by
        default: the API is unauthenticated by design, so the network you
        bind to is the trust boundary (widening it is a per-host decision
        to justify where it is made). IPv4 only: the mirrored unit's
        RestrictAddressFamilies carries AF_UNIX and AF_INET and nothing
        else, so an IPv6 bind would fail at runtime — refused at eval
        instead (see assertion).
      '';
    };

    collectors = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "system" ];
      description = ''
        Collector names to run. Each name <n> needs bin/se-collect-<n> in
        package and yields se-collect-<n>.socket plus the per-connection
        template se-collect-<n>@.service, wired into SE_COLLECTORS at
        /run/system-explorer/collect-<n>.sock. This is "fleet"
        configuration (DESIGN 08): which collectors exist — never what any
        of them may read; authority is each generated unit's own sandbox.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !(lib.hasInfix "[" cfg.listen);
        message = ''
          system-explorer-skeleton.listen ("${cfg.listen}") looks like an
          IPv6 bind, and the collator unit's RestrictAddressFamilies
          deliberately carries only AF_UNIX AF_INET (mirrored in
          packaging/systemd/se-collate.service). Widening the family is a
          decision to take in both spellings of the unit, not a value to
          slip past one of them.
        '';
      }
      {
        assertion = lib.all validName cfg.collectors;
        message = ''
          system-explorer-skeleton.collectors contains a name outside
          ^[a-z][a-z0-9-]*$ (${toString (lib.filter (n: !validName n) cfg.collectors)}).
          Collector names travel the request line and the stream's begin
          record (DESIGN 18/19) and become unit names and socket paths
          here; a name the contract's grammar refuses cannot exist anywhere
          downstream, so it is refused at eval.
        '';
      }
      {
        assertion = lib.length collectors == lib.length (lib.unique collectors);
        message = ''
          system-explorer-skeleton.collectors names a collector twice.
          se-collate refuses a duplicated SE_COLLECTORS entry at startup
          (half-parsing a fleet list would observe half a fleet); refusing
          at eval reports it before a deploy instead of after one.
        '';
      }
    ];

    # sysusers mirror: a static user because the collector sockets are mode
    # 0600 owned by the collator's user (DESIGN 18) — ownership needs a
    # name that exists before any unit runs.
    users.users.system-explorer = {
      isSystemUser = true;
      group = "system-explorer";
      description = "System Explorer collator";
    };
    users.groups.system-explorer = { };

    # tmpfiles mirror: the socket directory exists before sockets.target,
    # which is earlier than se-collate.service's RuntimeDirectory= can
    # provide it. Same mode/owner as RuntimeDirectory applies, so nothing
    # flaps between the two mechanisms.
    systemd.tmpfiles.rules =
      [ "d /run/system-explorer 0755 system-explorer system-explorer -" ];

    # packaging/systemd/system-explorer.slice — the kernel-enforced ceiling
    # (DESIGN 06): the budget is a promise the kernel keeps, not an
    # arithmetic our scheduler performs, and the slice cgroup makes the
    # product's own cost observable like everything else it measures.
    systemd.slices.system-explorer = {
      description = "System Explorer resource envelope (kernel-enforced ceiling)";
      sliceConfig = {
        CPUAccounting = true;
        MemoryAccounting = true;
        TasksAccounting = true;
        # Envelope target is <=1% of a core (DESIGN 05); 10% is the hard
        # cap, so hitting it is already a defect worth a finding.
        CPUQuota = "10%";
        # The whole product, hard; the two-level split lives in the member
        # units below — a single MemoryMax over the slice would let a
        # runaway collector kill the collator (DESIGN 06).
        MemoryMax = "128M";
        # Threads are tasks; this bounds a fork runaway, not normal work.
        TasksMax = 128;
      };
    };

    # One systemd.services definition carrying both the collator and the
    # per-collector templates (an attrset cannot repeat the key).
    systemd.services = lib.mkMerge [ {

    # packaging/systemd/se-collate.service — the collator.
    se-collate = {
      description = "System Explorer collator (read API, batch authority)";
      wantedBy = [ "multi-user.target" ];
      # First dial at boot should find the sockets bound, not spend the
      # one-minute no-declaration retry.
      wants = map (n: "se-collect-${n}.socket") collectors;
      after = [ "network.target" ] ++ map (n: "se-collect-${n}.socket") collectors;

      environment = {
        # "Reach" configuration (DESIGN 08): environment, no secrets.
        SE_STATE_DIR = "/var/lib/system-explorer";
        SE_COLLECTORS = lib.concatStringsSep ","
          (map (n: "${n}=${socketPath n}") collectors);
        SE_LISTEN = cfg.listen;
      };

      serviceConfig = commonHardening // {
        Slice = "system-explorer.slice";
        User = "system-explorer";
        Group = "system-explorer";
        ExecStart = "${cfg.package}/bin/se-collate";
        Restart = "on-failure";
        RestartSec = 2;

        # Durable store + socket directory. Preserve= because removal on
        # stop would unlink the socket path from under the still-running
        # socket unit; creation at boot belongs to tmpfiles (above).
        StateDirectory = "system-explorer";
        RuntimeDirectory = "system-explorer";
        RuntimeDirectoryPreserve = true;

        # The protected control-plane reservation (DESIGN 06): MemoryMax
        # bounds the collator's own appetite; MemoryLow makes the kernel
        # reclaim from collectors (which carry none) first, so the observer
        # is the last thing in the slice to die.
        MemoryMax = "64M";
        MemoryLow = "64M";

        # AF_UNIX to dial collectors, AF_INET for the loopback listener —
        # nothing else (see the listen option's assertion).
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" ];
        # The collator holds no credential of the observed system (DESIGN
        # 06); everything privileged happens in a collector unit.
        CapabilityBoundingSet = "";
      };
    };

    }

    # packaging/systemd/se-collect-<name>@.service — one instance per
    # accepted connection: run-and-exit, sandboxed to exactly the declared
    # authority (for "system": read-only os-release + hostname, nothing).
    (lib.listToAttrs (map (name: {
      name = "se-collect-${name}@";
      value = {
        description = "System Explorer ${name} collector (one connection)";
        # Refusals exit 2 (DESIGN 18) and would linger as failed units on a
        # unit type born by the thousand; the journal keeps the stderr line.
        unitConfig.CollectMode = "inactive-or-failed";
        serviceConfig = commonHardening // {
          Slice = "system-explorer.slice";
          ExecStart = "${cfg.package}/bin/se-collect-${name}";
          StandardInput = "socket";
          StandardOutput = "socket";
          # stderr to the journal — the channel that bypasses redaction;
          # the contract polices it behaviourally (canaries, DESIGN 19).
          StandardError = "journal";
          # Mints nothing, owns no files, lives for milliseconds: a
          # throwaway uid per connection is the cheapest statement of that.
          DynamicUser = true;
          # The collector half of the two-level budget (DESIGN 06): a
          # runaway collector kills itself, never the observer.
          MemoryMax = "32M";
          # Above the collator's 30s wire deadline on purpose: the collator
          # times out first and records it; this reaps a collector wedged
          # with no collator attached (DESIGN 18).
          RuntimeMaxSec = "1min";
          # Never opens a socket — enforced, not promised. Inherited
          # connection fds are unaffected; both govern creation only.
          PrivateNetwork = true;
          RestrictAddressFamilies = "none";
          CapabilityBoundingSet = "";
          # Other processes invisible; deliberately NOT ProcSubset=pid —
          # begin reads /proc/sys/kernel/random/boot_id and
          # /proc/self/timens_offsets (DESIGN 09/19).
          ProtectProc = "invisible";
        };
      };
    }) collectors)) ];

    # packaging/systemd/se-collect-<name>.socket — per-collector socket:
    # Accept=yes hands each connection to a template instance as fd 0/1,
    # so a collector never opens a socket (DESIGN 18).
    systemd.sockets = lib.listToAttrs (map (name: {
      name = "se-collect-${name}";
      value = {
        description = "System Explorer ${name} collector socket (per-connection activation)";
        wantedBy = [ "sockets.target" ];
        listenStreams = [ (socketPath name) ];
        socketConfig = {
          Accept = true;
          # DESIGN 18: 0600, owned by the collator's user — connect() on an
          # AF_UNIX socket needs write permission on the inode, so this IS
          # the access control, stated rather than defaulted.
          SocketUser = "system-explorer";
          SocketGroup = "system-explorer";
          SocketMode = "0600";
          # The default 64 would allow 64 x 32M of collector scopes —
          # the single-ceiling failure DESIGN 06 rejects, re-created by a
          # default. The collator is single-flight per collector.
          MaxConnections = 4;
          Slice = "system-explorer.slice";
        };
      };
    }) collectors);
  };
}
