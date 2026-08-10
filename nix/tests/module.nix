# Does the documented install path actually work, and does the agent degrade
# honestly on a host that has almost nothing?
#
# This closes a long-standing gap: every deployment so far rode a private
# estate repo's module shim, so `nixosModules.default` + `enable = true` — the
# path README.md and AGENTS.md tell a stranger to use — was never exercised.
# Here it is exercised by `nix flake check`.
#
# It is also where the ROADMAP section 5 phase-4 assertion lives, and the
# assertion is deliberately not "the happy path works". It is:
#
#     every collection returns data or an explicit unavailable-with-reason —
#     never a 500, never a silent empty.
#
# A bare NixOS VM is the ideal host for that, because it HAS almost nothing:
# no Docker socket, no libvirt, no zpool, no NVMe controller, no SCSI
# enclosure, no tailscaled. Nearly every subsystem must decline, in writing,
# with a reason a human can act on — and the two Nix collections must work,
# which is what stops this from testing only the sad path.
{ pkgs, self }:

pkgs.testers.runNixOSTest {
  name = "system-explorer-module";

  nodes.machine = { ... }: {
    imports = [ self.nixosModules.default ];
    # Exactly what the README tells a new user to write, and nothing else:
    # no grants, no wider bind, no extraPackages. The defaults are part of
    # the contract under test.
    services.systemExplorer.enable = true;
  };

  testScript = ''
    import json

    machine.wait_for_unit("system-explorer.service")
    # The default bind is loopback, so the port must be open there and the
    # service must not have quietly widened it.
    machine.wait_for_open_port(8091, addr = "127.0.0.1")


    def get(path):
        """curl -f, so any HTTP >= 400 fails the test rather than being parsed.
        Errors are observations carried at 200 in this API (SPEC rule 7); a
        4xx/5xx means the contract broke."""
        return json.loads(machine.succeed(
            f"curl -fsS --max-time 60 http://127.0.0.1:8091{path}"))


    with subtest("health and version"):
        health = get("/health")
        assert health["status"] == "ok", health
        assert health["version"], "no version reported"
        assert health["host"]["machine_id"], "no machine-id"

    with subtest("the operator UI is served from the installed package"):
        # Guards the failure this used to have: the UI was found by walking up
        # from the source tree, which resolves in a checkout and silently 404s
        # once installed.
        machine.succeed("curl -fsS --max-time 30 -o /dev/null http://127.0.0.1:8091/")
        machine.succeed("curl -fsS --max-time 30 http://127.0.0.1:8091/ui/app.js >/dev/null")

    caps = get("/v1/capabilities")
    assert caps["schema"] == "se.capabilities/1", caps

    with subtest("a NixOS host can answer the Nix questions"):
        # If everything declined, this test would only prove that absence is
        # reported — which a totally broken agent would also pass. So assert a
        # Nix-only collection really answers.
        nix_caps = caps["subsystems"]["system"]
        assert nix_caps["available"], nix_caps
        for collection in ("generations", "packages"):
            assert collection in nix_caps["collections"], (
                f"{collection} unavailable on a NixOS host: {nix_caps}")

        # packages, not generations, carries the positive assertion. A test VM
        # is built straight from a closure rather than by nixos-rebuild, so
        # /nix/var/nix/profiles exists but holds no system-*-link generations:
        # "ok with zero items" is literally true there, and the honest-absence
        # gate is right to stay quiet. /run/current-system/sw is always a
        # populated link farm, so this one must have content.
        packages = get("/v1/system/packages?limit=5")
        assert packages["status"] == "ok", packages
        assert packages["items"], "a NixOS host with no packages in its sw link farm"

        generations = get("/v1/system/generations")
        assert generations["status"] == "ok", generations

    with subtest("every subsystem is available or says why"):
        for name, subsystem in caps["subsystems"].items():
            if not subsystem.get("available"):
                reason = subsystem.get("reason")
                assert reason and reason.strip(), f"{name} unavailable with no reason"

    with subtest("declined collections answer with a reason, not an empty page"):
        # The phase-2 fix, asserted: an absent directory and an empty one both
        # glob to zero items, so a clean `ok` page here would be a lie. On this
        # VM that covers docker, libvirt, zfs, nvme and more.
        declined = 0
        for name, subsystem in caps["subsystems"].items():
            for collection, reason in subsystem.get("unavailable_collections", {}).items():
                assert reason and reason.strip(), f"{name}/{collection} declined blankly"
                envelope = get(f"/v1/{name}/{collection}")
                assert envelope["status"] == "error", (
                    f"{name}/{collection} is unavailable but answered "
                    f"status={envelope['status']} with {len(envelope['items'])} items")
                assert envelope["errors"], f"{name}/{collection} error with no errors[]"
                declined += 1
        assert declined, "no collection declined on a bare VM — the gate is untested"

    with subtest("available collections answer without a 500"):
        for name, subsystem in caps["subsystems"].items():
            if not subsystem.get("available"):
                continue
            for collection in subsystem.get("collections", []):
                envelope = get(f"/v1/{name}/{collection}?limit=5")
                assert envelope["schema"] == "se.collection/1", envelope
                if envelope["status"] == "error":
                    assert envelope["errors"], f"{name}/{collection} error with no errors[]"

    with subtest("the roll-up answers for the whole host"):
        status = get("/v1/status")
        assert status["schema"] == "se.status/1", status
        assert status["status"] in ("ok", "partial"), status
        # Every entry either rolls up a level or declines with a reason/error.
        for name, collections in status["subsystems"].items():
            for collection, entry in collections.items():
                if entry.get("worst") is None:
                    # Three distinct ways to have no level, and all three must
                    # be legible: declined (reason), failed (error), or simply
                    # empty (total 0 — a NixOS test VM really has no profile
                    # generations). What must never happen is a null level
                    # with none of the three.
                    explained = (entry.get("reason") or entry.get("error")
                                 or entry.get("total") == 0)
                    assert explained, (
                        f"{name}/{collection} has no level and no explanation: {entry}")

    with subtest("unknown routes are HTTP errors, not envelopes"):
        machine.succeed("curl -sS -o /dev/null -w '%{http_code}' "
                        "http://127.0.0.1:8091/v1/system/nonesuch | grep -q 404")
        machine.succeed("curl -sS -o /dev/null -w '%{http_code}' "
                        "http://127.0.0.1:8091/v1/nonesuch/nonesuch | grep -q 404")

    with subtest("the service is hardened as the module claims"):
        # Spot-check the sandbox the module sets, so a future edit that drops
        # it fails here rather than silently widening the agent's reach.
        properties = machine.succeed(
            "systemctl show system-explorer.service "
            "-p DynamicUser -p ProtectSystem -p PrivateTmp -p NoNewPrivileges")
        for expected in ("DynamicUser=yes", "ProtectSystem=strict",
                         "PrivateTmp=yes", "NoNewPrivileges=yes"):
            assert expected in properties, f"{expected} missing:\n{properties}"

    with subtest("read-only: no mutating method is accepted"):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            code = machine.succeed(
                f"curl -sS -o /dev/null -w '%{{http_code}}' -X {method} "
                "http://127.0.0.1:8091/v1/system/identity")
            assert code.strip() == "405", f"{method} returned {code}, expected 405"
  '';
}
