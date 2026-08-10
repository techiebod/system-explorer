# System Explorer as one Python distribution with three console scripts.
#
# The predecessors of this file were three stdenvNoCC derivations that copied
# source trees into $out/share and wrapped `uvicorn --app-dir`. That worked
# only because the tree sat beside the wrapper in the store: it needed no
# packaging metadata, so nothing checked that the nix inputs matched what the
# code imports, and the operator UI was found by walking up two directories.
# Neither survives a .deb or an .rpm.
#
# Now pyproject.toml is the dependency truth and this derivation feeds it to
# buildPythonApplication, whose pythonRuntimeDepsCheckHook fails the build
# when the two disagree. That check is the whole reason to prefer this shape
# over a hand-rolled wrapper, even on NixOS where nothing else needed it.
#
# Called with python3Packages.callPackage; dependencies are named one by one
# because nixpkgs refuses a whole python3Packages set here.
{ lib
, buildPythonApplication
, python
, setuptools
  # runtime
, anyio
, dbus-fast
, fastapi
, httpx
, starlette
, uvicorn
, libvirt
, mcp
  # checks
, pytestCheckHook
, jsonschema

, pname ? "system-explorer"
, mainProgram ? "system-explorer-agent"
  # libvirt-python is a C extension against libvirt: worth its closure on a
  # hypervisor host, pure waste on the hub and the aggregator. Declared as
  # the [vms] extra in pyproject.toml, so leaving it out does not trip the
  # runtime-deps check — extras are only verified when requested.
, withVms ? true
  # The MCP SDK, needed only by the aggregator (se-mcp).
, withMcp ? false
}:

buildPythonApplication {
  inherit pname;
  version = import ./version.nix { inherit lib; };
  pyproject = true;

  src = lib.cleanSourceWith {
    src = lib.cleanSource ../.;
    # cleanSource drops .git, editor backups and result symlinks but keeps
    # Python and lab artefacts, so name them. Two distinct reasons:
    #
    #   .state/.cache — the lab's VM state (cloud-init seeds, ssh config,
    #     inventory) and its multi-GB image cache. Host-specific and
    #     secret-adjacent; must never reach the store.
    #   build/__pycache__/*.egg-info — stale copies of the source. They make
    #     the source hash depend on whatever the builder happens to have
    #     lying around, so `nix build` stops being reproducible between two
    #     clones, and a superseded copy of a file can travel into the store
    #     (and thence to a binary cache) after the real one was fixed.
    filter = path: type:
      let base = baseNameOf (toString path); in
      !(type == "directory" && (
        base == ".state" || base == ".cache"
        || base == "build" || base == "dist" || base == "__pycache__"
        || lib.hasSuffix ".egg-info" base));
  };

  build-system = [ setuptools ];

  dependencies = [
    anyio
    dbus-fast
    fastapi
    httpx
    starlette
    uvicorn
  ]
  ++ lib.optional withVms libvirt
  ++ lib.optional withMcp mcp;

  # The conformance suite is the executable half of docs/SPEC.md (section
  # 11); running it here means `nix build` cannot produce a package whose
  # adapters violate the contract.
  nativeCheckInputs = [ pytestCheckHook jsonschema ];

  # Catches the packaging failures that only appear once installed: a UI
  # found by walking up from the source tree, or a module the wheel forgot.
  pythonImportsCheck = [
    "system_explorer"
    "system_explorer.cli"
    "system_explorer.agent.main"
    "system_explorer.hub.server"
  ] ++ lib.optional withMcp "system_explorer.mcp.server";

  postInstallCheck = ''
    test -f $out/${python.sitePackages}/system_explorer/ui/index.html \
      || { echo "operator UI missing from the installed package"; exit 1; }
  '';

  meta = {
    description = "Read-only infrastructure observation: host agent, envelope API, operator UI";
    homepage = "https://github.com/techiebod/system-explorer";
    inherit mainProgram;
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
  };
}
