# The single version source, read out of the Python package rather than
# duplicated here. pyproject.toml resolves the same attribute via
# tool.setuptools.dynamic, so nix and the wheel cannot disagree — three
# hand-maintained `version = "…"` lines had already drifted to 0.3.0/0.3.0/
# 0.4.0 against 0.4.0 code before this existed.
{ lib }:

let
  lines = lib.splitString "\n" (builtins.readFile ../src/system_explorer/__init__.py);
  line = lib.findFirst (l: lib.hasPrefix "__version__ = " l) null lines;
in
assert lib.assertMsg (line != null)
  "no __version__ assignment found in src/system_explorer/__init__.py";
lib.elemAt (lib.splitString "\"" line) 1
