"""System Explorer — read-only infrastructure observation.

Three deployables share this distribution and its contract (docs/SPEC.md):

  system_explorer.agent   the per-host HTTP agent (SPEC sections 5-8)
  system_explorer.hub     the per-site browsing hub (ROADMAP slice 1)
  system_explorer.mcp     the MCP aggregator over agents (SPEC section 9)

The namespace exists because the top-level names are taken: `agent`, `hub`
and `mcp` are all real PyPI distributions, and a top-level `mcp/` directory
shadowed the very SDK the aggregator imports whenever the repo root landed
on sys.path. Nesting fixes that — inside system_explorer.mcp, `import mcp`
is an absolute import and reaches the SDK, because Python 3 has no implicit
relative imports.
"""

# THE version. pyproject.toml reads this attribute (tool.setuptools.dynamic)
# and nix/version.nix parses this line, so a release is one edit and the
# build fails rather than shipping 0.4.0 code labelled 0.3.0 — which is what
# four hand-maintained copies did until 2026-08-10. Tracks docs/SPEC.md.
__version__ = "0.6.0"

# The source revision this build came from, when the builder knew it. Written
# by nix/package.nix as _build.py from the flake's own rev, so it is absent
# from a plain `pip install .` — a wheel built from a tarball has no git to
# ask, and inventing a value would be worse than admitting none.
#
# It exists because a version alone cannot answer "am I looking at the change
# we just made". Between releases every host reports 0.4.0, so the operator UI
# showed the same string before and after a deploy and there was no way to tell
# from the screen whether a fix had landed. That question was asked out loud.
try:                                          # pragma: no cover - build artefact
    from ._build import REVISION as __revision__
except ImportError:                           # pragma: no cover - source checkout
    __revision__ = None
