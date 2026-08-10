import sys

import pytest

from common import SRC_DIR, example_files, load_example

# The rules evaluators are pure (stdlib + system_explorer.agent.envelope
# only), so test_rules.py imports them directly on any platform — including
# the macOS workstation this is developed on. Adapters stay unimportable
# off-host; only the rulebook needs the package importable.
#
# pyproject.toml's [tool.pytest.ini_options] pythonpath already does this for
# any pytest run rooted at the repo; the insert keeps a bare
# `pytest conformance/` from another cwd working too.
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture(params=example_files(), ids=lambda p: p.name)
def example(request):
    """Each fixture file under schema/examples/, parsed, with its path."""
    return request.param, load_example(request.param)
