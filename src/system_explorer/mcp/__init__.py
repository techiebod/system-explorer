"""The MCP aggregator over System Explorer host agents (SPEC section 9).

Named `mcp` inside this namespace even though server.py imports the SDK's
top-level `mcp`: Python 3 resolves `import mcp` absolutely, so the sibling
never shadows it. What *did* shadow it was the old top-level `mcp/`
directory, back when the repo root reached sys.path via `--app-dir`.
"""
