"""Quasar as an MCP server, so Claude Code and other AI agents can call it natively and fold a
sample's analysis straight into a workflow. Run with `quasar serve` (stdio transport).

Works with the modern MCP SDK (`mcp>=2`, `MCPServer`) and the 1.x SDK (`FastMCP`)."""
from __future__ import annotations

from .analyze import analyze


def _make_server():
    try:
        from mcp.server.mcpserver import MCPServer  # mcp >= 2.x
        return MCPServer("quasar")
    except ImportError:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # mcp 1.x
        return FastMCP("quasar")
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise SystemExit("MCP SDK not installed. Run `pip install 'mcp>=2'` to use `quasar serve`.") from exc


def build():
    """Build the MCP server with Quasar's tool registered (returned un-run, for testability)."""
    server = _make_server()

    @server.tool()
    def analyze_file(path: str, intel: bool = False) -> dict:
        """Statically analyze the file at `path` and return Quasar's full report:
        verdict band + risk score with reasons, MITRE ATT&CK capabilities (each with the
        concrete evidence that triggered it), IOCs, PE structure, and imphash lineage.
        The sample is parsed, never executed."""
        return analyze(path, intel_enabled=intel)

    return server


def run() -> None:
    build().run()


if __name__ == "__main__":  # pragma: no cover
    run()
