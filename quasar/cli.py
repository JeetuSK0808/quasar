"""Quasar CLI.  `quasar analyze <file>` (or just `quasar <file>`), `--json`, and `quasar serve`."""
from __future__ import annotations
import argparse
import sys

from .analyze import analyze as run_analyze
from .report import render as render_report, to_json

_SUBCOMMANDS = {"analyze", "serve"}


def _do_analyze(path: str, as_json: bool, intel: bool, html: str | None = None) -> int:
    try:
        rep = run_analyze(path, intel_enabled=intel)
    except FileNotFoundError:
        print(f"quasar: file not found: {path}", file=sys.stderr)
        return 1
    except IsADirectoryError:
        print(f"quasar: not a file: {path}", file=sys.stderr)
        return 1
    if as_json:
        print(to_json(rep))
        return 0
    if html:
        from rich.console import Console
        console = Console(record=True, width=100)
        render_report(rep, console)
        console.save_html(html)
        print(f"wrote {html}")
        return 0
    render_report(rep)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        prog="quasar",
        description="Quasar — static malware analyzer (TQG Research). Parses samples, never executes them.",
    )
    sub = parser.add_subparsers(dest="cmd")
    pa = sub.add_parser("analyze", help="analyze a file")
    pa.add_argument("file")
    pa.add_argument("--json", action="store_true", help="emit JSON instead of the rendered report")
    pa.add_argument("--intel", action="store_true", help="enable (privacy-safe) online intel lookups")
    pa.add_argument("--html", metavar="FILE", help="also write a shareable HTML report to FILE")
    sub.add_parser("serve", help="run the MCP server for Claude Code / AI agents")

    # Shorthand: `quasar some.exe` == `quasar analyze some.exe`.
    if argv and argv[0] not in _SUBCOMMANDS and not argv[0].startswith("-"):
        argv = ["analyze"] + argv

    args = parser.parse_args(argv)
    if args.cmd == "serve":
        from . import mcp_server
        mcp_server.run()
        return 0
    if args.cmd == "analyze":
        return _do_analyze(args.file, args.json, args.intel, args.html)
    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
