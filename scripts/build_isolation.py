#!/usr/bin/env python3
"""Isolation flags for a Codex BUILD: shell and files, nothing that acts elsewhere.

The build (skills/build/SKILL.md) is the one Codex call that does not go through
codex_ro.py -- it is supposed to write, and it runs `--yolo`: no sandbox, no
approvals. Until 2026-10-27 it also ran with everything the user configured for
Codex: every MCP server, plugins, apps, hooks, computer and browser control. A
builder could call a secrets manager, a workflow server or a computer-use REPL
without a single prompt. Upstream reported the same gap for its runner
(chaseai-yt/claudex-loop#43, #45; builders lost hooks/apps/plugins in #37).

Measured here on 2026-10-27, codex-cli 0.162.1:
  codex mcp list --json                                -> n8n, node_repl, codex_app, cua_repl
  ... --disable apps --disable plugins                 -> n8n, node_repl
  ... -c mcp_servers.n8n.enabled=false (and node_repl) -> both enabled: false
  ... -c mcp_servers.<undefined>.enabled=false         -> "invalid transport", config refused

So: list with plugins and apps off (their servers go with those switches), switch off
every server still enabled, name nothing that was not listed, and refuse to print a
single flag when the listing cannot be trusted. `--user-config` stays loaded on
purpose -- the skill takes the model from ~/.codex/config.toml, and
`--ignore-user-config` would drop it.

Output: one argument per line, LF only, for `mapfile -t ISO <file`. Exit 0 = flags
printed; exit 2 = refused, nothing printed, reason on stderr. ASCII only.

    python scripts/build_isolation.py [--allow-mcp NAME ...] > "$SCRATCH_DIR/build-isolation.txt"
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

from codex_ro import ISOLATION_DISABLE, find_codex

# What a builder keeps of the reviewer's switch-off list, and why. Everything else in
# ISOLATION_DISABLE is off for the build too (tests hold the two lists together).
KEEP_FOR_BUILD = frozenset({
    "image_generation",        # documented build feature: specs may ask for assets
    "goals",                   # plan bookkeeping inside the session, acts on nothing
    "skill_search",            # finding a skill is reading, not acting
    "workspace_dependencies",  # dependency handling inside the checkout a build may need
})
BUILD_DISABLE = tuple(f for f in ISOLATION_DISABLE if f not in KEEP_FOR_BUILD)

SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
LIST_TIMEOUT = 60
EXIT_REFUSED = 2

_stdout = sys.stdout.buffer


def _refuse(reason: str) -> int:
    sys.stderr.write(f"build_isolation: REFUSED - {reason}\n"
                     "  No flags printed. Do not start the build without them.\n")
    return EXIT_REFUSED


def _servers() -> list[str]:
    """Names of the MCP servers still enabled with plugins and apps off; raises on doubt."""
    argv = find_codex() + ["mcp", "list", "--json", "--disable", "apps", "--disable", "plugins"]
    done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=LIST_TIMEOUT)
    if done.returncode != 0:
        raise ValueError(f"'codex mcp list' exited {done.returncode}")
    data = json.loads(done.stdout)
    if not isinstance(data, list):
        raise ValueError("'codex mcp list --json' did not return a list")
    names = []
    for entry in data:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("an MCP listing entry has no name")
        name = entry["name"]
        if not SERVER_NAME.match(name):
            raise ValueError("an MCP server name is outside [A-Za-z0-9_-]")
        if entry.get("enabled") is not False:
            names.append(name)
    return names


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Isolation flags for a Codex build.")
    ap.add_argument("--allow-mcp", action="append", default=[], metavar="NAME",
                    help="keep this MCP server for the build (logged on stderr)")
    args = ap.parse_args(argv)
    try:
        servers = _servers()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return _refuse(str(exc).encode("ascii", "replace").decode("ascii"))
    for name in args.allow_mcp:
        if name not in servers:
            return _refuse("--allow-mcp names a server that is not enabled")

    flags: list[str] = []
    for feature in BUILD_DISABLE:
        flags += ["--disable", feature]
    flags += ["-c", "notify=[]"]
    for name in servers:
        if name not in args.allow_mcp:
            flags += ["-c", f"mcp_servers.{name}.enabled=false"]
    off = [n for n in servers if n not in args.allow_mcp]
    sys.stderr.write(f"build_isolation: {len(off)} MCP server(s) off"
                     + (f"; kept on request: {', '.join(args.allow_mcp)}" if args.allow_mcp else "")
                     + "\n")
    _stdout.write(("\n".join(flags) + "\n").encode("utf-8"))
    _stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
