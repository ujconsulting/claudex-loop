#!/usr/bin/env python3
"""The Codex BUILD gets no user MCP server, plugin, app, hook or computer control.

Upstream chaseai-yt/claudex-loop#43 / #45 / #37 (2026-10): the reviewer was isolated,
the builder was not. Here it was worse than upstream: `skills/build/SKILL.md` started
`codex exec --yolo` -- no sandbox, no approvals -- with every user MCP server loaded.
Measured on this machine 2026-10-27 (codex-cli 0.162.1): `codex mcp list --json`
reported n8n, node_repl, codex_app and cua_repl; with `--disable apps --disable
plugins` n8n and node_repl remained; `-c mcp_servers.<name>.enabled=false` switched
those off, and naming a server that is NOT defined broke the whole config
("invalid transport"). So only listed names are ever named, and they are checked.

Every test here was written before scripts/build_isolation.py and seen failing first.
Nothing starts Codex: find_codex and subprocess.run are faked.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import unittest
import unittest.mock
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import build_isolation  # noqa: E402
import codex_ro  # noqa: E402

BUILD_SKILL = REPO / "skills" / "build" / "SKILL.md"


def _listing(*servers):
    return json.dumps([{"name": n, "enabled": e, "transport": {}} for n, e in servers])


class FlagsTest(unittest.TestCase):
    def run_main(self, stdout_text="[]", returncode=0, argv=()):
        done = subprocess.CompletedProcess([], returncode, stdout_text, "boom")
        out, err = io.BytesIO(), io.StringIO()
        with unittest.mock.patch.object(build_isolation, "find_codex", return_value=["codex"]), \
                unittest.mock.patch.object(build_isolation.subprocess, "run",
                                           return_value=done) as run, \
                unittest.mock.patch.object(build_isolation, "_stdout", out), \
                unittest.mock.patch("sys.stderr", err):
            code = build_isolation.main(list(argv))
        return code, out.getvalue(), err.getvalue(), run

    def test_every_enabled_server_is_switched_off(self):
        code, out, _, _ = self.run_main(_listing(("n8n", True), ("node_repl", True), ("off", False)))
        self.assertEqual(code, 0)
        args = out.decode("utf-8").split("\n")
        self.assertIn("mcp_servers.n8n.enabled=false", args)
        self.assertIn("mcp_servers.node_repl.enabled=false", args)
        self.assertNotIn("mcp_servers.off.enabled=false", args,
                         "a disabled server is not named -- naming is what can break the config")

    def test_one_argument_per_line_lf_only(self):
        """mapfile in bash keeps a CR: on Windows a text-mode print would end every flag in \\r."""
        _, out, _, _ = self.run_main(_listing(("n8n", True)))
        self.assertNotIn(b"\r", out)
        self.assertTrue(out.endswith(b"\n"))

    def test_the_listing_itself_runs_without_plugins_and_apps(self):
        """Plugin servers have no [mcp_servers] table; they go with --disable plugins."""
        _, _, _, run = self.run_main(_listing())
        argv = run.call_args.args[0]
        self.assertEqual(argv[:1], ["codex"])
        for pair in (["mcp", "list", "--json"], ["--disable", "apps"], ["--disable", "plugins"]):
            self.assertTrue(any(argv[i:i + len(pair)] == pair for i in range(len(argv))), pair)

    def test_features_off_include_the_outward_ones(self):
        _, out, _, _ = self.run_main(_listing())
        args = out.decode("utf-8").split("\n")
        disabled = {args[i + 1] for i, a in enumerate(args) if a == "--disable"}
        for feature in ("apps", "plugins", "hooks", "computer_use", "browser_use",
                        "in_app_browser", "skill_mcp_dependency_install"):
            self.assertIn(feature, disabled)
        self.assertNotIn("image_generation", disabled,
                         "image generation is a documented build feature (SKILL.md prerequisites)")
        self.assertIn("notify=[]", args, "notify runs a user program on every turn")

    def test_build_keeps_what_the_reviewer_loses_only_where_named(self):
        """Every reviewer switch applies to the build too, except the documented KEEP set."""
        self.assertTrue(build_isolation.KEEP_FOR_BUILD <= set(codex_ro.ISOLATION_DISABLE))
        self.assertEqual(set(build_isolation.BUILD_DISABLE),
                         set(codex_ro.ISOLATION_DISABLE) - build_isolation.KEEP_FOR_BUILD)

    def test_allow_mcp_keeps_exactly_that_server_and_says_so(self):
        code, out, err, _ = self.run_main(_listing(("n8n", True), ("docs", True)),
                                          argv=["--allow-mcp", "docs"])
        self.assertEqual(code, 0)
        self.assertNotIn("mcp_servers.docs.enabled=false", out.decode("utf-8"))
        self.assertIn("mcp_servers.n8n.enabled=false", out.decode("utf-8"))
        self.assertIn("docs", err)

    def test_fails_closed(self):
        for name, kwargs in (
                ("listing exits non-zero", {"stdout_text": "[]", "returncode": 1}),
                ("not JSON", {"stdout_text": "Error: failed"}),
                ("not a list", {"stdout_text": "{}"}),
                ("odd server name", {"stdout_text": _listing(("x.y", True))}),
                ("name with a quote", {"stdout_text": _listing(('a"b', True))}),
                ("allow-mcp names an unknown server",
                 {"stdout_text": _listing(("n8n", True)), "argv": ["--allow-mcp", "nope"]})):
            with self.subTest(name):
                code, out, err, _ = self.run_main(**kwargs)
                self.assertNotEqual(code, 0)
                self.assertEqual(out, b"", "a refused run prints no flags at all")
                self.assertTrue(all(ord(c) < 128 for c in err), "ASCII only on stderr")

    def test_codex_not_starting_is_fail_closed(self):
        err = io.StringIO()
        with unittest.mock.patch.object(build_isolation, "find_codex", return_value=["codex"]), \
                unittest.mock.patch.object(build_isolation.subprocess, "run",
                                           side_effect=OSError("nope")), \
                unittest.mock.patch.object(build_isolation, "_stdout", io.BytesIO()), \
                unittest.mock.patch("sys.stderr", err):
            self.assertNotEqual(build_isolation.main([]), 0)


class SkillContractTest(unittest.TestCase):
    """The build skill must actually USE the flags, on exec and on resume."""

    def setUp(self):
        self.text = BUILD_SKILL.read_text(encoding="utf-8")

    def test_isolation_is_computed_before_the_build_and_its_exit_stops_it(self):
        self.assertIn("scripts/build_isolation.py", self.text)
        self.assertIn("build-isolation.txt", self.text)

    def test_every_codex_exec_in_the_skill_carries_the_flags(self):
        launches = [ln for ln in self.text.splitlines()
                    if ln.lstrip().startswith("codex exec")]
        self.assertGreaterEqual(len(launches), 2, "exec and resume")
        for line in launches:
            self.assertIn('"${ISO[@]}"', line, line)


if __name__ == "__main__":
    unittest.main()
