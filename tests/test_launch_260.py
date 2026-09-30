#!/usr/bin/env python3
"""Wrapper 2.6.0, package Z: Codex is started without a batch file in between.

On Windows a `.cmd` always runs through cmd.exe, which re-reads its arguments. The
npm starter `codex.cmd` only calls `node.exe` with the package's `bin/codex.js`, so
the wrapper does exactly that itself, as a list, and never launches a batch file.
These tests check WHAT gets started; they were written before the change.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import codex_ro  # noqa: E402


class _NpmLayout:
    """A fake npm global prefix: the starter, the package, optionally node.exe beside it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.prefix = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.starter = self.prefix / "codex.cmd"
        self.starter.write_text("@echo off\r\n", encoding="ascii")
        self.js = self.prefix / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
        self.js.parent.mkdir(parents=True)
        self.js.write_text("// launcher\n", encoding="utf-8")

    def which(self, mapping):
        return lambda name: mapping.get(name)


@unittest.skipUnless(os.name == "nt", "the batch-file starter only exists on Windows")
class WindowsLaunchTests(_NpmLayout, unittest.TestCase):
    def _find(self, which, bundled=None):
        with unittest.mock.patch.object(codex_ro.shutil, "which", which), \
                unittest.mock.patch.object(codex_ro, "bundled_codex", return_value=bundled):
            return codex_ro.find_codex()

    def test_the_starter_is_replaced_by_node_and_the_package_script(self):
        node = self.prefix / "elsewhere" / "node.exe"
        launch = self._find(self.which({"codex.cmd": str(self.starter), "node.exe": str(node)}))
        self.assertEqual(launch, [str(node), str(self.js)])

    def test_a_node_beside_the_starter_wins_over_path(self):
        beside = self.prefix / "node.exe"
        beside.write_bytes(b"MZ")
        launch = self._find(self.which({"codex.cmd": str(self.starter),
                                        "node.exe": str(self.prefix / "other" / "node.exe")}))
        self.assertEqual(launch, [str(beside), str(self.js)])

    def test_a_real_executable_on_path_is_used_as_is(self):
        exe = self.prefix / "codex.exe"
        launch = self._find(self.which({"codex.exe": str(exe)}))
        self.assertEqual(launch, [str(exe)])

    def test_the_app_copy_is_the_fallback(self):
        launch = self._find(self.which({}), bundled="C:\\app\\codex.exe")
        self.assertEqual(launch, ["C:\\app\\codex.exe"])

    def test_a_starter_without_its_package_script_is_refused(self):
        self.js.unlink()
        with self.assertRaises(SystemExit) as caught:
            self._find(self.which({"codex.cmd": str(self.starter), "node.exe": "C:\\n\\node.exe"}))
        self.assertEqual(caught.exception.code, codex_ro.EXIT_NO_CODEX)

    def test_a_starter_without_node_is_refused(self):
        with self.assertRaises(SystemExit) as caught:
            self._find(self.which({"codex.cmd": str(self.starter)}))
        self.assertEqual(caught.exception.code, codex_ro.EXIT_NO_CODEX)

    def test_no_resolution_ever_starts_a_batch_file(self):
        for bundled in ("C:\\app\\codex.cmd", "C:\\app\\codex.BAT"):
            with self.subTest(bundled=bundled):
                with self.assertRaises(SystemExit) as caught:
                    self._find(self.which({}), bundled=bundled)
                self.assertEqual(caught.exception.code, codex_ro.EXIT_NO_CODEX)


class LaunchListTests(unittest.TestCase):
    """Every platform: the resolved launch is a list, and main() starts that list."""

    def test_posix_starts_codex_from_path(self):
        if os.name == "nt":
            return
        with unittest.mock.patch.object(codex_ro.shutil, "which", lambda n: "/usr/bin/codex"):
            self.assertEqual(codex_ro.find_codex(), ["/usr/bin/codex"])

    def test_the_version_probe_and_the_run_use_the_same_launch(self):
        launch = ["C:\\node\\node.exe", "C:\\npm\\codex.js"]
        seen = []

        class _Child:
            returncode = 0
            pid = 1

            def __init__(self, cmd, **kw):
                seen.append(cmd)
                self.kw = kw

            def communicate(self, input=None, timeout=None):  # noqa: A002
                self.kw["stdout"].write(
                    b'{"type":"thread.started","thread_id":"t1"}\n{"type":"turn.started"}\n'
                    b'{"type":"item.completed","item":{"type":"command_execution","exit_code":0,'
                    b'"status":"completed"}}\n{"type":"turn.completed"}\n')
                Path(cmd_out(self)).write_text("ok\n", encoding="utf-8")
                return (b"", b"")

        def cmd_out(child):
            args = seen[-1]
            return args[args.index("-o") + 1]

        probed = []
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.getcwd()
            os.chdir(tmp)
            try:
                with unittest.mock.patch.object(codex_ro, "find_codex", return_value=launch), \
                        unittest.mock.patch.object(codex_ro, "probe_cli_version",
                                                   side_effect=lambda l, **k: probed.append(l) or "0.156.0"), \
                        unittest.mock.patch.object(codex_ro.subprocess, "Popen", _Child):
                    self.assertEqual(codex_ro.main(["--prompt", "x", "--out-file", "o.txt"]), 0)
            finally:
                os.chdir(previous)
        self.assertEqual(probed, [launch])
        self.assertEqual(seen[0][:2], launch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
