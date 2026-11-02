#!/usr/bin/env python3
"""review_mirror.py copies only the declared review scope and refuses everything unsafe.

robocopy is never started: subprocess.run is faked.

    python -m unittest tests.test_review_mirror -v
"""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import review_mirror as rm  # noqa: E402


class ReadScope(unittest.TestCase):
    def test_dirs_files_comments(self):
        self.assertEqual(rm.read_scope("doku/\n# x\nAGENTS.md  # rules\n\n_knowledge\\concepts\\\n"),
                         (["doku/", "AGENTS.md", "_knowledge/concepts/"], []))

    def test_exclusions_under_listed_dirs(self):
        self.assertEqual(rm.read_scope("_scripte/\n!_scripte/kunden/\n!_scripte/databases.json\n"),
                         (["_scripte/"], ["_scripte/kunden/", "_scripte/databases.json"]))

    def test_exclusion_outside_listed_dirs_is_refused(self):
        for bad in ("doku/\n!_scripte/kunden/\n", "doku/\n!doku/\n", "AGENTS.md\n!AGENTS.md\n"):
            with self.subTest(bad=bad), self.assertRaises(rm.ScopeError):
                rm.read_scope(bad)

    def test_refuses_unsafe_entries(self):
        for bad in ("/etc", "C:\\x", "../up", "a/../b", ".git", ".env", ".env.local",
                    "cfg/.env", "x/.envrc"):
            with self.subTest(bad=bad), self.assertRaises(rm.ScopeError):
                rm.read_scope(bad)

    def test_env_templates_are_allowed(self):
        self.assertEqual(rm.read_scope(".env.example\nsub/.env.sample\n")[0],
                         [".env.example", "sub/.env.sample"])
        with self.assertRaises(rm.ScopeError):
            rm.read_scope(".env.example.local")

    def test_empty_scope_is_refused(self):
        with self.assertRaises(rm.ScopeError):
            rm.read_scope("# nothing\n\n")


class Robocopy(unittest.TestCase):
    def test_dir_mirrors_and_excludes_secrets_and_caches(self):
        a = rm.robocopy_dir(Path("Q"), Path("Z"), check=False)
        self.assertIn("/MIR", a)
        for x in (".env", ".env.*", "*.env", "__pycache__", ".playwright-mcp", ".git"):
            self.assertIn(x, a)
        self.assertNotIn("/L", a)

    def test_check_only_lists(self):
        self.assertEqual(rm.robocopy_dir(Path("Q"), Path("Z"), check=True)[-1], "/L")
        self.assertEqual(rm.robocopy_file(Path("Q/a.md"), Path("Z/a.md"), check=True)[-1], "/L")


class Main(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        (self.repo / ".codex").mkdir(parents=True)
        (self.repo / "doku").mkdir()
        (self.repo / "AGENTS.md").write_text("x", encoding="utf-8")
        (self.repo / ".env").write_text("secret", encoding="utf-8")
        self.target = self.tmp / "mirror"

    def run_main(self, *extra):
        buf = io.StringIO()
        with mock.patch.object(rm.subprocess, "run") as run, redirect_stdout(buf):
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="")
            code = rm.main(["--repo", str(self.repo), "--target", str(self.target), *extra])
        return code, run, buf.getvalue()

    def test_no_scope_file_copies_nothing(self):
        code, run, out = self.run_main()
        self.assertEqual(code, 2)
        run.assert_not_called()
        self.assertIn("nothing is mirrored", out)

    def test_only_listed_existing_entries_are_copied(self):
        (self.repo / rm.SCOPE_FILE).write_text("doku/\nAGENTS.md\nsrc/\n", encoding="utf-8")
        code, run, out = self.run_main()
        self.assertEqual(code, 0)
        sources = [c.args[0][1] for c in run.call_args_list]
        self.assertEqual(sources, [str(self.repo / "doku"), str(self.repo)])
        self.assertIn("src/", out)  # missing entry reported, not copied
        self.assertTrue((self.target / rm.SOURCE_MARK).is_file())

    def test_robocopy_failure_is_exit_1(self):
        (self.repo / rm.SCOPE_FILE).write_text("doku/\n", encoding="utf-8")
        with mock.patch.object(rm.subprocess, "run") as run, redirect_stdout(io.StringIO()):
            run.return_value = mock.Mock(returncode=8, stdout="ERROR", stderr="")
            code = rm.main(["--repo", str(self.repo), "--target", str(self.target)])
        self.assertEqual(code, 1)
        self.assertFalse((self.target / rm.SOURCE_MARK).exists())

    def test_exclusions_reach_robocopy_with_full_paths(self):
        (self.repo / "_scripte" / "kunden").mkdir(parents=True)
        (self.repo / "_scripte" / "databases.json").write_text("{}", encoding="utf-8")
        (self.repo / rm.SCOPE_FILE).write_text(
            "_scripte/\n!_scripte/kunden/\n!_scripte/databases.json\n", encoding="utf-8")
        code, run, _ = self.run_main()
        self.assertEqual(code, 0)
        args = run.call_args_list[0].args[0]
        xd, xf = args.index("/XD"), args.index("/XF")
        self.assertIn(str(self.repo / "_scripte" / "kunden"), args[xd:xf])
        self.assertIn(str(self.repo / "_scripte" / "databases.json"), args[xf:])

    def test_target_inside_repo_is_refused(self):
        (self.repo / rm.SCOPE_FILE).write_text("doku/\n", encoding="utf-8")
        self.target = self.repo / "mirror"
        code, run, _ = self.run_main()
        self.assertEqual(code, 2)
        run.assert_not_called()

    def test_target_of_another_repo_is_refused(self):
        (self.repo / rm.SCOPE_FILE).write_text("doku/\n", encoding="utf-8")
        self.target.mkdir()
        (self.target / rm.SOURCE_MARK).write_text(str(self.tmp / "other"), encoding="utf-8")
        code, run, out = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("already mirrors", out)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
