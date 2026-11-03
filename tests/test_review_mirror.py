#!/usr/bin/env python3
"""review_mirror.py publishes immutable generations of the declared review scope.

robocopy is faked (an emulation that honours /XD, /XF, /XJ) everywhere except in the
one class at the bottom that runs the real robocopy on Windows.

    python -m unittest tests.test_review_mirror -v
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import review_mirror as rm  # noqa: E402

IS_WIN = os.name == "nt"
FLAGS = {"/E", "/XJ", "/XD", "/XF", "/NFL", "/NDL", "/NJH", "/NJS", "/NP", "/R:1", "/W:1", "/L"}


def _link_like(p: str) -> bool:
    if os.path.islink(p):
        return True
    try:
        return bool(getattr(os.lstat(p), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return False


def rm_all(path) -> None:
    """Test-side delete that never follows a link."""
    path = str(path)
    if not os.path.lexists(path):
        return
    if _link_like(path):
        try:
            os.rmdir(path)
        except OSError:
            os.unlink(path)
        return
    if os.path.isdir(path):
        for n in os.listdir(path):
            rm_all(os.path.join(path, n))
        os.chmod(path, 0o700)
        os.rmdir(path)
    else:
        os.chmod(path, 0o600)
        os.unlink(path)


def make_link(link, target) -> None:
    """Junction on Windows, symlink elsewhere (skip when the OS refuses)."""
    link, target = str(link), str(target)
    if IS_WIN:
        import _winapi
        _winapi.CreateJunction(target, link)
        return
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError as e:  # pragma: no cover
        raise unittest.SkipTest(f"cannot create a link here: {e}")


def snapshot(path: Path) -> dict:
    out = {}
    for dp, dns, fns in os.walk(path):
        for n in fns:
            p = Path(dp) / n
            out[str(p.relative_to(path))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def fake_robocopy(args, hook=None, calls=None):
    """Emulate the robocopy calls review_mirror builds (argv list, honours XD/XF/XJ)."""
    if calls is not None:
        calls.append(list(args))
    src, dst = args[1], args[2]
    mode, xd, xf, files = None, [], [], []
    for t in args[3:]:
        if t in FLAGS:
            mode = t
        elif mode == "/XD":
            xd.append(t)
        elif mode == "/XF":
            xf.append(t)
        else:
            files.append(t)
    xd_names = {x.lower() for x in xd if os.sep not in x and "/" not in x}
    xd_full = {os.path.normcase(os.path.normpath(x)) for x in xd if os.sep in x or "/" in x}
    xf_pats = [x for x in xf if os.sep not in x and "/" not in x]
    xf_full = {os.path.normcase(os.path.normpath(x)) for x in xf if os.sep in x or "/" in x}
    if "/E" in args:
        for dp, dns, fns in os.walk(src):
            keep = []
            for d in dns:
                full = os.path.join(dp, d)
                if _link_like(full) and "/XJ" in args:
                    continue
                if any(fnmatch.fnmatch(d.lower(), p) for p in xd_names) \
                        or os.path.normcase(os.path.normpath(full)) in xd_full:
                    continue
                keep.append(d)
            dns[:] = keep
            rel = os.path.relpath(dp, src)
            target_dir = os.path.join(dst, "" if rel == "." else rel)
            os.makedirs(target_dir, exist_ok=True)
            for f in fns:
                full = os.path.join(dp, f)
                if any(fnmatch.fnmatch(f.lower(), p.lower()) for p in xf_pats):
                    continue
                if os.path.normcase(os.path.normpath(full)) in xf_full:
                    continue
                shutil.copy2(full, os.path.join(target_dir, f))
    else:
        os.makedirs(dst, exist_ok=True)
        for f in files:
            shutil.copy2(os.path.join(src, f), os.path.join(dst, f))
    if hook:
        hook(Path(src), Path(dst), args)
    return mock.Mock(returncode=1, stdout="", stderr="")


class Base(unittest.TestCase):
    SCOPE = "doku/\nAGENTS.md\n"

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(rm_all, self.tmp)
        self.repo = self.tmp / "repo"
        (self.repo / ".codex").mkdir(parents=True)
        (self.repo / "doku" / "sub").mkdir(parents=True)
        (self.repo / "doku" / "a.md").write_text("A", encoding="utf-8")
        (self.repo / "doku" / "sub" / "b.md").write_text("B", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("x", encoding="utf-8")
        (self.repo / ".env").write_text("secret", encoding="utf-8")
        self.root = self.tmp / "root"
        self.write_scope(self.SCOPE)

    def write_scope(self, text, repo=None):
        (Path(repo or self.repo) / ".codex" / "review-scope.txt").write_bytes(text.encode("utf-8"))

    @property
    def container(self) -> Path:
        return self.root / rm.container_name(self.repo)

    def gens(self):
        return sorted(self.container.glob("gen-*")) if self.container.is_dir() else []

    def run_main(self, *extra, hook=None, repo=None, root=True, rc=None):
        calls = []
        buf = io.StringIO()
        argv = ["--repo", str(repo or self.repo)]
        if root:
            argv += ["--root", str(self.root)]
        argv += list(extra)
        if rc is None:
            side = lambda a, **kw: fake_robocopy(a, hook=hook, calls=calls)  # noqa: E731
        else:
            side = lambda a, **kw: (calls.append(list(a)), mock.Mock(returncode=rc, stdout="ERR", stderr=""))[1]  # noqa: E731
        with mock.patch.object(rm.subprocess, "run", side_effect=side) as run, redirect_stdout(buf):
            code = rm.main(argv)
        self.run_mock, self.calls = run, calls
        return code, buf.getvalue()

    def build_ok(self, **kw):
        code, out = self.run_main(**kw)
        self.assertEqual(code, 0, out)
        return Path(out.strip().splitlines()[-1].split("=", 1)[1])

    def verify(self, gen, repo=None):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rm.main(["--repo", str(repo or self.repo), "--root", str(self.root),
                            "--verify", str(gen)])
        return code, buf.getvalue()


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
        bad = [
            "/etc", "C:\\x", "C:x", "\\\\srv\\share\\x", "../up", "a/../b", "doku/.", "a/./b",
            "./.git/", "a//b",
            ".git", ".GIT/", "x/.git/", ".Git/config", ".git./", "x/.git./y", "x/.git /y",
            ".git::$INDEX_ALLOCATION", "GIT~1", "a~1/b", "a/b~2",
            "a/b./c", "a/b /c", "a:b", "a\x01b", "a\x7fb", "a*b", "a?b", "a|b", 'a"b', "a<b",
            ".env", ".ENV.local", ".env.local", "cfg/.env", "x/.envrc", "x/.env_local",
            "prod.env", "a/PROD.ENV", "a/.env/b", ".env.example/", ".env.example/x",
            ".env.example.local", "sub/.env.example.bak",
            "__pycache__/x", "a/__pycache__", ".pytest_cache", ".RUFF_CACHE/", ".playwright-mcp/x",
            "node_modules", "a/Node_Modules/b",
            ".review-mirror-receipt.json", "a/.review-mirror-receipt.json", "gen-1", "a/GEN-2026/b",
            ".lock", "a/.LOCK",
            "?", "?../x", "??x", "? ", "!",
        ]
        for b in bad:
            with self.subTest(bad=b), self.assertRaises(rm.ScopeError):
                rm.read_scope(b)

    def test_exclusions_follow_the_same_path_rule(self):
        for bad in ("doku/\n!doku/..\n", "doku/\n!doku/.git/\n", "doku/\n!doku/x:y\n",
                    "doku/\n!/doku/x\n", "doku/\n!\n"):
            with self.subTest(bad=bad), self.assertRaises(rm.ScopeError):
                rm.read_scope(bad)

    def test_env_templates_are_allowed_as_single_files(self):
        self.assertEqual(rm.read_scope(".env.example\nsub/.env.sample\n.ENV.TEMPLATE\n")[0],
                         [".env.example", "sub/.env.sample", ".ENV.TEMPLATE"])

    def test_exclusion_overrides_every_entry(self):
        for bad in ("doku/\n!doku/a/\ndoku/a/x.md\n",       # under an exclusion
                    "doku/\n!doku/a/\ndoku/a/\n",           # equal to one
                    "doku/a/x.md\ndoku/\n!doku/a/\n",       # order must not matter
                    "doku/\n!doku/a.md\ndoku/a.md\n",
                    "Doku/\n!Doku/A/\ndoku/a/x\n",          # case-insensitive
                    "doku/\n!doku/a/\n?doku/a/x\n"):
            with self.subTest(bad=bad), self.assertRaises(rm.ScopeError):
                rm.read_scope(bad)

    def test_optional_prefix_is_kept_and_checked(self):
        self.assertEqual(rm.read_scope("?src/\nAGENTS.md\n")[0], ["?src/", "AGENTS.md"])
        self.assertEqual(rm.read_scope("? src/\n")[0], ["?src/"])

    def test_empty_scope_is_refused(self):
        for bad in ("# nothing\n\n", "", "!doku/x\n"):
            with self.subTest(bad=bad), self.assertRaises(rm.ScopeError):
                rm.read_scope(bad)


class CaptureScope(Base):
    def test_reads_bytes_once(self):
        self.assertEqual(rm.capture_scope(self.repo), self.SCOPE.encode())

    def test_refusals(self):
        scope = self.repo / rm.SCOPE_FILE
        scope.unlink()
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.repo)                       # missing
        scope.mkdir()
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.repo)                       # directory
        scope.rmdir()
        scope.write_bytes(b"a" * (rm.MAX_SCOPE_BYTES + 1))
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.repo)                       # too large
        scope.write_bytes(b"\xff\xfe\x00bad")
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.repo)                       # not UTF-8

    def test_repo_root_that_is_a_link_is_refused(self):
        make_link(self.tmp / "linkrepo", self.repo)
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.tmp / "linkrepo")

    def test_repo_ancestor_that_is_a_link_is_refused(self):
        make_link(self.tmp / "linkparent", self.tmp)
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.tmp / "linkparent" / "repo")

    def test_codex_dir_that_is_a_link_is_refused(self):
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "review-scope.txt").write_text("doku/\n", encoding="utf-8")
        rm_all(self.repo / ".codex")
        make_link(self.repo / ".codex", elsewhere)
        with self.assertRaises(rm.ScopeError):
            rm.capture_scope(self.repo)


class Helpers(Base):
    def test_container_name_is_repo_name_plus_hash_of_realpath(self):
        real = os.path.realpath(self.repo)
        h = hashlib.sha256((real.lower() if IS_WIN else real).encode("utf-8", "surrogatepass")).hexdigest()[:12]
        self.assertEqual(rm.container_name(self.repo), f"repo-{h}")

    def test_same_name_other_checkout_gets_other_container(self):
        other = self.tmp / "b" / "repo"
        other.mkdir(parents=True)
        self.assertNotEqual(rm.container_name(self.repo), rm.container_name(other))
        self.assertTrue(re.fullmatch(r"repo-[0-9a-f]{12}", rm.container_name(other)))

    def test_default_root_is_under_the_profile(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.tmp / "lad")}):
            self.assertEqual(rm.default_root(), self.tmp / "lad" / "codex-review")

    def test_is_link_like(self):
        d = self.tmp / "d"
        d.mkdir()
        make_link(self.tmp / "l", d)
        self.assertTrue(rm.is_link_like(self.tmp / "l"))
        self.assertFalse(rm.is_link_like(d))
        self.assertFalse(rm.is_link_like(self.tmp / "missing"))


class Robocopy(unittest.TestCase):
    def test_dir_copy_argv(self):
        a = rm.robocopy_dir(Path("Q"), Path("Z"), xd=("Q/x",), xf=("Q/y.json",))
        self.assertIsInstance(a, list)
        self.assertEqual(a[0], "robocopy")
        self.assertIn("/E", a)
        self.assertIn("/XJ", a)
        self.assertNotIn("/MIR", a)
        self.assertNotIn("/PURGE", a)
        xd, xf = a.index("/XD"), a.index("/XF")
        for x in (".git", "__pycache__", ".playwright-mcp", "node_modules", "Q/x"):
            self.assertIn(x, a[xd:xf])
        for x in (".env*", "*.env", "Q/y.json"):
            self.assertIn(x, a[xf:])
        self.assertNotIn("/L", a)

    def test_dir_copy_excludes_every_name_validate_tree_forbids(self):
        # validate_tree refuses a .git FILE and an .env* DIRECTORY too: robocopy must not
        # copy them, or a submodule's gitlink fails the whole mirror (CodeRabbit 2026-11-03).
        a = rm.robocopy_dir(Path("Q"), Path("Z"))
        xd, xf = a.index("/XD"), a.index("/XF")
        for x in (".env*", "*.env"):
            self.assertIn(x, a[xd:xf])
        self.assertIn(".git", a[xf:])

    def test_file_copy_argv_has_xj_and_no_env_filter(self):
        a = rm.robocopy_file(Path("Q/.env.example"), Path("Z/.env.example"))
        self.assertIn("/XJ", a)
        self.assertNotIn("/XF", a)
        self.assertNotIn("/E", a)
        self.assertEqual(a[3], ".env.example")

    def test_check_only_lists(self):
        self.assertEqual(rm.robocopy_dir(Path("Q"), Path("Z"), check=True)[-1], "/L")
        self.assertEqual(rm.robocopy_file(Path("Q/a.md"), Path("Z/a.md"), check=True)[-1], "/L")


class Build(Base):
    def test_no_scope_file_copies_nothing(self):
        (self.repo / rm.SCOPE_FILE).unlink()
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertIn("nothing is mirrored", out)
        self.assertFalse(self.root.exists())

    def test_bad_scope_is_exit_2_without_copy(self):
        self.write_scope(".git/\n")
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_generation_published_with_receipt_and_mirror_line(self):
        code, out = self.run_main()
        self.assertEqual(code, 0, out)
        last = out.strip().splitlines()[-1]
        self.assertTrue(last.startswith("MIRROR="))
        gen = Path(last[len("MIRROR="):])
        self.assertEqual(gen.parent, self.container)
        self.assertTrue(re.fullmatch(r"gen-\d{8}T\d{6}-[0-9a-f]{8}", gen.name), gen.name)
        self.assertEqual(self.gens(), [gen])
        self.assertEqual((gen / "doku" / "sub" / "b.md").read_text(), "B")
        self.assertEqual((gen / "AGENTS.md").read_text(), "x")
        self.assertFalse((gen / ".env").exists())
        self.assertFalse((self.container / ".lock").exists(), "lock released")
        r = json.loads((gen / rm.RECEIPT).read_text(encoding="utf-8"))
        self.assertEqual(r["schema"], 1)
        self.assertEqual(r["repo"], os.path.realpath(self.repo))
        self.assertEqual(r["scope_sha256"], hashlib.sha256(self.SCOPE.encode()).hexdigest())
        self.assertEqual(r["entries"], ["doku/", "AGENTS.md"])
        self.assertEqual(r["skipped"], [])
        self.assertEqual(r["manifest"], {"AGENTS.md": hashlib.sha256(b"x").hexdigest(),
                                         "doku/a.md": hashlib.sha256(b"A").hexdigest(),
                                         "doku/sub/b.md": hashlib.sha256(b"B").hexdigest()})
        self.assertNotIn(rm.RECEIPT, r["manifest"], "receipt is not in its own manifest")
        self.assertTrue(out.isascii())

    def test_receipt_is_written_after_every_copy(self):
        seen = []
        def hook(src, dst, args):
            gen = next(p for p in [dst, *dst.parents] if p.name.startswith("gen-"))
            seen.append((gen / rm.RECEIPT).exists())
        self.build_ok(hook=hook)
        self.assertTrue(seen and not any(seen))

    def test_robocopy_is_called_with_a_list_no_shell_and_xj(self):
        self.build_ok()
        self.assertEqual(len(self.calls), 2)
        for c in self.run_mock.call_args_list:
            self.assertIsInstance(c.args[0], list)
            self.assertFalse(c.kwargs.get("shell"))
            self.assertIn("/XJ", c.args[0])
        gen = self.gens()[0]
        self.assertEqual(self.calls[0][1:3], [str(self.repo / "doku"), str(gen / "doku")])
        self.assertEqual(self.calls[1][1:4], [str(self.repo), str(gen), "AGENTS.md"])

    def test_exclusions_reach_robocopy_with_full_paths(self):
        (self.repo / "_scripte" / "kunden").mkdir(parents=True)
        (self.repo / "_scripte" / "kunden" / "k.txt").write_text("k", encoding="utf-8")
        (self.repo / "_scripte" / "databases.json").write_text("{}", encoding="utf-8")
        (self.repo / "_scripte" / "ok.py").write_text("1", encoding="utf-8")
        self.write_scope("_scripte/\n!_scripte/kunden/\n!_scripte/databases.json\n")
        gen = self.build_ok()
        args = self.calls[0]
        xd, xf = args.index("/XD"), args.index("/XF")
        self.assertIn(str(self.repo / "_scripte" / "kunden"), args[xd:xf])
        self.assertIn(str(self.repo / "_scripte" / "databases.json"), args[xf:])
        self.assertEqual(sorted(k.replace("\\", "/") for k in snapshot(gen)),
                         sorted(["_scripte/ok.py", rm.RECEIPT]))

    def test_submodule_gitlink_and_env_directory_stay_out(self):
        (self.repo / "doku" / "sub" / ".git").write_text("gitdir: ../../.git/modules/sub", encoding="utf-8")
        (self.repo / "doku" / ".env.d").mkdir()
        (self.repo / "doku" / ".env.d" / "k").write_text("secret", encoding="utf-8")
        (self.repo / "doku" / "prod.env").mkdir()
        (self.repo / "doku" / "prod.env" / "k").write_text("secret", encoding="utf-8")
        gen = self.build_ok()
        self.assertEqual(sorted(k.replace("\\", "/") for k in snapshot(gen)),
                         sorted(["AGENTS.md", "doku/a.md", "doku/sub/b.md", rm.RECEIPT]))

    def test_template_file_entry_is_copied_but_env_stays_out(self):
        (self.repo / ".env.example").write_text("K=", encoding="utf-8")
        (self.repo / "doku" / ".envrc").write_text("x", encoding="utf-8")
        self.write_scope("doku/\n.env.example\n")
        gen = self.build_ok()
        self.assertTrue((gen / ".env.example").is_file())
        self.assertFalse((gen / "doku" / ".envrc").exists())

    def test_missing_required_entry_is_exit_2_and_nothing_is_created(self):
        self.write_scope("doku/\nsrc/\n")
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn("src/", out)
        self.run_mock.assert_not_called()
        self.assertEqual(self.gens(), [])

    def test_optional_entries_may_be_absent_or_present(self):
        self.write_scope("doku/\n?src/\n?AGENTS.md\n")
        gen = self.build_ok()
        r = json.loads((gen / rm.RECEIPT).read_text(encoding="utf-8"))
        self.assertEqual(r["skipped"], ["src/"])
        self.assertEqual(r["entries"], ["doku/", "?src/", "?AGENTS.md"])
        self.assertTrue((gen / "AGENTS.md").is_file())
        self.assertEqual(self.verify(gen)[0], 0)

    def test_optional_present_at_selection_must_exist_in_generation(self):
        self.write_scope("doku/\n?AGENTS.md\n")
        def hook(src, dst, args):
            f = dst / "AGENTS.md"
            if f.exists():
                f.unlink()
        code, out = self.run_main(hook=hook)
        self.assertEqual(code, 1, out)
        self.assertEqual(self.gens(), [])

    def test_held_lock_is_exit_2_and_untouched(self):
        self.container.mkdir(parents=True)
        lock = self.container / ".lock"
        lock.write_text("someone", encoding="utf-8")
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertIn(str(lock), out)
        self.assertEqual(lock.read_text(encoding="utf-8"), "someone")
        self.assertEqual(self.gens(), [])

    def test_lock_released_after_robocopy_failure_and_nothing_remains(self):
        code, out = self.run_main(rc=8)
        self.assertEqual(code, 1)
        self.assertEqual(self.gens(), [])
        self.assertFalse((self.container / ".lock").exists())
        self.assertNotIn("MIRROR=", out)

    def test_failed_validation_deletes_the_generation(self):
        def inject_git(src, dst, args):
            (dst / ".git").mkdir(exist_ok=True)
            (dst / ".git" / "config").write_text("c", encoding="utf-8")
        def inject_env(src, dst, args):
            (dst / ".envrc").write_text("c", encoding="utf-8")
        def inject_dot_env_dir(src, dst, args):
            (dst / "x.env").write_text("c", encoding="utf-8")
        def inject_cache(src, dst, args):
            (dst / "__pycache__").mkdir(exist_ok=True)
        def inject_stray(src, dst, args):
            gen = next(p for p in [dst, *dst.parents] if p.name.startswith("gen-"))
            (gen / "stray.txt").write_text("c", encoding="utf-8")
        def inject_link(src, dst, args):
            outside = self.tmp / "outside"
            outside.mkdir(exist_ok=True)
            make_link(dst / "lnk", outside)
        def drop_file(src, dst, args):
            if (dst / "AGENTS.md").exists():
                (dst / "AGENTS.md").unlink()
        def drop_dir(src, dst, args):
            if dst.name == "doku":
                shutil.rmtree(dst)
        def reserved(src, dst, args):
            if dst.name == "doku":
                (dst / rm.RECEIPT).write_text("{}", encoding="utf-8")
        for name, hook in [("git", inject_git), ("envrc", inject_env), ("x.env", inject_dot_env_dir),
                           ("cache", inject_cache), ("stray", inject_stray), ("link", inject_link),
                           ("missing file", drop_file), ("missing dir", drop_dir),
                           ("reserved name", reserved)]:
            with self.subTest(name):
                code, out = self.run_main(hook=hook)
                self.assertEqual(code, 1, out)
                self.assertEqual(self.gens(), [], "the generation may contain the forbidden path")
                self.assertNotIn("MIRROR=", out)
                self.assertFalse((self.container / ".lock").exists())
                rm_all(self.container)

    def test_path_under_exclusion_in_generation_fails(self):
        (self.repo / "doku" / "priv").mkdir()
        (self.repo / "doku" / "priv" / "p.md").write_text("p", encoding="utf-8")
        self.write_scope("doku/\n!doku/priv/\n")
        def hook(src, dst, args):
            if dst.name == "doku":
                (dst / "priv").mkdir(exist_ok=True)
                (dst / "priv" / "p.md").write_text("p", encoding="utf-8")
        code, out = self.run_main(hook=hook)
        self.assertEqual(code, 1, out)
        self.assertEqual(self.gens(), [])

    def test_second_run_makes_a_second_generation_and_leaves_the_first(self):
        g1 = self.build_ok()
        before = snapshot(g1)
        g2 = self.build_ok()
        self.assertNotEqual(g1, g2)
        self.assertEqual(self.gens(), sorted([g1, g2]))
        self.assertEqual(snapshot(g1), before)

    def test_source_entry_that_is_a_link_is_refused(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "leak.md").write_text("leak", encoding="utf-8")
        make_link(self.repo / "lnk", outside)
        self.write_scope("lnk/\n")
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertEqual(self.gens(), [])

    def test_source_ancestor_that_is_a_link_is_refused(self):
        outside = self.tmp / "outside"
        (outside / "sub").mkdir(parents=True)
        (outside / "sub" / "leak.md").write_text("leak", encoding="utf-8")
        make_link(self.repo / "lnk", outside)
        for scope in ("lnk/sub/\n", "lnk/sub/leak.md\n", "?lnk/sub/leak.md\n"):
            with self.subTest(scope=scope):
                self.write_scope(scope)
                code, out = self.run_main()
                self.assertEqual(code, 2, out)
                self.run_mock.assert_not_called()

    def test_repo_root_that_is_a_link_is_refused_in_every_mode(self):
        make_link(self.tmp / "linkrepo", self.repo)
        for extra in ((), ("--check",), ("--prune",), ("--verify", str(self.tmp / "x"))):
            with self.subTest(extra=extra):
                code, out = self.run_main(*extra, repo=self.tmp / "linkrepo")
                self.assertEqual(code, 2, out)
                self.run_mock.assert_not_called()
                self.assertFalse(self.root.exists())

    def test_select_refuses_a_link_repo_root_itself(self):
        make_link(self.tmp / "linkrepo", self.repo)
        with self.assertRaises(rm.Refused):
            rm.select(self.tmp / "linkrepo", ["doku/"])

    def test_directory_exclusion_without_trailing_slash_goes_to_xd(self):
        for spelling in ("!doku/sub", "!doku/sub/"):
            with self.subTest(spelling=spelling):
                self.write_scope(f"doku/\n{spelling}\n")
                gen = self.build_ok()
                args = self.calls[0]
                xd, xf = args.index("/XD"), args.index("/XF")
                self.assertIn(str(self.repo / "doku" / "sub"), args[xd:xf])
                self.assertNotIn(str(self.repo / "doku" / "sub"), args[xf:])
                self.assertFalse((gen / "doku" / "sub").exists())
                self.assertEqual(self.verify(gen)[0], 0)
                rm_all(self.container)

    def test_exclusion_prefix_does_not_leak_into_a_sibling_entry(self):
        (self.repo / "doku2" / "sub").mkdir(parents=True)
        (self.repo / "doku2" / "keep.md").write_text("k", encoding="utf-8")
        (self.repo / "doku2" / "sub" / "c.md").write_text("c", encoding="utf-8")
        self.write_scope("doku\ndoku2/\n!doku2/sub/\n")
        self.build_ok()
        self.assertNotIn(str(self.repo / "doku2" / "sub"), self.calls[0])

    def test_root_overlapping_the_repo_is_refused(self):
        for root in (self.repo / "mirror", self.repo, self.tmp):
            with self.subTest(root=str(root)):
                self.root = root
                code, out = self.run_main()
                self.assertEqual(code, 2)
                self.run_mock.assert_not_called()

    def test_root_that_is_a_link_is_refused(self):
        real = self.tmp / "real-root"
        real.mkdir()
        make_link(self.tmp / "linkroot", real)
        self.root = self.tmp / "linkroot"
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertEqual(list(real.iterdir()), [])

    def test_root_ancestor_that_is_a_link_is_refused(self):
        real = self.tmp / "real-parent"
        real.mkdir()
        make_link(self.tmp / "linkparent", real)
        self.root = self.tmp / "linkparent" / "codex-review"
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertEqual(list(real.iterdir()), [])

    def test_container_that_is_a_link_is_refused(self):
        real = self.tmp / "real-container"
        real.mkdir()
        self.root.mkdir()
        make_link(self.container, real)
        code, out = self.run_main()
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()
        self.assertEqual(list(real.iterdir()), [])

    def test_check_mode_lists_and_publishes_nothing(self):
        code, out = self.run_main("--check", rc=1)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.calls), 2)
        for c in self.calls:
            self.assertEqual(c[-1], "/L")
            self.assertIn("/XJ", c)
        self.assertFalse(self.root.exists())
        self.assertNotIn("MIRROR=", out)
        self.assertIn("nothing published", out)

    def test_check_mode_still_refuses_a_missing_required_entry(self):
        self.write_scope("doku/\nsrc/\n")
        code, out = self.run_main("--check")
        self.assertEqual(code, 2)
        self.run_mock.assert_not_called()

    def test_default_root_is_used_without_root_option(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": str(self.tmp / "lad"),
                                          "XDG_DATA_HOME": str(self.tmp / "lad")}):
            self.root = rm.default_root()
            gen = self.build_ok(root=False)
        self.assertTrue(str(gen).startswith(str(self.tmp / "lad")))


class LockDiagnostics(Base):
    def test_windows_never_reads_the_holder(self):
        lock = self.tmp / "l"
        lock.write_text("secret holder", encoding="utf-8")
        with mock.patch.object(rm, "os", wraps=os) as fake_os, \
                mock.patch.object(rm.os, "name", "nt"), \
                mock.patch("builtins.open", side_effect=AssertionError("open")), \
                mock.patch.object(fake_os, "open", side_effect=AssertionError("os.open")):
            self.assertEqual(rm.lock_holder_text(lock), "(holder not shown)")

    @unittest.skipIf(IS_WIN, "POSIX lock reader")
    def test_posix_regular_file_is_shown_bounded(self):
        lock = self.tmp / "l"
        lock.write_text("review_mirror pid=1 now", encoding="utf-8")
        self.assertEqual(rm.lock_holder_text(lock), "review_mirror pid=1 now")
        lock.write_bytes(b"a" * 10_000_000)
        self.assertLessEqual(len(rm.lock_holder_text(lock)), 200)

    @unittest.skipIf(IS_WIN, "POSIX lock reader")
    def test_posix_large_lock_is_never_read_beyond_200_bytes(self):
        lock = self.tmp / "big"
        lock.write_bytes(b"a" * 10_000_000)
        requested, consumed, opened = [], [], []
        real_read, real_open = os.read, os.open

        def spy_read(fd, n):
            requested.append(n)
            data = real_read(fd, n)
            consumed.append(len(data))
            return data

        def spy_open(path, *a, **kw):
            opened.append(os.fspath(path))
            return real_open(path, *a, **kw)

        def no_buffered(*a, **kw):
            raise AssertionError("buffered read of the lock file")

        with mock.patch.object(os, "read", spy_read), mock.patch.object(os, "open", spy_open), \
                mock.patch.object(os, "fdopen", no_buffered), \
                mock.patch("builtins.open", side_effect=AssertionError("builtins.open on the lock")):
            text = rm.lock_holder_text(lock)
        self.assertEqual(opened, [str(lock)])
        self.assertTrue(requested, "the holder text must come from os.read")
        self.assertLessEqual(sum(requested), 200, "asked the kernel for more than 200 bytes")
        self.assertLessEqual(sum(consumed), 200, "consumed more than 200 bytes")
        self.assertLessEqual(len(text), 200)

    @unittest.skipIf(IS_WIN, "POSIX lock reader")
    def test_posix_symlink_fifo_hardlink_are_not_read(self):
        target = self.tmp / "t"
        target.write_text("secret", encoding="utf-8")
        link = self.tmp / "sl"
        os.symlink(target, link)
        self.assertEqual(rm.lock_holder_text(link), "(holder not shown)")
        fifo = self.tmp / "fifo"
        os.mkfifo(fifo)
        self.assertEqual(rm.lock_holder_text(fifo), "(holder not shown)")
        hl = self.tmp / "hl"
        os.link(target, hl)
        self.assertEqual(rm.lock_holder_text(hl), "(holder not shown)")


class Verify(Base):
    def test_fresh_generation_verifies(self):
        gen = self.build_ok()
        code, out = self.verify(gen)
        self.assertEqual(code, 0, out)
        self.assertTrue(out.isascii())

    def test_changed_extra_and_missing_files_fail(self):
        for name, mutate in [
            ("changed", lambda g: (g / "doku" / "a.md").write_text("EVIL", encoding="utf-8")),
            ("extra", lambda g: (g / "doku" / "new.md").write_text("n", encoding="utf-8")),
            ("extra root", lambda g: (g / "stray.md").write_text("n", encoding="utf-8")),
            ("missing", lambda g: (g / "AGENTS.md").unlink()),
            ("forbidden", lambda g: (g / "doku" / ".envrc").write_text("n", encoding="utf-8")),
            ("git", lambda g: (g / "doku" / ".git").mkdir()),
        ]:
            with self.subTest(name):
                gen = self.build_ok()
                mutate(gen)
                self.assertEqual(self.verify(gen)[0], 1)

    def test_directory_replaced_by_a_link_fails(self):
        gen = self.build_ok()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "b.md").write_text("B", encoding="utf-8")
        rm_all(gen / "doku" / "sub")
        make_link(gen / "doku" / "sub", outside)
        self.assertEqual(self.verify(gen)[0], 1)

    @unittest.skipIf(IS_WIN, "file symlinks need a privilege on Windows")
    def test_file_replaced_by_symlink_fails(self):
        gen = self.build_ok()
        (gen / "AGENTS.md").unlink()
        os.symlink(self.repo / "AGENTS.md", gen / "AGENTS.md")
        self.assertEqual(self.verify(gen)[0], 1)

    def test_generation_that_is_a_link_fails(self):
        gen = self.build_ok()
        make_link(self.container / "gen-20990101T000000-deadbeef", gen)
        self.assertEqual(self.verify(self.container / "gen-20990101T000000-deadbeef")[0], 1)

    def test_other_repo_fails(self):
        gen = self.build_ok()
        repo2 = self.tmp / "repo2"
        (repo2 / ".codex").mkdir(parents=True)
        self.write_scope(self.SCOPE, repo=repo2)
        (repo2 / "doku").mkdir()
        (repo2 / "AGENTS.md").write_text("x", encoding="utf-8")
        code, out = self.verify(gen, repo=repo2)
        self.assertEqual(code, 1, out)

    def test_changed_scope_hash_fails(self):
        gen = self.build_ok()
        self.write_scope(self.SCOPE + "# comment\n")
        self.assertEqual(self.verify(gen)[0], 1)

    def test_receipt_defects_fail(self):
        def rewrite(g, fn):
            p = g / rm.RECEIPT
            d = json.loads(p.read_text(encoding="utf-8"))
            fn(d)
            p.write_text(json.dumps(d), encoding="utf-8")
        cases = {
            "missing": lambda g: (g / rm.RECEIPT).unlink(),
            "not json": lambda g: (g / rm.RECEIPT).write_text("{nope", encoding="utf-8"),
            "schema": lambda g: rewrite(g, lambda d: d.update(schema=2)),
            "manifest hash": lambda g: rewrite(g, lambda d: d["manifest"].update({"AGENTS.md": "0" * 64})),
            "manifest extra": lambda g: rewrite(g, lambda d: d["manifest"].update({"ghost.md": "0" * 64})),
            "manifest missing": lambda g: rewrite(g, lambda d: d["manifest"].pop("AGENTS.md")),
            "oversized": lambda g: (g / rm.RECEIPT).write_bytes(b" " * (rm.MAX_RECEIPT_BYTES + 1)),
            "directory": lambda g: (os.unlink(g / rm.RECEIPT), (g / rm.RECEIPT).mkdir()),
            "hard link": lambda g: os.link(g / rm.RECEIPT, self.tmp / "receipt-alias"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                gen = self.build_ok()
                mutate(gen)
                self.assertEqual(self.verify(gen)[0], 1)

    def test_entry_types_in_the_receipt_are_required_and_checked(self):
        def rewrite(g, fn):
            p = g / rm.RECEIPT
            d = json.loads(p.read_text(encoding="utf-8"))
            fn(d)
            p.write_text(json.dumps(d), encoding="utf-8")
        cases = {
            "missing": lambda d: d.pop("entry_types"),
            "not a dict": lambda d: d.update(entry_types=["doku/"]),
            "wrong type": lambda d: d["entry_types"].update({"doku/": "file"}),
            "unknown value": lambda d: d["entry_types"].update({"AGENTS.md": "other"}),
            "entry absent": lambda d: d["entry_types"].pop("AGENTS.md"),
        }
        for name, fn in cases.items():
            with self.subTest(name):
                gen = self.build_ok()
                rewrite(gen, lambda d: fn(d))
                self.assertEqual(self.verify(gen)[0], 1)

    def test_container_that_is_a_link_is_refused_in_verify(self):
        gen = self.build_ok()
        moved = self.tmp / "moved"
        shutil.move(str(self.container), str(moved))
        make_link(self.container, moved)
        self.assertEqual(self.verify(self.container / gen.name)[0], 1)


class Prune(Base):
    def prune(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rm.main(["--repo", str(self.repo), "--root", str(self.root), "--prune"])
        return code, buf.getvalue()

    def test_keeps_only_the_newest_verified_generation(self):
        gens = [self.build_ok() for _ in range(3)]
        code, out = self.prune()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.gens(), [gens[-1]])
        self.assertEqual(self.verify(gens[-1])[0], 0)
        self.assertFalse((self.container / ".lock").exists())
        self.assertTrue(out.isascii())

    def test_same_second_generations_are_ordered_by_creation_not_by_name(self):
        fixed = datetime.datetime(2026, 11, 2, 12, 0, 0, tzinfo=datetime.timezone.utc)
        suffixes = iter(["ffffffff", "00000000", "80000000"])   # name order is the opposite of creation
        with mock.patch.object(rm, "_utc_now", return_value=fixed), \
                mock.patch.object(rm.secrets, "token_hex", side_effect=lambda n: next(suffixes)):
            gens = [self.build_ok() for _ in range(3)]
        self.assertGreater(gens[0].name, gens[2].name, "the fixture must invert name order")
        code, out = self.prune()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.gens(), [gens[2]], "the generation built last must survive")

    def test_creation_order_survives_a_frozen_clock(self):
        fixed = datetime.datetime(2026, 11, 2, 12, 0, 0, tzinfo=datetime.timezone.utc)
        suffixes = iter(["ffffffff", "00000000"])
        with mock.patch.object(rm, "_utc_now", return_value=fixed), \
                mock.patch("time.time_ns", return_value=1_700_000_000_000_000_000), \
                mock.patch.object(rm.secrets, "token_hex", side_effect=lambda n: next(suffixes)):
            gens = [self.build_ok() for _ in range(2)]
        ns = [json.loads((g / rm.RECEIPT).read_text(encoding="utf-8"))["created_ns"] for g in gens]
        self.assertLess(ns[0], ns[1], "created_ns must be strictly increasing within one container")
        self.assertEqual(self.prune()[0], 0)
        self.assertEqual(self.gens(), [gens[1]])

    def test_entry_without_trailing_slash_builds_verifies_and_prunes(self):
        self.write_scope("doku\nAGENTS.md\n")
        g1 = self.build_ok()
        g2 = self.build_ok()
        r = json.loads((g2 / rm.RECEIPT).read_text(encoding="utf-8"))
        self.assertEqual(r["entry_types"], {"doku": "dir", "AGENTS.md": "file"})
        code, vout = self.verify(g2)
        self.assertEqual(code, 0, vout)
        code, out = self.prune()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.gens(), [g2])
        self.assertNotIn(g1, self.gens())

    def test_newest_unverifiable_keeps_the_newest_verified_one(self):
        g = [self.build_ok() for _ in range(3)]
        newest = g[-1]
        (newest / "AGENTS.md").write_text("tampered", encoding="utf-8")
        older = g[:-1]
        code, out = self.prune()
        self.assertEqual(code, 0, out)
        self.assertIn(older[-1], self.gens())
        self.assertNotIn(older[0], self.gens())

    def test_nothing_verified_deletes_nothing(self):
        g = [self.build_ok() for _ in range(2)]
        for x in g:
            (x / "AGENTS.md").write_text("tampered", encoding="utf-8")
        code, out = self.prune()
        self.assertEqual(code, 1)
        self.assertEqual(self.gens(), sorted(g))

    def test_foreign_entries_are_left_alone(self):
        g = [self.build_ok() for _ in range(2)]
        (self.container / "notes.txt").write_text("n", encoding="utf-8")
        (self.container / "foo").mkdir()
        (self.container / "gen-20200101T000000-00000000").mkdir()          # no receipt
        alien = self.container / "gen-20200101T000001-11111111"             # another repo's receipt
        shutil.copytree(g[-1], alien)
        d = json.loads((alien / rm.RECEIPT).read_text(encoding="utf-8"))
        d["repo"] = str(self.tmp / "other")
        (alien / rm.RECEIPT).write_text(json.dumps(d), encoding="utf-8")
        other = self.root / "other-container"
        other.mkdir()
        (other / "gen-20200101T000000-22222222").mkdir()
        code, out = self.prune()
        self.assertEqual(code, 0, out)
        names = {p.name for p in self.container.iterdir()}
        self.assertTrue({"notes.txt", "foo", "gen-20200101T000000-00000000", alien.name} <= names)
        self.assertIn(g[-1].name, names)
        self.assertNotIn(g[0].name, names)
        self.assertTrue((other / "gen-20200101T000000-22222222").is_dir())

    def test_held_lock_is_exit_2_and_deletes_nothing(self):
        g = [self.build_ok() for _ in range(2)]
        (self.container / ".lock").write_text("busy", encoding="utf-8")
        code, out = self.prune()
        self.assertEqual(code, 2)
        self.assertEqual(self.gens(), sorted(g))

    def test_link_entries_are_not_followed(self):
        for _ in range(2):
            self.build_ok()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        make_link(self.container / "gen-20200101T000000-33333333", outside)
        code, out = self.prune()
        self.assertEqual(code, 0, out)
        self.assertTrue((outside / "keep.txt").is_file())

    def test_container_that_is_a_link_is_refused(self):
        self.build_ok()
        moved = self.tmp / "moved"
        shutil.move(str(self.container), str(moved))
        make_link(self.container, moved)
        n = len(list(moved.iterdir()))
        code, out = self.prune()
        self.assertEqual(code, 2)
        self.assertEqual(len(list(moved.iterdir())), n)

    def test_no_container_is_not_an_error(self):
        code, out = self.prune()
        self.assertEqual(code, 0, out)

    def _set_stamp(self, gen, value, drop=False):
        p = gen / rm.RECEIPT
        d = json.loads(p.read_text(encoding="utf-8"))
        if drop:
            d.pop("created_ns")
        else:
            d["created_ns"] = value
        p.write_text(json.dumps(d), encoding="utf-8")

    def test_verify_requires_a_positive_int_created_ns(self):
        cases = {"missing": (None, True), "string": ("123", False), "bool": (True, False),
                 "negative": (-5, False), "zero": (0, False), "float": (1.5, False)}
        for name, (val, drop) in cases.items():
            with self.subTest(name):
                gen = self.build_ok()
                self._set_stamp(gen, val, drop=drop)
                code, out = self.verify(gen)
                self.assertEqual(code, 1, out)
                self.assertIn("created_ns", out)

    def test_prune_refuses_a_candidate_without_a_valid_stamp(self):
        cases = {"missing": (None, True), "string": ("999", False), "bool": (True, False),
                 "negative": (-1, False)}
        for name, (val, drop) in cases.items():
            with self.subTest(name):
                rm_all(self.container)
                g = [self.build_ok() for _ in range(2)]
                self._set_stamp(g[-1], val, drop=drop)    # the newest one loses its stamp
                code, out = self.prune()
                self.assertEqual(code, 1, out)
                self.assertEqual(self.gens(), sorted(g), "nothing may be deleted")

    def test_prune_refuses_equal_stamps_among_verified_generations(self):
        g = [self.build_ok() for _ in range(2)]
        for x in g:
            self._set_stamp(x, 1_700_000_000_000_000_000)
        code, out = self.prune()
        self.assertEqual(code, 1, out)
        self.assertEqual(self.gens(), sorted(g), "nothing may be deleted")


class GenerationLinks(Base):
    def test_linked_generation_refuses_the_build_without_reading_its_target(self):
        self.build_ok()
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / rm.RECEIPT).write_text(json.dumps({"schema": rm.SCHEMA, "created_ns": 2 ** 62}),
                                          encoding="utf-8")
        link = self.container / "gen-20990101T000000-cafebabe"
        make_link(link, outside)
        touched = []
        # the link itself may be lstat'ed (that is how it is recognised); anything below it,
        # or anything at its target, may not be touched
        marks = [os.path.normcase(str(link)) + os.sep, os.path.normcase(str(outside))]

        def watch(real):
            def inner(path, *a, **kw):
                try:
                    s = os.path.normcase(os.fsdecode(os.fspath(path)))
                except TypeError:
                    s = ""
                if any(s.startswith(m) for m in marks):
                    touched.append(s)
                return real(path, *a, **kw)
            return inner

        before = self.gens()
        import builtins
        with mock.patch.object(builtins, "open", watch(builtins.open)), \
                mock.patch.object(rm.os, "open", watch(os.open)), \
                mock.patch.object(rm.os, "lstat", watch(os.lstat)), \
                mock.patch.object(rm.os, "stat", watch(os.stat)):
            code, out = self.run_main()
        self.assertEqual(code, 2, out)
        self.assertEqual(touched, [], "the receipt behind a linked generation must never be opened")
        self.assertEqual(self.gens(), before, "no new generation may be published")
        self.assertTrue((outside / rm.RECEIPT).is_file())


class ReviewFindings(Base):
    """Final-review findings M1-M8: check probe link, nested JSON, lock init, OSError mapping, hardlinks."""

    def test_check_mode_refuses_a_linked_probe_without_running_robocopy(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        self.container.mkdir(parents=True)
        make_link(self.container / "gen-check", outside)
        code, out = self.run_main("--check")
        self.assertEqual(code, 2, out)
        self.run_mock.assert_not_called()
        self.assertEqual(os.listdir(outside), [])

    def test_deeply_nested_receipt_is_an_invalid_receipt_not_a_crash(self):
        gen = self.build_ok()
        (gen / rm.RECEIPT).write_bytes(b"[" * 100000)
        self.assertLess(100000, rm.MAX_RECEIPT_BYTES)
        rec, why = rm._read_receipt(gen)
        self.assertIsNone(rec)
        code, out = self.verify(gen)
        self.assertEqual(code, 1, out)

    def test_deeply_nested_receipt_does_not_break_build_or_prune(self):
        g1 = self.build_ok()
        (g1 / rm.RECEIPT).write_bytes(b"[" * 100000)
        g2 = self.build_ok()                      # created_ns search reads every receipt
        self.assertTrue((g2 / rm.RECEIPT).is_file())
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rm.main(["--repo", str(self.repo), "--root", str(self.root), "--prune"])
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn(g1, self.gens(), "an unattributable generation is left alone")

    def test_lock_holder_write_failure_cleans_up_and_refuses(self):
        self.container.mkdir(parents=True)
        closed = []
        real_close = os.close

        def spy_close(fd):
            closed.append(fd)
            return real_close(fd)

        with mock.patch.object(rm.os, "write", side_effect=OSError("disk full")), \
                mock.patch.object(rm.os, "close", side_effect=spy_close):
            lock = rm._Lock(self.container)
            with self.assertRaises(rm.Refused):
                lock.__enter__()
        self.assertEqual(len(closed), 1, "the lock fd must be closed")
        self.assertFalse((self.container / rm.LOCK_NAME).exists(), "the half-made lock must be removed")
        with rm._Lock(self.container):            # a later run is not blocked
            pass

    def test_lock_holder_write_failure_is_a_controlled_exit(self):
        with mock.patch.object(rm.os, "write", side_effect=OSError("disk full")):
            code, out = self.run_main()
        self.assertEqual(code, 2, out)
        self.assertFalse((self.container / rm.LOCK_NAME).exists())
        self.assertEqual(self.gens(), [])

    def test_unreadable_scope_file_is_a_refusal_not_a_traceback(self):
        with mock.patch.object(rm, "open", side_effect=PermissionError("denied"), create=True):
            code, out = self.run_main()
        self.assertEqual(code, 2, out)
        self.run_mock.assert_not_called()

    def test_missing_robocopy_is_a_failure_with_cleanup(self):
        buf = io.StringIO()
        with mock.patch.object(rm.subprocess, "run", side_effect=FileNotFoundError("robocopy")), \
                redirect_stdout(buf):
            code = rm.main(["--repo", str(self.repo), "--root", str(self.root)])
        self.assertEqual(code, 1, buf.getvalue())
        self.assertEqual(self.gens(), [], "the half-made generation must be deleted")
        self.assertFalse((self.container / rm.LOCK_NAME).exists())
        self.assertTrue(buf.getvalue().isascii())

    def test_unwritable_receipt_is_a_failure_with_cleanup(self):
        real_open = os.open

        def deny_receipt(path, *a, **kw):
            if os.fspath(path).endswith(rm.RECEIPT):
                raise PermissionError("denied")
            return real_open(path, *a, **kw)

        with mock.patch.object(rm.os, "open", side_effect=deny_receipt):
            code, out = self.run_main()
        self.assertEqual(code, 1, out)
        self.assertEqual(self.gens(), [])
        self.assertFalse((self.container / rm.LOCK_NAME).exists())

    def _hardlinked_old_generation(self, external_mode):
        external = self.tmp / "external.txt"
        external.write_text("external", encoding="utf-8")
        os.chmod(external, external_mode)
        g1 = self.build_ok()
        g2 = self.build_ok()
        victim = g1 / "AGENTS.md"
        os.chmod(victim, 0o600)
        os.unlink(victim)
        os.link(external, victim)
        return external, g1, g2

    def _prune(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rm.main(["--repo", str(self.repo), "--root", str(self.root), "--prune"])
        return code, buf.getvalue()

    def test_prune_never_changes_metadata_of_a_hardlinked_external_file(self):
        external, g1, g2 = self._hardlinked_old_generation(0o640)
        before = os.lstat(external)
        code, out = self._prune()
        self.assertEqual(code, 0, out)
        after = os.lstat(external)
        self.assertEqual(after.st_mode, before.st_mode)
        self.assertEqual(getattr(after, "st_file_attributes", 0), getattr(before, "st_file_attributes", 0))
        self.assertEqual(external.read_text(encoding="utf-8"), "external")
        self.assertEqual(self.gens(), [g2])

    def test_prune_refuses_rather_than_clearing_a_readonly_hardlink(self):
        external, g1, g2 = self._hardlinked_old_generation(0o444)
        before = os.lstat(external)
        code, out = self._prune()
        after = os.lstat(external)
        self.assertEqual(after.st_mode, before.st_mode, "prune must not chmod a shared inode")
        self.assertEqual(getattr(after, "st_file_attributes", 0), getattr(before, "st_file_attributes", 0))
        self.assertEqual(external.read_text(encoding="utf-8"), "external")
        if IS_WIN:
            self.assertEqual(code, 1, out)         # unlink of a readonly file needs an attribute change
            self.assertIn(g1, self.gens())
        else:
            self.assertEqual(code, 0, out)         # unlink needs no file permission on POSIX
        os.chmod(external, 0o600)


@unittest.skipUnless(IS_WIN and shutil.which("robocopy"), "needs the real robocopy on Windows")
class RealRobocopy(Base):
    SCOPE = "listed/\n.env.example\n!listed/skip/\n"

    def setUp(self):
        super().setUp()
        (self.repo / "listed" / "skip").mkdir(parents=True)
        (self.repo / "listed" / "skip" / "s.txt").write_text("s", encoding="utf-8")
        (self.repo / "listed" / "sub").mkdir()
        (self.repo / "listed" / "sub" / "keep.txt").write_text("k", encoding="utf-8")
        (self.repo / "listed" / "a.txt").write_text("a", encoding="utf-8")
        (self.repo / "listed" / ".envrc").write_text("x", encoding="utf-8")
        (self.repo / "listed" / ".env").write_text("x", encoding="utf-8")
        (self.repo / "listed" / "prod.env").write_text("x", encoding="utf-8")
        (self.repo / "listed" / "__pycache__").mkdir()
        (self.repo / "listed" / "__pycache__" / "c.pyc").write_text("x", encoding="utf-8")
        (self.repo / "listed" / ".git").mkdir()
        (self.repo / "listed" / ".git" / "config").write_text("x", encoding="utf-8")
        (self.repo / ".env.example").write_text("K=", encoding="utf-8")
        self.outside = self.tmp / "outside"
        self.outside.mkdir()
        (self.outside / "leak.txt").write_text("leak", encoding="utf-8")
        make_link(self.repo / "listed" / "jx", self.outside)
        self.write_scope(self.SCOPE)

    def real_main(self, *extra):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = rm.main(["--repo", str(self.repo), "--root", str(self.root), *extra])
        return code, buf.getvalue()

    def test_real_run(self):
        code, out = self.real_main()
        self.assertEqual(code, 0, out)
        gen = Path(out.strip().splitlines()[-1].split("=", 1)[1])
        found = sorted(k.replace("\\", "/") for k in snapshot(gen))
        self.assertEqual(found, sorted([".env.example", "listed/a.txt", "listed/sub/keep.txt", rm.RECEIPT]))
        self.assertFalse((gen / "listed" / "jx").exists())
        code, vout = self.verify(gen)
        self.assertEqual(code, 0, vout)
        first = snapshot(gen)
        code, out2 = self.real_main()
        self.assertEqual(code, 0, out2)
        gen2 = Path(out2.strip().splitlines()[-1].split("=", 1)[1])
        self.assertNotEqual(gen, gen2)
        self.assertEqual(self.gens(), sorted([gen, gen2]))
        self.assertEqual(snapshot(gen), first)
        self.assertTrue((self.outside / "leak.txt").is_file())
        code, pout = self.real_main("--prune")
        self.assertEqual(code, 0, pout)
        self.assertEqual(self.gens(), [gen2])
        self.assertTrue((self.outside / "leak.txt").is_file(), "prune must not follow links")


if __name__ == "__main__":
    unittest.main()
