#!/usr/bin/env python3
"""Tests for the read-only Codex wrapper.

Stdlib unittest on purpose: this suite has to run on a fresh macOS or Windows
machine with nothing installed but Python, because that is exactly the situation
a repo is in right after `tools/codex_ro.py` was copied into it.

Nothing here starts Codex. What is tested is the part that has to hold before
Codex is ever reached: the refusals. The live behaviour of the sandbox itself is
a measurement, recorded in the wrapper's module docstring, not a unit test.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import warnings
import unittest.mock
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import codex_ro  # noqa: E402


class ConfigOverrideTests(unittest.TestCase):
    """The wrapper's whole reason to exist: no override may touch the sandbox."""

    def test_each_forbidden_key_is_refused(self):
        for key in codex_ro.FORBIDDEN_CONFIG_KEYS:
            with self.subTest(key=key):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_config_overrides([f"{key}=whatever"])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_dotted_child_keys_are_refused(self):
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_config_overrides(["sandbox_workspace_write.network_access=true"])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_surrounding_whitespace_does_not_hide_the_key(self):
        with self.assertRaises(SystemExit):
            codex_ro.check_config_overrides(["  sandbox_mode  =danger-full-access"])

    def test_a_lookalike_key_is_not_refused(self):
        # sandbox_mode_note is a different key; refusing it would be a false positive.
        codex_ro.check_config_overrides(["sandbox_mode_note=hello", "model_verbosity=low"])


class ArgvTests(unittest.TestCase):
    """What actually reaches Codex on each of the two paths."""

    def _args(self, extra=None):
        return codex_ro.parse_args(["--prompt", "x", "--out-file", "out.txt"] + (extra or []))

    def test_exec_path_pins_read_only_with_dash_s(self):
        argv = codex_ro.build_argv(self._args(), Path("out.txt"))
        self.assertIn("-s", argv)
        self.assertEqual(argv[argv.index("-s") + 1], "read-only")

    def test_resume_path_pins_read_only_via_config(self):
        # resume knows no -s; read-only is reachable only through -c there.
        argv = codex_ro.build_argv(self._args(["--resume", "01a047d5-4e4b-7662-8672-0ccbf2f514f0"]), Path("out.txt"))
        self.assertNotIn("-s", argv)
        self.assertIn("sandbox_mode=read-only", argv)

    def test_resume_path_names_sandbox_mode_exactly_once(self):
        # A later -c beats an earlier one, so a second occurrence would decide.
        argv = codex_ro.build_argv(self._args(["--resume", "01a047d5-4e4b-7662-8672-0ccbf2f514f0"]), Path("out.txt"))
        occurrences = [a for a in argv if a.startswith("sandbox_mode=")]
        self.assertEqual(occurrences, ["sandbox_mode=read-only"])

    def test_emptying_disable_mcp_is_refused_when_servers_are_configured(self):
        """The third door to the same room as --allow-path and -c mcp_servers.

        Codex runs MCP servers outside the sandbox, so an empty --disable-mcp is
        a caller weakening the wrapper from its own command line. It used to warn
        and continue; nobody reads stderr on a call that succeeded.
        (CodeRabbit, 2026-08-30.)
        """
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "config.toml").write_text(
                "[mcp_servers]\n[mcp_servers.n8n]\ntransport='http'\n", encoding="utf-8"
            )
            previous = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = home
            try:
                with self.assertRaises(SystemExit) as caught:
                    self._args(["--disable-mcp", ""])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
            finally:
                if previous is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = previous

    def test_emptying_disable_mcp_is_fine_when_there_are_no_servers(self):
        """Nothing to leave enabled, so nothing to refuse."""
        with tempfile.TemporaryDirectory() as home:
            previous = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = home
            try:
                argv = codex_ro.build_argv(self._args(["--disable-mcp", ""]), Path("out.txt"))
                self.assertFalse([a for a in argv if a.startswith("mcp_servers.")])
            finally:
                if previous is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = previous

    def test_prompt_is_never_passed_as_an_argument(self):
        # It goes over stdin; an argument would also have to be quoted, and the
        # missing EOF would hang codex exec under a non-interactive driver.
        argv = codex_ro.build_argv(self._args(), Path("out.txt"))
        self.assertNotIn("x", argv)


class PathConfinementTests(unittest.TestCase):
    """--out-file is deleted before the run, so an unbounded path is a write primitive."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_a_path_inside_a_root_is_accepted(self):
        target = self.root / "sub" / "verdict.txt"
        self.assertEqual(codex_ro.resolve_in_roots(str(target), [self.root], "--out-file"), target)

    def test_a_path_outside_every_root_is_refused(self):
        outside = Path(tempfile.gettempdir()).resolve() / "elsewhere" / "verdict.txt"
        with self.assertRaises(SystemExit) as caught:
            codex_ro.resolve_in_roots(str(outside), [self.root], "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_dot_dot_cannot_climb_out_of_a_root(self):
        with self.assertRaises(SystemExit):
            codex_ro.resolve_in_roots(str(self.root / ".." / "escaped.txt"), [self.root], "--out-file")

    def test_a_sibling_with_a_shared_prefix_is_not_inside(self):
        # String prefix matching would accept `<root>-evil`; path matching must not.
        sibling = Path(str(self.root) + "-evil") / "verdict.txt"
        with self.assertRaises(SystemExit):
            codex_ro.resolve_in_roots(str(sibling), [self.root], "--out-file")

    def test_the_repo_and_the_temp_dir_are_roots_by_default(self):
        roots = codex_ro.allowed_roots([])
        self.assertIn(Path(tempfile.gettempdir()).resolve(), roots)
        self.assertTrue(any((r / ".git").exists() for r in roots), "the repo root should be a root")

    def test_an_opt_in_root_is_honoured(self):
        extra = Path(tempfile.gettempdir()).resolve()
        self.assertIn(extra, codex_ro.allowed_roots([str(extra)]))


class WriteRootTests(unittest.TestCase):
    """Audit 2026-08-30, CRITICAL: the caller could widen its own confinement.

    `--allow-path` is an ordinary flag, so it rode the same allowlist prefix as the
    call itself -- and the wrapper then unlinks `--out-file` and truncates
    `--err-file` inside whatever root it was handed. `--allow-path /` turned an
    approved "read-only review" into an arbitrary delete. Opt-in roots are for
    READS now; write targets stay in the repo and the OS temp dir.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.extra = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_an_opt_in_root_still_widens_reads(self):
        self.assertIn(self.extra, codex_ro.allowed_roots([str(self.extra)]))

    def test_an_opt_in_root_does_not_widen_writes(self):
        self.assertNotIn(self.extra, codex_ro.allowed_roots([str(self.extra)], for_write=True))

    def test_the_environment_variable_does_not_widen_writes_either(self):
        previous = os.environ.get("CLAUDEX_ALLOWED_PATHS")
        os.environ["CLAUDEX_ALLOWED_PATHS"] = str(self.extra)
        try:
            self.assertIn(self.extra, codex_ro.allowed_roots([]))
            self.assertNotIn(self.extra, codex_ro.allowed_roots([], for_write=True))
        finally:
            if previous is None:
                del os.environ["CLAUDEX_ALLOWED_PATHS"]
            else:
                os.environ["CLAUDEX_ALLOWED_PATHS"] = previous

    def test_a_world_writable_temp_dir_is_not_a_write_root(self):
        """The wrapper DELETES its out-file, so a shared parent is a real race.

        O_NOFOLLOW covers the final component; a parent directory swapped for a
        symlink between resolve() and open() is not covered, and on POSIX `/tmp`
        (mode 1777) any local user can do that. openat-style directory handles
        would close it but do not exist on Windows, so the exposure is removed
        rather than raced. (CodeRabbit, 2026-08-30.)
        """
        temp = Path(tempfile.gettempdir()).resolve()
        # Force the predicate instead of branching on it. Branching made the test
        # assert whatever this machine happened to do -- it could not fail on a
        # Windows runner, which is where it most needed to hold.
        # (CodeRabbit, 2026-08-30.)
        original = codex_ro._is_private_dir
        codex_ro._is_private_dir = lambda p: Path(p) != temp
        try:
            self.assertNotIn(
                temp,
                codex_ro.allowed_roots([], for_write=True),
                "a world-writable temp dir must not hold write targets",
            )
        finally:
            codex_ro._is_private_dir = original

        codex_ro._is_private_dir = lambda p: True
        try:
            self.assertIn(temp, codex_ro.allowed_roots([], for_write=True))
        finally:
            codex_ro._is_private_dir = original

    def test_the_repo_is_always_a_write_root(self):
        roots = codex_ro.allowed_roots([], for_write=True)
        self.assertTrue(any((r / ".git").exists() for r in roots))

    def test_an_explicit_scratch_dir_is_a_write_root_on_posix(self):
        """On POSIX, _is_private_dir() performs a real ancestor stat() check --
        so a caller-named scratch dir that genuinely is private stays usable.

        The directory has to be created somewhere actually private, and
        `tempfile` is not that on Linux: `gettempdir()` is `/tmp`, mode 1777, so
        the ancestor walk refuses anything under it — correctly. This test used
        to build its scratch dir there and failed on every Ubuntu runner while
        passing on macOS, where `gettempdir()` is a per-user `/var/folders/…`.
        The production code was right both times; the test's premise was not.
        (CI, 2026-09-03.)
        """
        if os.name == "nt":
            self.skipTest("Windows has its own refusal test below; there the check is not real")
        home = Path.home()
        if not codex_ro._is_private_dir(home):
            self.skipTest(f"{home} is not private on this machine — nothing to assert")
        private = tempfile.TemporaryDirectory(dir=str(home))
        self.addCleanup(private.cleanup)
        scratch = Path(private.name).resolve()

        previous = os.environ.get(codex_ro.SCRATCH_DIR_ENV)
        os.environ[codex_ro.SCRATCH_DIR_ENV] = str(scratch)
        try:
            self.assertIn(scratch, codex_ro.allowed_roots([], for_write=True))
        finally:
            if previous is None:
                os.environ.pop(codex_ro.SCRATCH_DIR_ENV, None)
            else:
                os.environ[codex_ro.SCRATCH_DIR_ENV] = previous

    def test_an_explicit_scratch_dir_is_refused_on_windows(self):
        """Audit 2026-09-02, CRITICAL: on Windows, _is_private_dir() cannot
        verify ANY directory (os.stat reports 0o777 for everything there), so
        before this fix every candidate -- including one named at runtime --
        was accepted as "private" without question. A caller able to set this
        one environment variable on an unattended, allowlisted invocation (a
        `.claude/settings.json` `env` block is enough; no shell prefix on the
        individual call is needed) could point it at a directory of their own
        choosing and have it accepted as a write root, where --out-file gets
        unlinked and --err-file gets truncated.

        Gegenprobe: the attacker-named directory (self.extra, a real,
        genuinely-writable temp dir standing in for the attacker's own) is
        rejected as a write root.
        """
        if os.name != "nt":
            self.skipTest("this is the Windows-specific refusal; POSIX has a real privacy check")
        previous = os.environ.get(codex_ro.SCRATCH_DIR_ENV)
        os.environ[codex_ro.SCRATCH_DIR_ENV] = str(self.extra)
        try:
            self.assertNotIn(self.extra, codex_ro.allowed_roots([], for_write=True))
        finally:
            if previous is None:
                os.environ.pop(codex_ro.SCRATCH_DIR_ENV, None)
            else:
                os.environ[codex_ro.SCRATCH_DIR_ENV] = previous

    def test_the_repo_is_still_a_write_root_when_the_scratch_dir_is_refused(self):
        """Positive control for the Windows refusal above: rejecting the named
        scratch dir must not take the legitimate write roots down with it.
        """
        previous = os.environ.get(codex_ro.SCRATCH_DIR_ENV)
        os.environ[codex_ro.SCRATCH_DIR_ENV] = str(self.extra)
        try:
            roots = codex_ro.allowed_roots([], for_write=True)
            self.assertTrue(any((r / ".git").exists() for r in roots))
        finally:
            if previous is None:
                os.environ.pop(codex_ro.SCRATCH_DIR_ENV, None)
            else:
                os.environ[codex_ro.SCRATCH_DIR_ENV] = previous


class PrivateDirRuleTests(unittest.TestCase):
    """The sticky-bit rule, tested as a rule rather than as this machine's /tmp.

    `os.stat` is stubbed so the POSIX branch runs on any host — including this
    Windows workstation, where the real branch is unreachable and the CI failure
    that prompted the fix could not be reproduced locally. (2026-09-03.)
    """

    ME = 4242
    ROOT = 0

    def _run(self, layout):
        """layout: {path-string: (mode, uid)} for the leaf and every parent."""
        import stat as _stat

        real_stat, real_name, real_geteuid = os.stat, os.name, getattr(os, "geteuid", None)

        class _St:
            def __init__(self, mode, uid):
                self.st_mode, self.st_uid = mode, uid

        os.name = "posix"
        os.geteuid = lambda: self.ME
        os.stat = lambda p: _St(*layout[str(p)])
        try:
            return codex_ro._is_private_dir(PurePosixPath(next(iter(layout))))
        finally:
            os.stat, os.name = real_stat, real_name
            if real_geteuid is None:
                del os.geteuid
            else:
                os.geteuid = real_geteuid

    def test_a_mkdtemp_style_dir_under_sticky_tmp_is_accepted(self):
        """The case that broke every Linux runner. /tmp is 1777 — sticky."""
        self.assertTrue(self._run({
            "/tmp/scratch": (0o040700, self.ME),
            "/tmp": (0o041777, self.ROOT),
            "/": (0o040755, self.ROOT),
        }))

    def test_a_world_writable_parent_without_the_sticky_bit_is_refused(self):
        """0777 and no sticky: anyone may rename our directory out from under us."""
        self.assertFalse(self._run({
            "/shared/scratch": (0o040700, self.ME),
            "/shared": (0o040777, self.ROOT),
            "/": (0o040755, self.ROOT),
        }))

    def test_a_sticky_parent_owned_by_someone_else_is_refused(self):
        """Sticky protects entries from everyone EXCEPT the directory's owner."""
        self.assertFalse(self._run({
            "/theirs/scratch": (0o040700, self.ME),
            "/theirs": (0o041777, 1337),
            "/": (0o040755, self.ROOT),
        }))

    def test_a_leaf_owned_by_someone_else_is_refused(self):
        self.assertFalse(self._run({
            "/tmp/scratch": (0o040700, 1337),
            "/tmp": (0o041777, self.ROOT),
            "/": (0o040755, self.ROOT),
        }))

    def test_a_group_writable_leaf_is_refused(self):
        self.assertFalse(self._run({
            "/tmp/scratch": (0o040770, self.ME),
            "/tmp": (0o041777, self.ROOT),
            "/": (0o040755, self.ROOT),
        }))

    def test_an_ordinary_private_tree_is_accepted(self):
        self.assertTrue(self._run({
            "/home/me/work/repo": (0o040755, self.ME),
            "/home/me/work": (0o040755, self.ME),
            "/home/me": (0o040700, self.ME),
            "/home": (0o040755, self.ROOT),
            "/": (0o040755, self.ROOT),
        }))


class WriteTargetTests(unittest.TestCase):
    """A write target must be a plain file, not something pointing elsewhere."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_a_regular_file_is_accepted(self):
        target = self.root / "verdict.txt"
        target.write_text("previous round", encoding="utf-8")
        codex_ro.prepare_write_target(target, "--out-file")  # must not raise

    def test_a_missing_file_is_accepted(self):
        codex_ro.prepare_write_target(self.root / "fresh.txt", "--out-file")

    def test_a_directory_is_refused(self):
        (self.root / "adir").mkdir()
        with self.assertRaises(SystemExit) as caught:
            codex_ro.prepare_write_target(self.root / "adir", "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_a_symlink_is_refused(self):
        victim = self.root / "victim.txt"
        victim.write_text("do not clobber me", encoding="utf-8")
        link = self.root / "verdict.txt"
        try:
            link.symlink_to(victim)
        except (OSError, NotImplementedError):
            self.skipTest("this platform will not let the test create a symlink")
        with self.assertRaises(SystemExit) as caught:
            codex_ro.prepare_write_target(link, "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(victim.read_text(encoding="utf-8"), "do not clobber me")

    def test_a_windows_junction_is_refused(self):
        """Audit 2026-09-02, CRITICAL (the other half of the "reparse point or
        hard link" finding): a directory JUNCTION is a different reparse tag
        than a symlink, `Path.is_symlink()` returns False for it, and --
        unlike a symlink -- `mklink /J` needs no special Windows privilege.
        Verified live 2026-09-02 from a plain, non-elevated account before
        writing this fix. Gegenprobe: the junction is refused, and nothing
        under the directory it points at is touched.
        """
        if os.name != "nt":
            self.skipTest("junctions are a Windows/NTFS concept")
        victim_dir = self.root / "victim_dir"
        victim_dir.mkdir()
        (victim_dir / "victim.txt").write_text("do not clobber me", encoding="utf-8")
        junction = self.root / "verdict.txt"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(victim_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # cmd's console codepage is not reliably UTF-8/cp1252
        )
        if result.returncode != 0:
            self.skipTest(f"this environment would not create a junction: {result.stderr}")
        with self.assertRaises(SystemExit) as caught:
            codex_ro.prepare_write_target(junction, "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(
            (victim_dir / "victim.txt").read_text(encoding="utf-8"), "do not clobber me"
        )

    def test_a_hard_linked_target_is_refused(self):
        """The other reparse-point-free half of the same finding: a hard link
        is a second name for the SAME data, invisible to is_symlink() and to
        the junction check above. --err-file and the event stream are opened
        directly with O_TRUNC (no prior unlink) -- truncating a hard-linked
        name truncates the data the other name still points at. Gegenprobe:
        the hard-linked target is refused, and the victim's own name still
        holds its content.
        """
        victim = self.root / "victim.txt"
        victim.write_text("do not clobber me", encoding="utf-8")
        hardlink = self.root / "verdict.txt"
        try:
            os.link(victim, hardlink)
        except (OSError, NotImplementedError):
            self.skipTest("this platform/filesystem would not create a hard link")
        with self.assertRaises(SystemExit) as caught:
            codex_ro.prepare_write_target(hardlink, "--err-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(victim.read_text(encoding="utf-8"), "do not clobber me")

    def test_a_freshly_written_file_has_no_other_hardlinks(self):
        """Positive control for test_a_hard_linked_target_is_refused: an
        ordinary file this wrapper itself would produce (single name, just
        written) must NOT be refused -- only a target that already shares its
        data with another name is.
        """
        target = self.root / "verdict.txt"
        target.write_text("previous round", encoding="utf-8")
        codex_ro.prepare_write_target(target, "--out-file")  # must not raise


class McpTests(unittest.TestCase):
    """Audit 2026-08-30: MCP was open in one direction and broken in the other.

    Broken: the default list named `MCP_DOCKER`, which is not configured on most
    machines. `-c mcp_servers.MCP_DOCKER.enabled=false` then synthesises a server
    table with no transport, and Codex refuses to load its config AT ALL -- exit 1,
    empty answer file. It cost this repo's own audit its first four sessions.
    Open: user `-c` overrides were appended after the disable list, so
    `-c mcp_servers.x.command=...` defined a server. Codex runs MCP servers as
    separate processes OUTSIDE the shell sandbox.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)
        self.previous = os.environ.get("CODEX_HOME")
        os.environ["CODEX_HOME"] = str(self.home)
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop("CODEX_HOME", None)
        else:
            os.environ["CODEX_HOME"] = self.previous

    def _write_config(self, text):
        (self.home / "config.toml").write_text(text, encoding="utf-8")

    def test_configured_servers_are_discovered(self):
        self._write_config(
            "model = 'gpt-5.6-terra'\n"
            "[mcp_servers]\n"
            "[mcp_servers.n8n]\n"
            "transport = 'http'\n"
            "url = 'http://127.0.0.1:3069/mcp'\n"
            "[mcp_servers.other]\n"
            "command = 'x'\n"
        )
        self.assertEqual(codex_ro.installed_mcp_servers(), {"n8n", "other"})

    def test_no_config_means_no_servers(self):
        self.assertEqual(codex_ro.installed_mcp_servers(), set())

    def test_a_server_that_is_not_installed_is_never_named(self):
        """The whole point: an override for an absent server breaks Codex outright."""
        self._write_config("[mcp_servers]\n[mcp_servers.n8n]\ntransport = 'http'\n")
        args = codex_ro.parse_args(
            ["--prompt", "x", "--out-file", "out.txt", "--disable-mcp", "n8n,MCP_DOCKER"]
        )
        argv = codex_ro.build_argv(args, Path("out.txt"))
        self.assertIn("mcp_servers.n8n.enabled=false", argv)
        self.assertNotIn("mcp_servers.MCP_DOCKER.enabled=false", argv)

    def test_the_default_is_every_installed_server(self):
        self._write_config(
            "[mcp_servers]\n[mcp_servers.alpha]\ncommand='a'\n[mcp_servers.beta]\ncommand='b'\n"
        )
        args = codex_ro.parse_args(["--prompt", "x", "--out-file", "out.txt"])
        argv = codex_ro.build_argv(args, Path("out.txt"))
        self.assertIn("mcp_servers.alpha.enabled=false", argv)
        self.assertIn("mcp_servers.beta.enabled=false", argv)

    def test_an_mcp_override_from_the_caller_is_refused(self):
        for override in (
            "mcp_servers.evil.command=/bin/sh",
            "mcp_servers.n8n.enabled=true",
            "mcp_servers=whatever",
        ):
            with self.subTest(override=override):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_config_overrides([override])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_a_profile_override_is_refused(self):
        # A profile can carry sandbox_mode and approval_policy of its own, which
        # is the forbidden-key check being walked around rather than beaten.
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_config_overrides(["profile=wide-open"])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)


class RefusalExitCodeTests(unittest.TestCase):
    """main() must refuse before it creates, deletes or reads anything."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmp.name).resolve()
        self.previous = Path.cwd()
        os.chdir(self.cwd)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: os.chdir(self.previous))

    def _refuses(self, argv):
        with self.assertRaises(SystemExit) as caught:
            codex_ro.main(argv)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_model_may_not_carry_extra_arguments(self):
        self._refuses(["--prompt", "x", "--out-file", "o.txt",
                       "--model", "gpt-5.6-terra -c sandbox_mode=danger-full-access"])

    def test_resume_must_look_like_a_thread_id(self):
        self._refuses(["--prompt", "x", "--out-file", "o.txt", "--resume", "not-an-id; rm -rf /"])

    def test_an_empty_prompt_is_refused(self):
        self._refuses(["--prompt", "   ", "--out-file", "o.txt"])

    def test_a_missing_prompt_file_is_refused(self):
        self._refuses(["--prompt-file", str(self.cwd / "absent.txt"), "--out-file", "o.txt"])

    def test_a_non_positive_timeout_is_refused(self):
        self._refuses(["--prompt", "x", "--out-file", "o.txt", "--timeout", "0"])

    def test_the_flag_that_gates_the_trust_check_is_always_passed(self):
        """CORRECTION 2026-09-09: this repo refused non-git directories instead.

        The reasoning — that the trust check scopes Codex's writable root to the
        repo — came from upstream issue #10 and was repeated here without ever
        being measured. @mraol08831 measured it and falsified it: the sandbox
        roots are [cwd, /tmp, $TMPDIR] with and without the flag alike. Refusing
        bought no safety and cost every review outside a repo.
        """
        argv = codex_ro.build_argv(
            codex_ro.parse_args(["--prompt", "x", "--out-file", "o.txt"]), Path("o.txt")
        )
        self.assertIn("--skip-git-repo-check", argv)
        self.assertIn("-s", argv, "the sandbox pin is what the flag does NOT touch")
        self.assertEqual(argv[argv.index("-s") + 1], "read-only")

    def test_nothing_is_created_on_the_refusal_path(self):
        with self.assertRaises(SystemExit):
            codex_ro.main(["--prompt", "x", "--out-file", "sub/o.txt", "--model", "bad model"])
        self.assertFalse((self.cwd / "sub").exists(), "the output directory must not be created")


class WindowsSandboxBackendTests(unittest.TestCase):
    """The pin needs a backend, and on Windows no backend is selected by default.

    Measured 2026-09-16 on codex-cli 0.149.1: with no `[windows] sandbox` key,
    `codex exec -s read-only` refuses EVERY command -- a plain file read included
    -- with `rejected: blocked by policy`, and still exits 0 with a fluent answer.
    Same signature as openai/codex#42172, #44839, #43633. `-s workspace-write`
    was refused identically, so this is not a read-only defect: no sandbox mode
    worked at all. With `windows.sandbox="unelevated"` the read succeeded and the
    write attempt was still denied.
    """

    @staticmethod
    def _argv():
        return codex_ro.build_argv(
            codex_ro.parse_args(["--prompt", "x", "--out-file", "o.txt"]), Path("o.txt")
        )

    def test_the_backend_is_named_on_windows_and_only_there(self):
        argv = self._argv()
        gesetzt = [a for a in argv if a.startswith("windows.sandbox=")]
        if os.name == "nt":
            self.assertEqual(gesetzt, [f'windows.sandbox="{codex_ro.WINDOWS_SANDBOX}"'])
        else:
            self.assertEqual(
                gesetzt, [],
                "the key does not exist off Windows, and naming it makes Codex "
                "refuse its entire config",
            )

    def test_the_pinned_backend_is_the_one_that_works_everywhere(self):
        """`elevated` runs the command as another user and cannot reach a working
        directory inside the caller's profile -- which is where the harness
        scratchpad lives. Measured: it failed there with CreateProcessWithLogonW
        267 while `unelevated` read and refused the write in both locations."""
        self.assertEqual(codex_ro.WINDOWS_SANDBOX, "unelevated")

    def test_a_caller_cannot_swap_the_backend(self):
        for versuch in ('windows.sandbox="elevated"', "windows.sandbox=x", "windows=1"):
            with self.subTest(override=versuch):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_config_overrides([versuch])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)


class BlindRunTests(unittest.TestCase):
    """A reviewer that could not run one command still writes a confident answer.

    This is the failure the sandbox bug produces, and it is invisible from
    outside: exit 0, a valid thread_id, a full answer file. Every existing check
    passes it through. The run is worthless and must not be reported as a review.
    """

    REFUSAL = (
        'ERROR codex_core::tools::router: error=exec_command failed for '
        '`"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -Command "Get-Content ziel.txt"`: '
        'CreateProcess { message: "Rejected(\\"... rejected: blocked by policy\\")" }'
    )
    ERFOLG = 'exec "pwsh.exe" -Command "Get-Content ziel.txt"\n succeeded in 1335ms:\nINHALT'

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.err = self.dir / "stderr.txt"

    def _blind(self, text):
        self.err.write_text(text, encoding="utf-8")
        return codex_ro.blind_run(self.err)

    def test_every_command_refused_is_a_blind_run(self):
        grund = self._blind(self.REFUSAL + "\n" + self.REFUSAL)
        self.assertIsNotNone(grund)
        self.assertIn("without reading anything", grund.lower().replace("  ", " "))

    def test_the_elevated_backends_own_failure_counts_too(self):
        """The second signature: the backend IS selected but cannot start the
        process (CreateProcessWithLogonW 267). Different message, same blindness."""
        self.assertIsNotNone(self._blind(
            'exec_command failed for `pwsh.exe`: CreateProcessWithLogonW failed: 267'))

    def test_one_refusal_among_successes_is_not_a_blind_run(self):
        """⛔ The direction that matters more. A model that reaches for one illegal
        command, is told no, and then does the job has produced a real review.
        Failing that run would make the wrapper block normal work -- and a control
        that blocks normal work gets switched off and then protects nothing."""
        self.assertIsNone(self._blind(self.REFUSAL + "\n" + self.ERFOLG))
        self.assertIsNone(self._blind(self.ERFOLG + "\n" + self.REFUSAL))

    def test_an_ordinary_run_is_silent(self):
        self.assertIsNone(self._blind(self.ERFOLG))
        self.assertIsNone(self._blind(""))
        self.assertIsNone(self._blind("some unrelated warning about MCP\n"))

    def test_a_missing_stderr_file_is_not_an_accusation(self):
        self.assertIsNone(codex_ro.blind_run(self.dir / "gibtsnicht.txt"))

    def test_the_reason_names_the_file_to_look_in(self):
        grund = self._blind(self.REFUSAL)
        self.assertIn(str(self.err), grund)


class SilentDeathTests(unittest.TestCase):
    """Upstream issue #10.1: a killed binary must not be reported as an auth failure."""

    def test_sigkill_is_named_as_such_and_not_as_auth(self):
        message = codex_ro.diagnose_silent_death("/usr/local/bin/codex", 137)
        self.assertIn("137", message)
        self.assertIn("SIGKILL", message)
        self.assertIn("do not retry", message.lower())
        self.assertNotIn("401", message)

    def test_the_binary_that_failed_is_named(self):
        self.assertIn("/opt/weird/codex", codex_ro.diagnose_silent_death("/opt/weird/codex", 1))

    def test_the_windows_app_install_is_discovered_under_its_hash_directory(self):
        """2.3.0 stranded any Windows box whose only Codex lives in the app dir.

        The macOS bundle fallback existed; Windows had none, and removing
        CLAUDEX_CODEX_BIN in 2.3.0 turned that gap into a hard stop —
        EXIT_NO_CODEX on every review while an authenticated CLI sat on disk.
        Reported from a second workstation, 2026-09-07. The hash directory
        changes per version, so putting it on PATH by hand is not a fix.
        """
        if os.name != "nt":
            self.skipTest("the Windows branch needs a Windows path layout")
        with tempfile.TemporaryDirectory() as base:
            older = Path(base) / "OpenAI" / "Codex" / "bin" / "aaa111"
            newer = Path(base) / "OpenAI" / "Codex" / "bin" / "bbb222"
            for d in (older, newer):
                d.mkdir(parents=True)
                (d / "codex.exe").write_text("", encoding="utf-8")
            os.utime(older / "codex.exe", (1_000_000, 1_000_000))
            os.utime(newer / "codex.exe", (2_000_000, 2_000_000))

            previous = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = base
            try:
                found = codex_ro.bundled_codex()
            finally:
                if previous is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = previous

            self.assertIsNotNone(found, "the app install must be found")
            self.assertIn("bbb222", found, "several versions coexist — take the newest")

    def test_no_bundle_means_no_guess(self):
        """Absent an install, this returns None rather than inventing a path."""
        if os.name != "nt":
            self.skipTest("the Windows branch needs a Windows path layout")
        with tempfile.TemporaryDirectory() as empty:
            previous = os.environ.get("LOCALAPPDATA")
            os.environ["LOCALAPPDATA"] = empty
            try:
                self.assertIsNone(codex_ro.bundled_codex())
            finally:
                if previous is None:
                    os.environ.pop("LOCALAPPDATA", None)
                else:
                    os.environ["LOCALAPPDATA"] = previous

    def _find_codex_or_skip(self):
        try:
            return codex_ro.find_codex()
        except SystemExit:
            self.skipTest("no codex installation on this machine to resolve either way")

    def test_an_explicit_binary_override_no_longer_replaces_the_executable(self):
        """Audit 2026-09-02, CRITICAL: CLAUDEX_CODEX_BIN used to let ANY
        existing file run as "Codex", trusted with no further check. This
        wrapper is meant to be allowlisted for UNATTENDED calls (see the
        module docstring) -- its environment is not something a human reviews
        per call, and setting this one variable once (e.g. in a repo's
        `.claude/settings.json` `env` block) was enough; no shell prefix on
        the individual call was needed. The replacement program then received
        the prompt and ran under no obligation to honour `-s read-only`.

        Gegenprobe: `fake`, a real file fully controlled by "the attacker",
        is what a live exploit would point the variable at. The attack is
        refused if find_codex() ignores it -- resolving exactly as it would
        with no override at all (the positive control).
        """
        without_override = self._find_codex_or_skip()
        with tempfile.NamedTemporaryFile(suffix=".sh", delete=False) as handle:
            fake = handle.name
        self.addCleanup(lambda: os.path.exists(fake) and os.unlink(fake))
        previous = os.environ.get("CLAUDEX_CODEX_BIN")
        os.environ["CLAUDEX_CODEX_BIN"] = fake
        try:
            with_override = codex_ro.find_codex()
        finally:
            if previous is None:
                del os.environ["CLAUDEX_CODEX_BIN"]
            else:
                os.environ["CLAUDEX_CODEX_BIN"] = previous
        self.assertNotEqual(os.path.realpath(with_override), os.path.realpath(fake))
        self.assertEqual(with_override, without_override)

    def test_an_override_pointing_nowhere_no_longer_causes_a_refusal(self):
        """The env var is inert now, so a dangling value must not even be
        looked at -- resolution succeeds exactly as without it (positive
        control), instead of the old EXIT_NO_CODEX for a missing override
        target.
        """
        without_override = self._find_codex_or_skip()
        previous = os.environ.get("CLAUDEX_CODEX_BIN")
        os.environ["CLAUDEX_CODEX_BIN"] = str(Path(tempfile.gettempdir()) / "no-such-codex-binary")
        try:
            self.assertEqual(codex_ro.find_codex(), without_override)
        finally:
            if previous is None:
                del os.environ["CLAUDEX_CODEX_BIN"]
            else:
                os.environ["CLAUDEX_CODEX_BIN"] = previous


class ThreadIdTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stream = Path(self.tmp.name) / "stream.json"
        self.addCleanup(self.tmp.cleanup)

    def test_the_started_event_wins_over_later_mentions(self):
        self.stream.write_text(
            '{"type":"thread.started","thread_id":"01a0-first"}\n'
            '{"type":"item.completed","thread_id":"01a0-second"}\n',
            encoding="utf-8",
        )
        self.assertEqual(codex_ro.read_thread_id(self.stream), "01a0-first")

    def test_a_missing_stream_is_not_an_error(self):
        self.assertIsNone(codex_ro.read_thread_id(Path(self.tmp.name) / "absent.json"))


class KillTreeTests(unittest.TestCase):
    """The PowerShell version had a bare `catch { }` here. A failed kill must speak."""

    def test_a_failing_kill_is_reported(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()

        class _Refuses:
            returncode = 1
            stdout = ""
            stderr = "the process could not be terminated"

        original_run, original_killpg = subprocess.run, getattr(os, "killpg", None)
        subprocess.run = lambda *a, **k: _Refuses()
        if original_killpg is not None:
            os.killpg = lambda *a, **k: (_ for _ in ()).throw(OSError("no such process group"))
        try:
            with _CapturedStderr() as captured:
                codex_ro.kill_tree(proc)
        finally:
            subprocess.run = original_run
            if original_killpg is not None:
                os.killpg = original_killpg

        self.assertIn("codex_ro:", captured.text)
        self.assertNotEqual(captured.text.strip(), "", "a failed kill must not be swallowed")

    @staticmethod
    def _spawn_detached(script):
        """Spawn the way main() does — its own process group, like the real child.

        Without this the child inherits pytest's process group, and kill_tree's
        POSIX branch then SIGKILLs that whole group: the test runner, and on a
        CI machine the runner agent. That is exactly what happened on
        2026-09-03 — every POSIX job died as "the hosted runner lost
        communication with the server" while Windows passed, because taskkill /T
        is scoped to the tree. The test was wrong, and the production code now
        refuses this case too.
        """
        platform_kwargs = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            if os.name == "nt"
            else {"start_new_session": True}
        )
        return subprocess.Popen([sys.executable, "-c", script], **platform_kwargs)

    def test_a_successful_kill_stops_the_child(self):
        proc = self._spawn_detached("import time; time.sleep(30)")
        try:
            codex_ro.kill_tree(proc)
            proc.wait(timeout=15)
        finally:
            if proc.poll() is None:  # pragma: no cover - only on a failed kill
                proc.kill()
                proc.wait(timeout=5)
        self.assertIsNotNone(proc.poll(), "the child must be gone after kill_tree")


class _CapturedStderr:
    def __enter__(self):
        import io

        self._previous = sys.stderr
        self._buffer = io.StringIO()
        sys.stderr = self._buffer
        return self

    def __exit__(self, *exc):
        sys.stderr = self._previous
        self.text = self._buffer.getvalue()
        return False


class _CapturedStdout:
    def __enter__(self):
        import io

        self._previous = sys.stdout
        self._buffer = io.StringIO()
        sys.stdout = self._buffer
        return self

    def __exit__(self, *exc):
        sys.stdout = self._previous
        self.text = self._buffer.getvalue()
        return False


class _FakeCompletedChild:
    """Stands in for subprocess.Popen so main() never starts real Codex.

    communicate() writes to whatever path follows `-o` in the child argv --
    that is how build_argv() tells the (real) Codex process where to put its
    answer, and main() checks that same path afterwards. Nothing here talks to
    a network or spends quota.
    """

    def __init__(self, cmd, **kwargs):
        self.args = cmd
        self.kwargs = kwargs
        self.returncode = 0
        self.pid = 999999

    def communicate(self, input=None, timeout=None):  # noqa: A002 - matches Popen's signature
        try:
            idx = self.args.index("-o")
            Path(self.args[idx + 1]).write_text('{"ok":true}\n', encoding="utf-8")
        except ValueError:
            pass
        return (b"", b"")


class _FakeCodexRun:
    """Context manager patching find_codex + Popen so a run "proceeds" without
    ever touching the real Codex quota. Records every Popen call for R1."""

    def __init__(self):
        self.popen_calls = []

    def __enter__(self):
        self._find_patch = unittest.mock.patch("codex_ro.find_codex", return_value="fake-codex")
        self._find_patch.start()

        def fake_popen(cmd, **kwargs):
            self.popen_calls.append((cmd, kwargs))
            return _FakeCompletedChild(cmd, **kwargs)

        self._popen_patch = unittest.mock.patch("codex_ro.subprocess.Popen", side_effect=fake_popen)
        self._popen_patch.start()
        return self

    def __exit__(self, *exc):
        self._popen_patch.stop()
        self._find_patch.stop()
        return False


# --- --expect-workdir (wrapper 2.5.0, docs/audit/2026-09-11-scope.md §5) --------------------------


class SourceHygieneTests(unittest.TestCase):
    def test_the_wrapper_compiles_without_a_syntax_warning(self):
        """A Windows path in a non-raw docstring is an invalid escape sequence.

        Twice on 2026-09-18 alone a docstring about `--expect-workdir` gained a
        backslash followed by a letter. Python 3.12 only WARNS, once, at first
        compile -- after that the .pyc hides it, so neither the suite nor a
        normal run ever shows it again. Later versions are set to make it an
        error, and this file is copied into every consumer repo. Compile from
        source with warnings as errors, bypassing the cache.
        """
        source = Path(codex_ro.__file__).read_text(encoding="utf-8")
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compile(source, codex_ro.__file__, "exec")


class ExpectWorkdirLexicalTests(unittest.TestCase):
    """check_expected_workdir(): the lexical refusals, no filesystem access at
    all -- T6/T14/T15/T19/T21/T23. `cwd` here is an arbitrary string; these
    checks must fire before `cwd` is ever touched."""

    CWD = "C:\\actual\\project" if os.name == "nt" else "/actual/project"

    def _refused(self, raw):
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_expected_workdir(raw, self.CWD)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_t14_empty_and_whitespace_values_are_refused(self):
        for raw in ("", "   ", "\t "):
            with self.subTest(raw=repr(raw)):
                self._refused(raw)

    def test_t15_t19_dot_forms_and_relative_values_are_refused(self):
        for raw in (".", "./", ".\\", "./.", "missing/..", "some/relative/dir"):
            with self.subTest(raw=raw):
                self._refused(raw)

    def test_t6_t23_unc_and_device_paths_are_refused_on_every_platform(self):
        for raw in (r"\\srv\share", "//srv/share", r"\\?\C:\x", r"\\.\C:\x"):
            with self.subTest(raw=raw):
                self._refused(raw)

    def test_t21_a_file_path_as_expectation_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            file_path = Path(d) / "somefile.txt"
            file_path.write_text("x", encoding="utf-8")
            with self.assertRaises(SystemExit) as caught:
                codex_ro.check_expected_workdir(str(file_path), str(d))
            self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_control_characters_are_refused_and_the_raw_newline_never_echoed(self):
        raw = "C:\\x\nFAKE LOG LINE"
        with _CapturedStderr() as captured:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.check_expected_workdir(raw, self.CWD)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertNotIn("\nFAKE LOG LINE", captured.text)


class ExpectWorkdirComparisonTests(unittest.TestCase):
    """T1-T3, T9's building block: real-filesystem string comparison."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def test_t1_matching_cwd_does_not_raise(self):
        codex_ro.check_expected_workdir(str(self.root), str(self.root))  # must not raise

    def test_t2_mismatch_is_refused_and_shows_both_paths(self):
        other = self.root / "elsewhere"
        other.mkdir()
        with _CapturedStderr() as captured:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.check_expected_workdir(str(other), str(self.root))
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertIn(str(self.root), captured.text)
        self.assertIn(str(other), captured.text)

    def test_t3_a_subdirectory_of_cwd_is_refused(self):
        sub = self.root / "sub"
        sub.mkdir()
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_expected_workdir(str(sub), str(self.root))
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_t3_the_parent_of_cwd_is_refused(self):
        child = self.root / "child"
        child.mkdir()
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_expected_workdir(str(self.root), str(child))
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    @unittest.skipUnless(os.name == "nt", "case/drive-letter folding is a Windows question")
    def test_t4_a_different_case_and_forward_slashes_are_accepted(self):
        raw = str(self.root).upper().replace("\\", "/")
        codex_ro.check_expected_workdir(raw, str(self.root))  # must not raise

    def test_a_spelling_that_only_NORMALISES_to_the_cwd_is_refused(self):
        """Closing-gate finding (code-review, 2026-09-18): the comparison ran the
        expectation through os.path.abspath() first, and abspath() is a
        normaliser. `<cwd>/sub/..`, `<cwd>/.`, a trailing dot or space and --
        on Windows -- a drive-rooted `\\repo` all came out as the cwd and were
        ACCEPTED, samefile() included. "Names exactly this logical path" had
        quietly become "names something that collapses to it". The value is
        now compared as typed; normcase() (case, slash direction) and one
        trailing separator are the only tolerance.
        """
        cwd = str(self.root)
        (self.root / "sub").mkdir()
        spellings = [
            os.path.join(cwd, "sub", ".."),
            os.path.join(cwd, "."),
            cwd + os.sep + os.sep + ".",
            cwd + ".",
            cwd + " ",
        ]
        if os.name == "nt":
            spellings.append(os.path.splitdrive(cwd)[1])  # drive-rooted: \Users\...\tmpX
        with unittest.mock.patch.object(codex_ro.os.path, "samefile", return_value=True) as belt:
            for raw in spellings:
                with self.subTest(raw=raw), _CapturedStderr():
                    with self.assertRaises(SystemExit) as caught:
                        codex_ro.check_expected_workdir(raw, cwd)
                    self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(belt.call_count, 0, "none of these may get as far as samefile()")

    def test_one_trailing_separator_is_still_the_same_path(self):
        cwd = str(self.root)
        codex_ro.check_expected_workdir(cwd + os.sep, cwd)  # must not raise

    def test_t4b_mocked_samefile_confirms_a_case_variant_without_a_real_alias(self):
        """Portable stand-in for T4: no real filesystem alias needed."""
        fake_cwd = "C:\\Fake\\Project" if os.name == "nt" else "/fake/project"
        raw = fake_cwd.upper() if os.name == "nt" else fake_cwd
        with unittest.mock.patch.object(codex_ro.os.path, "realpath", return_value=fake_cwd), \
             unittest.mock.patch.object(codex_ro.os.path, "samefile", return_value=True) as mock_samefile:
            codex_ro.check_expected_workdir(raw, fake_cwd)  # must not raise
        mock_samefile.assert_called_once_with(fake_cwd, raw)


class ExpectWorkdirAliasTests(unittest.TestCase):
    """T5 (reversed from earlier plan rounds, docs/audit/2026-09-11-scope.md §5/E-1.4): an alias
    for the same directory -- symlink, junction -- is refused. Herkunft, not
    nur Blatt."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.addCleanup(self.tmp.cleanup)

    def _make_alias(self, target, link):
        try:
            link.symlink_to(target, target_is_directory=True)
            return True
        except (OSError, NotImplementedError):
            pass
        if os.name == "nt":
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode == 0:
                return True
        return False

    def test_t5_an_alias_of_cwd_as_the_expectation_is_refused(self):
        real_dir = self.base / "real"
        real_dir.mkdir()
        alias_dir = self.base / "alias"
        if not self._make_alias(real_dir, alias_dir):
            self.skipTest("this environment will not let the test create a symlink or junction")
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_expected_workdir(str(alias_dir), str(real_dir))
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_t5_cwd_reached_through_a_real_alias_is_refused_where_observable(self):
        """POSIX's os.getcwd() typically canonicalises a symlinked cwd away
        already (PLAN.md O-1) -- this only demonstrates something where the
        alias is still observable in `cwd` itself; otherwise it skips, and
        the mocked variant below covers the rule on every runner regardless.
        """
        real_dir = self.base / "real2"
        real_dir.mkdir()
        alias_dir = self.base / "alias2"
        if not self._make_alias(real_dir, alias_dir):
            self.skipTest("this environment will not let the test create a symlink or junction")
        observed_cwd = str(alias_dir)
        if os.path.normcase(os.path.realpath(observed_cwd)) == os.path.normcase(observed_cwd):
            self.skipTest("this platform's realpath() already canonicalises the alias away")
        with self.assertRaises(SystemExit) as caught:
            codex_ro.check_expected_workdir(observed_cwd, observed_cwd)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_t5_mocked_alias_free_cwd_rule_holds_on_every_runner(self):
        """Portable: realpath(cwd) != cwd must refuse regardless of what this
        particular machine's chdir/getcwd happen to canonicalise."""
        fake_cwd = "C:\\fake\\project\\alias" if os.name == "nt" else "/fake/project/alias"
        fake_real = "C:\\fake\\project\\real" if os.name == "nt" else "/fake/project/real"
        with unittest.mock.patch.object(codex_ro.os.path, "realpath", return_value=fake_real), \
             unittest.mock.patch.object(codex_ro.os.path, "samefile") as mock_samefile:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.check_expected_workdir(fake_cwd, fake_cwd)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        mock_samefile.assert_not_called()


class ExpectWorkdirSamefileBeltTests(unittest.TestCase):
    """T7: samefile() is the belt, after the string/alias checks already
    passed -- its own failure must refuse too, never fall back."""

    CWD = "C:\\match\\here" if os.name == "nt" else "/match/here"

    def test_t7_samefile_raising_oserror_is_refused(self):
        with unittest.mock.patch.object(codex_ro.os.path, "realpath", return_value=self.CWD), \
             unittest.mock.patch.object(codex_ro.os.path, "samefile", side_effect=OSError("boom")):
            with self.assertRaises(SystemExit) as caught:
                codex_ro.check_expected_workdir(self.CWD, self.CWD)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_t7_samefile_returning_false_is_refused(self):
        with unittest.mock.patch.object(codex_ro.os.path, "realpath", return_value=self.CWD), \
             unittest.mock.patch.object(codex_ro.os.path, "samefile", return_value=False):
            with self.assertRaises(SystemExit) as caught:
                codex_ro.check_expected_workdir(self.CWD, self.CWD)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)


class ExpectWorkdirOracleLimitTests(unittest.TestCase):
    """T17: the mismatch/failure messages must never leak the exception text
    an underlying OSError happened to carry -- only the two paths."""

    CWD = "C:\\match\\here" if os.name == "nt" else "/match/here"
    SECRET = "TOTALLY-UNIQUE-EXCEPTION-TEXT-should-not-leak-42"

    def test_realpath_exception_text_is_not_in_the_message(self):
        with unittest.mock.patch.object(
            codex_ro.os.path, "realpath", side_effect=OSError(self.SECRET)
        ):
            with _CapturedStderr() as captured:
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_expected_workdir(self.CWD, self.CWD)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertNotIn(self.SECRET, captured.text)

    def test_samefile_exception_text_is_not_in_the_message(self):
        with unittest.mock.patch.object(codex_ro.os.path, "realpath", return_value=self.CWD), \
             unittest.mock.patch.object(
                 codex_ro.os.path, "samefile", side_effect=OSError(self.SECRET)
             ):
            with _CapturedStderr() as captured:
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.check_expected_workdir(self.CWD, self.CWD)
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertNotIn(self.SECRET, captured.text)


class ExpectWorkdirOrderingTests(unittest.TestCase):
    """T20: samefile() must be provably unreached for anything refused in the
    lexical or string-comparison steps. The order is the control."""

    CWD = "C:\\some\\project" if os.name == "nt" else "/some/project"

    CASES = {
        "empty": "",
        "whitespace": "   ",
        "control_char": "C:\\x\nFAKE",
        "unc_backslash": r"\\srv\share",
        "unc_forward": "//srv/share",
        "extended_device": r"\\?\C:\x",
        "device_ns": r"\\.\C:\x",
        "relative_dot": ".",
        "relative_dot_slash": "./",
        "relative_dot_backslash": ".\\",
        "relative_dot_dot_slash": "./.",
        "relative_missing_dotdot": "missing/..",
        "relative_plain": "some/relative/dir",
        "plain_mismatch": ("C:\\somewhere\\else" if os.name == "nt" else "/somewhere/else"),
    }

    def test_t20_samefile_is_never_called_for_any_of_these(self):
        for name, raw in self.CASES.items():
            with self.subTest(case=name):
                with unittest.mock.patch.object(codex_ro.os.path, "samefile") as mock_samefile:
                    with self.assertRaises(SystemExit) as caught:
                        codex_ro.check_expected_workdir(raw, self.CWD)
                    self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
                self.assertEqual(
                    mock_samefile.call_count, 0,
                    f"samefile() must not be reached for {name!r}",
                )


class CwdCaptureTests(unittest.TestCase):
    """T16: capture_cwd() is the single os.getcwd() call every later step
    reuses; its own failure must not be a traceback."""

    def test_t16_getcwd_failure_is_refused_with_the_placeholder(self):
        with unittest.mock.patch.object(codex_ro.os, "getcwd", side_effect=OSError("gone")):
            with _CapturedStderr() as captured:
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.capture_cwd()
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertIn("<cwd unavailable>", captured.text)
        self.assertNotIn("Traceback", captured.text)

    def test_getcwd_success_is_returned_unchanged(self):
        self.assertEqual(codex_ro.capture_cwd(), os.getcwd())


class ResolveInRootsCwdFailureTests(unittest.TestCase):
    """T24's narrower target, tested directly and portably: resolve_in_roots()
    must not let a vanished cwd surface as a traceback for a RELATIVE path
    argument, where os.path.realpath() needs os.getcwd() internally."""

    def test_a_realpath_failure_is_refused_not_raised(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            with unittest.mock.patch.object(
                codex_ro.os.path, "realpath", side_effect=OSError("cwd vanished")
            ):
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.resolve_in_roots("relative.txt", [root], "--out-file")
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_an_absolute_path_is_unaffected_by_the_new_handling(self):
        """Positive control: the try/except must not change behaviour for the
        ordinary case that was already covered by PathConfinementTests."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            target = root / "sub" / "verdict.txt"
            self.assertEqual(
                codex_ro.resolve_in_roots(str(target), [root], "--out-file"), target
            )


class ExpectWorkdirMainIntegrationTests(unittest.TestCase):
    """--expect-workdir wired through main(): header, allowed_roots, out-file
    survival, the whole ordering. Codex itself never starts here -- find_codex
    and Popen are faked (see _FakeCodexRun)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmp.name).resolve()
        self.previous = Path.cwd()
        os.chdir(self.cwd)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: os.chdir(self.previous))

    def test_t1_matching_cwd_lets_a_run_proceed(self):
        out = self.cwd / "out.txt"
        with _FakeCodexRun():
            rc = codex_ro.main([
                "--prompt", "x", "--out-file", str(out),
                "--expect-workdir", str(self.cwd),
            ])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists() and out.stat().st_size > 0)

    def test_t2_mismatched_expectation_refuses_before_any_codex_call(self):
        out = self.cwd / "out.txt"
        with _FakeCodexRun() as fake:
            with self.assertRaises(SystemExit) as caught:
                codex_ro.main([
                    "--prompt", "x", "--out-file", str(out),
                    "--expect-workdir", str(self.cwd / "elsewhere"),
                ])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(fake.popen_calls, [], "a refused run must never reach Popen")

    def test_t14_an_empty_expectation_is_refused_through_main_not_skipped(self):
        """The fail-open from round 3 of the plan review, one level up.

        check_expected_workdir("") refuses -- but main() guarded the call with
        `if args.expect_workdir:`, and "" is falsy. So `--expect-workdir "$TARGET"`
        with an unset TARGET skipped the assertion ENTIRELY and the run went
        ahead unchecked: the flag confirmed itself by vanishing. Found reading
        the diff on 2026-09-18, before it shipped; the unit-level T14 above was
        green the whole time, which is why this one goes through main().
        "Flag given" is `is not None`, never truthiness.
        """
        out = self.cwd / "out.txt"
        for value in ("", "   "):
            with self.subTest(value=repr(value)), _FakeCodexRun() as fake:
                with self.assertRaises(SystemExit) as caught:
                    codex_ro.main([
                        "--prompt", "x", "--out-file", str(out),
                        "--expect-workdir", value,
                    ])
                self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
                self.assertEqual(fake.popen_calls, [], "an empty expectation must never reach Popen")

    def test_t8_a_refused_run_leaves_an_existing_out_file_untouched(self):
        out = self.cwd / "out.txt"
        original = b"previous round's verdict, byte for byte"
        out.write_bytes(original)
        with self.assertRaises(SystemExit) as caught:
            with _FakeCodexRun():
                codex_ro.main([
                    "--prompt", "x", "--out-file", str(out),
                    "--expect-workdir", str(self.cwd / "elsewhere"),
                ])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)
        self.assertEqual(out.read_bytes(), original)

    def test_t9_the_header_names_the_cwd_and_the_repo_marker(self):
        out = self.cwd / "out.txt"
        with _CapturedStdout() as captured, _FakeCodexRun():
            codex_ro.main(["--prompt", "x", "--out-file", str(out)])
        self.assertIn("cwd:", captured.text)
        self.assertIn(str(self.cwd), captured.text)
        self.assertTrue(
            "(git repo)" in captured.text or "(no git repo)" in captured.text,
            captured.text,
        )

    def test_t18_allowed_roots_never_receives_the_expectation_value_as_extra(self):
        """When --expect-workdir matches, its string equals the real cwd's, so
        the `cwd` KWARG legitimately carrying that same value proves nothing
        (it is the captured cwd, not a leak of the expectation). What must
        never happen is the expectation reaching allowed_roots() as an
        opt-in/`extra` root -- that positional argument stays whatever
        --allow-path supplied (nothing, here), never the checked value.
        """
        out = self.cwd / "out.txt"
        with unittest.mock.patch.object(
            codex_ro, "allowed_roots", wraps=codex_ro.allowed_roots
        ) as mock_roots, _FakeCodexRun():
            codex_ro.main([
                "--prompt", "x", "--out-file", str(out),
                "--expect-workdir", str(self.cwd),
            ])
        self.assertGreaterEqual(mock_roots.call_count, 2)
        for call in mock_roots.call_args_list:
            args, kwargs = call
            extra = args[0] if args else kwargs.get("extra", [])
            self.assertEqual(list(extra), [], "no --allow-path was given; extra must stay empty")
            self.assertIn("cwd", kwargs, "main() must pass the captured cwd explicitly")
            self.assertEqual(kwargs["cwd"], self.cwd)

    def _assert_no_bare_exception(self, argv):
        """Either the run completes (an int return) or it refuses cleanly
        (SystemExit(EXIT_REFUSED)) -- anything else (a bare OSError escaping
        as a traceback) fails this assertion, and would fail the test even
        without it since unittest treats an uncaught exception as an error.

        No fixed call count is asserted: os.path.realpath()/Path.resolve()
        internally consult os.getcwd() even for an ALREADY absolute path on
        this platform (measured on Windows/ntpath; POSIX's realpath does not
        for an absolute argument) -- an implementation detail of the stdlib,
        not of this wrapper's own code, and one CLAUDE.md's "measure, don't
        assume" rule says not to hard-code across platforms.
        """
        try:
            rc = codex_ro.main(argv)
        except SystemExit as exc:
            self.assertEqual(
                exc.code, codex_ro.EXIT_REFUSED,
                "a cwd that vanishes mid-run must refuse cleanly, not exit some other way",
            )
            return None
        self.assertIsInstance(rc, int)
        return rc

    def test_t24_a_cwd_that_vanishes_soon_after_capture_never_raises_a_bare_exception(self):
        out = self.cwd / "out.txt"
        real_cwd = str(self.cwd)
        calls = {"n": 0}

        def fake_getcwd():
            calls["n"] += 1
            if calls["n"] == 1:
                return real_cwd
            raise OSError("cwd vanished after capture")

        with unittest.mock.patch.object(codex_ro.os, "getcwd", side_effect=fake_getcwd), _FakeCodexRun():
            self._assert_no_bare_exception([
                "--prompt", "x", "--out-file", str(out),
                "--expect-workdir", real_cwd,
            ])
        self.assertGreaterEqual(calls["n"], 1, "capture_cwd() must have run at least once")

    def test_t24_a_relative_out_file_after_the_cwd_vanishes_never_raises_a_bare_exception(self):
        real_cwd = str(self.cwd)
        calls = {"n": 0}

        def fake_getcwd():
            calls["n"] += 1
            if calls["n"] == 1:
                return real_cwd
            raise OSError("cwd vanished after capture")

        with unittest.mock.patch.object(codex_ro.os, "getcwd", side_effect=fake_getcwd), _FakeCodexRun():
            self._assert_no_bare_exception(["--prompt", "x", "--out-file", "relative-out.txt"])


class ExpectWorkdirRegressionTests(unittest.TestCase):
    """R1/R2: hold today already (no --expect-workdir logic to speak of yet for
    R1's shape), listed as regression per CLAUDE.md rule 6, not "first red"."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmp.name).resolve()
        self.previous = Path.cwd()
        os.chdir(self.cwd)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: os.chdir(self.previous))

    def test_r1_module_source_never_calls_chdir(self):
        source = Path(codex_ro.__file__).read_text(encoding="utf-8")
        self.assertNotIn("os.chdir(", source)

    def test_r1_popen_is_never_given_a_cwd_kwarg(self):
        out = self.cwd / "out.txt"
        with _FakeCodexRun() as fake:
            codex_ro.main(["--prompt", "x", "--out-file", str(out)])
        self.assertTrue(fake.popen_calls)
        for _cmd, kwargs in fake.popen_calls:
            self.assertNotIn("cwd", kwargs)

    def test_r2_allowed_roots_cwd_none_matches_an_explicit_current_cwd(self):
        explicit = Path.cwd().resolve()
        self.assertEqual(codex_ro.allowed_roots([]), codex_ro.allowed_roots([], cwd=explicit))
        self.assertEqual(
            codex_ro.allowed_roots([], for_write=True),
            codex_ro.allowed_roots([], for_write=True, cwd=explicit),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
