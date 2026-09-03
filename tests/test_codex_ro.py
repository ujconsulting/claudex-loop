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
from pathlib import Path

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
        """
        if os.name == "nt":
            self.skipTest("Windows has its own refusal test below; there the check is not real")
        previous = os.environ.get(codex_ro.SCRATCH_DIR_ENV)
        os.environ[codex_ro.SCRATCH_DIR_ENV] = str(self.extra)
        try:
            self.assertIn(self.extra, codex_ro.allowed_roots([], for_write=True))
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

    def test_a_non_git_directory_is_refused_with_its_own_reason(self):
        """Upstream PR #15 wants --skip-git-repo-check passed everywhere instead.

        Same problem, different answer. Codex's own refusal arrives with no
        answer file and no thread.started line — the exact signature of an
        expired token — so the failure is worth naming here rather than being
        inherited. The flag is not offered: under `-s read-only` it would be
        harmless, but under the build step's `--yolo` there is no sandbox and
        the git check is the last write boundary standing (upstream issue #10).
        """
        # setUp already chdir'd into a fresh temp dir, which is not a repo.
        with self.assertRaises(SystemExit) as caught:
            codex_ro.main(["--prompt", "x", "--out-file", "o.txt"])
        self.assertEqual(caught.exception.code, codex_ro.EXIT_REFUSED)

    def test_the_refusal_names_both_remedies_and_offers_no_third(self):
        with _CapturedStderr() as captured:
            with self.assertRaises(SystemExit):
                codex_ro.main(["--prompt", "x", "--out-file", "o.txt"])
        self.assertIn("git init", captured.text)
        self.assertIn("repo root", captured.text)
        self.assertIn("does not pass --skip-git-repo-check", captured.text)

    def test_nothing_is_created_on_the_refusal_path(self):
        with self.assertRaises(SystemExit):
            codex_ro.main(["--prompt", "x", "--out-file", "sub/o.txt", "--model", "bad model"])
        self.assertFalse((self.cwd / "sub").exists(), "the output directory must not be created")


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

    def test_bundled_lookup_is_darwin_only(self):
        if sys.platform != "darwin":
            self.assertIsNone(codex_ro.bundled_codex())

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

    def test_a_successful_kill_stops_the_child(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
