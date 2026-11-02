"""sandbox_run: the host side of the B1 container runner (plan B1, Verification 1-5).

WHY THIS FILE EXISTS. The runner is the one place where repository code under review is
executed, so every promise the plan makes about it has to be pinned by a test that fails
when the promise is broken -- not by reading the code again:

- Part A (always runs, no Docker needed): the result-stream parser accepts exactly the
  documented shape and refuses every deviation; `docker create` carries every flag of plan
  step 2 and no bind mount / privileged / network; refusals (bad export names, timeouts,
  tree ids, a missing command, DOCKER_HOST, an unknown image or a wrong image id) happen
  BEFORE any docker call (docker is patched to fail the test if called); the janitor removes
  only containers well past their deadline and reports a survivor; `--pin` refuses unsafe
  paths before any git object is written.
- Part A, B1.5 (plan PLAN-B15-deps.md steps 2, 3, 4 runner side, 6; post-approval changes 1
  and 2) and B2 U6 (approach 3b): the driver goes in through a fixed stdin loader -- argv carries
  only the loader and the source's sha256, the source arrives first on stdin, bounded and
  hash-checked -- so `docker create` stays below 8 000 characters and carries nothing from the
  snapshot; `--deps` refuses before any network call or container;
  the fetch result is cross-checked and re-verified; the deps tar is framed deterministically
  after the snapshot; `/deps` is mounted only with `--deps`; the manifest records it all; an
  unconfirmed worker leaves its directory in quarantine. docker and the fetch worker are faked.
- Part B (only with CLAUDEX_DOCKER_TESTS=1, needs the local image): each probe goes through
  `sandbox_run.main([...])` on a throwaway repository whose tree holds a small probe script,
  so the boundary is measured end to end -- escape probes, "edits are discarded", binding to
  the pinned tree, status separation, snapshot refusals, driver isolation, and the lifecycle
  refusals. Every container carries the label `claudex.run`; the last test proves none is left.

No test writes to the plugin repository, uses a bind mount, or runs git against anything but
a throwaway repository in a temporary directory.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sandbox_deps as sdeps  # noqa: E402
import sandbox_fetch as sf  # noqa: E402
import sandbox_run as sr  # noqa: E402
import sandbox_snapshot as ss  # noqa: E402

# Tests that build a snapshot need git >= 2.44 (--no-lazy-fetch); see GitVersionTests.
_GIT_OK = (ss.git_version() or (0, 0)) >= ss.MIN_GIT
NEEDS_GIT = unittest.skipUnless(_GIT_OK, "git older than 2.44: the snapshot refuses it by design")

DOCKER_TESTS = os.environ.get("CLAUDEX_DOCKER_TESTS") == "1"
CONTEXT = "desktop-linux"

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}
NONCE = "0123456789abcdef0123456789abcdef"
SHA1_TREE = "a" * 40


# --- helpers ---------------------------------------------------------------------------------

def git(repo, *args, data=None):
    res = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args], input=data,
                         capture_output=True, env=_GIT_ENV, timeout=60)
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    return res.stdout.decode().strip()


def make_repo(root: Path, files: dict, exe=()) -> tuple[Path, str]:
    """A throwaway repository with one commit; returns (repo, tree id of that commit)."""
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
    git(repo, "add", *files)
    for name in exe:
        git(repo, "update-index", "--chmod=+x", name)
    git(repo, "commit", "-q", "-m", "x")
    return repo, git(repo, "rev-parse", "HEAD^{tree}")


def tree_with_entry(repo: Path, mode: str, name: str, oid: str) -> str:
    """The HEAD tree plus one raw entry (used for symlink and submodule entries)."""
    index = repo / ".git" / "extra-index"
    env = {**_GIT_ENV, "GIT_INDEX_FILE": str(index)}
    subprocess.run(["git", "-C", str(repo), "read-tree", "HEAD"], env=env, check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"{mode},{oid},{name}"],
                   env=env, check=True, capture_output=True)
    out = subprocess.run(["git", "-C", str(repo), "write-tree"], env=env, check=True, capture_output=True)
    return out.stdout.decode().strip()


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sr.main(argv)
    return code, out.getvalue(), err.getvalue()


def docker_ids(label: str) -> set:
    env = sr.client_env()
    res = subprocess.run(["docker", "--context", CONTEXT, "ps", "-a", "--filter", f"label={label}", "-q"],
                         capture_output=True, env=env, timeout=60)
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    return set(res.stdout.decode().split())


def independent_input_hash(repo: Path, tree: str) -> str:
    """The manifest's input hash rebuilt from `git ls-tree -r` and `git cat-file blob`: sorted
    [path, mode, sha256(content)] triples, compact sorted JSON, sha256."""
    listing = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "-z", tree], capture_output=True,
                             env=_GIT_ENV, timeout=60, check=True).stdout
    entries = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        assert kind == "blob", record
        blob = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", oid], capture_output=True,
                              env=_GIT_ENV, timeout=60, check=True).stdout
        entries.append([path.decode(), int(mode, 8) & 0o777, hashlib.sha256(blob).hexdigest()])
    entries.sort()
    canon = json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canon).hexdigest()


def fail_if_called(*_a, **_k):
    raise AssertionError("docker was called, but the run had to be refused before any docker call")


class TempMixin:
    def tmp(self) -> Path:
        d = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(d.cleanup)
        return Path(d.name)

    def clean_env(self):
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        for var in [k for k in os.environ if k.upper().startswith("DOCKER_")]:
            os.environ.pop(var)


def make_tar(members, trailing: bytes = b"") -> bytes:
    """members: (name, content[, tar type]) -> a USTAR stream like the driver's."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, content, *rest in members:
            ti = tarfile.TarInfo(name)
            ti.mtime = 0
            if rest:
                ti.type = rest[0]
                if ti.type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    ti.linkname = "/etc/passwd"
                    tf.addfile(ti)
                    continue
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))
    return buf.getvalue() + trailing


def result_doc(nonce=NONCE, **override) -> bytes:
    doc = {"nonce": nonce, "command_status": "exited", "command_exit": 0, "truncated": False,
           "durations": {}, "exports": {}, "infrastructure": None}
    doc.update(override)
    return json.dumps(doc).encode()


def good_members(nonce=NONCE, **override):
    return [("result.json", result_doc(nonce, **override)), ("stdout.txt", b"out"), ("stderr.txt", b"err")]


# --- part A: host unit tests -----------------------------------------------------------------

class ReadResultTests(unittest.TestCase):
    def test_correct_tar_is_accepted(self):
        result, got = sr.read_result(make_tar(good_members()), NONCE, [])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(got["stdout.txt"], b"out")
        self.assertEqual(got["stderr.txt"], b"err")

    def test_export_member_is_accepted_when_requested(self):
        data = make_tar(good_members() + [("out/cov.xml", b"<x/>")])
        _result, got = sr.read_result(data, NONCE, ["cov.xml"])
        self.assertEqual(got["out/cov.xml"], b"<x/>")

    def test_export_member_not_requested_is_refused(self):
        data = make_tar(good_members() + [("out/cov.xml", b"<x/>")])
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(data, NONCE, [])

    def test_wrong_nonce(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(good_members(nonce="f" * 32)), NONCE, [])

    def test_extra_member(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(good_members() + [("evil.txt", b"x")]), NONCE, [])

    def test_duplicate_member(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(good_members() + [("stdout.txt", b"again")]), NONCE, [])

    def test_link_member(self):
        members = [("result.json", result_doc()), ("stdout.txt", b"", tarfile.SYMTYPE), ("stderr.txt", b"")]
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(members), NONCE, [])

    def test_hardlink_member(self):
        members = [("result.json", result_doc()), ("stdout.txt", b"", tarfile.LNKTYPE), ("stderr.txt", b"")]
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(members), NONCE, [])

    def test_oversized_member(self):
        members = [("result.json", result_doc()), ("stdout.txt", b"x" * (sr.CAPTURE_CAP + 1)),
                   ("stderr.txt", b"")]
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(members), NONCE, [])

    def test_oversized_result_json(self):
        members = [("result.json", result_doc(note="x" * (1024 * 1024 + 1))), ("stdout.txt", b""),
                   ("stderr.txt", b"")]
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(members), NONCE, [])

    def test_trailing_bytes(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(good_members(), trailing=b"trailing junk"), NONCE, [])

    def test_exact_framing_is_accepted(self):
        sr.read_result(make_tar(good_members()), NONCE, [])

    def test_extra_zero_bytes_are_refused(self):
        # Inspection A, finding 7: framing is exact -- after the standard end-of-archive
        # blocks and record padding nothing more, not even more zeros.
        for extra in (b"\0", b"\0" * 512, b"\0" * 4096, b"\0" * 10240):
            with self.subTest(extra=len(extra)):
                with self.assertRaises(sr.Infrastructure):
                    sr.read_result(make_tar(good_members(), trailing=extra), NONCE, [])

    def test_truncated_padding_is_refused(self):
        data = make_tar(good_members())
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(data[:-512], NONCE, [])

    def test_missing_stdout(self):
        members = [("result.json", result_doc()), ("stderr.txt", b"err")]
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(members), NONCE, [])

    def test_missing_result_json(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar([("stdout.txt", b""), ("stderr.txt", b"")]), NONCE, [])

    def test_infrastructure_field_set(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(good_members(infrastructure="extraction failed")), NONCE, [])

    def test_bad_command_status(self):
        for status in ("oom", "bogus", None, 7):
            with self.subTest(status=status), self.assertRaises(sr.Infrastructure):
                sr.read_result(make_tar(good_members(command_status=status)), NONCE, [])

    def test_valid_statuses(self):
        for status in ("exited", "timeout", "output_limit", "not_started"):
            with self.subTest(status=status):
                result, _ = sr.read_result(make_tar(good_members(command_status=status)), NONCE, [])
                self.assertEqual(result["command_status"], status)

    def test_not_a_tar_and_not_json(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(b"this is not a tar archive " * 100, NONCE, [])
        members = [("result.json", b"{not json"), ("stdout.txt", b""), ("stderr.txt", b"")]
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(members), NONCE, [])

    def test_stream_over_the_total_cap(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(b"\0" * (sr.RESULT_CAP + 1), NONCE, [])


# The loader argv for a fixed source hash (plan B2 approach 3b); create_args accepts no other tail.
DRIVER_TAIL = ["python3", "-I", "-S", "-c", sr.LOADER % ("1" * 64)]

# B1's `docker create` argv up to the image, verbatim (commit f9acbfe/995cbec). Without --deps the
# B1.5 runner must produce exactly this; only the driver argv after the image may differ (plan
# step 2; post-approval change 1).
B1_CREATE_HEAD = [
    "create", "--name", "claudex-run-abcd", "--label", "claudex.run=abcd",
    "--label", "claudex.deadline=1234567890", "--pull=never", "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
    "--security-opt", "no-new-privileges", "--user", "0:0", "--pids-limit", "512",
    "--memory", "4g", "--memory-swap", "4g", "--cpus", "2", "--log-driver", "none",
    "--mount", "type=tmpfs,destination=/work,tmpfs-size=512m,tmpfs-mode=1777",
    "--mount", "type=tmpfs,destination=/out,tmpfs-size=48m,tmpfs-mode=1777",
    "--tmpfs", "/tmp:size=256m", "--tmpfs", "/home/run:size=64m",
    "-e", "HOME=/home/run", "-w", "/", "-i",
]


class CreateArgsTests(unittest.TestCase):
    def setUp(self):
        self.args = sr.create_args("abcd", 1234567890, "sha256:" + "1" * 64, DRIVER_TAIL)

    def pair(self, flag, value):
        found = [i for i, a in enumerate(self.args) if a == flag and self.args[i + 1:i + 2] == [value]]
        self.assertTrue(found, f"{flag} {value} missing from {self.args}")

    def test_every_flag_of_plan_step_2(self):
        a = self.args
        self.assertEqual(a[0], "create")
        self.pair("--name", "claudex-run-abcd")
        self.pair("--label", "claudex.run=abcd")
        self.pair("--label", "claudex.deadline=1234567890")
        self.assertIn("--pull=never", a)
        self.pair("--network", "none")
        self.assertIn("--read-only", a)
        self.pair("--cap-drop", "ALL")
        for cap in ("SETUID", "SETGID", "KILL"):
            self.pair("--cap-add", cap)
        self.pair("--security-opt", "no-new-privileges")
        self.pair("--user", "0:0")
        self.pair("--pids-limit", "512")
        self.pair("--memory", "4g")
        self.pair("--memory-swap", "4g")
        self.pair("--cpus", "2")
        self.pair("--log-driver", "none")
        self.pair("-e", "HOME=/home/run")
        self.pair("-w", "/")
        self.assertIn("-i", a)
        self.pair("--tmpfs", "/tmp:size=256m")
        self.pair("--tmpfs", "/home/run:size=64m")
        mounts = [a[i + 1] for i, x in enumerate(a) if x == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(any(m.startswith("type=tmpfs,destination=/work,") and "tmpfs-mode=1777" in m
                            for m in mounts), mounts)
        self.assertTrue(any(m.startswith("type=tmpfs,destination=/out,tmpfs-size=48m,") for m in mounts), mounts)

    def test_capabilities_are_exactly_three(self):
        added = [self.args[i + 1] for i, x in enumerate(self.args) if x == "--cap-add"]
        self.assertEqual(sorted(added), ["KILL", "SETGID", "SETUID"])

    def test_no_bind_mount_privileged_or_extra_network(self):
        a = self.args
        for bad in ("-v", "--volume", "--privileged", "--volumes-from", "--device", "--pid", "--ipc",
                    "--userns", "--cgroupns", "-p", "--publish", "-P", "--add-host", "--env-file"):
            self.assertNotIn(bad, a)
        for i, x in enumerate(a):
            if x == "--mount":
                self.assertIn("type=tmpfs", a[i + 1])
                self.assertNotIn("bind", a[i + 1])
                self.assertNotIn("source=", a[i + 1])
            if x == "--network" or x == "--net":
                self.assertEqual(a[i + 1], "none")
            if x == "-e":
                self.assertEqual(a[i + 1], "HOME=/home/run")
        self.assertFalse(any(x.startswith(("--network=", "--privileged=", "--volume=")) for x in a))

    def test_image_and_driver_form_the_tail(self):
        self.assertEqual(self.args[-6:], ["sha256:" + "1" * 64, *DRIVER_TAIL])

    def test_without_deps_the_flags_are_b1s(self):
        # Plan B1.5 step 2: without --deps the same flags, mounts and limits as B1.
        self.assertEqual(self.args, B1_CREATE_HEAD + ["sha256:" + "1" * 64] + DRIVER_TAIL)
        self.assertFalse(any("/deps" in a for a in self.args))

    def test_deps_tmpfs_only_with_deps(self):
        # Post-approval change 2: --tmpfs (exec), not --mount type=tmpfs (noexec by default).
        args = sr.create_args("abcd", 1234567890, "sha256:" + "1" * 64, DRIVER_TAIL, deps_tmpfs="2g")
        flag = "/deps:rw,exec,nosuid,nodev,size=2g,mode=1777"
        self.assertEqual([args[i + 1] for i, a in enumerate(args) if a == "--tmpfs"],
                         ["/tmp:size=256m", "/home/run:size=64m", flag])
        # everything else is unchanged: removing the one flag pair gives B1's argv back
        i = args.index(flag)
        self.assertEqual(args[:i - 1] + args[i + 1:], self.args)

    def test_driver_tail_must_be_the_loader_shape(self):
        # plan B2 approach 3b: only the fixed loader with a 64-hex digest reaches the container
        loader = sr.LOADER % ("a" * 64)
        for bad in ("print(1)", ["python3", "-c", "x"], ["sh", "-I", "-S", "-c", loader],
                    ["python3", "-I", "-S", "-c", "print(1)"], ["python3", "-I", "-S", "-c", loader + ";x"],
                    ["python3", "-I", "-S", "-c", sr.LOADER % ("A" * 64)],
                    ["python3", "-I", "-S", "-c", sr.LOADER % ("a" * 63)]):
            with self.subTest(bad=bad), self.assertRaises((TypeError, ValueError)):
                sr.create_args("abcd", 1, "sha256:" + "1" * 64, bad)


class EnvironmentTests(TempMixin, unittest.TestCase):
    def test_docker_host_and_context_are_refused(self):
        for var in ("DOCKER_HOST", "DOCKER_CONTEXT"):
            with self.subTest(var=var):
                self.clean_env()
                os.environ[var] = "tcp://127.0.0.1:2375" if var == "DOCKER_HOST" else "other"
                with self.assertRaises(sr.Refused):
                    sr.check_environment()

    def test_every_variable_that_redirects_the_client_is_refused(self):
        # DOCKER_CONFIG names another config directory, where the policy's context name can
        # resolve to another daemon; the TLS variables re-point or re-trust the connection.
        for var in ("DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_TLS"):
            with self.subTest(var=var):
                self.clean_env()
                os.environ[var] = "1"
                with self.assertRaises(sr.Refused):
                    sr.check_environment()

    def test_an_unrelated_docker_variable_passes(self):
        self.clean_env()
        os.environ["DOCKER_BUILDKIT"] = "1"
        sr.check_environment()

    def test_the_docker_client_gets_no_docker_variable(self):
        self.clean_env()
        os.environ["DOCKER_BUILDKIT"] = "1"
        os.environ["DOCKER_CONFIG"] = "elsewhere"   # refused up front; stripped here regardless
        seen = []

        def fake_run(argv, **kw):
            seen.append(kw["env"])
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        class FakePopen:
            def __init__(self, argv, **kw):
                seen.append(kw["env"])
                raise OSError("stop here")

        with mock.patch.object(sr.subprocess, "run", fake_run), \
                mock.patch.object(sr.subprocess, "Popen", FakePopen):
            sr.docker("ctx", "version")
            with self.assertRaises(sr.Infrastructure):
                sr.stream_start("ctx", "cid", b"", 1.0)
        self.assertEqual(len(seen), 2)
        for env in seen:
            self.assertEqual([k for k in env if k.upper().startswith("DOCKER_")], [])
            self.assertIn("PATH", {k.upper() for k in env})

    def test_clean_environment_passes(self):
        self.clean_env()
        sr.check_environment()

    def test_main_exits_2_without_docker_when_docker_host_is_set(self):
        self.clean_env()
        os.environ["DOCKER_HOST"] = "tcp://127.0.0.1:2375"
        base = self.tmp()
        with mock.patch.object(sr, "docker", fail_if_called):
            code, _out, err = run_main(["--repo", str(base), "--scratch", str(base), "--tree", SHA1_TREE,
                                        "--image", "python-test", "--", "true"])
        self.assertEqual(code, 2)
        self.assertIn("REFUSED", err)


class RefusalTests(TempMixin, unittest.TestCase):
    """Every refusal must happen before the first docker call and exit 2."""

    def setUp(self):
        self.clean_env()
        self.base = self.tmp()
        patcher = mock.patch.object(sr, "docker", fail_if_called)
        patcher.start()
        self.addCleanup(patcher.stop)

    def call(self, extra=(), tree=SHA1_TREE, command=("true",), image="python-test"):
        argv = ["--repo", str(self.base), "--scratch", str(self.base), "--image", image, *extra]
        if tree is not None:
            argv += ["--tree", tree]
        argv += ["--", *command]
        return run_main(argv)

    def assertRefused(self, result):
        code, _out, err = result
        self.assertEqual(code, 2, err)
        self.assertNotIn("Traceback", err)

    def test_bad_export_names(self):
        for name in ("../x", "a/b", ".x", "C:x", "a\\b", "", "x" * 65, "/etc/x", "a b"):
            with self.subTest(name=name):
                self.assertRefused(self.call(["--export", name]))

    def test_good_export_names_pass_the_name_check(self):
        # A valid name gets past the name check and stops later (no tree object in this repo, but
        # docker must still not have been called by then -- the snapshot comes after resolve_image,
        # so the fake docker raising AssertionError proves the name check passed).
        for name in ("coverage.xml", "a", "A_b-c.1", "x" * 64):
            with self.subTest(name=name), self.assertRaises(AssertionError):
                self.call(["--export", name])

    def test_more_than_three_exports(self):
        self.assertRefused(self.call(["--export", "a", "--export", "b", "--export", "c", "--export", "d"]))

    def test_duplicate_exports(self):
        self.assertRefused(self.call(["--export", "a", "--export", "a"]))

    def test_timeout_bounds(self):
        for value in ("0", "-5", "3601"):
            with self.subTest(timeout=value):
                self.assertRefused(self.call(["--timeout", value]))

    def test_timeout_bounds_inclusive_edges_pass(self):
        for value in ("1", "3600"):
            with self.subTest(timeout=value), self.assertRaises(AssertionError):
                self.call(["--timeout", value])

    def test_bad_tree(self):
        for tree in ("zz", "A" * 40, "a" * 39, "a" * 41, "a" * 63, "HEAD", "refs/heads/main"):
            with self.subTest(tree=tree):
                self.assertRefused(self.call(tree=tree))

    # BUG: sandbox_run.TREE_RE ends in a dollar sign, which also matches before a trailing newline,
    # so a tree id "<40 hex>+LF" passes the host check and reaches docker (resolve_image) instead of
    # being refused. Harmless downstream (the snapshot uses fullmatch), but the check is not strict.
    # Fix: fullmatch (or \Z); the same applies to EXPORT_NAME_RE.
    def test_bad_tree_with_trailing_newline(self):
        self.assertRefused(self.call(tree="a" * 40 + chr(10)))

    # BUG: same flaw in EXPORT_NAME_RE: a name followed by LF passes the host-side name check.
    def test_bad_export_name_with_trailing_newline(self):
        self.assertRefused(self.call(["--export", "x" + chr(10)]))

    def test_neither_tree_nor_pin(self):
        self.assertRefused(self.call(tree=None))

    def test_no_command(self):
        for argv in (["--repo", str(self.base), "--scratch", str(self.base), "--tree", SHA1_TREE,
                      "--image", "python-test"],
                     ["--repo", str(self.base), "--scratch", str(self.base), "--tree", SHA1_TREE,
                      "--image", "python-test", "--"]):
            with self.subTest(argv=argv[-1]):
                self.assertRefused(run_main(argv))

    def test_unknown_image_refused_without_docker(self):
        # Reaches resolve_image with a well-formed tree; the policy lookup must refuse first.
        self.assertRefused(self.call(image="no-such-image"))


class ResolveImageTests(unittest.TestCase):
    ID = "sha256:" + "ab" * 32
    POLICY = {"context": "ctx", "images": {"img": {"ref": "claudex-sandbox-x:1", "id": ID, "tools": ["true"]}}}

    @staticmethod
    def done(code=0, out=b"", err=b""):
        return subprocess.CompletedProcess([], code, stdout=out, stderr=err)

    def test_name_not_in_policy_refused_without_docker(self):
        with mock.patch.object(sr, "docker", fail_if_called):
            with self.assertRaises(sr.Refused):
                sr.resolve_image(self.POLICY, "other")

    def test_policy_entry_with_malformed_id_refused_without_docker(self):
        bad = {"context": "c", "images": {"img": {"ref": "r:1", "id": "sha256:short", "tools": []}}}
        with mock.patch.object(sr, "docker", fail_if_called):
            with self.assertRaises(sr.Refused):
                sr.resolve_image(bad, "img")

    def test_wrong_id_refused(self):
        with mock.patch.object(sr, "docker", return_value=self.done(0, b"sha256:" + b"0" * 64 + b"\n")):
            with self.assertRaises(sr.Refused):
                sr.resolve_image(self.POLICY, "img")

    def test_missing_image_refused_never_pulled(self):
        calls = []

        def fake(context, *args, **kw):
            calls.append(args)
            return self.done(1, err=b"Error response from daemon: No such image: claudex-sandbox-x:1")

        with mock.patch.object(sr, "docker", fake):
            with self.assertRaises(sr.Refused):
                sr.resolve_image(self.POLICY, "img")
        self.assertEqual([c[0] for c in calls], ["image"])
        self.assertNotIn("pull", [c[0] for c in calls])

    def test_matching_id_returned_and_context_used(self):
        seen = []

        def fake(context, *args, **kw):
            seen.append((context, args))
            return self.done(0, self.ID.encode() + b"\n")

        with mock.patch.object(sr, "docker", fake):
            self.assertEqual(sr.resolve_image(self.POLICY, "img"), self.ID)
        self.assertEqual(seen[0][0], "ctx")

    def test_main_refuses_a_wrong_image_id_via_policy_copy(self):
        # Verification 5 without Docker: a policy copy that pins another id, a daemon that reports the real one.
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        real_load = sr.load_policy
        policy = {"context": "ctx", "images": {"python-test": {"ref": "r:1", "id": "sha256:" + "9" * 64,
                                                               "tools": ["true"]}}}
        copy = Path(tmp.name) / "policy.json"
        copy.write_text(json.dumps(policy))
        patchers = [
            mock.patch.object(sr, "load_policy", lambda: real_load(copy)),
            mock.patch.object(sr, "docker", lambda *a, **k: self.done(0, b"sha256:" + b"1" * 64)),
            mock.patch.dict(os.environ),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        for var in sr.REDIRECTING_VARS:
            os.environ.pop(var, None)
        code, _out, err = run_main(["--repo", tmp.name, "--scratch", tmp.name, "--tree", SHA1_TREE,
                                    "--image", "python-test", "--", "true"])
        self.assertEqual(code, 2, err)
        self.assertIn("REFUSED", err)

    def test_shipped_policy_is_loadable_and_names_a_pinned_image(self):
        policy = sr.load_policy()
        self.assertEqual(policy["context"], CONTEXT)
        self.assertRegex(policy["images"]["python-test"]["id"], r"^sha256:[0-9a-f]{64}$")
        entry = policy["images"]["python-test"]
        # Inspection A, finding 13: a real assertion on the local-reference contract -- a plain
        # local name:tag (no registry host, no digest: the runner never pulls; the id pins it).
        self.assertRegex(entry["ref"], r"^claudex-sandbox-[a-z0-9-]+:[A-Za-z0-9._-]+$")
        self.assertEqual(sr.policy_entry(policy, "python-test"), entry)
        self.assertIn("pytest", entry["tools"])

    def test_transport_enoent_on_image_inspect_is_infrastructure(self):
        # Inspection round 2, part A, finding A6: a socket ENOENT after the reachability check
        # is not "image missing".
        for err in (b"error during connect: dial unix /run/docker.sock: connect: no such file or directory",
                    b"Error response from daemon: No such image: claudex-sandbox-other:1"):
            with self.subTest(err=err):
                with mock.patch.object(sr, "docker", lambda *a, **k: self.done(1, err=err)):
                    with self.assertRaises(sr.Infrastructure):
                        sr.resolve_image(self.POLICY, "img")

    def test_other_inspect_failure_is_infrastructure_not_refusal(self):
        # Inspection A, finding 6: only docker's "no such image" means absent.
        with mock.patch.object(sr, "docker", lambda *a, **k: self.done(1, err=b"permission denied")):
            with self.assertRaises(sr.Infrastructure):
                sr.resolve_image(self.POLICY, "img")

    def test_stopped_daemon_is_infrastructure(self):
        err = b"Cannot connect to the Docker daemon at npipe:////./pipe/dockerDesktopLinuxEngine."
        with mock.patch.object(sr, "docker", lambda *a, **k: self.done(1, err=err)):
            with self.assertRaises(sr.Infrastructure):
                sr.daemon_reachable("ctx")

    def test_main_exits_5_when_the_daemon_is_down(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        err = b"Cannot connect to the Docker daemon"
        patchers = [mock.patch.object(sr, "docker", lambda *a, **k: self.done(1, err=err)),
                    mock.patch.dict(os.environ)]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        for var in sr.REDIRECTING_VARS:
            os.environ.pop(var, None)
        code, out, err_text = run_main(["--repo", tmp.name, "--scratch", tmp.name, "--tree", SHA1_TREE,
                                        "--image", "python-test", "--", "true"])
        self.assertEqual(code, 5, err_text)
        self.assertIn("INFRASTRUCTURE", err_text)
        # Inspection A, finding 10: the failure leaves a manifest with its status.
        run_dir = Path(re.search(r"^RUN_DIR=(.*)$", out, re.M).group(1))
        manifest = json.loads((run_dir / "manifest.json").read_text())
        self.assertEqual(manifest["runner_status"], "infrastructure")
        self.assertIn("reason", manifest)


class ToolPreflightTests(unittest.TestCase):
    """Inspection A, finding 9: B1 runs only image-contained tools; the rest is a B1.5 refusal."""
    ENTRY = {"ref": "r:1", "id": "sha256:" + "a" * 64, "tools": ["python3", "pytest"]}

    def test_listed_tools_pass(self):
        for argv in (["pytest", "-q"], ["python3", "-m", "pytest"]):
            with self.subTest(argv=argv):
                sr.check_tool(self.ENTRY, argv)

    def test_a_path_to_a_listed_tool_is_refused(self):
        # Inspection round 2, part A, finding A9: the tool list vouches for what PATH resolves in
        # the image; a path names a file the image may not have.
        for argv in (["/usr/local/bin/pytest"], ["/no/such/python3"], ["./python3"],
                     ["bin\\pytest"]):
            with self.subTest(argv=argv):
                with self.assertRaises(sr.Refused) as ctx:
                    sr.check_tool(self.ENTRY, argv)
                self.assertIn("bare", str(ctx.exception))

    def test_unlisted_tool_refused_with_b15(self):
        for argv in (["npm", "test"], ["tox"], ["bash", "-c", "x"]):
            with self.subTest(argv=argv):
                with self.assertRaises(sr.Refused) as ctx:
                    sr.check_tool(self.ENTRY, argv)
                self.assertIn("B1.5", str(ctx.exception))

    def test_main_refuses_unlisted_tool_before_docker(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(sr, "docker", fail_if_called), mock.patch.dict(os.environ):
            for var in sr.REDIRECTING_VARS:
                os.environ.pop(var, None)
            code, _out, err = run_main(["--repo", tmp.name, "--scratch", tmp.name, "--tree", SHA1_TREE,
                                        "--image", "python-test", "--", "npm", "test"])
        self.assertEqual(code, 2, err)
        self.assertIn("B1.5", err)

    def test_static_refusal_leaves_a_manifest_when_scratch_exists(self):
        # Inspection round 2, part A, finding A10: a refusal before any docker call is recorded
        # too, with the known identity and arguments.
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        with mock.patch.object(sr, "docker", fail_if_called), mock.patch.dict(os.environ):
            for var in sr.REDIRECTING_VARS:
                os.environ.pop(var, None)
            for argv in (["npm", "test"], ["/no/such/python3"]):
                with self.subTest(argv=argv):
                    code, out, err = run_main(["--repo", tmp.name, "--scratch", tmp.name, "--tree", SHA1_TREE,
                                               "--image", "python-test", "--", *argv])
                    self.assertEqual(code, 2, err)
                    run_dir = Path(re.search(r"^RUN_DIR=(.*)$", out, re.M).group(1))
                    manifest = json.loads((run_dir / "manifest.json").read_text())
                    self.assertEqual(manifest["runner_status"], "refused")
                    self.assertEqual(manifest["cleanup"], "not_needed")
                    self.assertEqual(manifest["argv"], argv)
                    self.assertEqual(manifest["image"], "python-test")
                    self.assertIn("reason", manifest)

    def test_static_refusal_without_scratch_creates_nothing(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        missing = Path(tmp.name) / "no-such-scratch"
        with mock.patch.object(sr, "docker", fail_if_called), mock.patch.dict(os.environ):
            for var in sr.REDIRECTING_VARS:
                os.environ.pop(var, None)
            code, out, _err = run_main(["--repo", tmp.name, "--scratch", str(missing), "--tree", SHA1_TREE,
                                        "--image", "python-test", "--", "npm", "test"])
        self.assertEqual(code, 2)
        self.assertNotIn("RUN_DIR=", out)
        self.assertFalse(missing.exists())


class JanitorTests(unittest.TestCase):
    def setUp(self):
        self.removed = []
        self.stuck = False
        self.daemon_gone = False

    def fake(self, lines, ps_code=0):
        def docker(context, *args, **kw):
            if args[0] == "ps":
                return subprocess.CompletedProcess([], ps_code, stdout="\n".join(lines).encode(), stderr=b"")
            if args[0] == "rm":
                self.removed.append(args[-1])
                return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            if args[0] == "inspect":
                if self.daemon_gone:
                    return subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"Cannot connect to the Docker daemon")
                found = self.stuck and args[-1] in self.removed
                return subprocess.CompletedProcess([], 0 if found else 1, stdout=b"",
                                                   stderr=b"" if found else b"Error: No such object: " + args[-1].encode())
            raise AssertionError(f"unexpected docker call {args}")
        return docker

    def test_removes_only_containers_past_deadline_plus_grace(self):
        now = int(time.time())
        lines = [
            f"within {now + 30}",               # inside its deadline
            f"justpast {now - 100}",            # past the deadline, inside the 600 s grace
            f"edge {now - sr.JANITOR_GRACE + 30}",  # still inside the grace
            f"old {now - sr.JANITOR_GRACE - 60}",   # beyond the grace -> removed
            f"ancient {now - 100000}",          # removed
            "nodeadline",                       # label empty -> never removed
            "garbage notanumber",               # unparsable -> never removed
            "",
        ]
        with mock.patch.object(sr, "docker", self.fake(lines)):
            removed = sr.janitor("ctx")
        self.assertEqual(sorted(removed), ["ancient", "old"])
        self.assertEqual(sorted(self.removed), ["ancient", "old"])

    def test_nothing_to_do(self):
        with mock.patch.object(sr, "docker", self.fake([])):
            self.assertEqual(sr.janitor("ctx"), [])

    def test_survivor_after_rm_is_infrastructure(self):
        self.stuck = True
        lines = [f"old {int(time.time()) - sr.JANITOR_GRACE - 60}"]
        with mock.patch.object(sr, "docker", self.fake(lines)):
            with self.assertRaises(sr.Infrastructure):
                sr.janitor("ctx")

    def test_transport_enoent_is_not_a_removal(self):
        # Inspection round 2, part A, finding A4: "no such file or directory" from the socket
        # contains "no such" and proves nothing.
        lines = [f"old {int(time.time()) - sr.JANITOR_GRACE - 60}"]

        def docker(context, *args, **kw):
            if args[0] == "ps":
                return subprocess.CompletedProcess([], 0, stdout="\n".join(lines).encode(), stderr=b"")
            if args[0] == "rm":
                return subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(
                [], 1, stdout=b"", stderr=b"error during connect: dial unix /run/docker.sock: "
                                            b"connect: no such file or directory")

        with mock.patch.object(sr, "docker", docker):
            with self.assertRaises(sr.Infrastructure):
                sr.janitor("ctx")

    def test_absence_of_another_ref_is_not_a_removal(self):
        done = subprocess.CompletedProcess([], 1, stdout=b"",
                                           stderr=b"Error response from daemon: No such container: other")
        self.assertFalse(sr._absent(done, "container", "old"))
        done.stderr = b"Error response from daemon: No such container: old"
        self.assertTrue(sr._absent(done, "container", "old"))
        done.returncode = 0
        self.assertFalse(sr._absent(done, "container", "old"))

    def test_unconfirmable_removal_is_infrastructure(self):
        # Inspection A, finding 4: an inspect that fails for another reason (daemon gone,
        # permission) proves nothing about removal.
        self.daemon_gone = True
        lines = [f"old {int(time.time()) - sr.JANITOR_GRACE - 60}"]
        with mock.patch.object(sr, "docker", self.fake(lines)):
            with self.assertRaises(sr.Infrastructure):
                sr.janitor("ctx")

    def test_listing_failure_is_infrastructure(self):
        with mock.patch.object(sr, "docker", self.fake([], ps_code=1)):
            with self.assertRaises(sr.Infrastructure):
                sr.janitor("ctx")

    def test_queries_only_the_run_label(self):
        seen = []

        def docker(context, *args, **kw):
            seen.append(args)
            return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

        with mock.patch.object(sr, "docker", docker):
            sr.janitor("ctx")
        self.assertIn("label=claudex.run", seen[0])

    # Plan B2 approach 11 (U6): networks, the order, the per-pass bound, the survivors ---------
    def fleet(self, containers, networks, stuck=()):
        """A fake daemon with labelled containers and networks; `stuck` refs survive removal."""
        calls = []

        def docker(context, *args, **kw):
            calls.append(args)
            if args[0] == "ps":
                return subprocess.CompletedProcess([], 0, stdout="\n".join(containers).encode(), stderr=b"")
            if args[:2] == ("network", "ls"):
                return subprocess.CompletedProcess([], 0, stdout="\n".join(networks).encode(), stderr=b"")
            if args[0] == "rm" or args[:2] == ("network", "rm"):
                return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            if args[:2] == ("inspect", "--type"):
                kind, ref = args[2], args[3]
                if ref in stuck:
                    return subprocess.CompletedProcess([], 0, stdout=b"[{}]", stderr=b"")
                msg = (f"Error response from daemon: No such container: {ref}" if kind == "container"
                       else f"Error response from daemon: network {ref} not found")
                return subprocess.CompletedProcess([], 1, stdout=b"[]\n", stderr=msg.encode())
            raise AssertionError(f"unexpected docker call {args}")
        return docker, calls

    def test_default_kinds_touch_no_network(self):
        old = int(time.time()) - sr.JANITOR_GRACE - 60
        docker, calls = self.fleet([f"c1 {old}"], [f"n1 {old}"])
        with mock.patch.object(sr, "docker", docker):
            self.assertEqual(sr.janitor("ctx"), ["c1"])
        self.assertFalse(any(a[0] == "network" for a in calls), calls)

    def test_networks_are_removed_after_containers_and_proven_gone(self):
        now = int(time.time())
        old, live = now - sr.JANITOR_GRACE - 60, now + 600
        docker, calls = self.fleet([f"c1 {old}", f"c2 {live}"], [f"n1 {old}", f"n2 {live}", "n3"])
        with mock.patch.object(sr, "docker", docker):
            # the tuple order does not matter: containers always go first
            removed = sr.janitor("ctx", kinds=("network", "container"))
        self.assertEqual(removed, ["c1", "n1"])
        order = [a for a in calls if a[0] == "rm" or a[:2] == ("network", "rm")]
        self.assertEqual(order, [("rm", "-f", "c1"), ("network", "rm", "n1")])
        listing = next(a for a in calls if a[:2] == ("network", "ls"))
        self.assertIn("label=claudex.run", listing)
        self.assertIn(("inspect", "--type", "network", "n1"), calls)

    def test_network_listing_is_narrowed_by_run_id(self):
        docker, calls = self.fleet([], [])
        with mock.patch.object(sr, "docker", docker):
            sr.janitor("ctx", run_id="abc", kinds=("container", "network"))
        self.assertIn("label=claudex.run=abc", next(a for a in calls if a[:2] == ("network", "ls")))
        self.assertIn("label=claudex.run=abc", next(a for a in calls if a[0] == "ps"))

    def test_an_unknown_kind_is_a_programming_error(self):
        for kinds in (("volume",), (), ("container", "container"), "container"):
            with self.subTest(kinds=kinds), self.assertRaises(ValueError):
                sr.janitor("ctx", kinds=kinds)

    def test_at_most_fifty_removals_per_pass_and_the_rest_reported(self):
        old = int(time.time()) - sr.JANITOR_GRACE - 60
        docker, _calls = self.fleet([f"c{i:02d} {old}" for i in range(40)],
                                    [f"n{i:02d} {old}" for i in range(20)])
        err = io.StringIO()
        with mock.patch.object(sr, "docker", docker), contextlib.redirect_stderr(err):
            removed = sr.janitor("ctx", kinds=("container", "network"))
        self.assertEqual(sr.JANITOR_MAX, 50)
        self.assertEqual(len(removed), 50)
        self.assertEqual(removed[:40], [f"c{i:02d}" for i in range(40)])
        self.assertIn("deferred=10", err.getvalue())

    def test_every_survivor_is_named_after_the_whole_pass(self):
        old = int(time.time()) - sr.JANITOR_GRACE - 60
        docker, calls = self.fleet([f"c1 {old}", f"c2 {old}"], [f"n1 {old}"], stuck=("c1", "n1"))
        with mock.patch.object(sr, "docker", docker):
            with self.assertRaises(sr.Infrastructure) as caught:
                sr.janitor("ctx", kinds=("container", "network"))
        self.assertIn(("rm", "-f", "c2"), calls)   # the pass went on after the first survivor
        self.assertIn("c1", str(caught.exception))
        self.assertIn("n1", str(caught.exception))

    def test_remove_object_per_kind(self):
        docker, calls = self.fleet([], [])
        with mock.patch.object(sr, "docker", docker):
            sr.remove_object("ctx", "container", "c9")
            sr.remove_object("ctx", "network", "n9")
            with self.assertRaises(ValueError):
                sr.remove_object("ctx", "volume", "v9")
        self.assertEqual(calls, [("rm", "-f", "c9"), ("inspect", "--type", "container", "c9"),
                                 ("network", "rm", "n9"), ("inspect", "--type", "network", "n9")])
        docker, _calls = self.fleet([], [], stuck=("n9",))
        with mock.patch.object(sr, "docker", docker), self.assertRaises(sr.Infrastructure):
            sr.remove_object("ctx", "network", "n9")

    def test_network_absence_is_dockers_own_answer_for_exactly_that_ref(self):
        # docker 29.8.2 measured 2026-11-01: `docker inspect --type network <ref>` on a missing
        # network answers "Error response from daemon: network <ref> not found".
        done = subprocess.CompletedProcess([], 1, stdout=b"[]\n",
                                           stderr=b"Error response from daemon: network n1 not found")
        self.assertTrue(sr._absent(done, "network", "n1"))
        self.assertFalse(sr._absent(done, "network", "other"))
        self.assertFalse(sr._absent(done, "container", "n1"))
        done.stderr = b"Error response from daemon: No such network: n1"
        self.assertTrue(sr._absent(done, "network", "n1"))
        done.stderr = b"error during connect: network n1 not found here"
        self.assertFalse(sr._absent(done, "network", "n1"))
        done.returncode = 0
        done.stderr = b"Error response from daemon: network n1 not found"
        self.assertFalse(sr._absent(done, "network", "n1"))


@NEEDS_GIT
class PinRefusalTests(TempMixin, unittest.TestCase):
    """Plan 7b / 4c: a bad --pin path refuses before any git object is written."""

    def setUp(self):
        self.clean_env()
        self.base = self.tmp()
        self.repo, _tree = make_repo(self.base, {"a.txt": "a\n"})
        (self.repo / "secret.txt").write_text("secret\n")
        patcher = mock.patch.object(sr, "docker", fail_if_called)
        patcher.start()
        self.addCleanup(patcher.stop)

    def objects(self):
        return git(self.repo, "count-objects", "-v")

    def test_unsafe_pin_paths_refused_before_any_object_is_written(self):
        before = self.objects()
        for path in ("..\\x", "C:\\x", "../x", "/etc/passwd", "a/../../x", ".git/config", "a//b", "./a.txt",
                     "a.txt\\..\\..\\x", "x:y"):
            with self.subTest(path=path):
                scratch = self.base / "scratch"
                scratch.mkdir(exist_ok=True)
                code, _out, err = run_main(["--repo", str(self.repo), "--scratch", str(scratch),
                                            "--pin", path, "--image", "python-test", "--", "true"])
                self.assertEqual(code, 2, err)
                self.assertEqual(self.objects(), before)

    def test_pin_builds_a_tree_without_touching_the_index(self):
        index_before = git(self.repo, "ls-files", "--stage")
        scratch = self.base / "scratch"
        scratch.mkdir()
        tree = ss.pin_paths(self.repo, ["secret.txt"], scratch)
        listing = git(self.repo, "ls-tree", "-r", tree)
        self.assertIn("secret.txt", listing)
        self.assertIn("a.txt", listing)
        self.assertEqual(git(self.repo, "ls-files", "--stage"), index_before)
        self.assertEqual(list(scratch.iterdir()), [])  # the private index is gone


@NEEDS_GIT
class SupervisedSnapshotTests(TempMixin, unittest.TestCase):
    """Inspection A, finding 1: the snapshot is built in a supervised child with a hard deadline."""

    def test_snapshot_comes_back_from_the_worker(self):
        repo, tree = make_repo(self.tmp(), {"a.txt": "a\n", "d/b.txt": "b\n"})
        work = self.tmp()
        info, tar_bytes = sr.supervised_snapshot(repo, tree, None, work)
        self.assertEqual(info["tree"], tree)
        self.assertEqual(info["input_sha256"], independent_input_hash(repo, tree))
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            self.assertIn("d/b.txt", tf.getnames())

    def test_deadline_is_infrastructure_not_refusal(self):
        repo, tree = make_repo(self.tmp(), {"a.txt": "a\n"})
        with self.assertRaises(sr.Infrastructure) as caught:
            sr.supervised_snapshot(repo, tree, None, self.tmp(), deadline=0.001)
        self.assertIn("exceeded", str(caught.exception))

    def test_worker_refusal_is_a_refusal(self):
        repo, _tree = make_repo(self.tmp(), {"a.txt": "a\n"})
        with self.assertRaises(sr.Refused):
            sr.supervised_snapshot(repo, "1" * 40, None, self.tmp())


class StreamStartTests(unittest.TestCase):
    """Inspection A, finding 3: stdout is read under the cap WHILE receiving; overflow and the
    deadline kill the container at once."""

    def fake_popen(self, code):
        real = subprocess.Popen

        def popen(argv, **kw):
            self.argv = argv
            kw.pop("env", None)
            return real([sys.executable, "-c", code], **kw)
        return popen

    def run_stream(self, code, timeout=30):
        killed = []

        def docker(context, *args, **kw):
            killed.append(args)
            return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

        with mock.patch.object(sr.subprocess, "Popen", self.fake_popen(code)), \
                mock.patch.object(sr, "docker", docker), mock.patch.object(sr, "RESULT_CAP", 1024 * 1024):
            started = time.monotonic()
            try:
                return sr.stream_start("ctx", "cid", b"input", timeout), killed, time.monotonic() - started
            except sr.Infrastructure as exc:
                return exc, killed, time.monotonic() - started

    def test_overflow_kills_while_receiving(self):
        writer = "import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)"
        result, killed, elapsed = self.run_stream(writer)
        self.assertIsInstance(result, sr.Infrastructure)
        self.assertIn("over the cap", str(result))
        self.assertIn(("kill", "cid"), killed)
        self.assertLess(elapsed, 20)

    def test_deadline_kills(self):
        result, killed, elapsed = self.run_stream("import time\ntime.sleep(60)", timeout=1)
        self.assertIsInstance(result, sr.Infrastructure)
        self.assertIn("no result within", str(result))
        self.assertIn(("kill", "cid"), killed)
        self.assertLess(elapsed, 20)

    def test_failed_docker_kill_still_kills_and_reaps_the_local_client(self):
        # Inspection round 2, part A, finding 15: the local `docker start -ai` client never
        # outlives stream_start, whatever `docker kill` does.
        procs = []
        real = subprocess.Popen

        def popen(argv, **kw):
            kw.pop("env", None)
            procs.append(real([sys.executable, "-c", "import time\ntime.sleep(60)"], **kw))
            return procs[-1]

        def docker(context, *args, **kw):
            raise sr.Infrastructure("docker kill timed out")

        with mock.patch.object(sr.subprocess, "Popen", popen), mock.patch.object(sr, "docker", docker):
            started = time.monotonic()
            with self.assertRaises(sr.Infrastructure) as ctx:
                sr.stream_start("ctx", "cid", b"input", 1)
        self.assertIn("no result within", str(ctx.exception))
        self.assertIsNotNone(procs[0].poll(), "local docker client still running")
        self.assertLess(time.monotonic() - started, 20)

    def test_interrupt_kills_and_reaps_the_local_client(self):
        procs = []
        real = subprocess.Popen

        def popen(argv, **kw):
            kw.pop("env", None)
            procs.append(real([sys.executable, "-c", "import time\ntime.sleep(60)"], **kw))
            return procs[-1]

        def interrupted(*a, **k):
            raise KeyboardInterrupt

        with mock.patch.object(sr.subprocess, "Popen", popen), mock.patch.object(sr, "_stream", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                sr.stream_start("ctx", "cid", b"input", 30)
        self.assertIsNotNone(procs[0].poll(), "local docker client still running")

    def test_normal_stream_is_returned_and_stdin_delivered(self):
        echo = "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())"
        result, killed, _elapsed = self.run_stream(echo)
        self.assertEqual(result, (b"input", b""))
        self.assertEqual(killed, [])
        self.assertEqual(self.argv[-3:], ["start", "-ai", "cid"])

    # Plan B2 approach 5 (U6): explicit per-run caps through the shared transport -------------
    def explicit(self, code, cap):
        killed = []

        def docker(context, *args, **kw):
            killed.append(args)
            return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

        with mock.patch.object(sr.subprocess, "Popen", self.fake_popen(code)), mock.patch.object(sr, "docker", docker):
            try:
                return sr.stream_start("ctx", "cid", b"", 30, result_cap=cap), killed
            except sr.Infrastructure as exc:
                return exc, killed

    def test_an_explicit_cap_below_the_default_kills_on_its_byte_plus_one(self):
        result, killed = self.explicit("import sys\nsys.stdout.buffer.write(b'x' * 4097)", 4096)
        self.assertIsInstance(result, sr.Infrastructure)
        self.assertIn("over the cap", str(result))
        self.assertIn(("kill", "cid"), killed)
        result, killed = self.explicit("import sys\nsys.stdout.buffer.write(b'x' * 4096)", 4096)
        self.assertEqual(result, (b"x" * 4096, b""))

    def test_an_explicit_cap_above_the_default_is_honoured(self):
        # 2 MiB through a 3 MiB cap while the module default is patched down to 1 MiB
        with mock.patch.object(sr, "RESULT_CAP", 1024 * 1024):
            result, killed = self.explicit("import sys\nsys.stdout.buffer.write(b'x' * (2 * 1024 * 1024))",
                                           3 * 1024 * 1024)
        self.assertEqual(len(result[0]), 2 * 1024 * 1024)
        self.assertEqual(killed, [])

    def test_the_default_cap_is_b1s(self):
        import inspect
        self.assertIsNone(inspect.signature(sr.stream_start).parameters["result_cap"].default)
        self.assertEqual(sr.RESULT_CAP, 64 * 1024 * 1024)

    def test_an_invalid_cap_is_refused_before_docker(self):
        def popen(*_a, **_k):
            raise AssertionError("docker started")

        with mock.patch.object(sr.subprocess, "Popen", popen):
            for bad in (0, -1, True, 1.5, "64", sr.MAX_RESULT_CAP + 1):
                with self.subTest(cap=bad), self.assertRaises(ValueError):
                    sr.stream_start("ctx", "cid", b"", 1, result_cap=bad)


@NEEDS_GIT
class CreateCleanupTests(TempMixin, unittest.TestCase):
    """Inspection A, findings 4 and 5: creation is inside the cleanup region, and cleanup is
    confirmed only by docker's "no such" answer."""

    ID = "sha256:" + "c" * 64

    def setUp(self):
        self.clean_env()
        self.base = self.tmp()
        self.repo, self.tree = make_repo(self.base, {"a.txt": "a\n"})
        self.calls = []
        policy = {"context": "ctx", "images": {"python-test": {"ref": "r:1", "id": self.ID, "tools": ["true"]}}}
        p = mock.patch.object(sr, "load_policy", lambda: policy)
        p.start()
        self.addCleanup(p.stop)

    def fake(self, create, gone=True):
        def docker(context, *args, **kw):
            self.calls.append(args)
            if args[0] == "version":
                return subprocess.CompletedProcess([], 0, stdout=b"29\n", stderr=b"")
            if args[:2] == ("image", "inspect"):
                return subprocess.CompletedProcess([], 0, stdout=self.ID.encode(), stderr=b"")
            if args[0] == "ps":
                return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            if args[0] == "create":
                return create()
            if args[0] == "rm":
                return subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")
            if args[0] == "inspect":
                if gone:
                    return subprocess.CompletedProcess(
                        [], 1, stdout=b"[]\n",
                        stderr=b"Error response from daemon: No such container: " + args[-1].encode())
                return subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"error during connect")
            raise AssertionError(f"unexpected docker call {args}")
        return docker

    def main(self):
        scratch = self.base / "scratch"
        scratch.mkdir(exist_ok=True)
        return run_main(["--repo", str(self.repo), "--scratch", str(scratch), "--tree", self.tree,
                         "--image", "python-test", "--", "true"])

    def removed_names(self):
        return [a[-1] for a in self.calls if a[0] == "rm"]

    def test_failed_create_still_removes_by_name(self):
        failed = lambda: subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"context deadline exceeded")
        with mock.patch.object(sr, "docker", self.fake(failed)):
            code, out, err = self.main()
        self.assertEqual(code, 5, err)
        names = self.removed_names()
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^claudex-run-[0-9a-f]{16}$")
        manifest = json.loads((Path(parse_kv(out)["RUN_DIR"]) / "manifest.json").read_text())
        self.assertEqual(manifest["cleanup"], "confirmed")
        self.assertEqual(manifest["runner_status"], "infrastructure")

    def test_interrupted_create_still_removes_by_name(self):
        def interrupted():
            raise KeyboardInterrupt
        with mock.patch.object(sr, "docker", self.fake(interrupted)):
            with self.assertRaises(KeyboardInterrupt):
                self.main()
        self.assertEqual(len(self.removed_names()), 1)

    def test_unwritable_manifest_is_never_a_pass(self):
        # Inspection round 2, part A, finding 14: COMMAND_EXIT=0 with MANIFEST_SHA256=None was a
        # pass without evidence.
        ok = lambda: subprocess.CompletedProcess([], 0, stdout=b"cid\n", stderr=b"")
        base = self.fake(ok)

        def docker(context, *args, **kw):
            if args[0] == "inspect" and "--format" in args:
                return subprocess.CompletedProcess([], 0, stdout=b"0 false\n", stderr=b"")
            return base(context, *args, **kw)

        result = {"command_status": "exited", "command_exit": 0, "truncated": False, "exports": {}}
        real_write = sr._Run.write
        with mock.patch.object(sr, "docker", docker), \
                mock.patch.object(sr, "stream_start", lambda *a, **k: (b"", b"")), \
                mock.patch.object(sr, "read_result", lambda *a, **k: (result, {})), \
                mock.patch.object(sr._Run, "write",
                                  lambda self, status, reason="": None if status == "ok"
                                  else real_write(self, status, reason)):
            code, out, err = self.main()
        self.assertEqual(code, 5, err)
        self.assertNotIn("COMMAND_EXIT=0", out)
        self.assertNotIn("MANIFEST_SHA256=None", out)
        self.assertIn("manifest could not be written", err)

    def test_unconfirmed_removal_is_reported_as_such(self):
        failed = lambda: subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"boom")
        with mock.patch.object(sr, "docker", self.fake(failed, gone=False)):
            code, out, err = self.main()
        self.assertEqual(code, 5, err)
        manifest = json.loads((Path(parse_kv(out)["RUN_DIR"]) / "manifest.json").read_text())
        self.assertEqual(manifest["cleanup"], "UNCONFIRMED")


# --- part A, B1.5: --deps, the stdin driver loader (B2 U6), the deps tar ---------------------

POLICY_DEPS = {
    "wheel_target": {"python": "3.13", "platforms": ["manylinux_2_17_x86_64", "any"]},
    "deps_max_bytes": 512 * 1024 * 1024, "deps_max_file_bytes": 128 * 1024 * 1024,
    "deps_tmpfs": "2g", "deps_install_timeout": 300,
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_wheel(name, version, requires=(), files=None):
    """(file name, bytes) of a minimal valid pure-Python wheel, like test_sandbox_driver's."""
    di = f"{name}-{version}.dist-info"
    meta = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    meta += "".join(f"Requires-Dist: {r}\n" for r in requires)
    entries = dict(files if files is not None else {f"{name}/__init__.py": b"VALUE = 7\n"})
    entries[di + "/METADATA"] = meta.encode()
    entries[di + "/WHEEL"] = (b"Wheel-Version: 1.0\nGenerator: claudex-test\nRoot-Is-Purelib: true\n"
                              b"Tag: py3-none-any\n")
    record = "".join(f"{p},{_record_hash(d)},{len(d)}\n" for p, d in entries.items())
    record += f"{di}/RECORD,,\n"
    entries[di + "/RECORD"] = record.encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries.items():
            info = zipfile.ZipInfo(path, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return f"{name}-{version}-py3-none-any.whl", buf.getvalue()


def req_line(filename: str, data: bytes) -> str:
    name, version = filename.split("-")[:2]
    return f"{name}=={version} --hash=sha256:{sha(data)}\n"


def unconfirmed(message, pid, path, record, deadline_epoch):
    """A FetchUnconfirmed carrying what sandbox_fetch puts on it -- pid, path, record and the exact
    deadline_epoch of the quarantine record -- built without relying on the constructor's
    signature, so the runner is tested against the attribute interface only."""
    exc = sf.FetchUnconfirmed.__new__(sf.FetchUnconfirmed)
    Exception.__init__(exc, message)
    exc.pid, exc.path, exc.record, exc.deadline_epoch = pid, path, record, deadline_epoch
    return exc


class FakeWorker:
    """Stands in for sandbox_fetch.run_job: writes exactly what a worker writes into the job
    directory (the four worker files plus one wheel per requirement) and returns its result.
    `tamper` may replace the bytes written for a file name (the report keeps the original hash);
    `report` may rewrite the reported files list; `fail` raises instead (given the job dir)."""

    def __init__(self, wheels, tamper=None, report=None, fail=None):
        self.wheels = dict(wheels)
        self.tamper, self.report, self.fail = tamper or {}, report, fail
        self.calls = []

    def __call__(self, job, job_dir, deadline_s, scratch, run_id):
        job_dir = Path(job_dir)
        self.calls.append({"job": job, "job_dir": job_dir, "deadline": deadline_s, "run_id": run_id,
                           "fresh": sorted(os.listdir(job_dir))})
        (job_dir / sf.JOB_NAME).write_bytes(json.dumps(job).encode())
        (job_dir / sf.STDOUT_NAME).write_bytes(b"")
        (job_dir / sf.STDERR_NAME).write_bytes(b"")
        if self.fail is not None:
            raise self.fail(job_dir)
        files = []
        for name, version, _hashes in job["requirements"]:
            filename = next(f for f in self.wheels if f.startswith(f"{name}-{version}-"))
            data = self.wheels[filename]
            (job_dir / filename).write_bytes(self.tamper.get(filename, data))
            files.append([name, version, filename, sha(data), len(data)])
        if self.report is not None:
            files = self.report(files)
        result = {"ok": True, "files": files}
        (job_dir / sf.RESULT_NAME).write_bytes(json.dumps(result).encode())
        return result


class FakeDocker:
    """docker and stream_start for a run that never starts a container. The fake driver parses
    the stdin protocol exactly (nonce, spec, tar_len bytes, deps_len bytes, nothing more) and
    answers like the real one: install.txt iff deps_len > 0."""

    def __init__(self, image_id, status="exited", deps_obj=None):
        self.image_id, self.status, self.deps_obj = image_id, status, deps_obj
        self.calls, self.stdin, self.spec = [], None, None

    def docker(self, context, *args, **kw):
        self.calls.append(args)
        ok = lambda out=b"": subprocess.CompletedProcess([], 0, stdout=out, stderr=b"")  # noqa: E731
        if args[0] == "version":
            return ok(b"29\n")
        if args[:2] == ("image", "inspect"):
            return ok(self.image_id.encode() + b"\n")
        if args[0] in ("ps", "create", "rm", "kill"):
            return ok()
        if args[0] == "inspect" and "--format" in args:
            return ok(b"0 false\n")
        if args[0] == "inspect":
            return subprocess.CompletedProcess(
                [], 1, stdout=b"[]\n", stderr=b"Error response from daemon: No such container: " + args[-1].encode())
        raise AssertionError(f"unexpected docker call {args}")

    def stream(self, context, cid, stdin, timeout, result_cap=None):
        self.stdin = stdin
        # plan B2 approach 3b: the loader block comes first -- `<len>\n<source>`, and the source
        # must hash to the sha256 the created container's loader carries
        loader = self.creates()[-1][-1]
        length_line, rest = stdin.split(b"\n", 1)
        self.source, rest = rest[:int(length_line)], rest[int(length_line):]
        assert loader == sr.LOADER % sha(self.source), "stdin source does not match the loader hash"
        nonce_line, rest = rest.split(b"\n", 1)
        spec_line, rest = rest.split(b"\n", 1)
        self.spec = json.loads(spec_line)
        self.snapshot = rest[:self.spec["tar_len"]]
        self.deps = rest[self.spec["tar_len"]:]
        assert len(self.deps) == self.spec["deps_len"], "bytes after the deps tar"
        with_deps = self.spec["deps_len"] > 0
        deps = None
        if with_deps:
            deps = self.deps_obj or {"status": "installed", "reason": None, "installed": [["alpha", "1.0"]]}
        doc = {"nonce": nonce_line.decode(), "command_status": self.status,
               "command_exit": 0 if self.status == "exited" else None, "truncated": False,
               "durations": {}, "exports": {}, "infrastructure": None, "deps": deps}
        members = [("result.json", json.dumps(doc).encode()), ("stdout.txt", b"out"), ("stderr.txt", b"")]
        if with_deps:
            members.append(("install.txt", b"Successfully installed alpha-1.0\n"))
        return make_tar(members), b""

    def creates(self):
        return [a for a in self.calls if a[0] == "create"]


def run_loader(tail, stdin: bytes):
    """Run a loader argv tail (`python3 -I -S -c <loader>`) with this interpreter."""
    return subprocess.run([sys.executable, *tail[1:]], input=stdin, capture_output=True, timeout=60,
                          check=False)


class LoaderTests(unittest.TestCase):
    """Plan B2 approach 3b (U6): argv carries only a fixed loader and the sha256 of the driver
    source; the source arrives FIRST on stdin as `<decimal length>\\n<bytes>`, bounded and
    hash-checked, and is executed as __main__; the driver's own protocol follows unchanged."""

    PROBE = (b"import sys\nprint('BOOT', __name__, sys.flags.isolated, sys.flags.no_site)\n"
             b"sys.stdout.write('REST=' + sys.stdin.buffer.read().decode() + '\\n')\n")

    def driver(self) -> bytes:
        return sr.DRIVER_FILE.read_bytes()

    def test_shape_tail_and_stdin_prefix(self):
        source = self.driver()
        tail, prefix = sr.bootstrap(source)
        self.assertEqual(tail[:4], ["python3", "-I", "-S", "-c"])
        self.assertEqual(len(tail), 5)
        self.assertEqual(tail[4], sr.LOADER % sha(source))
        self.assertIsNotNone(sr.LOADER_RE.fullmatch(tail[4]))
        self.assertEqual(prefix, str(len(source)).encode() + b"\n" + source)

    def test_the_loader_text_is_fixed_and_needs_no_quoting(self):
        # no double quote and no backslash: list2cmdline and docker pass it verbatim
        text = sr.LOADER % ("0" * 64)
        self.assertNotIn('"', text)
        self.assertNotIn("\\", text)
        self.assertNotIn("\n", text)
        text.encode("ascii")

    def test_the_loader_imports_only_sys_and_hashlib(self):
        import ast
        tree = ast.parse(sr.LOADER % ("0" * 64))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.fail(f"from-import in the loader: {node.module}")
            if isinstance(node, ast.Import):
                names |= {a.name for a in node.names}
        self.assertEqual(names, {"sys", "hashlib"})

    def test_runs_the_source_as_main_under_minus_I_minus_S_and_leaves_the_rest_of_stdin(self):
        tail, prefix = sr.bootstrap(self.PROBE)
        done = run_loader(tail, prefix + b"nonce\nspec\npayload")
        self.assertEqual(done.returncode, 0, done.stderr)
        boot, rest = done.stdout.decode().replace("\r\n", "\n").split("\n", 1)
        self.assertEqual(boot.split(), ["BOOT", "__main__", "1", "1"])
        # the driver's protocol starts exactly after the source block
        self.assertEqual(rest, "REST=nonce\nspec\npayload\n")

    def test_a_source_whose_sha256_differs_is_refused_and_never_runs(self):
        good = b"print('GOOD')\n"
        evil = b"print('EVIL')\n"
        self.assertEqual(len(good), len(evil))
        tail, _prefix = sr.bootstrap(good)
        done = run_loader(tail, str(len(evil)).encode() + b"\n" + evil + b"rest")
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b"EVIL", done.stdout)
        self.assertIn(b"sha256", done.stderr)

    def test_bad_length_lines_are_refused(self):
        tail, _prefix = sr.bootstrap(self.PROBE)
        over = str(sr.LOADER_MAX + 1).encode()
        for bad in (b"", b"\n", b"0\n", b"-5\n", b" 5\n", b"5 \n", b"abc\n", b"0012\n", b"+12\n",
                    over + b"\n", b"123456789\n", b"9" * 64 + b"\n", b"12"):
            with self.subTest(line=bad):
                done = run_loader(tail, bad + self.PROBE)
                self.assertNotEqual(done.returncode, 0, done.stdout)
                self.assertNotIn(b"BOOT", done.stdout)

    def test_a_short_source_is_refused_even_when_its_hash_matches(self):
        # the length check on its own: the digest is that of the bytes actually sent
        short = self.PROBE[:-1]
        tail = [*sr.DRIVER_PREFIX, sr.LOADER % sha(short)]
        done = run_loader(tail, str(len(self.PROBE)).encode() + b"\n" + short)
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b"BOOT", done.stdout)

    def test_a_source_over_the_bound_is_refused_even_when_its_hash_matches(self):
        # the length bound on its own: a correctly hashed source one byte over LOADER_MAX
        big = b"print('BOOT')\n" + b"#" * (sr.LOADER_MAX + 1 - 14)
        self.assertEqual(len(big), sr.LOADER_MAX + 1)
        tail = [*sr.DRIVER_PREFIX, sr.LOADER % sha(big)]
        done = run_loader(tail, str(len(big)).encode() + b"\n" + big)
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b"BOOT", done.stdout)
        at_bound = big[:-1]
        tail = [*sr.DRIVER_PREFIX, sr.LOADER % sha(at_bound)]
        done = run_loader(tail, str(len(at_bound)).encode() + b"\n" + at_bound)
        self.assertEqual(done.returncode, 0, done.stderr[-300:])
        self.assertIn(b"BOOT", done.stdout)

    def test_the_host_refuses_an_empty_or_over_long_source(self):
        for bad in (b"", b"x" * (sr.LOADER_MAX + 1)):
            with self.subTest(size=len(bad)), self.assertRaises(sr.Infrastructure):
                sr.bootstrap(bad)

    def test_the_argv_does_not_grow_with_the_source(self):
        small, _ = sr.bootstrap(b"pass\n")
        big, _ = sr.bootstrap(b"#" * sr.LOADER_MAX)
        self.assertEqual(len(small[4]), len(big[4]))
        self.assertLess(sr.cmdline_length(big), 1000)

    def test_the_old_argv_bootstrap_is_removed_not_aliased(self):
        for gone in ("driver_bootstrap", "BOOTSTRAP", "B85_ALPHABET"):
            self.assertFalse(hasattr(sr, gone), gone)

    def test_the_driver_fits_the_loader_bound(self):
        self.assertLessEqual(len(self.driver()), sr.LOADER_MAX)


class CommandLineLengthTests(unittest.TestCase):
    """Plan B2 approach 3b: every `docker create` variant stays below 8 000 characters as
    joined by subprocess.list2cmdline -- the form Windows hands to CreateProcess. B1 and B1.5
    are built here; the B2 probe, builder and proxy variants are U7's create-args functions and
    are measured with the same sandbox_run.cmdline_length in tests/test_sandbox_build.py."""

    LIMIT = 8000

    def variants(self):
        tail, _prefix = sr.bootstrap(sr.DRIVER_FILE.read_bytes())
        image = "sha256:" + "f" * 64
        head = ["docker", "--context", sr.load_policy()["context"]]
        return {
            "B1": head + sr.create_args("0123456789abcdef", 9999999999, image, tail),
            "B1.5 --deps": head + sr.create_args("0123456789abcdef", 9999999999, image, tail,
                                                 deps_tmpfs="1023g"),
        }

    def test_cmdline_length_is_list2cmdline(self):
        argv = ["docker", "a b", 'q"x', "back\\slash\\", ""]
        self.assertEqual(sr.cmdline_length(argv), len(subprocess.list2cmdline(argv)))

    def test_every_b1_variant_is_below_the_limit(self):
        for name, argv in self.variants().items():
            with self.subTest(variant=name):
                self.assertLess(sr.cmdline_length(argv), self.LIMIT)


class ReadFramedTests(unittest.TestCase):
    """Plan B2 interfaces (U6): the framed-tar reader with explicit member caps, prefix members
    (`change/<n>`) and a total cap; read_result is the B1 wrapper around it."""

    EXPECTED = {"result.json": 1024, "codex-last.txt": 64}
    PREFIX = {"change/": 32}

    def read(self, members, total_cap=1024 * 1024, trailing=b"", nonce=NONCE):
        return sr.read_framed(make_tar(members, trailing=trailing), nonce, self.EXPECTED, self.PREFIX,
                              total_cap)

    def doc(self, **over):
        return json.dumps({"nonce": NONCE, "infrastructure": None, **over}).encode()

    def test_exact_and_prefix_members_are_accepted(self):
        result, got = self.read([("result.json", self.doc(x=1)), ("change/0", b"a"), ("change/17", b"b"),
                                 ("codex-last.txt", b"ok")])
        self.assertEqual(result["x"], 1)
        self.assertEqual(got["change/0"], b"a")
        self.assertEqual(got["change/17"], b"b")
        self.assertEqual(got["codex-last.txt"], b"ok")

    def test_optional_exact_members_may_be_absent(self):
        _result, got = self.read([("result.json", self.doc())])
        self.assertEqual(sorted(got), ["result.json"])

    def test_prefix_suffix_must_be_a_canonical_index(self):
        for name in ("change/", "change/01", "change/x", "change/1/2", "change/-1", "change/1.txt",
                     "change/" + "9" * 7, "changes/1", "out/x"):
            with self.subTest(name=name), self.assertRaises(sr.Infrastructure):
                self.read([("result.json", self.doc()), (name, b"a")])

    def test_caps_duplicates_nonce_and_total(self):
        cases = {
            "prefix cap": [("result.json", self.doc()), ("change/1", b"x" * 33)],
            "exact cap": [("result.json", self.doc()), ("codex-last.txt", b"x" * 65)],
            "duplicate prefix member": [("result.json", self.doc()), ("change/1", b"a"), ("change/1", b"b")],
            "duplicate exact member": [("result.json", self.doc()), ("result.json", self.doc())],
            "no result.json": [("codex-last.txt", b"ok")],
            "other nonce": [("result.json", json.dumps({"nonce": "f" * 32}).encode())],
            "driver infrastructure": [("result.json", self.doc(infrastructure="boom"))],
            "not json": [("result.json", b"{")],
        }
        for what, members in cases.items():
            with self.subTest(what), self.assertRaises(sr.Infrastructure):
                self.read(members)
        with self.assertRaises(sr.Infrastructure):
            self.read([("result.json", self.doc())], total_cap=10)
        with self.assertRaises(sr.Infrastructure):
            self.read([("result.json", self.doc())], trailing=b"junk")

    def test_read_result_keeps_b1s_caps(self):
        self.assertEqual(sr.RESULT_CAP, 64 * 1024 * 1024)
        seen = {}
        real = sr.read_framed

        def spy(data, nonce, expected, prefix_caps, total_cap):
            seen.update(expected=dict(expected), prefix=dict(prefix_caps), total=total_cap)
            return real(data, nonce, expected, prefix_caps, total_cap)

        with mock.patch.object(sr, "read_framed", spy):
            sr.read_result(make_tar(good_members()), NONCE, ["cov.xml"])
        self.assertEqual(seen["expected"], {"result.json": 1024 * 1024, "stdout.txt": sr.CAPTURE_CAP,
                                            "stderr.txt": sr.CAPTURE_CAP, "out/cov.xml": sr.EXPORT_CAP})
        self.assertEqual(seen["prefix"], {})
        self.assertEqual(seen["total"], sr.RESULT_CAP)


class DepsPolicyTests(unittest.TestCase):
    """Plan step 3: wheel_target and the deps limits are policy data, validated strictly."""

    def entry(self, **over):
        e = {"ref": "r:1", "id": "sha256:" + "a" * 64, "tools": ["true"], **json.loads(json.dumps(POLICY_DEPS))}
        for k, v in over.items():
            if v is KeyError:
                e.pop(k)
            else:
                e[k] = v
        return e

    def test_shipped_policy_carries_the_measured_wheel_target(self):
        # glibc of claudex-sandbox-python-test:2 measured 2026-11-01: ('glibc', '2.41'), Debian 13.
        entry = sr.load_policy()["images"]["python-test"]
        expected = [f"manylinux_2_{n}_x86_64" for n in range(41, 16, -1)] + [
            "manylinux2014_x86_64", "manylinux_2_12_x86_64", "manylinux2010_x86_64",
            "manylinux_2_5_x86_64", "manylinux1_x86_64", "any"]
        self.assertEqual(entry["wheel_target"], {"python": "3.13", "platforms": expected})
        self.assertEqual(entry["deps_max_bytes"], 512 * 1024 * 1024)
        self.assertEqual(entry["deps_max_file_bytes"], 128 * 1024 * 1024)
        self.assertEqual(entry["deps_tmpfs"], "2g")
        self.assertEqual(entry["deps_install_timeout"], 300)
        cfg = sr.deps_policy(entry)
        self.assertEqual(cfg["wheel_target"], entry["wheel_target"])

    def test_no_deps_fields_means_none(self):
        self.assertIsNone(sr.deps_policy({"ref": "r:1", "id": "sha256:" + "a" * 64, "tools": []}))

    def test_malformed_fields_are_refused(self):
        bad = {
            "partial": {"deps_tmpfs": KeyError},
            "target not object": {"wheel_target": ["3.13"]},
            "target extra key": {"wheel_target": {"python": "3.13", "platforms": ["any"], "abi": "x"}},
            "python bad": {"wheel_target": {"python": "3", "platforms": ["any"]}},
            "platforms empty": {"wheel_target": {"python": "3.13", "platforms": []}},
            "platform bad": {"wheel_target": {"python": "3.13", "platforms": ["many linux"]}},
            "platform dup": {"wheel_target": {"python": "3.13", "platforms": ["any", "any"]}},
            "bytes bool": {"deps_max_bytes": True},
            "bytes zero": {"deps_max_bytes": 0},
            "bytes huge": {"deps_max_bytes": 2 * 1024 ** 3},
            "bytes str": {"deps_max_bytes": "512"},
            "file over total": {"deps_max_file_bytes": 513 * 1024 * 1024},
            "tmpfs comma": {"deps_tmpfs": "2g,exec"},
            "tmpfs unit": {"deps_tmpfs": "2t"},
            "tmpfs too small": {"deps_tmpfs": "100m"},
            "timeout zero": {"deps_install_timeout": 0},
            "timeout big": {"deps_install_timeout": 3601},
            "timeout float": {"deps_install_timeout": 30.5},
        }
        for label, over in bad.items():
            with self.subTest(label=label), self.assertRaises(sr.Refused):
                sr.deps_policy(self.entry(**over))


class ReadResultDepsTests(unittest.TestCase):
    INSTALLED = {"status": "installed", "reason": None, "installed": [["alpha", "1.0"]]}
    FAILED = {"status": "failed", "reason": "missing beta", "installed": []}

    def members(self, deps, status="exited", install=b"log"):
        exit_ = 0 if status == "exited" else None
        m = good_members(command_status=status, command_exit=exit_, deps=deps)
        return m + ([("install.txt", install)] if install is not None else [])

    def test_install_txt_is_accepted_only_with_deps(self):
        result, got = sr.read_result(make_tar(self.members(self.INSTALLED)), NONCE, [], with_deps=True)
        self.assertEqual(got["install.txt"], b"log")
        self.assertEqual(result["deps"], self.INSTALLED)
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(self.members(None)), NONCE, [])

    def test_install_txt_missing_with_deps(self):
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(self.members(self.INSTALLED, install=None)), NONCE, [], with_deps=True)

    def test_install_txt_over_its_cap(self):
        big = b"x" * (sr.INSTALL_CAP + 1)
        with self.assertRaises(sr.Infrastructure):
            sr.read_result(make_tar(self.members(self.INSTALLED, install=big)), NONCE, [], with_deps=True)

    def test_deps_failed_is_valid_only_with_deps_and_a_failed_object(self):
        result, _ = sr.read_result(make_tar(self.members(self.FAILED, "deps_failed")), NONCE, [],
                                   with_deps=True)
        self.assertEqual(result["command_status"], "deps_failed")
        for deps, status, with_deps in ((self.FAILED, "deps_failed", False),
                                        (self.INSTALLED, "deps_failed", True),
                                        (self.FAILED, "exited", True),
                                        (None, "exited", True),
                                        ({"status": "weird", "reason": None, "installed": []}, "exited", True),
                                        (self.INSTALLED, "exited", False)):
            with self.subTest(deps=deps, status=status, with_deps=with_deps):
                install = b"log" if with_deps else None
                with self.assertRaises(sr.Infrastructure):
                    sr.read_result(make_tar(self.members(deps, status, install)), NONCE, [],
                                   with_deps=with_deps)

    def test_b1_result_without_deps_key_still_reads(self):
        result, _ = sr.read_result(make_tar(good_members()), NONCE, [])
        self.assertIsNone(result.get("deps"))


@NEEDS_GIT
class DepsRunTests(TempMixin, unittest.TestCase):
    """The runner end to end with docker and the fetch worker faked (plan steps 2-4, 6)."""

    def setUp(self):
        self.clean_env()
        self.base = self.tmp()
        self.alpha = ("alpha-1.0-py3-none-any.whl", b"ALPHA-WHEEL-BYTES")
        self.beta = ("beta-2.0-py3-none-any.whl", b"BETA-WHEEL-BYTES" * 3)
        self.marker = "SNAPSHOT-MARKER-" + uuid.uuid4().hex
        files = {
            "requirements.txt": "# compiled\n" + req_line(*self.beta) + req_line(*self.alpha),
            "other.txt": req_line(*self.alpha),
            "probe.txt": self.marker + "\n",
            "dir/x.txt": "x\n",
            "options.txt": "-r requirements.txt\n",
            "unhashed.txt": "alpha==1.0\n",
            "marker.txt": f"alpha==1.0 ; python_version > '3' --hash=sha256:{sha(self.alpha[1])}\n",
            "conflict.txt": "alpha==1.1 --hash=sha256:" + "0" * 64 + "\n",
            "nohash-in-common.txt": "alpha==1.0 --hash=sha256:" + "0" * 64 + "\n",
            "empty.txt": "# nothing\n",
            "blank-a.txt": "# only a comment\n\n",
            "blank-b.txt": "\n   \n# and another\n",
            # A3: continuations that end in a blank or a comment line
            "cont-blank.txt": "six==1.17.0 \\\n\n",
            "cont-comment.txt": "six==1.17.0 \\\n# a comment\n",
            "lone-blank.txt": f"alpha==1.0 --hash=sha256:{sha(self.alpha[1])}\n\\\n\n",
            "lone-comment.txt": f"alpha==1.0 --hash=sha256:{sha(self.alpha[1])}\n\\\n# a comment\n",
            # 300 distinct requirements each: every file is within MAX_REQUIREMENTS, the merge is not
            "many-a.txt": "".join(f"pa{i:03d}==1.0 --hash=sha256:{i:064x}\n" for i in range(300)),
            "many-b.txt": "".join(f"pb{i:03d}==1.0 --hash=sha256:{i + 1000:064x}\n" for i in range(300)),
        }
        self.repo, self.tree = make_repo(self.base, files)
        self.scratch = self.base / "scratch"
        self.scratch.mkdir()
        self.image_id = sr.load_policy()["images"]["python-test"]["id"]
        self.fake = FakeDocker(self.image_id)
        self.worker = FakeWorker([self.alpha, self.beta])
        for p in (mock.patch.object(sr, "docker", self.fake.docker),
                  mock.patch.object(sr, "stream_start", self.fake.stream),
                  mock.patch.object(sr.sandbox_fetch, "run_job", self.worker)):
            p.start()
            self.addCleanup(p.stop)

    def main(self, deps=(), command=("true",)):
        argv = ["--repo", str(self.repo), "--scratch", str(self.scratch), "--tree", self.tree,
                "--image", "python-test"]
        for d in deps:
            argv += ["--deps", d]
        code, out, err = run_main(argv + ["--", *command])
        return code, parse_kv(out), err

    def manifest(self, info):
        return json.loads((Path(info["RUN_DIR"]) / "manifest.json").read_text())

    def run_dirs(self):
        return list((self.scratch / "sandbox").glob("run-*"))

    # --- the good path -----------------------------------------------------------------------
    def test_with_deps_the_deps_tar_follows_the_snapshot(self):
        code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 0, err)
        self.assertEqual(info["COMMAND_STATUS"], "exited")
        run_dir = Path(info["RUN_DIR"])
        # the worker got a fresh, empty job directory under the run directory and the plan's job
        call = self.worker.calls[0]
        self.assertEqual(call["job_dir"], run_dir / "deps")
        self.assertEqual(call["fresh"], [])
        self.assertEqual(call["deadline"], 600)
        self.assertRegex(call["run_id"], r"^[0-9a-f]{16}$")
        self.assertEqual(run_dir.name, "run-" + call["run_id"])
        job = call["job"]
        self.assertEqual(job["kind"], "wheels")
        self.assertEqual([r[:2] for r in job["requirements"]], [["alpha", "1.0"], ["beta", "2.0"]])
        self.assertEqual(job["requirements"][0][2], [sha(self.alpha[1])])
        policy = sr.load_policy()["images"]["python-test"]
        self.assertEqual(job["target"], policy["wheel_target"])
        self.assertEqual((job["max_file"], job["max_total"]),
                         (policy["deps_max_file_bytes"], policy["deps_max_bytes"]))
        # the job directory is gone, the run directory keeps manifest and results only
        self.assertFalse((run_dir / "deps").exists())
        self.assertEqual(sorted(p.name for p in run_dir.iterdir()),
                         ["install.txt", "manifest.json", "result.json", "stderr.txt", "stdout.txt"])
        self.assertEqual((run_dir / "install.txt").read_bytes(), b"Successfully installed alpha-1.0\n")
        # spec keys and stdin framing
        spec = self.fake.spec
        self.assertEqual(spec["deps_len"], len(self.fake.deps))
        self.assertEqual(spec["deps_sha256"], sha(self.fake.deps))
        self.assertEqual(spec["deps_timeout"], 300)
        with tarfile.open(fileobj=io.BytesIO(self.fake.snapshot)) as tf:
            self.assertIn("probe.txt", tf.getnames())
        # the deps tar: flat, deterministic, root-owned 0644 regular members, mtime 0
        with tarfile.open(fileobj=io.BytesIO(self.fake.deps), mode="r:") as tf:
            ms = tf.getmembers()
            self.assertEqual([m.name for m in ms], [self.alpha[0], self.beta[0], "requirements.txt"])
            for m in ms:
                self.assertTrue(m.isreg())
                self.assertEqual((m.mode, m.uid, m.gid, m.mtime, m.uname, m.gname), (0o644, 0, 0, 0, "", ""))
            data = {m.name: tf.extractfile(m).read() for m in ms}
        self.assertEqual(data[self.alpha[0]], self.alpha[1])
        self.assertEqual(data[self.beta[0]], self.beta[1])
        self.assertEqual(data["requirements.txt"],
                         (req_line(*self.alpha) + req_line(*self.beta)).encode())
        # the container: /deps tmpfs, the bootstrap, nothing from the snapshot on the command line
        create = list(self.fake.creates()[0])
        self.assertIn("/deps:rw,exec,nosuid,nodev,size=2g,mode=1777", create)
        self.assertEqual(create[-5:-1], ["python3", "-I", "-S", "-c"])
        self.assertEqual(create[-1], sr.LOADER % sha(sr.DRIVER_FILE.read_bytes()))
        # the driver source went in first on stdin, verified by the fake against that hash
        self.assertEqual(self.fake.source, sr.DRIVER_FILE.read_bytes())
        joined = " ".join(create)
        self.assertNotIn(self.marker, joined)
        self.assertNotIn(sha(self.alpha[1]), joined)
        self.assertLess(len(joined), 30000)
        # the manifest
        m = self.manifest(info)
        self.assertEqual(m["driver_sha256"], sha(sr.DRIVER_FILE.read_bytes()))
        reqs = sdeps.parse_requirements(req_line(*self.alpha).encode() + req_line(*self.beta).encode(), "x")
        d = m["deps"]
        self.assertEqual(d["files"], [{"path": "requirements.txt", "content_sha256": sha(
            ("# compiled\n" + req_line(*self.beta) + req_line(*self.alpha)).encode())}])
        self.assertEqual(d["requirements"], [
            {"name": "alpha", "version": "1.0", "wheel": self.alpha[0], "sha256": sha(self.alpha[1])},
            {"name": "beta", "version": "2.0", "wheel": self.beta[0], "sha256": sha(self.beta[1])}])
        self.assertEqual(d["requirements_sha256"], sdeps.requirements_sha256(reqs))
        self.assertEqual(d["deps_tar_sha256"], sha(self.fake.deps))
        self.assertEqual(d["wheel_target"], policy["wheel_target"])
        self.assertEqual(d["install"], {"status": "installed", "reason": None, "installed": [["alpha", "1.0"]]})
        self.assertEqual(d["install_txt_sha256"], sha(b"Successfully installed alpha-1.0\n"))
        self.assertEqual(info["REQUIREMENTS_SHA256"], d["requirements_sha256"])
        self.assertEqual(info["MANIFEST_SHA256"], sha((run_dir / "manifest.json").read_bytes()))

    def test_two_files_are_merged(self):
        code, info, err = self.main(deps=["requirements.txt", "other.txt"])
        self.assertEqual(code, 0, err)
        self.assertEqual([f["path"] for f in self.manifest(info)["deps"]["files"]],
                         ["requirements.txt", "other.txt"])
        self.assertEqual([r[:2] for r in self.worker.calls[0]["job"]["requirements"]],
                         [["alpha", "1.0"], ["beta", "2.0"]])

    def test_without_deps_the_run_is_b1s(self):
        code, info, err = self.main()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.worker.calls, [])
        self.assertEqual((self.fake.spec["deps_len"], self.fake.spec["deps_sha256"],
                          self.fake.spec["deps_timeout"]), (0, "", 300))
        self.assertEqual(self.fake.deps, b"")
        create = list(self.fake.creates()[0])
        self.assertFalse(any("/deps" in a for a in create))
        tail = create.index(self.image_id)
        self.assertEqual(len(create[:tail]), len(B1_CREATE_HEAD))
        m = self.manifest(info)
        self.assertIsNone(m["deps"])
        self.assertNotIn("REQUIREMENTS_SHA256", info)
        self.assertEqual(sorted(p.name for p in Path(info["RUN_DIR"]).iterdir()),
                         ["manifest.json", "result.json", "stderr.txt", "stdout.txt"])

    def test_deps_failed_is_a_command_status_never_a_pass(self):
        self.fake.status = "deps_failed"
        self.fake.deps_obj = {"status": "failed", "reason": "beta>=1 missing", "installed": []}
        code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 0, err)
        self.assertEqual(info["COMMAND_STATUS"], "deps_failed")
        self.assertEqual(info["COMMAND_EXIT"], "-")
        m = self.manifest(info)
        self.assertIsNone(m["command_exit"])
        self.assertEqual(m["deps"]["install"]["status"], "failed")

    # --- refusals: before any network call and any container ---------------------------------
    def assert_refused_before_fetch(self, deps, needle=None):
        code, info, err = self.main(deps=deps)
        self.assertEqual(code, 2, err)
        self.assertNotIn("Traceback", err)
        if needle:
            self.assertIn(needle, err)
        self.assertEqual(self.worker.calls, [], "the fetch worker ran")
        self.assertEqual(self.fake.creates(), [], "a container was created")
        for run_dir in self.run_dirs():
            self.assertFalse((run_dir / "deps").exists())

    def test_files_that_are_not_regular_entries_of_the_pinned_tree(self):
        (self.repo / "untracked.txt").write_text(req_line(*self.alpha))  # working tree only
        for path in ("missing.txt", "dir", "untracked.txt", "Requirements.txt"):
            with self.subTest(path=path):
                self.assert_refused_before_fetch([path], "not a regular file of the pinned tree")

    def test_unacceptable_requirements_are_refused(self):
        for path in ("options.txt", "unhashed.txt", "marker.txt", "empty.txt"):
            with self.subTest(path=path):
                self.assert_refused_before_fetch([path])

    def test_merge_conflicts_are_refused(self):
        for pair in (["requirements.txt", "conflict.txt"], ["requirements.txt", "nohash-in-common.txt"]):
            with self.subTest(pair=pair):
                self.assert_refused_before_fetch(pair)

    def test_static_deps_refusals_happen_before_any_docker_call(self):
        with mock.patch.object(sr, "docker", fail_if_called):
            for deps in (["a.txt"] * 5, ["../x"], ["/etc/passwd"], [".git/config"], ["a//b"],
                         ["C:\\x"], ["requirements.txt", "./requirements.txt"],
                         ["requirements.txt", "requirements.txt"]):
                with self.subTest(deps=deps):
                    self.assert_refused_before_fetch(deps)

    def test_an_image_without_wheel_target_refuses_deps_before_docker(self):
        policy = json.loads(json.dumps(sr.load_policy()))
        for key in POLICY_DEPS:
            policy["images"]["python-test"].pop(key)
        with mock.patch.object(sr, "load_policy", lambda: policy), mock.patch.object(sr, "docker", fail_if_called):
            self.assert_refused_before_fetch(["requirements.txt"], "wheel_target")

    def test_without_deps_a_policy_without_deps_fields_still_runs(self):
        policy = json.loads(json.dumps(sr.load_policy()))
        for key in POLICY_DEPS:
            policy["images"]["python-test"].pop(key)
        with mock.patch.object(sr, "load_policy", lambda: policy):
            code, _info, err = self.main()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fake.spec["deps_timeout"], sr.DEFAULT_DEPS_TIMEOUT)

    # --- the fetch outcome ---------------------------------------------------------------------
    def test_fetch_refused_is_exit_2_and_removes_the_job_dir(self):
        self.worker.fail = lambda _d: sf.FetchRefused("no wheel for the image's platform")
        code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 2, err)
        self.assertIn("no wheel for the image's platform", err)
        self.assertEqual(self.fake.creates(), [])
        self.assertFalse((Path(info["RUN_DIR"]) / "deps").exists())
        self.assertEqual(self.manifest(info)["runner_status"], "refused")
        self.assertIn("REQUIREMENTS_SHA256", info)

    def test_fetch_infrastructure_is_exit_5_and_removes_the_job_dir(self):
        self.worker.fail = lambda _d: sf.FetchInfrastructure("HTTP 503 from pypi.org")
        code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 5, err)
        self.assertEqual(self.fake.creates(), [])
        self.assertFalse((Path(info["RUN_DIR"]) / "deps").exists())

    def test_merged_files_over_max_requirements_are_refused_before_fetch(self):
        # A6: 300 + 300 distinct requirements -- each file is accepted alone, the merge is not
        self.assertGreater(600, sdeps.MAX_REQUIREMENTS)
        self.assert_refused_before_fetch(["many-a.txt", "many-b.txt"], str(sdeps.MAX_REQUIREMENTS))
        # each file alone stays within the limit and reaches the fetch (the fake worker has no
        # wheel for it and is told to refuse, which proves the parse passed)
        self.worker.fail = lambda _d: sf.FetchRefused("no wheel")
        code, _info, err = self.main(deps=["many-a.txt"])
        self.assertEqual(code, 2, err)
        self.assertEqual(len(self.worker.calls), 1)
        self.assertEqual(len(self.worker.calls[0]["job"]["requirements"]), 300)

    def test_files_that_together_list_no_requirement_are_refused_before_fetch(self):
        # B3: an empty --deps inventory is a caller mistake, never an empty deps tar
        for deps in (["empty.txt"], ["blank-a.txt", "blank-b.txt"], ["empty.txt", "blank-a.txt", "blank-b.txt"]):
            with self.subTest(deps=deps):
                self.fake.calls.clear()
                self.assert_refused_before_fetch(deps, "the files list no requirement")
                self.assertFalse(any(a and a[0] in ("create", "start") for a in self.fake.calls))

    def test_continuations_into_blank_or_comment_lines_are_refused_with_their_line(self):
        # A3, callers' outcome: a normal refusal with a written manifest, never a crash; the
        # reason names file and line; no worker and no docker create. The `six==1.17.0 \` cases
        # join to an unhashed requirement; a lone backslash joins nothing (empty logical line).
        cases = {"cont-blank.txt": ("cont-blank.txt:1:", "no hash"),
                 "cont-comment.txt": ("cont-comment.txt:1:", "no hash"),
                 "lone-blank.txt": ("lone-blank.txt:2:", "joins nothing"),
                 "lone-comment.txt": ("lone-comment.txt:2:", "joins nothing")}
        for path, (where, what) in cases.items():
            with self.subTest(path=path):
                self.fake.calls.clear()
                before = set(self.run_dirs())
                code, info, err = self.main(deps=[path])
                self.assertEqual(code, 2, err)
                self.assertNotIn("Traceback", err)
                self.assertIn(where, err)
                self.assertIn(what, err)
                self.assertEqual(self.worker.calls, [], "run_job was called")
                self.assertEqual(self.fake.creates(), [], "a container was created")
                new = set(self.run_dirs()) - before
                self.assertEqual(len(new), 1)
                run_dir = new.pop()
                self.assertEqual(Path(info["RUN_DIR"]), run_dir)
                m = self.manifest(info)
                self.assertEqual(m["runner_status"], "refused")
                self.assertIn(where, m["reason"])
                self.assertIn(what, m["reason"])
                self.assertFalse((run_dir / "deps").exists())

    def test_quarantine_block_copies_the_exception_and_equals_the_record(self):
        # A8: pid, path, deadline_epoch and record come from FetchUnconfirmed -- the exact values
        # sandbox_fetch wrote into the quarantine record, not a deadline the runner computed itself
        deadline = time.time() + 1234.5678901  # deliberately not now + FETCH_DEADLINE

        def fail(d):
            record = sf.write_quarantine_record(self.scratch, self.worker.calls[-1]["run_id"], d, 4242, deadline)
            return unconfirmed("worker pid 4242 not confirmed dead", 4242, d, record, deadline)
        self.worker.fail = fail
        code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 5, err)
        q = self.manifest(info)["quarantine"]
        record_path = self.scratch / sf.QUARANTINE_DIR / f"{self.worker.calls[-1]['run_id']}.json"
        rec = json.loads(record_path.read_text())
        self.assertEqual(q, {"cleanup": "unconfirmed", "pid": rec["pid"], "path": rec["path"],
                             "deadline_epoch": rec["deadline_epoch"], "record": str(record_path)})
        self.assertEqual(q["deadline_epoch"], deadline)
        self.assertEqual(rec["cleanup"], "unconfirmed")

    def test_a_failed_removal_of_the_download_dir_is_infrastructure(self):
        # A9: outside quarantine the download directory must go; if it cannot, the run is exit 5,
        # the retained path is named in manifest and stderr, and no container is created
        real_rmtree = sr.shutil.rmtree

        def rmtree(p, *a, **k):
            if Path(p).name == "deps":
                return None  # the removal "fails" silently, as ignore_errors=True would
            return real_rmtree(p, *a, **k)
        for fail, needle in ((None, None),
                             (lambda _d: sf.FetchRefused("no wheel for the image's platform"), "no wheel"),
                             (lambda _d: sf.FetchInfrastructure("HTTP 503"), "HTTP 503")):
            with self.subTest(needle=needle):
                self.fake.calls.clear()
                self.worker.fail = fail
                with mock.patch.object(sr.shutil, "rmtree", rmtree):
                    code, info, err = self.main(deps=["requirements.txt"])
                self.assertEqual(code, 5, err)
                self.assertNotIn("Traceback", err)
                job_dir = Path(info["RUN_DIR"]) / "deps"
                self.assertTrue(job_dir.is_dir())
                self.assertIn(ascii(str(job_dir)), err)
                m = self.manifest(info)
                self.assertEqual(m["runner_status"], "infrastructure")
                self.assertEqual(m["deps_dir_cleanup"], "failed")
                self.assertEqual(m["deps_dir_retained"], str(job_dir))
                self.assertNotIn("COMMAND_STATUS", info)
                self.assertEqual(self.fake.creates(), [])
                if needle is not None:
                    self.assertIn(needle, m["reason"])  # the first failure is not hidden
                real_rmtree(job_dir)

    def test_unconfirmed_worker_keeps_its_directory_and_exits_5(self):
        removed = []
        self.worker.fail = lambda d: unconfirmed("worker pid 4242 not confirmed dead", 4242, d, None,
                                                 time.time() + 600)
        real_rmtree = sr.shutil.rmtree
        with mock.patch.object(sr.shutil, "rmtree",
                               lambda p, *a, **k: (removed.append(Path(p)), real_rmtree(p, *a, **k))):
            code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 5, err)
        job_dir = Path(info["RUN_DIR"]) / "deps"
        self.assertTrue(job_dir.is_dir())
        self.assertTrue((job_dir / sf.JOB_NAME).exists())
        self.assertNotIn(job_dir, removed)
        m = self.manifest(info)
        self.assertEqual(m["cleanup"], "unconfirmed")
        self.assertEqual(m["quarantine"]["pid"], 4242)
        self.assertEqual(m["quarantine"]["path"], str(job_dir))
        self.assertEqual(m["quarantine"]["cleanup"], "unconfirmed")
        self.assertGreater(m["quarantine"]["deadline_epoch"], time.time())
        self.assertIn("4242", err)
        self.assertEqual(self.fake.creates(), [])

    def test_interrupted_fetch_removes_the_job_dir(self):
        def interrupt(_d):
            raise KeyboardInterrupt
        self.worker.fail = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.main(deps=["requirements.txt"])
        self.assertEqual(self.fake.creates(), [])
        for run_dir in self.run_dirs():
            self.assertFalse((run_dir / "deps").exists())

    def test_a_misreported_hash_is_rejected(self):
        # The worker writes other bytes but reports the pinned hash: the parent re-hashes.
        self.worker.tamper = {self.alpha[0]: b"TAMPERED-BYTES"}
        code, info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 2, err)
        self.assertEqual(self.fake.creates(), [])
        self.assertFalse((Path(info["RUN_DIR"]) / "deps").exists())

    def test_a_worker_list_that_does_not_match_the_requirements_is_rejected(self):
        cases = {
            "wrong version": lambda f: [[f[0][0], "9.9", *f[0][2:]], f[1]],
            "missing entry": lambda f: f[:1],
            "two files for one": lambda f: [f[0], [f[0][0], f[0][1], "alpha-1.0-py2-none-any.whl", *f[0][3:]], f[1]],
            "file of another package": lambda f: [[f[0][0], f[0][1], f[1][2], *f[0][3:]], f[1]],
            "malformed": lambda f: [f[0], "beta"],
        }
        for label, report in cases.items():
            with self.subTest(label=label):
                self.fake.calls.clear()
                self.worker.report = report
                code, info, err = self.main(deps=["requirements.txt"])
                self.assertEqual(code, 5, err)
                self.assertEqual(self.fake.creates(), [])
                self.assertFalse((Path(info["RUN_DIR"]) / "deps").exists())

    def test_a_deps_tar_over_its_cap_is_refused(self):
        small = self.small_policy(100)
        with mock.patch.object(sr, "DEPS_TAR_SLACK", 0), \
                mock.patch.object(sr, "load_policy", lambda: small):
            # the wheels (65 bytes) fit the 100-byte download cap; the framed tar does not
            code, _info, err = self.main(deps=["requirements.txt"])
        self.assertEqual(code, 2, err)
        self.assertIn("deps tar", err)
        self.assertEqual(self.fake.creates(), [])

    def small_policy(self, total):
        policy = json.loads(json.dumps(sr.load_policy()))
        entry = policy["images"]["python-test"]
        entry["deps_max_bytes"] = total
        entry["deps_max_file_bytes"] = total
        entry["deps_tmpfs"] = "16m"
        return policy

    # --- quarantine listing ------------------------------------------------------------------
    def test_quarantine_records_are_listed_at_start_and_nothing_is_touched(self):
        victim = self.base / "victim"
        victim.mkdir()
        (victim / "sentinel").write_text("keep")
        rid = sf.new_run_id()
        record = sf.write_quarantine_record(self.scratch, rid, victim, 4321, time.time() - 99999)
        code, _info, err = self.main(deps=["a.txt"] * 5)  # a static refusal: still listed
        self.assertEqual(code, 2, err)
        self.assertIn(f"quarantined run {rid}", err)
        self.assertIn("remove by hand after checking that pid 4321 is gone", err)
        self.assertTrue((victim / "sentinel").exists())
        self.assertTrue(record.exists())

    # --- broken output streams (plan B1.5 hardening) -------------------------------------------
    # A stderr diagnostic is best effort: a full redirected log (OSError) or a closed stream
    # (ValueError) must not turn the outcome into an escaped exception -- exit 1, no manifest,
    # quarantine fields lost. A lost stdout KEY=value line is never a pass.
    def main_broken(self, deps=(), command=("true",), err_exc=None, out_exc=None):
        argv = ["--repo", str(self.repo), "--scratch", str(self.scratch), "--tree", self.tree,
                "--image", "python-test"]
        for d in deps:
            argv += ["--deps", d]
        out = BrokenStream(out_exc) if out_exc else io.StringIO()
        err = BrokenStream(err_exc) if err_exc else io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            code = sr.main(argv + ["--", *command])
        return code, out, err

    def only_run_dir(self) -> Path:
        dirs = self.run_dirs()
        self.assertEqual(len(dirs), 1, dirs)
        return dirs[0]

    def test_broken_stderr_during_a_refusal_is_still_exit_2_with_a_manifest(self):
        for exc in BROKEN_STREAM_ERRORS:
            with self.subTest(exc=type(exc).__name__):
                for d in self.run_dirs():
                    sr.shutil.rmtree(d)
                code, out, err = self.main_broken(deps=["unhashed.txt"], err_exc=exc)
                self.assertEqual(code, 2)
                self.assertGreater(err.attempts, 0, "no diagnostic was attempted")
                run_dir = self.only_run_dir()
                m = json.loads((run_dir / "manifest.json").read_text())
                self.assertEqual(m["runner_status"], "refused")
                self.assertIn(f"RUN_DIR={run_dir}", out.getvalue())

    def test_broken_stderr_after_an_unconfirmed_worker_keeps_quarantine_and_exits_5(self):
        removed = []
        real_rmtree = sr.shutil.rmtree
        for exc in BROKEN_STREAM_ERRORS:
            with self.subTest(exc=type(exc).__name__):
                for d in self.run_dirs():
                    real_rmtree(d)
                removed.clear()
                self.worker.fail = lambda d: unconfirmed("worker pid 4242 not confirmed dead", 4242, d,
                                                         None, time.time() + 600)
                with mock.patch.object(sr.shutil, "rmtree",
                                       lambda p, *a, **k: (removed.append(Path(p)), real_rmtree(p, *a, **k))):
                    code, _out, _err = self.main_broken(deps=["requirements.txt"], err_exc=exc)
                self.assertEqual(code, 5)
                run_dir = self.only_run_dir()
                job_dir = run_dir / "deps"
                self.assertTrue(job_dir.is_dir())
                self.assertNotIn(job_dir, removed)
                m = json.loads((run_dir / "manifest.json").read_text())
                self.assertEqual(m["runner_status"], "infrastructure")
                self.assertEqual(m["cleanup"], "unconfirmed")
                self.assertEqual(m["quarantine"]["pid"], 4242)
                self.assertEqual(m["quarantine"]["path"], str(job_dir))
                self.assertEqual(m["quarantine"]["cleanup"], "unconfirmed")
                self.assertEqual(self.fake.creates(), [])

    def test_broken_stderr_when_the_download_dir_is_retained_is_still_exit_5(self):
        real_rmtree = sr.shutil.rmtree

        def rmtree(p, *a, **k):
            if Path(p).name == "deps":
                return None
            return real_rmtree(p, *a, **k)
        with mock.patch.object(sr.shutil, "rmtree", rmtree):
            code, _out, _err = self.main_broken(deps=["requirements.txt"], err_exc=OSError(28, "full"))
        self.assertEqual(code, 5)
        run_dir = self.only_run_dir()
        m = json.loads((run_dir / "manifest.json").read_text())
        self.assertEqual(m["runner_status"], "infrastructure")
        self.assertEqual(m["deps_dir_retained"], str(run_dir / "deps"))
        real_rmtree(run_dir / "deps")

    def test_broken_stderr_while_listing_quarantine_does_not_stop_a_clean_run(self):
        victim = self.base / "victim"
        victim.mkdir()
        sf.write_quarantine_record(self.scratch, sf.new_run_id(), victim, 4321, time.time() - 99999)
        code, out, err = self.main_broken(err_exc=ValueError("I/O operation on closed file."))
        self.assertEqual(code, 0)
        self.assertGreater(err.attempts, 0)
        self.assertIn("MANIFEST_SHA256=", out.getvalue())

    def test_broken_stdout_on_a_successful_run_is_exit_5_never_a_pass(self):
        for exc in BROKEN_STREAM_ERRORS:
            with self.subTest(exc=type(exc).__name__):
                for d in self.run_dirs():
                    sr.shutil.rmtree(d)
                code, _out, err = self.main_broken(deps=["requirements.txt"], out_exc=exc)
                self.assertEqual(code, 5)
                m = json.loads((self.only_run_dir() / "manifest.json").read_text())
                self.assertEqual(m["command_status"], "exited")  # the manifest is the evidence
                self.assertIn("stdout", err.getvalue())

    def test_broken_stdout_and_stderr_on_a_refusal_stay_exit_2(self):
        code, _out, _err = self.main_broken(deps=["unhashed.txt"], err_exc=OSError(28, "full"),
                                            out_exc=OSError(32, "broken pipe"))
        self.assertEqual(code, 2)
        m = json.loads((self.only_run_dir() / "manifest.json").read_text())
        self.assertEqual(m["runner_status"], "refused")


class BrokenStream(io.StringIO):
    """A text stream whose writes (and flushes) raise -- a full redirected log or a closed pipe."""

    def __init__(self, exc):
        super().__init__()
        self.exc, self.attempts = exc, 0

    def write(self, s):
        self.attempts += 1
        raise self.exc

    def flush(self):
        if self.exc is not None:
            raise self.exc

    def close(self):
        self.exc = None  # IOBase.close flushes; the finaliser must not raise
        super().close()


BROKEN_STREAM_ERRORS = (OSError(28, "No space left on device"), ValueError("I/O operation on closed file."))


# --- gate recheck 2 (B1.5 block A2), finding 10: the PROCESS exit code survives a failed stream ----
# main() returned 5 / 2, but the interpreter flushes a failed stdout/stderr once more while shutting
# down and then replaces the exit code with 120. Only a real child process shows that.

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"

SUCCESS_DRIVER = r'''
import json, subprocess, sys
sys.path.insert(0, sys.argv[1])
import sandbox_run as sr

ID = "sha256:" + "c" * 64
POLICY = {"context": "ctx", "images": {"python-test": {"ref": "r:1", "id": ID, "tools": ["true"]}}}


def done(code, out=b"", err=b""):
    return subprocess.CompletedProcess([], code, stdout=out, stderr=err)


def docker(context, *args, **kw):
    if args[0] == "version":
        return done(0, b"29\n")
    if args[:2] == ("image", "inspect"):
        return done(0, ID.encode())
    if args[0] in ("ps", "rm"):
        return done(0)
    if args[0] == "create":
        return done(0, b"cid\n")
    if args[0] == "inspect":
        if "--format" in args:
            return done(0, b"0 false\n")
        return done(1, b"[]\n", b"Error response from daemon: No such container: " + args[-1].encode())
    raise AssertionError(f"unexpected docker call {args}")


RESULT = {"command_status": "exited", "command_exit": 0, "truncated": False, "exports": {}}
sr.load_policy = lambda: POLICY
sr.docker = docker
sr.stream_start = lambda *a, **k: (b"", b"")
sr.read_result = lambda *a, **k: (RESULT, {})
sys.exit(sr.entry(json.loads(sys.argv[2])))
'''


@contextlib.contextmanager
def dead_pipe():
    """The write end of a pipe whose read end is already closed: every write fails (EPIPE on
    POSIX, EINVAL on Windows) -- a reader that went away."""
    r, w = os.pipe()
    os.close(r)
    try:
        yield w
    finally:
        os.close(w)


class ProcessExitCodeTests(TempMixin, unittest.TestCase):
    def setUp(self):
        self.base = self.tmp()
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith("DOCKER_")}

    def child(self, argv, *, stdout, stderr):
        return subprocess.run([sys.executable, "-I", *argv], stdout=stdout, stderr=stderr,
                              stdin=subprocess.DEVNULL, env=self.env, timeout=180, check=False)

    def refusal_argv(self):
        # --timeout 0 is refused before any docker call, with a diagnostic and a manifest
        return [str(SCRIPTS_DIR / "sandbox_run.py"), "--repo", str(self.base), "--scratch", str(self.base),
                "--tree", SHA1_TREE, "--image", "python-test", "--timeout", "0", "--", "true"]

    def test_refusal_with_failing_stderr_is_process_exit_2(self):
        control = self.child(self.refusal_argv(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(control.returncode, 2, control.stderr)
        self.assertIn(b"REFUSED", control.stderr)
        with dead_pipe() as w:
            res = self.child(self.refusal_argv(), stdout=subprocess.PIPE, stderr=w)
        self.assertEqual(res.returncode, 2, res.stdout)
        self.assertIn(b"MANIFEST_SHA256=", res.stdout)

    def test_refusal_with_both_streams_failing_is_process_exit_2(self):
        with dead_pipe() as w:
            res = self.child(self.refusal_argv(), stdout=w, stderr=w)
        self.assertEqual(res.returncode, 2)

    @NEEDS_GIT
    def test_would_be_success_with_lost_stdout_is_process_exit_5(self):
        repo, tree = make_repo(self.base, {"a.txt": "a\n"})
        scratch = self.base / "scratch"
        scratch.mkdir()
        driver = self.base / "driver.py"
        driver.write_text(SUCCESS_DRIVER, encoding="utf-8")
        args = json.dumps(["--repo", str(repo), "--scratch", str(scratch), "--tree", tree,
                           "--image", "python-test", "--", "true"])
        argv = [str(driver), str(SCRIPTS_DIR), args]
        control = self.child(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(control.returncode, 0, control.stderr)
        self.assertIn(b"COMMAND_EXIT=0", control.stdout)
        with dead_pipe() as w:
            res = self.child(argv, stdout=w, stderr=subprocess.PIPE)
        self.assertEqual(res.returncode, 5, res.stderr)
        self.assertIn(b"could not be written to stdout", res.stderr)
        runs = [d for d in (scratch / "sandbox").iterdir() if (d / "manifest.json").is_file()]
        self.assertEqual(len(runs), 2, runs)
        for run_dir in runs:
            self.assertEqual(json.loads((run_dir / "manifest.json").read_text())["command_status"], "exited")

    def test_main_block_goes_through_the_stream_settling_entry(self):
        tail = (SCRIPTS_DIR / "sandbox_run.py").read_text(encoding="utf-8").rstrip().splitlines()[-2:]
        self.assertEqual(tail, ['if __name__ == "__main__":', "    sys.exit(entry())"])

    def test_settle_leaves_working_streams_alone(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            sr.settle_std_streams()
            self.assertIs(sys.stdout, out)
            self.assertIs(sys.stderr, err)

    def test_settle_replaces_a_failing_stream_without_a_descriptor(self):
        broken = BrokenStream(OSError(28, "full"))
        with mock.patch.object(sys, "stdout", broken):
            sr.settle_std_streams()
            replaced = sys.stdout
            self.assertIsNot(replaced, broken)
            replaced.write("dropped\n")
            replaced.flush()
        replaced.close()
        broken.close()


# --- part B: container probes ----------------------------------------------------------------

PROBE = r'''
import errno, os, socket, sys, time

def say(key, value):
    print("%s=%s" % (key, value), flush=True)

def try_write(path):
    try:
        with open(path, "w") as fh:
            fh.write("x")
        return "WROTE"
    except OSError as exc:
        return "FAIL:" + errno.errorcode.get(exc.errno, str(exc.errno))

def connect(family, addr):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(addr)
        return "CONNECTED"
    except OSError as exc:
        return "UNREACHABLE:" + errno.errorcode.get(exc.errno or 0, type(exc).__name__)
    finally:
        s.close()

what = sys.argv[1]
if what == "write_outside":
    for p in ("/etc/claudex-probe", "/usr/claudex-probe", "/claudex-probe", "/var/claudex-probe",
              "/proc/claudex-probe", "/sys/claudex-probe"):
        say(p, try_write(p))
elif what == "net":
    say("v4_1.1.1.1:53", connect(socket.AF_INET, ("1.1.1.1", 53)))
    say("v4_8.8.8.8:443", connect(socket.AF_INET, ("8.8.8.8", 443)))
    say("v4_gateway", connect(socket.AF_INET, ("172.17.0.1", 80)))
    say("v6", connect(socket.AF_INET6, ("2606:4700:4700::1111", 53, 0, 0)))
    try:
        socket.getaddrinfo("host.docker.internal", 80)
        say("host.docker.internal", "RESOLVED")
    except OSError:
        say("host.docker.internal", "UNRESOLVABLE")
    say("interfaces", ",".join(sorted(os.listdir("/sys/class/net"))))
elif what == "ident":
    say("uid", ",".join(map(str, os.getresuid())))
    say("gid", ",".join(map(str, os.getresgid())))
    say("groups", ",".join(map(str, os.getgroups())) or "none")
    status = open("/proc/self/status").read().splitlines()
    for line in status:
        if line.startswith(("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb", "NoNewPrivs")):
            k, v = line.split(":")
            say(k, v.strip())
    say("docker_sock", os.path.exists("/var/run/docker.sock") or os.path.exists("/run/docker.sock"))
    say("cwd", os.getcwd())
elif what == "forkbomb":
    n = 0
    for _ in range(3000):
        try:
            pid = os.fork()
        except OSError as exc:
            say("fork_failed", errno.errorcode.get(exc.errno, exc.errno))
            break
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        n += 1
    say("forked", n)
elif what == "tmpfs_full":
    chunk = b"\0" * (1 << 20)
    total = 0
    err = "none"
    with open("/work/big.bin", "wb", buffering=0) as fh:
        try:
            while total < 800 * (1 << 20):
                fh.write(chunk)
                total += len(chunk)
        except OSError as exc:
            err = errno.errorcode.get(exc.errno, exc.errno)
    say("error", err)
    say("written_mib", total >> 20)
elif what == "write_work":
    say("work_x", try_write("/work/x"))
    say("work_sub", try_write("/work/newfile.txt"))
elif what == "driver_attacks":
    for p, mode in (("/proc/1/fd/1", "wb"), ("/proc/1/fd/0", "rb"), ("/proc/1/fd/2", "wb")):
        try:
            open(p, mode).close()
            say(p, "OPENED")
        except OSError as exc:
            say(p, "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
    try:
        os.kill(1, 9)
        say("kill1", "SENT")
    except OSError as exc:
        say("kill1", "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
    try:
        say("tmp_driver_list", ",".join(os.listdir("/tmp/driver")))
    except OSError as exc:
        say("tmp_driver_list", "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
    for name in ("stdout.txt", "stderr.txt"):
        try:
            open("/tmp/driver/" + name, "rb").close()
            say("tmp_driver_" + name, "OPENED")
        except OSError as exc:
            say("tmp_driver_" + name, "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
    try:
        open("/tmp/driver", "rb")
        say("tmp_driver_dir_open", "OPENED")
    except OSError as exc:
        say("tmp_driver_dir_open", "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
    try:
        say("proc1_mem", "OPENED" if open("/proc/1/mem", "rb") else "?")
    except OSError as exc:
        say("proc1_mem", "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
    try:
        say("proc1_environ", "OPENED" if open("/proc/1/environ", "rb") else "?")
    except OSError as exc:
        say("proc1_environ", "FAIL:" + errno.errorcode.get(exc.errno, exc.errno))
elif what == "fake_tar":
    import io, json, tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        doc = json.dumps({"nonce": "0" * 32, "command_status": "timeout", "command_exit": None,
                          "truncated": False, "durations": {}, "exports": {}, "infrastructure": None}).encode()
        for name, data in (("result.json", doc), ("stdout.txt", b"FORGED"), ("stderr.txt", b"")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    sys.stdout.buffer.write(buf.getvalue())
    sys.stdout.buffer.flush()
    sys.stderr.write("forged\n")
elif what == "umask_export":
    os.umask(0o077)
    with open("/out/private.txt", "w") as fh:
        fh.write("secret-bytes")
    say("mode", oct(os.stat("/out/private.txt").st_mode & 0o777))
elif what == "zombies":
    # a child that exits and is never waited for, and a grandchild orphaned onto the driver
    if os.fork() == 0:
        os._exit(0)
    pid = os.fork()
    if pid == 0:
        if os.fork() == 0:
            time.sleep(0.3)
            os._exit(0)
        os._exit(0)
    time.sleep(1.0)
    say("done", "yes")
elif what == "late_writer":
    if os.fork() == 0:
        time.sleep(2.0)
        with open("/out/late.txt", "w") as fh:
            fh.write("late")
        os._exit(0)
    say("parent", "exits")
elif what == "export_ok":
    with open("/out/made.txt", "w") as fh:
        fh.write("made-in-container")
elif what == "export_symlink":
    os.symlink("/etc/passwd", "/out/link.txt")
elif what == "read_data":
    print(open("/work/data.txt").read(), end="")
else:
    sys.exit(64)
'''

POISON = "raise SystemExit(99)\n"


def parse_kv(text: str) -> dict:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


class Run:
    def __init__(self, code, out, err):
        self.code, self.err = code, err
        self.info = parse_kv(out)
        self.run_dir = Path(self.info["RUN_DIR"]) if "RUN_DIR" in self.info else None

    def text(self, name):
        return (self.run_dir / name).read_bytes().decode("utf-8", "replace")

    def kv(self):
        return parse_kv(self.text("stdout.txt"))

    def manifest(self):
        return json.loads(self.text("manifest.json"))


@unittest.skipUnless(DOCKER_TESTS, "container probes need CLAUDEX_DOCKER_TESTS=1 and the local image")
class ContainerProbes(TempMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keep = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.repo, cls.tree = make_repo(Path(cls._keep.name), {"probe.py": PROBE, "data.txt": "pinned\n"})

    @classmethod
    def tearDownClass(cls):
        cls._keep.cleanup()

    def setUp(self):
        self.clean_env()

    # Run ids of the runners THIS class started. Cleanup is checked against them only: another
    # session's legitimate run is not this suite's leftover (closing gate, block A, finding 5).
    owned: set = set()

    def sandbox(self, argv, repo=None, tree=None, exports=(), timeout=None, extra=(), scratch=None):
        scratch = scratch or self.tmp()
        args = ["--repo", str(repo or self.repo), "--scratch", str(scratch), "--tree", tree or self.tree,
                "--image", "python-test", *extra]
        for name in exports:
            args += ["--export", name]
        if timeout is not None:
            args += ["--timeout", str(timeout)]
        res = Run(*run_main(args + ["--", *argv]))
        runs = scratch / "sandbox"
        self.last_ids = {p.name[len("run-"):] for p in runs.glob("run-*")} if runs.is_dir() else set()
        ContainerProbes.owned |= self.last_ids
        return res

    def own_left(self, ids=None) -> set:
        """Containers still present for the given run ids (default: the last sandbox() call)."""
        ids = self.last_ids if ids is None else ids
        self.assertTrue(ids, "the run left no run directory, so its id is unknown")
        return set().union(*(docker_ids(f"claudex.run={i}") for i in ids))

    def probe(self, what, **kw):
        res = self.sandbox(["python3", "probe.py", what], **kw)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info.get("COMMAND_STATUS"), "exited", res.err)
        return res

    # Verification 1 ---------------------------------------------------------------------
    def test_v1_manifest_binds_input_image_and_argv(self):
        res = self.sandbox(["sh", "-c", "echo hello"])
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "exited")
        self.assertEqual(res.info["COMMAND_EXIT"], "0")
        m = res.manifest()
        # Inspection A, finding 12: the expected hash is reconstructed from git's own listing
        # and blob bytes, not by calling the snapshot code that produced the manifest value.
        self.assertEqual(m["input_sha256"], independent_input_hash(self.repo, self.tree))
        self.assertEqual(m["tree"], self.tree)
        self.assertEqual(m["cleanup"], "confirmed")
        self.assertEqual(m["argv"], ["sh", "-c", "echo hello"])
        self.assertEqual(m["image_id"], sr.load_policy()["images"]["python-test"]["id"])
        self.assertEqual(res.text("stdout.txt"), "hello\n")
        self.assertEqual(hashlib.sha256((res.run_dir / "manifest.json").read_bytes()).hexdigest(),
                         res.info["MANIFEST_SHA256"])

    # Verification 2 ---------------------------------------------------------------------
    def test_v2_write_outside_work_fails(self):
        kv = self.probe("write_outside").kv()
        self.assertEqual(len(kv), 6)
        for path, outcome in kv.items():
            self.assertTrue(outcome.startswith("FAIL:"), f"{path}: {outcome}")

    def test_v2_network_unreachable(self):
        kv = self.probe("net").kv()
        for key in ("v4_1.1.1.1:53", "v4_8.8.8.8:443", "v4_gateway", "v6"):
            self.assertTrue(kv[key].startswith("UNREACHABLE"), f"{key}: {kv[key]}")
        self.assertEqual(kv["host.docker.internal"], "UNRESOLVABLE")
        self.assertEqual(kv["interfaces"], "lo")

    def test_v2_identity_capabilities_and_no_docker_socket(self):
        kv = self.probe("ident").kv()
        self.assertEqual(kv["uid"], "65532,65532,65532")
        self.assertEqual(kv["gid"], "65532,65532,65532")
        self.assertEqual(kv["groups"], "none")
        for cap in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
            self.assertEqual(int(kv[cap], 16), 0, f"{cap}={kv[cap]}")
        # The bounding set is inherited from the container and keeps exactly the three capabilities
        # the driver needs (KILL=5, SETGID=6, SETUID=7 -> 0xe0); with no_new_privs it cannot grant
        # anything, but it must never be wider than that.
        self.assertEqual(int(kv["CapBnd"], 16) & ~0xE0, 0, f"CapBnd={kv['CapBnd']}")
        self.assertEqual(kv["NoNewPrivs"], "1")
        self.assertEqual(kv["docker_sock"], "False")
        self.assertEqual(kv["cwd"], "/work")

    def test_v2_id_command_prints_65532(self):
        res = self.sandbox(["id", "-u"])
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.text("stdout.txt").strip(), "65532")

    def test_v2_fork_bomb_is_stopped_by_the_pids_limit(self):
        res = self.probe("forkbomb", timeout=120)
        kv = res.kv()
        self.assertIn("fork_failed", kv, "the fork bomb was not stopped")
        self.assertLess(int(kv["forked"]), 520)
        self.assertEqual(res.manifest()["cleanup"], "confirmed")

    def test_v2_tmpfs_cap_stops_a_large_write(self):
        res = self.probe("tmpfs_full", timeout=120)
        kv = res.kv()
        self.assertEqual(kv["error"], "ENOSPC")
        self.assertLessEqual(int(kv["written_mib"]), 512)

    def test_v2_output_beyond_cap_is_cut_and_killed(self):
        res = self.sandbox(["yes"], timeout=120)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "output_limit")
        self.assertEqual(res.info["COMMAND_EXIT"], "-")
        self.assertTrue(res.manifest()["truncated"])
        self.assertLessEqual(len((res.run_dir / "stdout.txt").read_bytes()), sr.CAPTURE_CAP)

    # Verification 3 ---------------------------------------------------------------------
    def test_v3_edits_in_work_leave_the_host_untouched(self):
        before = sorted(p.name for p in self.repo.iterdir())
        status_before = git(self.repo, "status", "--porcelain")
        kv = self.probe("write_work").kv()
        self.assertEqual(kv["work_x"], "WROTE")
        self.assertEqual(kv["work_sub"], "WROTE")
        self.assertEqual(sorted(p.name for p in self.repo.iterdir()), before)
        self.assertFalse((self.repo / "x").exists())
        self.assertFalse((self.repo / "newfile.txt").exists())
        self.assertEqual(git(self.repo, "status", "--porcelain"), status_before)

    def test_v3_export_of_uncreated_file_is_missing_even_if_host_has_one(self):
        root = self.tmp()
        repo, tree = make_repo(root, {"probe.py": PROBE})
        (repo / "coverage.xml").write_text("STALE")  # untracked, on the host
        res = self.sandbox(["sh", "-c", "true"], repo=repo, tree=tree, exports=["coverage.xml"])
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.manifest()["exported"], {"coverage.xml": "missing"})
        self.assertFalse((res.run_dir / "out" / "coverage.xml").exists())

    def test_v3_export_created_by_the_command_is_returned(self):
        res = self.sandbox(["python3", "probe.py", "export_ok"], exports=["made.txt"])
        self.assertEqual(res.code, 0, res.err)
        data = b"made-in-container"
        self.assertEqual((res.run_dir / "out" / "made.txt").read_bytes(), data)
        self.assertEqual(res.manifest()["exported"], {"made.txt": hashlib.sha256(data).hexdigest()})

    def test_v3_export_that_is_a_symlink_is_not_returned(self):
        res = self.sandbox(["python3", "probe.py", "export_symlink"], exports=["link.txt"])
        self.assertEqual(res.code, 0, res.err)
        self.assertNotIn("root:", json.dumps(res.manifest()))
        self.assertFalse((res.run_dir / "out" / "link.txt").exists())
        self.assertTrue(res.manifest()["exported"]["link.txt"].startswith("refused:"))

    # Verification 3b --------------------------------------------------------------------
    def test_v3b_container_sees_the_pinned_bytes_after_a_working_tree_edit(self):
        root = self.tmp()
        repo, tree = make_repo(root, {"probe.py": PROBE, "data.txt": "pinned\n"})
        (repo / "data.txt").write_text("EDITED AFTER PINNING\n")
        res = self.sandbox(["python3", "probe.py", "read_data"], repo=repo, tree=tree)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.text("stdout.txt"), "pinned\n")
        self.assertEqual(res.manifest()["tree"], tree)
        self.assertEqual(res.info["TREE"], tree)

    # Verification 3c --------------------------------------------------------------------
    def test_v3c_command_exit_2_is_not_a_refusal(self):
        res = self.sandbox(["sh", "-c", "exit 2"])
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "exited")
        self.assertEqual(res.info["COMMAND_EXIT"], "2")
        self.assertEqual(res.manifest()["command_exit"], 2)

    def test_v3c_timeout(self):
        started = time.monotonic()
        res = self.sandbox(["sleep", "60"], timeout=3)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "timeout")
        self.assertEqual(res.info["COMMAND_EXIT"], "-")
        self.assertIsNone(res.manifest()["command_exit"])
        self.assertLess(time.monotonic() - started, 55)

    def test_v3c_path_to_a_listed_tool_is_refused_before_any_container(self):
        # Inspection round 2, part A, finding A9: only bare tool names pass the preflight. The
        # driver's own `not_started` path stays covered in test_sandbox_driver.py.
        res = self.sandbox(["/no/such/python3"])
        self.assertEqual(res.code, 2, res.err)
        self.assertIn("bare", res.err)
        self.assertEqual(self.own_left(), set())

    def test_v3c_unlisted_tool_is_refused_before_any_container(self):
        res = self.sandbox(["/no/such/binary"])
        self.assertEqual(res.code, 2, res.err)
        self.assertIn("B1.5", res.err)
        self.assertEqual(self.own_left(), set())

    # Verification 4 / 4a ----------------------------------------------------------------
    def test_v4_symlink_and_submodule_entries_are_refused_and_leave_no_container(self):
        link_oid = git(self.repo, "hash-object", "-w", "--stdin", data=b"data.txt")
        commit = git(self.repo, "rev-parse", "HEAD")
        cases = {"symlink": tree_with_entry(self.repo, "120000", "link", link_oid),
                 "submodule": tree_with_entry(self.repo, "160000", "sub", commit)}
        for name, tree in cases.items():
            with self.subTest(entry=name):
                res = self.sandbox(["true"], tree=tree)
                self.assertEqual(res.code, 2, res.err)
                self.assertIn("REFUSED", res.err)
                # Inspection A, finding 10: a refused run leaves a manifest saying so.
                self.assertEqual(res.manifest()["runner_status"], "refused")
                self.assertEqual(res.manifest()["cleanup"], "not_needed")
                self.assertEqual(self.own_left(), set())

    def test_v4_missing_tree_object_is_refused_and_leaves_no_container(self):
        res = self.sandbox(["true"], tree="1" * 40)
        self.assertEqual(res.code, 2, res.err)
        self.assertEqual(self.own_left(), set())

    def test_v4a_poisoned_stdlib_modules_do_not_affect_the_driver(self):
        files = {name + ".py": POISON for name in ("json", "tarfile", "os", "io", "hashlib", "sys", "re",
                                                     "stat", "errno", "signal", "time", "encodings",
                                                     "typing", "shutil", "copy", "struct", "zlib")}
        repo, tree = make_repo(self.tmp(), {**files, "keep.txt": "k\n"})
        res = self.sandbox(["sh", "-c", "ls /work | wc -l; echo ok"], repo=repo, tree=tree)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "exited")
        self.assertEqual(res.info["COMMAND_EXIT"], "0")
        lines = res.text("stdout.txt").split()
        self.assertEqual(lines, [str(len(files) + 1), "ok"])

    def test_v4a_zombie_children_are_reaped_and_the_run_succeeds(self):
        res = self.probe("zombies", timeout=120)
        self.assertEqual(res.info["COMMAND_EXIT"], "0", res.err)
        self.assertEqual(res.kv()["done"], "yes")

    # Verification 4b --------------------------------------------------------------------
    def test_v4b_command_cannot_touch_the_driver(self):
        res = self.probe("driver_attacks")
        kv = res.kv()
        for key in ("/proc/1/fd/1", "/proc/1/fd/0", "/proc/1/fd/2", "kill1", "tmp_driver_stdout.txt",
                    "tmp_driver_stderr.txt", "tmp_driver_dir_open", "proc1_mem", "proc1_environ"):
            self.assertTrue(kv[key].startswith("FAIL:"), f"{key}: {kv[key]}")
        self.assertTrue(kv["tmp_driver_list"].startswith("FAIL:"), kv["tmp_driver_list"])
        self.assertEqual(res.manifest()["cleanup"], "confirmed")

    def test_v4b_forged_result_tar_never_reaches_the_host_as_result(self):
        res = self.probe("fake_tar")
        m = res.manifest()
        self.assertEqual(m["command_status"], "exited")  # the forgery claimed timeout
        self.assertEqual(m["command_exit"], 0)
        self.assertEqual(res.info["COMMAND_STATUS"], "exited")
        self.assertIn(b"FORGED", (res.run_dir / "stdout.txt").read_bytes())  # it is only captured output
        names = sorted(p.name for p in res.run_dir.iterdir())
        self.assertEqual(names, ["manifest.json", "result.json", "stderr.txt", "stdout.txt"])
        self.assertNotEqual(json.loads(res.text("result.json"))["nonce"], "0" * 32)

    def test_v4b_background_writer_is_killed_before_packaging(self):
        res = self.sandbox(["python3", "probe.py", "late_writer"], exports=["late.txt"], timeout=60)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.manifest()["exported"], {"late.txt": "missing"})
        self.assertFalse((res.run_dir / "out" / "late.txt").exists())

    # Verification 4c --------------------------------------------------------------------
    def test_v4c_export_created_with_umask_077_is_exported(self):
        res = self.sandbox(["python3", "probe.py", "umask_export"], exports=["private.txt"])
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.kv()["mode"], "0o600")
        self.assertEqual((res.run_dir / "out" / "private.txt").read_bytes(), b"secret-bytes")
        self.assertEqual(res.manifest()["exported"]["private.txt"],
                         hashlib.sha256(b"secret-bytes").hexdigest())

    # Verification 5 ---------------------------------------------------------------------
    def test_v5_docker_host_set_exits_2(self):
        os.environ["DOCKER_HOST"] = "tcp://127.0.0.1:2375"
        res = self.sandbox(["true"])
        self.assertEqual(res.code, 2, res.err)
        os.environ.pop("DOCKER_HOST")
        os.environ["DOCKER_CONTEXT"] = "default"
        self.assertEqual(self.sandbox(["true"]).code, 2)

    def test_v5_image_id_mismatch_exits_2_via_a_policy_copy(self):
        policy = json.loads(json.dumps(sr.load_policy()))
        policy["images"]["python-test"]["id"] = "sha256:" + "0" * 64
        copy = self.tmp() / "policy.json"
        copy.write_text(json.dumps(policy))
        real = sr.load_policy
        # POLICY_FILE is also pointed at the copy, as a runner that reads it late would need.
        with mock.patch.object(sr, "POLICY_FILE", copy), mock.patch.object(sr, "load_policy",
                                                                           lambda: real(copy)):
            res = self.sandbox(["true"])
        self.assertEqual(res.code, 2, res.err)
        self.assertIn("does not have the id", res.err)
        self.assertEqual(self.own_left(), set())

    def test_v5_unknown_image_name_exits_2_no_pull(self):
        scratch = self.tmp()
        code, _out, err = run_main(["--repo", str(self.repo), "--scratch", str(scratch), "--tree", self.tree,
                                    "--image", "does-not-exist", "--", "true"])
        self.assertEqual(code, 2, err)

    # Inspection A, finding 11: OOM, an externally killed driver, the janitor lifecycle ------
    def test_v3c_memory_hog_is_oom(self):
        res = self.sandbox(["python3", "-c", "x = b'x' * (6 * 1024 ** 3)"], timeout=180)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "oom")
        self.assertEqual(res.info["COMMAND_EXIT"], "-")
        self.assertEqual(res.manifest()["cleanup"], "confirmed")

    @staticmethod
    def own_run_id(scratch: Path, stop: threading.Event, wait: float = 120):
        """The run id of the ONE runner started on `scratch`, read from its run directory -- so a
        probe acts on its own container by exact name and never on another session's (inspection
        round 2, part A, finding 16)."""
        end = time.monotonic() + wait
        while not stop.is_set() and time.monotonic() < end:
            runs = list((scratch / "sandbox").glob("run-*")) if (scratch / "sandbox").is_dir() else []
            if runs:
                return runs[0].name[len("run-"):]
            time.sleep(0.2)
        return None

    @staticmethod
    def container_state(name: str, env: dict) -> str:
        res = subprocess.run(["docker", "--context", CONTEXT, "inspect", "--format", "{{.State.Status}}", name],
                             capture_output=True, env=env, timeout=60)
        return res.stdout.decode().strip() if res.returncode == 0 else ""

    def test_v5_externally_killed_driver_is_infrastructure_and_cleaned_up(self):
        env = sr.client_env()
        scratch = self.tmp()
        stop, killed = threading.Event(), []

        def killer():
            run_id = self.own_run_id(scratch, stop)
            if run_id is None:
                return
            name = f"claudex-run-{run_id}"
            while not stop.is_set():
                if self.container_state(name, env) == "running":
                    time.sleep(2)
                    subprocess.run(["docker", "--context", CONTEXT, "kill", name], capture_output=True,
                                   env=env, timeout=60)
                    killed.append(name)
                    return
                time.sleep(0.3)

        t = threading.Thread(target=killer, daemon=True)
        t.start()
        try:
            res = self.sandbox(["sleep", "60"], timeout=120, scratch=scratch)
        finally:
            stop.set()
            t.join(30)
        self.assertEqual(len(killed), 1, "the probe never found its own container")
        self.assertEqual(res.code, 5, res.err)
        self.assertIn("INFRASTRUCTURE", res.err)
        m = res.manifest()
        self.assertEqual(m["runner_status"], "infrastructure")
        self.assertEqual(m["cleanup"], "confirmed")
        self.assertEqual(self.container_state(killed[0], env), "")

    def test_v5_killed_runner_leaves_its_container_to_the_janitor_after_expiry(self):
        # Inspection round 2, part A, finding 11: the REAL runner is killed mid-run. Its container
        # must survive while within the deadline the runner generated, and the janitor must
        # remove exactly it once that deadline plus the grace has passed.
        env = sr.client_env()
        scratch = self.tmp()
        timeout = 120
        started = int(time.time())
        runner = subprocess.Popen(
            [sys.executable, str(Path(sr.__file__)), "--repo", str(self.repo), "--scratch", str(scratch),
             "--tree", self.tree, "--image", "python-test", "--timeout", str(timeout), "--", "sleep", "100"],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stop = threading.Event()
        run_id = None
        try:
            run_id = self.own_run_id(scratch, stop)
            self.assertIsNotNone(run_id, "runner never created its run directory")
            name = f"claudex-run-{run_id}"
            end = time.monotonic() + 120
            while self.container_state(name, env) != "running" and time.monotonic() < end:
                time.sleep(0.3)
            self.assertEqual(self.container_state(name, env), "running")
        finally:
            runner.kill()
            runner.wait(30)
        self.addCleanup(lambda: subprocess.run(["docker", "--context", CONTEXT, "rm", "-f", name],
                                               capture_output=True, env=env, timeout=60))
        # The runner is gone; its container is not, and nothing removed it.
        self.assertIn(self.container_state(name, env), ("running", "exited"))
        label = subprocess.run(["docker", "--context", CONTEXT, "inspect", "--format",
                                '{{index .Config.Labels "claudex.deadline"}}', name],
                               capture_output=True, env=env, timeout=60).stdout.decode().strip()
        deadline = int(label)
        self.assertGreaterEqual(deadline, started + timeout + 300)
        self.assertLessEqual(deadline, int(time.time()) + timeout + 300)
        # within the deadline: the janitor keeps it
        self.assertEqual(sr.janitor(CONTEXT, run_id=run_id), [])
        self.assertNotEqual(self.container_state(name, env), "")
        # still within the grace after the deadline: kept
        self.assertEqual(sr.janitor(CONTEXT, now=deadline + sr.JANITOR_GRACE - 5, run_id=run_id), [])
        # past deadline + grace: removed, and proven gone
        removed = sr.janitor(CONTEXT, now=deadline + sr.JANITOR_GRACE + 5, run_id=run_id)
        self.assertEqual(len(removed), 1)
        self.assertEqual(self.container_state(name, env), "")

    def test_v5_janitor_removes_an_abandoned_container_and_keeps_a_live_one(self):
        env = sr.client_env()
        image = sr.load_policy()["images"]["python-test"]["id"]
        now = int(time.time())
        made = {}
        for name, deadline in (("abandoned", now - sr.JANITOR_GRACE - 600), ("live", now + 3600)):
            res = subprocess.run(["docker", "--context", CONTEXT, "create", "--label", "claudex.run=janitor-test",
                                  "--label", f"claudex.deadline={deadline}", "--network", "none", image, "true"],
                                 capture_output=True, env=env, timeout=60)
            self.assertEqual(res.returncode, 0, res.stderr)
            made[name] = res.stdout.decode().strip()
        self.addCleanup(lambda: subprocess.run(["docker", "--context", CONTEXT, "rm", "-f", *made.values()],
                                               capture_output=True, env=env, timeout=60))
        removed = sr.janitor(CONTEXT)
        present = docker_ids("claudex.run=janitor-test")
        self.assertTrue(any(made["abandoned"].startswith(r) or r.startswith(made["abandoned"][:12])
                            for r in removed), removed)
        self.assertNotIn(made["abandoned"][:12], {c[:12] for c in present})
        # positive control: the container within its deadline is untouched
        self.assertIn(made["live"][:12], {c[:12] for c in present})

    def test_v5_janitor_removes_an_expired_network_and_keeps_a_live_one(self):
        # Plan B2 approach 11 (U6), against the real daemon: listing by label, removal and the
        # absence proof ("network <ref> not found"). Narrowed to this test's own run id.
        env = sr.client_env()
        run_id = "janitor-net-" + uuid.uuid4().hex[:12]
        now = int(time.time())
        made = {}
        for name, deadline in (("abandoned", now - sr.JANITOR_GRACE - 600), ("live", now + 3600)):
            res = subprocess.run(["docker", "--context", CONTEXT, "network", "create", "--internal",
                                  "--label", f"claudex.run={run_id}", "--label", f"claudex.deadline={deadline}",
                                  f"claudex-{run_id}-{name}"], capture_output=True, env=env, timeout=60)
            self.assertEqual(res.returncode, 0, res.stderr)
            made[name] = res.stdout.decode().strip()
        self.addCleanup(lambda: subprocess.run(["docker", "--context", CONTEXT, "network", "rm", *made.values()],
                                               capture_output=True, env=env, timeout=60))
        removed = sr.janitor(CONTEXT, run_id=run_id, kinds=("container", "network"))
        self.assertEqual(removed, [made["abandoned"]])
        left = subprocess.run(["docker", "--context", CONTEXT, "network", "ls", "-q", "--no-trunc", "--filter",
                               f"label=claudex.run={run_id}"], capture_output=True, env=env, timeout=60)
        self.assertEqual(left.stdout.decode().split(), [made["live"]])
        gone = sr.docker(CONTEXT, "inspect", "--type", "network", made["abandoned"])
        self.assertTrue(sr._absent(gone, "network", made["abandoned"]), gone.stderr)

    # B1.5, real container, no network: only the fetch is bypassed (the worker is faked; the
    # parent's re-verification, the deps tar, the driver's install and closure check are real).
    DEPS_TEST = "import alpha\n\ndef test_alpha():\n    assert alpha.VALUE == 7\n"

    def deps_repo(self, wheels, extra=None):
        files = {"requirements.txt": "".join(req_line(*w) for w in wheels), "test_alpha.py": self.DEPS_TEST,
                 **(extra or {})}
        return make_repo(self.tmp(), files)

    def deps_sandbox(self, argv, wheels, repo, tree, deps=("requirements.txt",), timeout=300):
        worker = FakeWorker(wheels)
        extra = [x for d in deps for x in ("--deps", d)]
        with mock.patch.object(sr.sandbox_fetch, "run_job", worker):
            res = self.sandbox(argv, repo=repo, tree=tree, extra=extra, timeout=timeout)
        self.assertEqual(len(worker.calls), 1 if deps else 0)
        return res

    PYTEST = ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "test_alpha.py"]

    def test_v6_deps_install_and_import_pass_end_to_end(self):
        wheel = make_wheel("alpha", "1.0")
        repo, tree = self.deps_repo([wheel])
        res = self.deps_sandbox(self.PYTEST, [wheel], repo, tree)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "exited", res.text("install.txt"))
        self.assertEqual(res.info["COMMAND_EXIT"], "0", res.text("stdout.txt"))
        m = res.manifest()
        self.assertEqual(m["deps"]["install"], {"status": "installed", "reason": None,
                                                "installed": [["alpha", "1.0"]]})
        self.assertEqual(m["deps"]["requirements"][0]["sha256"], sha(wheel[1]))
        self.assertEqual(res.info["REQUIREMENTS_SHA256"], m["deps"]["requirements_sha256"])
        self.assertTrue((res.run_dir / "install.txt").is_file())
        self.assertFalse((res.run_dir / "deps").exists())
        self.assertEqual(m["cleanup"], "confirmed")
        self.assertEqual(self.own_left(), set())

    def test_v6_the_same_test_without_deps_fails_as_in_b1(self):
        wheel = make_wheel("alpha", "1.0")
        repo, tree = self.deps_repo([wheel])
        res = self.deps_sandbox(self.PYTEST, [wheel], repo, tree, deps=())
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "exited")
        self.assertEqual(res.info["COMMAND_EXIT"], "2")  # pytest: collection error (ImportError)
        self.assertIsNone(res.manifest()["deps"])
        self.assertFalse((res.run_dir / "install.txt").exists())

    def test_v6_a_missing_declared_dependency_is_deps_failed(self):
        wheel = make_wheel("alpha", "1.0", requires=["beta>=1"])
        repo, tree = self.deps_repo([wheel])
        res = self.deps_sandbox(["sh", "-c", "echo RAN"], [wheel], repo, tree)
        self.assertEqual(res.code, 0, res.err)
        self.assertEqual(res.info["COMMAND_STATUS"], "deps_failed")
        self.assertEqual(res.info["COMMAND_EXIT"], "-")
        m = res.manifest()
        self.assertEqual(m["deps"]["install"]["status"], "failed")
        self.assertIn("beta", m["deps"]["install"]["reason"])
        self.assertEqual(res.text("stdout.txt"), "")
        self.assertEqual(self.own_left(), set())

    def test_v6_the_command_cannot_alter_the_installed_tree(self):
        wheel = make_wheel("alpha", "1.0")
        repo, tree = self.deps_repo([wheel])
        script = ("import alpha, errno, os\n"
                  "for p in (os.path.join(os.path.dirname(alpha.__file__), 'x.py'), alpha.__file__):\n"
                  "    try:\n        open(p, 'a').close(); print('WROTE')\n"
                  "    except OSError as e:\n        print(errno.errorcode[e.errno])\n")
        res = self.deps_sandbox(["python3", "-c", script], [wheel], repo, tree)
        self.assertEqual(res.info["COMMAND_EXIT"], "0", res.text("stderr.txt"))
        self.assertEqual(res.text("stdout.txt").split(), ["EACCES", "EACCES"])

    # Cleanup proof (runs last: named after the others and defined last) --------------------
    def test_zz_no_container_is_left(self):
        # only what this class started; claudex.measure=1 and janitor-test are labels no runner uses
        self.assertTrue(ContainerProbes.owned, "no probe recorded a run id")
        self.assertEqual(self.own_left(ContainerProbes.owned), set())
        self.assertEqual(docker_ids("claudex.run=janitor-test"), set())
        self.assertEqual(docker_ids("claudex.measure=1"), set())



# Plan B1.5 Verification 2 with the REAL fetch: pypi.org and files.pythonhosted.org are
# contacted, so this is opt-in on top of the container suite. Hashes taken from
# https://pypi.org/simple/<name>/ (PEP 691 JSON) on 2026-11-01.
SIX_WHL_SHA = "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274"  # py2.py3-none-any
MARKUPSAFE_X86_SHA = "ccfcd093f13f0f0b7fdd0f198b90053bf7b2f02a3927a30e63f3ccc9df56b676"  # cp313 manylinux x86_64
MARKUPSAFE_ARM_SHA = "133a43e73a802c5562be9bbcd03d090aa5a1fe899db609c29e8c8d815c5f6de6"  # cp313 manylinux aarch64


@unittest.skipUnless(DOCKER_TESTS and os.environ.get("CLAUDEX_NETWORK_TESTS") == "1",
                     "real PyPI fetch: needs CLAUDEX_DOCKER_TESTS=1 and CLAUDEX_NETWORK_TESTS=1")
class NetworkDepsTests(TempMixin, unittest.TestCase):
    def test_real_fetch_of_a_pure_and_a_compiled_wheel(self):
        self.clean_env()
        requirements = (f"six==1.17.0 --hash=sha256:{SIX_WHL_SHA}\n"
                        f"markupsafe==3.0.3 \\\n    --hash=sha256:{MARKUPSAFE_ARM_SHA} \\\n"
                        f"    --hash=sha256:{MARKUPSAFE_X86_SHA}\n")
        probe = ("import six, markupsafe\nfrom markupsafe import _speedups\n"
                 "print(six.__version__, markupsafe.escape('<x>'), _speedups.__file__.endswith('.so'))\n")
        base = self.tmp()
        repo, tree = make_repo(base, {"requirements.txt": requirements, "probe.py": probe})
        scratch = base / "scratch"
        scratch.mkdir()
        code, out, err = run_main(["--repo", str(repo), "--scratch", str(scratch), "--tree", tree,
                                   "--image", "python-test", "--deps", "requirements.txt",
                                   "--timeout", "600", "--", "python3", "probe.py"])
        res = Run(code, out, err)
        run_ids = {p.name[len("run-"):] for p in (scratch / "sandbox").glob("run-*")}
        self.assertEqual(code, 0, err)
        self.assertEqual(res.info["COMMAND_EXIT"], "0", res.text("stderr.txt") if res.run_dir else err)
        self.assertEqual(res.text("stdout.txt").split(), ["1.17.0", "&lt;x&gt;", "True"])
        wheels = {r["name"]: r for r in res.manifest()["deps"]["requirements"]}
        self.assertEqual(wheels["markupsafe"]["sha256"], MARKUPSAFE_X86_SHA)
        self.assertIn("x86_64", wheels["markupsafe"]["wheel"])
        self.assertEqual(wheels["six"]["sha256"], SIX_WHL_SHA)
        self.assertFalse((res.run_dir / "deps").exists())
        self.assertEqual(set().union(*(docker_ids(f"claudex.run={i}") for i in run_ids)), set())

    def test_v5_an_sdist_only_release_is_refused_and_leaves_nothing(self):
        # docopt 0.6.2 has exactly one distribution, docopt-0.6.2.tar.gz (no wheel at all).
        # sha256 read from https://pypi.org/simple/docopt/ (Accept: application/vnd.pypi.simple.v1+json)
        # on 2026-11-01.
        self.clean_env()
        base = self.tmp()
        repo, tree = make_repo(base, {"requirements.txt": f"docopt==0.6.2 --hash=sha256:{DOCOPT_SDIST_SHA}\n"})
        scratch = base / "scratch"
        scratch.mkdir()
        calls = []
        real_docker = sr.docker

        def spy(context, *args, **kw):
            calls.append(args)
            return real_docker(context, *args, **kw)
        with mock.patch.object(sr, "docker", spy):
            code, out, err = run_main(["--repo", str(repo), "--scratch", str(scratch), "--tree", tree,
                                       "--image", "python-test", "--deps", "requirements.txt",
                                       "--timeout", "600", "--", "true"])
        res = Run(code, out, err)
        self.assertEqual(code, 2, err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("COMMAND_STATUS", res.info)
        m = res.manifest()
        self.assertEqual(m["runner_status"], "refused")
        self.assertIn("docopt", m["reason"])
        self.assertIsNone(m["deps"]["requirements"])
        # nothing in the run dir's deps area, no other leftover beside the manifest
        self.assertFalse((res.run_dir / "deps").exists())
        self.assertEqual(sorted(p.name for p in res.run_dir.iterdir()), ["manifest.json"])
        self.assertFalse((scratch / sf.QUARANTINE_DIR).exists())
        # no container was even created
        self.assertEqual([a for a in calls if a and a[0] in ("create", "start")], [])
        run_ids = {p.name[len("run-"):] for p in (scratch / "sandbox").glob("run-*")}
        self.assertEqual(set().union(*(docker_ids(f"claudex.run={i}") for i in run_ids)), set())


DOCOPT_SDIST_SHA = "49b3a825280bd66b3aa83585ef59c4a8c82f2c8a522dbe754a8bc8d08c85c491"  # docopt-0.6.2.tar.gz


class DeadlineOrderTests(unittest.TestCase):
    """Inspection round 2, part A, finding A1: the snapshot worker's own git timers fire before
    the supervisor's deadline, so an internal timeout is reported (exit 5) instead of killed."""

    def test_supervisor_deadline_is_the_plan_default(self):
        self.assertEqual(sr.SNAPSHOT_DEADLINE, 120)

    def test_internal_timers_are_below_the_supervisor(self):
        self.assertLess(ss.GIT_TIMEOUT, sr.SNAPSHOT_DEADLINE)
        self.assertLess(ss.BATCH_DEADLINE, sr.SNAPSHOT_DEADLINE)


class GitVersionTests(unittest.TestCase):
    """The snapshot refuses a git without --no-lazy-fetch instead of dropping the flag."""

    def test_an_old_git_is_refused_with_a_clear_reason(self):
        with mock.patch.object(ss, "git_version", return_value=(2, 43)):
            with self.assertRaises(ss.SnapshotRefused) as caught:
                ss.require_git()
        self.assertIn("2.44", str(caught.exception))

    def test_an_unreadable_git_version_is_refused(self):
        with mock.patch.object(ss, "git_version", return_value=None):
            with self.assertRaises(ss.SnapshotRefused):
                ss.require_git()

    def test_build_snapshot_checks_the_version_first(self):
        with mock.patch.object(ss, "git_version", return_value=(2, 43)),                 mock.patch.object(ss, "_build", side_effect=AssertionError("must not run")):
            with self.assertRaises(ss.SnapshotRefused):
                ss.build_snapshot(Path("."), "0" * 40)


if __name__ == "__main__":
    unittest.main()
