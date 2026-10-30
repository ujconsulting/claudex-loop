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
- Part B (only with CLAUDEX_DOCKER_TESTS=1, needs the local image): each probe goes through
  `sandbox_run.main([...])` on a throwaway repository whose tree holds a small probe script,
  so the boundary is measured end to end -- escape probes, "edits are discarded", binding to
  the pinned tree, status separation, snapshot refusals, driver isolation, and the lifecycle
  refusals. Every container carries the label `claudex.run`; the last test proves none is left.

No test writes to the plugin repository, uses a bind mount, or runs git against anything but
a throwaway repository in a temporary directory.
"""
from __future__ import annotations

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
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
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


class CreateArgsTests(unittest.TestCase):
    def setUp(self):
        self.args = sr.create_args("abcd", 1234567890, "sha256:" + "1" * 64, "print('driver')")

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
        self.assertEqual(self.args[-6:], ["sha256:" + "1" * 64, "python3", "-I", "-S", "-c", "print('driver')"])


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

    # Cleanup proof (runs last: named after the others and defined last) --------------------
    def test_zz_no_container_is_left(self):
        # only what this class started; claudex.measure=1 and janitor-test are labels no runner uses
        self.assertTrue(ContainerProbes.owned, "no probe recorded a run id")
        self.assertEqual(self.own_left(ContainerProbes.owned), set())
        self.assertEqual(docker_ids("claudex.run=janitor-test"), set())
        self.assertEqual(docker_ids("claudex.measure=1"), set())



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
