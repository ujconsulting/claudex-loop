"""sandbox_driver: the in-container driver of the B1 sandbox runner.

Plan B1 (docs/plans/2026-10-27-sicherheitskette, approved round 6), Approach 2 and 5.
The driver runs inside the container as `python3 -I -S -c <source>`; the pure parts
(spec validation, result.json, tar framing, the zombie-aware /proc parser) are tested on
the host. The container-level behaviour has an OPTIONAL smoke class below, skipped unless
CLAUDEX_DOCKER_TESTS=1. Written before scripts/sandbox_driver.py and seen failing first.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import unittest
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import sandbox_driver as sd  # noqa: E402

NONCE = "0123456789abcdef0123456789abcdef"


def good_spec(**over):
    spec = {"argv": ["python3", "-c", "print(1)"], "exports": ["coverage.xml"],
            "capture_cap": 8 * 1024 * 1024, "export_cap": 16 * 1024 * 1024,
            "timeout": 900, "tar_len": 10}
    spec.update(over)
    return spec


class SpecTests(unittest.TestCase):
    def test_good_spec_parses(self):
        s = sd.parse_spec(good_spec())
        self.assertEqual(s.argv, ["python3", "-c", "print(1)"])
        self.assertEqual(s.exports, ["coverage.xml"])
        self.assertEqual((s.capture_cap, s.export_cap, s.timeout, s.tar_len),
                         (8 * 1024 * 1024, 16 * 1024 * 1024, 900, 10))

    def test_unknown_key_rejected(self):
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(good_spec(extra=1))

    def test_missing_key_rejected(self):
        spec = good_spec()
        del spec["timeout"]
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(spec)

    def test_not_an_object_rejected(self):
        for bad in ([], "x", 3, None):
            with self.assertRaises(sd.SpecError):
                sd.parse_spec(bad)

    def test_argv_must_be_nonempty_list_of_strings(self):
        for bad in ("python3 -c x", [], [""], ["a", 3], ["a", None], ["a\x00b"], {"a": 1}):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(good_spec(argv=bad))

    def test_export_names(self):
        for ok in ("coverage.xml", "a", "A_b-c.d", "0", "_x", "-x", "x" * 64):
            self.assertTrue(sd.valid_export_name(ok), ok)
        for bad in ("", ".x", "..", "../x", "/etc/x", "a/b", "a\\b", "C:x", "x" * 65,
                    "a b", "a\n", "caf\u00e9", ".", "x\x00"):
            self.assertFalse(sd.valid_export_name(bad), repr(bad))
        self.assertFalse(sd.valid_export_name(5))

    def test_bad_export_rejected(self):
        for bad in (["../x"], [".x"], "coverage.xml", [1], ["a", "a"], ["a", "b", "c", "d"]):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(good_spec(exports=bad))

    def test_empty_exports_ok(self):
        self.assertEqual(sd.parse_spec(good_spec(exports=[])).exports, [])

    def test_caps_out_of_range(self):
        for key, bad in (("capture_cap", 0), ("capture_cap", -1), ("capture_cap", 10**12),
                         ("export_cap", 0), ("export_cap", 10**12),
                         ("timeout", 0), ("timeout", 3601), ("timeout", -5),
                         ("tar_len", -1), ("tar_len", 10**12),
                         ("timeout", 1.5), ("timeout", "9"), ("timeout", True)):
            with self.assertRaises(sd.SpecError, msg=f"{key}={bad!r}"):
                sd.parse_spec(good_spec(**{key: bad}))

    def test_caps_boundaries_ok(self):
        sd.parse_spec(good_spec(timeout=1, capture_cap=1, export_cap=1, tar_len=0))
        sd.parse_spec(good_spec(timeout=3600))


class HeaderTests(unittest.TestCase):
    def test_header_ok(self):
        nonce, spec = sd.parse_header(NONCE.encode() + b"\n", json.dumps(good_spec()).encode() + b"\n")
        self.assertEqual(nonce, NONCE)
        self.assertEqual(spec.tar_len, 10)

    def test_bad_nonce(self):
        for bad in (b"", b"\n", b"xyz\n", NONCE.upper().encode() + b"\n", NONCE.encode(),
                    (NONCE + "0").encode() + b"\n", NONCE[:-1].encode() + b"\n"):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_nonce(bad)

    def test_spec_line_must_be_json(self):
        with self.assertRaises(sd.SpecError):
            sd.parse_header(NONCE.encode() + b"\n", b"{not json\n")
        with self.assertRaises(sd.SpecError):
            sd.parse_header(NONCE.encode() + b"\n", b"\xff\xfe\n")
        with self.assertRaises(sd.SpecError):
            sd.parse_header(NONCE.encode() + b"\n", b"")

    def test_nonce_available_even_when_spec_bad(self):
        """The driver can still sign an infrastructure result when only the spec is bad."""
        self.assertEqual(sd.parse_nonce(NONCE.encode() + b"\n"), NONCE)


class ResultTests(unittest.TestCase):
    def test_shape(self):
        r = sd.build_result(NONCE, "exited", 0, False, {"command_ms": 5}, {"a": "ab" * 32}, None)
        self.assertEqual(list(r.keys()), ["nonce", "command_status", "command_exit", "truncated",
                                          "durations", "exports", "infrastructure"])
        self.assertEqual(r["nonce"], NONCE)
        self.assertIsNone(r["infrastructure"])

    def test_status_enum(self):
        for st in ("exited", "timeout", "output_limit", "not_started"):
            sd.build_result(NONCE, st, 0 if st == "exited" else None, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "oom", None, False, {}, {}, None)

    def test_exit_only_when_exited(self):
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "timeout", 0, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "exited", None, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "exited", True, False, {}, {}, None)

    def test_export_value_forms(self):
        sd.build_result(NONCE, "exited", 0, False, {}, {"a": "missing", "b": "refused:not regular",
                                                       "c": hashlib.sha256(b"x").hexdigest()}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "exited", 0, False, {}, {"a": "whatever"}, None)

    def test_json_bytes_ascii_and_canonical(self):
        r = sd.build_result(NONCE, "exited", 3, True, {"b": 1, "a": 2}, {}, "caf\u00e9")
        data = sd.result_json_bytes(r)
        data.decode("ascii")
        self.assertEqual(json.loads(data)["command_exit"], 3)
        self.assertEqual(data, sd.result_json_bytes(r))


class TarTests(unittest.TestCase):
    def _members(self, data):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            return [(m, tf.extractfile(m).read()) for m in tf.getmembers()]

    def test_order_regular_only_deterministic(self):
        mem = [("result.json", b"{}"), ("stdout.txt", b"hi\n"), ("stderr.txt", b""),
               ("out/coverage.xml", b"<x/>")]
        a = sd.build_result_tar(mem)
        b = sd.build_result_tar(mem)
        self.assertEqual(a, b)
        got = self._members(a)
        self.assertEqual([m.name for m, _ in got], [n for n, _ in mem])
        for m, content in got:
            self.assertTrue(m.isreg())
            self.assertEqual((m.mtime, m.uid, m.gid, m.mode), (0, 0, 0, 0o644))
        self.assertEqual([c for _, c in got], [c for _, c in mem])

    def test_bad_member_names_refused(self):
        for bad in ("../x", "/abs", "out/", "a/../b", "", "out/a/b", "x\\y", "out/.x", "other.txt"):
            with self.assertRaises(ValueError, msg=bad):
                sd.build_result_tar([(bad, b"")])

    def test_empty_content_ok(self):
        got = self._members(sd.build_result_tar([("stdout.txt", b"")]))
        self.assertEqual(got[0][1], b"")


class MemberCheckTests(unittest.TestCase):
    def test_member_problem(self):
        ok = sd.member_problem
        self.assertIsNone(ok("a/b.py", "file"))
        self.assertIsNone(ok("a", "dir"))
        self.assertIsNone(ok("./a", "file"))
        for name, kind in (("/abs", "file"), ("../x", "file"), ("a/../../x", "file"),
                           ("a", "symlink"), ("a", "hardlink"), ("a", "fifo"), ("a", "device"),
                           ("", "file"), ("a\x00b", "file"), ("C:/x", "file")):
            self.assertIsNotNone(ok(name, kind), (name, kind))


class ProcParserTests(unittest.TestCase):
    TEMPLATE = ("Name:\tsleep\nUmask:\t0022\nState:\t{state}\nTgid:\t12\nPid:\t12\nPPid:\t1\n"
                "Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t65532\t65532\t65532\t65532\n")

    def test_running_sleeping_zombie(self):
        for state, letter in (("R (running)", "R"), ("S (sleeping)", "S"), ("Z (zombie)", "Z"),
                              ("D (disk sleep)", "D"), ("X (dead)", "X")):
            text = self.TEMPLATE.format(state=state, uid=65532)
            self.assertEqual(sd.parse_proc_status(text), (65532, letter))

    def test_root_uid(self):
        self.assertEqual(sd.parse_proc_status(self.TEMPLATE.format(state="S (sleeping)", uid=0)),
                         (0, "S"))

    def test_garbage_raises(self):
        for bad in ("", "Name:\tx\n", "State:\tS (sleeping)\n", "Uid:\t1\n", "Uid:\nState:\tS\n", "Uid:\tx\nState:\tS\n",
                    "State:\n Uid:\tabc\n"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                sd.parse_proc_status(bad)

    def test_scan_proc_separates_zombies(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            def put(pid, state, uid):
                (root / str(pid)).mkdir()
                (root / str(pid) / "status").write_text(
                    self.TEMPLATE.format(state=state, uid=uid), encoding="ascii")
            put(1, "S (sleeping)", 0)
            put(20, "S (sleeping)", 65532)
            put(21, "Z (zombie)", 65532)
            put(22, "R (running)", 65532)
            put(23, "S (sleeping)", 1000)
            (root / "self").mkdir()
            (root / "cpuinfo").write_text("x", encoding="ascii")
            live, zombies = sd.scan_proc(str(root), 65532)
            self.assertEqual(sorted(live), [20, 22])
            self.assertEqual(zombies, [21])

    def test_scan_proc_vanished_process_is_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "30").mkdir()  # no status file: the process exited while scanning
            self.assertEqual(sd.scan_proc(str(root), 65532), ([], []))

    def test_scan_proc_unreadable_proc_fails_closed(self):
        with self.assertRaises(OSError):
            sd.scan_proc(str(REPO / "no-such-proc-dir"), 65532)

    def test_scan_proc_unparseable_status_fails_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "40").mkdir()
            (root / "40" / "status").write_text("garbage", encoding="ascii")
            with self.assertRaises(ValueError):
                sd.scan_proc(str(root), 65532)


class SourceShapeTests(unittest.TestCase):
    """The file is passed whole with `python3 -I -S -c`; it must stay self-contained."""

    def setUp(self):
        self.src = (REPO / "scripts" / "sandbox_driver.py").read_text(encoding="utf-8")

    def test_ascii_only(self):
        self.src.encode("ascii")

    def test_imports_stdlib_only_and_at_top(self):
        import ast
        tree = ast.parse(self.src)
        stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
        seen_def = False
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                seen_def = True
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertFalse(seen_def, "import after a definition")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertIn(node, tree.body, "import not at module top level")
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module]
                for n in names:
                    top = n.split(".")[0]
                    if stdlib is not None:
                        self.assertIn(top, stdlib)
                    self.assertNotIn(top, {"hunt_io", "hunt_run", "codex_ro", "claudex_roles"})

    def test_main_guard(self):
        self.assertIn('if __name__ == "__main__":', self.src)
        self.assertIn("sys.exit(main())", self.src)

    def test_compiles_as_c_argument(self):
        compile(self.src, "<driver>", "exec")


def _inproc_allowed():
    """Root alone is not enough: quiesce() SIGKILLs every uid-65532 process in /proc, so on a
    real host it could hit unrelated services. Only an explicit opt-in INSIDE a container (own
    PID namespace) runs these tests (inspection round 2, B1 finding 4)."""
    return (hasattr(os, "fork") and hasattr(os, "geteuid") and os.geteuid() == 0
            and os.environ.get("CLAUDEX_DRIVER_INPROC") == "1" and os.path.exists("/.dockerenv"))


@unittest.skipUnless(_inproc_allowed(), "needs root inside a throwaway container and CLAUDEX_DRIVER_INPROC=1")
class InProcessDriverTests(unittest.TestCase):
    """The driver's real code paths, run in-process against temp directories.

    These need root (the driver drops to uid 65532 with setuid), so they skip on the Windows
    host and on an unprivileged POSIX user; run them as root in the sandbox image:
    docker --context desktop-linux run --rm --network none -e CLAUDEX_DRIVER_INPROC=1
    -v <repo>:/src:ro claudex-sandbox-python-test:2 sh -c 'cp -r /src /tmp/r && python3 -m unittest -v
    tests.test_sandbox_driver.InProcessDriverTests' (cwd /tmp/r).
    """

    def setUp(self):
        import tempfile
        from unittest import mock
        self.base = tempfile.mkdtemp(prefix="drv")
        os.chmod(self.base, 0o755)
        self.work = os.path.join(self.base, "work")
        self.out = os.path.join(self.base, "out")
        for path in (self.work, self.out):
            os.mkdir(path)
            os.chmod(path, 0o1777)
        self.scratch = os.path.join(self.base, "scratch")
        for name, value in (("WORK", self.work), ("OUT", self.out), ("SCRATCH", self.scratch)):
            patcher = mock.patch.object(sd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        import shutil
        try:
            sd.quiesce()
        finally:
            shutil.rmtree(self.base, ignore_errors=True)

    def run_main(self, argv, files=(), exports=(), capture_cap=8 * 1024 * 1024, timeout=20,
                 tar_bytes=None):
        from unittest import mock
        tar = _snapshot_tar(files) if tar_bytes is None else tar_bytes
        spec = {"argv": list(argv), "exports": list(exports), "capture_cap": capture_cap,
                "export_cap": 16 * 1024 * 1024, "timeout": timeout, "tar_len": len(tar)}
        payload = NONCE.encode() + b"\n" + json.dumps(spec).encode() + b"\n" + tar

        class _Std:
            def __init__(self, data=b""):
                self.buffer = io.BytesIO(data)

        fake_in, fake_out = _Std(payload), _Std()
        with mock.patch.object(sys, "stdin", fake_in), mock.patch.object(sys, "stdout", fake_out):
            self.assertEqual(sd.main(), 0)
        members = {}
        with tarfile.open(fileobj=io.BytesIO(fake_out.buffer.getvalue()), mode="r:") as tf:
            for m in tf.getmembers():
                members[m.name] = tf.extractfile(m).read()
        return json.loads(members["result.json"]), members

    # -- finding 1: output overflow can never satisfy the pass gate
    def test_finite_overflow_with_exit_zero_is_output_limit(self):
        """The command writes more than the cap and exits 0 between two polls."""
        from unittest import mock
        real_sleep = sd.time.sleep
        # Stretch the poll interval so the command is long finished at the next poll: the
        # overflow is first seen by the final check, not by the in-loop check.
        with mock.patch.object(sd.time, "sleep", lambda _s: real_sleep(0.6)):
            result, members = self.run_main(
                ["sh", "-c", "sleep 0.1; head -c 200000 /dev/zero; exit 0"], capture_cap=1000)
        self.assertEqual(result["command_status"], "output_limit")
        self.assertIsNone(result["command_exit"])
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(members["stdout.txt"]), 1000)

    def test_overflow_on_stderr_with_exit_zero_is_output_limit(self):
        from unittest import mock
        real_sleep = sd.time.sleep
        with mock.patch.object(sd.time, "sleep", lambda _s: real_sleep(0.6)):
            result, _ = self.run_main(
                ["sh", "-c", "sleep 0.1; head -c 200000 /dev/zero >&2; exit 0"], capture_cap=1000)
        self.assertEqual((result["command_status"], result["command_exit"]), ("output_limit", None))

    def test_descendant_writing_after_the_command_exited_is_output_limit(self):
        """Closing gate, block B1, SECURITY 3: a background child keeps stdout and writes past
        the cap AFTER the main command exited 0; the capture must still count those bytes and
        never report exited/0.

        Handshake, no timing (closing gate recheck 1, B1 #4): the first quiesce() call is the
        moment after the main child was reaped. It creates `go`; only then does the descendant
        write 2000 bytes (over the 1000-byte cap, under the pipe buffer) and create `done`; only
        then does cleanup proceed."""
        from unittest import mock
        real_quiesce = sd.quiesce
        go, done = os.path.join(self.out, "go"), os.path.join(self.out, "done")
        calls = []

        def handshake_quiesce():
            if not calls:
                calls.append("first")
                with open(go, "w") as handle:
                    handle.write("1")
                end = time.monotonic() + 15
                while not os.path.exists(done) and time.monotonic() < end:
                    time.sleep(0.01)
                calls.append("written" if os.path.exists(done) else "never written")
            return real_quiesce()

        script = ("(while [ ! -f %s ]; do sleep 0.01; done; head -c 2000 /dev/zero; echo d > %s) & exit 0"
                  % (go, done))
        with mock.patch.object(sd, "quiesce", handshake_quiesce):
            result, members = self.run_main(["sh", "-c", script], capture_cap=1000)
        self.assertEqual(calls[:2], ["first", "written"], "the descendant never wrote after the exit")
        self.assertEqual((result["command_status"], result["command_exit"]), ("output_limit", None))
        self.assertTrue(result["truncated"])
        self.assertIsNone(result["infrastructure"])
        self.assertLessEqual(len(members["stdout.txt"]), 1000)

    @staticmethod
    def _open_fds():
        return set(os.listdir("/proc/self/fd"))

    def test_failed_quiescence_is_infrastructure_and_skips_exports(self):
        """Closing gate recheck 1, B1 #5: the capture is never finalised on a failed cleanup."""
        from unittest import mock
        before = self._open_fds()
        with mock.patch.object(sd, "quiesce", lambda: "uid 65532 processes survived SIGKILL"):
            result, members = self.run_main(["sh", "-c", "echo x > %s/e.txt; echo ok"
                                             % self.out], exports=["e.txt"])
        self.assertIn("survived SIGKILL", result["infrastructure"])
        self.assertIsNone(result["command_exit"])
        self.assertEqual(result["exports"], {})
        self.assertNotIn("out/e.txt", members)
        self.assertEqual(self._open_fds() - before, set(), "capture descriptors leaked")

    def test_pipe_held_open_past_the_drain_deadline_is_infrastructure(self):
        """Closing gate recheck 1, B1 #5: a writer that survives (quiesce stubbed to kill nothing)
        keeps the pipe open; the drain gives up within its bound and reports infrastructure."""
        from unittest import mock
        before = self._open_fds()
        started = time.monotonic()
        with mock.patch.object(sd, "quiesce", lambda: None), mock.patch.object(sd, "QUIESCE_SECONDS", 0.5):
            result, _members = self.run_main(["sh", "-c", "sleep 30 & echo started"])
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("did not close", result["infrastructure"])
        self.assertIsNone(result["command_exit"])
        self.assertEqual(result["exports"], {})
        self.assertEqual(self._open_fds() - before, set(), "capture descriptors leaked")

    def test_truncating_the_capture_does_not_hide_an_overflow(self):
        """Closing gate, block B1, SECURITY 3: with a regular capture file the command could write
        past the cap and ftruncate it back before the size check. A pipe cannot be truncated."""
        code = ("import os\nos.write(1, b'x' * 5000)\n"
                "try:\n    os.ftruncate(1, 0)\nexcept OSError:\n    pass\n")
        result, _ = self.run_main(["python3", "-I", "-c", code], capture_cap=1000)
        self.assertEqual((result["command_status"], result["command_exit"]), ("output_limit", None))

    def test_output_within_cap_is_still_exited(self):
        result, members = self.run_main(["sh", "-c", "echo ok"], capture_cap=1000)
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0))
        self.assertFalse(result["truncated"])
        self.assertEqual(members["stdout.txt"], b"ok\n")

    # -- finding 2: nothing of uid 65532 is alive when the exports are read
    def test_background_writer_is_dead_and_content_stable_at_export_time(self):
        from unittest import mock
        ready = os.path.join(self.out, "ready")
        bg = os.path.join(self.out, "bg.txt")
        script = ("(echo x >> %s; echo r > %s; while :; do echo x >> %s; done) >/dev/null 2>&1 & "
                  "while [ ! -f %s ]; do :; done; echo started" % (bg, ready, bg, ready))
        seen = {}
        real_read_export = sd.read_export

        def spy(name, cap):
            seen["live"] = sd.scan_proc(sd.PROC, sd.RUN_UID)[0]
            first = os.path.getsize(bg)
            sd.time.sleep(0.3)
            seen["grew"] = os.path.getsize(bg) != first
            return real_read_export(name, cap)

        with mock.patch.object(sd, "read_export", spy):
            result, members = self.run_main(["sh", "-c", script], exports=["bg.txt"])
        self.assertEqual(result["command_status"], "exited")
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(members["stdout.txt"], b"started\n")
        self.assertEqual(seen["live"], [], "a uid-65532 process was alive at export time")
        self.assertFalse(seen["grew"], "the exported file was still being written")
        self.assertRegex(result["exports"]["bg.txt"], r"^[0-9a-f]{64}$")

    # -- finding 3: the extraction ownership / writability gate refuses and the command never runs
    def assert_refused_and_not_run(self, result, members):
        self.assertIsNotNone(result["infrastructure"], "the gate let the snapshot through")
        self.assertIn("not owned by 65532 or not writable", result["infrastructure"])
        self.assertEqual(result["command_status"], "not_started")
        self.assertIsNone(result["command_exit"])
        self.assertEqual(members["stdout.txt"], b"")
        self.assertFalse(os.path.exists(os.path.join(self.out, "ran")), "the command started")

    def _marker_cmd(self):
        return ["sh", "-c", "echo x > %s" % os.path.join(self.out, "ran")]

    def test_entry_with_wrong_owner_is_refused(self):
        # A root-owned entry in /work (extraction runs as 65532 and cannot create one).
        planted = os.path.join(self.work, "planted.txt")
        with open(planted, "w") as handle:
            handle.write("x")
        self.assertEqual(os.stat(planted).st_uid, 0)
        result, members = self.run_main(self._marker_cmd(), files=[("a.txt", b"a")])
        self.assert_refused_and_not_run(result, members)

    def test_file_without_owner_write_is_refused(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            ti = tarfile.TarInfo("ro.txt")
            ti.size = 1
            ti.mode = 0o444
            tf.addfile(ti, io.BytesIO(b"x"))
        result, members = self.run_main(self._marker_cmd(), tar_bytes=buf.getvalue())
        self.assert_refused_and_not_run(result, members)

    def test_dir_without_owner_write_is_refused(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            ti = tarfile.TarInfo("d")
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o555
            tf.addfile(ti)
        result, members = self.run_main(self._marker_cmd(), tar_bytes=buf.getvalue())
        self.assert_refused_and_not_run(result, members)

    def test_clean_snapshot_still_passes_the_gate(self):
        result, _ = self.run_main(["sh", "-c", "cat a.txt"], files=[("a.txt", b"a")])
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["command_status"], "exited")


# ----------------------------------------------------------------------------------------
# Optional container smoke test. Needs Docker Desktop (context desktop-linux) and the image
# below present locally. Run with CLAUDEX_DOCKER_TESTS=1. Containers carry the label
# claudex.measure=1 and are removed in tearDown; `docker ps -a --filter label=claudex.measure=1`
# must be empty afterwards.
# ----------------------------------------------------------------------------------------
IMAGE = "python@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb"
DOCKER_ENV = dict(os.environ, MSYS_NO_PATHCONV="1")


def _docker(*args, input_bytes=None, timeout=120):
    return subprocess.run(["docker", "--context", "desktop-linux", *args], input=input_bytes,
                          capture_output=True, timeout=timeout, env=DOCKER_ENV)


def _snapshot_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, content in files:
            ti = tarfile.TarInfo(name)
            ti.size = len(content)
            ti.mode = 0o644
            ti.uid = ti.gid = 65532
            tf.addfile(ti, io.BytesIO(content))
    return buf.getvalue()


@unittest.skipUnless(os.environ.get("CLAUDEX_DOCKER_TESTS") == "1", "set CLAUDEX_DOCKER_TESTS=1")
class ContainerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.ids = []
        self.source = (REPO / "scripts" / "sandbox_driver.py").read_text(encoding="utf-8")

    def tearDown(self):
        for cid in self.ids:
            _docker("rm", "-f", cid, timeout=60)

    def run_driver(self, argv, exports=(), files=(), timeout=60, capture_cap=8 * 1024 * 1024):
        tar = _snapshot_tar(files)
        nonce = uuid.uuid4().hex
        spec = {"argv": list(argv), "exports": list(exports), "capture_cap": capture_cap,
                "export_cap": 16 * 1024 * 1024, "timeout": timeout, "tar_len": len(tar)}
        name = "claudex-measure-" + uuid.uuid4().hex[:12]
        create = _docker(
            "create", "--name", name, "--label", "claudex.measure=1", "--pull=never",
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "SETUID",
            "--cap-add", "SETGID", "--cap-add", "KILL", "--security-opt", "no-new-privileges",
            "--user", "0:0", "--pids-limit", "512", "--memory", "4g", "--memory-swap", "4g",
            "--cpus", "2", "--log-driver", "none",
            "--mount", "type=tmpfs,destination=/work,tmpfs-size=268435456,tmpfs-mode=1777",
            "--mount", "type=tmpfs,destination=/out,tmpfs-size=50331648,tmpfs-mode=1777",
            "--tmpfs", "/tmp:size=268435456", "--tmpfs", "/home/run:size=67108864",
            "-e", "HOME=/home/run", "-w", "/", "-i", IMAGE, "python3", "-I", "-S", "-c", self.source)
        self.assertEqual(create.returncode, 0, create.stderr.decode(errors="replace"))
        cid = create.stdout.decode().strip()
        self.ids.append(cid)
        payload = nonce.encode() + b"\n" + json.dumps(spec).encode() + b"\n" + tar
        start = _docker("start", "-ai", cid, input_bytes=payload, timeout=timeout + 60)
        inspect = _docker("inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", cid)
        self.assertEqual(inspect.stdout.decode().strip(), "0 false", start.stderr.decode(errors="replace"))
        self.assertEqual(start.returncode, 0, start.stderr.decode(errors="replace"))
        members = {}
        order = []
        with tarfile.open(fileobj=io.BytesIO(start.stdout), mode="r:") as tf:
            for m in tf.getmembers():
                self.assertTrue(m.isreg())
                order.append(m.name)
                members[m.name] = tf.extractfile(m).read()
        result = json.loads(members["result.json"])
        self.assertEqual(result["nonce"], nonce)
        self.assertEqual(order[:3], ["result.json", "stdout.txt", "stderr.txt"])
        return result, members

    def test_hello(self):
        result, members = self.run_driver(["python3", "-c", "print('hi')"])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(result["command_exit"], 0)
        self.assertEqual(members["stdout.txt"], b"hi\n")
        self.assertIsNone(result["infrastructure"])

    def test_snapshot_extracted_and_nonzero_exit(self):
        result, members = self.run_driver(
            ["python3", "-c", "import sys;print(open('a.txt').read());sys.exit(2)"],
            files=[("a.txt", b"payload")])
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 2))
        self.assertEqual(members["stdout.txt"], b"payload\n")

    def test_export_with_umask_077(self):
        result, members = self.run_driver(
            ["sh", "-c", "umask 077; echo data > /out/x.txt"], exports=["x.txt", "nope.txt"])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(result["exports"]["x.txt"], hashlib.sha256(b"data\n").hexdigest())
        self.assertEqual(result["exports"]["nope.txt"], "missing")
        self.assertEqual(members["out/x.txt"], b"data\n")
        self.assertNotIn("out/nope.txt", members)

    def test_driver_separation(self):
        script = ("echo forged > /proc/1/fd/1 2>/dev/null && echo WROTE; "
                  "kill -9 1 2>/dev/null && echo KILLED; "
                  "cat /proc/1/fd/0 >/dev/null 2>&1 && echo READ0; "
                  "ls /tmp/driver >/dev/null 2>&1 && echo LISTED; "
                  "id -u; true")
        result, members = self.run_driver(["sh", "-c", script])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(members["stdout.txt"].decode().split(), ["65532"])
        self.assertIsNone(result["infrastructure"])

    def test_background_writer_killed_before_packaging(self):
        # The writer announces itself before it loops and the command waits for that, so the
        # writer certainly exists when the command exits. The quiescence itself is asserted in
        # InProcessDriverTests (no live uid-65532 process and a stable file at export time).
        script = ("(echo x >> /out/bg.txt; echo r > /out/ready; while :; do echo x >> /out/bg.txt; done) "
                  ">/dev/null 2>&1 & "
                  "while [ ! -f /out/ready ]; do :; done; echo started")
        result, members = self.run_driver(["sh", "-c", script], exports=["bg.txt"])
        self.assertEqual(result["command_status"], "exited")
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(members["stdout.txt"], b"started\n")
        self.assertRegex(result["exports"]["bg.txt"], r"^[0-9a-f]{64}$")

    def test_timeout(self):
        result, _ = self.run_driver(["sleep", "30"], timeout=2)
        self.assertEqual(result["command_status"], "timeout")
        self.assertIsNone(result["command_exit"])

    def test_output_limit(self):
        result, members = self.run_driver(["sh", "-c", "yes"], capture_cap=65536)
        self.assertEqual(result["command_status"], "output_limit")
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(members["stdout.txt"]), 65536)

    def test_not_started(self):
        result, _ = self.run_driver(["/no/such/binary"])
        self.assertEqual(result["command_status"], "not_started")


if __name__ == "__main__":
    unittest.main()
