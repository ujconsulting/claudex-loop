"""T24: the fallback's outputs (--out, --append-log) are locked and staged uniquely.

Plan 2026-11-02-t24-t26, steps 11 and 12 (the fallback's own lock reader). The
reviewer is faked through the same seam the other fallback tests use
(`_opener`, plus stubs for configuration and preflight); no network is touched.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import codex_ro  # noqa: E402
import fallback_review  # noqa: E402

REPLY = "1. a\n2. b\n3. c\nVERDICT: REVISE"
IS_WINDOWS = os.name == "nt"


class _Resp:
    def __init__(self, text):
        self.text = text

    def read(self):
        return json.dumps({"choices": [{"message": {"content": self.text},
                                        "finish_reason": "stop"}]}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, text):
        self.text = text

    def open(self, *a, **k):
        return _Resp(self.text)


PROFILE = {"name": "t", "model": "m", "base_url": "http://127.0.0.1:1234/v1",
           "api_key": None, "temperature": 0, "max_tokens": 100, "timeout": 5}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.plan = self.dir / "plan.txt"
        self.plan.write_text("the plan\n", encoding="utf-8")
        self.out = self.dir / "verdict.txt"
        self.log = self.dir / "LOG.md"
        saved = {n: getattr(fallback_review, n) for n in
                 ("reviewer_names", "profile", "preflight", "_opener", "read_confined",
                  "load_dotenv")}
        self.addCleanup(lambda: [setattr(fallback_review, k, v) for k, v in saved.items()])
        fallback_review.reviewer_names = lambda: ["t"]
        fallback_review.profile = lambda name: dict(PROFILE)
        fallback_review.preflight = lambda p: (True, "ok")
        fallback_review._opener = lambda url: _Opener(REPLY)
        fallback_review.read_confined = lambda path, label: Path(path).read_text(encoding="utf-8")
        fallback_review.load_dotenv = lambda path=".env": None

    def run_main(self, out="default", log="default", extra=()):
        out = self.out if out == "default" else out
        log = self.log if log == "default" else log
        argv = ["fallback_review.py", "--plan", str(self.plan), "--append-log", str(log)]
        if out is not None:
            argv += ["--out", str(out)]
        argv += list(extra)
        saved = sys.argv
        sys.argv = argv
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                code = fallback_review.main()
        finally:
            sys.argv = saved
        return code, buf.getvalue()

    def lock_of(self, path):
        return Path(str(path) + fallback_review.LOCK_SUFFIX)

    def parts(self):
        return [p.name for p in self.dir.iterdir() if p.name.endswith(".claudex-part")]


class SuffixPinTests(unittest.TestCase):
    def test_suffix_equals_the_wrappers(self):
        self.assertEqual(fallback_review.LOCK_SUFFIX, codex_ro.LOCK_SUFFIX)


class HappyPathTests(Base):
    def test_run_publishes_and_releases_every_lock(self):
        code, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("VERDICT: REVISE", self.out.read_text(encoding="utf-8"))
        self.assertIn("## Round 1", self.log.read_text(encoding="utf-8"))
        self.assertFalse(self.lock_of(self.out).exists())
        self.assertFalse(self.lock_of(self.log).exists())
        self.assertEqual(self.parts(), [])

    def test_locks_are_held_during_the_review(self):
        seen = {}

        class Spy(_Opener):
            def open(s, *a, **k):
                seen["out"] = self.lock_of(self.out).exists()
                seen["log"] = self.lock_of(self.log).exists()
                return _Resp(REPLY)

        fallback_review._opener = lambda url: Spy(REPLY)
        self.run_main()
        self.assertEqual(seen, {"out": True, "log": True})

    def test_lock_holder_text(self):
        seen = {}

        class Spy(_Opener):
            def open(s, *a, **k):
                seen["t"] = self.lock_of(self.out).read_text(encoding="utf-8")
                return _Resp(REPLY)

        fallback_review._opener = lambda url: Spy(REPLY)
        self.run_main()
        self.assertTrue(seen["t"].startswith(f"fallback_review pid={os.getpid()} "), seen)

    def test_lock_released_when_the_run_fails(self):
        fallback_review.preflight = lambda p: (False, "down")
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertFalse(self.lock_of(self.out).exists())
        self.assertFalse(self.lock_of(self.log).exists())

    def test_stdout_mode_without_out_locks_only_the_log(self):
        code, _ = self.run_main(out=None)
        self.assertEqual(code, 0)
        self.assertFalse(self.lock_of(self.log).exists())


class HeldLockTests(Base):
    def _hold(self, path, text="someone pid=1"):
        lock = self.lock_of(path)
        lock.write_text(text, encoding="utf-8")
        return lock

    def test_held_out_lock_exits_2_and_touches_nothing(self):
        self.out.write_text("PREVIOUS VERDICT", encoding="utf-8")
        lock = self._hold(self.out)
        code, text = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUS VERDICT")
        self.assertFalse(self.log.exists())
        self.assertTrue(lock.exists(), "a foreign lock is never removed")
        self.assertFalse(self.lock_of(self.log).exists(), "taken locks are released")
        self.assertIn(str(lock), text)

    def test_held_log_lock_exits_2_and_releases_the_out_lock(self):
        self.out.write_text("PREVIOUS VERDICT", encoding="utf-8")
        lock = self._hold(self.log)
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUS VERDICT")
        self.assertTrue(lock.exists())
        self.assertFalse(self.lock_of(self.out).exists(), "partial acquisition is released")

    @unittest.skipIf(IS_WINDOWS, "the holder text is never read on Windows")
    def test_holder_is_shown_bounded_on_posix(self):
        self._hold(self.out, "H" * 5000)
        _, text = self.run_main()
        self.assertIn("H" * 200, text)
        self.assertNotIn("H" * 201, text)

    @unittest.skipUnless(IS_WINDOWS, "Windows only")
    def test_holder_never_read_on_windows(self):
        self._hold(self.out, "SECRETHOLDER")
        _, text = self.run_main()
        self.assertNotIn("SECRETHOLDER", text)
        self.assertIn(str(self.lock_of(self.out)), text)

    @unittest.skipIf(IS_WINDOWS, "needs POSIX symlinks and FIFOs")
    def test_lock_symlink_is_not_followed(self):
        secret = self.dir / "secret.txt"
        secret.write_text("TOPSECRET", encoding="utf-8")
        os.symlink(secret, self.lock_of(self.out))
        code, text = self.run_main()
        self.assertEqual(code, 2)
        self.assertNotIn("TOPSECRET", text)

    @unittest.skipIf(IS_WINDOWS, "needs POSIX FIFOs")
    def test_lock_fifo_does_not_block(self):
        os.mkfifo(self.lock_of(self.out))
        t0 = time.time()
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertLess(time.time() - t0, 5)

    @unittest.skipIf(IS_WINDOWS, "needs POSIX semantics")
    def test_lock_hard_link_is_not_read(self):
        other = self.dir / "other.txt"
        other.write_text("OTHERDATA", encoding="utf-8")
        os.link(other, self.lock_of(self.out))
        _, text = self.run_main()
        self.assertNotIn("OTHERDATA", text)

    def test_big_lock_is_not_read_whole(self):
        self._hold(self.out, "B" * (10 * 1024 * 1024))
        code, text = self.run_main()
        self.assertEqual(code, 2)
        self.assertLess(len(text), 5000)


class RefusalTests(Base):
    def test_out_equal_to_log(self):
        code, _ = self.run_main(out=self.log)
        self.assertEqual(code, 2)
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])

    def test_out_equal_to_log_through_a_different_spelling(self):
        (self.dir / "sub").mkdir()
        spelled = self.dir / "sub" / ".." / "LOG.md"
        self.log.write_text("keep", encoding="utf-8")
        code, _ = self.run_main(out=spelled)
        self.assertEqual(code, 2)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "keep")

    def test_reserved_suffix_on_out(self):
        for name in ("x.claudex-lock", "x.claudex-part"):
            code, _ = self.run_main(out=self.dir / name)
            self.assertEqual(code, 2, name)
            self.assertFalse((self.dir / name).exists())

    def test_reserved_suffix_on_log(self):
        for name in ("l.claudex-lock", "l.claudex-part"):
            code, _ = self.run_main(log=self.dir / name)
            self.assertEqual(code, 2, name)
            self.assertFalse((self.dir / name).exists())

    def test_hard_linked_out_is_refused(self):
        other = self.dir / "alias.txt"
        other.write_text("ALIASDATA", encoding="utf-8")
        os.link(other, self.out)
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(other.read_text(encoding="utf-8"), "ALIASDATA")
        self.assertTrue(self.out.exists())

    def test_hard_linked_log_is_refused(self):
        other = self.dir / "other-run-log.md"
        other.write_text("THEIR LOG", encoding="utf-8")
        os.link(other, self.log)
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(other.read_text(encoding="utf-8"), "THEIR LOG")

    def test_hard_link_between_out_and_log_is_refused(self):
        self.log.write_text("L", encoding="utf-8")
        os.link(self.log, self.out)
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "L")

    @unittest.skipIf(IS_WINDOWS, "needs POSIX symlinks")
    def test_symlink_out_and_log_are_refused(self):
        target = self.dir / "t.txt"
        target.write_text("T", encoding="utf-8")
        os.symlink(target, self.out)
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "T")
        self.out.unlink()
        os.symlink(target, self.log)
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "T")


class AliasSpellingTests(Base):
    """Finding 1: Windows aliases are refused on every OS, before any lock path is derived."""

    SPELLINGS = ("verdict.txt.", "verdict.txt ", "verdict.txt:stream", "VERDIC~1.TXT",
                 "ver\x01dict.txt", "foreign.claudex-lock.", "x.claudex-part ",
                 "x.claudex-lock:s")

    def _listing(self):
        return sorted(p.name for p in self.dir.iterdir())

    def test_alias_spellings_refused_for_out_and_log(self):
        before = self._listing()
        for name in self.SPELLINGS:
            for kind in ("out", "log"):
                code, text = self.run_main(**{kind: self.dir / name})
                self.assertEqual(code, 2, (kind, name))
                self.assertIn("alias", text.lower(), (kind, name))
                self.assertEqual(self._listing(), before, (kind, name))

    def test_trailing_dot_alias_cannot_bypass_a_held_lock(self):
        self.out.write_text("PREVIOUS", encoding="utf-8")
        held = self.lock_of(self.out)
        held.write_text("someone pid=1", encoding="utf-8")
        code, _ = self.run_main(out=self.dir / "verdict.txt.")
        self.assertEqual(code, 2)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUS")
        self.assertTrue(held.exists())

    def test_reserved_name_alias_cannot_delete_a_foreign_lock(self):
        foreign = self.dir / "foreign.claudex-lock"
        foreign.write_text("someone pid=1", encoding="utf-8")
        code, _ = self.run_main(out=self.dir / "foreign.claudex-lock.")
        self.assertEqual(code, 2)
        self.assertEqual(foreign.read_text(encoding="utf-8"), "someone pid=1")


class HolderWriteFailureTests(Base):
    """Finding 3: a failure while writing a lock's holder text strands no lock."""

    def test_failure_on_the_second_holder_write_releases_both(self):
        real = os.fdopen
        calls = []

        def flaky(fd, *a, **k):
            calls.append(fd)
            if len(calls) == 2:
                os.close(fd)
                raise OSError("disk full")
            return real(fd, *a, **k)

        os.fdopen = flaky
        try:
            code, text = self.run_main()
        finally:
            os.fdopen = real
        self.assertEqual(code, 2, text)
        self.assertEqual(len(calls), 2)
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])
        self.assertFalse(self.out.exists())
        self.assertFalse(self.log.exists())

    def test_failure_inside_the_holder_write_releases_the_lock(self):
        real = os.fdopen
        n = []

        class Bad:
            def __init__(s, fh):
                s.fh = fh

            def __enter__(s):
                return s

            def __exit__(s, *a):
                s.fh.close()
                return False

            def write(s, t):
                raise OSError("write failed")

        def wrap(fd, *a, **k):
            n.append(1)
            fh = real(fd, *a, **k)
            return Bad(fh) if len(n) == 2 else fh

        os.fdopen = wrap
        try:
            code, _ = self.run_main()
        finally:
            os.fdopen = real
        self.assertEqual(code, 2)
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])


class MetadataErrorTests(Base):
    """Finding 4: only FileNotFoundError means 'absent'."""

    def test_permission_error_on_lstat_refuses_before_touching_outputs(self):
        self.out.write_text("PREVIOUS", encoding="utf-8")
        real = os.lstat
        target = str(self.out)

        def boom(path, *a, **k):
            if str(path) == target:
                raise PermissionError("denied")
            return real(path, *a, **k)

        os.lstat = boom
        try:
            code, text = self.run_main()
        finally:
            os.lstat = real
        self.assertEqual(code, 2, text)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUS")
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])

    def test_missing_output_is_still_absent(self):
        code, _ = self.run_main()
        self.assertEqual(code, 0)


class LogReplacedDuringReviewTests(Base):
    """Finding 2: the append validates the handle it writes through, under the lock."""

    def _swap_during_request(self, swap):
        class Spy(_Opener):
            def open(s, *a, **k):
                swap()
                return _Resp(REPLY)

        fallback_review._opener = lambda url: Spy(REPLY)

    def test_hard_link_swapped_in_during_the_request_is_refused(self):
        other = self.dir / "other-run-log.md"
        other.write_text("THEIR LOG", encoding="utf-8")
        self._swap_during_request(lambda: os.link(other, self.log))
        code, text = self.run_main()
        self.assertNotEqual(code, 0, text)
        self.assertEqual(other.read_text(encoding="utf-8"), "THEIR LOG")
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])

    def test_existing_log_replaced_by_a_hard_link_is_refused(self):
        self.log.write_text("OLD", encoding="utf-8")
        other = self.dir / "other-run-log.md"
        other.write_text("THEIR LOG", encoding="utf-8")

        def swap():
            self.log.unlink()
            os.link(other, self.log)

        self._swap_during_request(swap)
        code, _ = self.run_main()
        self.assertNotEqual(code, 0)
        self.assertEqual(other.read_text(encoding="utf-8"), "THEIR LOG")

    @unittest.skipIf(IS_WINDOWS, "needs POSIX symlinks")
    def test_symlink_swapped_in_during_the_request_is_refused(self):
        target = self.dir / "target.md"
        target.write_text("TARGET", encoding="utf-8")
        self._swap_during_request(lambda: os.symlink(target, self.log))
        code, _ = self.run_main()
        self.assertNotEqual(code, 0)
        self.assertEqual(target.read_text(encoding="utf-8"), "TARGET")

    def test_untouched_log_is_still_appended(self):
        self.log.write_text("HEAD\n", encoding="utf-8")
        code, _ = self.run_main()
        self.assertEqual(code, 0)
        text = self.log.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("HEAD\n"))
        self.assertIn("## Round 1", text)


class _Probe:
    """Records what is opened and read for one path, at the os/builtins level."""

    def __init__(self, path):
        self.path = str(path)
        self.opens = []
        self.fds = set()
        self.requested = 0
        self.consumed = 0

    def __enter__(self):
        import builtins
        self._saved = (os.open, os.read, builtins.open, Path.read_text, Path.read_bytes)
        probe = self
        r_open, r_read, b_open, rt, rb = self._saved

        def s_open(path, flags, *a, **k):
            fd = r_open(path, flags, *a, **k)
            if str(path) == probe.path:
                probe.fds.add(fd)
                probe.opens.append(("os.open", flags))
            return fd

        def s_read(fd, n):
            data = r_read(fd, n)
            if fd in probe.fds:
                probe.requested += n
                probe.consumed += len(data)
            return data

        def s_bopen(file, mode="r", *a, **k):
            if isinstance(file, (str, bytes, os.PathLike)) and str(file) == probe.path:
                probe.opens.append(("builtins.open", mode))
            return b_open(file, mode, *a, **k)

        def s_rt(self_, *a, **k):
            if str(self_) == probe.path:
                probe.opens.append(("read_text", "r"))
            return rt(self_, *a, **k)

        def s_rb(self_, *a, **k):
            if str(self_) == probe.path:
                probe.opens.append(("read_bytes", "rb"))
            return rb(self_, *a, **k)

        os.open, os.read, builtins.open = s_open, s_read, s_bopen
        Path.read_text, Path.read_bytes = s_rt, s_rb
        return self

    def __exit__(self, *exc):
        import builtins
        os.open, os.read, builtins.open, Path.read_text, Path.read_bytes = self._saved
        return False

    def read_opens(self):
        out = []
        for api, how in self.opens:
            if api == "os.open":
                if how & os.O_ACCMODE == os.O_RDONLY:
                    out.append((api, how))
            elif not set(how) & set("wa+x"):
                out.append((api, how))
        return out


class InstrumentedReadTests(Base):
    """Finding 5: measure the reads, not the text that happens to be displayed."""

    def _hold(self, text):
        lock = self.lock_of(self.out)
        lock.write_text(text, encoding="utf-8")
        return lock

    @unittest.skipIf(IS_WINDOWS, "POSIX contract")
    def test_posix_reads_at_most_200_bytes_with_the_safe_flags(self):
        lock = self._hold("H" * 100000)
        with _Probe(lock) as pr:
            code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertGreater(pr.consumed, 0)
        self.assertLessEqual(pr.requested, 200)
        self.assertLessEqual(pr.consumed, 200)
        reads = pr.read_opens()
        self.assertEqual(len(reads), 1, pr.opens)
        self.assertEqual(reads[0][0], "os.open")
        for name in ("O_NOFOLLOW", "O_NONBLOCK"):
            if hasattr(os, name):
                self.assertTrue(reads[0][1] & getattr(os, name), name)
        self.assertEqual([o for o in pr.opens if o[0] != "os.open"], [])

    @unittest.skipIf(IS_WINDOWS, "needs POSIX symlinks")
    def test_posix_symlink_lock_is_never_opened_for_reading(self):
        secret = self.dir / "secret.txt"
        secret.write_text("TOPSECRET" * 1000, encoding="utf-8")
        os.symlink(secret, self.lock_of(self.out))
        # The read would go through the LOCK pathname (os.open(<out>.claudex-lock)),
        # which the OS resolves to the secret: watching only the target cannot see
        # a call that opens the link. Instrument both names.
        lock = self.lock_of(self.out)
        with _Probe(lock) as pl, _Probe(secret) as ps:
            code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(pl.read_opens(), [], pl.opens)
        self.assertEqual(pl.requested, 0)
        self.assertEqual(pl.consumed, 0)
        self.assertEqual(ps.requested, 0)
        self.assertEqual(ps.opens, [])

    @unittest.skipIf(IS_WINDOWS, "needs POSIX semantics")
    def test_posix_hard_linked_lock_is_never_read(self):
        other = self.dir / "other.txt"
        other.write_text("OTHERDATA" * 1000, encoding="utf-8")
        lock = self.lock_of(self.out)
        os.link(other, lock)
        with _Probe(lock) as pr:
            code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(pr.requested, 0)
        self.assertEqual(pr.read_opens(), [])

    @unittest.skipUnless(IS_WINDOWS, "Windows contract")
    def test_windows_never_opens_the_existing_lock_for_reading(self):
        lock = self._hold("SECRETHOLDER" * 1000)
        with _Probe(lock) as pr:
            code, text = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(pr.read_opens(), [], pr.opens)
        self.assertEqual(pr.requested, 0)
        self.assertEqual(pr.consumed, 0)
        self.assertNotIn("SECRETHOLDER", text)

    def test_big_lock_bounded_reads_everywhere(self):
        lock = self._hold("B" * (10 * 1024 * 1024))
        with _Probe(lock) as pr:
            code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertLessEqual(pr.consumed, 200)
        self.assertLessEqual(pr.requested, 200)


class PartialAcquisitionTests(Base):
    """Finding 6: the first lock really is acquired before the second is found held."""

    def test_first_lock_is_taken_then_released_when_the_second_is_held(self):
        first, second = self.dir / "a-verdict.txt", self.dir / "z-LOG.md"
        self.assertLess(str(self.lock_of(first)), str(self.lock_of(second)))
        held = self.lock_of(second)
        held.write_text("someone pid=1", encoding="utf-8")
        created, removed = [], []
        real_open, real_unlink = os.open, os.unlink

        def s_open(path, flags, *a, **k):
            fd = real_open(path, flags, *a, **k)
            if flags & os.O_EXCL and str(path).endswith(fallback_review.LOCK_SUFFIX):
                created.append(str(path))
            return fd

        def s_unlink(path, *a, **k):
            removed.append(str(path))
            return real_unlink(path, *a, **k)

        os.open, os.unlink = s_open, s_unlink
        try:
            code, _ = self.run_main(out=first, log=second)
        finally:
            os.open, os.unlink = real_open, real_unlink
        self.assertEqual(code, 2)
        self.assertEqual(created, [str(self.lock_of(first))], "first lock never acquired")
        self.assertIn(str(self.lock_of(first)), removed)
        self.assertFalse(self.lock_of(first).exists())
        self.assertTrue(held.exists())
        self.assertFalse(first.exists())


class StagingTests(Base):
    def test_staging_is_unique_and_exclusive(self):
        # A pre-planted fixed-name staging file is neither written through nor removed.
        fixed = self.dir / "verdict.txt.claudex-part"
        fixed.write_text("FOREIGN", encoding="utf-8")
        code, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(fixed.read_text(encoding="utf-8"), "FOREIGN")
        self.assertIn("VERDICT", self.out.read_text(encoding="utf-8"))

    def test_write_atomically_uses_a_unique_part_and_removes_it(self):
        names = []
        real_replace = os.replace

        def spy(src, dst):
            names.append(Path(src).name)
            return real_replace(src, dst)

        os.replace = spy
        try:
            fallback_review.write_atomically(self.out, "x\n")
        finally:
            os.replace = real_replace
        self.assertTrue(names and names[0].endswith(".claudex-part"))
        self.assertNotEqual(names[0], "verdict.txt.claudex-part")
        self.assertEqual(self.parts(), [])

    def test_failed_publication_removes_own_staging(self):
        real_replace = os.replace

        def boom(src, dst):
            raise OSError("nope")

        os.replace = boom
        try:
            with self.assertRaises(OSError):
                fallback_review.write_atomically(self.out, "x\n")
        finally:
            os.replace = real_replace
        self.assertEqual(self.parts(), [])


class InteropTests(Base):
    def test_wrapper_held_lock_blocks_the_fallback(self):
        self.out.write_text("PREVIOUS", encoding="utf-8")
        taken = codex_ro.acquire_locks([self.out])
        try:
            code, _ = self.run_main()
        finally:
            codex_ro.release_locks(taken)
        self.assertEqual(code, 2)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUS")

    def test_fallback_held_lock_blocks_the_wrapper(self):
        seen = {}

        class Spy(_Opener):
            def open(s, *a, **k):
                try:
                    codex_ro.acquire_locks([self.out])
                    seen["blocked"] = False
                except SystemExit as exc:
                    seen["blocked"] = exc.code == 2
                return _Resp(REPLY)

        fallback_review._opener = lambda url: Spy(REPLY)
        with contextlib.redirect_stderr(io.StringIO()):
            self.run_main()
        self.assertEqual(seen, {"blocked": True})


DRIVER = textwrap.dedent('''
    import json, os, sys, time
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    import fallback_review as f
    tag, work = sys.argv[2], Path(sys.argv[3])
    class R:
        def __init__(s, t): s.t = t
        def read(s):
            return json.dumps({"choices": [{"message": {"content": s.t},
                                            "finish_reason": "stop"}]}).encode()
        def __enter__(s): return s
        def __exit__(s, *a): return False
    class O:
        def open(s, *a, **k):
            (work / ("started-" + tag)).write_text("x")
            for _ in range(600):
                if (work / "go").exists():
                    break
                time.sleep(0.05)
            return R("1. TAG-" + tag + "\\n2. b\\n3. c\\nVERDICT: REVISE")
    f.reviewer_names = lambda: ["t"]
    f.profile = lambda n: {"name": "t", "model": "m", "base_url": "http://127.0.0.1:1/v1",
        "api_key": None, "temperature": 0, "max_tokens": 100, "timeout": 5}
    f.preflight = lambda p: (True, "ok")
    f._opener = lambda url: O()
    f.read_confined = lambda p, l: Path(p).read_text(encoding="utf-8")
    f.load_dotenv = lambda path=".env": None
    sys.argv = ["fallback_review.py", "--plan", str(work / "plan.txt"),
                "--append-log", str(work / ("log-" + tag + ".md")),
                "--out", str(work / "verdict.txt"), "--min-findings", "0"]
    sys.exit(f.main())
''')


class ConcurrencyTests(Base):
    def _spawn(self, driver, tag):
        return subprocess.Popen(
            [sys.executable, str(driver), str(SCRIPTS), tag, str(self.dir)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def test_two_runs_on_one_out_exactly_one_publishes_its_own_verdict(self):
        driver = self.dir / "driver.py"
        driver.write_text(DRIVER, encoding="utf-8")
        first = self._spawn(driver, "A")
        for _ in range(200):
            if (self.dir / "started-A").exists():
                break
            time.sleep(0.05)
        self.assertTrue((self.dir / "started-A").exists(), "first run never started")
        second = self._spawn(driver, "B")
        out_b, _ = second.communicate(timeout=60)
        self.assertEqual(second.returncode, 2, out_b)
        self.assertFalse((self.dir / "started-B").exists(), "second run reached the reviewer")
        (self.dir / "go").write_text("x")
        out_a, _ = first.communicate(timeout=60)
        self.assertEqual(first.returncode, 0, out_a)
        self.assertIn("TAG-A", (self.dir / "verdict.txt").read_text(encoding="utf-8"))
        self.assertEqual(self.parts(), [])
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])


class AbsentLogCreatedExclusivelyTests(Base):
    """An absent append log is created O_EXCL: nothing that appears between the
    lstat and the open (a link, another run's file) is ever written through."""

    def _appear_after_lstat(self, make):
        """Make `make()` run right after the append's own lstat found the log absent."""
        state = {"armed": False}

        class Spy(_Opener):
            def open(s, *a, **k):
                state["armed"] = True
                return _Resp(REPLY)

        fallback_review._opener = lambda url: Spy(REPLY)
        real = fallback_review._lstat
        self.addCleanup(lambda: setattr(fallback_review, "_lstat", real))
        log = str(self.log)

        def spy(path):
            st = real(path)
            if state["armed"] and str(path) == log and st is None:
                state["armed"] = False
                make()
            return st

        fallback_review._lstat = spy

    def test_file_appearing_between_lstat_and_open_is_not_appended_to(self):
        self._appear_after_lstat(lambda: self.log.write_text("THEIR LOG", encoding="utf-8"))
        code, text = self.run_main()
        self.assertEqual(code, 2, text)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "THEIR LOG")
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])

    @unittest.skipIf(IS_WINDOWS, "needs POSIX symlinks")
    def test_symlink_appearing_between_lstat_and_open_is_not_followed(self):
        target = self.dir / "target.md"
        target.write_text("TARGET", encoding="utf-8")
        self._appear_after_lstat(lambda: os.symlink(target, self.log))
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "TARGET")

    def test_absent_log_is_opened_with_o_excl(self):
        flags_seen = []
        real = os.open

        def spy(path, flags, *a, **k):
            if str(path) == str(self.log):
                flags_seen.append(flags)
            return real(path, flags, *a, **k)

        os.open = spy
        try:
            code, _ = self.run_main()
        finally:
            os.open = real
        self.assertEqual(code, 0)
        self.assertEqual(len(flags_seen), 1)
        self.assertTrue(flags_seen[0] & os.O_EXCL)
        self.assertTrue(flags_seen[0] & os.O_CREAT)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(flags_seen[0] & os.O_NOFOLLOW)

    def test_existing_log_is_not_opened_with_o_creat(self):
        self.log.write_text("HEAD\n", encoding="utf-8")
        flags_seen = []
        real = os.open

        def spy(path, flags, *a, **k):
            if str(path) == str(self.log):
                flags_seen.append(flags)
            return real(path, flags, *a, **k)

        os.open = spy
        try:
            code, _ = self.run_main()
        finally:
            os.open = real
        self.assertEqual(code, 0)
        self.assertEqual(len(flags_seen), 1)
        self.assertFalse(flags_seen[0] & os.O_CREAT)


class LockHandleClosedOnFdopenFailureTests(Base):
    """If os.fdopen fails before it owns the descriptor, the raw fd is closed
    before the lock is unlinked (an open handle blocks deletion on Windows)."""

    def test_raw_fd_closed_and_both_locks_removed(self):
        real_fdopen, real_close = os.fdopen, os.close
        raised, closed = [], []

        def failing(fd, *a, **k):
            raised.append(fd)  # does NOT close the fd itself
            raise OSError("fdopen failed")

        def spy_close(fd):
            closed.append(fd)
            return real_close(fd)

        os.fdopen, os.close = failing, spy_close
        try:
            code, text = self.run_main()
        finally:
            os.fdopen, os.close = real_fdopen, real_close
            for fd in raised:  # never leak in the test process either
                if fd not in closed:
                    try:
                        real_close(fd)
                    except OSError:
                        pass
        self.assertEqual(code, 2, text)
        self.assertEqual(len(raised), 1)
        self.assertIn(raised[0], closed)
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])
        self.assertFalse(self.out.exists())
        self.assertFalse(self.log.exists())


class StagingDurabilityTests(Base):
    """write_atomically: flush+fsync BEFORE the replace, and a failure on the way
    means nothing is published and the staging file is gone."""

    def test_fsync_happens_before_replace(self):
        calls = []
        real_fsync, real_replace = os.fsync, os.replace

        def fsync(fd):
            calls.append("fsync")
            return real_fsync(fd)

        def replace(src, dst):
            calls.append("replace")
            return real_replace(src, dst)

        os.fsync, os.replace = fsync, replace
        try:
            fallback_review.write_atomically(self.out, "data\n")
        finally:
            os.fsync, os.replace = real_fsync, real_replace
        self.assertEqual(calls, ["fsync", "replace"])
        self.assertEqual(self.out.read_text(encoding="utf-8"), "data\n")

    def test_data_is_flushed_to_the_file_before_fsync(self):
        seen = {}
        real_fsync = os.fsync

        def fsync(fd):
            # At fsync time the staging file must already hold the whole text.
            part = [p for p in self.dir.iterdir() if p.name.endswith(".claudex-part")]
            seen["content"] = part[0].read_bytes() if part else None
            return real_fsync(fd)

        os.fsync = fsync
        try:
            fallback_review.write_atomically(self.out, "data\n")
        finally:
            os.fsync = real_fsync
        self.assertEqual(seen.get("content"), b"data\n")

    def test_fsync_failure_prevents_publication(self):
        self.out.write_text("PREVIOUS", encoding="utf-8")
        real_fsync, real_replace = os.fsync, os.replace
        replaced = []

        def fsync(fd):
            raise OSError("disk full")

        def replace(src, dst):
            replaced.append(dst)
            return real_replace(src, dst)

        os.fsync, os.replace = fsync, replace
        try:
            with self.assertRaises(OSError):
                fallback_review.write_atomically(self.out, "NEW\n")
        finally:
            os.fsync, os.replace = real_fsync, real_replace
        self.assertEqual(replaced, [])
        self.assertEqual(self.out.read_text(encoding="utf-8"), "PREVIOUS")
        self.assertEqual(self.parts(), [])

    def test_fsync_failure_in_a_run_is_a_controlled_exit(self):
        real_fsync = os.fsync

        def fsync(fd):
            raise OSError("disk full")

        os.fsync = fsync
        try:
            code, text = self.run_main()
        finally:
            os.fsync = real_fsync
        self.assertEqual(code, 2, text)
        self.assertIn("ERROR", text)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.parts(), [])
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])


class StagingFdopenFailureTests(Base):
    """If os.fdopen fails on the mkstemp descriptor, the raw fd is closed before
    the staging file is unlinked (an open handle blocks deletion on Windows)."""

    def _failing_fdopen(self):
        """Fail os.fdopen only for the staging descriptor mkstemp handed out; the lock
        handles are built normally, so a run really reaches staging (gate recheck 1)."""
        real_fdopen, real_close = os.fdopen, os.close
        real_mkstemp = tempfile.mkstemp
        raised, closed, order, staged = [], [], [], []
        real_unlink = os.unlink

        def mkstemp(*a, **k):
            fd, name = real_mkstemp(*a, **k)
            staged.append(fd)
            return fd, name

        def failing(fd, *a, **k):
            if fd not in staged:
                return real_fdopen(fd, *a, **k)
            raised.append(fd)  # does NOT close the fd itself
            raise OSError("fdopen failed")

        def spy_close(fd):
            closed.append(fd)
            order.append("close")
            return real_close(fd)

        def spy_unlink(p, *a, **k):
            if str(p).endswith(".claudex-part"):
                order.append("unlink")
            return real_unlink(p, *a, **k)

        def restore():
            os.fdopen, os.close, os.unlink = real_fdopen, real_close, real_unlink
            tempfile.mkstemp = real_mkstemp
            for fd in raised:
                if fd not in closed:
                    try:
                        real_close(fd)
                    except OSError:
                        pass

        os.fdopen, os.close, os.unlink = failing, spy_close, spy_unlink
        tempfile.mkstemp = mkstemp
        return raised, closed, order, restore

    def test_raw_fd_closed_before_unlink(self):
        raised, closed, order, restore = self._failing_fdopen()
        try:
            with self.assertRaises(OSError):
                fallback_review.write_atomically(self.out, "x\n")
        finally:
            restore()
        self.assertEqual(len(raised), 1)
        self.assertIn(raised[0], closed)
        self.assertLess(order.index("close"), order.index("unlink"))
        self.assertEqual(self.parts(), [])
        self.assertFalse(self.out.exists())

    def test_run_exits_in_a_controlled_way_and_leaves_out_alone(self):
        raised, closed, order, restore = self._failing_fdopen()
        try:
            code, text = self.run_main()
        finally:
            restore()
        self.assertEqual(code, 2, text)
        self.assertIn("ERROR", text)
        self.assertEqual(len(raised), 1, "the run must reach staging, not fail at the locks")
        self.assertIn(raised[0], closed)
        self.assertLess(order.index("close"), order.index("unlink"))
        self.assertEqual(self.parts(), [])
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])


def _fake_stat(mode):
    import types
    return types.SimpleNamespace(st_mode=mode, st_nlink=1, st_dev=1, st_ino=1,
                                 st_file_attributes=0)


class NonRegularAppendLogTests(Base):
    """A non-regular append log (FIFO, device) is refused before it is opened."""

    def test_open_append_refuses_non_regular_without_opening(self):
        import stat as _stat
        real_lstat, real_open = fallback_review._lstat, os.open
        opened = []

        def lstat(path):
            if str(path) == str(self.log):
                return _fake_stat(_stat.S_IFIFO | 0o600)
            return real_lstat(path)

        def opener(path, *a, **k):
            opened.append(path)
            return real_open(path, *a, **k)

        fallback_review._lstat, os.open = lstat, opener
        try:
            with self.assertRaises(fallback_review.LogRefused):
                fallback_review._open_append(str(self.log))
        finally:
            fallback_review._lstat, os.open = real_lstat, real_open
        self.assertEqual(opened, [])

    def test_refuse_outputs_names_a_non_regular_log(self):
        import stat as _stat
        real_lstat = fallback_review._lstat

        def lstat(path):
            if str(path) == str(self.log):
                return _fake_stat(_stat.S_IFIFO | 0o600)
            return real_lstat(path)

        fallback_review._lstat = lstat
        try:
            reason = fallback_review._refuse_outputs(str(self.out), str(self.log))
        finally:
            fallback_review._lstat = real_lstat
        self.assertIsNotNone(reason)
        self.assertIn("regular", reason)

    @unittest.skipIf(IS_WINDOWS or not hasattr(os, "mkfifo"), "needs POSIX FIFOs")
    def test_fifo_log_exits_2_without_blocking(self):
        import threading
        os.mkfifo(self.log)
        result = {}

        def go():
            result["r"] = self.run_main()

        t = threading.Thread(target=go, daemon=True)
        t.start()
        t.join(10)
        if t.is_alive():
            # Unblock the stuck open so the process can finish, then fail.
            try:
                fd = os.open(self.log, os.O_RDONLY | os.O_NONBLOCK)
                t.join(5)
                os.close(fd)
            except OSError:
                pass
            self.fail("the run blocked on a FIFO append log")
        code, text = result["r"]
        self.assertEqual(code, 2, text)
        self.assertEqual(list(self.dir.glob("*.claudex-lock")), [])

    @unittest.skipIf(IS_WINDOWS or not hasattr(os, "O_NONBLOCK"), "needs POSIX")
    def test_existing_log_is_opened_with_o_nonblock(self):
        self.log.write_text("HEAD\n", encoding="utf-8")
        flags_seen = []
        real = os.open

        def spy(path, flags, *a, **k):
            if str(path) == str(self.log):
                flags_seen.append(flags)
            return real(path, flags, *a, **k)

        os.open = spy
        try:
            code, _ = self.run_main()
        finally:
            os.open = real
        self.assertEqual(code, 0)
        self.assertEqual(len(flags_seen), 1)
        self.assertTrue(flags_seen[0] & os.O_NONBLOCK)


if __name__ == "__main__":
    unittest.main()
