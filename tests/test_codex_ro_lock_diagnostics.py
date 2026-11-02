#!/usr/bin/env python3
"""Wrapper 2.7.2: the diagnostic read of an existing output lock is bounded and safe.

Before 2.7.2 acquire_locks() read the holder with Path.read_text(): it followed a
symlink (disclosing another file), read a huge file whole, and blocked on a FIFO.
Contract (plan docs/plans/2026-11-02-t24-t26, step 12): POSIX opens only a regular
file with st_nlink == 1 (O_NOFOLLOW|O_NONBLOCK, same dev/ino after fstat) and reads
at most 200 bytes; Windows never reads the lock; anything else is "(holder not shown)".

Three kinds of test live here:

* Regressions: written before the code and seen red against 2.7.1 (symlink, FIFO,
  huge file, hard link, Windows never reads / never opens the lock).
* Positive control: test_regular_lock_shows_holder. It passes on 2.7.1 AND 2.7.2; it
  only guards that the hardening did not remove the useful diagnostic.
* Meter controls (test_meter_*): feed a deliberately wrong reader to the same
  measurement the regressions use and require that the measurement flags it. They
  prove the regressions can fail (a reader consuming 10 MB in 200-byte chunks; on
  Windows a reader that os.open()s the lock and closes it again).

    python -m unittest tests.test_codex_ro_lock_diagnostics -v
"""

from __future__ import annotations

import builtins
import contextlib
import io
import os
import sys
import tempfile
import threading
import unittest
import unittest.mock
from contextlib import redirect_stderr
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import codex_ro  # noqa: E402

POSIX = os.name != "nt"
HOLDER = "pid 4242 since 2026-11-02T10:00:00\n"
SECRET = "TOP-SECRET-CONTENT-DO-NOT-LEAK"
HOLDER_MAX = 200


def _chunked_reader(path):
    """Wrong on purpose: consumes the whole file in 200-byte chunks (POSIX)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        first = os.read(fd, HOLDER_MAX)
        while os.read(fd, HOLDER_MAX):
            pass
        return first.decode("utf-8", errors="replace")
    finally:
        os.close(fd)


def _posix_open_reader(path):
    """Wrong on purpose: opens the lock through its pathname (following links), reads it,
    and still answers the safe text -- only a meter on the open can catch it (POSIX)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.read(fd, HOLDER_MAX)
    finally:
        os.close(fd)
    return "(holder not shown)"


def _buffered_reader(path):
    """Wrong on purpose: reads the lock through builtins.open (following links) and
    still answers the safe text (POSIX)."""
    with open(path, "rb") as handle:
        handle.read(HOLDER_MAX)
    return "(holder not shown)"


def _os_open_reader(path):
    """Wrong on purpose: opens the existing lock read-only, then closes it (Windows)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    os.close(fd)
    return "(holder not read on Windows)"


class LockDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        # "a" sorts before "b": a's lock is taken first, then released when b's exists.
        self.first = self.dir / "a.txt"
        self.second = self.dir / "b.txt"
        self.lock = Path(str(self.second) + codex_ro.LOCK_SUFFIX)
        self.first_lock = Path(str(self.first) + codex_ro.LOCK_SUFFIX)

    def refuse(self):
        """Run acquire_locks against the prepared lock; return (exit code, stderr)."""
        err = io.StringIO()
        with redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                codex_ro.acquire_locks([self.first, self.second])
        self.assertFalse(self.first_lock.exists(), "the lock taken first must be released")
        return ctx.exception.code, err.getvalue()

    # -- measurements shared by the regressions and the meter controls ---------

    def measure_huge_lock(self, reader=None):
        """Write a 10 MB lock, refuse, return (code, stderr, requested, consumed).

        requested/consumed are the AGGREGATE bytes asked for and returned by every
        os.read on the lock's own file (matched by st_ino), not the largest single call.
        """
        with open(self.lock, "wb") as handle:
            handle.write(b"A" * (10 * 1024 * 1024))
        lock_ino = os.stat(self.lock).st_ino
        totals = {"requested": 0, "consumed": 0, "calls": 0}
        real_read = os.read

        def spy(fd, n):
            data = real_read(fd, n)
            if os.fstat(fd).st_ino == lock_ino:
                totals["requested"] += n
                totals["consumed"] += len(data)
                totals["calls"] += 1
            return data

        stack = [unittest.mock.patch.object(codex_ro.os, "read", spy)]
        if reader is not None:
            stack.append(unittest.mock.patch.object(codex_ro, "_read_lock_holder", reader))
        with stack[0]:
            if reader is not None:
                with stack[1]:
                    code, err = self.refuse()
            else:
                code, err = self.refuse()
        return code, err, totals

    def measure_lock_opens(self, reader=None, prepare=True):
        """Refuse against an existing lock; return the read-mode opens of it.

        Metered: os.open, builtins.open and io.open (also used by Path.open).
        The wrapper's own O_CREAT|O_EXCL creation attempts are allowed (they fail with
        FileExistsError and never read); any other open of the lock path is a violation.
        prepare=False keeps a lock the test placed itself (a symlink, a hard link).
        """
        if prepare:
            self.lock.write_text(HOLDER, encoding="utf-8")
        target = os.path.normcase(os.path.abspath(self.lock))
        real_open = os.open
        violations = []

        def spy(path, flags, *args, **kwargs):
            try:
                same = os.path.normcase(os.path.abspath(os.fspath(path))) == target
            except TypeError:
                same = False
            if same and not (flags & os.O_CREAT and flags & os.O_EXCL):
                violations.append(flags)
            return real_open(path, flags, *args, **kwargs)

        def buffered_spy(name, real):
            # each spy delegates to the function it replaced (os.fdopen goes through io.open)
            def opener(file, *args, **kwargs):
                try:
                    same = os.path.normcase(os.path.abspath(os.fspath(file))) == target
                except TypeError:
                    same = False
                if same:
                    violations.append((name,) + args[:1])
                return real(file, *args, **kwargs)
            return opener

        patches = [unittest.mock.patch.object(os, "open", spy),
                   unittest.mock.patch.object(builtins, "open", buffered_spy("builtins.open", builtins.open)),
                   unittest.mock.patch.object(io, "open", buffered_spy("io.open", io.open))]
        if reader is not None:
            patches.append(unittest.mock.patch.object(codex_ro, "_read_lock_holder", reader))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            code, err = self.refuse()
        return code, err, violations

    # -- POSIX ---------------------------------------------------------------

    @unittest.skipUnless(POSIX, "POSIX lock semantics")
    def test_regular_lock_shows_holder(self):
        # positive control: also green on 2.7.1
        self.lock.write_text(HOLDER, encoding="utf-8")
        code, err = self.refuse()
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertIn("pid 4242", err)
        self.assertIn(str(self.lock), err)

    @unittest.skipUnless(POSIX, "symlinks")
    def test_symlink_lock_does_not_disclose_target(self):
        secret = self.dir / "secret.txt"
        secret.write_text(SECRET, encoding="utf-8")
        os.symlink(secret, self.lock)
        code, err, violations = self.measure_lock_opens(prepare=False)
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertNotIn(SECRET, err)
        self.assertIn("(holder not shown)", err)
        # the message alone cannot tell a reader that followed the link (gate W3)
        self.assertEqual(violations, [], "a symlinked lock must never be opened")

    @unittest.skipUnless(POSIX, "symlinks")
    def test_meter_flags_posix_open_reader(self):
        # a reader that opens the symlinked lock and still prints the safe text is caught
        secret = self.dir / "secret.txt"
        secret.write_text(SECRET, encoding="utf-8")
        os.symlink(secret, self.lock)
        _code, err, violations = self.measure_lock_opens(reader=_posix_open_reader, prepare=False)
        self.assertIn("(holder not shown)", err)
        self.assertTrue(violations)

    @unittest.skipUnless(POSIX, "symlinks")
    def test_meter_flags_buffered_reader(self):
        # a reader that follows the link through builtins.open is caught as well
        secret = self.dir / "secret.txt"
        secret.write_text(SECRET, encoding="utf-8")
        os.symlink(secret, self.lock)
        _code, err, violations = self.measure_lock_opens(reader=_buffered_reader, prepare=False)
        self.assertIn("(holder not shown)", err)
        self.assertTrue(violations)

    @unittest.skipUnless(POSIX, "POSIX lock semantics")
    def test_lock_replaced_between_lstat_and_open_is_not_read(self):
        # lstat sees one regular file, the open finds another (identity mismatch): no read
        self.lock.write_text("SECRETHOLDER " + HOLDER, encoding="utf-8")
        decoy = self.dir / "decoy.txt"
        decoy.write_text(HOLDER, encoding="utf-8")
        decoy_st = os.lstat(decoy)
        target = os.path.abspath(self.lock)
        real_lstat, real_read = os.lstat, os.read
        reads = []

        def lstat_spy(path, *args, **kwargs):
            if os.path.abspath(os.fspath(path)) == target:
                return decoy_st
            return real_lstat(path, *args, **kwargs)

        def read_spy(fd, n):
            reads.append(n)
            return real_read(fd, n)

        with unittest.mock.patch.object(os, "lstat", lstat_spy), \
                unittest.mock.patch.object(os, "read", read_spy):
            code, err = self.refuse()
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertNotIn("SECRETHOLDER", err)
        self.assertNotIn("pid 4242", err)
        self.assertIn("(holder not shown)", err)
        self.assertEqual(reads, [], "a lock whose identity changed must not be read")

    @unittest.skipUnless(POSIX and hasattr(os, "mkfifo"), "FIFO")
    def test_fifo_lock_does_not_block(self):
        os.mkfifo(self.lock)
        result = {}

        def run():
            result["out"] = self.refuse()

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(10)
        if worker.is_alive():
            # unblock the reader so the daemon thread ends, then fail
            fd = os.open(self.lock, os.O_WRONLY | os.O_NONBLOCK)
            os.close(fd)
            self.fail("acquire_locks blocked on a FIFO lock")
        code, err = result["out"]
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertIn("(holder not shown)", err)

    @unittest.skipUnless(POSIX, "POSIX lock semantics")
    def test_huge_lock_is_read_bounded(self):
        code, err, totals = self.measure_huge_lock()
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertGreater(totals["calls"], 0, "the holder must be read through os.read")
        # aggregate over ALL reads of the lock, not the largest single request
        self.assertLessEqual(totals["requested"], HOLDER_MAX)
        self.assertLessEqual(totals["consumed"], HOLDER_MAX)
        self.assertLess(len(err), 1500)
        self.assertLessEqual(err.count("A"), HOLDER_MAX)

    @unittest.skipUnless(POSIX, "POSIX lock semantics")
    def test_meter_flags_chunked_reader(self):
        # a reader that eats 10 MB in 200-byte chunks must trip the aggregate meter
        _code, _err, totals = self.measure_huge_lock(reader=_chunked_reader)
        self.assertGreater(totals["calls"], 1)
        self.assertGreater(totals["requested"], HOLDER_MAX)
        self.assertGreater(totals["consumed"], HOLDER_MAX)

    @unittest.skipUnless(POSIX, "hard links")
    def test_hardlinked_lock_holder_not_shown(self):
        other = self.dir / "alias.txt"
        other.write_text(SECRET, encoding="utf-8")
        os.link(other, self.lock)
        code, err, violations = self.measure_lock_opens(prepare=False)
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertNotIn(SECRET, err)
        self.assertIn("(holder not shown)", err)
        self.assertEqual(violations, [], "a hard-linked lock must never be opened")

    # -- Windows -------------------------------------------------------------

    @unittest.skipUnless(not POSIX, "Windows: the lock is never read")
    def test_windows_never_reads_the_lock(self):
        self.lock.write_text("SECRETHOLDER " + HOLDER, encoding="utf-8")
        code, err = self.refuse()
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertNotIn("SECRETHOLDER", err)
        self.assertNotIn("pid 4242", err)
        self.assertIn(str(self.lock), err)

    @unittest.skipUnless(not POSIX, "Windows: the lock is never read")
    def test_windows_does_not_open_the_lock(self):
        # Path.read_text and builtins.open are blocked too; os.open is metered.
        self.lock.write_text(HOLDER, encoding="utf-8")
        with unittest.mock.patch.object(Path, "read_text", side_effect=AssertionError("read")), \
                unittest.mock.patch("builtins.open", side_effect=AssertionError("open")):
            code, _err, violations = self.measure_lock_opens()
        self.assertEqual(code, codex_ro.EXIT_REFUSED)
        self.assertEqual(violations, [], "the existing lock must never be opened via os.open")

    @unittest.skipUnless(not POSIX, "Windows: the lock is never read")
    def test_meter_flags_os_open_reader(self):
        # a reader that os.open()s the lock and closes it must be caught by the meter
        _code, _err, violations = self.measure_lock_opens(reader=_os_open_reader)
        self.assertTrue(violations)


if __name__ == "__main__":
    unittest.main()
