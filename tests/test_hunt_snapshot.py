"""hunt_snapshot: the frozen, redacted input of the security hunt (plan A, stage 1, item 4).

- only regular files are taken; links, junctions, FIFOs, oversized and binary files are
  recorded as refused, nothing is followed (R3-6);
- check and open cannot be raced: the opened handle must be the object lstat saw (R4-3);
- reading never blocks the run: the worker is supervised with a hard deadline, its WHOLE
  process tree is terminated, and the termination itself is bounded (R5-2, R6-2, round 7);
- the snapshot is redacted, and its manifest hashes the REDACTED bytes, while a private
  original manifest hashes the original bytes (R4-5);
- later changes to the repository do not change the snapshot (R3-3).

Written before scripts/hunt_snapshot.py and seen failing first.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hunt_snapshot as hs  # noqa: E402
import redact_payload  # noqa: E402

WINDOWS = os.name == "nt"
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def fake_gitleaks(directory, work_dir=None):
    """Deterministic stand-in: these tests must not depend on an installed gitleaks
    (inspection round 1, finding 21). Real-scanner behaviour: tests/test_redact_payload.py."""
    import re
    out = []
    for p in Path(directory).rglob("*"):
        if p.is_file():
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                for m in re.finditer(r"ghp_[A-Za-z0-9]{36}", line):
                    out.append({"File": str(p), "Secret": m.group(0), "RuleID": "github-pat",
                                "StartLine": n})
    return out


@pytest.fixture(autouse=True)
def _no_real_scanner(monkeypatch):
    monkeypatch.setattr(redact_payload, "gitleaks_scan", fake_gitleaks)


def _build(repo: Path, tmp_path: Path, **kw):
    private = tmp_path / "private"
    private.mkdir(exist_ok=True)
    return hs.build_snapshot(repo, tmp_path / "run", private_dir=private, **kw)


def test_private_dir_is_required_and_must_lie_outside_the_run(repo, tmp_path):
    """Round 2, finding 16: the old default put original hashes into the run directory."""
    with pytest.raises(TypeError):
        hs.build_snapshot(repo, tmp_path / "run")  # keyword-only, no default
    with pytest.raises(hs.SnapshotError, match="required"):
        hs.build_snapshot(repo, tmp_path / "run", private_dir=None)
    with pytest.raises(hs.SnapshotError, match="outside"):
        hs.build_snapshot(repo, tmp_path / "run", private_dir=tmp_path / "run" / "p")


def _git(repo: Path, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "app.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    (r / "sub").mkdir()
    (r / "sub" / "db.py").write_text(f'TOKEN = "{TOKEN}"\nq = 1\n', encoding="utf-8")
    (r / "big.txt").write_bytes(b"a" * (hs.MAX_FILE_BYTES + 10))
    (r / "bin.dat").write_bytes(b"\x00\x01\x02binary")
    (r / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (r / "ignored.txt").write_text("nope\n", encoding="utf-8")
    _git(r, "add", "app.py", "sub/db.py", ".gitignore")
    (r / "untracked.py").write_text("u = 1\n", encoding="utf-8")
    return r


def test_snapshot_takes_regular_text_files_and_refuses_the_rest(repo, tmp_path):
    snap = _build(repo, tmp_path)
    m = snap.manifest
    assert {"app.py", "sub/db.py", ".gitignore", "untracked.py"} <= set(m["files"])
    assert m["refused"]["big.txt"] == "size"
    assert m["refused"]["bin.dat"] == "binary"
    assert "ignored.txt" not in m["files"] and "ignored.txt" not in m["refused"]


def test_the_snapshot_is_redacted_and_both_manifests_differ_where_it_was(repo, tmp_path):
    snap = _build(repo, tmp_path)
    db = (snap.input_dir / "sub" / "db.py").read_text(encoding="utf-8")
    assert TOKEN not in db
    assert snap.redacted_lines["sub/db.py"] == [1]
    original = hashlib.sha256((repo / "sub" / "db.py").read_bytes()).hexdigest()
    assert snap.original_manifest["files"]["sub/db.py"] == original
    assert snap.manifest["files"]["sub/db.py"] != original
    # finding 14: manifest_id is the hash of the bytes actually written
    assert snap.manifest_id == hashlib.sha256((snap.run_dir / "MANIFEST.json").read_bytes()).hexdigest()


def test_original_hashes_stay_out_of_the_run_directory(repo, tmp_path):
    """Finding 16: the run directory can sit inside the repository (.claudex-tmp)."""
    private = tmp_path / "private"
    private.mkdir()
    snap = hs.build_snapshot(repo, tmp_path / "run", private_dir=private)
    original = snap.original_manifest["files"]["sub/db.py"]
    for p in snap.run_dir.rglob("*"):
        if p.is_file():
            assert original not in p.read_bytes().decode("utf-8", "replace"), p
    assert any(original in p.read_text(encoding="utf-8") for p in private.iterdir())


def test_later_repo_changes_do_not_reach_the_snapshot(repo, tmp_path):
    snap = _build(repo, tmp_path)
    (repo / "app.py").write_text("CHANGED\n", encoding="utf-8")
    assert "return x" in (snap.input_dir / "app.py").read_text(encoding="utf-8")
    snap.verify()  # the snapshot itself still matches its manifest


def test_tampering_with_the_snapshot_is_detected(repo, tmp_path):
    snap = _build(repo, tmp_path)
    (snap.input_dir / "app.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(hs.SnapshotError):
        snap.verify()


def test_swap_between_lstat_and_open_is_refused(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("one\n", encoding="utf-8")

    def swap():
        os.replace(f, tmp_path / "a.old")
        (tmp_path / "a.txt").write_text("two\n", encoding="utf-8")
    assert hs.read_regular(f, _after_lstat=swap) == ("refused", "changed")


@pytest.mark.skipif(WINDOWS, reason="symlink/FIFO swap is a POSIX case")
def test_swap_to_a_fifo_is_refused_without_blocking(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("one\n", encoding="utf-8")

    def swap():
        f.unlink()
        os.mkfifo(f)
    t0 = time.monotonic()
    assert hs.read_regular(f, _after_lstat=swap)[0] == "refused"
    assert time.monotonic() - t0 < 5


@pytest.mark.skipif(WINDOWS, reason="symlinks need privileges on Windows")
def test_a_symlink_is_refused_and_not_followed(tmp_path):
    (tmp_path / "secret.txt").write_text("s\n", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(tmp_path / "secret.txt")
    assert hs.read_regular(tmp_path / "link.txt") == ("refused", "link")


def test_supervisor_kills_a_hanging_worker_and_its_grandchild(tmp_path):
    marker = tmp_path / "grandchild.pid"
    code = (
        "import subprocess,sys,time,pathlib;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(300)']);"
        f"pathlib.Path(r'{marker}').write_text(str(p.pid));"
        "time.sleep(300)"
    )
    t0 = time.monotonic()
    res = hs.run_supervised([sys.executable, "-c", code], deadline=3, kill_deadline=10)
    assert res.timed_out
    assert time.monotonic() - t0 < 20
    gpid = int(marker.read_text())
    time.sleep(1)
    assert not hs.pid_alive(gpid), "the grandchild survived the supervisor"
    assert res.survivors == []


def test_a_grandchild_that_survives_a_failed_tree_kill_is_reported(tmp_path, monkeypatch):
    """Finding 12: when only the worker died, its surviving grandchild used to vanish
    from the report (survivors == [])."""
    marker = tmp_path / "grandchild.pid"
    code = (
        "import subprocess,sys,time,pathlib;"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
        f"pathlib.Path(r'{marker}').write_text(str(p.pid));"
        "time.sleep(120)"
    )
    monkeypatch.setattr(hs, "kill_tree", lambda proc: proc.kill())  # a broken tree kill
    res = hs.run_supervised([sys.executable, "-c", code], deadline=3, kill_deadline=5)
    gpid = int(marker.read_text())
    try:
        assert res.timed_out
        assert res.survivors, "the surviving grandchild must be reported"
        assert gpid in res.survivors or any(s < 0 for s in res.survivors)
    finally:
        if hs.pid_alive(gpid):  # clean up the test's own grandchild
            if WINDOWS:
                subprocess.run(["taskkill", "/F", "/PID", str(gpid)], capture_output=True)
            else:
                os.kill(gpid, 9)


def test_a_hanging_termination_is_itself_bounded(tmp_path, monkeypatch):
    procs = []

    def stuck_kill(proc):
        procs.append(proc)
        time.sleep(60)
    monkeypatch.setattr(hs, "kill_tree", stuck_kill)
    t0 = time.monotonic()
    res = hs.run_supervised([sys.executable, "-c", "import time;time.sleep(60)"],
                            deadline=1, kill_deadline=2)
    try:
        assert res.timed_out
        assert time.monotonic() - t0 < 15
        assert res.survivors, "a termination that could not finish is reported, not hidden"
    finally:  # closing gate A2-4: the test used to leave its worker running
        for p in procs:
            p.kill()
            p.wait(timeout=10)


@pytest.mark.skipif(not WINDOWS, reason="Windows process APIs")
def test_failed_windows_process_queries_are_unknown_not_gone(monkeypatch):
    """Closing gate A2-3: a failed OpenProcess meant "dead", an empty enumeration meant
    "no descendants" -- both reported a clean-up nobody had verified."""
    import types

    def fn(result):
        def f(*a):
            return result
        return f  # plain functions take the argtypes/restype the code assigns
    k = types.SimpleNamespace(OpenProcess=fn(None), CloseHandle=fn(True),
                              CreateToolhelp32Snapshot=fn(1234),
                              Process32FirstW=fn(False), Process32NextW=fn(False))
    monkeypatch.setattr(hs, "_k32", lambda: k)
    monkeypatch.setattr(hs.ctypes, "get_last_error", lambda: 5)  # access denied
    assert hs.pid_alive(4242) is True
    monkeypatch.setattr(hs.ctypes, "get_last_error", lambda: hs.ERROR_INVALID_PARAMETER)
    assert hs.pid_alive(4242) is False
    assert hs.descendants(4242) is None


def test_an_unlistable_process_tree_is_reported_as_unverified(monkeypatch):
    """Round 2, finding 12: a failed process listing used to read as "no descendants",
    so an empty survivor list looked like a verified clean-up."""
    monkeypatch.setattr(hs, "descendants", lambda pid: None)
    res = hs.run_supervised([sys.executable, "-c", "import time;time.sleep(60)"],
                            deadline=1, kill_deadline=5)
    assert res.timed_out
    if WINDOWS:
        assert res.cleanup_unverified
    # POSIX lists nothing anyway (the group is the unit); the flag follows the listing
    assert res.cleanup_unverified == (hs.descendants(0) is None)


def test_the_read_cap_bounds_a_growing_file(tmp_path, monkeypatch):
    """Round 2, finding 13: a file that grows after lstat is read at most limit + 1 bytes."""
    import hunt_io
    f = tmp_path / "grow.txt"
    f.write_bytes(b"a" * 10)
    seen = []
    real_read = os.read

    def counting_read(fd, n):
        data = real_read(fd, n)
        seen.append(len(data))
        return data

    def grow():
        with open(f, "ab") as fh:
            fh.write(b"b" * 5000)
    monkeypatch.setattr(hunt_io.os, "read", counting_read)
    status, _ = hunt_io.read_regular(f, limit=100, _after_lstat=grow)
    assert status == "refused"
    assert sum(seen) <= 101


def test_snapshot_verify_refuses_an_extra_link_or_special_entry(repo, tmp_path):
    """Closing gate A2-2: rglob + is_file() silently skipped extra FIFOs, and the hash
    read followed a swapped-in link."""
    snap = _build(repo, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    if WINDOWS:
        import _winapi
        _winapi.CreateJunction(str(outside), str(snap.input_dir / "j"))
    else:
        os.mkfifo(snap.input_dir / "pipe")
    t0 = time.monotonic()
    with pytest.raises(hs.SnapshotError):
        snap.verify()
    assert time.monotonic() - t0 < 5


@pytest.mark.skipif(not WINDOWS, reason="Windows process APIs")
def test_an_enumeration_that_stops_on_an_error_is_unknown(monkeypatch):
    """Gate recheck A2-1: every false Process32NextW counted as the end of the list."""
    import types
    k = types.SimpleNamespace(CloseHandle=lambda h: True,
                              CreateToolhelp32Snapshot=lambda *a: 1234,
                              Process32FirstW=lambda *a: True,
                              Process32NextW=lambda *a: False)
    monkeypatch.setattr(hs, "_k32", lambda: k)
    monkeypatch.setattr(hs.ctypes, "get_last_error", lambda: 5)  # access denied
    assert hs.descendants(4242) is None
    monkeypatch.setattr(hs.ctypes, "get_last_error", lambda: hs.ERROR_NO_MORE_FILES)
    assert hs.descendants(4242) == []
