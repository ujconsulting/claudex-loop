"""sandbox_snapshot: the host-side snapshot of exactly one git tree (plan B1, step 1 and 7b).

Every case builds its own throwaway repository with plain git. Written before
scripts/sandbox_snapshot.py and seen failing first.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sandbox_snapshot as ss  # noqa: E402

# The snapshot refuses a git older than 2.44 (no --no-lazy-fetch) by design; on such a host these
# tests cannot run and are skipped with the reason -- the refusal itself is tested in
# tests/test_sandbox_run.py (GitVersionTests). Measured: WSL Ubuntu 24.04 has git 2.43.
_GIT = ss.git_version()
pytestmark = pytest.mark.skipif(_GIT is None or _GIT < ss.MIN_GIT,
                                reason=f"git {_GIT} older than {ss.MIN_GIT} (no --no-lazy-fetch)")

WINDOWS = os.name == "nt"

_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def git(repo, *args, data=None, env=None):
    res = subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True,
                         env=env or _ENV, timeout=60)
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    return res.stdout.decode().strip()


def make_repo(root: Path, files: dict, exe=()) -> Path:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    for rel, data in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    git(repo, "add", *files)
    for rel in exe:
        oid = git(repo, "rev-parse", f":{rel}")
        git(repo, "update-index", "--cacheinfo", f"100755,{oid},{rel}")
    git(repo, "commit", "-q", "-m", "x")
    return repo


FILES = {"a.txt": b"alpha\n", "sub/b.txt": b"beta\n", "run.sh": b"#!/bin/sh\necho hi\n"}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path, FILES, exe=("run.sh",))


def tree_of(repo):
    return git(repo, "rev-parse", "HEAD^{tree}")


def loose_count(repo):
    return sum(len(f) for _, _, f in os.walk(repo / ".git" / "objects"))


# --- hardening ------------------------------------------------------------------------

def test_hardened_prefix_and_env():
    argv = ss.HARDENED_GIT
    assert argv[0] == "git"
    for flag in ("--no-lazy-fetch", "--no-replace-objects", "--no-optional-locks"):
        assert flag in argv
    assert "core.fsmonitor=false" in argv
    assert any(a.startswith("core.hooksPath=") for a in argv)
    env = ss.git_env({"PATH": "x", "GIT_DIR": "evil", "GIT_INDEX_FILE": "evil"})
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_NO_LAZY_FETCH"] == "1"
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert "GIT_DIR" not in env and "GIT_INDEX_FILE" not in env


def test_object_format(repo):
    assert ss.object_format(repo) == "sha1"


# --- the snapshot ---------------------------------------------------------------------

def test_exact_bytes_modes_and_input_hash(repo):
    snap = ss.build_snapshot(repo, tree_of(repo))
    assert snap.tree == tree_of(repo)
    assert snap.files == 3
    assert snap.total_bytes == sum(len(v) for v in FILES.values())
    expected_entries = sorted(
        (rel, 0o755 if rel == "run.sh" else 0o644, hashlib.sha256(d).hexdigest())
        for rel, d in FILES.items())
    assert snap.entries == expected_entries
    canon = json.dumps([list(e) for e in expected_entries], sort_keys=True,
                       separators=(",", ":"), ensure_ascii=True).encode()
    assert snap.input_sha256 == hashlib.sha256(canon).hexdigest()

    with tarfile.open(fileobj=io.BytesIO(snap.tar_bytes)) as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        assert names == ["a.txt", "run.sh", "sub", "sub/b.txt"]
        for m in members:
            assert (m.mtime, m.uid, m.gid, m.uname, m.gname) == (0, 65532, 65532, "", "")
        by = {m.name: m for m in members}
        assert by["sub"].isdir() and by["sub"].mode == 0o755
        assert by["run.sh"].mode == 0o755 and by["a.txt"].mode == 0o644
        assert tf.extractfile("sub/b.txt").read() == b"beta\n"
        assert tf.extractfile("run.sh").read() == FILES["run.sh"]


def test_tar_is_deterministic(repo):
    t = tree_of(repo)
    assert ss.build_snapshot(repo, t).tar_bytes == ss.build_snapshot(repo, t).tar_bytes


def test_symlink_entry_refused(tmp_path):
    repo = make_repo(tmp_path, {"a.txt": b"x"})
    oid = git(repo, "hash-object", "-w", "--stdin", data=b"a.txt")
    git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},link")
    with pytest.raises(ss.SnapshotRefused, match="120000"):
        ss.build_snapshot(repo, git(repo, "write-tree"))


def test_submodule_entry_refused(tmp_path):
    repo = make_repo(tmp_path, {"a.txt": b"x"})
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},mod")
    with pytest.raises(ss.SnapshotRefused, match="160000"):
        ss.build_snapshot(repo, git(repo, "write-tree"))


def test_limits_refused(repo):
    t = tree_of(repo)
    with pytest.raises(ss.SnapshotRefused, match="entries"):
        ss.build_snapshot(repo, t, max_entries=2)
    with pytest.raises(ss.SnapshotRefused, match="bytes"):
        ss.build_snapshot(repo, t, max_bytes=10)


@pytest.mark.parametrize("bad", ["HEAD", "abc123", "A" * 40, "g" * 40, "1" * 41, "1" * 64, ""])
def test_bad_tree_id_refused(repo, bad):
    with pytest.raises(ss.SnapshotRefused):
        ss.build_snapshot(repo, bad)


def test_missing_object_refused(repo):
    with pytest.raises(ss.SnapshotRefused, match="missing"):
        ss.build_snapshot(repo, "1" * 40)


def test_blob_id_as_tree_refused(repo):
    blob = git(repo, "rev-parse", "HEAD:a.txt")
    with pytest.raises(ss.SnapshotRefused, match="type"):
        ss.build_snapshot(repo, blob)


def test_not_a_repository_refused(tmp_path):
    with pytest.raises(ss.SnapshotRefused):
        ss.build_snapshot(tmp_path, "1" * 40)


def test_object_under_mismatching_id_refused(repo):
    oid = git(repo, "rev-parse", "HEAD:a.txt")
    path = repo / ".git" / "objects" / oid[:2] / oid[2:]
    other = b"blob 5\0other"
    os.chmod(path, 0o600)
    path.write_bytes(zlib.compress(other))
    # the premise: git itself serves the wrong content without complaint
    assert git(repo, "cat-file", "-p", oid) == "other"
    with pytest.raises(ss.SnapshotRefused, match="mismatch"):
        ss.build_snapshot(repo, tree_of(repo))


def test_replace_ref_does_not_change_bytes(repo):
    t = tree_of(repo)
    before = ss.build_snapshot(repo, t)
    old = git(repo, "rev-parse", "HEAD:a.txt")
    new = git(repo, "hash-object", "-w", "--stdin", data=b"EVIL\n")
    git(repo, "replace", old, new)
    assert git(repo, "cat-file", "-p", old) == "EVIL"  # the premise: plain git is fooled
    after = ss.build_snapshot(repo, t)
    assert after.tar_bytes == before.tar_bytes
    assert after.input_sha256 == before.input_sha256


def test_working_tree_edits_do_not_matter(repo):
    t = tree_of(repo)
    before = ss.build_snapshot(repo, t)
    (repo / "a.txt").write_bytes(b"changed")
    (repo / "untracked.txt").write_bytes(b"u")
    assert ss.build_snapshot(repo, t).tar_bytes == before.tar_bytes


# --- pin_paths ------------------------------------------------------------------------

def test_pin_paths_includes_batch_file_with_blob_id(repo, tmp_path):
    (repo / "new.txt").write_bytes(b"batch\n")
    idx = tmp_path / "idx"
    idx.mkdir()
    tree = ss.pin_paths(repo, ["new.txt"], idx)
    assert git(repo, "ls-tree", tree, "new.txt").split()[2] == \
        git(repo, "hash-object", "new.txt")
    assert git(repo, "ls-tree", tree, "a.txt").split()[2] == git(repo, "rev-parse", "HEAD:a.txt")
    assert list(idx.iterdir()) == []  # the private index is gone
    snap = ss.build_snapshot(repo, tree)
    assert "new.txt" in [e[0] for e in snap.entries]


def test_pin_paths_overrides_tracked_file_from_working_tree(repo, tmp_path):
    (repo / "a.txt").write_bytes(b"edited\n")
    idx = tmp_path / "idx"
    idx.mkdir()
    tree = ss.pin_paths(repo, ["a.txt"], idx)
    assert git(repo, "cat-file", "-p", f"{tree}:a.txt") == "edited"


def test_pin_paths_ignores_and_keeps_the_shared_index(repo, tmp_path):
    (repo / "a.txt").write_bytes(b"other session\n")
    git(repo, "add", "a.txt")
    index = repo / ".git" / "index"
    before = hashlib.sha256(index.read_bytes()).hexdigest()
    (repo / "new.txt").write_bytes(b"batch\n")
    idx = tmp_path / "idx"
    idx.mkdir()
    tree = ss.pin_paths(repo, ["new.txt"], idx)
    assert git(repo, "cat-file", "-p", f"{tree}:a.txt") == "alpha"
    assert hashlib.sha256(index.read_bytes()).hexdigest() == before


def test_pin_paths_runs_no_clean_filter(repo, tmp_path):
    sentinel = tmp_path / "sentinel.txt"
    script = tmp_path / "clean.py"
    script.write_text("import sys\nopen(sys.argv[1], 'w').close()\n"
                      "sys.stdout.buffer.write(sys.stdin.buffer.read())\n")
    py = Path(sys.executable).as_posix()
    git(repo, "config", "filter.x.clean", f'"{py}" "{script.as_posix()}" "{sentinel.as_posix()}"')
    (repo / ".gitattributes").write_text("*.txt filter=x\n")
    (repo / "f.txt").write_bytes(b"data\n")
    idx = tmp_path / "idx"
    idx.mkdir()
    ss.pin_paths(repo, ["f.txt", ".gitattributes"], idx)
    assert not sentinel.exists()
    git(repo, "add", "f.txt")  # positive control: plain `git add` does run the filter
    assert sentinel.exists()


@pytest.mark.parametrize("bad", ["../x", "C:\\x", "/abs", "a//b", "a\\..\\b", "", ".", "a/./b",
                                 "a:b", "x/", ".git/config", "a\x00b"])
def test_bad_paths_refused_before_any_object_is_written(repo, tmp_path, bad):
    (repo / "new.txt").write_bytes(b"batch\n")
    idx = tmp_path / "idx"
    idx.mkdir()
    before = loose_count(repo)
    with pytest.raises(ss.SnapshotRefused):
        ss.pin_paths(repo, ["new.txt", bad], idx)
    assert loose_count(repo) == before
    assert list(idx.iterdir()) == []


def test_pin_paths_refuses_missing_and_directory(repo, tmp_path):
    idx = tmp_path / "idx"
    idx.mkdir()
    for rel in ("nope.txt", "sub"):
        with pytest.raises(ss.SnapshotRefused):
            ss.pin_paths(repo, [rel], idx)


@pytest.mark.skipif(not WINDOWS, reason="junctions are a Windows thing")
def test_pin_through_junction_refused(repo, tmp_path):
    secret = tmp_path / "secretdir"
    secret.mkdir()
    (secret / "secret.txt").write_bytes(b"s")
    res = subprocess.run(["cmd", "/c", "mklink", "/J", str(repo / "junction"), str(secret)],
                         capture_output=True)
    assert res.returncode == 0, res.stderr
    idx = tmp_path / "idx"
    idx.mkdir()
    before = loose_count(repo)
    with pytest.raises(ss.SnapshotRefused):
        ss.pin_paths(repo, ["junction\\secret.txt"], idx)
    with pytest.raises(ss.SnapshotRefused):
        ss.pin_paths(repo, ["junction/secret.txt"], idx)
    assert loose_count(repo) == before


@pytest.mark.skipif(WINDOWS, reason="symlinks need privileges on Windows")
def test_pin_symlink_leaf_refused(repo, tmp_path):
    os.symlink("a.txt", repo / "lnk")
    idx = tmp_path / "idx"
    idx.mkdir()
    with pytest.raises(ss.SnapshotRefused):
        ss.pin_paths(repo, ["lnk"], idx)


def test_main_prints_hash(repo, capsys):
    assert ss.main(["--repo", str(repo), "--tree", tree_of(repo)]) == 0
    out = capsys.readouterr().out
    assert "input_sha256=" in out and "files=3" in out
    assert ss.main(["--repo", str(repo), "--tree", "1" * 40]) == 2


# --- finding 2: the parser stops at the entry budget BEFORE accumulating --------------

def _big_tree(repo, n):
    """ONE tree object with n entries, all pointing at the same blob."""
    blob = git(repo, "rev-parse", "HEAD:a.txt")
    listing = "".join(f"100644 blob {blob}\tf{i:06d}\n" for i in range(n)).encode()
    return git(repo, "mktree", data=listing)


def test_tree_with_one_entry_too_many_refused(repo):
    tree = _big_tree(repo, 6)
    with pytest.raises(ss.SnapshotRefused, match="entries"):
        ss.build_snapshot(repo, tree, max_entries=5)
    assert ss.build_snapshot(repo, tree, max_entries=6).files == 6  # the boundary itself passes


def test_parser_does_not_build_more_than_budget_plus_one(repo, monkeypatch):
    tree = _big_tree(repo, 10000)
    orig = ss._parse_tree
    built = []

    def spy(raw, hashlen, *a, **k):
        result = orig(raw, hashlen, *a, **k)
        if isinstance(result, list):  # a list is fully built before the caller sees entry one
            built.append(len(result))
            return result

        def counting():
            n = 0
            for item in result:
                n += 1
                built.append(n)
                yield item
        return counting()

    monkeypatch.setattr(ss, "_parse_tree", spy)
    with pytest.raises(ss.SnapshotRefused, match="entries"):
        ss.build_snapshot(repo, tree, max_entries=5)
    assert built and max(built) <= 6, f"parser built {max(built)} entries for a budget of 5"


def test_entry_budget_refuses_before_a_poisoned_tail_is_parsed(repo):
    # Inspection round 2, part A, finding 17: a spy on yielded entries cannot tell a streaming
    # parser from one that builds the full list and then yields from it. A tree object whose
    # bytes after the budget are malformed can: a streaming parser refuses on the budget, an
    # eager one on the malformed tail it parsed first.
    blob = bytes.fromhex(git(repo, "rev-parse", "HEAD:a.txt"))
    raw = b"".join(b"100644 f%06d\0" % i + blob for i in range(6)) + b"100644 tail-without-nul"
    tree = subprocess.run(["git", "-C", str(repo), "hash-object", "-t", "tree", "--literally", "-w", "--stdin"],
                          input=raw, capture_output=True, check=True).stdout.decode().strip()
    with pytest.raises(ss.SnapshotRefused, match="too many entries"):
        ss.build_snapshot(repo, tree, max_entries=5)
    # positive control: with room for the tail, the same object is refused as malformed
    with pytest.raises(ss.SnapshotRefused, match="malformed"):
        ss.build_snapshot(repo, tree, max_entries=100)


# --- round 2, finding A1: an internal timeout is infrastructure (exit 5), not a refusal --

def test_git_timeout_is_infrastructure(repo, monkeypatch):
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)
    monkeypatch.setattr(ss.subprocess, "run", timeout)
    with pytest.raises(ss.SnapshotInfrastructure, match="timed out"):
        ss._git(repo, ["rev-parse", "HEAD"])


def test_git_that_cannot_start_is_infrastructure(repo, monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("git")
    monkeypatch.setattr(ss.subprocess, "run", missing)
    with pytest.raises(ss.SnapshotInfrastructure):
        ss._git(repo, ["rev-parse", "HEAD"])


def test_batch_deadline_is_infrastructure(repo, monkeypatch):
    monkeypatch.setattr(ss, "BATCH_DEADLINE", 0.05)
    batch = ss._Batch(repo, ss.object_format(repo))
    try:
        batch.proc.wait(30)  # the deadline timer kills the process
        with pytest.raises(ss.SnapshotInfrastructure, match="timed out"):
            batch.get(git(repo, "rev-parse", "HEAD:a.txt"), "blob", 1024)
    finally:
        batch.close()


def test_batch_failure_without_deadline_stays_a_refusal(repo):
    batch = ss._Batch(repo, ss.object_format(repo))
    try:
        with pytest.raises(ss.SnapshotRefused, match="missing"):
            batch.get("0" * len(git(repo, "rev-parse", "HEAD")), "blob", 1024)
    finally:
        batch.close()


def _timeout_below_the_api(monkeypatch):
    """Let `git --version` through (require_git) and time out the first real git call -- the
    failure is injected BELOW the public APIs, so their own exception handling is what is
    tested (closing gate, block A, findings 1 and 4)."""
    real = ss.subprocess.run

    def run(argv, *a, **k):
        if "--version" in argv:
            return real(argv, *a, **k)
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)
    monkeypatch.setattr(ss.subprocess, "run", run)


def test_build_snapshot_propagates_an_internal_timeout(repo, monkeypatch):
    tree = tree_of(repo)
    _timeout_below_the_api(monkeypatch)
    with pytest.raises(ss.SnapshotInfrastructure, match="timed out"):
        ss.build_snapshot(repo, tree)


def test_pin_paths_propagates_an_internal_timeout(repo, tmp_path, monkeypatch):
    (tmp_path / "idx").mkdir()
    _timeout_below_the_api(monkeypatch)
    with pytest.raises(ss.SnapshotInfrastructure, match="timed out"):
        ss.pin_paths(repo, ["a.txt"], tmp_path / "idx")


@pytest.mark.parametrize("pin", [False, True])
def test_cli_exits_5_when_git_times_out_inside(repo, tmp_path, monkeypatch, capsys, pin):
    tree = tree_of(repo)
    (tmp_path / "idx").mkdir()
    _timeout_below_the_api(monkeypatch)
    argv = ["--repo", str(repo)] + (["--pin", "a.txt", "--index-dir", str(tmp_path / "idx")] if pin
                                    else ["--tree", tree])
    assert ss.main(argv) == 5
    out = capsys.readouterr().out
    assert "ERROR=" in out and "REFUSED=" not in out


def test_cli_exits_5_on_an_internal_timeout(repo, monkeypatch, capsys):
    def timed_out(*a, **k):
        raise ss.SnapshotInfrastructure("git cat-file timed out")
    monkeypatch.setattr(ss, "build_snapshot", timed_out)
    assert ss.main(["--repo", str(repo), "--tree", tree_of(repo)]) == 5
    out = capsys.readouterr().out
    assert "ERROR=" in out and "REFUSED=" not in out


# --- finding 8: a tracked executable bit survives pinning on Windows ------------------

@pytest.mark.parametrize("is_nt,exec_bit,head,want", [
    (True, False, "100755", "100755"),   # Windows: no exec bit on disk, tracked 100755 stays
    (True, False, "100644", "100644"),
    (True, False, None, "100644"),       # new path on Windows
    (True, False, "120000", "100644"),   # a non-regular tracked mode is never inherited
    (False, True, "100644", "100755"),   # POSIX: the file mode wins
    (False, False, "100755", "100644"),
    (False, False, None, "100644"),
])
def test_pin_mode_choice(is_nt, exec_bit, head, want):
    assert ss._pin_mode(is_nt, exec_bit, head) == want


@pytest.mark.skipif(not WINDOWS, reason="the working-tree exec bit does not exist on Windows")
def test_pin_keeps_tracked_exec_bit_on_windows(repo, tmp_path):
    (repo / "run.sh").write_bytes(b"#!/bin/sh\necho changed\n")
    idx = tmp_path / "idx"
    idx.mkdir()
    tree = ss.pin_paths(repo, ["run.sh", "a.txt"], idx)
    assert git(repo, "ls-tree", tree, "run.sh").split()[0] == "100755"
    assert git(repo, "ls-tree", tree, "a.txt").split()[0] == "100644"


# --- finding 11: a partial clone must not reach the repo's own transport --------------

def _promisor_repo(tmp_path):
    repo = make_repo(tmp_path, {"a.txt": b"alpha\n", "b.txt": b"beta\n"})
    sentinel = tmp_path / "sentinel"
    script = tmp_path / "transport.sh"
    script.write_bytes(f"touch '{sentinel.as_posix()}'\nexit 1\n".encode())
    oid = git(repo, "rev-parse", "HEAD:b.txt")
    (repo / ".git" / "objects" / oid[:2] / oid[2:]).chmod(0o600)
    (repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
    git(repo, "config", "core.repositoryformatversion", "1")
    git(repo, "config", "extensions.partialClone", "origin")
    git(repo, "config", "remote.origin.promisor", "true")
    git(repo, "config", "remote.origin.url", f"ext::sh {script.as_posix()}")
    git(repo, "config", "protocol.ext.allow", "always")
    return repo, sentinel, oid


def test_promisor_transport_is_never_called(tmp_path):
    repo, sentinel, oid = _promisor_repo(tmp_path)
    # positive control: plain git DOES call the configured transport for the missing blob
    subprocess.run(["git", "-C", str(repo), "cat-file", "-p", oid], capture_output=True,
                   env=_ENV, timeout=60)
    if not sentinel.exists():
        pytest.skip("this git does not trigger the ext:: promisor transport; probe is not meaningful")
    sentinel.unlink()
    with pytest.raises(ss.SnapshotRefused, match="missing"):
        ss.build_snapshot(repo, tree_of(repo))
    assert not sentinel.exists(), "the hardened snapshot called the repo's promisor transport"


# --- finding 1: the CLI the supervised runner uses ------------------------------------

def _cli(repo, out, *extra):
    return ss.main(["--repo", str(repo), "--write", str(out), *extra])


def test_cli_write_tree(repo, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    assert _cli(repo, out, "--tree", tree_of(repo)) == 0
    printed = dict(line.split("=", 1) for line in capsys.readouterr().out.split())
    snap = ss.build_snapshot(repo, tree_of(repo))
    assert printed == {"TREE": snap.tree, "INPUT_SHA256": snap.input_sha256}
    assert (out / "snapshot.tar").read_bytes() == snap.tar_bytes
    meta = json.loads((out / "snapshot.json").read_text(encoding="ascii"))
    assert meta == {"tree": snap.tree, "input_sha256": snap.input_sha256, "files": 3,
                    "total_bytes": snap.total_bytes, "entries": [list(e) for e in snap.entries]}
    assert sorted(p.name for p in out.iterdir()) == ["snapshot.json", "snapshot.tar"]


def test_cli_write_pin(repo, tmp_path, capsys):
    (repo / "new.txt").write_bytes(b"batch\n")
    out, idx = tmp_path / "out", tmp_path / "idx"
    out.mkdir()
    idx.mkdir()
    assert _cli(repo, out, "--pin", "new.txt", "a.txt", "--index-dir", str(idx)) == 0
    printed = dict(line.split("=", 1) for line in capsys.readouterr().out.split())
    meta = json.loads((out / "snapshot.json").read_text())
    assert printed["TREE"] == meta["tree"]
    assert "new.txt" in [e[0] for e in meta["entries"]]
    assert list(idx.iterdir()) == []


def test_cli_limits_are_passed(repo, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    assert _cli(repo, out, "--tree", tree_of(repo), "--max-entries", "2") == 2
    assert "entries" in capsys.readouterr().err
    assert list(out.iterdir()) == []


def test_cli_refused_is_exit_2_ascii_no_files(repo, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    assert _cli(repo, out, "--tree", "1" * 40) == 2
    err = capsys.readouterr().err
    assert err.startswith("REFUSED") and err.isascii() and "Traceback" not in err
    assert list(out.iterdir()) == []


def test_cli_existing_output_file_refuses(repo, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    (out / "snapshot.tar").write_bytes(b"precious")
    assert _cli(repo, out, "--tree", tree_of(repo)) == 2
    assert "exists" in capsys.readouterr().err
    assert (out / "snapshot.tar").read_bytes() == b"precious"


def test_cli_other_exception_is_exit_5_without_traceback(repo, tmp_path, capsys, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(ss, "build_snapshot", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _cli(repo, out, "--tree", tree_of(repo)) == 5
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.isascii()


def test_cli_missing_output_dir_refuses(repo, tmp_path):
    assert _cli(repo, tmp_path / "nope", "--tree", tree_of(repo)) == 2


def test_cli_refusal_and_error_also_print_a_stdout_line(repo, tmp_path, capsys, monkeypatch):
    # the supervised runner discards stderr, so stdout must carry the reason as well
    out = tmp_path / "out"
    out.mkdir()
    assert _cli(repo, out, "--tree", "1" * 40) == 2
    cap = capsys.readouterr()
    line = [x for x in cap.out.splitlines() if x.startswith("REFUSED=")]
    assert len(line) == 1 and line[0].isascii() and "REFUSED" in cap.err
    monkeypatch.setattr(ss, "build_snapshot",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom " + "x" * 500)))
    assert _cli(repo, out, "--tree", tree_of(repo)) == 5
    cap = capsys.readouterr()
    line = [x for x in cap.out.splitlines() if x.startswith("ERROR=")]
    assert len(line) == 1 and "RuntimeError" in line[0] and "boom" in line[0]
    assert len(line[0]) <= len("ERROR=") + 200 and "Traceback" not in cap.out + cap.err
