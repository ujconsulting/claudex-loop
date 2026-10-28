"""hunt_io: write targets of the security hunt (plan A, stage 1, item 8; R4-6, R5-1).

- every ancestor of a write target is checked with lstat: no symlink, no reparse point
  (Windows junction);
- run directories are created exclusively, files with O_CREAT|O_EXCL (never overwritten);
- on POSIX creation is anchored to a verified directory handle (dir_fd), so swapping a
  parent between check and create cannot redirect the write (R5-1). On Windows that race
  is the named residual, tested only for a redirect that exists BEFORE the check.

Written before scripts/hunt_io.py and seen failing first.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hunt_io  # noqa: E402

WINDOWS = os.name == "nt"


def _junction(link: Path, target: Path) -> None:
    import _winapi  # Windows only; no admin rights needed for a junction
    _winapi.CreateJunction(str(target), str(link))


def _redirect(link: Path, target: Path) -> None:
    if WINDOWS:
        _junction(link, target)
    else:
        link.symlink_to(target, target_is_directory=True)


def test_creates_a_private_run_dir_and_an_exclusive_file(tmp_path):
    run = hunt_io.make_dir(tmp_path, "run-1")
    assert run.is_dir()
    f = hunt_io.create_file(run, "a.json", b"{}\n")
    assert f.read_bytes() == b"{}\n"


def test_an_existing_run_dir_is_not_reused(tmp_path):
    hunt_io.make_dir(tmp_path, "run-1")
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.make_dir(tmp_path, "run-1")


def test_an_existing_file_is_never_overwritten(tmp_path):
    hunt_io.create_file(tmp_path, "a.json", b"one")
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(tmp_path, "a.json", b"two")
    assert (tmp_path / "a.json").read_bytes() == b"one"


@pytest.mark.parametrize("name", ["../x", "a/b", "a\\b", "", ".", "..", "C:x"])
def test_names_are_plain_leaf_names(tmp_path, name):
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(tmp_path, name, b"x")


def test_a_redirected_ancestor_is_refused_and_nothing_written_outside(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    _redirect(base / "audit", outside)
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(base / "audit", "report.md", b"x")
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.make_dir(base / "audit", "run-1")
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(WINDOWS, reason="R5-1: on Windows a swap after the check is the named residual")
def test_posix_parent_swap_between_check_and_create_cannot_redirect(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    parent = tmp_path / "audit"
    parent.mkdir()

    def swap():
        parent.rename(tmp_path / "audit.old")
        parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(parent, "report.md", b"x", _after_check=swap)
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(WINDOWS, reason="R5-1: on Windows a swap after the check is the named residual")
def test_posix_ANCESTOR_swap_between_check_and_create_cannot_redirect(tmp_path):
    """Inspection round 1, finding 2: the old test swapped only the last component."""
    outside = tmp_path / "outside"
    (outside / "audit").mkdir(parents=True)
    grand = tmp_path / "docs"
    (grand / "audit").mkdir(parents=True)

    def swap():
        grand.rename(tmp_path / "docs.old")
        grand.symlink_to(outside, target_is_directory=True)

    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(grand / "audit", "report.md", b"x", _after_check=swap)
    assert list((outside / "audit").iterdir()) == []


def test_ensure_dirs_creates_nothing_below_a_redirected_ancestor(tmp_path):
    """Finding 3: mkdir(parents=True) used to create directories before any check."""
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    _redirect(base / "scratch", outside)
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.ensure_dirs(base / "scratch" / "security-hunt" / "x")
    assert list(outside.iterdir()) == []


def test_ensure_dirs_creates_missing_components(tmp_path):
    p = hunt_io.ensure_dirs(tmp_path / "a" / "b" / "c")
    assert p.is_dir()
    assert hunt_io.ensure_dirs(tmp_path / "a" / "b" / "c") == p  # idempotent for real dirs


def test_links_above_the_trusted_base_are_the_users_system(tmp_path):
    """A link ABOVE the base (macOS: /var, /tmp) is taken as it is; below it, refused."""
    real = tmp_path / "real"
    (real / "scratch").mkdir(parents=True)
    _redirect(tmp_path / "alias", real)
    base = tmp_path / "alias" / "scratch"  # the alias sits ABOVE the base
    run = hunt_io.make_dir(base, "run-1", base=base)
    assert (real / "scratch" / "run-1").is_dir()
    hunt_io.create_file(run, "a.txt", b"x", base=base)
    _redirect(base / "inner", tmp_path)
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(base / "inner", "b.txt", b"x", base=base)


def test_the_trusted_base_itself_must_not_be_a_link(tmp_path):
    """Inspection round 2, finding 23: a base that is itself a link or junction used to be
    accepted, so everything "below the base" landed wherever it pointed."""
    outside = tmp_path / "outside"
    outside.mkdir()
    _redirect(tmp_path / "base", outside)
    base = tmp_path / "base"
    with pytest.raises(hunt_io.HuntIOError, match="trusted base"):
        hunt_io.make_dir(base, "run-1", base=base)
    with pytest.raises(hunt_io.HuntIOError, match="trusted base"):
        hunt_io.ensure_dirs(base / "x", base=base)
    assert list(outside.iterdir()) == []
    assert hunt_io.read_at(base, "a.txt") == ("refused", "link")


def test_read_at_refuses_a_redirected_ancestor(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    _redirect(repo / "sub", outside)
    assert hunt_io.read_at(repo, "sub/secret.txt") == ("refused", "link")
    (repo / "ok.txt").write_bytes(b"fine\n")
    assert hunt_io.read_at(repo, "ok.txt") == ("ok", b"fine\n")


@pytest.mark.skipif(WINDOWS, reason="R5-1: on Windows a swap after the check is the named residual")
def test_posix_ancestor_swap_between_check_and_read_is_not_followed(tmp_path):
    """Inspection round 2, finding 30: the snapshot checked parents, then read by path --
    a parent swapped to a symlink in between led the read outside the repository."""
    outside = tmp_path / "outside"
    (outside / "sub").mkdir(parents=True)
    (outside / "sub" / "f.txt").write_text("OUTSIDE\n", encoding="utf-8")
    repo = tmp_path / "repo"
    (repo / "d" / "sub").mkdir(parents=True)
    (repo / "d" / "sub" / "f.txt").write_text("inside\n", encoding="utf-8")

    def swap():
        (repo / "d").rename(tmp_path / "d.old")
        (repo / "d").symlink_to(outside, target_is_directory=True)

    status, payload = hunt_io.read_at(repo, "d/sub/f.txt", _after_check=swap)
    assert status == "refused" and payload == "link"


def test_a_target_outside_the_base_is_refused(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.create_file(tmp_path / "b", "x.txt", b"x", base=tmp_path / "a")


def test_ledger_guard_sees_every_line_and_can_refuse(tmp_path):
    seen = []

    def guard(line):
        seen.append(line)
        if "bad" in line:
            raise hunt_io.HuntIOError("guard refused")
        return line.replace("secret", "[REDACTED]")
    with hunt_io.Ledger(tmp_path, "l.jsonl", guard=guard) as led:
        led.append({"x": "secret"})
        with pytest.raises(hunt_io.HuntIOError):
            led.append({"x": "bad"})
    assert (tmp_path / "l.jsonl").read_text(encoding="utf-8") == '{"x": "[REDACTED]"}\n'


def test_ledger_appends_and_never_replaces(tmp_path):
    with hunt_io.Ledger(tmp_path, "ledger.jsonl") as led:
        led.append({"n": 1})
        led.append({"n": 2})
    lines = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    assert lines == ['{"n": 1}', '{"n": 2}']
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.Ledger(tmp_path, "ledger.jsonl")


def test_reopen_refuses_a_linked_or_special_ledger(tmp_path):
    d = tmp_path / "audit"
    d.mkdir()
    (tmp_path / "outside.jsonl").write_bytes(b"")
    hunt_io.Ledger(d, "real.jsonl").close()
    assert hunt_io.Ledger.reopen(d, "real.jsonl").path == d / "real.jsonl"
    if not WINDOWS:
        (d / "link.jsonl").symlink_to(tmp_path / "outside.jsonl")
        with pytest.raises(hunt_io.HuntIOError):
            hunt_io.Ledger.reopen(d, "link.jsonl")
        os.mkfifo(d / "pipe.jsonl")
        with pytest.raises(hunt_io.HuntIOError):
            hunt_io.Ledger.reopen(d, "pipe.jsonl")


@pytest.mark.skipif(WINDOWS, reason="R5-1: on Windows a swap after the check is the named residual")
def test_posix_ancestor_swap_cannot_redirect_a_reopened_ledger(tmp_path):
    """Closing gate A1-1: reopen checked the chain, then stat-ed and opened by pathname."""
    outside = tmp_path / "outside"
    (outside / "audit").mkdir(parents=True)
    (outside / "audit" / "l.jsonl").write_bytes(b"")
    base = tmp_path / "repo"
    (base / "docs" / "audit").mkdir(parents=True)
    hunt_io.Ledger(base / "docs" / "audit", "l.jsonl", base=base).close()

    def swap():
        (base / "docs").rename(tmp_path / "docs.old")
        (base / "docs").symlink_to(outside, target_is_directory=True)
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.Ledger.reopen(base / "docs" / "audit", "l.jsonl", base=base, _after_check=swap)
    assert (outside / "audit" / "l.jsonl").read_bytes() == b""


def test_walk_files_refuses_links_and_special_entries(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.txt").write_bytes(b"x")
    assert hunt_io.walk_files(tmp_path) == ["a/f.txt"]
    (tmp_path / "o").mkdir()
    _redirect(tmp_path / "a" / "j", tmp_path / "o")
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.walk_files(tmp_path)


def test_replace_file_replaces_the_entry_and_never_writes_through_a_link(tmp_path):
    (tmp_path / "f.txt").write_bytes(b"old")
    hunt_io.replace_file(tmp_path, "f.txt", b"new")
    assert (tmp_path / "f.txt").read_bytes() == b"new"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.txt"]
    (tmp_path / "o").mkdir()
    (tmp_path / "o" / "victim.txt").write_bytes(b"keep")
    _redirect(tmp_path / "d", tmp_path / "o")
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.replace_file(tmp_path, "d/victim.txt", b"pwned")
    assert (tmp_path / "o" / "victim.txt").read_bytes() == b"keep"


def test_rename_and_remove_refuse_existing_targets_and_links(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.rename_entry(tmp_path, "a", "b", base=tmp_path)
    hunt_io.rename_entry(tmp_path, "a", "c", base=tmp_path)
    assert (tmp_path / "c").is_dir() and not (tmp_path / "a").exists()
    (tmp_path / "f").write_bytes(b"")
    hunt_io.remove_file(tmp_path, "f", base=tmp_path)
    assert not (tmp_path / "f").exists()
    with pytest.raises(hunt_io.HuntIOError):
        hunt_io.remove_file(tmp_path, "c", base=tmp_path)  # a directory, not a file


def test_walk_files_refuses_a_directory_it_cannot_list(tmp_path, monkeypatch):
    """Gate recheck A1-3/A2-2: os.walk() skips unlistable directories silently, so a
    tree could be reported complete with a subtree missing."""
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.txt").write_bytes(b"x")
    real = os.scandir

    def scandir(path="."):
        if str(path).endswith("a"):
            raise PermissionError(13, "denied", str(path))
        return real(path)
    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(hunt_io.HuntIOError, match="cannot list"):
        hunt_io.walk_files(tmp_path)


@pytest.mark.skipif(WINDOWS, reason="R5-1: on Windows a swap during the operation is the named residual")
def test_posix_failed_replace_cleans_up_only_its_own_directory(tmp_path, monkeypatch):
    """Gate recheck A1-2: after a failed rename the clean-up unlinked by pathname and,
    with an ancestor swapped meanwhile, deleted a same-named file elsewhere."""
    root = tmp_path / "root"
    (root / "d").mkdir(parents=True)
    (root / "d" / "f.txt").write_bytes(b"old")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / ".f.txt.claudex-new"
    sentinel.write_bytes(b"keep")
    real_replace = os.replace

    def failing_replace(*a, **k):
        (root / "d").rename(tmp_path / "d.old")
        (root / "d").symlink_to(outside, target_is_directory=True)
        raise OSError("simulated rename failure")
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError):
        hunt_io.replace_file(root, "d/f.txt", b"new")
    monkeypatch.setattr(os, "replace", real_replace)
    assert sentinel.read_bytes() == b"keep"
    assert not (tmp_path / "d.old" / ".f.txt.claudex-new").exists()
