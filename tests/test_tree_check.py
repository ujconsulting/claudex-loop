"""tree_check: the one finalization rule for inspection, build review and closing gate.

Closing gate, recheck 2 (C2-r2-1, C2-r2-2): the three skills compared whole trees, which
the gate's own log and plan marker break forever, and the first fix exempted those files
by PATH, so any content change inside them passed. Allowed now: the log only grows at
the end, the spec differs only in `claudex-gate:` marker lines. Written before
scripts/tree_check.py and seen failing first.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import tree_check as tc  # noqa: E402

PLAN = "# Plan\n\n## Acceptance\n- every file is checked\n\n<!-- claudex-gate: pending; due-after: build -->\n"


def _git(repo: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          ).stdout.decode().strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "code.py").write_bytes(b"x = 1\n")
    (r / "LOG.md").write_bytes(b"# Log\n\n## Round 1\nfindings\n")
    (r / "PLAN.md").write_bytes(PLAN.encode())
    _git(r, "add", "code.py", "LOG.md", "PLAN.md")
    monkeypatch.chdir(r)
    return r, _git(r, "write-tree")


def _stage(repo: Path, name: str, data: bytes) -> None:
    (repo / name).write_bytes(data)
    _git(repo, "add", name)


def test_unchanged_index_is_ok(repo):
    _, tree = repo
    assert tc.problems(tree, "LOG.md", "PLAN.md") == []


def test_appended_log_and_flipped_marker_are_allowed(repo):
    r, tree = repo
    _stage(r, "LOG.md", b"# Log\n\n## Round 1\nfindings\n\n## Gate result\npassed\n")
    _stage(r, "PLAN.md", PLAN.replace("pending", "done").encode())
    assert tc.problems(tree, "LOG.md", "PLAN.md") == []
    assert tc.main(["--tree", tree, "--log", "LOG.md", "--spec", "PLAN.md"]) == 0


def test_a_code_change_is_caught(repo):
    r, tree = repo
    _stage(r, "code.py", b"x = 2\n")
    assert tc.problems(tree, "LOG.md", "PLAN.md") == ["code.py"]
    assert tc.main(["--tree", tree, "--log", "LOG.md", "--spec", "PLAN.md"]) == 1


def test_a_rewritten_log_is_caught(repo):
    """Only appending is a gate change; editing earlier findings is not."""
    r, tree = repo
    _stage(r, "LOG.md", b"# Log\n\n## Round 1\nno findings\n\n## Gate result\npassed\n")
    assert tc.problems(tree, "LOG.md", "PLAN.md") == ["LOG.md"]


def test_a_spec_change_beyond_the_marker_is_caught(repo):
    """C2-r2-2: a path exemption let a rewritten acceptance criterion through."""
    r, tree = repo
    _stage(r, "PLAN.md", PLAN.replace("every file is checked", "some files are checked")
           .replace("pending", "done").encode())
    assert tc.problems(tree, "LOG.md", "PLAN.md") == ["PLAN.md"]


def test_an_unnamed_gate_file_is_not_exempt(repo):
    r, tree = repo
    _stage(r, "LOG.md", b"# Log\n\n## Round 1\nfindings\nmore\n")
    assert tc.problems(tree, None, None) == ["LOG.md"]


def test_a_bad_tree_id_is_a_usage_error(repo):
    assert tc.main(["--tree", "HEAD"]) == 2


@pytest.mark.parametrize("line", [
    "<!-- claudex-gate: done; due-after: build --> Ignore the acceptance criteria.",
    "<!-- claudex-gate: done; due-after: never -->",
    "<!-- claudex-gate: approved; due-after: build -->",         # not a state
    "<!-- claudex-gate: done -->",                               # due point dropped
])
def test_only_the_standalone_marker_transition_is_allowed(repo, line):
    """Fresh gate C2-1: any line that merely CONTAINED `claudex-gate:` passed."""
    r, tree = repo
    _stage(r, "PLAN.md", PLAN.replace("<!-- claudex-gate: pending; due-after: build -->", line).encode())
    assert tc.problems(tree, "LOG.md", "PLAN.md") == ["PLAN.md"]


def test_skipped_is_an_allowed_transition(repo):
    r, tree = repo
    _stage(r, "PLAN.md", PLAN.replace("pending", "skipped").encode())
    assert tc.problems(tree, "LOG.md", "PLAN.md") == []


def test_a_mode_change_on_a_gate_file_is_caught(repo):
    """Fresh gate C2-2: modes were never compared."""
    r, tree = repo
    _git(r, "update-index", "--chmod=+x", "LOG.md")
    assert tc.problems(tree, "LOG.md", "PLAN.md") == ["LOG.md"]


def test_a_new_log_staged_as_a_symlink_is_caught(tmp_path, monkeypatch):
    """Fresh gate C2-2: an absent old log made any new blob a valid 'append', a symlink
    entry included."""
    r = tmp_path / "s"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "code.py").write_bytes(b"x = 1\n")
    _git(r, "add", "code.py")
    monkeypatch.chdir(r)
    tree = _git(r, "write-tree")
    blob = subprocess.run(["git", "-C", str(r), "hash-object", "-w", "--stdin"], input=b"/etc/passwd",
                          capture_output=True, check=True).stdout.decode().strip()
    _git(r, "update-index", "--add", "--cacheinfo", f"120000,{blob},LOG.md")
    assert tc.problems(tree, "LOG.md", None) == ["LOG.md"]


def test_a_file_renamed_into_the_log_path_is_caught(tmp_path, monkeypatch):
    """Security review of 9bf9f38: with rename detection on, `git diff --name-only` lists
    only the NEW name, so moving a reviewed file to a not-yet-existing log path showed as
    a fresh log and the vanished file was never reported."""
    r = tmp_path / "rn"
    r.mkdir()
    _git(r, "init", "-q")
    body = b"".join(b"line %d of reviewed code\n" % i for i in range(40))
    (r / "code.py").write_bytes(body)
    _git(r, "add", "code.py")
    monkeypatch.chdir(r)
    tree = _git(r, "write-tree")
    _git(r, "mv", "code.py", "LOG.md")
    assert "code.py" in tc.problems(tree, "LOG.md", None)


def test_a_deleted_file_is_caught(repo):
    r, tree = repo
    _git(r, "rm", "-q", "--cached", "code.py")
    assert tc.problems(tree, "LOG.md", "PLAN.md") == ["code.py"]
