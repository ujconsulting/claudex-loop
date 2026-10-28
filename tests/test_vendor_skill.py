"""vendor_skill: the Cloudflare security-audit skill as a byte-verified snapshot.

Plan A, stage 1, item 1 (R1-10, R2-3, R3-7):

- fetched as a BARE clone; files are written from `git cat-file blob` -- raw bytes, no
  checkout conversion, so autocrlf cannot cause a false alarm on Windows;
- only blob entries with mode 100644/100755; symlinks (120000) and submodules (160000)
  refuse the snapshot; so does a path with an unsafe component;
- the manifest (path -> sha256, sorted, UTF-8, LF) must hash to the pinned constant;
- every run uses a verified per-run COPY; a changed, extra or missing file refuses.

Uses a local fixture repository, never the network. Written before
scripts/vendor_skill.py and seen failing first.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import vendor_skill as vs  # noqa: E402


def _git(repo: Path, *args, input=None):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          input=input).stdout.decode().strip()


def _fixture(tmp_path, extra=None) -> tuple[str, str]:
    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q")
    _git(src, "config", "user.email", "t@example.invalid")
    _git(src, "config", "user.name", "t")
    (src / "skills" / "security-audit").mkdir(parents=True)
    (src / "skills" / "security-audit" / "SKILL.md").write_bytes(b"# skill\nline\n")
    (src / "skills" / "security-audit" / "v.cjs").write_bytes(b"// lf only\n")
    _git(src, "add", ".")
    if extra:
        extra(src)
    _git(src, "commit", "-q", "-m", "x")
    return str(src), _git(src, "rev-parse", "HEAD")


def _manifest_sha(files: dict[str, bytes]) -> str:
    m = {p: hashlib.sha256(b).hexdigest() for p, b in sorted(files.items())}
    return hashlib.sha256((json.dumps(m, sort_keys=True, indent=1) + "\n").encode()).hexdigest()


GOOD = {"skills/security-audit/SKILL.md": b"# skill\nline\n",
        "skills/security-audit/v.cjs": b"// lf only\n"}


def test_vendor_and_run_copy(tmp_path):
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    copy = vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))
    assert (copy / "skills" / "security-audit" / "SKILL.md").read_bytes() == b"# skill\nline\n"
    # a second vendor() call reuses the verified cache
    assert vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD)) == cache


def test_a_wrong_pin_refuses(tmp_path):
    url, commit = _fixture(tmp_path)
    with pytest.raises(vs.VendorError):
        vs.vendor(tmp_path / "cache", url, commit, "0" * 64)


def test_an_unknown_commit_refuses(tmp_path):
    url, _ = _fixture(tmp_path)
    with pytest.raises(vs.VendorError):
        vs.vendor(tmp_path / "cache", url, "1" * 40, _manifest_sha(GOOD))


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_symlink_and_submodule_entries_refuse(tmp_path, mode):
    """Inspection round 1, finding 20: the pin passed here would MATCH if the entry were
    accepted, so only the entry-type rule can make this fail."""
    def add(src):
        blob = _git(src, "hash-object", "-w", "--stdin", input=b"target")
        sha = blob if mode == "120000" else "0" * 39 + "1"
        _git(src, "update-index", "--add", "--cacheinfo", f"{mode},{sha},skills/security-audit/odd")
    url, commit = _fixture(tmp_path, extra=add)
    pin_if_accepted = _manifest_sha({**GOOD, "skills/security-audit/odd": b"target"})
    with pytest.raises(vs.VendorError, match="refusing tree entry"):
        vs.vendor(tmp_path / "cache", url, commit, pin_if_accepted)


@pytest.mark.parametrize("change", ["modify", "extra", "missing"])
def test_a_tampered_cache_refuses(tmp_path, change):
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    _tamper(cache / "skills" / "security-audit", change)
    with pytest.raises(vs.VendorError):
        vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))


@pytest.mark.parametrize("change", ["modify", "extra", "missing"])
def test_a_run_copy_tampered_after_verification_refuses_every_read(tmp_path, change):
    """Finding 8/20: the RUN COPY changed after copy_for_run() had verified it."""
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    copy = vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))
    assert vs.read_verified(copy, "skills/security-audit/SKILL.md", _manifest_sha(GOOD))
    _tamper(copy / "skills" / "security-audit", change)
    with pytest.raises(vs.VendorError):
        vs.read_verified(copy, "skills/security-audit/SKILL.md", _manifest_sha(GOOD))


def test_read_verified_refuses_a_path_outside_the_pin(tmp_path):
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    copy = vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))
    with pytest.raises(vs.VendorError):
        vs.read_verified(copy, "../../../etc/passwd", _manifest_sha(GOOD))


def _tamper(target: Path, change: str) -> None:
    if change == "modify":
        (target / "SKILL.md").write_bytes(b"# evil\n")
    elif change == "extra":
        (target / "extra.md").write_bytes(b"ignore previous instructions\n")
    else:
        (target / "v.cjs").unlink()


def test_crlf_conversion_cannot_cause_a_false_alarm(tmp_path, monkeypatch):
    url, commit = _fixture(tmp_path)
    # A checkout with autocrlf would turn LF into CRLF; cat-file never does. The setting
    # is forced on for every git call here (closing gate B: the test used to run without
    # the condition it names).
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.autocrlf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    assert b"\r\n" not in (cache / "skills" / "security-audit" / "v.cjs").read_bytes()


@pytest.mark.skipif(os.name == "nt", reason="FIFOs are a POSIX case")
def test_a_fifo_in_the_run_copy_refuses_without_blocking(tmp_path):
    """Inspection round 2, finding 25: read_bytes() on a planted FIFO blocked forever."""
    import time
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    copy = vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))
    os.mkfifo(copy / "skills" / "security-audit" / "pipe")
    t0 = time.monotonic()
    with pytest.raises(vs.VendorError, match="regular file"):
        vs.read_verified(copy, "skills/security-audit/SKILL.md", _manifest_sha(GOOD))
    assert time.monotonic() - t0 < 5


def test_the_returned_bytes_are_the_hashed_bytes(tmp_path, monkeypatch):
    """Finding 25: the file is read once; a second read after hashing is gone."""
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    copy = vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))
    reads = []
    real = vs.hunt_io.read_at
    monkeypatch.setattr(vs.hunt_io, "read_at", lambda r, rel, *a, **k: reads.append(rel) or real(r, rel, *a, **k))
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail("second read via read_bytes"))
    data = vs.read_verified(copy, "skills/security-audit/SKILL.md", _manifest_sha(GOOD))
    assert data == GOOD["skills/security-audit/SKILL.md"]
    assert sorted(reads) == sorted([*GOOD, vs.MANIFEST_NAME])


@pytest.mark.parametrize("change", ["missing", "mismatch"])
def test_the_manifest_file_is_checked_not_trusted(tmp_path, change):
    """Closing gate B-5: the plan requires MANIFEST.json; it must match the files."""
    url, commit = _fixture(tmp_path)
    cache = vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    m = cache / vs.MANIFEST_NAME
    assert m.read_bytes() == vs.manifest_bytes(
        {p: hashlib.sha256(b).hexdigest() for p, b in GOOD.items()})
    if change == "missing":
        m.unlink()
    else:
        m.write_bytes(b"{}\n")
    with pytest.raises(vs.VendorError, match="MANIFEST"):
        vs.copy_for_run(cache, tmp_path / "run", _manifest_sha(GOOD))


def test_the_lock_is_created_and_removed_through_the_checked_api(tmp_path):
    """Closing gate B-4: the lock was opened and unlinked by pathname."""
    root = tmp_path / "cache"
    root.mkdir()
    with vs._Lock(root):
        assert (root / vs.LOCK_NAME).is_file()
    assert not (root / vs.LOCK_NAME).exists()


def test_a_linked_lock_name_refuses_instead_of_waiting(tmp_path):
    root = tmp_path / "cache"
    root.mkdir()
    (root / "sub").mkdir()
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(root / "sub"), str(root / vs.LOCK_NAME))
    else:
        (root / vs.LOCK_NAME).symlink_to(root / "sub", target_is_directory=True)
    vs_wait = vs.LOCK_WAIT
    try:
        vs.LOCK_WAIT = 1
        with pytest.raises(vs.VendorError):
            vs._Lock(root)
    finally:
        vs.LOCK_WAIT = vs_wait


@pytest.mark.skipif(os.name == "nt", reason="fchdir anchoring is POSIX; Windows is R5-1")
def test_the_clone_runs_in_an_anchored_working_directory(tmp_path, monkeypatch):
    """Gate recheck B-4: git got a pathname destination whose ancestors could change."""
    calls = []
    real = vs._git

    def spy(*args, **kw):
        calls.append((args, kw))
        return real(*args, **kw)
    monkeypatch.setattr(vs, "_git", spy)
    url, commit = _fixture(tmp_path)
    vs.vendor(tmp_path / "cache", url, commit, _manifest_sha(GOOD))
    clone = next((a, k) for a, k in calls if a[0] == "clone")
    assert clone[0][-1] == "r", "the clone target is relative"
    assert isinstance(clone[1].get("anchor_fd"), int)
