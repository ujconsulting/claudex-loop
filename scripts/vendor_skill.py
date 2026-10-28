#!/usr/bin/env python3
"""The Cloudflare security-audit skill as a byte-verified, pinned snapshot.

Plan A, stage 1, item 1 (docs/plans/2026-10-27-sicherheitskette, approved round 7).
`npx skills add` installs whatever the repository holds today and lets it change later;
here every byte the hunt reads is the pinned commit's:

- a BARE clone; files are written from `git cat-file blob` -- the raw blob, no checkout
  conversion, so core.autocrlf cannot turn LF into CRLF and cause a false alarm (R3-7);
- only blob entries with mode 100644/100755; a symlink (120000), a submodule (160000) or
  a path with an unsafe component refuses the snapshot;
- the manifest (path -> sha256, sorted, UTF-8, LF) must hash to MANIFEST_SHA256;
- the cache is published by one rename under an exclusive `vendor.claudex-lock`;
- every run copies the cache into its own directory and verifies the COPY (bytes, type,
  no extra or missing file) before anything is read from it (R2-3, R3-7).

The two .cjs validators of the pinned commit were read before pinning (2026-10-27): they
only open, read, fstat and close files -- no child process, network, write, environment
or eval. Updating the pin means reading them again.

Every write goes through hunt_io: the lock, each file, MANIFEST.json and the publishing
rename (closing gate B-4). `git clone` writes relative to a working directory set by
fchdir() to the anchored temporary directory (POSIX), so a swapped ancestor cannot
redirect it. On Windows all of this is path-based after the check: R5-1, as in hunt_io.
Messages are ASCII only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402

REPO_URL = "https://github.com/cloudflare/security-audit-skill.git"
PINNED_COMMIT = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
# sha256 of the manifest of PINNED_COMMIT, computed by `vendor_skill.py --print-pin`.
MANIFEST_SHA256 = "a4fe62abe68d9aa6a6a524eec29bf8156e947d39461fb7a6153f1f0628e3d4d2"  # 2026-10-27
DEFAULT_CACHE = Path.home() / ".claudex" / "vendor" / "security-audit-skill"
LOCK_NAME = "vendor.claudex-lock"
MANIFEST_NAME = "MANIFEST.json"  # path -> sha256, sorted, UTF-8, LF (plan A, item 1)
LOCK_WAIT = 60
GIT_TIMEOUT = 300
ALLOWED_MODES = ("100644", "100755")
_SAFE_PART = re.compile(r"^[A-Za-z0-9._@+-]+$")


class VendorError(Exception):
    pass


def _git(*args: str, cwd: Path | None = None, binary: bool = False, anchor_fd: int | None = None):
    """Run git; raise VendorError on failure. `anchor_fd` (POSIX): git starts with its
    working directory set by fchdir() to that already-verified directory handle, so
    relative paths it writes stay in that directory even if an ancestor is swapped
    afterwards (gate recheck B-4)."""
    # Unattended and anonymous: no stdin, no terminal or GUI credential prompt (the
    # Windows credential manager otherwise aborts the session: "remote helper 'https'
    # aborted session", measured 2026-10-27). The skill repository is public.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never")
    try:
        # core.longpaths: a bare clone below a deep cache path passes Windows' 260-char
        # MAX_PATH inside objects/pack/ (measured 2026-10-27 under the session scratchpad).
        anchored = {}
        if anchor_fd is not None:
            anchored = {"pass_fds": (anchor_fd,), "preexec_fn": lambda: os.fchdir(anchor_fd)}
        done = subprocess.run(["git", "-c", "credential.helper=", "-c", "core.longpaths=true", *args],
                              cwd=cwd,
                              capture_output=True, timeout=GIT_TIMEOUT,
                              stdin=subprocess.DEVNULL, env=env, **anchored)
    except (OSError, subprocess.SubprocessError) as exc:
        raise VendorError(f"git did not run: {exc}") from exc
    if done.returncode != 0:
        tail = done.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        reason = tail[0].encode("ascii", "replace").decode("ascii")[:200]
        raise VendorError(f"git {args[0]} exited {done.returncode}: {reason}")
    return done.stdout if binary else done.stdout.decode("utf-8", "strict")


def _safe_path(path: str) -> str:
    parts = path.split("/")
    if not parts or any(p in ("", ".", "..") or not _SAFE_PART.match(p) for p in parts):
        raise VendorError(f"unsafe path in the pinned tree: {path!r}")
    return path


def manifest_bytes(files: dict[str, str]) -> bytes:
    return (json.dumps(dict(sorted(files.items())), sort_keys=True, indent=1) + "\n").encode("utf-8")


def _tree(bare: Path, commit: str) -> list[tuple[str, str]]:
    out = []
    raw = _git("ls-tree", "-r", "-z", "--full-tree", commit, cwd=bare)
    for entry in raw.split("\0"):
        if not entry:
            continue
        meta, _, path = entry.partition("\t")
        mode, kind, sha = meta.split()
        if kind != "blob" or mode not in ALLOWED_MODES:
            raise VendorError(f"refusing tree entry {path!r}: {kind} {mode}")
        out.append((_safe_path(path), sha))
    return out


def _read_tree(root: Path) -> dict[str, bytes]:
    """Every file under root, read ONLY as a regular file without following a link; any
    link, junction or special entry refuses (inspection round 2, finding 25)."""
    try:
        rels = hunt_io.walk_files(root)
    except hunt_io.HuntIOError as exc:
        raise VendorError(f"skill tree refused: {exc}") from exc
    data = {}
    for rel in rels:
        status, payload = hunt_io.read_at(Path(root), rel)
        if status != "ok":
            raise VendorError(f"{rel} is not a readable regular file ({payload})")
        data[rel] = payload
    return data


def _verified(root: Path, manifest_sha: str, with_manifest: bool = True
              ) -> tuple[dict[str, str], dict[str, bytes]]:
    """(hashes, bytes) of the skill files under root. They must hash to the pinned
    manifest, and root/MANIFEST.json must hold exactly that manifest -- it is checked
    against the files, never trusted (closing gate B-5). `with_manifest=False` only while
    building, before the file is written."""
    data = _read_tree(root)
    stored = data.pop(MANIFEST_NAME, None)
    files = {rel: hashlib.sha256(b).hexdigest() for rel, b in data.items()}
    if hashlib.sha256(manifest_bytes(files)).hexdigest() != manifest_sha:
        raise VendorError("snapshot does not match the pinned manifest (changed, extra or missing file)")
    if with_manifest and stored != manifest_bytes(files):
        raise VendorError(f"{MANIFEST_NAME} is missing or does not match the files "
                          f"(a cache from before it existed: remove it and vendor again)")
    return files, data


def verify_tree(root: Path, manifest_sha: str) -> dict[str, str]:
    """Hash every regular file under root; the set must match and hash to manifest_sha."""
    return _verified(root, manifest_sha)[0]


class _Lock:
    def __init__(self, root: Path):
        self.root = root
        self.path = root / LOCK_NAME
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:  # exclusive and anchored (closing gate B-4)
                self.fd = hunt_io._open_exclusive(root, LOCK_NAME, base=root)
                return
            except hunt_io.HuntIOError:
                if not os.path.lexists(self.path):
                    raise  # not "locked" -- a real refusal
                if time.monotonic() > deadline:
                    raise VendorError(f"vendor cache is locked ({self.path}); another install "
                                      f"is running, or a stale lock needs removing by a human")
                time.sleep(0.5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        os.close(self.fd)
        hunt_io.remove_file(self.root, LOCK_NAME, base=self.root)


def vendor(cache_root: Path = DEFAULT_CACHE, url: str = REPO_URL, commit: str = PINNED_COMMIT,
           manifest_sha: str = MANIFEST_SHA256) -> Path:
    """Return the verified cache directory for `commit`, creating it if needed."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha):
        raise VendorError("commit or manifest pin is not a full hash")
    cache_root = hunt_io.ensure_dirs(Path(cache_root))  # checked creation (finding 3)
    with _Lock(cache_root):
        final = cache_root / commit
        if final.exists():
            verify_tree(final, manifest_sha)
            return final
        tmp = hunt_io.make_dir(cache_root, f"t{secrets.token_hex(4)}", base=cache_root)
        files_dir = hunt_io.make_dir(cache_root, f"f{secrets.token_hex(4)}", base=cache_root)
        try:
            bare = tmp / "r"
            # The clone is written RELATIVE to an anchored working directory (POSIX), never
            # to a pathname whose ancestors could change meanwhile (gate recheck B-4).
            dfd = hunt_io._open_dir_anchor(tmp, base=cache_root)
            try:
                if dfd is not None:
                    _git("clone", "--bare", "--quiet", url, "r", anchor_fd=dfd)
                else:  # Windows: path-based, R5-1
                    _git("clone", "--bare", "--quiet", url, "r", cwd=tmp)
            finally:
                if dfd is not None:
                    os.close(dfd)
            if _git("rev-parse", "--verify", f"{commit}^{{commit}}", cwd=bare).strip() != commit:
                raise VendorError("pinned commit not found")
            for path, sha in _tree(bare, commit):
                data = _git("cat-file", "blob", sha, cwd=bare, binary=True)
                parent = hunt_io.make_tree(files_dir, path.rpartition("/")[0], base=cache_root)
                hunt_io.create_file(parent, path.rpartition("/")[2], data, base=cache_root)
            files = _verified(files_dir, manifest_sha, with_manifest=False)[0]
            hunt_io.create_file(files_dir, MANIFEST_NAME, manifest_bytes(files), base=cache_root)
            # Published in one move through the anchored cache handle (closing gate B-4).
            hunt_io.rename_entry(cache_root, files_dir.name, commit, base=cache_root)
        except hunt_io.HuntIOError as exc:
            raise VendorError(f"vendor refused: {exc}") from exc
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(files_dir, ignore_errors=True)  # gone after a successful rename
        verify_tree(final, manifest_sha)
        return final


def copy_for_run(cache: Path, run_dir: Path, manifest_sha: str = MANIFEST_SHA256,
                 base: Path | None = None) -> Path:
    """Copy the verified cache into <run_dir>/skill and verify the COPY."""
    files, data_of = _verified(cache, manifest_sha)
    run_dir = Path(run_dir)
    if not run_dir.exists():
        run_dir = hunt_io.make_dir(run_dir.parent, run_dir.name, base=base)
    dest = hunt_io.make_dir(run_dir, "skill", base=base)
    for rel in sorted(files):
        data = data_of[rel]  # the bytes that were hashed, not a second read
        parent = hunt_io.make_tree(dest, rel.rpartition("/")[0], base=base)
        hunt_io.create_file(parent, rel.rpartition("/")[2], data, base=base)
    hunt_io.create_file(dest, MANIFEST_NAME, manifest_bytes(files), base=base)
    verify_tree(dest, manifest_sha)
    return dest


def read_verified(skill_dir: Path, rel: str, manifest_sha: str = MANIFEST_SHA256) -> bytes:
    """Bytes of one file of the run copy -- the whole copy is re-verified first, and the
    returned bytes are the hashed bytes (inspection round 1, finding 8: verification used
    to be separate from the later reads)."""
    files, data = _verified(skill_dir, manifest_sha)
    if rel not in files:
        raise VendorError(f"{rel!r} is not part of the pinned skill")
    return data[rel]  # exactly the bytes the manifest check hashed


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    try:
        if args == ["--print-pin"]:
            # Below the cache root, never the OS temp directory (finding 22).
            holder = hunt_io.ensure_dirs(DEFAULT_CACHE)
            with __import__("tempfile").TemporaryDirectory(prefix="pin-", dir=holder) as tmp:
                bare = Path(tmp) / "repo.git"
                _git("clone", "--bare", "--quiet", REPO_URL, str(bare))
                files = {p: hashlib.sha256(_git("cat-file", "blob", s, cwd=bare, binary=True)).hexdigest()
                         for p, s in _tree(bare, PINNED_COMMIT)}
                print(hashlib.sha256(manifest_bytes(files)).hexdigest())
                return 0
        path = vendor()
        print(path)
        return 0
    except (VendorError, hunt_io.HuntIOError) as exc:
        sys.stderr.write(f"vendor_skill: REFUSED - {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
