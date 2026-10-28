#!/usr/bin/env python3
"""Write targets of the security hunt: no redirected component, nothing overwritten.

Plan A, stage 1, item 8 (docs/plans/2026-10-27-sicherheitskette, approved round 7).
Every directory and file the hunt writes -- run directory, snapshot, report, ledger,
coverage manifests, vendor cache -- is created through this module.

TRUST BASE. Every call names the trusted root it writes below (`base`): the repository,
the session scratch directory, ~/.claudex. Links ABOVE that root belong to the user's
system (on macOS /var and /tmp are symlinks) and are taken as they are; every component
BELOW it must be a plain directory -- a symlink or a reparse point (Windows junction)
refuses the write. Without `base` the whole chain up to the filesystem root is checked.

- directories are created exclusively, files with O_CREAT | O_EXCL -- an existing name is
  never reused or overwritten;
- on POSIX the base is opened once and every component below it is opened relative to the
  handle of the one before, with O_NOFOLLOW, and the leaf is created relative to the last
  handle (dir_fd) -- swapping ANY component after the check cannot redirect the write
  (inspection round 1, finding 2);
- missing parents are created through the same checked API (ensure_dirs), never with
  mkdir(parents=True) (finding 3).

RESIDUAL (R5-1, accepted in review round 6): Windows has no dir_fd in Python. There a
second writer able to replace an already checked component DURING the operation can still
redirect it -- the same residual codex_ro.py (open_for_write) and wrapper_drift.py
document. On Windows the guarantee holds against redirects that exist before the check.
Reconsider before supporting directories that untrusted users can write.

Messages are ASCII only.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_BAD_NAMES = {"", ".", ".."}


class HuntIOError(Exception):
    pass


def _is_redirect(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def _levels(p: Path, base: Path | None) -> list[Path]:
    """`p` and its ancestors down to (excluding) `base`; all of them without a base."""
    if base is None:
        return [p, *p.parents]
    b = Path(os.path.abspath(base))
    try:
        rel = p.relative_to(b)
    except ValueError as exc:
        raise HuntIOError(f"refusing: {p} is not below the trusted base {b}") from exc
    out, cur = [], p
    for _ in rel.parts:
        out.append(cur)
        cur = cur.parent
    return out


def _check_base(base: Path | None) -> None:
    """The base ITSELF must be a plain directory (inspection round 2, finding 23); only
    what lies ABOVE it is taken as the user's system."""
    if base is None:
        return
    b = Path(os.path.abspath(base))
    try:
        st = os.lstat(b)
    except OSError as exc:
        raise HuntIOError(f"refusing: trusted base {b} is not accessible: {exc}") from exc
    if _is_redirect(st) or not stat.S_ISDIR(st.st_mode):
        raise HuntIOError(f"refusing: trusted base {b} is a link, a reparse point or no directory")


def check_chain(directory: Path, base: Path | None = None) -> Path:
    """Refuse if `directory`, a component below `base`, or `base` itself is a link or
    reparse point."""
    _check_base(base)
    p = Path(os.path.abspath(directory))
    for level in _levels(p, base):
        try:
            st = os.lstat(level)
        except FileNotFoundError:
            continue
        if _is_redirect(st):
            raise HuntIOError(f"refusing: {level} is a link or reparse point")
        if level == p and not stat.S_ISDIR(st.st_mode):
            raise HuntIOError(f"refusing: {level} is not a directory")
    if not p.is_dir():
        raise HuntIOError(f"refusing: {p} does not exist")
    return p


def _leaf(name: str) -> str:
    if (name in _BAD_NAMES or "/" in name or "\\" in name or ":" in name
            or name != name.strip() or "\x00" in name):
        raise HuntIOError(f"refusing: {name!r} is not a plain file name")
    return name


def _open_dir_anchor(parent: Path, base: Path | None) -> int | None:
    """POSIX: a handle on `parent`, every component below `base` opened relative to the
    previous handle with O_NOFOLLOW. None on Windows (see RESIDUAL)."""
    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return None
    p = Path(os.path.abspath(parent))
    start = Path(os.path.abspath(base)) if base is not None else Path(p.anchor or "/")
    try:
        rel_parts = p.relative_to(start).parts
    except ValueError as exc:
        raise HuntIOError(f"refusing: {p} is not below the trusted base {start}") from exc
    try:
        # NOFOLLOW on the base too (finding 23): only the components ABOVE it may be aliases.
        fd = os.open(start, os.O_RDONLY | os.O_DIRECTORY | (os.O_NOFOLLOW if base is not None else 0))
    except OSError as exc:
        raise HuntIOError(f"refusing: cannot open the trusted base {start}: {exc}") from exc
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        for part in rel_parts:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except OSError as exc:
        os.close(fd)
        raise HuntIOError(f"refusing: {p} is not reachable without following a link: {exc}") from exc
    return fd


def make_dir(parent: Path, name: str, base: Path | None = None, _after_check=None) -> Path:
    """Create parent/name exclusively; the chain below `base` must be free of redirects."""
    parent = check_chain(parent, base)
    leaf = _leaf(name)
    if _after_check:
        _after_check()
    dfd = _open_dir_anchor(parent, base)
    try:
        if dfd is not None:
            os.mkdir(leaf, 0o700, dir_fd=dfd)
            st = os.stat(leaf, dir_fd=dfd, follow_symlinks=False)
        else:
            os.mkdir(parent / leaf, 0o700)
            st = os.lstat(parent / leaf)
    except FileExistsError as exc:
        raise HuntIOError(f"refusing: {parent / leaf} already exists") from exc
    except OSError as exc:
        raise HuntIOError(f"refusing: cannot create {parent / leaf}: {exc}") from exc
    finally:
        if dfd is not None:
            os.close(dfd)
    if _is_redirect(st) or not stat.S_ISDIR(st.st_mode):
        raise HuntIOError(f"refusing: {parent / leaf} is not a plain directory after creation")
    return parent / leaf


def ensure_dirs(path: Path, base: Path | None = None) -> Path:
    """Create `path` and its missing parents through the checked API (finding 3).

    The deepest EXISTING ancestor is checked first; every missing component is then
    created exclusively below it. Nothing is created before that check passed.
    """
    p = Path(os.path.abspath(path))
    missing, current = [], p
    while not os.path.lexists(current):
        missing.append(current.name)
        current = current.parent
    check_chain(current, base if base is not None and current != Path(os.path.abspath(base)) else base)
    for name in reversed(missing):
        current = make_dir(current, name, base)
    return check_chain(p, base)


def make_tree(root: Path, rel: str, base: Path | None = None) -> Path:
    """Create the directories of the relative POSIX path `rel` below `root`."""
    current = check_chain(root, base)
    for part in [p for p in rel.split("/") if p]:
        nxt = current / _leaf(part)
        try:
            st = os.lstat(nxt)
        except FileNotFoundError:
            current = make_dir(current, part, base)
            continue
        if _is_redirect(st) or not stat.S_ISDIR(st.st_mode):
            raise HuntIOError(f"refusing: {nxt} is not a plain directory")
        current = nxt
    return current


def _open_exclusive(parent: Path, name: str, base: Path | None, _after_check=None) -> int:
    parent = check_chain(parent, base)
    leaf = _leaf(name)
    if _after_check:
        _after_check()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    dfd = _open_dir_anchor(parent, base)
    try:
        fd = os.open(leaf, flags, 0o600, dir_fd=dfd) if dfd is not None else \
            os.open(parent / leaf, flags, 0o600)
    except FileExistsError as exc:
        raise HuntIOError(f"refusing: {parent / leaf} already exists") from exc
    except OSError as exc:
        raise HuntIOError(f"refusing: cannot create {parent / leaf}: {exc}") from exc
    finally:
        if dfd is not None:
            os.close(dfd)
    # The handle must be a regular file, and the same object the path names now.
    try:
        st_fd, st_path = os.fstat(fd), os.lstat(parent / leaf)
        same = (st_fd.st_ino, st_fd.st_dev) == (st_path.st_ino, st_path.st_dev)
        if not stat.S_ISREG(st_fd.st_mode) or _is_redirect(st_path) or not same:
            raise HuntIOError(f"refusing: {parent / leaf} changed during creation")
    except OSError as exc:
        os.close(fd)
        raise HuntIOError(f"refusing: cannot verify {parent / leaf}: {exc}") from exc
    except HuntIOError:
        os.close(fd)
        raise
    return fd


MAX_READ = 5 * 1024 * 1024


def _read_fd(fd: int, st_expected: os.stat_result, limit: int):
    """Shared tail of the readers: identity, type, bounded read on an OPEN handle."""
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (fst.st_ino, fst.st_dev) != (st_expected.st_ino, st_expected.st_dev):
        return ("refused", "changed")
    if getattr(fst, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        return ("refused", "link")
    chunks, total = [], 0
    while True:
        block = os.read(fd, min(65536, limit + 1 - total))  # never past limit + 1
        if not block:
            break
        chunks.append(block)
        total += len(block)
        if total > limit:
            return ("refused", "size")
    return ("ok", b"".join(chunks))


_READ_FLAGS = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
               | getattr(os, "O_NONBLOCK", 0))


def read_regular(path: Path, limit: int = MAX_READ, _after_lstat=None):
    """("ok", bytes) or ("refused", reason) for ONE path. Never follows the leaf, never
    blocks on a FIFO (O_NONBLOCK, then the handle must be a regular file)."""
    try:
        st = os.lstat(path)
    except OSError:
        return ("refused", "missing")
    if _is_redirect(st):
        return ("refused", "link")
    if not stat.S_ISREG(st.st_mode):
        return ("refused", "special")
    if st.st_size > limit:
        return ("refused", "size")
    if _after_lstat:
        _after_lstat()
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError:
        return ("refused", "changed")
    try:
        return _read_fd(fd, st, limit)
    finally:
        os.close(fd)


def read_at(root: Path, rel: str, limit: int = MAX_READ, _after_check=None):
    """Read root/rel without following ANY link below root (inspection round 2,
    finding 30): on POSIX the parent is reached through anchored directory handles and
    the leaf is stat-ed and opened relative to it. Windows: path-based (R5-1 residual)."""
    parts = [p for p in rel.split("/") if p]
    if not parts or any(p in _BAD_NAMES for p in parts):
        return ("refused", "path")
    parent = Path(root).joinpath(*parts[:-1])
    try:
        check_chain(parent, base=root)
    except HuntIOError:
        return ("refused", "link")
    if _after_check:
        _after_check()
    try:
        dfd = _open_dir_anchor(parent, base=root)
    except HuntIOError:
        return ("refused", "link")
    if dfd is None:
        return read_regular(parent / parts[-1], limit)
    try:
        try:
            st = os.stat(parts[-1], dir_fd=dfd, follow_symlinks=False)
        except OSError:
            return ("refused", "missing")
        if _is_redirect(st):
            return ("refused", "link")
        if not stat.S_ISREG(st.st_mode):
            return ("refused", "special")
        if st.st_size > limit:
            return ("refused", "size")
        try:
            fd = os.open(parts[-1], _READ_FLAGS, dir_fd=dfd)
        except OSError:
            return ("refused", "changed")
        try:
            return _read_fd(fd, st, limit)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def walk_files(root: Path) -> list[str]:
    """Relative POSIX paths of every file below `root`, sorted.

    `root` itself and every entry below it must be a plain directory or a regular file:
    a link, a reparse point, a FIFO or a device anywhere refuses (closing gate A1-2/A2-2;
    rglob + is_file() followed links and silently skipped FIFOs). A directory that cannot
    be listed refuses too -- os.walk() skips it silently by default (gate recheck A1-3)."""
    root = Path(os.path.abspath(root))
    _check_base(root)
    out = []

    def fail(exc: OSError):
        raise HuntIOError(f"refusing: cannot list {exc.filename}: {exc.strerror}") from exc
    for dirpath, dirnames, filenames in os.walk(root, onerror=fail, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            st = os.lstat(p)
            if _is_redirect(st):
                raise HuntIOError(f"refusing: {p} is a link or reparse point")
            if name in filenames and not stat.S_ISREG(st.st_mode):
                raise HuntIOError(f"refusing: {p} is not a regular file")
            if name in dirnames and not stat.S_ISDIR(st.st_mode):
                raise HuntIOError(f"refusing: {p} is not a plain directory")
        out.extend((Path(dirpath) / n).relative_to(root).as_posix() for n in filenames)
    return sorted(out)


def replace_file(root: Path, rel: str, data: bytes, _after_check=None) -> None:
    """Replace the regular file root/rel with `data` without following any link below
    `root`: a new file is created exclusively next to it and renamed over it. POSIX: ONE
    anchored parent handle (dir_fd) carries the creation, the rename and the clean-up, so
    a swapped ancestor can neither redirect the write nor make the clean-up unlink a file
    elsewhere (gate recheck A1-2). The rename replaces the directory ENTRY and never writes
    through a planted link. Windows: path-based (R5-1)."""
    parts = [p for p in rel.split("/") if p]
    if not parts or any(p in _BAD_NAMES for p in parts):
        raise HuntIOError(f"refusing: {rel!r} is not a plain relative path")
    root = Path(os.path.abspath(root))
    parent = root.joinpath(*parts[:-1])
    leaf = _leaf(parts[-1])
    tmp = _leaf(f".{leaf}.claudex-new")
    status, _ = read_at(root, rel, _after_check=_after_check)  # target: regular, no link
    if status != "ok":
        raise HuntIOError(f"refusing: {root / rel} is not a readable regular file")
    dfd = _open_dir_anchor(parent, base=root)
    if dfd is None:  # Windows: path-based, R5-1
        fd = _open_exclusive(parent, tmp, base=root)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            check_chain(parent, base=root)
            os.replace(parent / tmp, parent / leaf)
        except BaseException:
            try:
                os.unlink(parent / tmp)
            except OSError:
                pass
            raise
        return
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(tmp, flags, 0o600, dir_fd=dfd)
        except OSError as exc:
            raise HuntIOError(f"refusing: cannot create {parent / tmp}: {exc}") from exc
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, leaf, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)  # the SAME handle: never another directory
            except OSError:
                pass
            raise
    finally:
        os.close(dfd)


def rename_entry(parent: Path, src: str, dst: str, base: Path | None = None) -> None:
    """Rename parent/src to parent/dst. POSIX: through the anchored parent handle, so a
    swapped ancestor cannot move the entry elsewhere (closing gate B-4). Windows:
    path-based after the chain check (R5-1).

    An EXISTING dst refuses. RESIDUAL: the check and the rename are two calls (Python has
    no renameat2(RENAME_NOREPLACE)); a dst created between them in the same directory --
    which needs write access to that private directory, and for the vendor cache also
    bypassing its install lock -- can still be replaced. The caller re-verifies what it
    published."""
    parent = check_chain(parent, base)
    src, dst = _leaf(src), _leaf(dst)
    dfd = _open_dir_anchor(parent, base)
    try:
        if dfd is not None:
            try:
                os.stat(dst, dir_fd=dfd, follow_symlinks=False)
                raise HuntIOError(f"refusing: {parent / dst} already exists")
            except FileNotFoundError:
                pass
            os.rename(src, dst, src_dir_fd=dfd, dst_dir_fd=dfd)
        else:
            if os.path.lexists(parent / dst):
                raise HuntIOError(f"refusing: {parent / dst} already exists")
            os.rename(parent / src, parent / dst)
    except OSError as exc:
        raise HuntIOError(f"refusing: cannot rename {parent / src}: {exc}") from exc
    finally:
        if dfd is not None:
            os.close(dfd)


def remove_file(parent: Path, name: str, base: Path | None = None) -> None:
    """Unlink the regular file parent/name through the anchored parent handle (POSIX);
    a link or a missing file refuses. Windows: path-based (R5-1)."""
    parent = check_chain(parent, base)
    leaf = _leaf(name)
    dfd = _open_dir_anchor(parent, base)
    try:
        st = os.stat(leaf, dir_fd=dfd, follow_symlinks=False) if dfd is not None \
            else os.lstat(parent / leaf)
        if _is_redirect(st) or not stat.S_ISREG(st.st_mode):
            raise HuntIOError(f"refusing: {parent / leaf} is not a plain file")
        if dfd is not None:
            os.unlink(leaf, dir_fd=dfd)
        else:
            os.unlink(parent / leaf)
    except OSError as exc:
        raise HuntIOError(f"refusing: cannot remove {parent / leaf}: {exc}") from exc
    finally:
        if dfd is not None:
            os.close(dfd)


def open_new(parent: Path, name: str, base: Path | None = None):
    """A NEW file parent/name, opened for binary writing through the checked API."""
    return os.fdopen(_open_exclusive(Path(parent), name, base), "wb")


def create_file(parent: Path, name: str, data: bytes, base: Path | None = None,
                _after_check=None) -> Path:
    """Write `data` to a NEW file parent/name; never overwrites."""
    fd = _open_exclusive(Path(parent), name, base, _after_check)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return Path(parent) / name


class Ledger:
    """An append-only JSON-lines file, created exclusively, appended immediately.

    `guard` (optional) receives each serialized line before it is written and returns the
    line to write -- the hunt passes its redaction there, so nothing reaches the file
    unscanned. A guard that raises means nothing is written.
    """

    def __init__(self, parent: Path, name: str, base: Path | None = None, guard=None,
                 _fd: int | None = None):
        self.path = Path(parent) / name
        self.guard = guard
        self._fh = os.fdopen(_fd if _fd is not None else _open_exclusive(Path(parent), name, base), "ab")

    @classmethod
    def reopen(cls, parent: Path, name: str, base: Path | None = None, guard=None,
               _after_check=None) -> "Ledger":
        """Open an EXISTING ledger for appending only -- never truncating, never following.

        POSIX: stat and open go through the anchored parent handle (dir_fd), so swapping an
        ancestor after the check cannot redirect the append (closing gate A1-1). The handle
        must be a regular file and the object that was stat-ed; O_NONBLOCK keeps a planted
        FIFO from blocking. Windows: path-based (R5-1)."""
        parent = check_chain(parent, base)
        leaf = _leaf(name)
        if _after_check:
            _after_check()
        flags = (os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        dfd = _open_dir_anchor(parent, base)
        try:
            if dfd is not None:
                st_path = os.stat(leaf, dir_fd=dfd, follow_symlinks=False)
            else:
                st_path = os.lstat(parent / leaf)
            if _is_redirect(st_path) or not stat.S_ISREG(st_path.st_mode):
                raise HuntIOError(f"refusing: {parent / leaf} is not a plain file")
            fd = os.open(leaf, flags, dir_fd=dfd) if dfd is not None else os.open(parent / leaf, flags)
        except OSError as exc:
            raise HuntIOError(f"refusing: cannot reopen {parent / leaf}: {exc}") from exc
        finally:
            if dfd is not None:
                os.close(dfd)
        st_fd = os.fstat(fd)
        if not stat.S_ISREG(st_fd.st_mode) or \
                (st_fd.st_ino, st_fd.st_dev) != (st_path.st_ino, st_path.st_dev):
            os.close(fd)
            raise HuntIOError(f"refusing: {parent / leaf} changed while reopening")
        return cls(parent, leaf, guard=guard, _fd=fd)

    def append(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        if self.guard is not None:
            line = self.guard(line)
        self._fh.write((line + "\n").encode("utf-8"))
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
