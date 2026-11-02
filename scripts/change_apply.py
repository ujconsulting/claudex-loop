#!/usr/bin/env python3
"""Review a sandboxed build's change set from quarantine, then publish it (plan B2, approach 8).

docs/plans/2026-10-27-sicherheitskette/PLAN-B2-build.md, unit U5. Two subcommands:

  show   --run-dir R --manifest-sha256 H --repo <checkout> (--summary | --file <n>) [--page <k>]
  apply  --run-dir R --manifest-sha256 H --target <checkout> [--accept-binary P]... [--accept-large P]...

RUN DIRECTORY (written by sandbox_build.py, U7; the change set itself by the driver, U3):

  manifest.json  its sha256 is MANIFEST_SHA256. Keys read here: "tree" (input tree id),
                 "source" (worktree_identity() of the checkout the run was made from),
                 "build_status", "changes_sha256" / "excluded_sha256" (sha256 of the two files
                 below, which binds them to the manifest).
  changes.json   a JSON list, sorted by path, of {"op", "path", "mode", "base_mode", "sha256",
                 "size", "binary", "base_sha256"}; op is added | modified | deleted | mode; modes
                 100644 / 100755.
  change/<i>     the new bytes of entry i (0-based index into changes.json); added and modified
                 entries only. `show --file <i>` uses the same index.
  excluded.json  {"excluded": [{"path", "reason" (git | generated | empty_dir), "entries"}],
                 "withheld": [paths]} -- listed only, never published, so these paths may be
                 non-ASCII (shown escaped).

SHOW runs in a separate worker (`sys.executable -I -S change_apply.py --show-worker ...`) under a
60 s deadline and, on POSIX, RLIMIT_AS 512 MiB; it refuses unless the manifest digest matches and
every blob re-hashes. Every page is at most 400 lines and 32 KiB and starts with `PAGE k/N`; a line
longer than 4 KiB is split into `[line L bytes a-b]` fragments (a..b is the half-open byte range of
the displayed line). Control, format and separator characters are shown as `\\u{XXXX}`, so an
escape sequence or a bidi override cannot hide text. Base bytes come from the input tree through
sandbox_snapshot's hardened `cat-file --batch` (every object id re-computed).

APPLY: a preflight that writes nothing refuses the whole set on any failure; then publication,
which is NOT all-or-nothing: on the first failure it stops and reports exactly PUBLISHED= and
NOT_PUBLISHED= with recovery commands from the input tree. Single-writer assumption: a concurrent
edit is detected best-effort by the re-check immediately before each rename, not prevented.
Permissions: a replaced file keeps its rwx bits and only the executable bits follow the result
mode (x where r, as git does; setuid/setgid/sticky are dropped); an addition gets 0666/0777 &
~umask; created directories 0777 & ~umask. Windows has no executable bit: MODE_TODO= lines carry
the exact `git --literal-pathspecs update-index --chmod=...` command to run after staging.

Every git command printed here uses `git --literal-pathspecs ... -- '<path>'`, each path
single-quoted for POSIX shells. Exit codes: 0 ok (or nothing to publish), 2 refused or conflict,
5 infrastructure. Messages are ASCII; shown file content is written as UTF-8 bytes.
"""
from __future__ import annotations

import argparse
import difflib
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402
import sandbox_snapshot as ss  # noqa: E402

PLUGIN_ROOT = Path(__file__).resolve().parents[1]

SHOW_DEADLINE = 60
SHOW_RLIMIT_AS = 512 * 1024 * 1024
PAGE_LINES = 400
PAGE_BYTES = 32 * 1024
HEADER_RESERVE = 64           # room for "PAGE k/N\n" inside PAGE_BYTES
LINE_FRAGMENT = 4096
SUMMARY_ENTRIES = 200
FULL_SHOW_LIMIT = 1024 * 1024  # per side
HEAD_TAIL_LINES = 200
HEAD_TAIL_BYTES = 64 * 1024
MAX_ENTRIES = 20000           # policy change_caps
MAX_ADDED = 2000
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 200 * 1024 * 1024  # build.change_caps.total_bytes; contract-tested against policy
MAX_JSON = 64 * 1024 * 1024
MAX_BASE_BLOB = 64 * 1024 * 1024
GITFILE_MAX = 4096

OPS = ("added", "modified", "deleted", "mode")
MODES = ("100644", "100755")
ENTRY_KEYS = {"op", "path", "mode", "base_mode", "sha256", "size", "binary", "base_sha256"}
WITHHELD_ROOT = ".codex"      # policy withheld_paths: `.codex/**` at the repository root
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TREE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_WIN_RESERVED = re.compile(r"(con|prn|aux|nul|com[0-9]|lpt[0-9]) *(\..*)?", re.IGNORECASE)
_SHORT_NAME = re.compile(r"~[0-9]")
_REASON = re.compile(r"[a-z0-9_]{1,64}")
_WIN_BAD = set('<>"|?*')
_CASE_INSENSITIVE_FS = os.name == "nt" or sys.platform == "darwin"

# Test hooks: called with the entry after its temp file is written and before its re-check.
_HOOK_BEFORE_RECHECK = None


class ApplyRefused(Exception):
    """The change set, the target or the arguments are refused (exit 2)."""


class ApplyInfrastructure(Exception):
    """An operational failure, e.g. git could not run (exit 5)."""


class _Conflict(Exception):
    """A target changed under publication (exit 2 after the report)."""


def _ascii(text) -> str:
    return str(text).encode("ascii", "backslashreplace").decode("ascii").replace("\n", " ").replace("\r", " ")


def _refuse(msg: str):
    raise ApplyRefused(_ascii(msg))


def sha256(data: bytes) -> str:
    """Return the lowercase SHA-256 digest used to bind manifests and blobs."""
    return hashlib.sha256(data).hexdigest()


# --- quoting and printed commands -----------------------------------------------------

def quote_posix(path: str) -> str:
    """`path` single-quoted for POSIX shells: ' becomes '\\''."""
    return "'" + str(path).replace("'", "'\\''") + "'"


def git_literal(args: list, paths: list) -> list:
    """The argument array of a git command on literal paths."""
    return ["git", "--literal-pathspecs", *args, "--", *paths]


def _render(args: list, paths: list) -> str:
    """git_literal() as one printable line; fixed args are plain tokens, every path is quoted."""
    argv = git_literal(args, paths)
    return " ".join(argv[: len(argv) - len(paths)] + [quote_posix(p) for p in paths])


def recovery_commands(report: dict, input_tree: str) -> list:
    """Commands that undo what `report` says was published, from the exact input tree."""
    out = []
    for item in report.get("published", []):
        if item["op"] == "added":
            out.append("rm -- " + quote_posix(item["path"]))
        else:
            out.append(_render(["restore", f"--source={input_tree}", "--worktree"], [item["path"]]))
    dirs = sorted(report.get("created_dirs", []), key=lambda d: (-d.count("/"), d))  # deepest first
    out.extend("rmdir -- " + quote_posix(d) for d in dirs)
    return out


def mode_todo(entries: list, index_modes: dict) -> list:
    """Windows: one `update-index --chmod` line per entry whose result mode differs from what
    `git add` will record (the index mode of a tracked path, 100644 for a new one)."""
    out = []
    for e in entries:
        if e["op"] == "deleted":
            continue
        after_add = index_modes.get(e["path"], "100644")
        if e["mode"] != after_add:
            flag = "+x" if e["mode"] == "100755" else "-x"
            out.append(_render(["update-index", f"--chmod={flag}"], [e["path"]]))
    return out


# --- permissions ----------------------------------------------------------------------

def result_permissions(existing: int | None, git_mode: str, umask: int) -> int:
    """Final permission bits of a published file.

    existing None (an addition): 0666 or 0777 & ~umask. Otherwise the existing rwx bits are
    kept (setuid/setgid/sticky dropped) and only the executable bits follow `git_mode`: for
    100755 each x is set where the matching r is set, for 100644 every x is cleared."""
    if git_mode not in MODES:
        _refuse(f"mode {git_mode!r} is not 100644 or 100755")
    if existing is None:
        return (0o777 if git_mode == "100755" else 0o666) & ~umask & 0o777
    bits = existing & 0o777
    if git_mode == "100644":
        return bits & ~0o111
    for r, x in ((0o400, 0o100), (0o040, 0o010), (0o004, 0o001)):
        if bits & r:
            bits |= x
    return bits


def _current_umask() -> int:
    old = os.umask(0)
    os.umask(old)
    return old


# --- worktree identity ----------------------------------------------------------------

def _norm(p: str) -> str:
    return os.path.normcase(os.path.realpath(p))


def _one_line_file(path: str, what: str) -> str:
    status, data = hunt_io.read_regular(Path(path), GITFILE_MAX)
    if status != "ok":
        _refuse(f"{what} {path} is not a regular file of at most {GITFILE_MAX} bytes ({data})")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _refuse(f"{what} {path} is not UTF-8")
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text or "\r" in text or "\0" in text:
        _refuse(f"{what} {path} is not exactly one line")
    return text


def worktree_identity(path) -> dict:
    """Realpaths of the worktree, its git directory and its common git directory, found by
    reading files only: a `.git` directory, or a gitfile (regular file <= 4 KiB, one line
    `gitdir: <path>` to an existing directory); a `commondir` file is resolved too."""
    wt = os.path.realpath(str(path))
    if not os.path.isdir(wt):
        _refuse(f"{wt} is not a directory")
    dotgit = os.path.join(wt, ".git")
    try:
        st = os.lstat(dotgit)
    except OSError:
        _refuse(f"{wt} has no .git")
    if hunt_io._is_redirect(st):
        _refuse(f"{dotgit} is a link or reparse point")
    if stat.S_ISDIR(st.st_mode):
        git_dir = os.path.realpath(dotgit)
    elif stat.S_ISREG(st.st_mode):
        line = _one_line_file(dotgit, "gitfile")
        if not line.startswith("gitdir: ") or not line[len("gitdir: "):].strip():
            _refuse(f"gitfile {dotgit} does not hold `gitdir: <path>`")
        target = line[len("gitdir: "):]
        target = target if os.path.isabs(target) else os.path.join(wt, target)
        if not os.path.isdir(target):
            _refuse(f"gitfile {dotgit} points to a missing directory")
        git_dir = os.path.realpath(target)
    else:
        _refuse(f"{dotgit} is neither a directory nor a regular file")
    if not os.path.isfile(os.path.join(git_dir, "HEAD")):
        _refuse(f"{git_dir} is not a git directory (no HEAD)")
    common = git_dir
    cfile = os.path.join(git_dir, "commondir")
    if os.path.lexists(cfile):
        rel = _one_line_file(cfile, "commondir")
        cand = rel if os.path.isabs(rel) else os.path.join(git_dir, rel)
        if not os.path.isdir(cand):
            _refuse(f"commondir of {git_dir} points to a missing directory")
        common = os.path.realpath(cand)
    return {"worktree": wt, "git_dir": git_dir, "common_dir": common}


def _same_identity(a: dict, b: dict) -> bool:
    try:
        return all(_norm(a[k]) == _norm(b[k]) for k in ("worktree", "git_dir", "common_dir"))
    except (KeyError, TypeError):
        return False


def _inside(child: str, parent: str) -> bool:
    c, p = _norm(child), _norm(parent)
    try:
        return os.path.commonpath([c, p]) == p
    except ValueError:  # different drives
        return False


def _check_plugin_containment(target: str) -> None:
    plugin = str(PLUGIN_ROOT)
    if _inside(plugin, target):
        _refuse(f"the installed plugin directory {plugin} is inside the target {target}")
    if _inside(target, plugin):
        _refuse(f"the target {target} is inside the installed plugin directory {plugin}")


# --- paths ----------------------------------------------------------------------------

def canonical_entry_path(path, is_nt: bool) -> str:
    """Validate a change-set path (POSIX, relative). Refused: non-printable-ASCII, backslash,
    colon, empty/./.. components, any `.git` component in any case, `~<digit>` (8.3 short
    names), Windows reserved names, a trailing dot or space, the withheld `.codex` root; on
    Windows also the characters <>"|?*."""
    if not isinstance(path, str) or not path:
        _refuse("an entry path is empty or not a string")
    if any(not 0x20 <= ord(c) < 0x7F for c in path) or "\\" in path or ":" in path:
        _refuse(f"path {path!r} has a non-printable or non-ASCII character, a backslash or a colon")
    parts = path.split("/")
    for p in parts:
        if p in ("", ".", ".."):
            _refuse(f"path {path!r} has an empty, '.' or '..' component, or is absolute")
        if p.casefold() == ".git":
            _refuse(f"path {path!r} has a .git component")
        if _SHORT_NAME.search(p):
            _refuse(f"path {path!r} has a ~<digit> component (8.3 short name)")
        if _WIN_RESERVED.fullmatch(p):
            _refuse(f"path {path!r} has a Windows reserved name")
        if p[-1] in ". ":
            _refuse(f"path {path!r} has a component ending in a dot or a space")
        if is_nt and _WIN_BAD.intersection(p):
            _refuse(f"path {path!r} has a character Windows cannot store")
    if parts[0].casefold() == WITHHELD_ROOT:
        _refuse(f"path {path!r} is at or beneath the withheld {WITHHELD_ROOT}/")
    return path


def _check_namespace(paths: list) -> None:
    """No two paths equal case-insensitively, none an ancestor of another."""
    keys = {}
    directories = {}
    for p in paths:
        k = p.casefold()
        if k in keys:
            _refuse(f"paths {keys[k]!r} and {p!r} collide case-insensitively")
        keys[k] = p
        for i in range(1, len(p.split("/"))):
            parent = "/".join(p.split("/")[:i])
            folded = parent.casefold()
            previous = directories.get(folded)
            if previous is not None and previous != parent:
                _refuse(f"directories {previous!r} and {parent!r} collide case-insensitively")
            directories[folded] = parent
    for k, p in keys.items():
        parts = k.split("/")
        for i in range(1, len(parts)):
            anc = "/".join(parts[:i])
            if anc in keys:
                _refuse(f"path {keys[anc]!r} is an ancestor of {p!r}")


def _listed_path(text, what: str) -> str:
    """An excluded or withheld path is only listed, never published, so the driver may report
    a non-ASCII or backslash name there (U3); shown escaped by _display()."""
    if not isinstance(text, str) or not text or len(text) > 4096 or "\0" in text:
        _refuse(f"{what} is not a non-empty string of at most 4096 characters without NUL")
    return text


# --- content classification -----------------------------------------------------------

def is_binary(data: bytes | None) -> bool:
    """Classify bytes as binary when they contain NUL or are not valid UTF-8."""
    if not data:
        return False
    if b"\0" in data[:8192]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def classify(entry: dict, base_len: int, base_binary: bool) -> str:
    """"mode-only" | "binary" | "full" | "partial" -- what show can present for an entry, and
    so what apply demands: binary needs --accept-binary, partial (a side over 1 MiB) needs
    --accept-large. The entry's own binary flag already covers its new bytes (load_change_set
    refuses a binary blob flagged as text); `base_*` describe the base bytes."""
    if entry["op"] == "mode":
        return "mode-only"
    if entry["binary"] or base_binary:
        return "binary"
    new_len = entry["size"] if entry["op"] in ("added", "modified") else 0
    if base_len <= FULL_SHOW_LIMIT and new_len <= FULL_SHOW_LIMIT:
        return "full"
    return "partial"


# --- loading the change set -----------------------------------------------------------

def _read_run_file(run_dir: Path, rel: str, limit: int) -> bytes:
    status, data = hunt_io.read_at(run_dir, rel, limit)
    if status != "ok":
        _refuse(f"run directory: {rel} is not readable as a plain file ({data})")
    return data


def _json(data: bytes, what: str):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _refuse(f"{what} is not valid JSON")


def _validate_entry(i: int, e) -> dict:
    if not isinstance(e, dict) or set(e) != ENTRY_KEYS:
        _refuse(f"changes.json entry {i} does not have exactly the keys {sorted(ENTRY_KEYS)}")
    op = e["op"]
    if op not in OPS:
        _refuse(f"changes.json entry {i}: unknown op {op!r}")
    canonical_entry_path(e["path"], is_nt=False)
    # Deleted entries have no new content to classify (U3 emits null).
    # Existing boolean producers remain compatible; null is allowed only here.
    if not isinstance(e["binary"], bool) and not (op == "deleted" and e["binary"] is None):
        _refuse(f"changes.json entry {i}: binary is not a boolean")

    def hexv(k):
        return isinstance(e[k], str) and _HEX64.fullmatch(e[k]) is not None

    def size_ok():
        return isinstance(e["size"], int) and not isinstance(e["size"], bool) and 0 <= e["size"] <= MAX_FILE
    ok = {
        "added": e["mode"] in MODES and e["base_mode"] is None and e["base_sha256"] is None
        and hexv("sha256") and size_ok(),
        "modified": e["mode"] in MODES and e["base_mode"] in MODES and hexv("sha256") and hexv("base_sha256")
        and size_ok() and not (e["sha256"] == e["base_sha256"] and e["mode"] == e["base_mode"]),
        "deleted": e["mode"] is None and e["base_mode"] in MODES and e["sha256"] is None and e["size"] is None
        and hexv("base_sha256"),
        "mode": e["mode"] in MODES and e["base_mode"] in MODES and e["mode"] != e["base_mode"]
        and hexv("sha256") and e["sha256"] == e["base_sha256"] and size_ok(),
    }[op]
    if not ok:
        _refuse(f"changes.json entry {i} ({op} {e['path']!r}) has inconsistent fields")
    return e


class ChangeSet:
    """Validated quarantine metadata and optionally retained blobs, bound to an input tree."""
    def __init__(self, run_dir: Path, manifest: dict, entries: list, excluded: list, withheld: list,
                 blobs: dict):
        self.run_dir, self.manifest, self.entries = run_dir, manifest, entries
        self.excluded, self.withheld, self.blobs = excluded, withheld, blobs
        self.tree = manifest["tree"]


def load_change_set(run_dir, manifest_sha256: str, keep=None) -> ChangeSet:
    """Read and verify everything in the run directory; `keep` = indices whose blob bytes are
    kept (None: all). Every blob is re-hashed whether kept or not."""
    if not isinstance(manifest_sha256, str) or not _HEX64.fullmatch(manifest_sha256):
        _refuse("--manifest-sha256 is not 64 lowercase hex characters")
    run_dir = Path(os.path.abspath(str(run_dir)))
    raw = _read_run_file(run_dir, "manifest.json", MAX_JSON)
    if sha256(raw) != manifest_sha256:
        _refuse("manifest.json does not hash to --manifest-sha256")
    manifest = _json(raw, "manifest.json")
    if not isinstance(manifest, dict):
        _refuse("manifest.json is not an object")
    if not isinstance(manifest.get("tree"), str) or not _TREE.fullmatch(manifest["tree"]):
        _refuse("manifest.json: tree is not a full object id")
    src = manifest.get("source")
    if not isinstance(src, dict) or not all(isinstance(src.get(k), str) for k in ("worktree", "git_dir",
                                                                                   "common_dir")):
        _refuse("manifest.json: source is not a worktree identity")
    if not isinstance(manifest.get("build_status"), str):
        _refuse("manifest.json: build_status missing")
    for k in ("changes_sha256", "excluded_sha256"):
        if not isinstance(manifest.get(k), str) or not _HEX64.fullmatch(manifest[k]):
            _refuse(f"manifest.json: {k} missing")
    craw = _read_run_file(run_dir, "changes.json", MAX_JSON)
    if sha256(craw) != manifest["changes_sha256"]:
        _refuse("changes.json does not hash to the manifest's changes_sha256")
    entries = _json(craw, "changes.json")
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        _refuse(f"changes.json is not a list of at most {MAX_ENTRIES} entries")
    entries = [_validate_entry(i, e) for i, e in enumerate(entries)]
    paths = [e["path"] for e in entries]
    if paths != sorted(paths):
        _refuse("changes.json is not sorted by path")
    if sum(1 for e in entries if e["op"] == "added") > MAX_ADDED:
        _refuse(f"more than {MAX_ADDED} added files")
    _check_namespace([e["path"] for e in entries])

    xraw = _read_run_file(run_dir, "excluded.json", MAX_JSON)
    if sha256(xraw) != manifest["excluded_sha256"]:
        _refuse("excluded.json does not hash to the manifest's excluded_sha256")
    xdoc = _json(xraw, "excluded.json")
    if not isinstance(xdoc, dict) or set(xdoc) != {"excluded", "withheld"}:
        _refuse('excluded.json is not {"excluded": [...], "withheld": [...]}')
    excluded, withheld = xdoc["excluded"], xdoc["withheld"]
    if not isinstance(excluded, list) or len(excluded) > MAX_ENTRIES:
        _refuse("excluded.json: excluded is not a list")
    if not isinstance(withheld, list) or len(withheld) > MAX_ENTRIES:
        _refuse("excluded.json: withheld is not a list")
    for x in excluded:
        if not isinstance(x, dict) or set(x) != {"path", "reason", "entries"}:
            _refuse("excluded.json: an excluded entry is not {path, reason, entries}")
        _listed_path(x["path"], "excluded path")
        if not isinstance(x["reason"], str) or not _REASON.fullmatch(x["reason"]):
            _refuse("excluded.json: reason is not [a-z0-9_]")
        n = x["entries"]
        if not isinstance(n, int) or isinstance(n, bool) or n < 0:
            _refuse("excluded.json: entries is not a non-negative integer")
    for w in withheld:
        _listed_path(w, "withheld path")

    blobs, total = {}, 0
    for i, e in enumerate(entries):
        if e["op"] not in ("added", "modified"):
            continue
        data = _read_run_file(run_dir, f"change/{i}", MAX_FILE)
        total += len(data)
        if total > MAX_TOTAL:
            _refuse(f"change set larger than {MAX_TOTAL} bytes")
        if len(data) != e["size"] or sha256(data) != e["sha256"]:
            _refuse(f"change/{i} ({e['path']!r}) does not match its size and sha256")
        if not e["binary"] and is_binary(data):
            _refuse(f"change/{i} ({e['path']!r}) is binary but not flagged as binary")
        if keep is None or i in keep:
            blobs[i] = data
    return ChangeSet(run_dir, manifest, entries, excluded, withheld, blobs)


# --- base bytes from the input tree (show) ---------------------------------------------

class _TreeReader:
    """Blobs of the input tree through sandbox_snapshot's hardened `cat-file --batch`."""

    def __init__(self, repo: Path, tree: str):
        try:
            ss.require_git()
            fmt = ss.object_format(repo)
        except ss.SnapshotRefused as exc:
            _refuse(str(exc))
        except ss.SnapshotInfrastructure as exc:
            raise ApplyInfrastructure(_ascii(exc)) from exc
        if not ss._HEX[fmt].fullmatch(tree):
            _refuse(f"input tree is not a {fmt} id")
        self.tree = tree
        self.batch = ss._Batch(repo, fmt)
        self._trees: dict = {}

    def close(self):
        self.batch.close()

    def _get(self, oid, kind, limit):
        try:
            return self.batch.get(oid, kind, limit)
        except ss.SnapshotRefused as exc:
            _refuse(str(exc))
        except ss.SnapshotInfrastructure as exc:
            raise ApplyInfrastructure(_ascii(exc)) from exc

    def _entries(self, oid) -> dict:
        if oid not in self._trees:
            raw = self._get(oid, "tree", MAX_JSON)
            self._trees[oid] = {name.decode("utf-8", "replace"): (mode, child)
                                for mode, name, child in ss._parse_tree(raw, self.batch.hashlen)}
        return self._trees[oid]

    def blob(self, path: str) -> tuple:
        oid, parts = self.tree, path.split("/")
        for i, part in enumerate(parts):
            found = self._entries(oid).get(part)
            if found is None:
                _refuse(f"{path!r} is not in the input tree")
            mode, oid = found
            last = i == len(parts) - 1
            if last != (mode in MODES):
                _refuse(f"{path!r} is not a regular file in the input tree")
        return self._get(oid, "blob", MAX_BASE_BLOB), mode


# --- display and pagination -----------------------------------------------------------

_NOT_PLAIN = re.compile(r"[^\t\x20-\x7e]")


def _escape_char(m: re.Match) -> str:
    ch = m.group(0)
    if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
        return "\\u{%04X}" % ord(ch)
    return ch


def _display(text: str) -> str:
    """Control, format and separator characters as \\u{XXXX} (escape sequences, CR, bidi
    overrides, zero-width characters); tab and other characters stay."""
    return _NOT_PLAIN.sub(_escape_char, text)


def fragment_lines(lines: list) -> list:
    """Logical lines -> physical lines; one longer than LINE_FRAGMENT bytes becomes fragments
    `[line L bytes a-b] <text>` cut on character boundaries."""
    out = []
    for no, line in enumerate(lines, 1):
        data = line.encode("utf-8")
        if len(data) <= LINE_FRAGMENT:
            out.append(line)
            continue
        pos = 0
        while pos < len(data):
            end = min(pos + LINE_FRAGMENT, len(data))
            while end < len(data) and (data[end] & 0xC0) == 0x80:  # never split a character
                end -= 1
            out.append(f"[line {no} bytes {pos}-{end}] " + data[pos:end].decode("utf-8"))
            pos = end
    return out


def paginate(lines: list, max_lines: int = PAGE_LINES, max_bytes: int = PAGE_BYTES,
             max_entries: int | None = None, entry_flags: list | None = None) -> list:
    """Split physical lines into pages of at most `max_lines` lines and `max_bytes` bytes
    (HEADER_RESERVE kept free for the PAGE header) and at most `max_entries` flagged lines."""
    budget = max_bytes - HEADER_RESERVE
    pages, cur, size, entries = [], [], 0, 0
    for i, line in enumerate(lines):
        n = len(line.encode("utf-8")) + 1
        is_entry = bool(entry_flags and entry_flags[i])
        if n > budget:
            raise ApplyInfrastructure("a physical line exceeds the page budget")
        full = (len(cur) >= max_lines or size + n > budget
                or (is_entry and max_entries is not None and entries >= max_entries))
        if cur and full:
            pages.append(cur)
            cur, size, entries = [], 0, 0
        cur.append(line)
        size += n
        entries += is_entry
    if cur or not pages:
        pages.append(cur)
    return pages


def _emit_page(pages: list, page: int) -> bytes:
    if not 1 <= page <= len(pages):
        _refuse(f"page {page} out of range 1..{len(pages)}")
    body = f"PAGE {page}/{len(pages)}\n" + "".join(ln + "\n" for ln in pages[page - 1])
    data = body.encode("utf-8")
    if len(data) > PAGE_BYTES:
        raise ApplyInfrastructure("page exceeds its byte budget")
    return data


def _split_text(data: bytes) -> list:
    text = data.decode("utf-8")
    # Terminators participate in comparison; EOF annotations must never be
    # comparison input (a real file can contain the same annotation text).
    pieces = text.split("\n")
    return [part + "\n" for part in pieces[:-1]] + ([pieces[-1]] if pieces[-1] else [])


def _mode_text(m) -> str:
    return m if m else "-"


def _summary_lines(cs: ChangeSet, kinds: dict) -> tuple:
    lines, flags = [], []
    counts = {k: sum(1 for v in kinds.values() if v == k) for k in ("binary", "partial")}
    head = [f"BUILD_STATUS={_ascii(cs.manifest['build_status'])} TREE={cs.tree}",
            f"CHANGES={len(cs.entries)} BINARY={counts['binary']} NOT_FULLY_SHOWN={counts['partial']} "
            f"EXCLUDED={len(cs.excluded)} WITHHELD={len(cs.withheld)}"]
    lines += head
    flags += [False] * len(head)
    for i, e in enumerate(cs.entries):
        kind = kinds[i]
        shown = {"mode-only": "full"}.get(kind, kind)
        size = e["size"] if e["size"] is not None else "-"
        lines.append(f"[{i}] {e['op']} {quote_posix(e['path'])} {_mode_text(e['base_mode'])}->"
                     f"{_mode_text(e['mode'])} size={size} sha256={e['sha256'] or '-'} "
                     f"binary={'yes' if kind == 'binary' else 'no'} shown={shown}")
        flags.append(True)
    for x in cs.excluded:
        lines.append(f"excluded {quote_posix(x['path'])} reason={x['reason']} entries={x['entries']}")
        flags.append(True)
    for w in cs.withheld:
        lines.append(f"withheld {quote_posix(w)}")
        flags.append(True)
    return lines, flags


def _head_tail(data: bytes) -> list:
    head = data[:HEAD_TAIL_BYTES].decode("utf-8", "replace").split("\n")[:HEAD_TAIL_LINES]
    tail = data[-HEAD_TAIL_BYTES:].decode("utf-8", "replace").split("\n")
    if tail and tail[-1] == "":
        tail.pop()
    tail = tail[-HEAD_TAIL_LINES:]
    return ["--- head ---", *head, "--- tail ---", *tail]


def _file_lines(i: int, e: dict, base: bytes | None, new: bytes | None, kind: str) -> list:
    bsize = len(base) if base is not None else "-"
    nsize = len(new) if new is not None else "-"
    lines = [f"FILE {i} {e['op']} {quote_posix(e['path'])}",
             f"MODE {_mode_text(e['base_mode'])}->{_mode_text(e['mode'])} SIZE {bsize}->{nsize}",
             f"SHA256 {e['base_sha256'] or '-'}->{e['sha256'] or '-'}",
             f"SHOWN {kind}"]
    if kind == "mode-only":
        return lines + ["mode only, content unchanged"]
    if kind == "binary":
        return lines + ["binary content, not shown; apply needs --accept-binary " + quote_posix(e["path"])]
    if kind == "partial":
        side = new if new is not None else base
        return lines + [f"NOT FULLY SHOWN: a side exceeds {FULL_SHOW_LIMIT} bytes; head and tail of the "
                        f"{'new' if new is not None else 'base'} content follow; apply needs --accept-large "
                        + quote_posix(e["path"]), *_head_tail(side)]
    a = _split_text(base) if base is not None else []
    b = _split_text(new) if new is not None else []
    diff = []
    for line in difflib.unified_diff(a, b, fromfile="a/" + e["path"], tofile="b/" + e["path"]):
        diff.append(line[:-1] if line.endswith("\n") else line)
        if not line.endswith("\n"):
            diff.append("\\ No newline at end of file")
    return lines + diff


def _show_worker(argv: list) -> int:
    ap = _show_parser(worker=True)
    args = ap.parse_args(argv)
    keep = None if args.file is None else {args.file}
    reader = None
    try:
        cs = load_change_set(args.run_dir, args.manifest_sha256, keep=keep if keep is not None else set())
        repo = worktree_identity(args.repo)
        if not _same_identity(repo, cs.manifest["source"]):
            _refuse("--repo is not the worktree the run was made from")
        if args.file is not None and not 0 <= args.file < len(cs.entries):
            _refuse(f"--file {args.file} out of range 0..{len(cs.entries) - 1}")
        kinds, shown_base = {}, None
        for i, e in enumerate(cs.entries):
            base_len, base_bin = 0, False
            if e["op"] in ("modified", "deleted"):
                if reader is None:
                    reader = _TreeReader(Path(repo["worktree"]), cs.tree)
                data, mode = reader.blob(e["path"])
                if sha256(data) != e["base_sha256"] or mode != e["base_mode"]:
                    _refuse(f"{e['path']!r}: the input tree does not hold the recorded base")
                base_len, base_bin = len(data), is_binary(data)
                if i == args.file:
                    shown_base = data
            kinds[i] = classify(e, base_len, base_bin)
        if args.summary:
            lines, flags = _summary_lines(cs, kinds)
            phys, pflags = _fragment_with_flags([_display(x) for x in lines], flags)
            pages = paginate(phys, max_entries=SUMMARY_ENTRIES, entry_flags=pflags)
        else:
            i = args.file
            lines = _file_lines(i, cs.entries[i], shown_base, cs.blobs.get(i), kinds[i])
            pages = paginate(fragment_lines([_display(x) for x in lines]))
        data = _emit_page(pages, args.page)
    except ApplyRefused as exc:
        print(f"REFUSED={_ascii(exc)}")
        return 2
    except ApplyInfrastructure as exc:
        print(f"ERROR={_ascii(exc)}")
        return 5
    except Exception as exc:  # never a traceback
        print(f"ERROR={_ascii(type(exc).__name__)}: {_ascii(exc)[:200]}")
        return 5
    finally:
        if reader is not None:
            reader.close()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
    return 0


def _fragment_with_flags(lines: list, flags: list) -> tuple:
    """Physical lines and their entry flags: the first fragment of a flagged line carries it.
    Fragment labels count lines in `lines` as a whole, as fragment_lines() does."""
    phys, pflags = [], []
    for no, (line, flag) in enumerate(zip(lines, flags), 1):
        frags = fragment_lines([line])
        if len(frags) > 1:
            frags = [f.replace("[line 1 ", f"[line {no} ", 1) for f in frags]
        phys += frags
        pflags += [flag] + [False] * (len(frags) - 1)
    return phys, pflags


def _limit_memory():  # pragma: no cover - runs in the child
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_AS, (SHOW_RLIMIT_AS, SHOW_RLIMIT_AS))
    except (ValueError, OSError):
        if sys.platform != "darwin":  # macOS refuses RLIMIT_AS; elsewhere a failure is fatal
            raise


def show(args) -> int:
    """Render one bounded review page in an isolated worker; return 5 on timeout or infrastructure failure."""
    argv = [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--show-worker",
            "--run-dir", str(args.run_dir), "--manifest-sha256", str(args.manifest_sha256),
            "--repo", str(args.repo), "--page", str(args.page)]
    argv += ["--summary"] if args.summary else ["--file", str(args.file)]
    kwargs = {} if os.name == "nt" else {"preexec_fn": _limit_memory}
    try:
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,  # nosec B603
                             timeout=SHOW_DEADLINE, **kwargs)
    except subprocess.TimeoutExpired:
        print(f"ERROR=show worker killed at the deadline ({SHOW_DEADLINE} s)")
        print(f"show: worker killed at the deadline ({SHOW_DEADLINE} s)", file=sys.stderr)
        return 5
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR=cannot start the show worker: {_ascii(exc)}")
        return 5
    if len(res.stdout) > PAGE_BYTES + 1024:
        print("ERROR=show worker output exceeds the page budget")
        return 5
    if res.stderr:
        sys.stderr.write(_ascii(res.stderr[:4096].decode("utf-8", "replace")) + "\n")
    sys.stdout.flush()
    if res.returncode == 0:
        sys.stdout.buffer.write(res.stdout)
    else:
        sys.stdout.write(_ascii(res.stdout.decode("utf-8", "replace")[:2048]) + "\n")
    sys.stdout.flush()
    return res.returncode if res.returncode in (0, 2, 5) else 5


# --- apply: preflight -----------------------------------------------------------------

def _exact_child(parent: Path, name: str, listing_cache: dict) -> str | None:
    """'exact', 'case' (only a case-insensitive match) or None, from the directory listing."""
    key = str(parent)
    if key not in listing_cache:
        try:
            listing_cache[key] = os.listdir(parent)
        except OSError:
            listing_cache[key] = []
    names = listing_cache[key]
    if name in names:
        return "exact"
    low = name.casefold()
    return "case" if any(n.casefold() == low for n in names) else None


def _read_leaf(parent: Path, dfd, leaf: str, limit: int, single_link=False) -> tuple:
    """(bytes, st_mode) of the regular file parent/leaf, never following a link."""
    try:
        st = os.stat(leaf, dir_fd=dfd, follow_symlinks=False) if dfd is not None else os.lstat(parent / leaf)
    except OSError as exc:
        raise _Conflict(f"{leaf}: missing") from exc
    if hunt_io._is_redirect(st) or not stat.S_ISREG(st.st_mode):
        raise _Conflict(f"{leaf}: not a regular file")
    if single_link and st.st_nlink != 1:
        raise _Conflict(f"{leaf}: mode change would affect another hardlink")
    try:
        fd = os.open(leaf, hunt_io._READ_FLAGS, dir_fd=dfd) if dfd is not None else \
            os.open(parent / leaf, hunt_io._READ_FLAGS)
    except OSError as exc:
        raise _Conflict(f"{leaf}: cannot open") from exc
    try:
        status, data = hunt_io._read_fd(fd, st, limit)
        opened = os.fstat(fd)
        if single_link and opened.st_nlink != 1:
            raise _Conflict(f"{leaf}: mode change would affect another hardlink")
        mode = opened.st_mode
    finally:
        os.close(fd)
    if status != "ok":
        raise _Conflict(f"{leaf}: {data}")
    return data, mode


def _exec_ok(st_mode: int, git_mode: str) -> bool:
    if os.name == "nt":
        return True
    return bool(st_mode & 0o100) == (git_mode == "100755")


class _Item:
    def __init__(self, entry: dict, new: bytes | None):
        self.e, self.new = entry, new
        self.parts = entry["path"].split("/")
        self.existing_mode: int | None = None
        self.base: bytes | None = None


def _anchor(target: Path, parent: Path):
    hunt_io.check_chain(parent, base=target)
    return hunt_io._open_dir_anchor(parent, base=target)


def _preflight(cs: ChangeSet, target: Path, accept_binary: list, accept_large: list) -> tuple:
    is_nt = os.name == "nt"
    for e in cs.entries:
        canonical_entry_path(e["path"], is_nt=is_nt)
    items = [_Item(e, cs.blobs.get(i)) for i, e in sorted(enumerate(cs.entries), key=lambda t: t[1]["path"])]
    listing: dict = {}
    to_create: set = set()
    plugin = str(PLUGIN_ROOT)
    for it in items:
        e, cur = it.e, target
        for depth, part in enumerate(it.parts[:-1]):
            cur = cur / part
            rel = "/".join(it.parts[: depth + 1])
            if rel in to_create:
                continue
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                if e["op"] != "added":
                    _refuse(f"{e['path']!r}: directory {rel!r} is missing")
                to_create.update("/".join(it.parts[: d + 1]) for d in range(depth, len(it.parts) - 1))
                break
            if hunt_io._is_redirect(st) or not stat.S_ISDIR(st.st_mode):
                _refuse(f"{e['path']!r}: {rel!r} is a link, a junction or not a directory")
            if _CASE_INSENSITIVE_FS and _exact_child(cur.parent, part, listing) != "exact":
                _refuse(f"{e['path']!r}: {rel!r} exists only with a different case")
            if _inside(str(cur), plugin) or not _inside(str(cur), str(target)):
                _refuse(f"{e['path']!r} resolves into the plugin directory or outside the target")
        parent = target.joinpath(*it.parts[:-1])
        leaf = it.parts[-1]
        parent_missing = any("/".join(it.parts[: d + 1]) in to_create for d in range(len(it.parts) - 1))
        if e["op"] == "added":
            if not parent_missing:
                if os.path.lexists(parent / leaf):
                    _refuse(f"{e['path']!r}: an added path already exists")
                if _CASE_INSENSITIVE_FS and _exact_child(parent, leaf, listing) is not None:
                    _refuse(f"{e['path']!r}: an added path exists with a different case")
            continue
        try:
            dfd = _anchor(target, parent)
        except hunt_io.HuntIOError as exc:
            _refuse(f"{e['path']!r}: {exc}")
        try:
            data, mode = _read_leaf(parent, dfd, leaf, max(MAX_FILE, MAX_BASE_BLOB), e["op"] == "mode")
        except _Conflict as exc:
            _refuse(f"{e['path']!r}: {exc}")
        finally:
            if dfd is not None:
                os.close(dfd)
        if _CASE_INSENSITIVE_FS and _exact_child(parent, leaf, listing) != "exact":
            _refuse(f"{e['path']!r}: exists only with a different case")
        if sha256(data) != e["base_sha256"]:
            _refuse(f"{e['path']!r}: the target no longer holds the base bytes (edited since the run)")
        if not _exec_ok(mode, e["base_mode"]):
            _refuse(f"{e['path']!r}: the target's executable bit does not match the base mode")
        it.existing_mode, it.base = mode, data
    need_binary, need_large = set(), set()
    for it in items:
        kind = classify(it.e, len(it.base or b""), is_binary(it.base))
        if kind == "binary":
            need_binary.add(it.e["path"])
        elif kind == "partial":
            need_large.add(it.e["path"])
    for flag, given, needed in (("--accept-binary", accept_binary, need_binary),
                                ("--accept-large", accept_large, need_large)):
        extra = sorted(set(given) - needed)
        if extra:
            _refuse(f"{flag} names paths that do not need it: {extra[:5]}")
        missing = sorted(needed - set(given))
        if missing:
            _refuse(f"{flag} is required for {missing[:5]}" + (" ..." if len(missing) > 5 else ""))
    dirs = sorted(to_create, key=lambda d: (d.count("/"), d))
    return items, dirs


def _index_modes(target: Path) -> dict:
    """Windows: {path: mode} of the target's index, read with hardened plumbing."""
    try:
        out = ss._git(target, ["ls-files", "-s", "-z"])
    except ss.SnapshotRefused as exc:
        _refuse(str(exc))
    except ss.SnapshotInfrastructure as exc:
        raise ApplyInfrastructure(_ascii(exc)) from exc
    modes = {}
    for rec in out.split(b"\0"):
        head, tab, name = rec.partition(b"\t")
        if tab:
            try:
                modes[name.decode("utf-8")] = head.split()[0].decode("ascii")
            except (UnicodeDecodeError, IndexError):
                continue
    return modes


def _verify_input_tree(target: Path, tree: str) -> None:
    reader = _TreeReader(target, tree)
    try:
        reader._entries(tree)
    finally:
        reader.close()


# --- apply: publication ---------------------------------------------------------------

def _replace(src: str, dst: str, dfd, parent: Path) -> None:
    if dfd is not None:
        os.replace(src, dst, src_dir_fd=dfd, dst_dir_fd=dfd)
    else:
        os.replace(parent / src, parent / dst)


class _PublishedError(OSError):
    """The destination exists, but cleanup failed; report it as published."""


def _place_new(src: str, dst: str, dfd, parent: Path) -> None:
    """Move a new file into place without replacing anything that appeared meanwhile."""
    if dfd is None:  # Windows: os.rename refuses an existing destination
        os.rename(parent / src, parent / dst)
        return
    try:
        os.link(src, dst, src_dir_fd=dfd, dst_dir_fd=dfd, follow_symlinks=False)
    except FileExistsError:
        raise
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EOPNOTSUPP, errno.EMLINK, errno.ENOSYS):
            raise
        try:  # no hard links on this file system: check, then rename (residual window)
            os.stat(dst, dir_fd=dfd, follow_symlinks=False)
            raise FileExistsError(errno.EEXIST, "destination exists", dst) from exc
        except FileNotFoundError:
            os.rename(src, dst, src_dir_fd=dfd, dst_dir_fd=dfd)
        return
    try:
        os.unlink(src, dir_fd=dfd)
    except OSError as exc:
        raise _PublishedError("published addition; temporary sibling cleanup failed") from exc


def _unlink(name: str, dfd, parent: Path) -> None:
    if dfd is not None:
        os.unlink(name, dir_fd=dfd)
    else:
        os.unlink(parent / name)


def _make_dir(target: Path, rel: str) -> None:
    parts = rel.split("/")
    parent = target.joinpath(*parts[:-1])
    dfd = _anchor(target, parent)
    try:
        if dfd is not None:
            os.mkdir(parts[-1], 0o777, dir_fd=dfd)
            st = os.stat(parts[-1], dir_fd=dfd, follow_symlinks=False)
        else:
            os.mkdir(parent / parts[-1], 0o777)
            st = os.lstat(parent / parts[-1])
    finally:
        if dfd is not None:
            os.close(dfd)
    if hunt_io._is_redirect(st) or not stat.S_ISDIR(st.st_mode):
        raise _Conflict(f"{rel}: not a plain directory after creation")


def _recheck(it: _Item, parent: Path, dfd, leaf: str) -> int | None:
    """Immediately before the rename/deletion/toggle: the target is still the base (or, for an
    addition, still absent). Returns the current st_mode of a replaced file."""
    e = it.e
    if e["op"] == "added":
        try:
            os.stat(leaf, dir_fd=dfd, follow_symlinks=False) if dfd is not None else os.lstat(parent / leaf)
        except FileNotFoundError:
            pass
        else:
            raise _Conflict(f"{e['path']}: appeared during publication")
        if _CASE_INSENSITIVE_FS and _exact_child(parent, leaf, {}) is not None:
            raise _Conflict(f"{e['path']}: appeared during publication (other case)")
        return None
    data, mode = _read_leaf(parent, dfd, leaf, max(MAX_FILE, MAX_BASE_BLOB), e["op"] == "mode")
    if sha256(data) != e["base_sha256"] or not _exec_ok(mode, e["base_mode"]):
        raise _Conflict(f"{e['path']}: changed during publication")
    return mode


def _publish_one(it: _Item, target: Path, umask: int) -> None:
    e = it.e
    parent = target.joinpath(*it.parts[:-1])
    leaf = it.parts[-1]
    dfd = _anchor(target, parent)
    tmp, tmp_fd = None, None
    try:
        if e["op"] in ("added", "modified"):
            tmp = hunt_io._leaf(f".{leaf}.claudex-pub-{secrets.token_hex(4)}")
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
            tmp_fd = os.open(tmp, flags, 0o600, dir_fd=dfd) if dfd is not None else \
                os.open(parent / tmp, flags, 0o600)
            view = memoryview(it.new)
            while view:
                view = view[os.write(tmp_fd, view):]
        if _HOOK_BEFORE_RECHECK is not None:
            _HOOK_BEFORE_RECHECK(e)
        current = _recheck(it, parent, dfd, leaf)
        if e["op"] in ("added", "modified"):
            if os.name != "nt":
                os.fchmod(tmp_fd, result_permissions(current, e["mode"], umask))
            os.fsync(tmp_fd)
            os.close(tmp_fd)
            tmp_fd = None
            if e["op"] == "added":
                try:
                    _place_new(tmp, leaf, dfd, parent)
                except FileExistsError as exc:
                    raise _Conflict(f"{e['path']}: appeared during publication") from exc
            else:
                _replace(tmp, leaf, dfd, parent)
            tmp = None
        elif e["op"] == "deleted":
            _unlink(leaf, dfd, parent)
        elif e["op"] == "mode" and os.name != "nt":
            fd = os.open(leaf, hunt_io._READ_FLAGS, dir_fd=dfd)
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode) or fst.st_mode != current or fst.st_nlink != 1:
                    raise _Conflict(f"{e['path']}: changed during publication")
                os.fchmod(fd, result_permissions(fst.st_mode, e["mode"], umask))
            finally:
                os.close(fd)
    finally:
        if tmp_fd is not None:
            os.close(tmp_fd)
        if tmp is not None:
            try:
                _unlink(tmp, dfd, parent)
            except OSError:
                pass
        if dfd is not None:
            os.close(dfd)


def _write_report(run_dir: Path, report: dict) -> str | None:
    data = (json.dumps(report, indent=1, sort_keys=True) + "\n").encode("utf-8")
    for n in range(1, 100):
        name = "apply-report.json" if n == 1 else f"apply-report-{n}.json"
        if os.path.lexists(run_dir / name):
            continue
        try:
            hunt_io.create_file(run_dir, name, data, base=run_dir)
            return str(run_dir / name)
        except hunt_io.HuntIOError:
            continue
    return None


def apply(args) -> int:
    """Validate identity and preconditions, then publish reviewed files and record exact partial recovery state."""
    try:
        target = Path(os.path.realpath(str(args.target)))
        _check_plugin_containment(str(target))
        cs = load_change_set(args.run_dir, args.manifest_sha256)
        if cs.manifest["build_status"] != "exited":
            _refuse(f"run status is {cs.manifest['build_status']!r}, not 'exited'")
        if not _same_identity(worktree_identity(target), cs.manifest["source"]):
            _refuse("the target is not the worktree the run was made from (realpath or git directory differ)")
        for p in list(args.accept_binary) + list(args.accept_large):
            canonical_entry_path(p, is_nt=os.name == "nt")
        items, dirs = _preflight(cs, target, list(args.accept_binary), list(args.accept_large))
        if items:
            _verify_input_tree(target, cs.tree)
        index_modes = _index_modes(target) if os.name == "nt" and items else {}
    except ApplyRefused as exc:
        print("APPLY_STATUS=refused")
        print(f"REFUSED={exc}")
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except ApplyInfrastructure as exc:
        print(f"ERROR={exc}")
        return 5
    except hunt_io.HuntIOError as exc:
        print("APPLY_STATUS=refused")
        print(f"REFUSED={_ascii(exc)}")
        return 2

    umask = _current_umask() if os.name != "nt" else 0o022
    created, published, code, reason = [], [], 0, ""
    try:
        for rel in dirs:
            _make_dir(target, rel)
            created.append(rel)
        for it in items:
            try:
                _publish_one(it, target, umask)
            except _PublishedError:
                published.append(it)
                raise
            published.append(it)
    except _Conflict as exc:
        code, reason = 2, f"conflict: {_ascii(exc)}"
    except (OSError, hunt_io.HuntIOError) as exc:
        code, reason = 5, f"I/O error: {_ascii(exc)}"
    done = {id(it) for it in published}
    not_published = [it for it in items if id(it) not in done]
    report = {"input_tree": cs.tree, "target": str(target),
              "status": "nothing" if not items else ("published" if code == 0 else "stopped"),
              "reason": reason,
              "published": [{"path": it.e["path"], "op": it.e["op"]} for it in published],
              "not_published": [{"path": it.e["path"], "op": it.e["op"]} for it in not_published],
              "created_dirs": created}
    todo = mode_todo([it.e for it in published], index_modes) if os.name == "nt" else []
    recovery = recovery_commands(report, cs.tree)
    report.update({"mode_todo": todo, "recovery": recovery})
    paths = [it.e["path"] for it in published]
    print(f"APPLY_STATUS={report['status']}")
    if reason:
        print(f"STOPPED={reason}")
        print(f"apply: stopped part-way ({reason}); see PUBLISHED / NOT_PUBLISHED and RECOVERY",
              file=sys.stderr)
    print("PUBLISHED=" + json.dumps(paths))
    print("NOT_PUBLISHED=" + json.dumps([it.e["path"] for it in not_published]))
    print("CREATED_DIRS=" + json.dumps(created))
    for line in todo:
        print(f"MODE_TODO={line}")
    if paths:
        print("STAGE=" + _render(["add"], paths))
        print("CHECK=" + _render(["diff", "--cached", "--name-only", cs.tree], paths))
    if recovery:
        print(f"RECOVERY_CWD={quote_posix(str(target))}")
        for line in recovery:
            print(f"RECOVERY={line}")
    where = _write_report(cs.run_dir, report)
    if where:
        print(f"REPORT={_ascii(where)}")
    else:
        print("apply: WARNING: apply-report.json could not be written (informational only)", file=sys.stderr)
    return code


# --- CLI ------------------------------------------------------------------------------

def _show_parser(worker: bool = False) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="change_apply.py show" if not worker else "change_apply.py --show-worker")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--manifest-sha256", required=True)
    ap.add_argument("--repo", required=True)
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--summary", action="store_true")
    sel.add_argument("--file", type=int)
    ap.add_argument("--page", type=int, default=1)
    return ap


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Review (show) and publish (apply) a sandboxed build's change set.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("show")
    s.add_argument("--run-dir", required=True)
    s.add_argument("--manifest-sha256", required=True)
    s.add_argument("--repo", required=True)
    sel = s.add_mutually_exclusive_group(required=True)
    sel.add_argument("--summary", action="store_true")
    sel.add_argument("--file", type=int)
    s.add_argument("--page", type=int, default=1)
    a = sub.add_parser("apply")
    a.add_argument("--run-dir", required=True)
    a.add_argument("--manifest-sha256", required=True)
    a.add_argument("--target", required=True)
    a.add_argument("--accept-binary", action="append", default=[], metavar="PATH")
    a.add_argument("--accept-large", action="append", default=[], metavar="PATH")
    return ap


def main(argv: list | None = None) -> int:
    """Dispatch show/apply arguments and return the public 0, 2 (refused), or 5 (infrastructure) status."""
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv[:1] == ["--show-worker"]:
            return _show_worker(argv[1:])
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse: usage error
        return 2 if exc.code not in (0, None) else 0
    try:
        return show(args) if args.cmd == "show" else apply(args)
    except Exception as exc:  # never a traceback
        print(f"ERROR={_ascii(type(exc).__name__)}: {_ascii(exc)[:200]}")
        return 5


if __name__ == "__main__":
    sys.exit(main())
