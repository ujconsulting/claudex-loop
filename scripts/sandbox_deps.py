#!/usr/bin/env python3
"""Strict dependency-file parsers for the sandbox runner and the dependency audit (pure, no I/O).

Plan B1.5, steps 1 and 7 (docs/plans/2026-10-27-sicherheitskette, approved round 6). Nothing in
this module opens a file, starts a process or touches the network: callers pass bytes in and get
values or a refusal out, so the whole surface is testable with byte strings.

- REQUIREMENTS FILES: accepted are blank lines, comments, line continuations and one
  `name==version --hash=sha256:<64 lowercase hex> ...` requirement per logical line, and nothing
  else. Every option line, URL, path, extra, environment marker, unhashed requirement,
  non-sha256 or uppercase hash, non-canonical version, duplicate name, more than 500
  requirements, file over 1 MiB and non-UTF-8 byte refuses with the file label and line number.
  Markers are refused rather than evaluated: evaluating them needs `packaging`, and a wrong
  evaluation silently drops or adds a dependency.
- MERGE of several files: equal versions, hash sets INTERSECTED, an empty intersection refuses.
- DIGESTS: `requirements_sha256` over a canonical JSON of the inventory, so the same inventory
  gives the same digest on every machine.
- PACKAGE-LOCK (npm lockfileVersion 2/3): only `packages` is read. Links, workspaces, `..` keys,
  bundled dependencies (the root entry included), non-registry or over-256-character versions,
  non-registry `resolved` URLs and aliases (an entry that is not what its key says) refuse the
  whole file; the audit would otherwise query the wrong
  identity. JSON nesting is pre-scanned (`json_depth_ok`) before `json.loads` ever runs.

Exceptions, per public function (none of them ever returns a partial result):

- `parse_requirements`, `merge`, `parse_package_lock`: DepsRefused (ASCII reason) for input that
  cannot be accepted - the file content is at fault.
- `render_requirements`: ValueError when a selected hash is not one of that requirement's hashes.
  That is a caller bug (the selection must come from the inventory), not bad input, so it is not
  DepsRefused.
- `json_depth_ok`: no refusal; it answers True or False.
- `normalize_name`, `canonical_json`, `requirements_sha256`: no refusal; they expect values the
  parsers above produced and raise only what Python raises for wrong types.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import NamedTuple

MAX_REQ_FILE = 1024 * 1024
MAX_REQUIREMENTS = 500
MAX_LOCK_FILE = 16 * 1024 * 1024
MAX_NPM_ENTRIES = 10000
MAX_SEMVER_LENGTH = 256  # node-semver MAX_LENGTH
DEFAULT_DEPTH = 64

NAME_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", re.ASCII)
_N = r"(?:0|[1-9][0-9]*)"
VERSION_RE = re.compile(rf"{_N}(?:\.{_N})*(?:(?:a|b|rc){_N})?(?:\.post{_N})?(?:\.dev{_N})?", re.ASCII)
HASH_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)

_SPLIT_RE = re.compile(r"^([A-Za-z0-9._-]+)(.*)$", re.ASCII | re.DOTALL)
_HEX64_ANYCASE = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)

_SEMVER_NUM = r"(?:0|[1-9][0-9]*)"
_SEMVER_PRE = r"(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)"
NPM_SEMVER_RE = re.compile(
    rf"{_SEMVER_NUM}\.{_SEMVER_NUM}\.{_SEMVER_NUM}"
    rf"(?:-{_SEMVER_PRE}(?:\.{_SEMVER_PRE})*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?", re.ASCII)
_NPM_PART = r"[A-Za-z0-9~][A-Za-z0-9._~-]*"
_NPM_COMP = rf"(?:@{_NPM_PART}/)?{_NPM_PART}"
_NPM_KEY_RE = re.compile(rf"(?:node_modules/{_NPM_COMP}/)*node_modules/({_NPM_COMP})", re.ASCII)
_REGISTRY = "https://registry.npmjs.org/"


class DepsRefused(Exception):
    """Input that cannot be accepted; the message is ASCII and names the file label."""


class Req(NamedTuple):
    """One pinned requirement: normalised name, canonical version, set of sha256 hex digests."""
    name: str
    version: str
    hashes: frozenset


def _a(value) -> str:
    """ASCII-safe, length-bounded rendering of untrusted text for a message."""
    text = ascii(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _label(label: str) -> str:
    return ascii(str(label))[1:-1]


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: runs of -, _ and . become one -, lower case."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ------------------------------------------------------------------ requirements files

def _strip_comment(raw: str) -> str:
    """Drop a trailing comment: a `#` preceded by whitespace, that whitespace run and the rest.

    Same result as `re.sub(r"\\s+#.*$", "", raw)` (pip's rule), but one linear pass: the
    unanchored regex rescanned a whitespace run from every start position, quadratic on 1 MiB
    of spaces (inspection round 1, A1). `str.isspace` and `str.rstrip()` use the same Unicode
    whitespace definition as `\\s` on str patterns.
    """
    pos = raw.find("#", 1)
    while pos != -1:
        if raw[pos - 1].isspace():
            return raw[:pos].rstrip()
        pos = raw.find("#", pos + 1)
    return raw


def _logical_lines(text: str, label: str):
    """Yield (first line number, logical line) with comments dropped and continuations joined.

    A continuation that joins only whitespace (a standalone backslash before a blank line, a
    comment line or the end of the file) refuses: it is not a requirement, and an empty logical
    line must never reach the tokenizer (inspection round 1, A3).
    """
    lab = _label(label)
    cur_no = 0
    parts: list[str] | None = None

    def joined() -> str:
        line = " ".join(parts)
        if not line.strip():
            raise DepsRefused(f"{lab}:{cur_no}: line continuation joins nothing (empty logical line)")
        return line

    for no, raw in enumerate(text.split("\n"), 1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        if raw.strip().startswith("#"):
            # a comment line ends a continuation (pip does the same)
            if parts is not None:
                yield cur_no, joined()
                parts = None
            continue
        line = _strip_comment(raw)
        if line.endswith("\\"):
            if parts is None:
                parts, cur_no = [], no
            parts.append(line[:-1])
            continue
        if parts is not None:
            parts.append(line)
            yield cur_no, joined()
            parts = None
        elif line.strip():
            yield no, line
    if parts is not None:
        raise DepsRefused(f"{lab}:{cur_no}: line continuation at end of file with nothing after it")


def parse_requirements(data: bytes, label: str) -> list[Req]:
    """Parse a fully hashed requirements file (plan B1.5 step 1); raises DepsRefused on anything else."""
    lab = _label(label)
    if len(data) > MAX_REQ_FILE:
        raise DepsRefused(f"{lab}: file is over the 1 MiB limit ({len(data)} bytes)")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DepsRefused(f"{lab}: file is not valid UTF-8") from None
    out: list[Req] = []
    seen: dict[str, int] = {}
    for no, line in _logical_lines(text, label):
        where = f"{lab}:{no}"
        tokens = line.split()
        if not tokens:  # _logical_lines never yields one; kept so tokens[0] below cannot raise
            raise DepsRefused(f"{where}: empty logical line")
        for tok in tokens:
            if tok.startswith("-") and not tok.startswith("--hash="):
                raise DepsRefused(f"{where}: option line or option {_a(tok)} is not allowed; only "
                                  "'name==version --hash=sha256:...' lines are accepted")
        if "[" in line:
            raise DepsRefused(f"{where}: extras ('[') are not allowed; list every package with its own pin")
        if "@" in line or "://" in line:
            raise DepsRefused(f"{where}: URL requirements are not allowed ({_a(tokens[0])})")
        if ";" in line:
            raise DepsRefused(f"{where}: environment markers are not allowed; markers are not evaluated "
                              "here, so a file that still carries them is refused")
        if "/" in line or "\\" in line:
            raise DepsRefused(f"{where}: path requirements are not allowed ({_a(tokens[0])})")
        first = tokens[0]
        m = _SPLIT_RE.match(first)
        if not m:
            raise DepsRefused(f"{where}: not a 'name==version' requirement: {_a(first)}")
        name, rest = m.group(1), m.group(2)
        if not NAME_RE.fullmatch(name):
            raise DepsRefused(f"{where}: invalid package name {_a(name)}")
        if not rest.startswith("==") or rest.startswith("==="):
            raise DepsRefused(f"{where}: {_a(first)} is not an exact '==' pin")
        version = rest[2:]
        if not VERSION_RE.fullmatch(version):
            raise DepsRefused(f"{where}: non-canonical version {_a(version)}; re-compile the file so every "
                              "version is canonical (N.N.N, optional aN/bN/rcN, .postN, .devN)")
        hashes = set()
        for tok in tokens[1:]:
            if not tok.startswith("--hash="):
                raise DepsRefused(f"{where}: unexpected token {_a(tok)}")
            value = tok[len("--hash="):]
            if not value.startswith("sha256:"):
                raise DepsRefused(f"{where}: non-sha256 hash {_a(tok)}")
            hexpart = value[len("sha256:"):]
            if HASH_RE.fullmatch(hexpart):
                hashes.add(hexpart)
            elif _HEX64_ANYCASE.fullmatch(hexpart):
                raise DepsRefused(f"{where}: hash must be lowercase hex")
            else:
                raise DepsRefused(f"{where}: malformed sha256 hash {_a(tok)} (64 lowercase hex digits needed)")
        if not hashes:
            raise DepsRefused(f"{where}: requirement {_a(first)} has no hash; compile the file with "
                              "--generate-hashes (pip-compile or uv pip compile)")
        norm = normalize_name(name)
        if norm in seen:
            raise DepsRefused(f"{where}: duplicate requirement {_a(norm)} (first at line {seen[norm]})")
        seen[norm] = no
        if len(out) >= MAX_REQUIREMENTS:
            raise DepsRefused(f"{where}: more than {MAX_REQUIREMENTS} requirements")
        out.append(Req(norm, version, frozenset(hashes)))
    return out


def merge(groups: list[list[Req]]) -> list[Req]:
    """Merge parsed files by name: equal versions, hash sets intersected, sorted by name."""
    by_name: dict[str, Req] = {}
    for group in groups:
        for req in group:
            prev = by_name.get(req.name)
            if prev is None:
                by_name[req.name] = req
                continue
            if prev.version != req.version:
                raise DepsRefused(f"version conflict for {_a(req.name)}: {_a(prev.version)} vs {_a(req.version)}")
            common = prev.hashes & req.hashes
            if not common:
                raise DepsRefused(f"no hash of {_a(req.name)}=={_a(req.version)} is common to all files")
            by_name[req.name] = Req(req.name, req.version, frozenset(common))
    return [by_name[n] for n in sorted(by_name)]


def canonical_json(reqs: list[Req]) -> bytes:
    """Canonical JSON of the inventory: [[name, version, [sorted hashes]], ...] sorted by name."""
    rows = [[r.name, r.version, sorted(r.hashes)] for r in sorted(reqs, key=lambda r: (r.name, r.version))]
    return json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")


def requirements_sha256(reqs: list[Req]) -> str:
    """sha256 hex of canonical_json(reqs)."""
    return hashlib.sha256(canonical_json(reqs)).hexdigest()


def render_requirements(selected: list[tuple[Req, str]]) -> bytes:
    """The container's requirements.txt: one `name==version --hash=sha256:<selected>` line each, sorted."""
    lines = []
    for req, chosen in sorted(selected, key=lambda s: s[0].name):
        if chosen not in req.hashes:
            raise ValueError(f"selected hash is not one of the hashes of {req.name}")
        lines.append(f"{req.name}=={req.version} --hash=sha256:{chosen}\n")
    return "".join(lines).encode("ascii")


# ------------------------------------------------------------------ JSON pre-scan, package-lock

def json_depth_ok(data: bytes, limit: int = DEFAULT_DEPTH) -> bool:
    """True when bracket nesting outside strings never exceeds `limit` (bounded pre-scan, no parsing)."""
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:      # backslash
                escaped = True
            elif byte == 0x22:      # closing quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > limit:
                return False
        elif byte in (0x5D, 0x7D):  # ] }
            depth = max(0, depth - 1)
    return True


def _no_dup_pairs(label: str):
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise DepsRefused(f"{_label(label)}: duplicate key in JSON object")
        return dict(pairs)
    return hook


def _bad_constant(label: str):
    def hook(name):
        raise DepsRefused(f"{_label(label)}: non-standard JSON constant {_a(name)}")
    return hook


def _lock_entry(where: str, key: str, entry) -> tuple[str, str] | None:
    """Validate one `packages` entry; the root ("") yields None.

    The forbidden constructs (bundles, links) are checked for EVERY entry before the root
    returns: a lockfile whose only entry was a `link: true` root parsed as an empty inventory,
    and the audit then reported clean without querying anything (inspection round 1, A5).
    """
    if not isinstance(entry, dict):
        raise DepsRefused(f"{where}: entry {_a(key)} is not an object")
    for bundle_key in ("bundleDependencies", "bundledDependencies"):
        if entry.get(bundle_key):
            raise DepsRefused(f"{where}: entry {_a(key)} has bundleDependencies; bundled packages are not supported")
    if entry.get("inBundle"):
        raise DepsRefused(f"{where}: entry {_a(key)} is bundled (inBundle); bundled packages are not supported")
    if "link" in entry and entry["link"] is not False:
        raise DepsRefused(f"{where}: entry {_a(key)} is a link; links and workspaces are not supported")
    if key == "":
        return None
    m = _NPM_KEY_RE.fullmatch(key)
    name = m.group(1)
    version = entry.get("version")
    if not isinstance(version, str):
        raise DepsRefused(f"{where}: entry {_a(key)} has no string version")
    if len(version) > MAX_SEMVER_LENGTH:
        # node-semver's own MAX_LENGTH; also keeps the regex below off multi-MiB strings
        raise DepsRefused(f"{where}: entry {_a(key)} has a version longer than {MAX_SEMVER_LENGTH} characters")
    if not NPM_SEMVER_RE.fullmatch(version):
        kind = " (file:/git/URL versions are not supported)" if re.match(r"(?i)(file:|git|https?:|link:|[a-z]+[:/])", version) else ""
        raise DepsRefused(f"{where}: entry {_a(key)} has version {_a(version)} that is not strict semver{kind}")
    alias = entry.get("name")
    if alias is not None and alias != name:
        raise DepsRefused(f"{where}: alias: entry {_a(key)} declares name {_a(alias)} but its key says {_a(name)}")
    resolved = entry.get("resolved")
    if not isinstance(resolved, str):
        raise DepsRefused(f"{where}: entry {_a(key)} has no resolved URL")
    if not resolved.startswith(_REGISTRY):
        raise DepsRefused(f"{where}: entry {_a(key)} has resolved {_a(resolved)} outside {_REGISTRY}")
    path = resolved[len(_REGISTRY):]
    if re.search(r"[?#\s\x00-\x1f]", path) or path.count("/-/") != 1:
        raise DepsRefused(f"{where}: entry {_a(key)} has an unexpected resolved URL {_a(resolved)}")
    left, filename = path.split("/-/")
    left = urllib.parse.unquote(left)
    if left != name:
        raise DepsRefused(f"{where}: alias: entry {_a(key)} is named {_a(name)} but resolves to package {_a(left)}")
    base = name.rsplit("/", 1)[-1]
    if filename not in (f"{base}-{version}.tgz", f"{base}-{version.split('+', 1)[0]}.tgz"):
        raise DepsRefused(f"{where}: alias or version mismatch: entry {_a(key)} version {_a(version)} but "
                          f"resolved file {_a(filename)}")
    return name, version


def parse_package_lock(data: bytes, label: str) -> list[tuple[str, str]]:
    """Read `packages` of an npm lockfileVersion 2/3 file; returns sorted unique (name, version)."""
    lab = _label(label)
    if len(data) > MAX_LOCK_FILE:
        raise DepsRefused(f"{lab}: file is over the 16 MiB limit ({len(data)} bytes)")
    if not json_depth_ok(data, DEFAULT_DEPTH):
        raise DepsRefused(f"{lab}: JSON nesting is deeper than {DEFAULT_DEPTH} levels")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DepsRefused(f"{lab}: file is not valid UTF-8") from None
    try:
        doc = json.loads(text, object_pairs_hook=_no_dup_pairs(label), parse_constant=_bad_constant(label))
    except DepsRefused:
        raise
    except (ValueError, RecursionError):
        raise DepsRefused(f"{lab}: not valid JSON") from None
    if not isinstance(doc, dict):
        raise DepsRefused(f"{lab}: top level is not a JSON object")
    version = doc.get("lockfileVersion")
    if isinstance(version, bool) or not isinstance(version, int) or version not in (2, 3):
        raise DepsRefused(f"{lab}: lockfileVersion {_a(version)} is not supported (2 or 3 needed; "
                          "regenerate with a current npm)")
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        raise DepsRefused(f"{lab}: no 'packages' object")
    if len(packages) - (1 if "" in packages else 0) > MAX_NPM_ENTRIES:
        raise DepsRefused(f"{lab}: more than {MAX_NPM_ENTRIES} package entries")
    found: set[tuple[str, str]] = set()
    for key, entry in packages.items():
        if key != "":
            if ".." in key.split("/"):
                raise DepsRefused(f"{lab}: package key {_a(key)} contains '..'")
            if not _NPM_KEY_RE.fullmatch(key):
                raise DepsRefused(f"{lab}: package key {_a(key)} is outside node_modules/ (workspace?) or malformed")
        item = _lock_entry(lab, key, entry)
        if item is not None:
            found.add(item)
    return sorted(found)
