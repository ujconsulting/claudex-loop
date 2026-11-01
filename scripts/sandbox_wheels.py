#!/usr/bin/env python3
"""Wheel tags, wheel file-name grammar and selection by pinned hash (plan B1.5, step 3).

Part of plan B1.5 (docs/plans/2026-10-27-sicherheitskette/PLAN-B15-deps.md). Pure functions, stdlib
only, no I/O: the network worker (sandbox_fetch.py) hands in the decoded PEP 691 JSON of PyPI's simple
index and gets back which file to download. Nothing here opens a wheel; only names and hashes.

Decisions beyond the plan text:

* Priority order. The plan lists the tag groups ("cp313-cp313-P, cp313-abi3-P, ...") "for each platform
  P in policy order". Read here as: group outer, platform inner, so a more specific interpreter/ABI
  group always beats a more generic one, whatever the platform; within a group the policy's platform
  order decides. The platform "any" is combined only with the ABI "none" (cp313-cp313-any would be
  meaningless), and only when the policy lists it.
* Yanked files. A yanked file whose sha256 is pinned is still the artifact the requirements file
  names, so it stays a candidate, and the yank status is not read at all: among candidates of
  equal tag priority the file name alone decides, as the interface specifies (gate A1-1 removed an
  earlier non-yanked-first tie-break that the plan never approved).
* Resource bounds. parse_wheel_filename refuses a name over MAX_WHEEL_FILENAME characters, a tag
  field with more than MAX_TAG_COMPONENTS components and a product over MAX_TAG_TRIPLES, each
  before anything is split or expanded, so a hostile index entry cannot make the host build a
  huge set (gate A1-8). select_wheel skips such a name like any other unparsable one.
* A candidate whose url is not under https://files.pythonhosted.org/ is skipped like an incompatible
  one; if nothing else remains the requirement is refused. A file name that does not parse as a wheel
  is skipped the same way (sdists, eggs, junk), because only hash-listed names matter.
* Only the sha256 entry of `hashes` is read; other algorithms are ignored.
"""
from __future__ import annotations

import re

__all__ = ["WheelRefused", "accepted_tags", "parse_wheel_filename", "select_wheel"]

PYPI_FILES_PREFIX = "https://files.pythonhosted.org/"

# Bounds checked BEFORE the compressed tag sets are expanded (gate A1-8): an index entry controls
# the file name, and {py}-{abi}-{platform} with dot-separated components is a Cartesian product.
# 255 is NAME_MAX of every file system the wheel is saved on (sandbox_fetch's WHEEL_FILE_RE allows
# no more either); the widest real tag sets have 2 python tags, 3 macOS or 4 manylinux platforms.
MAX_WHEEL_FILENAME = 255
MAX_TAG_COMPONENTS = 16
MAX_TAG_TRIPLES = 256

_PY_RE = re.compile(r"3\.(0|[1-9][0-9]{0,2})")
_PLATFORM_RE = re.compile(r"[A-Za-z0-9_]+")
_TAG_RE = re.compile(r"[A-Za-z0-9_]+")
_DIST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._]*[A-Za-z0-9])?")
_VERSION_RE = re.compile(r"[A-Za-z0-9_.+!]+")
_BUILD_RE = re.compile(r"[0-9][A-Za-z0-9_.]*")
_API_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_NORM_RE = re.compile(r"[-_.]+")
_URL_BAD = re.compile(r"[^\x21-\x7e]|\\")


class WheelRefused(Exception):
    """The input is at fault: a bad wheel name, an unsupported index version, no usable wheel."""


def _norm(name: str) -> str:
    return _NORM_RE.sub("-", name).lower()


def _ascii(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")


def accepted_tags(target: dict) -> list[tuple[str, str, str]]:
    """Return the accepted (python, abi, platform) triples, best first, for a policy wheel_target."""
    if not isinstance(target, dict):
        raise ValueError("wheel_target must be an object")
    py = target.get("python")
    platforms = target.get("platforms")
    if not isinstance(py, str) or not _PY_RE.fullmatch(py):
        raise ValueError("wheel_target.python must look like '3.13'")
    if (not isinstance(platforms, list) or not platforms
            or not all(isinstance(p, str) and _PLATFORM_RE.fullmatch(p) for p in platforms)
            or len(set(platforms)) != len(platforms)):
        raise ValueError("wheel_target.platforms must be a non-empty list of distinct platform tags")
    minor = int(py.split(".")[1])
    cp = f"cp3{minor}"
    groups: list[tuple[str, str]] = [(cp, cp), (cp, "abi3")]
    groups += [(f"cp3{x}", "abi3") for x in range(minor - 1, 1, -1)]
    groups += [(cp, "none"), (f"py3{minor}", "none"), ("py3", "none")]
    groups += [(f"py3{x}", "none") for x in range(minor - 1, -1, -1)]
    out: list[tuple[str, str, str]] = []
    for tag_py, abi in groups:
        for plat in platforms:
            if plat == "any" and abi != "none":
                continue
            out.append((tag_py, abi, plat))
    return out


def parse_wheel_filename(filename: str) -> tuple[str, str, str | None, frozenset]:
    """Parse {dist}-{version}(-{build})?-{py}-{abi}-{platform}.whl into
    (normalised name, version, build tag or None, expanded tag triples)."""
    if not isinstance(filename, str):
        raise WheelRefused("wheel file name is not a string")
    shown = _ascii(filename[:120])
    if len(filename) > MAX_WHEEL_FILENAME:
        raise WheelRefused(f"wheel file name is {len(filename)} characters, over the limit of "
                           f"{MAX_WHEEL_FILENAME}: {shown!r}...")
    if not filename.endswith(".whl"):
        raise WheelRefused(f"not a wheel file name: {shown!r}")
    stem = filename[:-4]
    parts = stem.split("-")
    if len(parts) not in (5, 6):
        raise WheelRefused(f"wheel file name has {len(parts)} fields, expected 5 or 6: {shown!r}")
    if any(p == "" for p in parts):
        raise WheelRefused(f"wheel file name has an empty field: {shown!r}")
    dist, version = parts[0], parts[1]
    build = parts[2] if len(parts) == 6 else None
    py_f, abi_f, plat_f = parts[-3], parts[-2], parts[-1]
    if not _DIST_RE.fullmatch(dist):
        raise WheelRefused(f"bad distribution field in wheel file name: {shown!r}")
    if not _VERSION_RE.fullmatch(version):
        raise WheelRefused(f"bad version field in wheel file name: {shown!r}")
    if build is not None and not _BUILD_RE.fullmatch(build):
        raise WheelRefused(f"bad build tag in wheel file name: {shown!r}")
    sets = []
    product = 1
    for field in (py_f, abi_f, plat_f):
        count = field.count(".") + 1
        if count > MAX_TAG_COMPONENTS:
            raise WheelRefused(f"wheel file name has {count} components in one tag field, over the "
                               f"limit of {MAX_TAG_COMPONENTS}: {shown!r}")
        product *= count
        if product > MAX_TAG_TRIPLES:
            raise WheelRefused(f"wheel file name expands to more than {MAX_TAG_TRIPLES} tag triples: "
                               f"{shown!r}")
        items = field.split(".")
        if not all(_TAG_RE.fullmatch(i) for i in items):
            raise WheelRefused(f"bad tag field in wheel file name: {shown!r}")
        sets.append(items)
    tags = frozenset((a, b, c) for a in sets[0] for b in sets[1] for c in sets[2])
    return _norm(dist), version, build, tags


def _check_index(index: object) -> list[dict]:
    """Validate the PEP 691 structure; WheelRefused for a foreign major, ValueError if malformed."""
    if not isinstance(index, dict):
        raise ValueError("index is not a JSON object")
    meta = index.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("index has no meta object")
    api = meta.get("api-version")
    if not isinstance(api, str) or not _API_RE.fullmatch(api):
        raise ValueError("index meta.api-version is missing or malformed")
    if int(api.split(".")[0]) != 1:
        raise WheelRefused(f"index api-version {api} is not supported (major 1 required)")
    files = index.get("files")
    if not isinstance(files, list):
        raise ValueError("index has no files list")
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("index files entry is not an object")
        if not isinstance(item.get("filename"), str) or not isinstance(item.get("url"), str):
            raise ValueError("index files entry lacks filename or url")
        hashes = item.get("hashes")
        if not isinstance(hashes, dict):
            raise ValueError("index files entry lacks a hashes object")
        if "sha256" in hashes and not isinstance(hashes["sha256"], str):
            raise ValueError("index sha256 hash is not a string")
    return files


def _url_ok(url: str) -> bool:
    return (url.startswith(PYPI_FILES_PREFIX) and len(url) > len(PYPI_FILES_PREFIX)
            and not _URL_BAD.search(url))


def select_wheel(index: dict, name: str, version: str, hashes: frozenset, target: dict) -> dict:
    """Pick the file for name==version whose sha256 is in `hashes`: best tag priority, ties by
    file name. Returns {"filename", "url", "sha256"}."""
    if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
        raise ValueError("name and version must be non-empty strings")
    if not hashes or not all(isinstance(h, str) for h in hashes):
        raise ValueError("hashes must be a non-empty set of strings")
    priority = {t: i for i, t in enumerate(accepted_tags(target))}
    files = _check_index(index)
    want = _norm(name)
    best = None
    skipped_url = 0
    for item in files:
        sha = item["hashes"].get("sha256")
        if sha not in hashes or not _SHA_RE.fullmatch(sha):
            continue
        try:
            dist, ver, _build, tags = parse_wheel_filename(item["filename"])
        except WheelRefused:
            continue
        if dist != want or ver != version:
            continue
        ranks = [priority[t] for t in tags if t in priority]
        if not ranks:
            continue
        if not _url_ok(item["url"]):
            skipped_url += 1
            continue
        key = (min(ranks), item["filename"])
        if best is None or key < best[0]:
            best = (key, item, sha)
    if best is None:
        extra = f"; {skipped_url} candidate(s) had a url outside files.pythonhosted.org" if skipped_url else ""
        raise WheelRefused(
            f"{_ascii(want)}=={_ascii(version)}: no wheel for the image's platform among the pinned "
            f"hashes (sdist-only releases land here; nothing is built){extra}")
    _key, item, sha = best
    return {"filename": item["filename"], "url": item["url"], "sha256": sha}
