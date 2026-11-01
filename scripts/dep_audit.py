#!/usr/bin/env python3
"""Dependency audit that runs no package tool (plan B1.5, step 7).

Plan: docs/plans/2026-10-27-sicherheitskette/PLAN-B15-deps.md. The inventory is read from files of
the PINNED git tree (the B1 snapshot, in memory -- never the working tree), parsed by plugin code
only (sandbox_deps: hashed requirements files and npm package-lock.json v2/v3), and every exact
name/version pair is asked of the OSV API by the deadline-killed worker of sandbox_fetch. The host
runs no pip, npm, pip-audit or osv-scanner.

    python -I "${CLAUDE_PLUGIN_ROOT}/scripts/dep_audit.py" --repo . --tree <sha> --scratch <dir> \
        --file <tree path> [--file <tree path>]... [--out dep-audit.json]

Classification: package-lock.json -> npm; the known unsupported lockfiles below -> refused by
name; every other file is a requirements file for the strict parser (requirements.lock and
locks/test.txt work, a file that is not one is refused by the parser).

Everything lands in a run directory of its own, <scratch>/dep-audit-<run id>/: the report (exclusive
create), audit-manifest.json (written on EVERY outcome once the directory exists, refusals included)
and the worker's job directory. The run directory is KEPT on every outcome: it is small and holds
the report, the manifest or the reason; after an unconfirmed worker kill it must be kept anyway.

Coverage, stated in the report: "only the dependency inventory in these files; no resolution".
Not covered ("no sandbox-safe audit yet"): yarn.lock, pnpm-lock.yaml, poetry.lock, uv.lock,
Pipfile.lock, unhashed requirements, Cargo, Go, Maven.

Exit codes: 0 complete, no known vulnerability; 1 complete, vulnerabilities found; 2 input refused;
5 infrastructure or incomplete (an unreadable plugin module -- the manifest's provenance -- is
always 5). Output lines (ASCII; non-ASCII characters of paths are backslash-escaped): RUN_DIR=,
TREE=, STATUS=, VULNERABLE_PACKAGES=, REPORT=, AUDIT_MANIFEST_SHA256=.

The report is rendered incrementally against its 16 MiB budget: every vulnerability entry is
counted as it is produced, so an advisory referenced by thousands of queries stops the rendering
at the budget (incomplete) instead of being expanded in full first. It is streamed into the
exclusively created report file (hashed on the way), so no second full copy of it exists; a
rendering that stops early removes the partial file. A report that cannot be written or closed
(disk full, I/O error) is incomplete (exit 5): the partial file is removed, and the outcome of
that removal is the manifest field report_cleanup. Memory bounds: see RENDER_AUX_BOUND.

The process exit code is the one main() chose, also when stdout or stderr failed: entry() puts
os.devnull under a failed stream before the interpreter's shutdown flush (which would otherwise
turn the exit code into 120) -- sandbox_run.settle_std_streams.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402
import sandbox_deps  # noqa: E402
import sandbox_fetch  # noqa: E402
import sandbox_run  # noqa: E402
import sandbox_snapshot  # noqa: E402

EXIT_CLEAN, EXIT_VULNERABLE, EXIT_REFUSED, EXIT_INFRA = 0, 1, 2, 5

COVERAGE = "only the dependency inventory in these files; no resolution"
ENDPOINTS = ["https://api.osv.dev/v1/querybatch", "https://api.osv.dev/v1/vulns/"]
DEADLINE_S = 300
MAX_FILES = 16
REPORT_CAP = 16 * 1024 * 1024
MAX_READ = sandbox_deps.MAX_LOCK_FILE
MANIFEST_NAME = "audit-manifest.json"
DEFAULT_OUT = "dep-audit.json"
OUT_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")
TREE_RE = sandbox_run.TREE_RE
SUMMARY_CAP = 500     # characters of an advisory summary in the report
SEVERITY_CAP = 160    # characters of a severity string (see _severity)
FIXED_CAP = 128       # characters of one fixed version
MAX_FIXED = 100       # fixed versions per vulnerability entry; more -> "fixed_truncated": true
# Memory of the renderer, stated as bounds that tests/test_dep_audit.py MEASURES (tracemalloc):
# - REPORT_MARGIN: the largest single piece appended before the budget check -- one vulnerability
#   entry (id <= 128, summary and severity escaped at <= 12 bytes a character, MAX_FIXED versions
#   of FIXED_CAP characters) or one package head, with its transient JSON encoding.
# - ENTRY_CACHE_CAP: rendered entries kept for reuse, charged with ENTRY_COST per entry for the
#   bytes header, key tuple and dict slot; beyond it entries are re-rendered.
# - INDEX_CAP: the advisory indexes, charged as they are built -- per queried package key
#   (INDEX_KEY_COST), per advisory (INDEX_VID_COST), per indexed package (INDEX_BUCKET_COST) and per
#   kept fixed version (its length + INDEX_ITEM_COST). Only the QUERIED packages are indexed and at
#   most MAX_FIXED + 1 versions are kept per package, so a real answer stays far below the cap; an
#   answer that would exceed it is incomplete, never rendered with an unbounded index.
# render_to holds, besides the OSV answer it reads, at most RENDER_AUX_BOUND. render_report (in
# memory) additionally holds the report buffer (<= REPORT_CAP plus 1/8 growth slack) and its joined
# copy (<= REPORT_CAP): RENDER_REPORT_BOUND.
REPORT_MARGIN = 2 * 1024 * 1024
ENTRY_CACHE_CAP = 4 * 1024 * 1024
ENTRY_COST = 256
INDEX_CAP = 6 * 1024 * 1024
INDEX_KEY_COST = 192
INDEX_VID_COST = 512
INDEX_BUCKET_COST = 512
INDEX_ITEM_COST = 64
RENDER_AUX_BOUND = REPORT_MARGIN + ENTRY_CACHE_CAP + INDEX_CAP
RENDER_REPORT_BOUND = 2 * REPORT_CAP + REPORT_CAP // 8 + RENDER_AUX_BOUND
VULN_ID_RE = sandbox_fetch.VULN_ID_RE
UNSUPPORTED_LOCKFILES = frozenset({
    "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock",
    "go.sum", "Gemfile.lock", "composer.lock"})


class Refused(Exception):
    """The input is at fault (exit 2)."""


class Incomplete(Exception):
    """The audit cannot be complete (exit 5)."""


def _ascii(text) -> str:
    """ASCII form of a message or path: non-ASCII characters backslash-escaped (stays traceable)."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


# --- inputs ----------------------------------------------------------------------------------

def classify(path: str) -> str:
    """'npm' for package-lock.json; a known unsupported lockfile is refused by name; every other
    file is 'pypi' -- a requirements file, which the strict parser accepts or refuses."""
    base = path.rsplit("/", 1)[-1]
    if base == "package-lock.json":
        return "npm"
    if base in UNSUPPORTED_LOCKFILES:
        raise Refused(f"no sandbox-safe audit yet: {_ascii(base)}")
    return "pypi"


def read_inputs(tar_bytes: bytes, entries: list, paths: list[str]) -> dict[str, tuple[bytes, str]]:
    """{path: (bytes, snapshot content_sha256)} for each path, read from the snapshot tar in memory.
    A path must be a regular-file ENTRY of the snapshot (absent, directory: refused) and its bytes
    must hash to the content hash the snapshot recorded."""
    known = {e[0]: e[2] for e in entries}
    out = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
            for path in paths:
                if path not in known:
                    raise Refused(f"{_ascii(path)} is not a regular file of the pinned tree")
                try:
                    member = tf.getmember(path)
                except KeyError:
                    raise Refused(f"{_ascii(path)} is not in the snapshot") from None
                if not member.isreg():
                    raise Refused(f"{_ascii(path)} is not a regular file of the pinned tree")
                if member.size > MAX_READ:
                    raise Refused(f"{_ascii(path)} is over the 16 MiB input limit")
                handle = tf.extractfile(member)
                data = handle.read(member.size + 1) if handle else b""
                digest = hashlib.sha256(data).hexdigest()
                if len(data) != member.size or digest != known[path]:
                    raise Incomplete(f"snapshot bytes of {_ascii(path)} do not match their recorded hash")
                out[path] = (data, digest)
    except tarfile.TarError as exc:
        raise Incomplete(f"snapshot tar unreadable: {_ascii(exc)}") from None
    return out


def build_queries(inputs: dict[str, tuple[bytes, str]]) -> list[list[str]]:
    """The deduplicated, sorted [ecosystem, name, version] list of every input.

    An audit lists inventory pairs; it resolves and installs nothing, so the files need not form
    one installable set (no merge): two files may pin different versions of a package, and equal
    versions with different hashes are one pair. Each requirements file still goes through the
    strict parser (unhashed or optioned -> refused)."""
    pairs = set()
    for path, (data, _digest) in sorted(inputs.items()):
        try:
            if classify(path) == "pypi":
                pairs.update(("PyPI", r.name, r.version)
                             for r in sandbox_deps.parse_requirements(data, path))
            else:
                pairs.update(("npm", n, v) for n, v in sandbox_deps.parse_package_lock(data, path))
        except sandbox_deps.DepsRefused as exc:
            raise Refused(str(exc)) from None
    return [list(p) for p in sorted(pairs)]


# --- the report ------------------------------------------------------------------------------

def _severity(doc: dict):
    spec = doc.get("database_specific")
    if isinstance(spec, dict) and isinstance(spec.get("severity"), str) and spec["severity"]:
        return spec["severity"][:64]
    sev = doc.get("severity")
    if isinstance(sev, list):
        for item in sev:
            if isinstance(item, dict) and isinstance(item.get("score"), str) and item["score"]:
                kind = item.get("type") if isinstance(item.get("type"), str) else "SEVERITY"
                return f"{kind[:16]}:{item['score'][:128]}"
    return None


def _no_charge(_amount: int) -> None:
    return None


def _keep_smallest(bucket: list[str], value: str, charge) -> None:
    """Insert `value` into the sorted distinct `bucket`, keeping only the MAX_FIXED + 1 smallest:
    enough for the first MAX_FIXED versions of the sorted distinct set and for knowing whether
    there were more (the `fixed_truncated` marker) -- so a bucket never grows with the document."""
    i = bisect.bisect_left(bucket, value)
    if i < len(bucket) and bucket[i] == value:
        return
    if len(bucket) > MAX_FIXED and i == len(bucket):
        return  # larger than every kept version of a full bucket
    charge(len(value) + INDEX_ITEM_COST)
    bucket.insert(i, value)
    if len(bucket) > MAX_FIXED + 1:
        charge(-(len(bucket.pop()) + INDEX_ITEM_COST))


def _fixed_index(doc: dict, wanted: dict | None = None, charge=_no_charge) -> dict[tuple[str, str], list[str]]:
    """{(ecosystem, package key): sorted distinct fixed versions, at most MAX_FIXED + 1} from
    affected[].ranges[].events[].fixed, built in ONE pass over the advisory (the package key is
    PEP 503-normalised for PyPI, verbatim for npm). Built once per advisory, so a query costs a
    lookup, not a walk of the document. With `wanted` ({key: key}) only those packages are kept;
    `charge(bytes)` is told every retained (positive) and released (negative) amount."""
    found: dict[tuple[str, str], list[str]] = {}
    affected = doc.get("affected")
    for aff in affected if isinstance(affected, list) else []:
        pkg = aff.get("package") if isinstance(aff, dict) else None
        if not isinstance(pkg, dict):
            continue
        eco, pname = pkg.get("ecosystem"), pkg.get("name")
        if not isinstance(eco, str) or not isinstance(pname, str):
            continue
        key = (eco, sandbox_deps.normalize_name(pname) if eco == "PyPI" else pname)
        if wanted is not None:
            key = wanted.get(key)
            if key is None:
                continue
        bucket = found.get(key)
        if bucket is None:
            charge(INDEX_BUCKET_COST)
            bucket = found[key] = []
        ranges = aff.get("ranges")
        for rng in ranges if isinstance(ranges, list) else []:
            events = rng.get("events") if isinstance(rng, dict) else None
            for ev in events if isinstance(events, list) else []:
                fixed = ev.get("fixed") if isinstance(ev, dict) else None
                if isinstance(fixed, str) and fixed:
                    _keep_smallest(bucket, fixed[:FIXED_CAP], charge)
    return found


def _fixed(doc: dict, eco: str, name: str) -> list[str]:
    """Fixed versions (at most MAX_FIXED + 1, sorted) for entries naming this package."""
    return _fixed_index(doc).get((eco, name), [])


def _j(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def render_to(sink, tree: str, inputs: list, queries: list[list[str]], answer: dict) -> int:
    """Render the report piece by piece into `sink(piece: bytes)` and return the number of
    vulnerable packages. One package per line; every vulnerability entry is counted against
    REPORT_CAP as it is appended, so once the budget is spent the rendering stops (Incomplete) --
    an advisory referenced by many queries is never expanded in full first. Nothing here keeps a
    piece after handing it to the sink: the run streams into the exclusively created report file,
    so no second full copy of the report exists.

    Memory besides the OSV answer: at most RENDER_AUX_BOUND -- one piece (REPORT_MARGIN), the
    entry cache (ENTRY_CACHE_CAP, charged with ENTRY_COST per entry) and the advisory indexes
    (INDEX_CAP, charged as they are built: queried keys, distinct ids, advisories, packages, kept
    versions). An index holds only the queried packages and is dropped (its charge released) once
    the last query referencing its advisory is rendered; an answer whose live indexes would exceed
    INDEX_CAP is incomplete. Measured in tests/test_dep_audit.py.

    One result per query, in query order; a result list that does not match the queries, a
    malformed id, or an id without details is incomplete -- never clean (plan step 7)."""
    results, details = answer.get("results"), answer.get("details")
    if not isinstance(results, list) or len(results) != len(queries) or not isinstance(details, dict):
        raise Incomplete("the OSV answer does not hold exactly one result per query")
    cap = REPORT_CAP
    total = 0
    indexed = 0

    def add(piece: bytes) -> None:
        nonlocal total
        total += len(piece)
        if total > cap:
            raise Incomplete("the report is over the 16 MiB cap")
        sink(piece)

    def charge(amount: int) -> None:
        nonlocal indexed
        indexed += amount
        if indexed > INDEX_CAP:
            raise Incomplete(f"the advisory index is over its {INDEX_CAP // (1024 * 1024)} MiB cap")

    wanted: dict[tuple[str, str], tuple[str, str]] = {}  # the queried package keys, canonical tuples
    pending: dict[str, int] = {}  # vid -> queries still to render that reference it
    for (eco, name, _version), ids in zip(queries, results):
        if not isinstance(ids, list) or not all(isinstance(v, str) and VULN_ID_RE.fullmatch(v) for v in ids):
            raise Incomplete("the OSV answer holds a malformed result")
        if (eco, name) not in wanted:
            charge(INDEX_KEY_COST)
            wanted[(eco, name)] = (eco, name)
        for vid in set(ids):
            if vid not in pending:
                charge(INDEX_KEY_COST)
                pending[vid] = 0
            pending[vid] += 1
    indexes: dict[str, dict] = {}      # vid -> fixed-version index of the queried packages
    index_cost: dict[str, int] = {}    # vid -> what its index was charged (released on drop)
    entries: dict[tuple, bytes] = {}   # (vid, eco, name) -> rendered entry; each counted per use
    cached = 0
    vulnerable = 0
    add(b'{"coverage":' + _j(COVERAGE) + b',"inputs":' + _j(inputs) + b',"packages":[')
    for i, ((eco, name, version), ids) in enumerate(zip(queries, results)):
        add((b"\n" if i == 0 else b",\n") + b'{"ecosystem":' + _j(eco) + b',"name":' + _j(name)
            + b',"version":' + _j(version) + b',"vulns":[')
        for k, vid in enumerate(sorted(set(ids))):
            entry = entries.get((vid, eco, name))
            if entry is None:
                doc = details.get(vid)
                if not isinstance(doc, dict):
                    raise Incomplete(f"no details for vulnerability {_ascii(vid)}")
                if vid not in indexes:
                    before = indexed
                    charge(INDEX_VID_COST)
                    indexes[vid] = _fixed_index(doc, wanted, charge)
                    index_cost[vid] = indexed - before
                fixed = indexes[vid].get((eco, name), [])
                summary = doc.get("summary")
                item = {"id": vid, "summary": summary[:SUMMARY_CAP] if isinstance(summary, str) else "",
                        "severity": _severity(doc), "fixed": fixed[:MAX_FIXED]}
                if len(fixed) > MAX_FIXED:
                    item["fixed_truncated"] = True
                entry = _j(item)
                if cached + len(entry) + ENTRY_COST <= ENTRY_CACHE_CAP:
                    entries[(vid, eco, name)] = entry
                    cached += len(entry) + ENTRY_COST
            add((b"," if k else b"") + entry)
            pending[vid] -= 1
            if not pending[vid] and vid in indexes:  # no later query needs this advisory
                del indexes[vid]
                charge(-index_cost.pop(vid))
        add(b"]}")
        vulnerable += bool(ids)
    add(b'\n],"status":"complete","tree":' + _j(tree) + b"}\n")
    return vulnerable


def render_report(tree: str, inputs: list, queries: list[list[str]], answer: dict) -> tuple[bytes, int]:
    """The whole report in memory (tests and small callers): render_to into one buffer, then take
    its bytes. Memory: the buffer (<= REPORT_CAP plus up to 1/8 growth slack), its joined copy
    (<= REPORT_CAP; CPython usually hands the buffer over without copying, the bound does not rely
    on it) and render_to's own RENDER_AUX_BOUND -- at most RENDER_REPORT_BOUND, measured in
    tests/test_dep_audit.py. The run itself streams (render_to) and holds no copy of the report."""
    buf = io.BytesIO()
    vulnerable = render_to(buf.write, tree, inputs, queries, answer)
    return buf.getvalue(), vulnerable


def dump(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("ascii")


# --- the run ---------------------------------------------------------------------------------

class _State:
    def __init__(self):
        self.run_id = sandbox_fetch.new_run_id()
        self.scratch: Path | None = None
        self.run_dir: Path | None = None
        self.tree: str | None = None
        self.inputs: list[dict] = []
        self.inventory_sha256: str | None = None
        self.report_sha256: str | None = None
        self.report_name: str | None = None
        self.quarantine: dict | None = None
        self.report_cleanup: str | None = None  # set when a partial report had to be removed
        self.vulnerable = 0

    def manifest(self, status: str, reason: str = "", files: dict | None = None) -> dict:
        """The manifest document; `files` is the provenance (None: it could not be read)."""
        doc = {"run_id": self.run_id, "tree": self.tree, "inputs": self.inputs,
               "inventory_sha256": self.inventory_sha256,
               "helper_sha256": files.get("dep_audit.py") if files else None,
               "plugin_files": files, "endpoints": ENDPOINTS, "status": status,
               "report_sha256": self.report_sha256}
        if reason:
            doc["reason"] = _ascii(reason)[:300]
        if self.quarantine:
            doc["quarantine"] = self.quarantine
        if self.report_cleanup:
            doc["report_cleanup"] = self.report_cleanup
        return doc

    def write_manifest(self, status: str, reason: str = "") -> tuple[str | None, str, str]:
        """Write the manifest; returns (sha256 or None, effective status, provenance problem or "").

        Construction is guarded as a whole: an unreadable plugin module turns the outcome into
        `incomplete` with the reason recorded (the code that ran cannot be identified, so nothing
        here is evidence), and a manifest that cannot be built or written returns None -- never a
        traceback, also not while another failure is being reported."""
        if self.run_dir is None:
            return None, status, ""
        problem = ""
        try:
            files = plugin_files()
        except (OSError, ValueError) as exc:
            files = None
            problem = f"plugin provenance unreadable: {_ascii(exc)}"
            status = "incomplete"
            reason = f"{problem}; {reason}" if reason else problem
        try:
            data = dump(self.manifest(status, reason, files))
            hunt_io.create_file(self.run_dir, MANIFEST_NAME, data, base=self.scratch)
        except (hunt_io.HuntIOError, OSError, TypeError, ValueError):
            return None, status, problem
        return hashlib.sha256(data).hexdigest(), status, problem


def plugin_module_names() -> list[str]:
    """File names of every plugin module this helper loads: the import closure of dep_audit.py
    inside scripts/, read from the import statements (not from sys.modules, which would depend on
    what else the process loaded)."""
    here = Path(__file__).resolve().parent
    todo, seen = ["dep_audit"], set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        try:
            tree = ast.parse((here / f"{name}.py").read_bytes())
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                    else [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module
                    else [])
            for mod in mods:
                top = mod.split(".")[0]
                if (here / f"{top}.py").is_file():
                    todo.append(top)
    return sorted(f"{n}.py" for n in seen)


def plugin_files() -> dict[str, str]:
    """{module file name: sha256 of its bytes} -- the plugin ships no version field, so the code
    that ran is identified by the digests of every module it loaded."""
    here = Path(__file__).resolve().parent
    return {n: hashlib.sha256((here / n).read_bytes()).hexdigest() for n in plugin_module_names()}


def run(args, state: _State) -> int:
    state.scratch = Path(os.path.abspath(args.scratch))
    if state.scratch.is_dir():
        for line in sandbox_fetch.list_quarantine(state.scratch):
            _diagnostic(lambda q=line: f"dep_audit: {_ascii(q)}\n")
        state.run_dir = hunt_io.make_dir(state.scratch, f"dep-audit-{state.run_id}", base=state.scratch)
    else:
        raise Refused("--scratch must be an existing directory")
    if TREE_RE.fullmatch(args.tree or ""):
        state.tree = args.tree
    else:
        raise Refused("--tree must be a full tree id")
    if not args.file:
        raise Refused("at least one --file is required")
    if len(args.file) > MAX_FILES:
        raise Refused(f"at most {MAX_FILES} --file")
    out_name = args.out
    if not OUT_NAME_RE.fullmatch(out_name) or out_name == MANIFEST_NAME:
        raise Refused("--out must be a plain file name other than " + MANIFEST_NAME)
    paths = [sandbox_snapshot.canonical_path(p) for p in args.file]
    if len(set(paths)) != len(paths):
        raise Refused("--file names the same path twice")
    for path in paths:
        classify(path)  # refuses before any git object is read

    work = hunt_io.make_dir(state.run_dir, "snapshot", base=state.scratch)
    try:
        info, tar_bytes = sandbox_run.supervised_snapshot(Path(os.path.abspath(args.repo)), state.tree,
                                                          None, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    inputs = read_inputs(tar_bytes, info["entries"], paths)
    state.inputs = [{"path": p, "content_sha256": inputs[p][1]} for p in paths]
    queries = build_queries(inputs)
    state.inventory_sha256 = hashlib.sha256(
        json.dumps(queries, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if len(queries) > sandbox_fetch.OSV_MAX_QUERIES:
        raise Refused(f"{len(queries)} packages exceed the budget of {sandbox_fetch.OSV_MAX_QUERIES}")

    if queries:
        job_dir = hunt_io.make_dir(state.run_dir, "osv", base=state.scratch)
        job = {"kind": "osv", "queries": queries, "max_queries": sandbox_fetch.OSV_MAX_QUERIES,
               "max_details": sandbox_fetch.OSV_MAX_DETAILS,
               "max_total_bytes": sandbox_fetch.OSV_MAX_TOTAL_BYTES}
        answer = sandbox_fetch.run_job(job, job_dir, DEADLINE_S, state.scratch, state.run_id)
    else:
        answer = {"results": [], "details": {}}
    digest = hashlib.sha256()
    fh = hunt_io.open_new(state.run_dir, out_name, base=state.scratch)

    def sink(piece: bytes) -> None:
        digest.update(piece)
        try:
            fh.write(piece)
        except OSError as exc:  # disk full, quota, I/O error: the report cannot be written
            raise _ReportIOError("write", exc) from None
    try:
        try:
            vulnerable = render_to(sink, state.tree, state.inputs, queries, answer)
        except BaseException:
            _close_quietly(fh)
            raise
        try:
            fh.close()  # the last buffered bytes reach the file here: a failure is a lost report
        except OSError as exc:
            raise _ReportIOError("close", exc) from None
    except BaseException as exc:
        state.report_cleanup = _remove_partial_report(state, out_name)  # a partial report is not a report
        if isinstance(exc, _ReportIOError):
            raise Incomplete(f"the report could not be written ({exc.step}: {_ascii(exc.error)}); "
                             f"partial report {state.report_cleanup}") from None
        raise
    state.report_name = out_name
    state.report_sha256 = digest.hexdigest()
    state.vulnerable = vulnerable
    return EXIT_VULNERABLE if state.vulnerable else EXIT_CLEAN


class _ReportIOError(Exception):
    """Writing or closing the report file failed; run() turns it into Incomplete (exit 5)."""

    def __init__(self, step: str, error: OSError):
        super().__init__(f"{step}: {error}")
        self.step, self.error = step, error


def _close_quietly(fh) -> None:
    """Close the report file while another failure is already on its way: a second error (the
    flush of the remaining bytes on a full disk) must not replace the first one. CPython closes
    the descriptor even when that flush fails, so the partial file can still be removed."""
    try:
        fh.close()
    except OSError:
        pass


def _remove_partial_report(state: _State, out_name: str) -> str:
    """Remove a partial report; the outcome ("removed" or "failed: <reason>") goes to the
    manifest field report_cleanup -- a partial file left behind is named, never silent."""
    try:
        hunt_io.remove_file(state.run_dir, out_name, base=state.scratch)
    except (hunt_io.HuntIOError, OSError) as exc:
        reason = f"failed: {_ascii(exc)}"[:200]
        _diagnostic(lambda: f"dep_audit: the partial report {_ascii(state.run_dir / out_name)} "
                            f"could not be removed ({reason})\n")
        return reason
    return "removed"


def _diagnostic(line) -> None:
    """Write one diagnostic line to stderr, best effort -- as sandbox_fetch._diagnostic: a full
    redirected log (OSError) or a closed stream (ValueError) is swallowed. An exception escaping
    from a log line would end the process with exit 1, which here reads as "vulnerable", and
    would lose the manifest with its quarantine fields. `line` is a callable so that formatting
    errors are covered too."""
    try:
        sys.stderr.write(line())
    except Exception:  # noqa: BLE001 - the diagnostic is optional, the outcome is not
        return


def _emit(lines: list[str]) -> bool:
    """Write the KEY=value result lines to stdout and flush; False when that fails."""
    try:
        sys.stdout.write("".join(f"{line}\n" for line in lines))
        sys.stdout.flush()
    except Exception:  # noqa: BLE001 - every failure of the stream means the same: not delivered
        return False
    return True


def finish(state: _State, status: str, code: int, reason: str = "") -> int:
    """Write the manifest first, then the result lines. Exit 0 or 1 needs both: without the
    manifest there is no evidence, and without the stdout lines the caller cannot read the
    result -- either is exit 5. A refusal (2) or an infrastructure failure (5) keeps its code."""
    digest, status, problem = state.write_manifest(status, reason)
    if problem:
        _diagnostic(lambda: f"dep_audit: INCOMPLETE - {problem}\n")
        code = EXIT_INFRA  # the code that ran cannot be identified: never a pass, never a refusal
    lines = []
    if state.run_dir is not None:
        lines.append(f"RUN_DIR={_ascii(state.run_dir)}")
    lines += [f"TREE={state.tree if state.tree else '-'}", f"STATUS={status}",
              f"VULNERABLE_PACKAGES={state.vulnerable}"]
    if state.report_name and state.run_dir is not None:
        lines.append(f"REPORT={_ascii(state.run_dir / state.report_name)}")
    if digest:
        lines.append(f"AUDIT_MANIFEST_SHA256={digest}")
    delivered = _emit(lines)
    if not delivered:
        _diagnostic(lambda: "dep_audit: INCOMPLETE - the result lines could not be written to stdout\n")
    if not digest and state.run_dir is not None:
        _diagnostic(lambda: "dep_audit: the audit manifest could not be written\n")
        if code in (EXIT_CLEAN, EXIT_VULNERABLE):
            return EXIT_INFRA  # no manifest, no evidence: never a pass
    if not delivered and code in (EXIT_CLEAN, EXIT_VULNERABLE):
        return EXIT_INFRA  # the caller cannot read the result: never a pass, never a finding
    return code


def parse_args(argv):
    ap = argparse.ArgumentParser(description="dependency audit without package tools (plan B1.5)")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--tree", required=True, help="the pinned git tree id")
    ap.add_argument("--scratch", required=True, help="the session scratch dir; the run dir goes below it")
    ap.add_argument("--file", action="append", default=[], help="tree path of a lockfile/requirements")
    ap.add_argument("--out", default=DEFAULT_OUT, help="report file name inside the run dir")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_REFUSED if exc.code else EXIT_CLEAN
    state = _State()
    try:
        code = run(args, state)
        return finish(state, "complete", code)
    except (Refused, sandbox_run.Refused, sandbox_snapshot.SnapshotRefused,
            hunt_io.HuntIOError, sandbox_fetch.FetchRefused) as exc:
        _diagnostic(lambda e=exc: f"dep_audit: REFUSED - {_ascii(e)}\n")
        return finish(state, "refused", EXIT_REFUSED, str(exc))
    except sandbox_fetch.FetchUnconfirmed as exc:
        record = getattr(exc, "record", None)
        state.quarantine = {"path": str(exc.path), "pid": exc.pid,
                            "record": str(record) if record else None,
                            "deadline_epoch": getattr(exc, "deadline_epoch", None),
                            "cleanup": "unconfirmed"}
        _diagnostic(lambda e=exc: f"dep_audit: INFRASTRUCTURE - {_ascii(e)}; worker pid {e.pid} not "
                                  f"confirmed dead, directory {_ascii(e.path)} left in place (remove "
                                  f"by hand after checking that the pid is gone)\n")
        return finish(state, "incomplete", EXIT_INFRA, str(exc))
    except (Incomplete, sandbox_fetch.FetchInfrastructure, sandbox_run.Infrastructure,
            sandbox_snapshot.SnapshotInfrastructure) as exc:
        _diagnostic(lambda e=exc: f"dep_audit: INCOMPLETE - {_ascii(e)}\n")
        return finish(state, "incomplete", EXIT_INFRA, str(exc))


def entry(argv=None) -> int:
    """The process entry point: main(), then sandbox_run.settle_std_streams() -- a stream whose
    write failed would otherwise fail again in the interpreter's shutdown flush, which turns the
    process exit code into 120 (neither 5 nor 2). See settle_std_streams for the remedy."""
    code = main(argv)
    sandbox_run.settle_std_streams()
    return code


if __name__ == "__main__":
    sys.exit(entry())
