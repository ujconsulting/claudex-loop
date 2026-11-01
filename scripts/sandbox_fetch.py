#!/usr/bin/env python3
"""Network access for B1.5: wheel downloads and OSV queries in a deadline-killed worker.

Plan: docs/plans/2026-10-27-sicherheitskette/PLAN-B15-deps.md (approved round 6), steps 3 and 7;
names fixed in B15-interfaces.md, section "scripts/sandbox_fetch.py (unit C)".

This is the only code on the host that talks to the network on behalf of a repository under
review. It runs no package tool and never opens a wheel: it hashes bytes and writes them.

  worker   `python -I -S sandbox_fetch.py --worker <job.json>`, started by run_job(). Reads the
           job, does every HTTP request, writes worker-result.json (exclusive create) into the
           job's directory. It starts no process.
  http     https only; an exact host allowlist per job kind (no userinfo, no port); every
           redirect raises; environment proxies ignored (ProxyHandler({})); TLS verified with
           ssl.create_default_context(); no cookies, no credentials; 30 s socket timeout; every
           response read in chunks of at most 64 KiB with its cap enforced WHILE reading (the
           read stops at cap + 1) and sha256 computed while streaming.
  parent   run_job() waits with the total deadline, then kills (POSIX: the worker's whole
           session) and waits at most 5 s for the reap. A worker that cannot be confirmed dead
           leaves its directory in place and gets a quarantine record
           <scratch>/claudex-quarantine/<run id>.json; nothing here ever deletes, renames or
           follows a recorded path. verify_download() re-reads every file itself and trusts
           nothing the worker reported.

    python -I -S scripts/sandbox_fetch.py --worker <job.json>     (started by run_job only)

Messages are ASCII only.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402
import sandbox_deps  # noqa: E402
import sandbox_wheels  # noqa: E402

# --- shared names ----------------------------------------------------------------------------

RUN_ID_RE = re.compile(r"[0-9a-f]{16}")  # what secrets.token_hex(8) generates; fullmatch only


def new_run_id() -> str:
    return secrets.token_hex(8)


class FetchRefused(Exception):
    """The input is at fault (exit 2)."""


class FetchInfrastructure(Exception):
    """Network, server or worker failure, or an incomplete answer (exit 5)."""


class FetchUnconfirmed(FetchInfrastructure):
    """The worker could not be confirmed dead; its directory is quarantined in place.

    `deadline_epoch` is the exact float run_job computed once and wrote into the quarantine
    record (also when the record could not be written); callers copy it, never recompute it."""

    def __init__(self, message: str, pid: int, path: Path, record: Path | None,
                 deadline_epoch: float | None = None):
        super().__init__(message)
        self.pid = pid
        self.path = path
        self.record = record
        self.deadline_epoch = None if deadline_epoch is None else float(deadline_epoch)


# --- limits ----------------------------------------------------------------------------------

MiB = 1024 * 1024
CHUNK = 64 * 1024
SOCKET_TIMEOUT = 30
KILL_WAIT = 5.0
INDEX_CAP = 8 * MiB
PEP691 = "application/vnd.pypi.simple.v1+json"
OSV_BATCH = 1000
OSV_MAX_PAGES = 10
OSV_RESPONSE_CAP = 32 * MiB
OSV_DETAIL_CAP = 1 * MiB
OSV_MAX_QUERIES = 10000
OSV_MAX_DETAILS = 2000
OSV_MAX_TOTAL_BYTES = 64 * MiB
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_ECOSYSTEMS = frozenset({"PyPI", "npm"})
VULN_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
WHEEL_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,250}\.whl")
JOB_CAP = 16 * MiB
RESULT_CAP = 96 * MiB
RECORD_CAP = 64 * 1024
MAX_RECORDS_LISTED = 1000
MAX_REASON = 500

WHEEL_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})
OSV_HOSTS = frozenset({"api.osv.dev"})
DOWNLOAD_HOSTS = frozenset({"files.pythonhosted.org"})

JOB_NAME = "job.json"
RESULT_NAME = "worker-result.json"
STDOUT_NAME = "worker-stdout.txt"
STDERR_NAME = "worker-stderr.txt"
WORKER_FILES = frozenset({JOB_NAME, RESULT_NAME, STDOUT_NAME, STDERR_NAME})
QUARANTINE_DIR = "claudex-quarantine"


def _esc(value) -> str:
    """Any value as one ASCII line of data: quoted, every control/non-ASCII char escaped."""
    return ascii(value if isinstance(value, str) else str(value))


def _reason(text: str) -> str:
    text = str(text).encode("ascii", "backslashreplace").decode("ascii")
    text = "".join(c if 32 <= ord(c) < 127 else "?" for c in text)
    return text[:MAX_REASON]


# --- HTTP ------------------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Every redirect raises; nothing is ever followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchRefused(f"redirect refused: HTTP {code} from {_esc(req.full_url)}")


def _build_opener() -> urllib.request.OpenerDirector:
    """An opener with exactly these handlers: no plain HTTP, file, ftp, data or unknown-scheme
    handler, no cookie or auth processor, no environment proxy, and no redirect following.
    (build_opener() would add HTTPHandler, FileHandler, FTPHandler, DataHandler and
    UnknownHandler; the URL check refuses those schemes anyway, this removes them too.)"""
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
                    _NoRedirect(),
                    urllib.request.HTTPDefaultErrorHandler(),
                    urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener


_OPENER: urllib.request.OpenerDirector | None = None


def _open(request: urllib.request.Request, timeout: float):
    """The one place a request leaves the process (tests replace this function)."""
    global _OPENER
    if _OPENER is None:
        _OPENER = _build_opener()
    return _OPENER.open(request, timeout=timeout)


def check_url(url: str, hosts: frozenset) -> str:
    """Refuse anything but https://<exact allowed host>/... without userinfo or port."""
    if not isinstance(url, str) or not url.isascii() or any(c <= " " or c == "\x7f" for c in url):
        raise FetchRefused(f"refusing URL {_esc(url)}: not a plain ASCII URL")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not url.startswith("https://"):
        raise FetchRefused(f"refusing URL {_esc(url)}: https only")
    if parts.netloc not in hosts:  # exact: no userinfo, no port (not even :443), no case games
        raise FetchRefused(f"refusing URL {_esc(url)}: host not allowed")
    return parts.netloc


def _read_bounded(resp, cap: int, over_cap, sink=None) -> tuple[bytes | None, int, str]:
    """Read resp in chunks <= CHUNK, never more than cap + 1 bytes in total; raise over_cap()
    when the body exceeds cap. With `sink`, bytes are written there (never beyond cap) and
    not kept. Returns (body or None, size, sha256 hex)."""
    length = None
    headers = getattr(resp, "headers", None)
    if headers is not None:
        raw = headers.get("Content-Length")
        if raw is not None:
            try:
                length = int(raw)
            except ValueError:
                raise FetchInfrastructure("malformed Content-Length") from None
    if length is not None and length > cap:
        raise over_cap()
    digest = hashlib.sha256()
    chunks, total = [], 0
    while True:
        block = resp.read(min(CHUNK, cap + 1 - total))
        if not block:
            break
        total += len(block)
        if total > cap:
            raise over_cap()
        digest.update(block)
        if sink is not None:
            sink.write(block)
        else:
            chunks.append(block)
    return (None if sink is not None else b"".join(chunks)), total, digest.hexdigest()


_NET_ERRORS = (urllib.error.URLError, ssl.SSLError, socket.timeout, TimeoutError,
               http.client.HTTPException, OSError, ValueError)


def _request(url: str, hosts: frozenset, cap: int, *, data: bytes | None = None,
             headers: dict | None = None, not_found: str | None = None, over_cap=None,
             sink=None):
    """One HTTP request under every rule above. Returns the body (bytes), or with `sink`
    (size, sha256). `not_found`: a 404 is refused with that reason; otherwise every HTTP
    error is infrastructure. `over_cap`: exception factory for a body over `cap` (default:
    refused)."""
    host = check_url(url, hosts)
    over_cap = over_cap or (lambda: FetchRefused(f"response from {host} exceeds {cap} bytes"))
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        resp = _open(req, SOCKET_TIMEOUT)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code == 404 and not_found is not None:
            raise FetchRefused(not_found) from None
        raise FetchInfrastructure(f"HTTP {exc.code} from {host}") from None
    except FetchRefused:
        raise
    except _NET_ERRORS as exc:
        raise FetchInfrastructure(f"request to {host} failed: {type(exc).__name__}: "
                                  f"{_reason(exc)}") from None
    if resp is None:
        raise FetchInfrastructure(f"no handler answered for {host}")
    try:
        final = resp.geturl() if hasattr(resp, "geturl") else url
        if final != url:
            raise FetchRefused(f"redirect refused: {_esc(url)} answered from {_esc(final)}")
        status = getattr(resp, "status", None)
        if status != 200:
            raise FetchInfrastructure(f"HTTP {status} from {host}")
        try:
            body, size, digest = _read_bounded(resp, cap, over_cap, sink)
        except (FetchRefused, FetchInfrastructure):
            raise
        except _NET_ERRORS as exc:
            raise FetchInfrastructure(f"reading from {host} failed: {type(exc).__name__}: "
                                      f"{_reason(exc)}") from None
    finally:
        try:
            resp.close()
        except (OSError, http.client.HTTPException):
            pass  # closing a response must not mask the outcome already decided above
    return (size, digest) if sink is not None else body


def _json(data: bytes, what: str):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise FetchInfrastructure(f"malformed JSON from {what}") from None


def _is_int(value, lo: int, hi: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi


# --- job: wheels -----------------------------------------------------------------------------

def _wheel_reqs(job: dict) -> list[tuple[str, str, frozenset]]:
    reqs = job.get("requirements")
    if not isinstance(reqs, list):
        raise FetchInfrastructure("job: requirements must be a list")
    out = []
    for item in reqs:
        if not (isinstance(item, list) and len(item) == 3 and isinstance(item[0], str)
                and isinstance(item[1], str) and isinstance(item[2], list)):
            raise FetchInfrastructure("job: malformed requirement")
        name, version, hashes = item
        # Exactly the parser's domain (gate A1-2): a name sandbox_deps accepts and normalises,
        # a version its VERSION_RE accepts -- no extra length limits of the worker's own.
        if not sandbox_deps.NAME_RE.fullmatch(name) or sandbox_deps.normalize_name(name) != name:
            raise FetchRefused(f"requirement name {_esc(name)} is not a normalised name")
        if not sandbox_deps.VERSION_RE.fullmatch(version):
            raise FetchRefused(f"requirement {name}: malformed version {_esc(version)}")
        if not hashes or not all(isinstance(h, str) and HEX64_RE.fullmatch(h) for h in hashes):
            raise FetchRefused(f"requirement {name}: hashes must be 64 lowercase hex")
        out.append((name, version, frozenset(hashes)))
    return out


def _job_wheels(job: dict, job_dir: Path) -> dict:
    """Index + selection + streamed download for every requirement; files land in job_dir."""
    reqs = _wheel_reqs(job)
    target = job.get("target")
    max_file, max_total = job.get("max_file"), job.get("max_total")
    if not isinstance(target, dict):
        raise FetchInfrastructure("job: target must be an object")
    if not _is_int(max_file, 1, 1 << 40) or not _is_int(max_total, 1, 1 << 42):
        raise FetchInfrastructure("job: max_file and max_total must be positive integers")
    job_dir = Path(os.path.abspath(job_dir))
    files, used, taken = [], 0, set()
    for name, version, hashes in reqs:
        url = f"https://pypi.org/simple/{name}/"
        body = _request(url, WHEEL_HOSTS, INDEX_CAP, headers={"Accept": PEP691},
                        not_found=f"unknown project {name} (HTTP 404 from pypi.org)")
        index = _json(body, f"the index of {name}")
        if not isinstance(index, dict):
            raise FetchInfrastructure(f"malformed index of {name}: not an object")
        try:
            sel = sandbox_wheels.select_wheel(index, name, version, hashes, target)
        except sandbox_wheels.WheelRefused as exc:
            raise FetchRefused(_reason(exc)) from None
        except ValueError as exc:
            raise FetchInfrastructure(f"selection for {name} failed: {_reason(exc)}") from None
        if not isinstance(sel, dict):
            raise FetchInfrastructure(f"selection for {name} returned no object")
        filename, wurl, sha = sel.get("filename"), sel.get("url"), sel.get("sha256")
        if not isinstance(sha, str) or sha not in hashes:
            raise FetchRefused(f"{name}: selected file's sha256 is not among the pinned hashes")
        if (not isinstance(filename, str) or not WHEEL_FILE_RE.fullmatch(filename)
                or filename in WORKER_FILES or filename.lower() in taken):
            raise FetchRefused(f"{name}: unsafe or duplicate wheel file name {_esc(filename)}")
        check_url(wurl, DOWNLOAD_HOSTS)
        remaining = max_total - used
        if remaining <= 0:
            raise FetchRefused(f"{name}: total download cap of {max_total} bytes reached")
        cap = min(max_file, remaining)
        what = "per-file" if cap == max_file else "total"

        def over(_n=name, _c=cap, _w=what):
            return FetchRefused(f"{_n}: download exceeds the {_w} cap ({_c} bytes)")
        taken.add(filename.lower())
        fh = hunt_io.open_new(job_dir, filename, base=job_dir)
        ok = False
        try:
            with fh:
                size, digest = _request(wurl, DOWNLOAD_HOSTS, cap, over_cap=over, sink=fh)
            if digest != sha:
                raise FetchRefused(f"{name}: downloaded sha256 {digest} differs from the selected hash")
            ok = True
        finally:
            if not ok:
                try:
                    hunt_io.remove_file(job_dir, filename, base=job_dir)
                except hunt_io.HuntIOError:
                    pass
        used += size
        files.append([name, version, filename, digest, size])
    return {"ok": True, "files": files}


# --- job: osv --------------------------------------------------------------------------------

class _Budget:
    def __init__(self, total: int):
        self.left = total

    def cap(self, per_response: int) -> int:
        return max(0, min(per_response, self.left))

    def spend(self, n: int) -> None:
        self.left -= n


def _osv_budget(job: dict, key: str, ceiling: int) -> int:
    value = job.get(key, ceiling)
    if not _is_int(value, 1, ceiling):
        raise FetchRefused(f"job: {key} must be an integer in 1..{ceiling}")
    return value


def _osv_queries(job: dict) -> list[tuple[str, str, str]]:
    queries = job.get("queries")
    if not isinstance(queries, list):
        raise FetchRefused("job: queries must be a list")
    out = []
    for q in queries:
        if not (isinstance(q, list) and len(q) == 3 and all(isinstance(x, str) for x in q)):
            raise FetchRefused("job: a query must be [ecosystem, name, version]")
        eco, name, version = q
        if eco not in OSV_ECOSYSTEMS:
            raise FetchRefused(f"job: unknown ecosystem {_esc(eco)}")
        for field in (name, version):
            if not field or len(field) > 256 or not field.isascii() or \
                    any(ord(c) < 33 or ord(c) == 127 for c in field):
                raise FetchRefused(f"job: malformed query field {_esc(field)}")
        out.append((eco, name, version))
    return out


def _osv_post(queries: list[dict], budget: _Budget) -> list:
    cap = budget.cap(OSV_RESPONSE_CAP)
    if cap <= 0:
        raise FetchInfrastructure("incomplete: total response byte budget exhausted")
    body = json.dumps({"queries": queries}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    data = _request(OSV_BATCH_URL, OSV_HOSTS, cap, data=body,
                    headers={"Content-Type": "application/json"},
                    over_cap=lambda: FetchInfrastructure(
                        "incomplete: querybatch response over its byte cap or the total budget"))
    budget.spend(len(data))
    doc = _json(data, "api.osv.dev querybatch")
    results = doc.get("results") if isinstance(doc, dict) else None
    if not isinstance(results, list):
        raise FetchInfrastructure("malformed querybatch answer: no results array")
    if len(results) != len(queries):
        raise FetchInfrastructure(f"incomplete: {len(results)} results for {len(queries)} queries")
    return results


def _osv_result(result) -> tuple[list[str], str | None]:
    if not isinstance(result, dict):
        raise FetchInfrastructure("malformed querybatch result: not an object")
    if "error" in result:
        raise FetchInfrastructure("incomplete: a querybatch result carries an error")
    vulns = result.get("vulns", [])
    if not isinstance(vulns, list):
        raise FetchInfrastructure("malformed querybatch result: vulns is not a list")
    ids = []
    for v in vulns:
        vid = v.get("id") if isinstance(v, dict) else None
        if not isinstance(vid, str) or not VULN_ID_RE.fullmatch(vid):
            raise FetchInfrastructure(f"malformed vulnerability id {_esc(vid)}")
        ids.append(vid)
    token = result.get("next_page_token")
    if token in (None, ""):
        return ids, None
    if not isinstance(token, str) or len(token) > 4096:
        raise FetchInfrastructure("malformed next_page_token")
    return ids, token


def _osv_query_obj(eco: str, name: str, version: str) -> dict:
    return {"package": {"name": name, "ecosystem": eco}, "version": version}


def _job_osv(job: dict) -> dict:
    """querybatch in batches, paging per query, then each vulnerability's details once."""
    max_queries = _osv_budget(job, "max_queries", OSV_MAX_QUERIES)
    max_details = _osv_budget(job, "max_details", OSV_MAX_DETAILS)
    max_bytes = _osv_budget(job, "max_total_bytes", OSV_MAX_TOTAL_BYTES)
    queries = _osv_queries(job)
    if len(queries) > max_queries:
        raise FetchRefused(f"{len(queries)} queries exceed the budget of {max_queries}")
    budget = _Budget(max_bytes)
    results: list[list[str]] = []
    for start in range(0, len(queries), OSV_BATCH):
        batch = queries[start:start + OSV_BATCH]
        answers = _osv_post([_osv_query_obj(*q) for q in batch], budget)
        for q, answer in zip(batch, answers):
            ids, token = _osv_result(answer)
            seen, pages = set(), 1
            while token is not None:
                if token in seen:
                    raise FetchInfrastructure(f"incomplete: repeated page token for {_esc(q[1])}")
                if pages >= OSV_MAX_PAGES:
                    raise FetchInfrastructure(
                        f"incomplete: {_esc(q[1])} still has a page token after {OSV_MAX_PAGES} pages")
                seen.add(token)
                page = _osv_post([{**_osv_query_obj(*q), "page_token": token}], budget)
                more, token = _osv_result(page[0])
                ids.extend(more)
                pages += 1
            results.append(list(dict.fromkeys(ids)))
    unique = list(dict.fromkeys(i for ids in results for i in ids))
    if len(unique) > max_details:
        raise FetchInfrastructure(f"incomplete: {len(unique)} vulnerabilities exceed the detail "
                                  f"budget of {max_details}")
    details = {}
    for vid in unique:  # each id once: the list is already de-duplicated
        cap = budget.cap(OSV_DETAIL_CAP)
        if cap <= 0:
            raise FetchInfrastructure("incomplete: total response byte budget exhausted")
        data = _request(OSV_VULN_URL + vid, OSV_HOSTS, cap, over_cap=lambda _v=vid: FetchInfrastructure(
            f"incomplete: details of {_v} over the 1 MiB cap or the total budget"))
        budget.spend(len(data))
        doc = _json(data, f"api.osv.dev details of {vid}")
        if not isinstance(doc, dict) or doc.get("id") != vid:
            raise FetchInfrastructure(f"incomplete: details for {vid} do not describe {vid}")
        details[vid] = doc
    return {"ok": True, "results": results, "details": details}


# --- worker ----------------------------------------------------------------------------------

def _run_kind(job, job_dir: Path) -> dict:
    if not isinstance(job, dict):
        raise FetchInfrastructure("job: not an object")
    kind = job.get("kind")
    if kind == "wheels":
        return _job_wheels(job, job_dir)
    if kind == "osv":
        return _job_osv(job)
    raise FetchInfrastructure(f"job: unknown kind {_esc(kind)}")


def worker_main(job_path) -> int:
    """Worker entry: run the job, write worker-result.json exclusively; 0 once it is written."""
    job_path = Path(os.path.abspath(job_path))
    job_dir = job_path.parent
    try:
        status, payload = hunt_io.read_regular(job_path, limit=JOB_CAP)
        if status != "ok":
            raise FetchInfrastructure(f"job file unreadable: {payload}")
        result = _run_kind(_json(payload, "the job file"), job_dir)
    except FetchRefused as exc:
        result = {"ok": False, "kind": "refused", "reason": _reason(exc)}
    except FetchInfrastructure as exc:
        result = {"ok": False, "kind": "infrastructure", "reason": _reason(exc)}
    except Exception as exc:  # noqa: BLE001 - any defect is infrastructure, never a pass
        result = {"ok": False, "kind": "infrastructure",
                  "reason": _reason(f"worker error: {type(exc).__name__}: {exc}")}
    data = json.dumps(result, sort_keys=True, ensure_ascii=True).encode("ascii")
    try:
        hunt_io.create_file(job_dir, RESULT_NAME, data, base=job_dir)
    except (hunt_io.HuntIOError, OSError) as exc:
        sys.stderr.write(f"sandbox_fetch worker: cannot write the result: {_reason(exc)}\n")
        return 3
    return 0


# --- parent ----------------------------------------------------------------------------------

def _worker_argv(job_path: Path) -> list[str]:
    """The worker's command line (tests replace this seam with their own scripts)."""
    return [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--worker", str(job_path)]


def _wait_deadline(proc: subprocess.Popen, timeout: float) -> int:
    return proc.wait(timeout=timeout)


def _kill(proc: subprocess.Popen) -> None:
    """SIGKILL the worker's whole session on POSIX (it is the session leader, so its pid is the
    process group id); TerminateProcess on Windows."""
    if os.name != "nt":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except OSError:
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _confirm_dead(proc: subprocess.Popen, timeout: float) -> bool:
    """True once the worker is reaped within `timeout`."""
    try:
        proc.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


CONFIRM_ATTEMPTS = 2  # an interrupted confirmation is retried once, then counts as unconfirmed


@contextlib.contextmanager
def _sigint_deferred(pending: list):
    """While the block runs, a SIGINT is recorded in `pending` instead of raising
    KeyboardInterrupt; the previous handler is restored afterwards. Only the main thread can
    install a handler (signal.signal raises ValueError elsewhere); off the main thread nothing
    is installed, and nothing is needed: CPython delivers SIGINT only to the main thread, so
    the calling thread is never interrupted by it."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    try:
        previous = signal.signal(signal.SIGINT, lambda signum, frame: pending.append(signum))
    except (ValueError, OSError):  # e.g. an embedded interpreter without signal support
        yield
        return
    try:
        yield
    finally:
        # previous is None when the handler was not installed from Python: fall back to the
        # interpreter's default, which raises KeyboardInterrupt.
        signal.signal(signal.SIGINT, previous if previous is not None else signal.default_int_handler)


def _diagnostic(line) -> None:
    """Write one diagnostic line to stderr, best effort: building or writing it may fail (a
    full redirected log raises OSError, a closed stream ValueError) and that failure is
    swallowed. On the unconfirmed path a log line must never stand between the worker and its
    quarantine record or FetchUnconfirmed (gate recheck 1, block A1, finding 9). `line` is a
    callable so that formatting errors are covered too."""
    try:
        sys.stderr.write(line())
    except Exception:  # noqa: BLE001 - the diagnostic is optional, the raise after it is not
        return


def _terminate(proc, job_dir: Path, scratch: Path, run_id: str, deadline_epoch: float) -> None:
    """Kill and confirm; on an unconfirmed death quarantine in place and raise FetchUnconfirmed.

    A SIGINT during kill, confirmation and quarantine is deferred (main thread), and a
    KeyboardInterrupt raised inside the kill/confirm path is caught and the confirmation
    retried (CONFIRM_ATTEMPTS in all; an attempt that never returns counts as unconfirmed).
    Only after confirmation or quarantine does an interrupt propagate: KeyboardInterrupt when
    the worker was confirmed dead, FetchUnconfirmed (which takes precedence) when it was not.
    Any other exception from kill or confirmation (OSError included) is an unconfirmed death:
    it is not retried, the quarantine record is written and FetchUnconfirmed raised with that
    exception as its cause -- the raw error never escapes past the quarantine (gate A1-3).
    Every diagnostic line on this path (CONFIRM_FAILED, QUARANTINE, QUARANTINE_RECORD_FAILED)
    is best effort: a failing stderr is swallowed, the record is still attempted and
    FetchUnconfirmed still raised (gate recheck 1, A1-9)."""
    pending: list = []
    confirmed = False
    record = None
    failure: Exception | None = None
    with _sigint_deferred(pending):
        for _ in range(CONFIRM_ATTEMPTS):
            try:
                _kill(proc)
                confirmed = bool(_confirm_dead(proc, KILL_WAIT))
                break
            except KeyboardInterrupt:
                pending.append(signal.SIGINT)
            except Exception as exc:  # noqa: BLE001 - unconfirmed, never a raw crash
                failure = exc
                _diagnostic(lambda e=exc: f"CONFIRM_FAILED pid={proc.pid} "
                                          f"reason={_esc(_reason(f'{type(e).__name__}: {e}'))}\n")
                break
        if not confirmed:
            try:
                record = write_quarantine_record(scratch, run_id, job_dir, proc.pid,
                                                 deadline_epoch)
            except Exception as exc:  # noqa: BLE001 - best effort; the facts still reach stderr
                _diagnostic(lambda e=exc: f"QUARANTINE_RECORD_FAILED path={_esc(str(job_dir))} "
                                          f"pid={proc.pid} cleanup=unconfirmed "
                                          f"reason={_esc(_reason(e))}\n")
            else:
                _diagnostic(lambda: f"QUARANTINE path={_esc(str(job_dir))} pid={proc.pid} "
                                    f"cleanup=unconfirmed record={_esc(str(record))}\n")
    if not confirmed:
        unconfirmed = FetchUnconfirmed(f"worker pid {proc.pid} could not be confirmed dead; "
                                       f"{job_dir} is quarantined in place", proc.pid, job_dir,
                                       record, deadline_epoch)
        if failure is not None:
            raise unconfirmed from failure
        raise unconfirmed
    if pending:
        raise KeyboardInterrupt


def _read_result(job_dir: Path) -> dict:
    status, payload = hunt_io.read_regular(job_dir / RESULT_NAME, limit=RESULT_CAP)
    if status != "ok":
        raise FetchInfrastructure(f"worker result missing or unreadable ({payload})")
    doc = _json(payload, "the worker result")
    if not isinstance(doc, dict) or not isinstance(doc.get("ok"), bool):
        raise FetchInfrastructure("worker result malformed")
    if doc["ok"]:
        return doc
    kind, reason = doc.get("kind"), doc.get("reason")
    if not isinstance(reason, str):
        raise FetchInfrastructure("worker result malformed: no reason")
    if kind == "refused":
        raise FetchRefused(_reason(reason))
    if kind == "infrastructure":
        raise FetchInfrastructure(_reason(reason))
    raise FetchInfrastructure("worker result malformed: unknown error kind")


def run_job(job: dict, job_dir: Path, deadline_s: float, scratch: Path, run_id: str) -> dict:
    """Run one job in a fresh worker under a hard deadline; return its ok result.

    `job_dir` is the caller's freshly created, empty directory; the worker writes only there.
    Raises FetchRefused / FetchInfrastructure from the worker's error result,
    FetchInfrastructure on timeout or a missing/invalid result, FetchUnconfirmed after the
    quarantine record when the worker cannot be confirmed dead. KeyboardInterrupt kills and
    confirms the worker, then re-raises (FetchUnconfirmed instead when the death is
    unconfirmed, so the caller's cleanup leaves the directory alone). The same holds for every
    other exit after Popen returned, closing the parent's output handles included; a failed
    close (OSError) surfaces as FetchInfrastructure after the kill was confirmed. A second
    interrupt during kill/confirm is deferred until confirmation or quarantine (_terminate).

    ACCEPTED RISK (inspection round 1, block B reinspection): a KeyboardInterrupt raised INSIDE
    subprocess.Popen after the child was created but before Popen returned is not covered --
    `proc` is never bound, so there is nothing to kill or confirm. Accepted because CPython
    raises KeyboardInterrupt only between bytecodes, so the window is a few bytecodes of
    Popen's own return path; the child's pid is not yet known to us, so no kill we could add
    would have a target; and such a child (start_new_session / its own process group) only
    ever writes into job_dir, its result is never read, and the interrupted run is reported
    as failed by the caller -- a never-written or unread result is never a pass. Revisit when the
    runner moves the worker into a container (B2, where the container itself can be removed
    by name), or as soon as a run leaves an unexplained process behind."""
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run id must be 16 lowercase hex characters")
    if not isinstance(job, dict) or job.get("kind") not in ("wheels", "osv"):
        raise ValueError("job kind must be 'wheels' or 'osv'")
    if not isinstance(deadline_s, (int, float)) or isinstance(deadline_s, bool) or deadline_s <= 0:
        raise ValueError("deadline must be a positive number of seconds")
    job_dir = Path(os.path.abspath(job_dir))
    scratch = Path(os.path.abspath(scratch))
    data = json.dumps(job, sort_keys=True, ensure_ascii=True).encode("ascii")
    kwargs = {}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    # The ONE deadline: the quarantine record and FetchUnconfirmed.deadline_epoch carry this
    # exact value; nothing recomputes it.
    deadline_epoch = float(time.time() + deadline_s)
    try:
        job_path = hunt_io.create_file(job_dir, JOB_NAME, data, base=job_dir)
        out = hunt_io.open_new(job_dir, STDOUT_NAME, base=job_dir)
        try:
            err = hunt_io.open_new(job_dir, STDERR_NAME, base=job_dir)
        except BaseException:
            out.close()
            raise
    except hunt_io.HuntIOError as exc:
        raise FetchInfrastructure(f"cannot prepare the job directory: {_reason(exc)}") from None
    # From here on ONE region covers the whole worker lifecycle: the Popen call, closing the
    # parent's copies of the output handles, the wait and reading the result. Every exit from
    # it while the worker may be alive -- an exception, KeyboardInterrupt, a failed close --
    # kills and confirms the worker (quarantine + FetchUnconfirmed when unconfirmed). `proc`
    # is bound inside the region, so no statement runs between Popen returning and the
    # protection taking effect.
    proc = None
    try:
        try:
            # env: a copy of ours is acceptable -- -I ignores every PYTHON* variable and the
            # user site, -S skips site-packages; the worker reads nothing else from the
            # environment (ProxyHandler({}) ignores the proxy variables).
            proc = subprocess.Popen(_worker_argv(job_path), stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=err, cwd=str(job_dir), env=dict(os.environ), **kwargs)
        except OSError as exc:
            raise FetchInfrastructure(f"cannot start the worker: {_reason(exc)}") from None
        finally:
            _close_both(out, err)
        rc = _wait_deadline(proc, deadline_s)
        if rc != 0:
            raise FetchInfrastructure(f"worker exited with status {rc}")
        return _read_result(job_dir)
    except subprocess.TimeoutExpired:
        if proc is None or proc.returncode is not None:
            raise FetchInfrastructure("worker supervision failed: unexpected timeout") from None
        _terminate(proc, job_dir, scratch, run_id, deadline_epoch)
        raise FetchInfrastructure(f"worker exceeded the deadline of {deadline_s} s and was "
                                  f"killed") from None
    except BaseException as exc:
        if proc is not None and proc.returncode is None:
            _terminate(proc, job_dir, scratch, run_id, deadline_epoch)  # FetchUnconfirmed if not dead
        if isinstance(exc, OSError):  # e.g. a failed close: infrastructure, never a raw crash
            raise FetchInfrastructure(f"worker supervision failed: {type(exc).__name__}: "
                                      f"{_reason(exc)}") from None
        raise


def _close_both(out, err) -> None:
    """Close both handles, the second even when the first close fails; re-raise the first
    failure (BaseException included) afterwards."""
    first = None
    for fh in (out, err):
        try:
            fh.close()
        except BaseException as exc:  # noqa: BLE001 - re-raised below, after the other close
            if first is None:
                first = exc
    if first is not None:
        raise first


def _hash_regular(path: Path, limit: int, over) -> tuple[int, str]:
    """Stream-hash ONE regular file without following a link; at most limit + 1 bytes read."""
    try:
        st = os.lstat(path)
    except OSError:
        raise FetchInfrastructure(f"{path.name}: missing") from None
    if hunt_io._is_redirect(st) or not stat.S_ISREG(st.st_mode):
        raise FetchInfrastructure(f"{path.name}: not a regular file")
    if st.st_size > limit:
        raise over()
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        raise FetchInfrastructure(f"{path.name}: changed while opening") from None
    try:
        fst = os.fstat(fd)
        if (not stat.S_ISREG(fst.st_mode) or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev)
                or getattr(fst, "st_file_attributes", 0) & hunt_io.FILE_ATTRIBUTE_REPARSE_POINT):
            raise FetchInfrastructure(f"{path.name}: changed while opening")
        digest, total = hashlib.sha256(), 0
        while True:
            block = os.read(fd, min(CHUNK, limit + 1 - total))
            if not block:
                break
            total += len(block)
            if total > limit:
                raise over()
            digest.update(block)
        return total, digest.hexdigest()
    finally:
        os.close(fd)


def _expected_hashes(value) -> frozenset:
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, (set, frozenset, list, tuple)) or not value or \
            not all(isinstance(h, str) and HEX64_RE.fullmatch(h) for h in value):
        raise FetchInfrastructure("expected hash must be 64 lowercase hex (or a set of them)")
    return frozenset(value)


def verify_download(job_dir: Path, expected: list, max_file: int,
                    max_total: int) -> list[tuple[str, str, str, str, int]]:
    """Parent-side check of a wheels job; trusts nothing the worker reported.

    `expected` = [(name, version, filename)] -- optionally a 4th element: the selected sha256
    or the requirement's set of allowed hashes, which the RECOMPUTED digest must match.
    The directory must hold exactly those files plus the worker's four own files, every one a
    regular file (no link); each wheel within max_file, all together within max_total.
    Returns [(name, version, filename, recomputed sha256, size)] in the order given."""
    job_dir = Path(os.path.abspath(job_dir))
    try:
        hunt_io.check_chain(job_dir, base=job_dir)
    except hunt_io.HuntIOError as exc:
        raise FetchInfrastructure(_reason(exc)) from None
    if not _is_int(max_file, 1, 1 << 42) or not _is_int(max_total, 1, 1 << 44):
        raise FetchInfrastructure("caps must be positive integers")
    items, names = [], set()
    for entry in expected:
        if not isinstance(entry, (tuple, list)) or len(entry) not in (3, 4) or \
                not all(isinstance(x, str) for x in entry[:3]):
            raise FetchInfrastructure("expected entries are (name, version, filename[, sha256])")
        name, version, filename = entry[:3]
        hashes = _expected_hashes(entry[3]) if len(entry) == 4 else None
        if not WHEEL_FILE_RE.fullmatch(filename) or filename in WORKER_FILES \
                or filename.lower() in names:
            raise FetchInfrastructure(f"unsafe or duplicate expected file {_esc(filename)}")
        names.add(filename.lower())
        items.append((name, version, filename, hashes))
    try:
        present = os.listdir(job_dir)
    except OSError as exc:
        raise FetchInfrastructure(f"cannot list the download directory: {_reason(exc)}") from None
    want = {i[2] for i in items} | WORKER_FILES
    if set(present) != want or len(present) != len(want):
        extra = sorted(set(present) - want)
        missing = sorted(want - set(present))
        raise FetchInfrastructure(f"download directory differs: extra {_esc(extra)}, "
                                  f"missing {_esc(missing)}")
    for name in WORKER_FILES:
        try:
            st = os.lstat(job_dir / name)
        except OSError:
            raise FetchInfrastructure(f"{name}: missing") from None
        if hunt_io._is_redirect(st) or not stat.S_ISREG(st.st_mode):
            raise FetchInfrastructure(f"{name}: not a regular file")
    out, total = [], 0
    for name, version, filename, hashes in items:
        cap = min(max_file, max_total - total)
        if cap <= 0:
            raise FetchRefused(f"{filename}: total size cap of {max_total} bytes exceeded")
        size, digest = _hash_regular(job_dir / filename, cap, lambda _f=filename: FetchRefused(
            f"{_f}: over the size cap"))
        if hashes is not None and digest not in hashes:
            raise FetchRefused(f"{filename}: sha256 {digest} is not the selected hash")
        total += size
        out.append((name, version, filename, digest, size))
    return out


# --- quarantine ------------------------------------------------------------------------------

def write_quarantine_record(scratch: Path, run_id: str, path: Path, pid: int,
                            deadline_epoch: float) -> Path:
    """Record an unconfirmed worker: <scratch>/claudex-quarantine/<run_id>.json, created
    exclusively through hunt_io (never overwritten). Returns the record's path."""
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run id must be 16 lowercase hex characters")
    scratch = Path(os.path.abspath(scratch))
    qdir = hunt_io.make_tree(scratch, QUARANTINE_DIR, base=scratch)
    record = {"run_id": run_id, "path": str(path), "pid": int(pid),
              "deadline_epoch": float(deadline_epoch), "cleanup": "unconfirmed",
              "recorded_epoch": time.time()}
    data = json.dumps(record, sort_keys=True, ensure_ascii=True).encode("ascii") + b"\n"
    return hunt_io.create_file(qdir, f"{run_id}.json", data, base=scratch)


def _describe_record(qdir: Path, name: str) -> str:
    stem = name[:-5] if name.endswith(".json") else None
    if stem is None or not RUN_ID_RE.fullmatch(stem):
        return f"unreadable record {_esc(name)}: not <run id>.json"
    status, payload = hunt_io.read_at(qdir, name, limit=RECORD_CAP)
    if status != "ok":
        return f"unreadable record {_esc(name)}: {payload}"
    try:
        rec = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return f"unreadable record {_esc(name)}: malformed JSON"
    if not isinstance(rec, dict):
        return f"unreadable record {_esc(name)}: not an object"
    pid, path = rec.get("pid"), rec.get("path")
    deadline, cleanup = rec.get("deadline_epoch"), rec.get("cleanup")
    if (rec.get("run_id") != stem or not _is_int(pid, 0, 1 << 62) or not isinstance(path, str)
            or not isinstance(cleanup, str) or isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))):
        return f"unreadable record {_esc(name)}: fields missing or malformed"
    return (f"quarantined run {stem}: path={_esc(path)} pid={pid} deadline_epoch={deadline!r} "
            f"cleanup={_esc(cleanup)} -- remove by hand after checking that pid {pid} is gone")


def list_quarantine(scratch: Path) -> list[str]:
    """One ASCII line per record under <scratch>/claudex-quarantine/, fields escaped as data.
    Never deletes, renames or opens a recorded path; records are read without following a
    link; an invalid name or content yields an "unreadable record <name>" line."""
    qdir = Path(os.path.abspath(scratch)) / QUARANTINE_DIR
    try:
        st = os.lstat(qdir)
    except FileNotFoundError:
        return []
    except OSError as exc:
        return [f"unreadable quarantine directory {_esc(str(qdir))}: {_reason(exc)}"]
    if hunt_io._is_redirect(st) or not stat.S_ISDIR(st.st_mode):
        return [f"unreadable quarantine directory {_esc(str(qdir))}: link or not a directory"]
    try:
        names = sorted(os.listdir(qdir))
    except OSError as exc:
        return [f"unreadable quarantine directory {_esc(str(qdir))}: {_reason(exc)}"]
    lines = [_describe_record(qdir, n) for n in names[:MAX_RECORDS_LISTED]]
    if len(names) > MAX_RECORDS_LISTED:
        lines.append(f"{len(names) - MAX_RECORDS_LISTED} more quarantine entries not listed")
    return lines


# --- entry -----------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == "--worker":
        return worker_main(argv[1])
    sys.stderr.write("usage: python -I -S sandbox_fetch.py --worker <job.json> "
                     "(started by run_job only)\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
