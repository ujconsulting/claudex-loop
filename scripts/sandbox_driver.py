#!/usr/bin/env python3
"""sandbox_driver: the in-container half of the sandbox runners (B1 run, B2 probe and build).

Plan B1 (docs/plans/2026-10-27-sicherheitskette, approved round 6), Approach 2 and 5; plan
B2 (PLAN-B2-build.md, approved round 5), approaches 3b, 4, 5, 6 and 7, unit U3.
The host (scripts/sandbox_run.py bootstrap(), shared by every producer) starts this file
inside a container (uid 0 with only CAP_SETUID/CAP_SETGID/CAP_KILL, no-new-privileges,
read-only root, tmpfs /work /out /tmp /home/run) through a fixed stdin LOADER (plan B2
approach 3b; it replaced B1.5's compressed argv bootstrap, which grew with the driver
towards the Windows command-line limit): argv is only `python3 -I -S -c "<loader>"` with
the 64-hex sha256 of this source embedded. The loader reads a decimal length line and
exactly that many source bytes FIRST on stdin, checks their sha256 and executes them as
__main__, so the guard at the bottom runs main(). The driver is therefore PID 1 and the
only producer of the result.

WHY ONE SELF-CONTAINED FILE. The source travels on stdin, never as a file from the
snapshot: the loader text is fixed, it imports only sys and hashlib, and it runs nothing
whose hash differs from the plugin's own source (the host manifest records that sha256).
It runs isolated (-I: no user site, no PYTHON* env, no script dir on sys.path; -S: no
site). Every import of the driver itself is at the top, before anything from the
repository exists (round-4 finding 2: a deferred import resolved from /work would run
repository code as the driver), and nothing here imports a plugin module. The loader and
the driver read stdin through the same buffered sys.stdin.buffer, so nothing the loader
read ahead is lost.

PROTOCOL on stdin, after the loader block (binary): line 1 = nonce (32 lowercase hex) +
LF; line 2 = JSON spec + LF. The spec's optional `mode` selects what follows:

  "run" (or no mode key; B1/B1.5, unchanged): exactly `tar_len` bytes = the snapshot tar;
      then exactly `deps_len` bytes = the deps tar (plan B1.5 step 4; `deps_len` 0 = none,
      and then `deps_sha256` is ""). On stdout: ONE tar stream with the members
      result.json, stdout.txt, stderr.txt, install.txt (present iff deps_len > 0) and
      out/<name> per exported file, nothing else. With deps_len 0 the run is B1's, and
      result.json differs from B1 only by the trailing `"deps": null`.
  "probe" (B2 approach 5): nothing follows the spec. Keys `probe_targets` ([proto, host,
      port] with proto tcp|udp and an IP literal, or ["dns", name, 0]), `probe_deadline`
      (seconds) and `exclude_addrs` (the probe's and the proxy's address; a target on one
      of them is refused). ONE uid-65532 child probes every target concurrently
      (non-blocking sockets, resolutions in threads of the same child) and reports each
      outcome over a pipe; the driver kills and reaps it at the absolute deadline. The
      driver also reads /proc/net/route and /proc/net/ipv6_route. One reached target or a
      default route -> isolation_failed; the child killed, or any target unreported,
      timed out or in error -> isolation_unverified; else isolated. stdout: one tar with
      result.json only.
  "build" (B2 approaches 4, 6, 7): then exactly tar_len bytes snapshot tar, deps_len
      bytes deps tar, prompt_len bytes prompt, placeholder_len bytes placeholder
      auth.json, ca_len bytes CA certificate (PEM). See BUILD MODE below.

The nonce arrives on stdin, not in argv (/proc/1/cmdline is world readable); the host
accepts a result only with the matching nonce AND a clean `docker inspect` exit code.

BUILD MODE. The uid-0 driver computes the BASELINE (path -> sha256, git mode) from the
snapshot tar bytes in its own memory before anything is extracted; a snapshot with a .git
path is refused. Members at or beneath a `withheld_paths` prefix (policy: .codex/**, a
repository's .codex/config.toml starts MCP processes even untrusted) are recorded as
withheld and NOT extracted; their absence is not a deletion. A uid-65532 child extracts
the rest into /work/repo. Another uid-65532 child writes the placeholder auth.json and the
CA certificate (0600, exclusive create) into CODEX_HOME=/codex-home, which must be an empty
directory, root-owned 1777 or 65532-owned. No git runs. Before the turn a uid-65532 child
runs `codex login status`; unless it exits 0 reporting "Logged in using ChatGPT", Codex
never starts (login_status "rejected"; a placeholder without the refresh_token key makes
Codex run unauthenticated instead of failing, measurement 2026-11-01). Codex then runs as
uid 65532 in /work/repo with the validated `codex_argv` (`codex exec --skip-git-repo-check
--dangerously-bypass-approvals-and-sandbox --ignore-user-config --ignore-rules`, then only
-c model / model_reasoning_effort / sandbox_mode="danger-full-access" /
approval_policy="never" / notify=[] and --disable <feature>, then `--json -o
/out/codex-last.txt -`), the prompt on stdin (a memfd), an environment built from scratch
(CODEX_HOME, CODEX_CA_CERTIFICATE, the four proxy variables = proxy_url, empty NO_PROXY,
PYTHONPATH only with deps) and one budget, codex_timeout, that also covers deps and the
login check. After Codex, every uid-65532 process is killed (QUIESCENCE below) and only
then does a uid-65532 helper walk /work/repo under `change_caps`, sending each regular
file's bytes to the driver over a pipe; it does not descend into .git (any depth, any case)
or a withheld path. The driver compares the walk with its baseline: added, modified,
deleted, mode (100644 <-> 100755), binary = NUL in the first 8 KiB or not UTF-8. Builder
.git directories and ADDED paths matching `generated_paths` are excluded and reported; a
changed baseline path is never excluded. A symlink, device, FIFO or socket outside the
excluded paths, a changed path that is not printable ASCII or holds a backslash, any entry
at or beneath a withheld path, or a cap hit refuses the change set (change_status
"refused"). stdout: one tar with result.json (B1's document plus "build": {codex_exit,
change_status, change_reason, counts, login_status}), codex-events.jsonl (Codex stdout,
16 MiB cap), codex-stderr.txt (1 MiB), login.txt, install.txt (iff deps), codex-last.txt
(iff exported), changes.json, excluded.json ({"excluded": [...], "withheld": [...]}) and
change/<n> for every added or modified entry, n = its index in changes.json.

PRIVILEGE SEPARATION (round-3 finding 2). The command and the extraction run as children
that drop to uid/gid 65532 (setgroups, setgid, setuid) before they touch anything; after
that they hold no capability and cannot signal PID 1, open /proc/1/fd/*, or read
/tmp/driver (0700, uid 0). Because the driver has no CAP_CHOWN and no DAC override
(round-4 finding 1, round-5 finding 2), extraction and the export reads also happen in
uid-65532 children.

DEPENDENCIES (plan B1.5 step 5) use a THIRD uid, 65531. /deps is a tmpfs the runner mounts
root-owned with mode 1777 (the driver has no CAP_CHOWN, so only a 65531 child can create
the 65531-owned tree; the sticky bit keeps 65532 from renaming it). A 65531 child extracts
the deps tar (flat regular members, *.whl or requirements.txt) into /deps/wheels, creates
/deps/site, /deps/home, /deps/tmp, and runs `python3 -I -m pip install --no-index
--no-deps --require-hashes ...` offline with cwd /deps/tmp and an environment built from
scratch, so neither /work, the cwd nor PYTHONPATH is on pip's sys.path. Then every uid-65531
process is killed, /deps/site and /deps/wheels are walked (owner 65531, no group/other
write, no link, device, setuid or setgid; files o+r and directories o+rx, because the
command reads them through the OTHER bits), and only then does the command start as 65532
with PYTHONPATH=/deps/site. It can read the installed tree but not alter it. Wheel member
names follow a copy of the host grammar (scripts/sandbox_wheels.py parse_wheel_filename).

ONE DEPS DEADLINE: min(deps_timeout, timeout) from the start of the deps step. No phase
(extraction, install, permission walk, METADATA reads, closure check) starts after it; the
extraction and the install get only what is left of it, and the walk, the reads and the
closure check test it between entries; the METADATA parser also tests it every
METADATA_CHECK_LINES lines inside one file (gate initial pass, B1), and its work is linear
and bounded by MAX_METADATA_LINES physical lines, continuations included. Expiry is
deps_failed with a timeout reason.

CLOSURE CHECK. pip check would import /deps/site; instead this driver reads every METADATA
of /deps/site and of the image's site-packages as text (bounded, no-follow) and evaluates
Requires-Dist with pip._vendor.packaging, imported at the top from IMAGE_SITE APPENDED to
sys.path (never /work, never /deps, never the cwd). /deps/site shadows the image; every
effective distribution seeds the worklist; extras propagate to a fixed point. HONEST LIMIT:
this proves the closure of what the metadata DECLARES; an undeclared import is invisible
to it, and a test that skips on a missing optional import still passes.

QUIESCENCE (round-3 finding 5, round-4 finding 5): before anything is packed, every live
uid-65532 and uid-65531 process is SIGKILLed and adopted orphans are reaped with waitpid.
A zombie keeps the uid in /proc, so the scan parses `State:` and counts only non-zombies.
In build mode this happens before the walk too: no builder process outlives Codex into it.

Messages are ASCII only. Exit code 0 means "a result was produced" (even for a failed
command); non-zero only when no trustworthy result could be produced at all.
"""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import io
import ipaddress
import json
import os
import re
import select
import signal
import socket
import stat
import sys
import tarfile
import threading
import time
import types

RUN_UID = 65532
RUN_GID = 65532
DEPS_UID = 65531
DEPS_GID = 65531
CHILD_UIDS = (DEPS_UID, RUN_UID)
WORK = "/work"
OUT = "/out"
DEPS = "/deps"
IMAGE_SITE = "/usr/local/lib/python3.13/site-packages"
# pip reads these even with --isolated (global and site configuration); the image pins the rest.
PIP_CONFIG_PATHS = ("/etc/pip.conf", "/etc/xdg/pip", "/usr/local/pip.conf")
# Inside the container: /tmp is a per-run tmpfs, and this directory is 0700 uid 0 (bandit B108).
SCRATCH = "/tmp/driver"  # nosec B108
PROC = "/proc"
SIGKILL = getattr(signal, "SIGKILL", 9)

NONCE_RE = re.compile(r"[0-9a-f]{32}")
EXPORT_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")
SPEC_KEYS = ("argv", "exports", "capture_cap", "export_cap", "timeout", "tar_len",
             "deps_len", "deps_sha256", "deps_timeout")
MAX_EXPORTS = 3
MAX_CAP = 64 * 1024 * 1024
MAX_TAR = 1024 * 1024 * 1024
MAX_DEPS_TAR = MAX_TAR + 1024 * 1024
MAX_TIMEOUT = 3600
MAX_SPEC_LINE = 65536
COMMAND_STATUSES = ("exited", "timeout", "output_limit", "not_started", "deps_failed")
EXPORT_SHA_RE = re.compile(r"[0-9a-f]{64}")
QUIESCE_SECONDS = 5.0
EXTRACT_SECONDS = 120.0
EXPORT_SECONDS = 20.0
CHILD_ENV = {"HOME": "/home/run", "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
INSTALL_PATH = "/usr/local/bin:/usr/bin:/bin"

INSTALL_CAP = 64 * 1024
MAX_DEPS_REQUIREMENTS = 500
MAX_DEPS_MEMBERS = MAX_DEPS_REQUIREMENTS + 1
MAX_REQ_BYTES = 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024
MAX_METADATA_HEADERS = 10000
# Physical header lines of one METADATA, continuations included (gate initial pass, B1): far
# above any real header block, far below what the 4 MiB cap would otherwise allow.
MAX_METADATA_LINES = 100000
METADATA_CHECK_LINES = 1024
MAX_SITE_ENTRIES = 20000
MAX_DEPS_ENTRIES = 200000
MAX_REASON = 300
# Wheel file names: a COPY of the host grammar in scripts/sandbox_wheels.py parse_wheel_filename
# (this file may import nothing of the plugin). Inspection round 1, B4: the driver may not refuse
# a name the host selected; tests/test_sandbox_driver.py compares both on a corpus.
WHEEL_DIST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._]*[A-Za-z0-9])?")
WHEEL_VERSION_RE = re.compile(r"[A-Za-z0-9_.+!]+")
WHEEL_BUILD_RE = re.compile(r"[0-9][A-Za-z0-9_.]*")
WHEEL_TAG_RE = re.compile(r"[A-Za-z0-9_]+")
WHEEL_MAX_FILENAME = 255       # sandbox_wheels.MAX_WHEEL_FILENAME
WHEEL_MAX_TAG_COMPONENTS = 16  # sandbox_wheels.MAX_TAG_COMPONENTS
WHEEL_MAX_TAG_TRIPLES = 256    # sandbox_wheels.MAX_TAG_TRIPLES
DIST_NAME_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?")
CANON_VERSION_RE = re.compile(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*((a|b|rc)(0|[1-9][0-9]*))?"
                              r"(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?")
DEPS_REQ_RE = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)==([0-9][0-9a-z.]*)"
                         r" --hash=sha256:([0-9a-f]{64})")
DIST_INFO_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_]*")

# ---- plan B2 (PLAN-B2-build.md, unit U3): modes "probe" and "build"
MODES = ("run", "probe", "build")
PROBE_SPEC_KEYS = ("mode", "probe_targets", "probe_deadline", "exclude_addrs")
BUILD_SPEC_KEYS = ("mode", "tar_len", "deps_len", "deps_sha256", "deps_timeout", "codex_argv",
                   "proxy_url", "ca_len", "placeholder_len", "prompt_len", "change_caps",
                   "generated_paths", "withheld_paths", "codex_timeout")
MAX_PROBE_TARGETS = 512
MAX_PROBE_DEADLINE = 60
MAX_EXCLUDE_ADDRS = 16
PROBE_PROTOS = ("tcp", "udp", "dns")
PROBE_OUTCOMES = ("reached", "blocked", "timeout", "error", "unreported")
PROBE_STATUSES = ("isolated", "isolation_failed", "isolation_unverified")
PROBE_REPORT_CAP = 1024 * 1024
HOSTNAME_RE = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                         r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
ROUTE_V4 = "/proc/net/route"
ROUTE_V6 = "/proc/net/ipv6_route"
RTF_UP, RTF_REJECT = 0x0001, 0x0200
# A connection refused (RST) is a host answering: reachable. These mean nothing answered.
BLOCKED_ERRNOS = frozenset(getattr(errno, name) for name in (
    "ENETUNREACH", "EHOSTUNREACH", "EACCES", "EPERM", "EADDRNOTAVAIL", "EAFNOSUPPORT", "ENETDOWN",
    "EHOSTDOWN") if hasattr(errno, name))
DNS_QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")

CODEX_HOME = "/codex-home"
# The codex-build image's PATH (config/sandbox/codex-build.Dockerfile): the Codex binary and its
# helper directory first. The driver builds every child environment from scratch.
BUILD_PATH = ("/opt/codex/package/vendor/x86_64-unknown-linux-musl/bin:"
              "/opt/codex/package/vendor/x86_64-unknown-linux-musl/codex-path:/usr/local/bin:/usr/bin:/bin")
CODEX_PREFIX = ("codex", "exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
                "--ignore-user-config", "--ignore-rules")
CODEX_FIXED = {"sandbox_mode": '"danger-full-access"', "approval_policy": '"never"', "notify": "[]"}
CODEX_FREE = {"model": re.compile(r'"[A-Za-z0-9._:-]{1,64}"'),
              "model_reasoning_effort": re.compile(r'"[a-z]{1,16}"')}
FEATURE_RE = re.compile(r"[a-z0-9_]{1,64}")
MAX_CODEX_ARGV = 128
LOGIN_ARGV = ["codex", "login", "status"]
LOGIN_OK = b"Logged in using ChatGPT"
LOGIN_SECONDS = 30.0
LOGIN_CAP = 64 * 1024
EVENTS_CAP = 16 * 1024 * 1024
CODEX_STDERR_CAP = 1024 * 1024
LAST_CAP = 1024 * 1024
LAST_NAME = "codex-last.txt"
MAX_PROMPT = 1024 * 1024
MAX_CA = 64 * 1024
MAX_PLACEHOLDER = 64 * 1024
CAP_BOUNDS = {"entries": 200000, "total_bytes": 256 * 1024 * 1024, "file_bytes": 64 * 1024 * 1024,
              "added_files": 100000}
MAX_PATH_RULES = 64
GLOB_SEGMENT_RE = re.compile(r"[A-Za-z0-9._*?-]+")
WITHHELD_SEGMENT_RE = re.compile(r"[A-Za-z0-9._-]+")
PROXY_URL_RE = re.compile(r"http://([0-9.]{7,15}):([1-9][0-9]{0,4})")
MAX_BASELINE_MEMBERS = 500000
WALK_SECONDS = 120.0
HOME_SECONDS = 10.0
MAX_RECORD_PATH = 4096
RECORD_HEADER = 64
RECORD_KINDS = "FSBDGLOWECTZ"
BINARY_SNIFF = 8192
CHANGE_STATUSES = ("ok", "refused", "not_computed")
COUNT_KEYS = ("added", "modified", "deleted", "mode", "binary", "excluded", "withheld")
LOGIN_STATUSES = ("chatgpt", "rejected", None)
BUILD_MEMBERS = ("result.json", "codex-events.jsonl", "codex-stderr.txt", "login.txt", "install.txt",
                 "codex-last.txt", "changes.json", "excluded.json")
CHANGE_MEMBER_RE = re.compile(r"change/(0|[1-9][0-9]{0,5})")
O_BINARY = getattr(os, "O_BINARY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

# The image's own vendored packaging, for the closure check (plan B1.5 step 5). IMAGE_SITE is
# APPENDED: with -I -S the path before it holds only the stdlib, so nothing from /work, /deps or
# the cwd can shadow it, and this runs before anything from the repository exists.
sys.path.append(IMAGE_SITE)
try:
    from pip._vendor.packaging.requirements import Requirement as _Requirement
    from pip._vendor.packaging.version import Version as _Version
except Exception:  # any import failure: every deps run then fails closed
    PACKAGING = None
else:
    PACKAGING = types.SimpleNamespace(Requirement=_Requirement, Version=_Version)


class SpecError(ValueError):
    """The stdin header is not what the protocol allows."""


class DepsError(ValueError):
    """The dependency set cannot be installed or does not form a closed set."""


class BaselineError(ValueError):
    """The snapshot tar cannot be a build baseline."""


class Spec:
    """A validated spec; plain attributes so the file stays trivially self-contained."""

    __slots__ = ("argv", "exports", "capture_cap", "export_cap", "timeout", "tar_len",
                 "deps_len", "deps_sha256", "deps_timeout")
    mode = "run"

    def __init__(self, argv, exports, capture_cap, export_cap, timeout, tar_len,
                 deps_len=0, deps_sha256="", deps_timeout=1):
        self.argv = argv
        self.exports = exports
        self.capture_cap = capture_cap
        self.export_cap = export_cap
        self.timeout = timeout
        self.tar_len = tar_len
        self.deps_len = deps_len
        self.deps_sha256 = deps_sha256
        self.deps_timeout = deps_timeout


class ProbeSpec:
    """A validated probe spec (plan B2 approach 5)."""

    __slots__ = ("targets", "deadline", "exclude")
    mode = "probe"

    def __init__(self, targets, deadline, exclude):
        self.targets = targets
        self.deadline = deadline
        self.exclude = exclude


class BuildSpec:
    """A validated build spec (plan B2 approaches 4, 6, 7)."""

    __slots__ = ("tar_len", "deps_len", "deps_sha256", "deps_timeout", "codex_argv", "proxy_url",
                 "ca_len", "placeholder_len", "prompt_len", "caps", "generated", "withheld",
                 "codex_timeout")
    mode = "build"

    def __init__(self, **values):
        for key in self.__slots__:
            setattr(self, key, values[key])


class Baseline:
    """The build baseline, computed by the uid-0 driver from the snapshot tar bytes."""

    __slots__ = ("files", "dirs", "withheld", "extract")

    def __init__(self, files, dirs, withheld, extract):
        self.files = files        # {path: (sha256 hex, "100644" | "100755")}
        self.dirs = dirs          # every directory path, explicit or implied
        self.withheld = withheld  # member paths at or beneath a withheld prefix, not extracted
        self.extract = extract    # member names to extract, in tar order


# ---------------------------------------------------------------- pure parts


def valid_export_name(name):
    """True for a plain file name: no separator, no leading dot, no colon, 1..64 ASCII."""
    return isinstance(name, str) and EXPORT_NAME_RE.fullmatch(name) is not None


def _int_in(spec, key, low, high):
    value = spec[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError("%s must be an integer" % key)
    if value < low or value > high:
        raise SpecError("%s out of range %d..%d" % (key, low, high))
    return value


def parse_spec(obj):
    """Validate the decoded JSON spec. Unknown keys, wrong types and bad ranges all refuse.
    An optional `mode` selects the spec: absent or "run" is B1's (returns Spec, unchanged),
    "probe" -> ProbeSpec, "build" -> BuildSpec (plan B2, unit U3)."""
    if not isinstance(obj, dict):
        raise SpecError("spec must be a JSON object")
    if "mode" in obj:
        mode = obj["mode"]
        if not isinstance(mode, str) or mode not in MODES:
            raise SpecError("unknown mode")
        if mode == "probe":
            return parse_probe_spec(obj)
        if mode == "build":
            return parse_build_spec(obj)
        obj = {k: v for k, v in obj.items() if k != "mode"}
    extra = sorted(set(obj) - set(SPEC_KEYS))
    if extra:
        raise SpecError("unknown spec key: %s" % ",".join(str(k) for k in extra)[:80])
    missing = [k for k in SPEC_KEYS if k not in obj]
    if missing:
        raise SpecError("missing spec key: %s" % ",".join(missing))
    argv = obj["argv"]
    if not isinstance(argv, list) or not argv:
        raise SpecError("argv must be a non-empty list")
    for item in argv:
        if not isinstance(item, str) or "\x00" in item:
            raise SpecError("argv items must be strings without NUL")
    if argv[0] == "":
        raise SpecError("argv[0] must not be empty")
    exports = obj["exports"]
    if not isinstance(exports, list) or len(exports) > MAX_EXPORTS:
        raise SpecError("exports must be a list of at most %d names" % MAX_EXPORTS)
    for name in exports:
        if not valid_export_name(name):
            raise SpecError("export name not allowed")
    if len(set(exports)) != len(exports):
        raise SpecError("duplicate export name")
    deps_len = _int_in(obj, "deps_len", 0, MAX_DEPS_TAR)
    deps_sha256 = obj["deps_sha256"]
    if not isinstance(deps_sha256, str):
        raise SpecError("deps_sha256 must be a string")
    if deps_len == 0 and deps_sha256 != "":
        raise SpecError("deps_sha256 must be empty when deps_len is 0")
    if deps_len > 0 and EXPORT_SHA_RE.fullmatch(deps_sha256) is None:
        raise SpecError("deps_sha256 must be 64 lowercase hex")
    return Spec(list(argv), list(exports),
                _int_in(obj, "capture_cap", 1, MAX_CAP),
                _int_in(obj, "export_cap", 1, MAX_CAP),
                _int_in(obj, "timeout", 1, MAX_TIMEOUT),
                _int_in(obj, "tar_len", 0, MAX_TAR),
                deps_len, deps_sha256,
                _int_in(obj, "deps_timeout", 1, MAX_TIMEOUT))


def parse_nonce(line):
    """The first stdin line: 32 lowercase hex plus LF. Returns the nonce text."""
    if not isinstance(line, bytes) or not line.endswith(b"\n"):
        raise SpecError("nonce line missing")
    try:
        text = line[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise SpecError("nonce not ASCII")
    if NONCE_RE.fullmatch(text) is None:
        raise SpecError("nonce malformed")
    return text


def parse_header(nonce_line, spec_line):
    """Both header lines -> (nonce, Spec)."""
    nonce = parse_nonce(nonce_line)
    if not spec_line.endswith(b"\n"):
        raise SpecError("spec line missing")
    try:
        obj = json.loads(spec_line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SpecError("spec is not JSON")
    return nonce, parse_spec(obj)


def _check_deps_result(deps, command_status):
    if deps is None:
        if command_status == "deps_failed":
            raise ValueError("deps_failed needs a failed deps object")
        return
    if not isinstance(deps, dict) or set(deps) != {"status", "reason", "installed"}:
        raise ValueError("deps must be null or {status, reason, installed}")
    status, reason, installed = deps["status"], deps["reason"], deps["installed"]
    if status == "installed":
        if reason is not None:
            raise ValueError("an installed deps object carries no reason")
        if command_status == "deps_failed":
            raise ValueError("deps_failed needs a failed deps object")
    elif status == "failed":
        if not isinstance(reason, str):
            raise ValueError("a failed deps object needs a reason")
        if command_status not in ("deps_failed", "not_started"):
            raise ValueError("the command cannot have run after failed deps")
    else:
        raise ValueError("unknown deps status")
    if not isinstance(installed, list):
        raise ValueError("deps installed must be a list")
    for item in installed:
        if (not isinstance(item, list) or len(item) != 2
                or not all(isinstance(part, str) for part in item)):
            raise ValueError("deps installed items are [name, version]")


def build_result(nonce, command_status, command_exit, truncated, durations, exports, infrastructure,
                 deps=None):
    """The result.json document, key order fixed. Raises ValueError on an impossible combination.
    `deps` (B1.5) is appended last, so a run without deps is B1's document plus "deps": null."""
    if command_status not in COMMAND_STATUSES:
        raise ValueError("unknown command_status")
    if command_status == "exited":
        if isinstance(command_exit, bool) or not isinstance(command_exit, int):
            raise ValueError("exited needs an integer command_exit")
    elif command_exit is not None:
        raise ValueError("command_exit only when exited")
    for name, value in exports.items():
        ok = (value == "missing" or (isinstance(value, str) and value.startswith("refused:"))
              or (isinstance(value, str) and EXPORT_SHA_RE.fullmatch(value) is not None))
        if not ok:
            raise ValueError("export value not allowed for %s" % name)
    _check_deps_result(deps, command_status)
    return {"nonce": nonce, "command_status": command_status, "command_exit": command_exit,
            "truncated": bool(truncated), "durations": dict(durations), "exports": dict(exports),
            "infrastructure": infrastructure,
            "deps": None if deps is None else {"status": deps["status"], "reason": deps["reason"],
                                                "installed": [list(i) for i in deps["installed"]]}}


def result_json_bytes(result):
    """Canonical, ASCII-only JSON bytes (non-ASCII is escaped)."""
    return json.dumps(result, sort_keys=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _framed_name_ok(name):
    if name in ("result.json", "stdout.txt", "stderr.txt", "install.txt"):
        return True
    return name.startswith("out/") and valid_export_name(name[4:])


def build_result_tar(members, name_ok=None):
    """Frame (name, bytes) pairs as one deterministic tar: regular members only, mtime 0,
    uid/gid 0, mode 0644, USTAR. Names are limited to the four protocol shapes of a run, or
    to what `name_ok` accepts (build mode passes build_member_ok)."""
    check = _framed_name_ok if name_ok is None else name_ok
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, content in members:
            if not check(name):
                raise ValueError("member name not allowed")
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def member_problem(name, kind):
    """Why a snapshot tar member must be refused, or None. kind: file|dir|symlink|hardlink|..."""
    if kind not in ("file", "dir"):
        return "member type %s not allowed" % kind
    if not name or "\x00" in name or "\\" in name:
        return "member name not allowed"
    if name.startswith("/") or re.match(r"[A-Za-z]:", name):
        return "absolute member name"
    if ".." in name.split("/"):
        return "member name escapes the workspace"
    return None


# ---------------------------------------------------------------- pure parts: dependencies (B1.5)


def _ascii(text):
    """A reason safe for result.json and the host: ASCII, escaped, bounded."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")[:MAX_REASON]


DEPS_TIMEOUT = "deps budget exceeded (timeout)"


def deadline_passed(deadline):
    """True once the monotonic `deadline` (None = no deadline) is reached (inspection round 1,
    B1: one deps deadline, checked between entries of every phase and before every phase)."""
    return deadline is not None and time.monotonic() >= deadline


def normalize_name(name):
    """PEP 503 / PEP 685 normalisation (distribution names and extras)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def wheel_filename_ok(name):
    """True iff the host's parse_wheel_filename accepts `name`:
    {dist}-{version}(-{build})?-{py}-{abi}-{platform}.whl, every field non-empty, tag fields
    dot-separated lists. The host's bounds are copied too (gate initial pass, A1-8): at most
    WHEEL_MAX_FILENAME characters (the deps tar is GNU format, like the runner's, so this is the
    host's limit, not a tar one), at most WHEEL_MAX_TAG_COMPONENTS per tag field and at most
    WHEEL_MAX_TAG_TRIPLES in the product of the three."""
    if not isinstance(name, str) or len(name) > WHEEL_MAX_FILENAME or not name.endswith(".whl"):
        return False
    parts = name[:-4].split("-")
    if len(parts) not in (5, 6) or any(p == "" for p in parts):
        return False
    if WHEEL_DIST_RE.fullmatch(parts[0]) is None or WHEEL_VERSION_RE.fullmatch(parts[1]) is None:
        return False
    if len(parts) == 6 and WHEEL_BUILD_RE.fullmatch(parts[2]) is None:
        return False
    product = 1
    for field in parts[-3:]:
        count = field.count(".") + 1
        product *= count
        if count > WHEEL_MAX_TAG_COMPONENTS or product > WHEEL_MAX_TAG_TRIPLES:
            return False
    return all(WHEEL_TAG_RE.fullmatch(item) is not None
               for field in parts[-3:] for item in field.split("."))


def deps_member_problem(name, kind):
    """Why a deps tar member must be refused, or None: B1's member check, and then only flat
    regular files named requirements.txt or a valid wheel file name (no directory, no ./
    prefix, no link)."""
    problem = member_problem(name, kind)
    if problem is not None:
        return problem
    if kind != "file":
        return "deps member must be a regular file"
    if name != "requirements.txt" and not wheel_filename_ok(name):
        return "deps member name not allowed"
    return None


def deps_tar_problem(deps_bytes):
    """(reason or None, requirements.txt bytes): the whole member list checked in memory before
    any extraction. Exactly one requirements.txt, at least one wheel, no duplicate names."""
    try:
        with tarfile.open(fileobj=io.BytesIO(deps_bytes), mode="r:", errorlevel=2) as tf:
            members = tf.getmembers()
            if len(members) > MAX_DEPS_MEMBERS:
                return "deps tar has too many members", None
            seen = set()
            requirements = None
            for member in members:
                kind = "file" if member.isreg() else "dir" if member.isdir() else "other"
                problem = deps_member_problem(member.name, kind)
                if problem is not None:
                    return "deps tar: %s" % problem, None
                if member.name in seen:
                    return "deps tar: duplicate member", None
                seen.add(member.name)
                if member.name == "requirements.txt":
                    if member.size > MAX_REQ_BYTES:
                        return "deps tar: requirements.txt too large", None
                    requirements = tf.extractfile(member).read()
    except (tarfile.TarError, OSError, ValueError):
        return "deps tar unreadable", None
    if requirements is None:
        return "deps tar: requirements.txt missing", None
    if len(seen) < 2:
        return "deps tar: no wheel", None
    return None, requirements


def parse_deps_requirements(data):
    """The runner's generated requirements.txt -> [(normalised name, version)] in file order.
    Only `name==version --hash=sha256:<64 hex>` + LF per line; anything else refuses."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_REQ_BYTES:
        raise DepsError("requirements.txt empty or too large")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise DepsError("requirements.txt is not ASCII")
    if not text.endswith("\n"):
        raise DepsError("requirements.txt must end with LF")
    lines = text[:-1].split("\n")
    if len(lines) > MAX_DEPS_REQUIREMENTS:
        raise DepsError("requirements.txt has too many lines")
    out = []
    seen = set()
    for number, line in enumerate(lines, 1):
        match = DEPS_REQ_RE.fullmatch(line)
        if match is None or CANON_VERSION_RE.fullmatch(match.group(2)) is None:
            raise DepsError("requirements.txt line %d not in the runner's form" % number)
        name = normalize_name(match.group(1))
        if name in seen:
            raise DepsError("requirements.txt line %d repeats %s" % (number, name))
        seen.add(name)
        out.append((name, match.group(2)))
    return out


def parse_metadata(data, deadline=None):
    """METADATA bytes -> {name, version, requires, extras}; headers only (up to the first blank
    line), folded lines joined. Exactly one Name and one Version. DepsError when unparsable.

    Gate initial pass, block B, findings 1/5: the work is linear in the header size. Lines are
    found one at a time (no split of the whole file), the fragments of a folded header are
    collected in a list and joined ONCE, and every physical header line -- continuations
    included -- counts against MAX_METADATA_LINES. `deadline` (monotonic, optional) is the deps
    deadline; it is checked every METADATA_CHECK_LINES lines inside the file, starting with the
    first, so one large file cannot outrun it."""
    if not isinstance(data, bytes) or len(data) > MAX_METADATA:
        raise DepsError("METADATA too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise DepsError("METADATA is not UTF-8")
    if "\x00" in text:
        raise DepsError("METADATA contains NUL")
    headers = []  # [key, [fragment, ...]]
    pos = 0
    lines = 0
    end = len(text)
    while pos < end:
        if lines % METADATA_CHECK_LINES == 0 and deadline_passed(deadline):
            raise DepsError("%s while parsing METADATA" % DEPS_TIMEOUT)
        nl = text.find("\n", pos)
        if nl < 0:
            nl = end
        line = text[pos:nl]
        pos = nl + 1
        if line.endswith("\r"):
            line = line[:-1]
        if line == "":
            break
        lines += 1
        if lines > MAX_METADATA_LINES:
            raise DepsError("METADATA has too many lines")
        if line[0] in " \t":
            if not headers:
                raise DepsError("METADATA starts with a continuation line")
            headers[-1][1].append(line.strip())
            continue
        key, sep, value = line.partition(":")
        if not sep or not key.strip():
            raise DepsError("METADATA header without colon")
        headers.append([key.strip().lower(), [value.strip()]])
        if len(headers) > MAX_METADATA_HEADERS:
            raise DepsError("METADATA has too many headers")
    headers = [(k, " ".join(parts)) for k, parts in headers]
    names = [v for k, v in headers if k == "name"]
    versions = [v for k, v in headers if k == "version"]
    if len(names) != 1 or len(versions) != 1 or not names[0] or not versions[0]:
        raise DepsError("METADATA needs exactly one Name and one Version")
    return {"name": names[0], "version": versions[0],
            "requires": [v for k, v in headers if k == "requires-dist"],
            "extras": [normalize_name(v) for k, v in headers if k == "provides-extra"]}


def dist_info_name(entry):
    """`<name>-<version>.dist-info` -> (normalised name, version text), else None."""
    if not entry.endswith(".dist-info"):
        return None
    name, sep, version = entry[:-len(".dist-info")].rpartition("-")
    if not sep or DIST_NAME_RE.fullmatch(name) is None or DIST_INFO_VERSION_RE.fullmatch(version) is None:
        return None
    return normalize_name(name), version


def _index_dists(dists, label, pk, check_deadline):
    out = {}
    for item in dists:
        check_deadline()
        key = normalize_name(item["name"])
        if key in out:
            raise DepsError("duplicate distribution %s in %s" % (key, label))
        try:
            version = pk.Version(item["version"])
            if "dir_version" in item and pk.Version(item["dir_version"]) != version:
                raise DepsError("dist-info directory of %s names another version" % key)
        except DepsError:
            raise
        except Exception:
            raise DepsError("unparsable version of %s in %s" % (key, label))
        out[key] = (item, version, label)
    return out


def check_closure(deps_dists, image_dists, requirements, pk, deadline=None):
    """None when the effective set is closed, else DepsError (plan B1.5 step 5, rounds 3/4).

    deps_dists / image_dists: parsed METADATA dicts of /deps/site and the image site-packages
    (`name`, `version`, `requires`, `extras`, optionally `dir_version`); requirements: the
    [(name, version)] of requirements.txt; pk: the packaging namespace (Requirement, Version),
    None -> fails closed. /deps/site shadows the image; every effective distribution seeds the
    worklist with no extras; each Requires-Dist marker is evaluated with extra "" and once per
    requested extra; an active edge must name an effective distribution whose version matches,
    and the extras it requests (declared by the target, else failure) are propagated until no
    set grows. No dependency code is imported or run here. `deadline` (monotonic, optional) is
    checked before the check starts, before each indexed distribution and each requirement,
    before each worklist step, Requires-Dist parse and edge, after each marker evaluation and
    before each extra (inspection rounds 1 and 2, B1): once it is reached the check raises a
    timeout DepsError instead of finishing."""
    if pk is None:
        raise DepsError("packaging unavailable")

    def check_deadline():
        if deadline_passed(deadline):
            raise DepsError("%s during the closure check" % DEPS_TIMEOUT)

    check_deadline()
    deps_map = _index_dists(deps_dists, "/deps/site", pk, check_deadline)
    image_map = _index_dists(image_dists, "the image", pk, check_deadline)
    wanted = {}
    for name, version in requirements:
        wanted[normalize_name(name)] = version
    for key in sorted(wanted):
        check_deadline()
        if key not in deps_map:
            raise DepsError("requirement %s==%s is not installed in /deps/site" % (key, wanted[key]))
        try:
            same = deps_map[key][1] == pk.Version(wanted[key])
        except Exception:
            raise DepsError("unparsable version of %s in requirements.txt" % key)
        if not same:
            raise DepsError("installed %s %s differs from requirements.txt %s"
                            % (key, deps_map[key][0]["version"], wanted[key]))
    for key in sorted(deps_map):
        if key not in wanted:
            raise DepsError("dist-info %s in /deps/site is not in requirements.txt" % key)
    effective = dict(image_map)
    effective.update(deps_map)
    declared = {key: {normalize_name(e) for e in entry[0]["extras"]} for key, entry in effective.items()}
    requested = {key: set() for key in effective}
    parsed = {}
    queue = sorted(effective)
    queued = set(queue)
    limit = len(effective) + sum(len(v) for v in declared.values()) + 1
    steps = 0
    while queue:
        check_deadline()
        steps += 1
        if steps > limit:
            raise DepsError("closure check did not converge")
        key = queue.pop(0)
        queued.discard(key)
        item, _version, label = effective[key]
        if key not in parsed:
            reqs = []
            for text in item["requires"]:
                check_deadline()
                try:
                    reqs.append(pk.Requirement(text))
                except Exception:
                    raise DepsError("unparsable Requires-Dist of %s (%s)" % (key, label))
            parsed[key] = reqs
        for req in parsed[key]:
            check_deadline()
            envs = [""] + sorted(requested[key])
            try:
                active = req.marker is None or any(req.marker.evaluate({"extra": e}) for e in envs)
            except Exception:
                raise DepsError("marker of a Requires-Dist of %s cannot be evaluated" % key)
            check_deadline()
            if not active:
                continue
            if getattr(req, "url", None):
                raise DepsError("%s has a direct url requirement" % key)
            target = normalize_name(req.name)
            if target not in effective:
                raise DepsError("%s %s (%s) requires %s, which is not installed"
                                % (key, item["version"], label, str(req)))
            t_item, t_version, t_label = effective[target]
            if not req.specifier.contains(t_version, prereleases=True):
                raise DepsError("%s %s (%s) requires %s; effective %s is %s (%s)"
                                % (key, item["version"], label, str(req), target, t_item["version"], t_label))
            for extra in sorted(normalize_name(x) for x in req.extras):
                check_deadline()
                if extra not in declared[target]:
                    raise DepsError("%s requests extra %s that %s does not declare" % (key, extra, target))
                if extra not in requested[target]:
                    requested[target].add(extra)
                    if target not in queued:
                        queue.append(target)
                        queued.add(target)
    return None


def deps_entry_problem(label, st):
    """Why one /deps/site or /deps/wheels entry (lstat result) is not acceptable, or None."""
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        return "%s: symlink" % label
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return "%s: not a regular file or directory" % label
    if st.st_uid != DEPS_UID:
        return "%s: not owned by 65531" % label
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "%s: group- or other-writable" % label
    if mode & (stat.S_ISUID | stat.S_ISGID):
        return "%s: setuid or setgid" % label
    # Inspection round 1, B2: the command (65532) is neither the owner nor in group 65531, so the
    # OTHER bits decide whether it can import the tree.
    if stat.S_ISREG(mode) and not mode & stat.S_IROTH:
        return "%s: not readable by the command (needs o+r)" % label
    if stat.S_ISDIR(mode) and (mode & (stat.S_IROTH | stat.S_IXOTH)) != (stat.S_IROTH | stat.S_IXOTH):
        return "%s: not readable and searchable by the command (needs o+rx)" % label
    return None


def deps_root_problem(st, entries):
    """/deps itself, before extraction: an empty directory, root-owned, mode exactly 1777."""
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
            or stat.S_IMODE(st.st_mode) != 0o1777 or entries):
        return "/deps is not an empty root-owned 1777 directory"
    return None


def pip_install_argv(deps):
    """Plan B1.5 step 5, flags verbatim."""
    return ["python3", "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes",
            "--only-binary=:all:", "--no-compile", "--no-cache-dir", "--no-warn-script-location",
            "--disable-pip-version-check", "--isolated", "--target", deps + "/site",
            "--find-links", deps + "/wheels", "-r", deps + "/wheels/requirements.txt"]


def install_env(deps):
    """The installer's whole environment, built from scratch."""
    # bandit B108: /deps/tmp is a 65531-owned 0755 directory on the per-run /deps tmpfs inside the
    # container, not a shared /tmp.
    return {"HOME": deps + "/home", "TMPDIR": deps + "/tmp", "PATH": INSTALL_PATH}  # nosec B108


def parse_proc_status(text):
    """(real uid, state letter) from the text of /proc/<pid>/status. ValueError if absent."""
    uid = None
    state = None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) < 2:
                raise ValueError("Uid line malformed")
            try:
                uid = int(parts[1])
            except ValueError:
                raise ValueError("Uid line malformed")
        elif line.startswith("State:"):
            parts = line.split()
            if len(parts) < 2 or not parts[1][:1].isalpha():
                raise ValueError("State line malformed")
            state = parts[1][:1]
    if uid is None or state is None:
        raise ValueError("status lacks Uid or State")
    return uid, state


def scan_proc(proc_root, uids):
    """(live pids, zombie pids) owned by any uid in `uids` (a set, or one int). A process that
    vanishes while scanned is skipped; a listing that cannot be read, or a status that cannot be
    parsed, raises (fail closed: the caller reports an infrastructure failure)."""
    wanted = {uids} if isinstance(uids, int) else set(uids)
    live = []
    zombies = []
    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, entry, "status"), "r", encoding="ascii",
                      errors="replace") as handle:
                text = handle.read()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as exc:
            if exc.errno in (errno.ESRCH, errno.ENOENT):
                continue
            raise
        owner, state = parse_proc_status(text)
        if owner not in wanted:
            continue
        if state == "Z":
            zombies.append(int(entry))
        else:
            live.append(int(entry))
    return live, zombies


# ---------------------------------------------------------------- pure parts: B2 specs


def _keys_exact(obj, keys, what):
    extra = sorted(str(k) for k in set(obj) - set(keys))
    if extra:
        raise SpecError("unknown %s spec key: %s" % (what, ",".join(extra)[:80]))
    missing = [k for k in keys if k not in obj]
    if missing:
        raise SpecError("missing %s spec key: %s" % (what, ",".join(missing)))


def _ip_literal(text):
    """The canonical IP literal `text`, else None (no leading zeros, lower-case IPv6)."""
    if not isinstance(text, str):
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    return text if str(addr) == text else None


def parse_probe_spec(obj):
    """mode "probe": probe_targets, probe_deadline, exclude_addrs (plan B2 approach 5)."""
    _keys_exact(obj, PROBE_SPEC_KEYS, "probe")
    exclude = obj["exclude_addrs"]
    if not isinstance(exclude, list) or len(exclude) > MAX_EXCLUDE_ADDRS:
        raise SpecError("exclude_addrs must be a list of at most %d addresses" % MAX_EXCLUDE_ADDRS)
    for addr in exclude:
        if _ip_literal(addr) is None:
            raise SpecError("exclude_addrs holds something that is not a canonical IP literal")
    targets = obj["probe_targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_PROBE_TARGETS:
        raise SpecError("probe_targets must be a list of 1..%d targets" % MAX_PROBE_TARGETS)
    out = []
    for item in targets:
        if not isinstance(item, list) or len(item) != 3:
            raise SpecError("a probe target is [proto, host, port]")
        proto, host, port = item
        if proto not in PROBE_PROTOS or not isinstance(proto, str):
            raise SpecError("probe proto must be tcp, udp or dns")
        if isinstance(port, bool) or not isinstance(port, int):
            raise SpecError("probe port must be an integer")
        if proto == "dns":
            if (not isinstance(host, str) or HOSTNAME_RE.fullmatch(host) is None
                    or _ip_literal(host) is not None or port != 0):
                raise SpecError("a dns target is [\"dns\", <host name>, 0]")
        else:
            if _ip_literal(host) is None:
                raise SpecError("a tcp/udp target needs a canonical IP literal")
            if not 1 <= port <= 65535:
                raise SpecError("probe port out of range 1..65535")
            if host in exclude:
                raise SpecError("probe target %s is an excluded address" % host)
        out.append((proto, host, port))
    return ProbeSpec(out, _int_in(obj, "probe_deadline", 1, MAX_PROBE_DEADLINE), tuple(exclude))


def validate_codex_argv(argv):
    """The Codex start line (plan B2 approach 7, measurement 2026-11-01 (e)): CODEX_PREFIX
    verbatim, then only `-c <key>=<value>` from a closed list (sandbox_mode, approval_policy and
    notify with their fixed values, model and model_reasoning_effort quoted, each exactly once)
    and `--disable <feature>`, then `--json -o <OUT>/codex-last.txt -` (prompt on stdin)."""
    if not isinstance(argv, list) or not len(CODEX_PREFIX) + 4 <= len(argv) <= MAX_CODEX_ARGV:
        raise SpecError("codex_argv must be a list of %d..%d strings" % (len(CODEX_PREFIX) + 4, MAX_CODEX_ARGV))
    for item in argv:
        if not isinstance(item, str) or "\x00" in item or len(item) > 256:
            raise SpecError("codex_argv items must be short strings without NUL")
    if tuple(argv[:len(CODEX_PREFIX)]) != CODEX_PREFIX:
        raise SpecError("codex_argv must start with: %s" % " ".join(CODEX_PREFIX))
    if argv[-4:] != ["--json", "-o", OUT + "/" + LAST_NAME, "-"]:
        raise SpecError("codex_argv must end with: --json -o %s -" % OUT + "/" + LAST_NAME)
    middle = argv[len(CODEX_PREFIX):-4]
    seen = set()
    i = 0
    while i < len(middle):
        flag = middle[i]
        value = middle[i + 1] if i + 1 < len(middle) else None
        if flag == "-c" and value is not None:
            key, sep, setting = value.partition("=")
            if not sep or key in seen:
                raise SpecError("codex_argv: -c %s is malformed or repeated" % _ascii(key)[:40])
            if key in CODEX_FIXED:
                if setting != CODEX_FIXED[key]:
                    raise SpecError("codex_argv: %s must be %s" % (key, CODEX_FIXED[key]))
            elif key in CODEX_FREE:
                if CODEX_FREE[key].fullmatch(setting) is None:
                    raise SpecError("codex_argv: %s value not allowed" % key)
            else:
                raise SpecError("codex_argv: -c %s is not allowed" % _ascii(key)[:40])
            seen.add(key)
        elif flag == "--disable" and value is not None and FEATURE_RE.fullmatch(value):
            pass
        else:
            raise SpecError("codex_argv: argument %s is not allowed" % _ascii(flag)[:40])
        i += 2
    missing = sorted((set(CODEX_FIXED) | set(CODEX_FREE)) - seen)
    if missing:
        raise SpecError("codex_argv lacks -c %s" % ",".join(missing))
    return list(argv)


def parse_generated(patterns):
    """`generated_paths` -> tuple of segment tuples. A pattern is root-relative, `/`-separated;
    a segment is `**` (any number of segments) or text with `*` and `?` (no brackets)."""
    if not isinstance(patterns, list) or len(patterns) > MAX_PATH_RULES:
        raise SpecError("generated_paths must be a list of at most %d patterns" % MAX_PATH_RULES)
    out = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 256:
            raise SpecError("a generated_paths pattern must be a non-empty string")
        segs = tuple(pattern.split("/"))
        for seg in segs:
            if seg != "**" and (GLOB_SEGMENT_RE.fullmatch(seg) is None or seg in (".", "..")
                                or "**" in seg):
                raise SpecError("generated_paths pattern not allowed: %s" % _ascii(pattern)[:60])
        out.append(segs)
    return tuple(out)


def parse_withheld(patterns):
    """`withheld_paths` -> tuple of root-relative prefixes. Only `<literal path>/**`."""
    if not isinstance(patterns, list) or len(patterns) > MAX_PATH_RULES:
        raise SpecError("withheld_paths must be a list of at most %d patterns" % MAX_PATH_RULES)
    out = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.endswith("/**") or len(pattern) > 256:
            raise SpecError("a withheld_paths pattern must be <path>/**")
        segs = pattern[:-3].split("/")
        for seg in segs:
            if WITHHELD_SEGMENT_RE.fullmatch(seg) is None or seg in (".", ".."):
                raise SpecError("withheld_paths pattern not allowed: %s" % _ascii(pattern)[:60])
        out.append("/".join(segs))
    return tuple(out)


def _closure(states, pat):
    out = set(states)
    stack = list(states)
    while stack:
        i = stack.pop()
        if i < len(pat) and pat[i] == "**" and i + 1 not in out:
            out.add(i + 1)
            stack.append(i + 1)
    return out


def _segments_match(pat, segs):
    """Linear NFA over segments: `**` matches zero or more segments, others fnmatchcase."""
    states = _closure({0}, pat)
    for seg in segs:
        nxt = set()
        for i in states:
            if i < len(pat):
                if pat[i] == "**":
                    nxt.add(i)
                elif fnmatch.fnmatchcase(seg, pat[i]):
                    nxt.add(i + 1)
        states = _closure(nxt, pat)
        if not states:
            return False
    return len(pat) in states


def generated_match(patterns, path):
    """True iff `path` (root-relative, `/`-separated) matches any parsed generated pattern."""
    segs = path.split("/")
    return any(_segments_match(pat, segs) for pat in patterns)


def under_any(prefixes, path):
    """True iff `path` is a withheld prefix or lies beneath one."""
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def git_component(path):
    """True iff any segment is `.git` in any case (a builder repository, never published)."""
    return any(seg.lower() == ".git" for seg in path.split("/"))


def change_path_problem(path):
    """Why `path` cannot be part of a change set, or None: printable ASCII, no backslash."""
    if not path:
        return "empty path"
    if any(not 0x20 <= ord(c) <= 0x7e for c in path):
        return "path is not printable ASCII"
    if "\\" in path:
        return "path contains a backslash"
    return None


def parse_build_spec(obj):
    """mode "build" (plan B2 interface, sandbox_driver.py (U3))."""
    _keys_exact(obj, BUILD_SPEC_KEYS, "build")
    deps_len = _int_in(obj, "deps_len", 0, MAX_DEPS_TAR)
    deps_sha256 = obj["deps_sha256"]
    if not isinstance(deps_sha256, str):
        raise SpecError("deps_sha256 must be a string")
    if deps_len == 0 and deps_sha256 != "":
        raise SpecError("deps_sha256 must be empty when deps_len is 0")
    if deps_len > 0 and EXPORT_SHA_RE.fullmatch(deps_sha256) is None:
        raise SpecError("deps_sha256 must be 64 lowercase hex")
    url = obj["proxy_url"]
    match = PROXY_URL_RE.fullmatch(url) if isinstance(url, str) else None
    if (match is None or _ip_literal(match.group(1)) is None or ":" in match.group(1)
            or not 1 <= int(match.group(2)) <= 65535):
        raise SpecError("proxy_url must be http://<IPv4>:<port>")
    caps = obj["change_caps"]
    if not isinstance(caps, dict) or set(caps) != set(CAP_BOUNDS):
        raise SpecError("change_caps must hold exactly %s" % ",".join(sorted(CAP_BOUNDS)))
    caps = {key: _int_in(caps, key, 1, high) for key, high in CAP_BOUNDS.items()}
    return BuildSpec(
        tar_len=_int_in(obj, "tar_len", 0, MAX_TAR), deps_len=deps_len, deps_sha256=deps_sha256,
        deps_timeout=_int_in(obj, "deps_timeout", 1, MAX_TIMEOUT),
        codex_argv=validate_codex_argv(obj["codex_argv"]), proxy_url=url,
        ca_len=_int_in(obj, "ca_len", 1, MAX_CA),
        placeholder_len=_int_in(obj, "placeholder_len", 1, MAX_PLACEHOLDER),
        prompt_len=_int_in(obj, "prompt_len", 1, MAX_PROMPT), caps=caps,
        generated=parse_generated(obj["generated_paths"]), withheld=parse_withheld(obj["withheld_paths"]),
        codex_timeout=_int_in(obj, "codex_timeout", 1, MAX_TIMEOUT))


# ---------------------------------------------------------------- pure parts: B2 baseline and change set


def baseline_from_tar(tar_bytes, withheld):
    """Baseline of the snapshot tar BYTES (plan B2 approach 4): regular members -> (sha256, git
    mode); directories explicit and implied; withheld members recorded, not extracted. Every
    member passes member_problem(); a .git component (any case) or a duplicate refuses."""
    files, dirs, held, extract, seen = {}, set(), [], [], set()
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:", errorlevel=2) as tf:
            members = tf.getmembers()
            if len(members) > MAX_BASELINE_MEMBERS:
                raise BaselineError("snapshot has too many members")
            for member in members:
                kind = "file" if member.isreg() else "dir" if member.isdir() else "other"
                problem = member_problem(member.name, kind)
                if problem is not None:
                    raise BaselineError("snapshot member refused: %s" % problem)
                name = member.name[2:] if member.name.startswith("./") else member.name
                segs = name.split("/")
                if not name or any(s in ("", ".", "..") for s in segs):
                    raise BaselineError("snapshot member name not canonical")
                if git_component(name):
                    raise BaselineError("snapshot contains a .git path")
                if name in seen:
                    raise BaselineError("snapshot member repeated")
                seen.add(name)
                if under_any(withheld, name):
                    held.append(name)
                    continue
                extract.append(member.name)
                for i in range(1, len(segs)):
                    dirs.add("/".join(segs[:i]))
                if member.isdir():
                    dirs.add(name)
                    continue
                data = tf.extractfile(member).read()
                files[name] = (hashlib.sha256(data).hexdigest(),
                               "100755" if member.mode & stat.S_IXUSR else "100644")
    except BaselineError:
        raise
    except (tarfile.TarError, OSError, ValueError, EOFError):
        raise BaselineError("snapshot tar unreadable")
    return Baseline(files, dirs, held, extract)


def encode_record(kind, mode, size, path, data=b""):
    """One walk record: `<kind> <st_mode> <size> <path length>\\n<path bytes>` + `data` (file
    bytes for F, an ASCII reason for E, nothing for any other kind)."""
    return b"%s %d %d %d\n" % (kind.encode("ascii"), mode, size, len(path)) + path + data


def parse_records(data):
    """The helper's whole output -> [(kind, st_mode, size, path bytes, data)], ending with Z.
    ValueError on anything else (malformed header, short body, missing or early end)."""
    out = []
    pos = 0
    end = len(data)
    while True:
        nl = data.find(b"\n", pos, pos + RECORD_HEADER)
        if nl < 0:
            raise ValueError("walk record header malformed or missing")
        parts = data[pos:nl].split(b" ")
        if len(parts) != 4 or len(parts[0]) != 1 or not all(p.isdigit() for p in parts[1:]):
            raise ValueError("walk record header malformed")
        kind = parts[0].decode("ascii", "replace")
        if kind not in RECORD_KINDS:
            raise ValueError("walk record kind unknown")
        mode, size, plen = (int(p) for p in parts[1:])
        if plen > MAX_RECORD_PATH:
            raise ValueError("walk record path too long")
        pos = nl + 1
        path = data[pos:pos + plen]
        if len(path) != plen:
            raise ValueError("walk record path short")
        pos += plen
        body = b""
        if kind in ("F", "E"):
            body = data[pos:pos + size]
            if len(body) != size:
                raise ValueError("walk record body short")
            pos += size
        out.append((kind, mode, size, path, body))
        if kind == "Z":
            if pos != end:
                raise ValueError("data after the end record")
            return out


def is_binary(data):
    """A NUL byte in the first 8 KiB, or not UTF-8 as a whole."""
    if b"\x00" in data[:BINARY_SNIFF]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _zero_counts(withheld):
    counts = {key: 0 for key in COUNT_KEYS}
    counts["withheld"] = len(withheld)
    return counts


def compute_changes(baseline, records, generated, caps):
    """Walk records vs. the baseline (plan B2 approach 7). Returns {status "ok" | "refused",
    reason, changes (sorted by path; fields op, path, mode, base_mode, sha256, size, binary,
    base_sha256), blobs [(index in changes, bytes)] for added and modified entries, excluded
    [{path, reason git|generated|empty_dir, entries}], withheld, counts}."""
    withheld = list(baseline.withheld)

    def refused(reason):
        return {"status": "refused", "reason": _ascii(reason), "changes": [], "blobs": [],
                "excluded": [], "withheld": withheld, "counts": _zero_counts(withheld)}

    if not records or records[-1][0] != "Z":
        return refused("the walk did not complete")
    found = {}
    excluded = []
    total = 0
    for number, (kind, mode, size, raw, body) in enumerate(records[:-1], 1):
        if number > caps["entries"] or kind == "C":
            return refused("the walk is over the entry cap (%d)" % caps["entries"])
        if kind == "T":
            return refused("the change set is over the byte cap (%d)" % caps["total_bytes"])
        if kind == "E":
            return refused("the walk failed: %s" % body.decode("ascii", "backslashreplace"))
        if kind == "Z":
            return refused("the walk ended early")
        try:
            path = raw.decode("utf-8")
        except UnicodeDecodeError:
            return refused("a path is not UTF-8: %r" % raw[:60])
        if kind == "W":
            return refused("an entry at or beneath a withheld path: %s" % path)
        if kind == "B":
            return refused("a file is over the per-file cap (%d): %s" % (caps["file_bytes"], path))
        if kind == "G":
            excluded.append({"path": path, "reason": "git", "entries": size + 1})
            continue
        in_base = path in baseline.files
        if kind in ("L", "O"):
            if not in_base and generated_match(generated, path):
                excluded.append({"path": path, "reason": "generated", "entries": 1})
                continue
            return refused("%s at %s" % ("a symlink" if kind == "L" else "a special file (device, FIFO "
                                         "or socket)", path))
        if kind == "D":
            if size == 0 and path not in baseline.dirs and not in_base:
                excluded.append({"path": path, "entries": 1, "reason": "generated"
                                 if generated_match(generated, path) else "empty_dir"})
            continue
        if kind == "S":
            if in_base or not generated_match(generated, path):
                return refused("the walk skipped a path it must send: %s" % path)
            excluded.append({"path": path, "reason": "generated", "entries": 1})
            continue
        # kind == "F"
        if size > caps["file_bytes"]:
            return refused("a file is over the per-file cap (%d): %s" % (caps["file_bytes"], path))
        total += size
        if total > caps["total_bytes"]:
            return refused("the change set is over the byte cap (%d)" % caps["total_bytes"])
        if path in found:
            return refused("the walk sent a path twice: %s" % path)
        if not in_base and generated_match(generated, path):
            excluded.append({"path": path, "reason": "generated", "entries": 1})
            continue
        found[path] = ("100755" if mode & stat.S_IXUSR else "100644", body)
    entries = []
    added = 0
    for path in sorted(set(found) | set(baseline.files)):
        base = baseline.files.get(path)
        if path in found:
            gmode, data = found[path]
            digest = hashlib.sha256(data).hexdigest()
            if base is None:
                op = "added"
                added += 1
                if added > caps["added_files"]:
                    return refused("more than %d added files" % caps["added_files"])
            elif digest != base[0]:
                op = "modified"
            elif gmode != base[1]:
                op = "mode"
            else:
                continue
            entry = {"op": op, "path": path, "mode": gmode, "base_mode": None if base is None else base[1],
                     "sha256": digest, "size": len(data), "binary": is_binary(data),
                     "base_sha256": None if base is None else base[0]}
            blob = data if op in ("added", "modified") else None
        else:
            entry = {"op": "deleted", "path": path, "mode": None, "base_mode": base[1], "sha256": None,
                     "size": None, "binary": None, "base_sha256": base[0]}
            blob = None
        problem = change_path_problem(path)
        if problem is not None:
            return refused("%s: %r" % (problem, path))
        entries.append((entry, blob))
    changes = [entry for entry, _blob in entries]
    blobs = [(n, blob) for n, (_entry, blob) in enumerate(entries) if blob is not None]
    excluded.sort(key=lambda e: e["path"])
    for item in excluded:
        if change_path_problem(item["path"]) is not None:
            item["path"] = _ascii(item["path"])
    counts = _zero_counts(withheld)
    for entry in changes:
        counts[entry["op"]] += 1
        counts["binary"] += 1 if entry["binary"] else 0
    counts["excluded"] = len(excluded)
    return {"status": "ok", "reason": None, "changes": changes, "blobs": blobs, "excluded": excluded,
            "withheld": withheld, "counts": counts}


# ---------------------------------------------------------------- pure parts: B2 probe, login, results


def classify_errno(err):
    """A socket outcome: 0 or ECONNREFUSED (a host answered) -> reached; no route, no host,
    refused by policy -> blocked; ETIMEDOUT -> timeout; anything else -> error."""
    if err == 0 or err == errno.ECONNREFUSED:
        return "reached"
    if err in BLOCKED_ERRNOS:
        return "blocked"
    if err == errno.ETIMEDOUT:
        return "timeout"
    return "error"


def probe_status(outcomes, default_route, killed):
    """isolation_failed on one reached target or a default route; isolation_unverified when
    the child was killed or any target is not reported as blocked; else isolated."""
    if default_route or "reached" in outcomes:
        return "isolation_failed"
    if killed or not outcomes or any(o != "blocked" for o in outcomes):
        return "isolation_unverified"
    return "isolated"


def default_route_v4(text):
    """True iff /proc/net/route holds an up, non-reject 0.0.0.0/0 route. ValueError if the
    text is not that table."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("Iface"):
        raise ValueError("not a route table")
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 8:
            raise ValueError("route line malformed")
        flags = int(fields[3], 16)
        if fields[1] == "00000000" and fields[7] == "00000000" and flags & RTF_UP and not flags & RTF_REJECT:
            return True
    return False


def default_route_v6(text):
    """True iff /proc/net/ipv6_route holds an up, non-reject ::/0 route."""
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 10:
            raise ValueError("ipv6 route line malformed")
        flags = int(fields[8], 16)
        if fields[0] == "0" * 32 and fields[1] == "00" and flags & RTF_UP and not flags & RTF_REJECT:
            return True
    return False


def login_ok(exit_code, output):
    """`codex login status` accepted the placeholder as a ChatGPT login (measurement (a))."""
    return exit_code == 0 and LOGIN_OK in output


def codex_env(proxy_url, with_deps):
    """The whole environment of `codex login status` and `codex exec`, built from scratch."""
    env = dict(CHILD_ENV)
    env["PATH"] = BUILD_PATH
    env["CODEX_HOME"] = CODEX_HOME
    env["CODEX_CA_CERTIFICATE"] = CODEX_HOME + "/ca.pem"
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        env[key] = proxy_url
    env["NO_PROXY"] = env["no_proxy"] = ""
    if with_deps:
        env["PYTHONPATH"] = DEPS + "/site"
    return env


def build_build_result(nonce, command_status, command_exit, truncated, durations, exports, infrastructure,
                       deps, build):
    """B1's result.json (command = the Codex turn) plus "build" last. ValueError when the build
    object does not fit the protocol."""
    result = build_result(nonce, command_status, command_exit, truncated, durations, exports,
                          infrastructure, deps=deps)
    if not isinstance(build, dict) or set(build) != {"codex_exit", "change_status", "change_reason", "counts",
                                                      "login_status"}:
        raise ValueError("build object keys")
    if build["codex_exit"] != command_exit or type(build["codex_exit"]) is not type(command_exit):
        raise ValueError("codex_exit must equal command_exit")
    if build["change_status"] not in CHANGE_STATUSES:
        raise ValueError("unknown change_status")
    reason = build["change_reason"]
    if (build["change_status"] == "refused") != isinstance(reason, str) or (reason is not None
                                                                              and not isinstance(reason, str)):
        raise ValueError("change_reason is a string exactly when refused")
    counts = build["counts"]
    if (not isinstance(counts, dict) or set(counts) != set(COUNT_KEYS)
            or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in counts.values())):
        raise ValueError("counts")
    if build["login_status"] not in LOGIN_STATUSES:
        raise ValueError("unknown login_status")
    result["build"] = {"codex_exit": build["codex_exit"], "change_status": build["change_status"],
                       "change_reason": reason, "counts": {k: counts[k] for k in COUNT_KEYS},
                       "login_status": build["login_status"]}
    return result


def build_probe_result(nonce, status, default_route, child_killed, results, durations, infrastructure):
    """The probe's result.json, key order fixed."""
    if status not in PROBE_STATUSES:
        raise ValueError("unknown probe status")
    counts = {key: 0 for key in PROBE_OUTCOMES}
    rows = []
    for proto, host, port, outcome, detail in results:
        if outcome not in PROBE_OUTCOMES:
            raise ValueError("unknown probe outcome")
        counts[outcome] += 1
        rows.append([proto, host, port, outcome, _ascii(detail)[:80]])
    return {"nonce": nonce, "mode": "probe", "status": status, "default_route": bool(default_route),
            "child_killed": bool(child_killed), "counts": counts, "results": rows,
            "durations": dict(durations), "infrastructure": infrastructure}


def build_member_ok(name):
    """Member names of the build result tar."""
    return name in BUILD_MEMBERS or CHANGE_MEMBER_RE.fullmatch(name) is not None


# ---------------------------------------------------------------- container-side actions


def _drop_privileges(uid, gid):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        raise OSError("privilege drop incomplete")


def _wait_child(pid, seconds):
    """Wait for `pid` up to `seconds`; returns its wait status or None after killing it."""
    end = time.monotonic() + seconds
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return status
        if time.monotonic() >= end:
            try:
                os.kill(pid, SIGKILL)
            except OSError:
                pass
            os.waitpid(pid, 0)
            return None
        time.sleep(0.01)


def _read_exact(stream, count, what="snapshot tar", key=None):
    if key is None:
        key = "deps_len" if what == "deps tar" else "tar_len"
    chunks = []
    left = count
    while left:
        chunk = stream.read(min(left, 1 << 20))
        if not chunk:
            raise SpecError("%s shorter than %s" % (what, key))
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def extract_snapshot(tar_bytes, dest=None, names=None):
    """Extract into /work as a uid-65532 child, then verify ownership and writability.
    Returns None on success or an ASCII reason. Build mode (plan B2 approach 4) passes
    dest=/work/repo, which the child creates, and `names`, the members to extract (the
    withheld ones are left out)."""
    target = WORK if dest is None else dest
    wanted = None if names is None else set(names)
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            _drop_privileges(RUN_UID, RUN_GID)
            if dest is not None:
                os.mkdir(target, 0o755)
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:", errorlevel=2) as tf:
                members = tf.getmembers()
                for member in members:
                    kind = "file" if member.isreg() else "dir" if member.isdir() else "other"
                    if member_problem(member.name, kind) is not None:
                        raise ValueError("member refused")
                if wanted is not None:
                    members = [m for m in members if m.name in wanted]
                # bandit B202: every member passed member_problem() above (regular file or dir,
                # no link, no absolute path, no ".."), plus filter="tar" and errorlevel=2.
                tf.extractall(target, members=members, filter="tar")  # nosec B202
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    status = _wait_child(pid, EXTRACT_SECONDS)
    if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        return "snapshot extraction failed"
    for base, dirs, files in os.walk(WORK):
        for name in dirs + files:
            st = os.lstat(os.path.join(base, name))
            if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                return "extracted entry has a disallowed type"
            if st.st_uid != RUN_UID or not (st.st_mode & stat.S_IWUSR):
                return "extracted entry not owned by 65532 or not writable"
    return None


def _exec_child(argv, out_fd, err_fd, report_fd, cwd, env, uid, gid, umask=None, stdin_fd=None):
    """Runs in a forked child (the command, the installer, Codex): never returns. stdin is
    /dev/null unless `stdin_fd` (build mode: the prompt memfd) is given."""
    try:
        os.setsid()
        _drop_privileges(uid, gid)
        if umask is not None:
            os.umask(umask)
        os.chdir(cwd)
        source = os.open("/dev/null", os.O_RDONLY) if stdin_fd is None else stdin_fd
        os.dup2(source, 0)
        os.dup2(out_fd, 1)
        os.dup2(err_fd, 2)
        os.execvpe(argv[0], argv, dict(env))
    except BaseException as exc:
        try:
            os.write(report_fd, ("exec failed: %s" % type(exc).__name__).encode("ascii"))
        except BaseException:
            pass
    finally:
        os._exit(127)


class CaptureError(Exception):
    """The capture could not be finalised (quiescence failed, a pipe never closed): an
    infrastructure failure, never a command result."""


class _Capture:
    """stdout and stderr as PIPES that only this driver reads and counts.

    Closing-gate finding (B1, SECURITY 3): regular capture files let repository code truncate
    an oversized capture (`ftruncate`) before the size poll saw it, and a descendant that kept
    the descriptor could write past the cap after the last check. A pipe cannot be truncated or
    rewound, and every byte that crosses it is counted here, kept up to the cap."""

    def __init__(self, cap, err_cap=None):
        self.cap = cap
        out_r, self.out_w = os.pipe()
        err_r, self.err_w = os.pipe()
        self.bufs = {out_r: bytearray(), err_r: bytearray()}
        self.seen = {out_r: 0, err_r: 0}
        # per pipe; stderr has its own cap only in build mode (Codex: 16 MiB events, 1 MiB stderr)
        self.caps = {out_r: cap, err_r: cap if err_cap is None else err_cap}
        self.open = {out_r, err_r}
        self.out_r, self.err_r = out_r, err_r

    def close_write_ends(self):
        for fd in (self.out_w, self.err_w):
            os.close(fd)

    def pump(self, wait):
        """Read whatever is ready within `wait` seconds; a closed pipe leaves the set."""
        if not self.open:
            time.sleep(wait)
            return
        ready, _, _ = select.select(list(self.open), [], [], wait)
        for fd in ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                self.open.discard(fd)
                os.close(fd)
                continue
            self.seen[fd] += len(chunk)
            room = self.caps[fd] - len(self.bufs[fd])
            if room > 0:
                self.bufs[fd] += chunk[:room]

    def over(self):
        return any(n > self.caps[fd] for fd, n in self.seen.items())

    def drain(self, seconds):
        """Read to EOF on both pipes; called only after quiesce(), so no writer is left."""
        end = time.monotonic() + seconds
        while self.open and time.monotonic() < end:
            self.pump(0.05)
        if self.open:
            raise CaptureError("capture pipes did not close after quiescence")

    def close(self):
        for fd in list(self.open):
            os.close(fd)
        self.open.clear()


def run_command(spec, timeout=None, extra_env=None):
    """Run the command as uid 65532 in /work and capture it under the caps.

    The status is decided only AFTER every uid-65532 process is dead and both capture pipes are
    read to EOF: a descendant that writes after the command exited is still counted, and any
    byte beyond the cap is `output_limit` with no exit code -- never "exited, exit 0".
    `timeout` defaults to the spec's (B1.5 passes what the deps phase left of it); `extra_env`
    adds PYTHONPATH=/deps/site after an installed dependency set.
    Returns (status, exit, truncated, stdout bytes, stderr bytes, reason or None); raises
    CaptureError when the capture cannot be finalised."""
    env = dict(CHILD_ENV)
    env.update(extra_env or {})
    return _supervise(spec.argv, WORK, env, RUN_UID, RUN_GID, spec.capture_cap,
                      spec.timeout if timeout is None else timeout, (RUN_UID,), False, None)


def _supervise(argv, cwd, env, uid, gid, cap_bytes, timeout, quiesce_uids, merge, umask,
               err_cap=None, stdin_fd=None):
    """Start `argv` as uid/gid in its own session, capture through pipes under `cap_bytes`
    (stderr into the stdout pipe when `merge`; under `err_cap` when given), kill the group at
    the deadline or overflow, then quiesce `quiesce_uids` BEFORE draining the pipes and
    deciding. `stdin_fd` replaces /dev/null as the child's stdin."""
    cap = _Capture(cap_bytes, err_cap)
    report_r, report_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(report_r)
        os.close(cap.out_r)
        os.close(cap.err_r)
        _exec_child(argv, cap.out_w, cap.out_w if merge else cap.err_w, report_w, cwd, env, uid, gid,
                    umask, stdin_fd)
    os.close(report_w)
    cap.close_write_ends()  # the driver holds no write end: EOF means every writer is gone
    try:
        started = os.read(report_r, 256)  # b"" once exec closed the pipe on success
        os.close(report_r)
        if started:
            os.waitpid(pid, 0)
            return "not_started", None, False, b"", b"", started.decode("ascii", "replace")
        deadline = time.monotonic() + max(timeout, 0)
        status = "exited"
        exit_code = None
        while True:
            done, wstatus = os.waitpid(pid, os.WNOHANG)
            if done:
                exit_code = os.waitstatus_to_exitcode(wstatus)
                break
            cap.pump(0.02)
            if cap.over():
                status = "output_limit"
            elif time.monotonic() >= deadline:
                status = "timeout"
            if status != "exited":
                try:
                    os.killpg(pid, SIGKILL)
                except OSError:
                    pass
                os.waitpid(pid, 0)
                break
        # Descendants may still hold the write ends: kill every process of the child's uid first,
        # then read the pipes to EOF, then decide.
        reason = quiesce(quiesce_uids)
        if reason is not None:
            raise CaptureError(reason)
        cap.drain(QUIESCE_SECONDS)
        truncated = cap.over()
        if truncated:
            status = "output_limit"
        return (status, exit_code if status == "exited" else None, truncated,
                bytes(cap.bufs[cap.out_r]), bytes(cap.bufs[cap.err_r]), None)
    finally:
        cap.close()


def _reap():
    while True:
        try:
            done, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if done == 0:
            return


def quiesce(uids=(RUN_UID,)):
    """Kill and reap every process of the given uids within QUIESCE_SECONDS. None or a reason
    that names the uids that still had live processes (B1: "uid 65532 ...")."""
    uids = frozenset(uids)
    end = time.monotonic() + QUIESCE_SECONDS
    while True:
        try:
            live, _zombies = scan_proc(PROC, uids)
        except (OSError, ValueError):
            return "process enumeration failed"
        for pid in live:
            try:
                os.kill(pid, SIGKILL)
            except ProcessLookupError:
                pass
        _reap()
        if not live:
            try:
                live, _zombies = scan_proc(PROC, uids)
            except (OSError, ValueError):
                return "process enumeration failed"
            if not live:
                return None
        if time.monotonic() >= end:
            try:
                owners = [u for u in sorted(uids) if scan_proc(PROC, {u})[0]] or sorted(uids)
            except (OSError, ValueError):
                owners = sorted(uids)
            return "uid %s processes survived SIGKILL" % ",".join(str(u) for u in owners)
        time.sleep(0.02)


def _export_child(path, cap, write_fd):
    """uid-65532 helper: open /out/<name> without following links, bytes over the pipe.
    First byte 'R' + data, or 'E' + ASCII reason."""
    try:
        _drop_privileges(RUN_UID, RUN_GID)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            os.write(write_fd, b"M")
            return
        except OSError as exc:
            os.write(write_fd, b"Eopen failed: " + errno.errorcode.get(exc.errno, "?").encode("ascii"))
            return
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            os.write(write_fd, b"Enot a regular file")
            return
        if st.st_size > cap:
            os.write(write_fd, b"Etoo large")
            return
        data = b""
        while len(data) < st.st_size:
            chunk = os.read(fd, min(1 << 20, st.st_size - len(data)))
            if not chunk:
                break
            data += chunk
        os.write(write_fd, b"R")
        view = memoryview(data)
        while view:
            sent = os.write(write_fd, view[:1 << 16])
            view = view[sent:]
    except BaseException:
        try:
            os.write(write_fd, b"Eread failed")
        except BaseException:
            pass


def read_export(name, cap):
    """(kind, payload): ('ok', bytes) | ('missing', None) | ('refused', reason)."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            _export_child(os.path.join(OUT, name), cap, write_fd)
        finally:
            os._exit(0)
    os.close(write_fd)
    chunks = []
    total = 0
    end = time.monotonic() + EXPORT_SECONDS
    ok = True
    while True:
        if time.monotonic() >= end or total > cap + 256:
            ok = False
            break
        chunk = os.read(read_fd, 1 << 16)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    os.close(read_fd)
    if not ok:
        try:
            os.kill(pid, SIGKILL)
        except OSError:
            pass
    os.waitpid(pid, 0)
    if not ok:
        return "refused", "read did not finish"
    data = b"".join(chunks)
    if data == b"M":
        return "missing", None
    if data[:1] == b"R":
        return "ok", data[1:]
    if data[:1] == b"E":
        return "refused", data[1:].decode("ascii", "replace")[:60]
    return "refused", "export helper failed"


def _read_regular_nofollow(path, cap):
    """Bytes of a regular file opened without following a final link; DepsError otherwise."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise DepsError("cannot open %s" % path)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise DepsError("%s is not a regular file" % path)
        if st.st_size > cap:
            raise DepsError("%s is too large" % path)
        chunks = []
        total = 0
        while total <= cap:
            chunk = os.read(fd, min(1 << 20, cap + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > cap:
            raise DepsError("%s is too large" % path)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_site(site, deadline=None):
    """Parsed METADATA of every *.dist-info directly in `site` (bounded, no link followed).
    An *.egg-info is a distribution this check cannot see: refused, as is any bad entry.
    `deadline` (monotonic, optional) is checked before each entry and, through
    parse_metadata(), inside each METADATA: a timeout DepsError."""
    try:
        entries = sorted(os.listdir(site))
    except OSError:
        raise DepsError("cannot list %s" % site)
    if len(entries) > MAX_SITE_ENTRIES:
        raise DepsError("%s has too many entries" % site)
    dists = []
    for entry in entries:
        if deadline_passed(deadline):
            raise DepsError("%s while reading METADATA in %s" % (DEPS_TIMEOUT, site))
        if entry.endswith(".egg-info"):
            raise DepsError("unsupported distribution format %s in %s" % (entry, site))
        if not entry.endswith(".dist-info"):
            continue
        parsed = dist_info_name(entry)
        if parsed is None:
            raise DepsError("unparsable dist-info name %s in %s" % (entry, site))
        path = os.path.join(site, entry)
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise DepsError("%s is not a directory" % path)
        meta = parse_metadata(_read_regular_nofollow(os.path.join(path, "METADATA"), MAX_METADATA),
                              deadline)
        if normalize_name(meta["name"]) != parsed[0]:
            raise DepsError("%s names distribution %s" % (path, meta["name"]))
        meta["dir_version"] = parsed[1]
        dists.append(meta)
    return dists


def extract_deps(deps_bytes, seconds):
    """As a uid-65531 child: create /deps/{wheels,site,home,tmp} (0755) and extract the deps
    tar into /deps/wheels (members re-checked). None on success or an ASCII reason. The child
    gets `seconds` -- what is left of the deps budget (inspection round 1, B1), not a fixed
    bound of its own -- and is killed when they run out."""
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            _drop_privileges(DEPS_UID, DEPS_GID)
            os.umask(0o022)
            for sub in ("wheels", "site", "home", "tmp"):
                os.mkdir(os.path.join(DEPS, sub), 0o755)
            with tarfile.open(fileobj=io.BytesIO(deps_bytes), mode="r:", errorlevel=2) as tf:
                members = tf.getmembers()
                for member in members:
                    kind = "file" if member.isreg() else "dir" if member.isdir() else "other"
                    if deps_member_problem(member.name, kind) is not None:
                        raise ValueError("member refused")
                # bandit B202: every member passed deps_member_problem() above (flat regular
                # files only), plus filter="tar" (clears group/other write) and errorlevel=2.
                tf.extractall(os.path.join(DEPS, "wheels"), members=members, filter="tar")  # nosec B202
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    status = _wait_child(pid, max(seconds, 0))
    if status is None:
        return "%s during the deps tar extraction" % DEPS_TIMEOUT
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        return "deps tar extraction failed"
    return None


def walk_deps(deadline=None):
    """Permission walk of /deps/site and /deps/wheels (bounded). None or an ASCII reason.
    `deadline` (monotonic, optional) is checked before each entry."""
    count = 0
    for sub in ("site", "wheels"):
        stack = [(os.path.join(DEPS, sub), "/deps/" + sub)]
        while stack:
            if deadline_passed(deadline):
                return "%s during the permission walk" % DEPS_TIMEOUT
            path, label = stack.pop()
            count += 1
            if count > MAX_DEPS_ENTRIES:
                return "/deps has too many entries"
            try:
                st = os.lstat(path)
            except OSError:
                return "/deps walk failed at %s" % _ascii(label)
            problem = deps_entry_problem(_ascii(label), st)
            if problem is not None:
                return problem
            if stat.S_ISDIR(st.st_mode):
                try:
                    names = os.listdir(path)
                except OSError:
                    return "/deps walk failed at %s" % _ascii(label)
                for name in names:
                    stack.append((os.path.join(path, name), label + "/" + name))
    return None


def run_deps(deps_bytes, budget_end):
    """Plan B1.5 step 5 inside the container. Returns (deps object, install.txt bytes); raises
    CaptureError when uid-65531 processes cannot be confirmed dead (infrastructure).

    `budget_end` is THE deps deadline (monotonic; main() passes min(deps_timeout, timeout) from
    the start of this step). Inspection round 1, B1: no phase -- extraction, install, walk,
    METADATA reads, closure check -- starts once it is reached; extraction and install get only
    what is left of it; the walk, the reads and the closure check test it between entries. Only
    the quiescence of uid 65531 still runs after expiry: it is cleanup, not a phase."""
    install_bytes = b""

    def failed(reason):
        return {"status": "failed", "reason": _ascii(reason), "installed": []}, install_bytes

    def expired(phase):
        return failed("%s before %s" % (DEPS_TIMEOUT, phase))

    if PACKAGING is None:
        return failed("packaging unavailable")
    for path in PIP_CONFIG_PATHS:
        if os.path.lexists(path):
            return failed("pip configuration present in the image: %s" % path)
    try:
        root_problem = deps_root_problem(os.lstat(DEPS), os.listdir(DEPS))
    except OSError:
        root_problem = "/deps is missing"
    if root_problem is not None:
        return failed(root_problem)
    problem, req_bytes = deps_tar_problem(deps_bytes)
    if problem is not None:
        return failed(problem)
    try:
        requirements = parse_deps_requirements(req_bytes)
    except DepsError as exc:
        return failed(str(exc))
    if deadline_passed(budget_end):
        return expired("the deps tar extraction")
    problem = extract_deps(deps_bytes, budget_end - time.monotonic())
    if problem is not None:
        return failed(problem)
    if deadline_passed(budget_end):
        return expired("pip install")
    status, exit_code, _trunc, out, _err, reason = _supervise(
        pip_install_argv(DEPS), os.path.join(DEPS, "tmp"), install_env(DEPS), DEPS_UID, DEPS_GID,
        INSTALL_CAP, budget_end - time.monotonic(), (DEPS_UID,), True, 0o022)
    install_bytes = out if reason is None else (reason + "\n").encode("ascii", "replace")
    if status == "not_started":
        return failed("pip install did not start: %s" % reason)
    if status == "timeout":
        return failed("pip install timeout")
    if status == "output_limit":
        return failed("pip install output over the %d byte cap" % INSTALL_CAP)
    if exit_code != 0:
        return failed("pip install exited %s" % exit_code)
    reason = quiesce((DEPS_UID,))
    if reason is not None:
        raise CaptureError(reason)
    if deadline_passed(budget_end):
        return expired("the permission walk")
    problem = walk_deps(budget_end)
    if problem is not None:
        return failed(problem)
    try:
        if deadline_passed(budget_end):
            return expired("the METADATA reads")
        deps_dists = read_site(os.path.join(DEPS, "site"), budget_end)
        if deadline_passed(budget_end):
            return expired("the METADATA reads of the image")
        image_dists = read_site(IMAGE_SITE, budget_end)
        if deadline_passed(budget_end):
            return expired("the closure check")
        check_closure(deps_dists, image_dists, requirements, PACKAGING, deadline=budget_end)
    except DepsError as exc:
        return failed(str(exc))
    except OSError:
        return failed("dist-info could not be read")
    if deadline_passed(budget_end):
        return failed(DEPS_TIMEOUT)
    installed = [[name, version] for name, version in sorted(requirements)]
    return {"status": "installed", "reason": None, "installed": installed}, install_bytes


# ---------------------------------------------------------------- B2: the change-set walk


def _list_dir(path):
    """Names in `path` (bytes); an owner without r/x gets u+rwx first (the helper is the owner
    of everything the builder made, and every builder process is dead). None on failure."""
    try:
        return os.listdir(path)
    except PermissionError:
        try:
            os.chmod(path, stat.S_IMODE(os.lstat(path).st_mode) | stat.S_IRWXU)
            return os.listdir(path)
        except OSError:
            return None
    except OSError:
        return None


def _read_file(path, st):
    """The bytes of the regular file lstat'ed as `st`, opened without following a link and
    checked to be the same inode; None on any failure or a size that does not match."""
    flags = os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_BINARY | O_CLOEXEC
    try:
        try:
            fd = os.open(path, flags)
        except PermissionError:
            os.chmod(path, stat.S_IMODE(st.st_mode) | stat.S_IRUSR)
            fd = os.open(path, flags)
    except OSError:
        return None
    try:
        now = os.fstat(fd)
        if not stat.S_ISREG(now.st_mode) or (now.st_ino, now.st_dev) != (st.st_ino, st.st_dev):
            return None
        chunks = []
        total = 0
        while total <= st.st_size:
            chunk = os.read(fd, min(1 << 20, st.st_size + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks) if total == st.st_size else None
    except OSError:
        return None
    finally:
        os.close(fd)


def walk_tree(root, baseline_paths, generated, withheld, caps, write):
    """The uid-65532 helper's body (plan B2 approach 7): walk `root` (bytes) without following
    links and `write` one record per entry (encode_record), then Z. It never descends into a
    .git entry (counted, kind G) or a withheld path (kind W); it sends no bytes for an added
    generated file (S) or a file over the per-file cap (B); C and T stop the walk at the entry
    and byte caps. The driver decides everything else (compute_changes)."""
    def emit_end():
        write(encode_record("Z", 0, 0, b""))

    try:
        st = os.lstat(root)
    except OSError:
        st = None
    if st is None or not stat.S_ISDIR(st.st_mode):
        write(encode_record("E", 0, len(b"the repository root is not a directory"), b"",
                            b"the repository root is not a directory"))
        return emit_end()
    count = 0
    sent = 0
    stack = [(b"", st.st_mode)]
    while stack:
        rel_dir, dir_mode = stack.pop()
        full_dir = root + b"/" + rel_dir if rel_dir else root
        names = _list_dir(full_dir)
        if names is None:
            reason = b"cannot list a directory"
            write(encode_record("E", dir_mode, len(reason), rel_dir, reason))
            return emit_end()
        if rel_dir:
            write(encode_record("D", dir_mode, len(names), rel_dir))
        for name in sorted(names):
            rel = rel_dir + b"/" + name if rel_dir else name
            count += 1
            if count > caps["entries"]:
                write(encode_record("C", 0, 0, b""))
                return emit_end()
            full = root + b"/" + rel
            try:
                est = os.lstat(full)
            except OSError:
                reason = b"cannot lstat an entry"
                write(encode_record("E", 0, len(reason), rel, reason))
                return emit_end()
            mode = est.st_mode
            text = rel.decode("utf-8", "surrogateescape")
            if under_any(withheld, text):
                write(encode_record("W", mode, 0, rel))
                continue
            if name.lower() == b".git":
                beneath = _count_beneath(full, caps["entries"] - count) if stat.S_ISDIR(mode) else 0
                count += beneath
                write(encode_record("G", mode, beneath, rel))
                if count > caps["entries"]:
                    write(encode_record("C", 0, 0, b""))
                    return emit_end()
                continue
            if stat.S_ISLNK(mode):
                write(encode_record("L", mode, 0, rel))
            elif stat.S_ISDIR(mode):
                stack.append((rel, mode))
            elif not stat.S_ISREG(mode):
                write(encode_record("O", mode, 0, rel))
            elif text not in baseline_paths and generated_match(generated, text):
                write(encode_record("S", mode, est.st_size, rel))
            elif est.st_size > caps["file_bytes"]:
                write(encode_record("B", mode, est.st_size, rel))
            elif sent + est.st_size > caps["total_bytes"]:
                write(encode_record("T", 0, 0, b""))
                return emit_end()
            else:
                data = _read_file(full, est)
                if data is None:
                    reason = b"cannot read a file"
                    write(encode_record("E", mode, len(reason), rel, reason))
                    return emit_end()
                sent += len(data)
                write(encode_record("F", mode, len(data), rel, data))
    return emit_end()


def _count_beneath(path, limit):
    """Entries beneath the directory `path` (bytes), no link followed; stops once over `limit`
    (a builder .git is counted, never read or sent)."""
    count = 0
    stack = [path]
    while stack:
        current = stack.pop()
        names = _list_dir(current)
        if names is None:
            return limit + 1
        for name in names:
            count += 1
            if count > limit:
                return count
            full = current + b"/" + name
            try:
                if stat.S_ISDIR(os.lstat(full).st_mode):
                    stack.append(full)
            except OSError:
                return limit + 1
    return count


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view[:1 << 16]):]


def run_walk(baseline, generated, withheld, caps):
    """Run walk_tree() over /work/repo in a uid-65532 helper and return its parsed records.
    The output is bounded (caps) and the helper killed at WALK_SECONDS; an incomplete or
    malformed walk returns records compute_changes() refuses. Raises CaptureError when uid
    65532 cannot be confirmed dead afterwards."""
    root = os.fsencode(os.path.join(WORK, "repo"))
    paths = frozenset(baseline.files)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(read_fd)
            _drop_privileges(RUN_UID, RUN_GID)
            walk_tree(root, paths, generated, withheld, caps, lambda data: _write_all(write_fd, data))
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    os.close(write_fd)
    limit = caps["total_bytes"] + (caps["entries"] + 4) * (RECORD_HEADER + MAX_RECORD_PATH)
    buf = bytearray()
    end = time.monotonic() + WALK_SECONDS
    late = over = False
    try:
        while True:
            left = end - time.monotonic()
            if left <= 0:
                late = True
                break
            ready, _, _ = select.select([read_fd], [], [], min(left, 0.5))
            if not ready:
                continue
            chunk = os.read(read_fd, 1 << 20)
            if not chunk:
                break
            buf += chunk
            if len(buf) > limit:
                over = True
                break
    finally:
        os.close(read_fd)
    if late or over:
        try:
            os.kill(pid, SIGKILL)
        except OSError:
            pass
    os.waitpid(pid, 0)
    reason = quiesce((RUN_UID,))
    if reason is not None:
        raise CaptureError(reason)
    end_record = ("Z", 0, 0, b"", b"")
    if late:
        msg = b"the walk did not finish in time"
        return [("E", 0, len(msg), b"", msg), end_record]
    if over:
        return [("T", 0, 0, b"", b""), end_record]
    try:
        return parse_records(bytes(buf))
    except ValueError:
        return []


# ---------------------------------------------------------------- B2: CODEX_HOME


def prepare_codex_home(auth_bytes, ca_bytes):
    """Write the placeholder auth.json and the CA certificate into CODEX_HOME as a uid-65532
    child (exclusive create, 0600, no link followed). CODEX_HOME must be an empty directory,
    root-owned 1777 or 65532-owned with no group/other write. None or an ASCII reason."""
    try:
        st = os.lstat(CODEX_HOME)
        entries = os.listdir(CODEX_HOME)
    except OSError:
        return "codex-home is missing"
    mode = stat.S_IMODE(st.st_mode)
    shape = stat.S_ISDIR(st.st_mode) and not entries and (
        (st.st_uid == 0 and mode == 0o1777)
        or (st.st_uid == RUN_UID and mode & stat.S_IRWXU == stat.S_IRWXU and not mode & 0o022))
    if not shape:
        return "codex-home is not an empty directory writable by 65532 (root 1777 or 65532-owned)"
    files = (("auth.json", auth_bytes), ("ca.pem", ca_bytes))
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            _drop_privileges(RUN_UID, RUN_GID)
            os.umask(0o077)
            for name, data in files:
                fd = os.open(os.path.join(CODEX_HOME, name),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
                try:
                    _write_all(fd, data)
                finally:
                    os.close(fd)
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    status = _wait_child(pid, HOME_SECONDS)
    if status is None or not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        return "codex-home files could not be written"
    for name, data in files:
        fst = os.lstat(os.path.join(CODEX_HOME, name))
        if (not stat.S_ISREG(fst.st_mode) or fst.st_uid != RUN_UID or stat.S_IMODE(fst.st_mode) != 0o600
                or fst.st_size != len(data)):
            return "codex-home file %s is not what the driver wrote" % name
    return None


def placeholder_problem(auth_bytes, ca_bytes):
    """Sanity of the two CODEX_HOME inputs (their content is the orchestrator's; whether Codex
    accepts the placeholder is decided by `codex login status`)."""
    try:
        doc = json.loads(auth_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "placeholder auth.json is not JSON"
    if not isinstance(doc, dict):
        return "placeholder auth.json is not a JSON object"
    try:
        text = ca_bytes.decode("ascii")
    except UnicodeDecodeError:
        return "CA certificate is not ASCII"
    if not text.startswith("-----BEGIN CERTIFICATE-----") or "-----END CERTIFICATE-----" not in text:
        return "CA certificate is not PEM"
    return None


# ---------------------------------------------------------------- B2: probe


def probe_one_dns(name):
    """Resolve `name` once (in a thread of the probe child): (outcome, detail)."""
    try:
        infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return "blocked", "gaierror %s" % exc.errno
    except OSError as exc:
        outcome = classify_errno(exc.errno) if exc.errno else "error"
        return outcome, "oserror %s" % exc.errno
    return ("reached", "resolved") if infos else ("blocked", "no address")


def _errname(err):
    return errno.errorcode.get(err, str(err)) if err else "connected"


def probe_child(targets, inner_deadline, write_fd):
    """The uid-65532 probe child's body: every tcp/udp target as a non-blocking socket, every
    name in its own thread, all at once; one JSON line per outcome on `write_fd` as it is
    known. Pending sockets at `inner_deadline` are reported as timeout; a resolution that has
    not returned by then stays unreported (the caller exits the process)."""
    lock = threading.Lock()

    def report(i, outcome, detail):
        line = (json.dumps({"i": i, "o": outcome, "d": detail}) + "\n").encode("ascii")
        with lock:
            _write_all(write_fd, line)

    poller = select.poll()
    pending = {}
    for i, (proto, host, port) in enumerate(targets):
        if proto == "dns":
            continue
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            sock = socket.socket(family, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
        except OSError as exc:
            report(i, classify_errno(exc.errno) if exc.errno else "error", "socket: " + _errname(exc.errno))
            continue
        sock.setblocking(False)
        err = sock.connect_ex((host, port))
        if proto == "tcp" and err == errno.EINPROGRESS:
            pending[sock.fileno()] = (i, sock, proto)
            poller.register(sock.fileno(), select.POLLOUT)
            continue
        if proto == "udp" and err == 0:
            try:
                sock.send(DNS_QUERY if port == 53 else b"\x00")
            except OSError as exc:
                report(i, classify_errno(exc.errno) if exc.errno else "error", "send: " + _errname(exc.errno))
                sock.close()
                continue
            pending[sock.fileno()] = (i, sock, proto)
            poller.register(sock.fileno(), select.POLLIN)
            continue
        report(i, classify_errno(err), "connect: " + _errname(err))
        sock.close()
    threads = []
    for i, (proto, host, _port) in enumerate(targets):
        if proto == "dns":
            def resolve(index=i, name=host):
                outcome, detail = probe_one_dns(name)
                report(index, outcome, detail)
            thread = threading.Thread(target=resolve, daemon=True)
            thread.start()
            threads.append(thread)
    while pending:
        left = inner_deadline - time.monotonic()
        if left <= 0:
            break
        for fd, _event in poller.poll(int(min(left, 0.2) * 1000) + 1):
            entry = pending.pop(fd, None)
            if entry is None:
                continue
            poller.unregister(fd)
            i, sock, proto = entry
            if proto == "tcp":
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                report(i, classify_errno(err), "connect: " + _errname(err))
            else:
                try:
                    sock.recv(512)
                    report(i, "reached", "udp reply")
                except OSError as exc:
                    report(i, classify_errno(exc.errno) if exc.errno else "error", "recv: " + _errname(exc.errno))
            sock.close()
    for i, sock, _proto in pending.values():
        report(i, "timeout", "no answer before the deadline")
        sock.close()
    for thread in threads:
        thread.join(max(0.0, inner_deadline - time.monotonic()))


def read_routes():
    """(default route present, reason or None) from /proc/net/route and, when it exists,
    /proc/net/ipv6_route."""
    try:
        with open(ROUTE_V4, "r", encoding="ascii", errors="replace") as handle:
            found = default_route_v4(handle.read())
        if os.path.exists(ROUTE_V6):
            with open(ROUTE_V6, "r", encoding="ascii", errors="replace") as handle:
                found = default_route_v6(handle.read()) or found
    except (OSError, ValueError):
        return False, "route table unreadable"
    return found, None


def main_probe(nonce, spec, started):
    """Mode "probe" (plan B2 approach 5): one supervised uid-65532 child under one absolute
    deadline, then the route tables. Always emits result.json; returns 0."""
    durations = {}
    hard = started + spec.deadline
    inner = max(time.monotonic() + 0.5, hard - 1.0)
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(read_fd)
            os.setsid()
            _drop_privileges(RUN_UID, RUN_GID)
            probe_child(spec.targets, inner, write_fd)
            code = 0
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    os.close(write_fd)
    t0 = time.monotonic()
    buf = bytearray()
    killed = False
    try:
        while True:
            left = hard - time.monotonic()
            if left <= 0 or len(buf) > PROBE_REPORT_CAP:
                killed = True
                break
            ready, _, _ = select.select([read_fd], [], [], min(left, 0.1))
            if ready:
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                buf += chunk
    finally:
        os.close(read_fd)
    if killed:
        try:
            os.killpg(pid, SIGKILL)
        except OSError:
            pass
        os.waitpid(pid, 0)
    elif _wait_child(pid, max(hard - time.monotonic(), 0.5)) is None:
        killed = True
    durations["probe_ms"] = int((time.monotonic() - t0) * 1000)
    infrastructure = quiesce((RUN_UID,))
    outcomes = [None] * len(spec.targets)
    details = [""] * len(spec.targets)
    garbled = False
    for line in bytes(buf).split(b"\n"):
        if not line:
            continue
        try:
            item = json.loads(line.decode("ascii"))
            i, outcome, detail = item["i"], item["o"], item["d"]
            if (isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(outcomes)
                    or outcome not in PROBE_OUTCOMES[:4] or not isinstance(detail, str)):
                raise ValueError("bad report")
        except (UnicodeDecodeError, ValueError, KeyError, TypeError):
            garbled = True
            continue
        if outcomes[i] is None:
            outcomes[i], details[i] = outcome, detail
    route, route_reason = read_routes()
    if infrastructure is None:
        infrastructure = route_reason
    if infrastructure is None and garbled:
        infrastructure = "probe report malformed"
    status = probe_status(outcomes, route, killed)
    if status == "isolated" and infrastructure is not None:
        status = "isolation_unverified"
    results = [(proto, host, port, "unreported" if outcomes[i] is None else outcomes[i], details[i])
               for i, (proto, host, port) in enumerate(spec.targets)]
    durations["total_ms"] = int((time.monotonic() - started) * 1000)
    result = build_probe_result(nonce, status, route, killed, results, durations, infrastructure)
    emit([("result.json", result_json_bytes(result))])
    return 0


# ---------------------------------------------------------------- B2: build


def _prompt_fd(prompt):
    """The prompt as an anonymous memory file, positioned at 0 (Codex reads it as stdin)."""
    fd = os.memfd_create("claudex-prompt")
    _write_all(fd, prompt)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def main_build(nonce, spec, stdin, started):
    """Mode "build" (plan B2 approaches 4, 6, 7). Always emits a result; returns 0."""
    durations = {}
    infrastructure = None
    tar_bytes = deps_bytes = prompt = auth = ca = b""
    try:
        tar_bytes = _read_exact(stdin, spec.tar_len)
        deps_bytes = _read_exact(stdin, spec.deps_len, "deps tar")
        prompt = _read_exact(stdin, spec.prompt_len, "prompt", "prompt_len")
        auth = _read_exact(stdin, spec.placeholder_len, "placeholder auth.json", "placeholder_len")
        ca = _read_exact(stdin, spec.ca_len, "CA certificate", "ca_len")
    except SpecError as exc:
        infrastructure = "header: %s" % exc
    if infrastructure is None and spec.deps_len and hashlib.sha256(deps_bytes).hexdigest() != spec.deps_sha256:
        infrastructure = "header: deps tar digest mismatch"
    if infrastructure is None:
        problem = placeholder_problem(auth, ca)
        if problem is not None:
            infrastructure = "header: %s" % problem
    with_deps = spec.deps_len > 0
    deps = {"status": "failed", "reason": "not attempted", "installed": []} if with_deps else None
    install_bytes = login_bytes = events = codex_err = b""
    command_status, command_exit, truncated = "not_started", None, False
    login_status = None
    exports = {}
    out_members = []
    baseline = None
    change = None
    if infrastructure is None:
        try:
            os.makedirs(SCRATCH, mode=0o700, exist_ok=False)
            os.chmod(SCRATCH, 0o700)
        except OSError:
            infrastructure = "scratch directory could not be created"
    if infrastructure is None:
        try:
            baseline = baseline_from_tar(tar_bytes, spec.withheld)
        except BaselineError as exc:
            infrastructure = "snapshot: %s" % exc
    repo = os.path.join(WORK, "repo")
    if infrastructure is None:
        t0 = time.monotonic()
        infrastructure = extract_snapshot(tar_bytes, dest=repo, names=baseline.extract)
        durations["extract_ms"] = int((time.monotonic() - t0) * 1000)
    if infrastructure is None:
        infrastructure = prepare_codex_home(auth, ca)
    budget_end = time.monotonic() + spec.codex_timeout
    if infrastructure is None and with_deps:
        t0 = time.monotonic()
        try:
            deps, install_bytes = run_deps(deps_bytes, t0 + min(spec.deps_timeout, spec.codex_timeout))
        except CaptureError as exc:
            infrastructure = str(exc)
            deps = {"status": "failed", "reason": "installer processes not confirmed dead", "installed": []}
        durations["deps_ms"] = int((time.monotonic() - t0) * 1000)
        if infrastructure is None and deps["status"] == "failed":
            command_status = "deps_failed"
        elif infrastructure is None:
            infrastructure = quiesce((DEPS_UID,))
    env = codex_env(spec.proxy_url, with_deps)
    if infrastructure is None and command_status != "deps_failed":
        t0 = time.monotonic()
        try:
            status, code, _trunc, out, _err, reason = _supervise(
                LOGIN_ARGV, repo, env, RUN_UID, RUN_GID, LOGIN_CAP,
                min(LOGIN_SECONDS, budget_end - time.monotonic()), (RUN_UID,), True, None)
            login_bytes = out if reason is None else (reason + "\n").encode("ascii", "replace")
            if status == "timeout":
                login_bytes += b"\nclaudex: the login status check timed out\n"
            login_status = "chatgpt" if status == "exited" and login_ok(code, out) else "rejected"
        except CaptureError as exc:
            infrastructure = str(exc)
        durations["login_ms"] = int((time.monotonic() - t0) * 1000)
    ran_codex = False
    if infrastructure is None and login_status == "chatgpt":
        ran_codex = True
        t0 = time.monotonic()
        prompt_fd = None
        try:
            prompt_fd = _prompt_fd(prompt)
            outcome = _supervise(spec.codex_argv, repo, env, RUN_UID, RUN_GID, EVENTS_CAP,
                                 budget_end - time.monotonic(), (RUN_UID,), False, None,
                                 err_cap=CODEX_STDERR_CAP, stdin_fd=prompt_fd)
            command_status, command_exit, truncated, events, codex_err, reason = outcome
            if reason is not None:
                codex_err = (reason + "\n").encode("ascii", "replace")
        except CaptureError as exc:
            infrastructure = str(exc)
            command_status, command_exit, truncated = "not_started", None, False
        except OSError:
            infrastructure = "the prompt could not be handed to Codex"
            command_status, command_exit, truncated = "not_started", None, False
        finally:
            if prompt_fd is not None:
                os.close(prompt_fd)
        durations["command_ms"] = int((time.monotonic() - t0) * 1000)
    if infrastructure is None and baseline is not None:
        t0 = time.monotonic()
        infrastructure = quiesce(CHILD_UIDS)
        durations["quiesce_ms"] = int((time.monotonic() - t0) * 1000)
    if infrastructure is None:
        kind, payload = read_export(LAST_NAME, LAST_CAP)
        if kind == "ok":
            exports[LAST_NAME] = hashlib.sha256(payload).hexdigest()
            out_members.append((LAST_NAME, payload))
        elif kind == "missing":
            exports[LAST_NAME] = "missing"
        else:
            exports[LAST_NAME] = "refused:" + payload
    if infrastructure is None and ran_codex:
        t0 = time.monotonic()
        try:
            records = run_walk(baseline, spec.generated, spec.withheld, spec.caps)
            change = compute_changes(baseline, records, spec.generated, spec.caps)
        except CaptureError as exc:
            infrastructure = str(exc)
        durations["walk_ms"] = int((time.monotonic() - t0) * 1000)
    durations["total_ms"] = int((time.monotonic() - started) * 1000)
    if infrastructure is not None:
        change = None
        if command_status == "deps_failed":
            command_status = "not_started"
    withheld = list(baseline.withheld) if baseline is not None else []
    if change is None:
        build = {"codex_exit": command_exit, "change_status": "not_computed", "change_reason": None,
                 "counts": _zero_counts(withheld), "login_status": login_status}
        changes, blobs, excluded = [], [], []
    else:
        build = {"codex_exit": command_exit, "change_status": change["status"],
                 "change_reason": change["reason"], "counts": change["counts"], "login_status": login_status}
        changes, blobs, excluded = change["changes"], change["blobs"], change["excluded"]
    result = build_build_result(nonce, command_status, command_exit, truncated, durations, exports,
                                infrastructure, deps, build)
    members = [("result.json", result_json_bytes(result)), ("codex-events.jsonl", events),
               ("codex-stderr.txt", codex_err), ("login.txt", login_bytes)]
    if with_deps:
        members.append(("install.txt", install_bytes))
    members += out_members
    members.append(("changes.json", json.dumps(changes, separators=(",", ":"), ensure_ascii=True).encode("ascii")))
    members.append(("excluded.json", json.dumps({"excluded": excluded, "withheld": withheld},
                                                separators=(",", ":"), ensure_ascii=True).encode("ascii")))
    members += [("change/%d" % n, blob) for n, blob in blobs]
    emit(members, build_member_ok)
    return 0


def emit(members, name_ok=None):
    sys.stdout.buffer.write(build_result_tar(members, name_ok))
    sys.stdout.buffer.flush()


def main():
    stdin = sys.stdin.buffer
    nonce_line = stdin.readline(64)
    try:
        nonce = parse_nonce(nonce_line)
    except SpecError as exc:
        sys.stderr.write("driver: %s\n" % exc)
        return 3
    started = time.monotonic()
    spec = None
    infrastructure = None
    try:
        spec_line = stdin.readline(MAX_SPEC_LINE)
        _nonce, spec = parse_header(nonce_line, spec_line)
    except SpecError as exc:
        infrastructure = "header: %s" % exc
    if spec is not None and spec.mode == "probe":
        return main_probe(nonce, spec, started)
    if spec is not None and spec.mode == "build":
        return main_build(nonce, spec, stdin, started)
    return main_run(nonce, spec, stdin, started, infrastructure)


def main_run(nonce, spec, stdin, started, infrastructure):
    """Mode "run": B1/B1.5, unchanged (the header was read by main())."""
    durations = {}
    tar_bytes = deps_bytes = b""
    if infrastructure is None:
        try:
            tar_bytes = _read_exact(stdin, spec.tar_len)
            deps_bytes = _read_exact(stdin, spec.deps_len, "deps tar")
        except SpecError as exc:
            infrastructure = "header: %s" % exc
    if infrastructure is None and spec.deps_len and hashlib.sha256(deps_bytes).hexdigest() != spec.deps_sha256:
        infrastructure = "header: deps tar digest mismatch"
    with_deps = spec is not None and spec.deps_len > 0
    # Present iff deps_len > 0; replaced by the outcome once the deps phase ran.
    deps = {"status": "failed", "reason": "not attempted", "installed": []} if with_deps else None
    install_bytes = b""
    if infrastructure is None:
        try:
            os.makedirs(SCRATCH, mode=0o700, exist_ok=False)
            os.chmod(SCRATCH, 0o700)
        except OSError:
            infrastructure = "scratch directory could not be created"
    command_status, command_exit, truncated = "not_started", None, False
    stdout_bytes = stderr_bytes = b""
    exports = {}
    out_members = []
    if infrastructure is None:
        t0 = time.monotonic()
        infrastructure = extract_snapshot(tar_bytes)
        durations["extract_ms"] = int((time.monotonic() - t0) * 1000)
    command_timeout = spec.timeout if spec is not None else 0
    extra_env = None
    if infrastructure is None and with_deps:
        # The install+check budget is deps_timeout, and it is counted inside the run's timeout:
        # the command gets what the deps phase left of spec.timeout.
        t0 = time.monotonic()
        try:
            deps, install_bytes = run_deps(deps_bytes, t0 + min(spec.deps_timeout, spec.timeout))
        except CaptureError as exc:
            infrastructure = str(exc)
            deps = {"status": "failed", "reason": "installer processes not confirmed dead", "installed": []}
        elapsed = time.monotonic() - t0
        durations["deps_ms"] = int(elapsed * 1000)
        command_timeout = spec.timeout - elapsed
        if infrastructure is None and deps["status"] == "failed":
            command_status = "deps_failed"
        elif infrastructure is None:
            extra_env = {"PYTHONPATH": os.path.join(DEPS, "site")}
            # Nothing runs as 65531 any more; prove it once more right before 65532 starts.
            infrastructure = quiesce((DEPS_UID,))
    ran_command = False
    if infrastructure is None and command_status != "deps_failed":
        ran_command = True
        t0 = time.monotonic()
        try:
            if with_deps:
                outcome = run_command(spec, timeout=command_timeout, extra_env=extra_env)
            else:
                outcome = run_command(spec)
            command_status, command_exit, truncated, stdout_bytes, stderr_bytes, reason = outcome
        except CaptureError as exc:
            infrastructure = str(exc)
            command_status, command_exit, truncated, reason = "not_started", None, False, None
        durations["command_ms"] = int((time.monotonic() - t0) * 1000)
        if reason is not None:
            stderr_bytes = (reason + "\n").encode("ascii")
    if infrastructure is None and (ran_command or command_status == "deps_failed"):
        # run_command already quiesced its own uid before reading its pipes; this pass covers
        # both child uids (65531 and 65532) and the not_started path, and proves nothing came
        # back before the exports are read.
        t0 = time.monotonic()
        infrastructure = quiesce(CHILD_UIDS)
        durations["quiesce_ms"] = int((time.monotonic() - t0) * 1000)
    if infrastructure is None:
        t0 = time.monotonic()
        for name in spec.exports:
            kind, payload = read_export(name, spec.export_cap)
            if kind == "ok":
                exports[name] = hashlib.sha256(payload).hexdigest()
                out_members.append(("out/" + name, payload))
            elif kind == "missing":
                exports[name] = "missing"
            else:
                exports[name] = "refused:" + payload
        durations["export_ms"] = int((time.monotonic() - t0) * 1000)
    durations["total_ms"] = int((time.monotonic() - started) * 1000)
    if infrastructure is not None and command_status == "deps_failed":
        command_status = "not_started"
    result = build_result(nonce, command_status, command_exit, truncated, durations, exports,
                          infrastructure, deps=deps)
    members = [("result.json", result_json_bytes(result)), ("stdout.txt", stdout_bytes),
               ("stderr.txt", stderr_bytes)]
    if with_deps:
        members.append(("install.txt", install_bytes))
    emit(members + out_members)
    return 0


if __name__ == "__main__":
    sys.exit(main())
