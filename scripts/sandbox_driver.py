#!/usr/bin/env python3
"""sandbox_driver: the in-container half of the B1 sandbox runner.

Plan B1 (docs/plans/2026-10-27-sicherheitskette, approved round 6), Approach 2 and 5.
The host runner (scripts/sandbox_run.py driver_bootstrap) starts this file inside a
container (uid 0 with only CAP_SETUID/CAP_SETGID/CAP_KILL, no-new-privileges, read-only
root, tmpfs /work /out /tmp /home/run, no network) as a fixed, plugin-written bootstrap:
`python3 -I -S -c "import zlib,base64;exec(zlib.decompress(base64.b85decode('<b85>')))"`,
where <b85> is this file's source, zlib-compressed and base85-encoded (plan B1.5,
post-approval change 1: the source as a plain -c argument exceeded the Windows command-line
limit, WinError 206). The bootstrap decompresses the source and executes it as __main__, so
the guard at the bottom runs main(). The driver is therefore PID 1 and the only producer of
the result.

WHY ONE SELF-CONTAINED FILE. The source travels inside that argument, never as a file from
the snapshot: the text around the payload is fixed, the payload is wholly plugin-defined
(base85 has no quote or backslash, so it cannot end the string literal), and the host
manifest records the sha256 of the uncompressed source. It runs isolated (-I: no user
site, no PYTHON* env, no script dir on sys.path; -S: no site); zlib and base64 are stdlib
modules the bootstrap imports before anything from the repository exists. Every import of
the driver itself is at the top, likewise before anything from the repository exists
(round-4 finding 2: a deferred import resolved from /work would run repository code as the
driver), and nothing here imports a plugin module.

PROTOCOL on stdin (binary): line 1 = nonce (32 lowercase hex) + LF; line 2 = JSON spec +
LF; then exactly `tar_len` bytes = the snapshot tar; then exactly `deps_len` bytes = the
deps tar (plan B1.5 step 4; `deps_len` 0 = none, and then `deps_sha256` is ""). On stdout:
ONE tar stream with the members result.json, stdout.txt, stderr.txt, install.txt (present
iff deps_len > 0) and out/<name> per exported file, nothing else. The nonce arrives on
stdin, not in argv (/proc/1/cmdline is world readable); the host accepts a result only
with the matching nonce AND a clean `docker inspect` exit code. With deps_len 0 the run is
B1's, and result.json differs from B1 only by the trailing `"deps": null`.

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

Messages are ASCII only. Exit code 0 means "a result was produced" (even for a failed
command); non-zero only when no trustworthy result could be produced at all.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import re
import select
import signal
import stat
import sys
import tarfile
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


class Spec:
    """A validated spec; plain attributes so the file stays trivially self-contained."""

    __slots__ = ("argv", "exports", "capture_cap", "export_cap", "timeout", "tar_len",
                 "deps_len", "deps_sha256", "deps_timeout")

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
    """Validate the decoded JSON spec. Unknown keys, wrong types and bad ranges all refuse."""
    if not isinstance(obj, dict):
        raise SpecError("spec must be a JSON object")
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


def build_result_tar(members):
    """Frame (name, bytes) pairs as one deterministic tar: regular members only, mtime 0,
    uid/gid 0, mode 0644, USTAR. Names are limited to the four protocol shapes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, content in members:
            if not _framed_name_ok(name):
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


def _read_exact(stream, count, what="snapshot tar"):
    chunks = []
    left = count
    while left:
        chunk = stream.read(min(left, 1 << 20))
        if not chunk:
            raise SpecError("%s shorter than %s" % (what, "deps_len" if what == "deps tar" else "tar_len"))
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def extract_snapshot(tar_bytes):
    """Extract into /work as a uid-65532 child, then verify ownership and writability.
    Returns None on success or an ASCII reason."""
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            _drop_privileges(RUN_UID, RUN_GID)
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:", errorlevel=2) as tf:
                members = tf.getmembers()
                for member in members:
                    kind = "file" if member.isreg() else "dir" if member.isdir() else "other"
                    if member_problem(member.name, kind) is not None:
                        raise ValueError("member refused")
                # bandit B202: every member passed member_problem() above (regular file or dir,
                # no link, no absolute path, no ".."), plus filter="tar" and errorlevel=2.
                tf.extractall(WORK, members=members, filter="tar")  # nosec B202
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


def _exec_child(argv, out_fd, err_fd, report_fd, cwd, env, uid, gid, umask=None):
    """Runs in a forked child (the command, or the installer): never returns."""
    try:
        os.setsid()
        _drop_privileges(uid, gid)
        if umask is not None:
            os.umask(umask)
        os.chdir(cwd)
        devnull = os.open("/dev/null", os.O_RDONLY)
        os.dup2(devnull, 0)
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

    def __init__(self, cap):
        self.cap = cap
        out_r, self.out_w = os.pipe()
        err_r, self.err_w = os.pipe()
        self.bufs = {out_r: bytearray(), err_r: bytearray()}
        self.seen = {out_r: 0, err_r: 0}
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
            room = self.cap - len(self.bufs[fd])
            if room > 0:
                self.bufs[fd] += chunk[:room]

    def over(self):
        return any(n > self.cap for n in self.seen.values())

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


def _supervise(argv, cwd, env, uid, gid, cap_bytes, timeout, quiesce_uids, merge, umask):
    """Start `argv` as uid/gid in its own session, capture through pipes under `cap_bytes`
    (stderr into the stdout pipe when `merge`), kill the group at the deadline or overflow,
    then quiesce `quiesce_uids` BEFORE draining the pipes and deciding."""
    cap = _Capture(cap_bytes)
    report_r, report_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(report_r)
        os.close(cap.out_r)
        os.close(cap.err_r)
        _exec_child(argv, cap.out_w, cap.out_w if merge else cap.err_w, report_w, cwd, env, uid, gid,
                    umask)
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


def emit(members):
    sys.stdout.buffer.write(build_result_tar(members))
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
    durations = {}
    spec = None
    tar_bytes = deps_bytes = b""
    infrastructure = None
    try:
        spec_line = stdin.readline(MAX_SPEC_LINE)
        _nonce, spec = parse_header(nonce_line, spec_line)
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
