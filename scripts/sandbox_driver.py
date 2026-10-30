#!/usr/bin/env python3
"""sandbox_driver: the in-container half of the B1 sandbox runner.

Plan B1 (docs/plans/2026-10-27-sicherheitskette, approved round 6), Approach 2 and 5.
The host runner passes this file's WHOLE SOURCE to `python3 -I -S -c <source>` inside a
container (uid 0 with only CAP_SETUID/CAP_SETGID/CAP_KILL, no-new-privileges, read-only
root, tmpfs /work /out /tmp /home/run, no network). The driver is therefore PID 1 and the
only producer of the result.

WHY ONE SELF-CONTAINED FILE. The source travels as an argument, never as a file from the
snapshot, and runs isolated (-I: no user site, no PYTHON* env, no script dir on sys.path;
-S: no site). Every import is at the top, before anything from the repository exists
(round-4 finding 2: a deferred import resolved from /work would run repository code as the
driver), and nothing here imports a plugin module.

PROTOCOL on stdin (binary): line 1 = nonce (32 lowercase hex) + LF; line 2 = JSON spec +
LF; then exactly `tar_len` bytes = the snapshot tar. On stdout: ONE tar stream with the
members result.json, stdout.txt, stderr.txt and out/<name> per exported file, nothing else.
The nonce arrives on stdin, not in argv (/proc/1/cmdline is world readable); the host
accepts a result only with the matching nonce AND a clean `docker inspect` exit code.

PRIVILEGE SEPARATION (round-3 finding 2). The command and the extraction run as children
that drop to uid/gid 65532 (setgroups, setgid, setuid) before they touch anything; after
that they hold no capability and cannot signal PID 1, open /proc/1/fd/*, or read
/tmp/driver (0700, uid 0). Because the driver has no CAP_CHOWN and no DAC override
(round-4 finding 1, round-5 finding 2), extraction and the export reads also happen in
uid-65532 children.

QUIESCENCE (round-3 finding 5, round-4 finding 5): before anything is packed, every live
uid-65532 process is SIGKILLed and adopted orphans are reaped with waitpid. A zombie keeps
the uid in /proc, so the scan parses `State:` and counts only non-zombies as survivors.

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

RUN_UID = 65532
RUN_GID = 65532
WORK = "/work"
OUT = "/out"
# Inside the container: /tmp is a per-run tmpfs, and this directory is 0700 uid 0 (bandit B108).
SCRATCH = "/tmp/driver"  # nosec B108
PROC = "/proc"
SIGKILL = getattr(signal, "SIGKILL", 9)

NONCE_RE = re.compile(r"[0-9a-f]{32}")
EXPORT_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")
SPEC_KEYS = ("argv", "exports", "capture_cap", "export_cap", "timeout", "tar_len")
MAX_EXPORTS = 3
MAX_CAP = 64 * 1024 * 1024
MAX_TAR = 1024 * 1024 * 1024
MAX_TIMEOUT = 3600
MAX_SPEC_LINE = 65536
COMMAND_STATUSES = ("exited", "timeout", "output_limit", "not_started")
EXPORT_SHA_RE = re.compile(r"[0-9a-f]{64}")
QUIESCE_SECONDS = 5.0
EXTRACT_SECONDS = 120.0
EXPORT_SECONDS = 20.0
CHILD_ENV = {"HOME": "/home/run", "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}


class SpecError(ValueError):
    """The stdin header is not what the protocol allows."""


class Spec:
    """A validated spec; plain attributes so the file stays trivially self-contained."""

    __slots__ = ("argv", "exports", "capture_cap", "export_cap", "timeout", "tar_len")

    def __init__(self, argv, exports, capture_cap, export_cap, timeout, tar_len):
        self.argv = argv
        self.exports = exports
        self.capture_cap = capture_cap
        self.export_cap = export_cap
        self.timeout = timeout
        self.tar_len = tar_len


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
    return Spec(list(argv), list(exports),
                _int_in(obj, "capture_cap", 1, MAX_CAP),
                _int_in(obj, "export_cap", 1, MAX_CAP),
                _int_in(obj, "timeout", 1, MAX_TIMEOUT),
                _int_in(obj, "tar_len", 0, MAX_TAR))


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


def build_result(nonce, command_status, command_exit, truncated, durations, exports, infrastructure):
    """The result.json document, key order fixed. Raises ValueError on an impossible combination."""
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
    return {"nonce": nonce, "command_status": command_status, "command_exit": command_exit,
            "truncated": bool(truncated), "durations": dict(durations), "exports": dict(exports),
            "infrastructure": infrastructure}


def result_json_bytes(result):
    """Canonical, ASCII-only JSON bytes (non-ASCII is escaped)."""
    return json.dumps(result, sort_keys=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _framed_name_ok(name):
    if name in ("result.json", "stdout.txt", "stderr.txt"):
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


def scan_proc(proc_root, uid):
    """(live pids, zombie pids) owned by `uid`. A process that vanishes while scanned is
    skipped; a listing that cannot be read, or a status that cannot be parsed, raises
    (fail closed: the caller reports an infrastructure failure)."""
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
        if owner != uid:
            continue
        if state == "Z":
            zombies.append(int(entry))
        else:
            live.append(int(entry))
    return live, zombies


# ---------------------------------------------------------------- container-side actions


def _drop_privileges():
    os.setgroups([])
    os.setgid(RUN_GID)
    os.setuid(RUN_UID)
    if os.getresuid() != (RUN_UID, RUN_UID, RUN_UID) or os.getresgid() != (RUN_GID, RUN_GID, RUN_GID):
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


def _read_exact(stream, count):
    chunks = []
    left = count
    while left:
        chunk = stream.read(min(left, 1 << 20))
        if not chunk:
            raise SpecError("snapshot tar shorter than tar_len")
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
            _drop_privileges()
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


def _exec_child(argv, out_fd, err_fd, report_fd):
    """Runs in the forked command child: never returns."""
    try:
        os.setsid()
        _drop_privileges()
        os.chdir(WORK)
        devnull = os.open("/dev/null", os.O_RDONLY)
        os.dup2(devnull, 0)
        os.dup2(out_fd, 1)
        os.dup2(err_fd, 2)
        os.execvpe(argv[0], argv, dict(CHILD_ENV))
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


def run_command(spec):
    """Run the command and capture it under the caps.

    The status is decided only AFTER every uid-65532 process is dead and both capture pipes are
    read to EOF: a descendant that writes after the command exited is still counted, and any
    byte beyond the cap is `output_limit` with no exit code -- never "exited, exit 0".
    Returns (status, exit, truncated, stdout bytes, stderr bytes, reason or None); raises
    CaptureError when the capture cannot be finalised."""
    cap = _Capture(spec.capture_cap)
    report_r, report_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(report_r)
        os.close(cap.out_r)
        os.close(cap.err_r)
        _exec_child(spec.argv, cap.out_w, cap.err_w, report_w)
    os.close(report_w)
    cap.close_write_ends()  # the driver holds no write end: EOF means every writer is gone
    try:
        started = os.read(report_r, 256)  # b"" once exec closed the pipe on success
        os.close(report_r)
        if started:
            os.waitpid(pid, 0)
            return "not_started", None, False, b"", b"", started.decode("ascii", "replace")
        deadline = time.monotonic() + spec.timeout
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
        # Descendants may still hold the write ends: kill every uid-65532 process first, then
        # read the pipes to EOF, then decide.
        reason = quiesce()
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


def quiesce():
    """Kill and reap every uid-65532 process within QUIESCE_SECONDS. None or a reason."""
    end = time.monotonic() + QUIESCE_SECONDS
    while True:
        try:
            live, _zombies = scan_proc(PROC, RUN_UID)
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
                live, _zombies = scan_proc(PROC, RUN_UID)
            except (OSError, ValueError):
                return "process enumeration failed"
            if not live:
                return None
        if time.monotonic() >= end:
            return "uid 65532 processes survived SIGKILL"
        time.sleep(0.02)


def _export_child(path, cap, write_fd):
    """uid-65532 helper: open /out/<name> without following links, bytes over the pipe.
    First byte 'R' + data, or 'E' + ASCII reason."""
    try:
        _drop_privileges()
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
    tar_bytes = b""
    infrastructure = None
    try:
        spec_line = stdin.readline(MAX_SPEC_LINE)
        _nonce, spec = parse_header(nonce_line, spec_line)
        tar_bytes = _read_exact(stdin, spec.tar_len)
    except SpecError as exc:
        infrastructure = "header: %s" % exc
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
    if infrastructure is None:
        t0 = time.monotonic()
        try:
            command_status, command_exit, truncated, stdout_bytes, stderr_bytes, reason = run_command(spec)
        except CaptureError as exc:
            infrastructure = str(exc)
            command_status, command_exit, truncated, reason = "not_started", None, False, None
        durations["command_ms"] = int((time.monotonic() - t0) * 1000)
        if reason is not None:
            stderr_bytes = (reason + "\n").encode("ascii")
        if infrastructure is None:
            # run_command already quiesced before reading its pipes; this second pass covers the
            # not_started path and proves nothing came back before the exports are read.
            t0 = time.monotonic()
            infrastructure = quiesce()
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
    result = build_result(nonce, command_status, command_exit, truncated, durations, exports,
                          infrastructure)
    emit([("result.json", result_json_bytes(result)), ("stdout.txt", stdout_bytes),
          ("stderr.txt", stderr_bytes)] + out_members)
    return 0


if __name__ == "__main__":
    sys.exit(main())
