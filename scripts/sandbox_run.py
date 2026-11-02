#!/usr/bin/env python3
"""Run repository code in a hardened, disposable container -- never on the host (plan B1).

Plan: docs/plans/2026-10-27-sicherheitskette/PLAN-B1-sandbox-run.md (approved in round 6). Every
place where a skill executes code of the repository under review -- `build`'s proof run,
`code-review`'s coverage measurement, `docs-backfill`'s test suite, `audit`'s repo entry points --
goes through this runner:

  input    exactly the pinned git TREE (`--tree <sha>`, or `--pin <path>...` which builds one from a
           private index without any repository filter), read by scripts/sandbox_snapshot.py:
           hardened plumbing, every object id recomputed, complete or refused;
  policy   image and docker context come from the INSTALLED plugin's config/sandbox-policy.json,
           never from the checkout; the image's id must match (`--pull=never`);
  deps     (plan B1.5, optional) `--deps <tree path>` up to 4 fully hashed requirements files,
           read from the snapshot of the pinned tree and parsed strictly (sandbox_deps); wheels
           are selected by hash and downloaded by the deadline-killed worker of sandbox_fetch,
           re-verified here byte by byte, and handed in as a second tar after the snapshot;
           the driver installs them offline as uid 65531 into a tmpfs /deps;
  run      `docker create` (id known before anything runs) with no network, read-only rootfs,
           tmpfs /work /out /tmp /home/run (and /deps only with --deps), only SETUID/SETGID/KILL
           for the uid-0 driver (scripts/sandbox_driver.py), the command itself as uid 65532
           without capabilities. The driver is handed over by the stdin loader (plan B2
           approach 3b, bootstrap()): argv is a fixed `python3 -I -S -c <LOADER>` carrying only
           the sha256 of the plugin's own driver source; stdin (`start -ai`) carries, in this
           order, `<len>\n<driver source>` (bounded, hash-checked by the loader, then executed
           as __main__), nonce + spec + snapshot tar (+ deps tar) -- the driver's protocol,
           unchanged by B2; one framed result tar comes back over stdout;
  accept   only a result whose nonce matches, whose members are exactly the expected ones within
           their caps (read_framed; the per-run stream cap goes through stream_start), and whose
           container (= driver) ended with ExitCode 0 and not OOMKilled;
  clean    `docker rm -f` on every exit path, confirmed by `docker inspect`; a janitor removes only
           labelled containers (and, for plan B2's callers, networks) more than 600 s past their
           deadline.

The runner's own exit code says whether the run HAPPENED: 0 ok (the command's outcome is in
COMMAND_STATUS= / COMMAND_EXIT= and the manifest), 2 refused, 5 infrastructure. A skill passes only
on COMMAND_STATUS=exited and COMMAND_EXIT=0 (`deps_failed` is never a pass). There is no host
fallback of any kind. With --deps the runner also prints REQUIREMENTS_SHA256=.

    python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_run.py" --repo . --scratch <dir> --tree <sha> \
        --image python-test [--deps <tree path>]... [--export NAME]... [--timeout S] -- <argv...>

Messages are ASCII only.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402
import hunt_snapshot  # noqa: E402
import sandbox_deps  # noqa: E402
import sandbox_fetch  # noqa: E402
import sandbox_snapshot  # noqa: E402
import sandbox_wheels  # noqa: E402

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = PLUGIN_ROOT / "config" / "sandbox-policy.json"
DRIVER_FILE = Path(__file__).resolve().parent / "sandbox_driver.py"

EXIT_OK, EXIT_REFUSED, EXIT_INFRA = 0, 2, 5
DOCKER_TIMEOUT = 30
DEFAULT_TIMEOUT, MAX_TIMEOUT = 900, 3600
JANITOR_GRACE = 600
CAPTURE_CAP = 8 * 1024 * 1024
EXPORT_CAP = 16 * 1024 * 1024
RESULT_CAP = 64 * 1024 * 1024
MAX_EXPORTS = 3
# fullmatch, not match + "$": "$" also matches before a trailing newline (test_sandbox_run).
EXPORT_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}")
TREE_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
WORK_TMPFS = "512m"
LABEL = "claudex.run"
SNAPSHOT_DEADLINE = 120  # plan step 1 default; sandbox_snapshot's own git timers stay below it
SNAPSHOT_TAR_CAP = 256 * 1024 * 1024

# Plan B1.5.
MAX_DEPS_FILES = 4
FETCH_DEADLINE = 600          # plan step 3: total deadline of the wheel worker
DEFAULT_DEPS_TIMEOUT = 300    # spec deps_timeout when the image has no deps policy
DEPS_TAR_SLACK = 1024 * 1024  # plan step 4: the deps tar is bounded by deps_max_bytes + 1 MiB
MAX_DEPS_BYTES = 1024 ** 3    # the driver accepts at most 1 GiB + 1 MiB of deps tar
INSTALL_CAP = 64 * 1024       # the driver's install.txt cap
DEPS_POLICY_KEYS = ("wheel_target", "deps_max_bytes", "deps_max_file_bytes", "deps_tmpfs",
                    "deps_install_timeout")
TMPFS_SIZE_RE = re.compile(r"([1-9][0-9]{0,5})([kmg])")
WHEEL_PY_RE = re.compile(r"3\.(0|[1-9][0-9]?)")

# The stdin driver loader (plan B2 approach 3b, unit U6; replaces B1.5's zlib+base85 argv
# bootstrap). argv carries only this fixed text with the 64-hex sha256 of the driver source
# filled in; the source itself arrives FIRST on stdin as `<decimal length>\n<bytes>`. The
# loader reads the length line (at most 9 bytes, canonical decimal, 1..LOADER_MAX), exactly that
# many bytes, checks their sha256 and executes them as __main__ -- through sys.stdin.buffer, the
# same buffered reader the driver reads its protocol from, so nothing the loader's reads buffered
# ahead is lost and the protocol after the source block is unchanged. It imports only sys and
# hashlib, contains no double quote and no backslash (list2cmdline and docker pass it verbatim),
# and its length does not depend on the source. Any refusal is sys.exit(<ASCII text>): exit 1,
# nothing executed, nothing on stdout.
LOADER_MAX = 4 * 1024 * 1024
LOADER = ("import sys,hashlib;i=sys.stdin.buffer;n=i.readline(9);"
          "k=int(n) if n[-1:]==bytes((10,)) and n[:-1].isdigit() and n[:1]!=b'0' else 0;"
          "0<k<=" + str(LOADER_MAX) + " or sys.exit('loader: bad length line');"
          "s=i.read(k);"
          "len(s)==k and hashlib.sha256(s).hexdigest()=='%s' or sys.exit('loader: driver source sha256 mismatch');"
          "c=compile(s,'sandbox_driver','exec');del i,n,k,s;exec(c)")
LOADER_RE = re.compile(re.escape(LOADER).replace(re.escape("%s"), "[0-9a-f]{64}"))
DRIVER_PREFIX = ["python3", "-I", "-S", "-c"]
# Upper bound for an explicit stream cap (B2 uses 256 MiB for the build result).
MAX_RESULT_CAP = 1024 ** 3
JANITOR_MAX = 50  # removals per janitor pass, all kinds together (plan B2 approach 11)
JANITOR_KINDS = ("container", "network")  # removal order: containers before their networks


class Refused(Exception):
    """The run must not happen (exit 2)."""


class Infrastructure(Exception):
    """The run could not be carried out or its result cannot be trusted (exit 5)."""


def _ascii(text) -> str:
    return str(text).encode("ascii", "replace").decode("ascii")


# --- policy and docker -----------------------------------------------------------------

def load_policy(path: Path | None = None) -> dict:
    """The installed plugin's policy. Never resolved relative to the checkout under review.
    The default is looked up at call time, so a patched POLICY_FILE takes effect."""
    path = POLICY_FILE if path is None else path
    try:
        data = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"sandbox policy unreadable: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("context"), str) \
            or not isinstance(data.get("images"), dict):
        raise Refused("sandbox policy has no context/images")
    return data


# Variables that make the docker client talk to another daemon or trust another one: the host
# and context directly, DOCKER_CONFIG through another config directory in which the policy's
# context name resolves differently, the TLS set by re-pointing or re-trusting the connection
# (round-1 finding 13; post-commit security review 2026-10-30).
REDIRECTING_VARS = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                    "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")


def check_environment() -> None:
    """Refuse when a variable in REDIRECTING_VARS is set: it would select another daemon, where
    the same image name can mean other bytes."""
    for var in REDIRECTING_VARS:
        if os.environ.get(var):
            raise Refused(f"{var} is set; the runner uses only the context named in the plugin policy")


def client_env() -> dict[str, str]:
    """The environment for every docker client call: ours without any DOCKER_* variable, so a
    variable added to the client later cannot redirect it either."""
    return {k: v for k, v in os.environ.items() if not k.upper().startswith("DOCKER_")}


def docker(context: str, *args: str, timeout: float = DOCKER_TIMEOUT, data: bytes | None = None):
    """One bounded docker call. Raises Infrastructure on timeout or start failure."""
    env = client_env()
    try:
        return subprocess.run(["docker", "--context", context, *args], input=data,
                              stdin=None if data is not None else subprocess.DEVNULL,
                              capture_output=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as exc:
        raise Infrastructure(f"docker {args[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise Infrastructure(f"docker not available: {exc}") from exc


def daemon_reachable(context: str) -> None:
    """A stopped or unreachable daemon is an infrastructure failure, never "image missing"
    (post-build inspection A, finding 6)."""
    done = docker(context, "version", "--format", "{{.Server.Version}}")
    if done.returncode != 0 or not done.stdout.strip():
        raise Infrastructure("the docker daemon of the policy's context is not reachable")


def policy_entry(policy: dict, name: str) -> dict:
    """The policy entry for `name`, checked without docker."""
    entry = policy["images"].get(name)
    if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str) \
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(entry.get("id", ""))) \
            or not isinstance(entry.get("tools"), list) \
            or not all(isinstance(t, str) for t in entry["tools"]):
        raise Refused(f"image {name!r} is not in the plugin's sandbox policy")
    return entry


def _policy_int(entry: dict, key: str, low: int, high: int) -> int:
    value = entry[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Refused(f"sandbox policy: {key} must be an integer {low}..{high}")
    return value


def _tmpfs_bytes(text) -> int:
    m = TMPFS_SIZE_RE.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise Refused("sandbox policy: deps_tmpfs must be a size like '2g' (digits + k, m or g)")
    return int(m.group(1)) * {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2)]


def deps_policy(entry: dict) -> dict | None:
    """The image's B1.5 settings (plan step 3), validated strictly; None when the image has
    none -- then --deps is refused. Either all of DEPS_POLICY_KEYS are present or none."""
    present = [k for k in DEPS_POLICY_KEYS if k in entry]
    if not present:
        return None
    if len(present) != len(DEPS_POLICY_KEYS):
        raise Refused(f"sandbox policy: the deps settings are incomplete (need all of "
                      f"{', '.join(DEPS_POLICY_KEYS)})")
    target = entry["wheel_target"]
    if not isinstance(target, dict) or set(target) != {"python", "platforms"} \
            or not isinstance(target["python"], str) or not WHEEL_PY_RE.fullmatch(target["python"]):
        raise Refused("sandbox policy: wheel_target must be {\"python\": \"3.N\", \"platforms\": [...]}")
    try:
        sandbox_wheels.accepted_tags(target)
    except ValueError as exc:
        raise Refused(f"sandbox policy: {_ascii(exc)}") from None
    max_bytes = _policy_int(entry, "deps_max_bytes", 1, MAX_DEPS_BYTES)
    max_file = _policy_int(entry, "deps_max_file_bytes", 1, max_bytes)
    if _tmpfs_bytes(entry["deps_tmpfs"]) < max_bytes + DEPS_TAR_SLACK:
        raise Refused("sandbox policy: deps_tmpfs is smaller than deps_max_bytes + 1 MiB")
    return {"wheel_target": {"python": target["python"], "platforms": list(target["platforms"])},
            "max_bytes": max_bytes, "max_file": max_file, "tmpfs": entry["deps_tmpfs"],
            "install_timeout": _policy_int(entry, "deps_install_timeout", 1, MAX_TIMEOUT)}


def resolve_image(policy: dict, name: str) -> str:
    """The pinned image id after checking that the local image IS the one the policy names. Call
    only after daemon_reachable(): only docker's "no such image" means the image is absent
    (refusal); any other failed inspect is infrastructure."""
    entry = policy_entry(policy, name)
    done = docker(policy["context"], "image", "inspect", "--format", "{{.Id}}", entry["ref"])
    if done.returncode != 0:
        if not _absent(done, "image", entry["ref"]):
            raise Infrastructure(f"image inspect failed: {_tail(done.stderr)}")
        raise Refused(f"image {entry['ref']} is not present locally; a human builds it "
                      f"(see config/sandbox/python-test.Dockerfile) -- the runner never pulls")
    if done.stdout.decode("ascii", "replace").strip() != entry["id"]:
        raise Refused(f"image {entry['ref']} does not have the id the policy pins")
    return entry["id"]


def check_tool(entry: dict, argv: list[str]) -> None:
    """B1 runs only what the image contains (plan Approach 4). The command's program must be one of
    the image's listed tools; anything else is refused with the B1.5 explanation. This is a
    dependency contract, not a security boundary -- the container is that."""
    prog = argv[0]
    if prog not in entry["tools"]:
        # A bare name only: `/no/such/python3` or `./python3` names a file the image may not have,
        # and the tool list vouches for what PATH resolves in the image, nothing else (inspection
        # round 2, part A, finding A9). What the program then loads (`python3 -m x`, `sh -c '...'`)
        # is not checked here: a dependency the image lacks fails INSIDE the container as a
        # command result, never as a pass, and the skills' pass rule requires exit 0.
        raise Refused(f"{_ascii(prog)!r} is not a tool of this image ({', '.join(entry['tools'])}); "
                      f"name the tool bare; B1 supports only projects whose test dependencies are in "
                      f"the image -- see B1.5")


def _tail(raw: bytes) -> str:
    return _ascii(raw.decode("utf-8", "replace").strip())[-200:]


def _absent(done, kind: str, ref: str) -> bool:
    """Docker's own absence answer for exactly `ref` -- the ONLY failure that proves absence.

    One stderr line must read `[Error[ response from daemon]: ]No such <kind|object>: <ref>`
    (docker 29.8.2 measured: "Error response from daemon: No such container: <ref>"). A
    substring is not enough: a transport error such as `dial unix /run/docker.sock: connect:
    no such file or directory` contains "no such" and proves nothing (post-build inspection
    round 2, part A, findings A4 and A6)."""
    if done.returncode == 0:
        return False
    prefix = r"(?:Error(?: response from daemon)?: )?"
    forms = [r"No such (?:%s|object): %s" % (re.escape(kind), re.escape(ref))]
    if kind == "network":
        # docker 29.8.2, measured 2026-11-01: `docker inspect --type network <ref>` on a missing
        # network answers "Error response from daemon: network <ref> not found".
        forms.append("network " + re.escape(ref) + " not found")
    line = re.compile(prefix + "(?:" + "|".join(forms) + ")", re.IGNORECASE)
    return any(line.fullmatch(t.strip())
               for t in done.stderr.decode("utf-8", "replace").splitlines())


def _expired(context: str, kind: str, selector: str, now: float) -> list[str]:
    """The ids of `kind` objects carrying `selector` whose claudex.deadline + JANITOR_GRACE is
    past `now`. An object without a numeric deadline label is never expired."""
    fmt = '{{.ID}} {{.Label "claudex.deadline"}}'
    if kind == "container":
        done = docker(context, "ps", "-a", "--filter", selector, "--format", fmt)
    else:
        done = docker(context, "network", "ls", "--no-trunc", "--filter", selector, "--format", fmt)
    if done.returncode != 0:
        raise Infrastructure(f"cannot list sandbox {kind}s")
    out = []
    for line in done.stdout.decode("ascii", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) + JANITOR_GRACE < now:
            out.append(parts[0])
    return out


def janitor(context: str, now: float | None = None, run_id: str | None = None,
            kinds: tuple[str, ...] = ("container",)) -> list[str]:
    """Remove labelled objects more than JANITOR_GRACE seconds past their deadline -- never one
    within its deadline, whoever started it. Returns the ids it removed.

    `kinds` names what to collect: B1 and B1.5 keep the container-only default; plan B2 adds
    "network" (approach 11). Containers always go first, then networks (a network with an
    attached container cannot be removed). At most JANITOR_MAX objects are removed per pass,
    all kinds together; the expired rest is left for the next pass and reported on stderr as
    `deferred=<n>`. Every object whose removal cannot be proven is a survivor: the pass goes on,
    and afterwards Infrastructure names all of them.

    `now` and `run_id` only narrow it, for a test that checks ONE abandoned run "after expiry"
    without touching any other session's objects; the runner calls it with neither."""
    if isinstance(kinds, str) or not kinds or len(set(kinds)) != len(kinds) \
            or any(k not in JANITOR_KINDS for k in kinds):
        raise ValueError(f"janitor kinds must be distinct names from {JANITOR_KINDS}")
    selector = f"label={LABEL}" if run_id is None else f"label={LABEL}={run_id}"
    now = time.time() if now is None else now
    removed, survivors, deferred = [], [], 0
    for kind in (k for k in JANITOR_KINDS if k in kinds):
        for ref in _expired(context, kind, selector, now):
            if len(removed) + len(survivors) >= JANITOR_MAX:
                deferred += 1
                continue
            try:
                remove_object(context, kind, ref)
            except Infrastructure:
                survivors.append(f"{kind} {ref[:24]}")
                continue
            removed.append(ref)
    if deferred:
        _diagnostic(lambda: f"sandbox_run: JANITOR deferred={deferred} expired objects are left for "
                            f"the next pass (at most {JANITOR_MAX} per pass)\n")
    if survivors:
        raise Infrastructure(f"janitor could not confirm the removal of: {', '.join(survivors)}")
    return removed


def remove_object(context: str, kind: str, ref: str) -> None:
    """Remove a container or a network by id or name and PROVE it is gone: only docker's own
    absence answer for exactly `ref` to the follow-up `inspect --type <kind>` counts (_absent). A
    disconnected daemon or a permission error is not a removal (post-build inspection A,
    finding 4)."""
    if kind == "container":
        docker(context, "rm", "-f", ref)
    elif kind == "network":
        docker(context, "network", "rm", ref)
    else:
        raise ValueError(f"cannot remove a {kind!r}")
    gone = docker(context, "inspect", "--type", kind, ref)
    if not _absent(gone, kind, ref):
        raise Infrastructure(f"{kind} {ref[:24]} could not be confirmed removed")


def _remove(context: str, ref: str) -> None:
    """B1's container removal with absence proof; remove_object(context, "container", ref)."""
    remove_object(context, "container", ref)


# --- the result stream -------------------------------------------------------------------

RECORD = 10240  # tarfile's default record size; the driver writes with the defaults


INDEX_RE = re.compile(r"0|[1-9][0-9]{0,5}")  # the <n> of a prefix member such as change/<n>


def read_framed(data: bytes, nonce: str, expected: dict[str, int], prefix_caps: dict[str, int],
                total_cap: int) -> tuple[dict, dict[str, bytes]]:
    """Parse a driver's framed result tar member by member (stream mode) under explicit caps --
    the shared reader of B1, B1.5 and B2 (plan B2 interfaces, U6).

    `expected` maps each allowed exact member name to its byte cap; `prefix_caps` maps a prefix
    to the cap of each member named `<prefix><n>`, n a canonical decimal index (0..999999, no
    sign, no leading zero, nothing after it) -- B2's `change/<n>`. Every member is a regular file
    within its cap and appears at most once; `result.json` must be among `expected` and present,
    and it must be a JSON object carrying `nonce` and no `infrastructure` reason. Which other
    members are REQUIRED is the caller's rule. The framing is exact: after the last member the
    end-of-archive blocks and the zero padding to the record size, nothing more, not even more
    zeros (post-build inspection A, finding 7); the whole stream is at most `total_cap` bytes."""
    if "result.json" not in expected:
        raise ValueError("read_framed: result.json must be an expected member")
    if len(data) > total_cap:
        raise Infrastructure("result stream over the cap")

    def cap_of(name: str) -> int | None:
        if name in expected:
            return expected[name]
        for prefix, cap in prefix_caps.items():
            if name.startswith(prefix) and INDEX_RE.fullmatch(name[len(prefix):]):
                return cap
        return None

    got: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as tf:
            for member in tf:
                cap = cap_of(member.name)
                if cap is None or member.name in got:
                    raise Infrastructure(f"unexpected result member {_ascii(member.name)!r}")
                if not member.isreg() or member.size > cap:
                    raise Infrastructure(f"result member {_ascii(member.name)!r} is not a regular file "
                                         f"within its cap")
                handle = tf.extractfile(member)
                got[member.name] = handle.read(member.size + 1) if handle else b""
                if len(got[member.name]) != member.size:
                    raise Infrastructure(f"result member {_ascii(member.name)!r} has the wrong size")
            end = tf.offset
    except tarfile.TarError as exc:
        raise Infrastructure(f"result stream is not a valid tar: {exc}") from exc
    framed = -(-(end + 1024) // RECORD) * RECORD
    if len(data) != framed or any(data[end:]):
        raise Infrastructure("the result archive is not framed exactly (trailing or missing bytes)")
    if "result.json" not in got:
        raise Infrastructure("result member result.json missing")
    try:
        result = json.loads(got["result.json"].decode("utf-8"))
    except ValueError as exc:
        raise Infrastructure("result.json is not JSON") from exc
    if not isinstance(result, dict) or result.get("nonce") != nonce:
        raise Infrastructure("result does not carry this run's nonce")
    if result.get("infrastructure"):
        raise Infrastructure(f"driver: {_ascii(result['infrastructure'])[:200]}")
    return result, got


def read_result(data: bytes, nonce: str, exports: list[str],
                with_deps: bool = False) -> tuple[dict, dict[str, bytes]]:
    """The B1/B1.5 result: read_framed with B1's caps (RESULT_CAP, looked up at call time),
    exactly the names result.json, stdout.txt, stderr.txt, out/<export> -- the first three
    required -- and `install.txt`, which belongs to a run with deps and to no other, as does a
    deps object (plan B1.5 steps 5 and 6)."""
    caps = {"result.json": 1024 * 1024, "stdout.txt": CAPTURE_CAP, "stderr.txt": CAPTURE_CAP}
    if with_deps:
        caps["install.txt"] = INSTALL_CAP
    caps.update({f"out/{n}": EXPORT_CAP for n in exports})
    result, got = read_framed(data, nonce, caps, {}, RESULT_CAP)
    for need in ("stdout.txt", "stderr.txt") + (("install.txt",) if with_deps else ()):
        if need not in got:
            raise Infrastructure(f"result member {need} missing")
    status = result.get("command_status")
    if status not in ("exited", "timeout", "output_limit", "not_started", "deps_failed"):
        raise Infrastructure("result has no valid command_status")
    _check_result_deps(result.get("deps"), status, with_deps)
    return result, got


def _check_result_deps(deps, status: str, with_deps: bool) -> None:
    """The driver's deps object must fit the run: null without deps; with deps an object whose
    status agrees with command_status (deps_failed <-> failed; a failed install never ran)."""
    if not with_deps:
        if deps is not None or status == "deps_failed":
            raise Infrastructure("result carries a deps outcome although no deps were sent")
        return
    if not isinstance(deps, dict) or set(deps) != {"status", "reason", "installed"} \
            or deps["status"] not in ("installed", "failed") or not isinstance(deps["installed"], list):
        raise Infrastructure("result has no valid deps outcome")
    if deps["status"] == "installed" and (status == "deps_failed" or deps["reason"] is not None):
        raise Infrastructure("result: deps installed but the command was not run")
    if deps["status"] == "failed" and (status not in ("deps_failed", "not_started")
                                       or not isinstance(deps["reason"], str)):
        raise Infrastructure("result: the command ran although the deps failed")


def stream_start(context: str, cid: str, stdin: bytes, timeout: float,
                 result_cap: int | None = None) -> tuple[bytes, bytes]:
    """`docker start -ai`: write stdin from a thread, read stdout under the result cap and stderr
    under its own small cap WHILE receiving; on byte cap + 1, or on the deadline, kill the
    container at once (post-build inspection A, finding 3).

    `result_cap` is the explicit per-run cap of the shared transport (plan B2 approach 5: the
    build result is bounded by the policy's `result_cap`); None means B1's RESULT_CAP, looked up
    at call time. It is validated before docker is started."""
    if result_cap is None:
        result_cap = RESULT_CAP
    if isinstance(result_cap, bool) or not isinstance(result_cap, int) \
            or not 1 <= result_cap <= MAX_RESULT_CAP:
        raise ValueError(f"result_cap must be an integer 1..{MAX_RESULT_CAP}")
    env = client_env()
    try:
        proc = subprocess.Popen(["docker", "--context", context, "start", "-ai", cid], env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise Infrastructure(f"docker not available: {exc}") from exc
    try:
        return _stream(context, cid, proc, stdin, timeout, result_cap)
    finally:
        # The local docker client never outlives this call -- on success, on a failed `docker
        # kill`, on a deadline and on KeyboardInterrupt alike (inspection round 2, part A,
        # finding 15). Killing it is independent of whether the container kill worked.
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _stream(context: str, cid: str, proc, stdin: bytes, timeout: float,
            result_cap: int) -> tuple[bytes, bytes]:
    out, err, failure = bytearray(), bytearray(), []

    def feed():
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except OSError:
            pass

    def drain_err():
        while True:
            chunk = proc.stderr.read(65536)
            if not chunk:
                return
            if len(err) < 65536:
                err.extend(chunk[: 65536 - len(err)])

    threads = [threading.Thread(target=feed, daemon=True), threading.Thread(target=drain_err, daemon=True)]
    for t in threads:
        t.start()
    end = time.monotonic() + timeout

    def stop(why):
        failure.append(why)
        try:
            proc.kill()
        finally:
            try:
                docker(context, "kill", cid)
            except Infrastructure:
                pass  # the removal in run()'s finally still proves the container gone, or fails

    reader_done = threading.Event()

    def drain_out():
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    return
                out.extend(chunk)
                if len(out) > result_cap:
                    stop("result stream over the cap")
                    return
        finally:
            reader_done.set()

    reader = threading.Thread(target=drain_out, daemon=True)
    reader.start()
    while not reader_done.wait(0.2):
        if time.monotonic() > end:
            stop(f"no result within {timeout:.0f}s")
            break
    reader.join(10)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    for t in threads:
        t.join(5)
    if failure:
        raise Infrastructure(failure[0])
    return bytes(out), bytes(err)


def supervised_snapshot(repo: Path, tree: str | None, pin: list[str] | None, work: Path,
                        deadline: float = SNAPSHOT_DEADLINE):
    """Build the snapshot in a SUPERVISED child process (plan step 1, post-build inspection A,
    finding 1): hard deadline, process tree terminated and verified. Exit 2 of the child is a
    refusal, anything else that is not 0 -- or a deadline -- is infrastructure."""
    index_dir = hunt_io.make_dir(work, "index", base=work)
    argv = [sys.executable, "-I", str(Path(__file__).resolve().parent / "sandbox_snapshot.py"),
            "--repo", str(repo), "--index-dir", str(index_dir), "--write", str(work)]
    argv += ["--pin", *pin] if pin else ["--tree", tree]
    with hunt_io.open_new(work, "snapshot.stdout", base=work) as fh:
        res = hunt_snapshot.run_supervised(argv, deadline=deadline, stdout_file=fh)
    status, raw = hunt_io.read_at(work, "snapshot.stdout", limit=65536)
    text = raw.decode("utf-8", "replace") if status == "ok" else ""
    if res.timed_out or res.survivors or getattr(res, "cleanup_unverified", False):
        raise Infrastructure(f"snapshot worker exceeded {deadline:.0f}s (survivors: {res.survivors})")
    if res.returncode == 2:
        reason = re.search(r"^REFUSED=(.*)$", text, re.M)
        raise Refused(f"snapshot: {_ascii(reason.group(1)) if reason else 'refused'}")
    if res.returncode != 0:
        reason = re.search(r"^ERROR=(.*)$", text, re.M)
        raise Infrastructure(f"snapshot worker exit {res.returncode}: {_ascii(reason.group(1)) if reason else ''}")
    s_meta, meta = hunt_io.read_at(work, "snapshot.json", limit=64 * 1024 * 1024)
    s_tar, tar_bytes = hunt_io.read_at(work, "snapshot.tar", limit=SNAPSHOT_TAR_CAP)
    if s_meta != "ok" or s_tar != "ok":
        raise Infrastructure("snapshot worker left no readable result")
    info = json.loads(meta.decode("utf-8"))
    if tree is not None and info.get("tree") != tree:
        raise Infrastructure("snapshot worker returned another tree")
    return info, tar_bytes


# --- the run -----------------------------------------------------------------------------

def bootstrap(source: bytes) -> tuple[list[str], bytes]:
    """The driver hand-over for EVERY producer (plan B2 approach 3b): returns the argv tail after
    the image -- `python3 -I -S -c <LOADER with sha256(source)>` -- and the bytes that must come
    FIRST on the container's stdin, `<len(source)>\\n<source>`; the producer's own protocol
    follows them unchanged. The argv length does not depend on the source (it replaced B1.5's
    compressed argv bootstrap, which grew with the driver towards the Windows command-line
    limit). Nothing in either part comes from the repository; the source is the plugin's own."""
    if not isinstance(source, bytes) or not 1 <= len(source) <= LOADER_MAX:
        raise Infrastructure(f"driver source must be 1..{LOADER_MAX} bytes")
    tail = [*DRIVER_PREFIX, LOADER % hashlib.sha256(source).hexdigest()]
    return tail, str(len(source)).encode("ascii") + b"\n" + source


def cmdline_length(argv: list[str]) -> int:
    """The length of `argv` as Windows' CreateProcess receives it (subprocess.list2cmdline)."""
    return len(subprocess.list2cmdline(argv))


def create_args(run_id: str, deadline: int, image_id: str, driver_argv: list[str],
                deps_tmpfs: str | None = None) -> list[str]:
    """`docker create` arguments exactly as plan B1 step 2 states them. With deps (plan B1.5,
    post-approval change 2) one more tmpfs: /deps, exec (extension modules), nosuid, nodev,
    root-owned 1777; without deps the argv is B1's apart from the driver argv, which must be
    bootstrap()'s loader tail and nothing else."""
    if not isinstance(driver_argv, list) or len(driver_argv) != 5 or driver_argv[:4] != DRIVER_PREFIX \
            or not isinstance(driver_argv[4], str) or not LOADER_RE.fullmatch(driver_argv[4]):
        raise ValueError("driver argv must be python3 -I -S -c <loader>")
    deps = [] if deps_tmpfs is None else [
        "--tmpfs", f"/deps:rw,exec,nosuid,nodev,size={deps_tmpfs},mode=1777"]
    return [
        "create", "--name", f"claudex-run-{run_id}", "--label", f"{LABEL}={run_id}",
        "--label", f"claudex.deadline={deadline}", "--pull=never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
        "--security-opt", "no-new-privileges", "--user", "0:0", "--pids-limit", "512",
        "--memory", "4g", "--memory-swap", "4g", "--cpus", "2", "--log-driver", "none",
        "--mount", f"type=tmpfs,destination=/work,tmpfs-size={WORK_TMPFS},tmpfs-mode=1777",
        "--mount", "type=tmpfs,destination=/out,tmpfs-size=48m,tmpfs-mode=1777",
        # bandit B108: a tmpfs INSIDE the container, not the host's /tmp.
        "--tmpfs", "/tmp:size=256m",  # nosec B108
        "--tmpfs", "/home/run:size=64m", *deps,
        "-e", "HOME=/home/run", "-w", "/", "-i", image_id, *driver_argv,
    ]


# --- plan B1.5: the dependency set -----------------------------------------------------------

def deps_paths(raw: list[str]) -> list[str]:
    """--deps paths canonicalised like --pin paths; at most MAX_DEPS_FILES, each once. Static."""
    if len(raw) > MAX_DEPS_FILES:
        raise Refused(f"--deps: at most {MAX_DEPS_FILES} files")
    paths = [sandbox_snapshot.canonical_path(p) for p in raw]
    if len(set(paths)) != len(paths):
        raise Refused("--deps names the same file twice")
    return paths


def read_deps_files(info: dict, tar_bytes: bytes, paths: list[str]) -> list[tuple[str, str, bytes]]:
    """(path, content_sha256, bytes) of each --deps file, from the in-memory snapshot of the
    pinned tree -- never the working tree. Each must be a regular-file entry of the snapshot
    (a directory, a missing path or anything else is refused), and its bytes must hash to the
    entry's verified content_sha256."""
    entries = {}
    for item in info.get("entries") or ():
        if isinstance(item, list) and len(item) == 3 and isinstance(item[0], str):
            entries[item[0]] = item[2]
    want = {p: None for p in paths}
    for p in paths:
        if p not in entries:
            raise Refused(f"--deps {_ascii(p)!r} is not a regular file of the pinned tree")
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tf:
            for member in tf:
                if member.name in want:
                    if want[member.name] is not None or not member.isreg():
                        raise Infrastructure(f"snapshot member {_ascii(member.name)!r} is not one regular file")
                    if member.size > sandbox_deps.MAX_REQ_FILE:
                        raise Refused(f"--deps {_ascii(member.name)!r} is over the "
                                      f"{sandbox_deps.MAX_REQ_FILE} byte limit")
                    handle = tf.extractfile(member)
                    want[member.name] = handle.read() if handle else b""
    except tarfile.TarError as exc:
        raise Infrastructure(f"the snapshot tar cannot be read: {exc}") from exc
    out = []
    for p in paths:
        data = want[p]
        if data is None or hashlib.sha256(data).hexdigest() != entries[p]:
            raise Infrastructure(f"snapshot member {_ascii(p)!r} does not match its entry")
        out.append((p, entries[p], data))
    return out


def parse_deps(files: list[tuple[str, str, bytes]]) -> list:
    """Strict parse (sandbox_deps) and merge of the --deps files; refusals name file and line."""
    try:
        groups = [sandbox_deps.parse_requirements(data, path) for path, _sha, data in files]
        reqs = sandbox_deps.merge(groups)
    except sandbox_deps.DepsRefused as exc:
        raise Refused(f"--deps: {_ascii(exc)}") from None
    if not reqs:
        # an empty inventory is a caller mistake; the driver requires at least one wheel
        # (post-build inspection B, finding 3 -- fixed here, not with an empty deps tar)
        raise Refused("--deps: the files list no requirement")
    if len(reqs) > sandbox_deps.MAX_REQUIREMENTS:
        # each file is bounded by the parser, the merge is not -- and the driver accepts at most
        # MAX_REQUIREMENTS (post-build inspection A, finding 6)
        raise Refused(f"--deps: the files list {len(reqs)} requirements together, more than "
                      f"{sandbox_deps.MAX_REQUIREMENTS}")
    return reqs


def _check_worker_files(result: dict, reqs: list, target: dict) -> dict:
    """The worker's file list must be exactly one wheel per requirement, with the same name and
    version, whose file name parses to that name and version and carries an accepted tag. The
    worker is ours, so a mismatch is an infrastructure failure, not the input's fault."""
    files = result.get("files")
    if not isinstance(files, list) or len(files) != len(reqs):
        raise Infrastructure("fetch worker: the file list does not match the requirements")
    accepted = set(sandbox_wheels.accepted_tags(target))
    by_name = {}
    for item in files:
        if not (isinstance(item, list) and len(item) == 5 and all(isinstance(x, str) for x in item[:4])):
            raise Infrastructure("fetch worker: malformed file entry")
        if item[0] in by_name:
            raise Infrastructure(f"fetch worker: two files for {_ascii(item[0])}")
        by_name[item[0]] = item
    for req in reqs:
        item = by_name.get(req.name)
        if item is None or item[1] != req.version:
            raise Infrastructure(f"fetch worker: no file for {req.name}=={req.version}")
        try:
            name, version, _build, tags = sandbox_wheels.parse_wheel_filename(item[2])
        except sandbox_wheels.WheelRefused as exc:
            raise Infrastructure(f"fetch worker: {_ascii(exc)}") from None
        if name != req.name or version != req.version or not (set(tags) & accepted):
            raise Infrastructure(f"fetch worker: {_ascii(item[2])} is not a wheel of "
                                 f"{req.name}=={req.version} for the image")
    return by_name


def build_deps_tar(members: list[tuple[str, bytes]]) -> bytes:
    """Flat regular members in the given order, mode 0644, uid/gid 0, no names, mtime 0."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT, encoding="utf-8") as tf:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.type, ti.mode, ti.size = tarfile.REGTYPE, 0o644, len(data)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _diagnostic(line) -> None:
    """Write one diagnostic line to stderr, best effort -- as sandbox_fetch._diagnostic: a full
    redirected log (OSError) or a closed stream (ValueError) is swallowed, so a log line never
    stands between a failure and its exit code, its manifest or its quarantine fields. `line` is
    a callable so that formatting errors are covered too."""
    try:
        sys.stderr.write(line())
    except Exception:  # noqa: BLE001 - the diagnostic is optional, the outcome is not
        return


def _emit(lines: list[str]) -> bool:
    """Write the KEY=value result lines to stdout and flush; False when that fails. A lost line
    means the caller cannot read the result, so the caller of _emit maps False to exit 5 -- the
    manifest has already been written and stays the evidence."""
    try:
        sys.stdout.write("".join(f"{line}\n" for line in lines))
        sys.stdout.flush()
    except Exception:  # noqa: BLE001 - every failure of the stream means the same: not delivered
        return False
    return True


def _flushes(stream) -> bool:
    """True when the stream flushes; every failure of the stream means the same: lost output."""
    try:
        stream.flush()
    except Exception:  # noqa: BLE001
        return False
    return True


def settle_std_streams() -> None:
    """Make sure the interpreter's shutdown flush of stdout and stderr cannot fail.

    A stream whose write failed (a reader that went away, a full redirected log) keeps its
    unwritten bytes; Python flushes the stream once more while shutting down, and when that
    flush fails it replaces the process exit code with 120 -- whatever main() returned. So the
    entry point flushes both streams here; a stream that still fails gets os.devnull put under
    its descriptor (os.dup2 -- the remedy the Python documentation gives for SIGPIPE), which
    discards the bytes that could not be delivered anyway. A stream without a descriptor is
    replaced by an os.devnull writer instead. Normal shutdown (atexit, finalisers) still runs;
    only output that was already lost is dropped. Called only from entry(), never by main()."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        if _flushes(stream):
            continue
        try:
            null = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null, stream.fileno())
            finally:
                os.close(null)
            stream.flush()  # the pending bytes now go to os.devnull
        except Exception:  # noqa: BLE001 - no descriptor, or still failing: swap the object
            with contextlib.suppress(OSError):
                setattr(sys, name, open(os.devnull, "w", encoding="ascii"))  # noqa: SIM115


def entry(argv=None) -> int:
    """The process entry point: main(), then settle_std_streams(), so that the exit code main()
    chose (5 for a lost result line, 2 for a refusal) is the exit code of the process."""
    code = main(argv)
    settle_std_streams()
    return code


def _remove_job_dir(state: "_Run", job_dir: Path) -> str | None:
    """Remove the download directory; None when it is gone. Otherwise record the retained path
    in the manifest fields, name it on stderr and return the reason -- a retained directory is
    an infrastructure failure, never a success (post-build inspection A, finding 9)."""
    shutil.rmtree(job_dir, ignore_errors=True)
    if not os.path.lexists(job_dir):
        return None
    state.fields["deps_dir_cleanup"] = "failed"
    state.fields["deps_dir_retained"] = str(job_dir)
    _diagnostic(lambda: f"sandbox_run: RETAINED path={ascii(str(job_dir))} -- the download directory "
                        f"could not be removed; remove it by hand\n")
    return f"the download directory {_ascii(str(job_dir))} could not be removed and is retained"


def fetch_deps(state: "_Run", reqs: list, cfg: dict) -> bytes:
    """Plan B1.5 steps 3 and 4: download in the deadline-killed worker, re-verify every byte
    here, build the deps tar. The job directory is created fresh under the run directory and
    removed on every exit path -- except after an unconfirmed worker termination, which leaves
    it in place as quarantine (FetchUnconfirmed; manifest cleanup "unconfirmed"). A removal that
    fails is Infrastructure naming the retained path, whatever the outcome before it was."""
    job_dir = hunt_io.make_dir(state.run_dir, "deps", base=state.scratch)
    job = {"kind": "wheels", "requirements": [[r.name, r.version, sorted(r.hashes)] for r in reqs],
           "target": cfg["wheel_target"], "max_file": cfg["max_file"], "max_total": cfg["max_bytes"]}
    keep = False
    try:
        try:
            result = sandbox_fetch.run_job(job, job_dir, FETCH_DEADLINE, state.scratch, state.run_id)
            by_name = _check_worker_files(result, reqs, cfg["wheel_target"])
            expected = [(r.name, r.version, by_name[r.name][2], r.hashes) for r in reqs]
            verified = sandbox_fetch.verify_download(job_dir, expected, cfg["max_file"], cfg["max_bytes"])
        except sandbox_fetch.FetchUnconfirmed as exc:
            keep = True
            state.fields["cleanup"] = "unconfirmed"
            # Every field is copied from the exception, which carries what sandbox_fetch wrote into
            # the quarantine record -- the runner computes no deadline of its own (inspection A,
            # finding 8). A missing attribute is recorded as null, never filled in.
            state.fields["quarantine"] = {"cleanup": "unconfirmed", "pid": exc.pid, "path": str(exc.path),
                                          "deadline_epoch": getattr(exc, "deadline_epoch", None),
                                          "record": str(exc.record) if exc.record else None}
            _diagnostic(lambda e=exc: f"sandbox_run: QUARANTINE path={ascii(str(e.path))} pid={e.pid} "
                                      f"cleanup=unconfirmed -- remove by hand after checking that pid "
                                      f"{e.pid} is gone\n")
            raise Infrastructure(f"fetch: {_ascii(exc)}") from None
        except sandbox_fetch.FetchRefused as exc:
            raise Refused(f"fetch: {_ascii(exc)}") from None
        except sandbox_fetch.FetchInfrastructure as exc:
            raise Infrastructure(f"fetch: {_ascii(exc)}") from None
        hashes = {r.name: r.hashes for r in reqs}
        wheels, selected, listed = [], [], []
        for (name, version, filename, digest, size), req in zip(verified, reqs):
            # read once more and hash what goes into the tar: nothing between the check and the
            # copy is trusted either
            status, data = hunt_io.read_regular(job_dir / filename, limit=cfg["max_file"])
            if status != "ok" or len(data) != size or hashlib.sha256(data).hexdigest() != digest \
                    or digest not in hashes[name]:
                raise Infrastructure(f"{_ascii(filename)} changed after its verification")
            wheels.append((filename, data))
            selected.append((req, digest))
            listed.append({"name": name, "version": version, "wheel": filename, "sha256": digest})
    except BaseException as exc:
        if not keep:
            failure = _remove_job_dir(state, job_dir)
            if failure is not None and isinstance(exc, Exception):
                # the retained directory is the outcome; the first failure stays in the reason
                raise Infrastructure(f"{failure}; the fetch had already failed: {_ascii(exc)}") from None
        raise
    failure = _remove_job_dir(state, job_dir)
    if failure is not None:
        raise Infrastructure(failure)
    members = sorted(wheels) + [("requirements.txt", sandbox_deps.render_requirements(selected))]
    tar = build_deps_tar(members)
    if len(tar) > cfg["max_bytes"] + DEPS_TAR_SLACK:
        raise Refused(f"the deps tar ({len(tar)} bytes) is over its cap of "
                      f"{cfg['max_bytes'] + DEPS_TAR_SLACK} bytes")
    state.fields["deps"].update({"requirements": listed,
                                 "deps_tar_sha256": hashlib.sha256(tar).hexdigest()})
    return tar


class _Run:
    """What is known about a run so far -- written as a manifest on EVERY outcome, failures
    included (post-build inspection A, finding 10)."""

    def __init__(self):
        self.run_id = sandbox_fetch.new_run_id()  # one generator for run dirs and quarantine records
        self.run_dir: Path | None = None
        self.scratch: Path | None = None
        self.fields: dict = {"run_id": self.run_id, "mode": "container", "cleanup": "not_needed",
                             "deps": None}

    def requirements_sha256(self) -> str | None:
        deps = self.fields.get("deps")
        return deps.get("requirements_sha256") if isinstance(deps, dict) else None

    def open_run_dir(self) -> Path:
        if self.run_dir is None:
            self.run_dir = hunt_io.ensure_dirs(self.scratch / "sandbox" / f"run-{self.run_id}",
                                               base=self.scratch)
        return self.run_dir

    def write(self, runner_status: str, reason: str = "") -> str | None:
        if self.run_dir is None:
            return None
        manifest = dict(self.fields, runner_status=runner_status)
        if reason:
            manifest["reason"] = _ascii(reason)[:300]
        data = (json.dumps(manifest, sort_keys=True, indent=1) + "\n").encode("utf-8")
        try:
            hunt_io.create_file(self.run_dir, "manifest.json", data, base=self.scratch)
        except hunt_io.HuntIOError:
            return None
        return hashlib.sha256(data).hexdigest()


def run(args, state: _Run) -> int:
    # Known before any check, so that a static refusal can still be recorded (finding A10).
    state.scratch = Path(os.path.abspath(args.scratch))
    state.fields.update({"image": args.image, "argv": list(args.argv), "timeout": args.timeout})
    # Plan B1.5 step 3: quarantine records are listed as data, never acted on.
    for line in sandbox_fetch.list_quarantine(state.scratch):
        _diagnostic(lambda q=line: f"sandbox_run: QUARANTINE {q}\n")
    policy = load_policy()
    check_environment()
    context = policy["context"]
    if not 1 <= args.timeout <= MAX_TIMEOUT:
        raise Refused(f"--timeout must be 1..{MAX_TIMEOUT}")
    if len(args.export) > MAX_EXPORTS or any(not EXPORT_NAME_RE.fullmatch(e) for e in args.export) \
            or len(set(args.export)) != len(args.export):
        raise Refused("--export: at most 3 distinct plain names [A-Za-z0-9._-]")
    if not args.argv:
        raise Refused("no command given after --")
    if not args.pin and (not args.tree or not TREE_RE.fullmatch(args.tree)):
        raise Refused("--tree must be a full tree id (or use --pin)")
    for rel in args.pin or ():
        sandbox_snapshot.canonical_path(rel)  # refuses before docker and before any git object
    paths = deps_paths(list(args.deps))
    entry = policy_entry(policy, args.image)
    cfg = deps_policy(entry)
    if paths and cfg is None:
        raise Refused(f"image {args.image!r} has no wheel_target in the plugin's sandbox policy; "
                      f"--deps is not available for it")
    check_tool(entry, list(args.argv))
    # Everything above is static and refuses without a docker call; _report_failure records such
    # a refusal in a run directory of its own when the scratch directory exists.
    repo = Path(os.path.abspath(args.repo))
    scratch = state.scratch
    state.open_run_dir()

    daemon_reachable(context)
    state.fields["image_id"] = resolve_image(policy, args.image)
    janitor(context)
    work = hunt_io.make_dir(state.run_dir, "snapshot", base=scratch)
    try:
        info, tar_bytes = supervised_snapshot(repo, None if args.pin else args.tree, args.pin, work)
    finally:
        # The run directory keeps the manifest and the results, not a copy of the repository.
        shutil.rmtree(work, ignore_errors=True)
    tree = info["tree"]
    state.fields.update({"tree": tree, "input_sha256": info["input_sha256"], "files": info["files"]})

    deps_tar = b""
    if paths:
        # Every refusal of the input happens here, before the network and before any container.
        files = read_deps_files(info, tar_bytes, paths)
        reqs = parse_deps(files)
        state.fields["deps"] = {
            "files": [{"path": p, "content_sha256": h} for p, h, _data in files],
            "requirements_sha256": sandbox_deps.requirements_sha256(reqs),
            "wheel_target": cfg["wheel_target"], "requirements": None, "deps_tar_sha256": None,
            "install": None, "install_txt_sha256": None,
        }
        deps_tar = fetch_deps(state, reqs, cfg)

    nonce = secrets.token_hex(16)
    deadline = int(time.time()) + args.timeout + 300
    driver = DRIVER_FILE.read_bytes()
    state.fields["driver_sha256"] = hashlib.sha256(driver).hexdigest()
    loader_argv, loader_block = bootstrap(driver)
    spec = {"argv": list(args.argv), "exports": list(args.export), "capture_cap": CAPTURE_CAP,
            "export_cap": EXPORT_CAP, "timeout": args.timeout, "tar_len": len(tar_bytes),
            "deps_len": len(deps_tar),
            "deps_sha256": hashlib.sha256(deps_tar).hexdigest() if deps_tar else "",
            "deps_timeout": cfg["install_timeout"] if cfg else DEFAULT_DEPS_TIMEOUT}
    # The loader block first (plan B2 approach 3b), then the driver's protocol unchanged.
    stdin = loader_block + (nonce + "\n").encode() + (json.dumps(spec, sort_keys=True) + "\n").encode() \
        + tar_bytes + deps_tar

    name = f"claudex-run-{state.run_id}"
    state.fields["cleanup"] = "pending"
    try:
        # Creation is INSIDE the protected region: if docker creates the container but the client
        # times out or is interrupted, the finally still removes it by its predetermined name
        # (post-build inspection A, finding 5).
        created = docker(context, *create_args(state.run_id, deadline, entry["id"], loader_argv,
                                               deps_tmpfs=cfg["tmpfs"] if deps_tar else None))
        if created.returncode != 0:
            raise Infrastructure(f"docker create failed: {_tail(created.stderr)}")
        out, err = stream_start(context, name, stdin, args.timeout + 240)
        st = docker(context, "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name)
        if st.returncode != 0:
            raise Infrastructure("cannot inspect the finished container")
        state_words = st.stdout.decode("ascii", "replace").split()
        if len(state_words) != 2:
            raise Infrastructure("unexpected container state from inspect")
        exit_code, oom = state_words
        if oom == "true":
            result, got = {"command_status": "oom", "command_exit": None, "truncated": False,
                           "exports": {}}, {}
        elif exit_code != "0":
            raise Infrastructure(f"driver ended with exit {exit_code}: {_tail(err)}")
        else:
            result, got = read_result(out, nonce, list(args.export), with_deps=bool(deps_tar))
    finally:
        try:
            _remove(context, name)
            state.fields["cleanup"] = "confirmed"
        except Infrastructure:
            state.fields["cleanup"] = "UNCONFIRMED"
            raise

    exported = {}
    for fname, data in sorted(got.items()):
        if fname.startswith("out/"):
            hunt_io.make_tree(state.run_dir, "out", base=scratch)
            hunt_io.create_file(state.run_dir / "out", fname[4:], data, base=scratch)
            exported[fname[4:]] = hashlib.sha256(data).hexdigest()
        else:
            hunt_io.create_file(state.run_dir, fname, data, base=scratch)
    for ename in args.export:
        exported.setdefault(ename, result.get("exports", {}).get(ename, "missing")
                            if isinstance(result.get("exports"), dict) else "missing")
    state.fields.update({
        "command_status": result["command_status"],
        "command_exit": result.get("command_exit") if result["command_status"] == "exited" else None,
        "truncated": bool(result.get("truncated")), "exported": exported,
    })
    if isinstance(state.fields["deps"], dict):
        state.fields["deps"]["install"] = result.get("deps")
        if "install.txt" in got:
            state.fields["deps"]["install_txt_sha256"] = hashlib.sha256(got["install.txt"]).hexdigest()
    digest = state.write("ok")
    if digest is None:
        # No manifest, no result: the pass rule needs MANIFEST_SHA256, and printing `None` next to
        # COMMAND_EXIT=0 would be a pass without evidence (inspection round 2, part A, finding 14).
        raise Infrastructure("the run manifest could not be written")
    exit_shown = state.fields["command_exit"]
    lines = [f"RUN_DIR={state.run_dir}", f"TREE={tree}",
             f"COMMAND_STATUS={state.fields['command_status']}",
             f"COMMAND_EXIT={exit_shown if exit_shown is not None else '-'}"]
    if state.requirements_sha256():
        lines.append(f"REQUIREMENTS_SHA256={state.requirements_sha256()}")
    lines.append(f"MANIFEST_SHA256={digest}")
    if not _emit(lines):
        # The manifest is written and stays the evidence, but a caller that cannot read
        # MANIFEST_SHA256 cannot apply the pass rule: never exit 0.
        _diagnostic(lambda: f"sandbox_run: INFRASTRUCTURE - the result lines could not be written "
                            f"to stdout; manifest {ascii(str(state.run_dir))}/manifest.json\n")
        return EXIT_INFRA
    return EXIT_OK


def parse_args(argv):
    ap = argparse.ArgumentParser(description="run repository code in a hardened container (plan B1)")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--scratch", required=True, help="the session scratch dir; run dirs go below it")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--tree", help="the pinned git tree id")
    src.add_argument("--pin", nargs="+", metavar="PATH",
                     help="build a tree from HEAD plus these paths, without repository filters")
    ap.add_argument("--image", required=True, help="an image name from the plugin's sandbox policy")
    ap.add_argument("--export", action="append", default=[], help="file name under /out to return")
    ap.add_argument("--deps", action="append", default=[], metavar="PATH",
                    help="a fully hashed requirements file of the pinned tree (at most 4; plan B1.5)")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("argv", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    if a.argv and a.argv[0] == "--":
        a.argv = a.argv[1:]
    return a


def main(argv=None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_REFUSED if exc.code else EXIT_OK
    state = _Run()
    try:
        return run(args, state)
    except (Refused, sandbox_snapshot.SnapshotRefused, hunt_io.HuntIOError) as exc:
        kind = {Refused: "", sandbox_snapshot.SnapshotRefused: " (snapshot)",
                hunt_io.HuntIOError: " (run dir)"}.get(type(exc), "")
        _diagnostic(lambda e=exc: f"sandbox_run: REFUSED{kind} - {_ascii(e)}\n")
        _report_failure(state, "refused", exc)
        return EXIT_REFUSED
    except Infrastructure as exc:
        _diagnostic(lambda e=exc: f"sandbox_run: INFRASTRUCTURE - {_ascii(e)}\n")
        _report_failure(state, "infrastructure", exc)
        return EXIT_INFRA


def _report_failure(state: _Run, status: str, exc: Exception) -> None:
    """A failed run still leaves a manifest with what is known (inspection A, finding 10) --
    a static refusal too, as long as the scratch directory exists; the runner never creates
    the scratch directory itself. The stdout lines are best effort here: the outcome is
    already a failure (2 or 5) and keeps its exit code when they are lost."""
    if state.run_dir is None and state.scratch is not None and state.scratch.is_dir():
        try:
            state.open_run_dir()
        except hunt_io.HuntIOError:
            pass
    digest = state.write(status, str(exc))
    if digest:
        lines = [f"RUN_DIR={state.run_dir}"]
        if state.requirements_sha256():
            lines.append(f"REQUIREMENTS_SHA256={state.requirements_sha256()}")
        lines.append(f"MANIFEST_SHA256={digest}")
        if not _emit(lines):
            _diagnostic(lambda: "sandbox_run: the result lines could not be written to stdout\n")


if __name__ == "__main__":
    sys.exit(entry())
