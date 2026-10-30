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
  run      `docker create` (id known before anything runs) with no network, read-only rootfs,
           tmpfs /work /out /tmp /home/run, only SETUID/SETGID/KILL for the uid-0 driver
           (scripts/sandbox_driver.py, passed as `python3 -I -S -c`), the command itself as uid
           65532 without capabilities; nonce + spec + snapshot tar over stdin (`start -ai`), one
           framed result tar back over stdout;
  accept   only a result whose nonce matches, whose members are exactly the expected ones within
           their caps, and whose container (= driver) ended with ExitCode 0 and not OOMKilled;
  clean    `docker rm -f` on every exit path, confirmed by `docker inspect`; a janitor removes only
           labelled containers more than 600 s past their deadline.

The runner's own exit code says whether the run HAPPENED: 0 ok (the command's outcome is in
COMMAND_STATUS= / COMMAND_EXIT= and the manifest), 2 refused, 5 infrastructure. A skill passes only
on COMMAND_STATUS=exited and COMMAND_EXIT=0. There is no host fallback of any kind.

    python scripts/sandbox_run.py --repo . --scratch <dir> --tree <sha> --image python-test \
        [--export NAME]... [--timeout S] -- <argv...>

Messages are ASCII only.
"""

from __future__ import annotations

import argparse
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
import sandbox_snapshot  # noqa: E402

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


def check_environment() -> None:
    """A DOCKER_HOST/DOCKER_CONTEXT in the environment would select another daemon, where the
    same image name can mean other bytes (round-1 finding 13)."""
    for var in ("DOCKER_HOST", "DOCKER_CONTEXT"):
        if os.environ.get(var):
            raise Refused(f"{var} is set; the runner uses only the context named in the plugin policy")


def docker(context: str, *args: str, timeout: float = DOCKER_TIMEOUT, data: bytes | None = None):
    """One bounded docker call. Raises Infrastructure on timeout or start failure."""
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
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
    line = re.compile(r"(?:Error(?: response from daemon)?: )?No such (?:%s|object): %s"
                      % (re.escape(kind), re.escape(ref)), re.IGNORECASE)
    return any(line.fullmatch(t.strip())
               for t in done.stderr.decode("utf-8", "replace").splitlines())


def janitor(context: str, now: float | None = None, run_id: str | None = None) -> list[str]:
    """Remove labelled containers more than JANITOR_GRACE seconds past their deadline -- never one
    within its deadline, whoever started it. Returns the ids it removed; raises Infrastructure for
    a survivor it could not remove.

    `now` and `run_id` only narrow it, for a test that checks ONE abandoned run "after expiry"
    without touching any other session's container; the runner calls it with neither."""
    selector = f"label={LABEL}" if run_id is None else f"label={LABEL}={run_id}"
    done = docker(context, "ps", "-a", "--filter", selector,
                  "--format", '{{.ID}} {{.Label "claudex.deadline"}}')
    if done.returncode != 0:
        raise Infrastructure("cannot list sandbox containers")
    removed, now = [], time.time() if now is None else now
    for line in done.stdout.decode("ascii", "replace").splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[1].isdigit():
            continue
        if int(parts[1]) + JANITOR_GRACE < now:
            _remove(context, parts[0])
            removed.append(parts[0])
    return removed


def _remove(context: str, ref: str) -> None:
    """Remove a container by id or name and PROVE it is gone: only docker's "No such container:
    <ref>" answer to the follow-up inspect counts. A disconnected daemon or a permission error is
    not a removal (post-build inspection A, finding 4)."""
    docker(context, "rm", "-f", ref)
    gone = docker(context, "inspect", "--type", "container", ref)
    if not _absent(gone, "container", ref):
        raise Infrastructure(f"container {ref[:24]} could not be confirmed removed")


# --- the result stream -------------------------------------------------------------------

RECORD = 10240  # tarfile's default record size; the driver writes with the defaults


def read_result(data: bytes, nonce: str, exports: list[str]) -> tuple[dict, dict[str, bytes]]:
    """Parse the driver's framed result tar member by member (stream mode) under the caps. Accepts
    exactly the expected names, each a regular member, and exactly the standard framing: after the
    last member the end-of-archive blocks and the zero padding to the record size, nothing more,
    not even more zeros (post-build inspection A, finding 7)."""
    if len(data) > RESULT_CAP:
        raise Infrastructure("result stream over the cap")
    caps = {"result.json": 1024 * 1024, "stdout.txt": CAPTURE_CAP, "stderr.txt": CAPTURE_CAP}
    caps.update({f"out/{n}": EXPORT_CAP for n in exports})
    got: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as tf:
            for member in tf:
                if member.name not in caps or member.name in got:
                    raise Infrastructure(f"unexpected result member {member.name!r}")
                if not member.isreg() or member.size > caps[member.name]:
                    raise Infrastructure(f"result member {member.name!r} is not a regular file within its cap")
                handle = tf.extractfile(member)
                got[member.name] = handle.read(member.size + 1) if handle else b""
                if len(got[member.name]) != member.size:
                    raise Infrastructure(f"result member {member.name!r} has the wrong size")
            end = tf.offset
    except tarfile.TarError as exc:
        raise Infrastructure(f"result stream is not a valid tar: {exc}") from exc
    framed = -(-(end + 1024) // RECORD) * RECORD
    if len(data) != framed or any(data[end:]):
        raise Infrastructure("the result archive is not framed exactly (trailing or missing bytes)")
    for need in ("result.json", "stdout.txt", "stderr.txt"):
        if need not in got:
            raise Infrastructure(f"result member {need} missing")
    try:
        result = json.loads(got["result.json"].decode("utf-8"))
    except ValueError as exc:
        raise Infrastructure("result.json is not JSON") from exc
    if not isinstance(result, dict) or result.get("nonce") != nonce:
        raise Infrastructure("result does not carry this run's nonce")
    if result.get("infrastructure"):
        raise Infrastructure(f"driver: {_ascii(result['infrastructure'])[:200]}")
    if result.get("command_status") not in ("exited", "timeout", "output_limit", "not_started"):
        raise Infrastructure("result has no valid command_status")
    return result, got


def stream_start(context: str, cid: str, stdin: bytes, timeout: float) -> tuple[bytes, bytes]:
    """`docker start -ai`: write stdin from a thread, read stdout under RESULT_CAP and stderr under
    its own small cap WHILE receiving; on byte RESULT_CAP + 1, or on the deadline, kill the
    container at once (post-build inspection A, finding 3)."""
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    try:
        proc = subprocess.Popen(["docker", "--context", context, "start", "-ai", cid], env=env,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise Infrastructure(f"docker not available: {exc}") from exc
    try:
        return _stream(context, cid, proc, stdin, timeout)
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


def _stream(context: str, cid: str, proc, stdin: bytes, timeout: float) -> tuple[bytes, bytes]:
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
                if len(out) > RESULT_CAP:
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

def create_args(run_id: str, deadline: int, image_id: str, driver_source: str) -> list[str]:
    """`docker create` arguments exactly as plan step 2 states them."""
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
        "--tmpfs", "/home/run:size=64m",
        "-e", "HOME=/home/run", "-w", "/", "-i", image_id, "python3", "-I", "-S", "-c", driver_source,
    ]


class _Run:
    """What is known about a run so far -- written as a manifest on EVERY outcome, failures
    included (post-build inspection A, finding 10)."""

    def __init__(self):
        self.run_id = secrets.token_hex(8)
        self.run_dir: Path | None = None
        self.scratch: Path | None = None
        self.fields: dict = {"run_id": self.run_id, "mode": "container", "cleanup": "not_needed"}

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
    entry = policy_entry(policy, args.image)
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

    nonce = secrets.token_hex(16)
    deadline = int(time.time()) + args.timeout + 300
    driver_source = DRIVER_FILE.read_bytes().decode("utf-8")
    spec = {"argv": list(args.argv), "exports": list(args.export), "capture_cap": CAPTURE_CAP,
            "export_cap": EXPORT_CAP, "timeout": args.timeout, "tar_len": len(tar_bytes)}
    stdin = (nonce + "\n").encode() + (json.dumps(spec, sort_keys=True) + "\n").encode() + tar_bytes

    name = f"claudex-run-{state.run_id}"
    state.fields["cleanup"] = "pending"
    try:
        # Creation is INSIDE the protected region: if docker creates the container but the client
        # times out or is interrupted, the finally still removes it by its predetermined name
        # (post-build inspection A, finding 5).
        created = docker(context, *create_args(state.run_id, deadline, entry["id"], driver_source))
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
            result, got = read_result(out, nonce, list(args.export))
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
    digest = state.write("ok")
    if digest is None:
        # No manifest, no result: the pass rule needs MANIFEST_SHA256, and printing `None` next to
        # COMMAND_EXIT=0 would be a pass without evidence (inspection round 2, part A, finding 14).
        raise Infrastructure("the run manifest could not be written")
    print(f"RUN_DIR={state.run_dir}")
    print(f"TREE={tree}")
    print(f"COMMAND_STATUS={state.fields['command_status']}")
    exit_shown = state.fields["command_exit"]
    print(f"COMMAND_EXIT={exit_shown if exit_shown is not None else '-'}")
    print(f"MANIFEST_SHA256={digest}")
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
        sys.stderr.write(f"sandbox_run: REFUSED{kind} - {_ascii(exc)}\n")
        _report_failure(state, "refused", exc)
        return EXIT_REFUSED
    except Infrastructure as exc:
        sys.stderr.write(f"sandbox_run: INFRASTRUCTURE - {_ascii(exc)}\n")
        _report_failure(state, "infrastructure", exc)
        return EXIT_INFRA


def _report_failure(state: _Run, status: str, exc: Exception) -> None:
    """A failed run still leaves a manifest with what is known (inspection A, finding 10) --
    a static refusal too, as long as the scratch directory exists; the runner never creates
    the scratch directory itself."""
    if state.run_dir is None and state.scratch is not None and state.scratch.is_dir():
        try:
            state.open_run_dir()
        except hunt_io.HuntIOError:
            pass
    digest = state.write(status, str(exc))
    if digest:
        print(f"RUN_DIR={state.run_dir}")
        print(f"MANIFEST_SHA256={digest}")


if __name__ == "__main__":
    sys.exit(main())
