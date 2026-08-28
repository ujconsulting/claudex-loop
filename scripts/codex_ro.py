#!/usr/bin/env python3
"""Run Codex read-only, with the sandbox nailed shut.

A thin wrapper around `codex exec` / `codex exec resume` that guarantees exactly
one thing: Codex runs read-only. That guarantee is what makes it safe to put this
call on a permission allowlist instead of answering a prompt every review round.

WHY THE WRAPPER EXISTS (measured 2026-08-27, codex-cli 0.149.1; every row is a
write attempt into an empty git directory, with a positive control -- without one
a "did not write" result would be worthless, since it could also mean the probe
never writes):

    exec -s read-only                                             -> no write
    exec -s read-only -c sandbox_mode="danger-full-access"         -> no write   (-s wins)
    exec -s danger-full-access                                     -> WRITES     (positive control)
    resume -c sandbox_mode="read-only" -c ..."danger-full-access"  -> WRITES     (last -c wins)

So for `exec` with an explicit `-s read-only`, the mode cannot be prised open. For
`resume` it can: there is no `-s` there, and a later `-c` beats an earlier one. A
permission rule only matches the START of a command and cannot catch that. This
wrapper can, because it inspects the arguments itself.

This file is the CANONICAL implementation. Repos receive a copy at
`tools/codex_ro.py`; `scripts/wrapper_drift.py` reports copies that fell behind.

It replaces the earlier PowerShell version (`codex_ro.ps1`) for two reasons: it
runs on macOS as well as Windows, and it builds the child's argv as a LIST.
PowerShell's `Start-Process -ArgumentList` does not quote, which is what made
argument injection through `-Model` and `-c` possible there (audit 2026-08-28,
two CRITICAL findings). With a list there is no command line to inject into.

Exit codes:
    0    Codex ran and produced a non-empty answer
    1    Codex exited 0 but the answer file is empty -- the classic expired-token
         case: exit 0, a valid thread_id, and the 401 only in stderr
    2    refused: bad arguments, a path outside the allowed roots, or a config
         override that would touch the sandbox
    124  timeout -- treat as a failure, do not blindly retry
    127  codex executable not found
    else Codex's own exit code
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

WRAPPER_VERSION = "2.1.0"

DEFAULT_MODEL = "gpt-5.6-terra"
EFFORT_CHOICES = ("low", "medium", "high", "xhigh", "max")

# MCP servers bring nothing to a plan review and cost startup time. These are
# THIS INSTALLATION's servers; set CLAUDEX_DISABLE_MCP (comma-separated, empty
# string to disable nothing) to override. Naming a server that does not exist is
# harmless. Note: `-c mcp_servers="{}"` does NOT work -- only the dotted path per
# server takes effect.
DEFAULT_DISABLE_MCP = ("n8n", "MCP_DOCKER")

# The whole point of the wrapper. Refused as `-c` overrides, including any dotted
# child key such as `sandbox_workspace_write.network_access`.
FORBIDDEN_CONFIG_KEYS = (
    "sandbox_mode",
    "approval_policy",
    "sandbox_permissions",
    "sandbox_workspace_write",
)

MODEL_RE = re.compile(r"^[A-Za-z0-9._-]+$")
RESUME_RE = re.compile(r"^[0-9a-fA-F-]{8,}$")
THREAD_RE = re.compile(r'"thread_id"\s*:\s*"([^"]+)"')

EXIT_EMPTY = 1
EXIT_REFUSED = 2
EXIT_TIMEOUT = 124
EXIT_NO_CODEX = 127


def die(message: str, code: int) -> None:
    """Stop with a defined exit code and a reason on stderr."""
    print(f"codex_ro: {message}", file=sys.stderr)
    raise SystemExit(code)


def warn(message: str) -> None:
    print(f"codex_ro: {message}", file=sys.stderr)


# --- path handling --------------------------------------------------------------
# The wrapper is meant to be allowlisted, which means its arguments arrive
# unattended. --out-file is deleted before the run and --err-file is truncated, so
# an unconstrained path argument is a write primitive pointed anywhere on disk.
# Hence: every file this wrapper touches must sit inside an allowed root.
# Audit finding 2026-08-28 (path whitelist for the prompt and output files).


def _case_key(path: str) -> str:
    return path.casefold() if os.name == "nt" else path


def _repo_root(start: Path) -> Path | None:
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def allowed_roots(extra: list[str]) -> list[Path]:
    """Roots a path argument may point into: the repo, the OS temp dir, opt-ins.

    The repo, because that is the work. The temp dir, because prompt and verdict
    files are routinely staged there. Everything else has to be named explicitly
    via --allow-path or CLAUDEX_ALLOWED_PATHS, which is the point: an unattended
    call cannot reach outside unless someone said so.
    """
    cwd = Path.cwd().resolve()
    roots = [(_repo_root(cwd) or cwd).resolve(), Path(tempfile.gettempdir()).resolve()]
    opt_ins = list(extra) + os.environ.get("CLAUDEX_ALLOWED_PATHS", "").split(os.pathsep)
    for raw in opt_ins:
        if raw and raw.strip():
            roots.append(Path(raw.strip()).expanduser().resolve())
    return roots


def _within(child: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath([_case_key(str(child)), _case_key(str(root))])
    except ValueError:
        # Different drives on Windows -- commonpath refuses, and rightly so.
        return False
    return common == _case_key(str(root))


def resolve_in_roots(raw: str, roots: list[Path], label: str) -> Path:
    """Normalise a path argument and refuse it if it escapes the allowed roots.

    realpath() first, so a symlink or a `..` cannot smuggle the target out of a
    root that the literal string appears to stay inside.
    """
    path = Path(os.path.realpath(Path(raw).expanduser()))
    if not any(_within(path, root) for root in roots):
        listed = "\n    ".join(str(r) for r in roots)
        die(
            f"{label} points outside the allowed roots: {path}\n"
            f"  allowed:\n    {listed}\n"
            f"  Add a root with --allow-path or CLAUDEX_ALLOWED_PATHS if that is intended.",
            EXIT_REFUSED,
        )
    return path


# --- argument construction ------------------------------------------------------


def check_config_overrides(overrides: list[str]) -> None:
    for override in overrides:
        key = override.split("=", 1)[0].strip()
        for forbidden in FORBIDDEN_CONFIG_KEYS:
            if key == forbidden or key.startswith(forbidden + "."):
                die(
                    f"'-c {key}' is not allowed here. This wrapper exists to nail the "
                    f"sandbox down; whoever wants to change it calls codex directly -- "
                    f"and answers the permission prompt.",
                    EXIT_REFUSED,
                )


def build_argv(args: argparse.Namespace, out_file: Path) -> list[str]:
    argv = ["exec"]
    if args.resume:
        # resume knows no -s. Read-only is reachable only via -c there, and since a
        # later -c wins it has to be the ONLY sandbox_mode argument -- which is what
        # check_config_overrides() guarantees.
        argv += ["resume", args.resume, "-c", "sandbox_mode=read-only"]
    else:
        # exec: -s beats any trailing -c sandbox_mode (measured, see module docstring).
        argv += ["-s", "read-only"]
    argv += ["-m", args.model, "-c", f"model_reasoning_effort={args.effort}"]
    for server in args.disable_mcp:
        argv += ["-c", f"mcp_servers.{server}.enabled=false"]
    for override in args.config:
        argv += ["-c", override]
    argv += ["--json", "-o", str(out_file)]
    # No prompt argument: `codex exec` reads the instructions from stdin when none
    # is given. That is also what supplies EOF -- without it, codex exec hangs
    # forever at ~0% CPU under a non-interactive driver waiting on stdin.
    return argv


# On macOS the working CLI ships inside the ChatGPT desktop app. A leftover
# npm-global install can shadow it on PATH, and older builds of that one are
# killed by the OS on launch (upstream issue #10) -- see diagnose_silent_death().
MACOS_BUNDLED_CODEX = (
    "/Applications/ChatGPT.app/Contents/Resources/codex",
    "~/Applications/ChatGPT.app/Contents/Resources/codex",
)


def bundled_codex() -> str | None:
    """The Codex that ships inside ChatGPT.app, if this is a Mac and it is there."""
    if sys.platform != "darwin":
        return None
    for candidate in MACOS_BUNDLED_CODEX:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def find_codex() -> str:
    # CLAUDEX_CODEX_BIN wins, so a user whose PATH is wrong has one thing to set
    # rather than a PATH to untangle.
    override = os.environ.get("CLAUDEX_CODEX_BIN")
    if override:
        if not Path(override).expanduser().is_file():
            die(f"CLAUDEX_CODEX_BIN points at no file: {override}", EXIT_NO_CODEX)
        return str(Path(override).expanduser())

    # On Windows, `codex` on PATH is an EXTENSIONLESS shell shim from the npm
    # install; CreateProcess cannot run it ("not a valid Win32 application").
    # The .cmd wrapper is the one that works.
    names = ("codex.cmd", "codex.exe") if os.name == "nt" else ("codex",)
    for name in names:
        found = shutil.which(name)
        if found:
            return found

    # PATH first, so a deliberate install still wins; the bundle is the fallback.
    bundled = bundled_codex()
    if bundled:
        return bundled

    die(f"codex not found on PATH (tried: {', '.join(names)}).", EXIT_NO_CODEX)
    raise AssertionError("unreachable")


def diagnose_silent_death(executable: str, returncode: int) -> str:
    """Explain a child that failed without saying anything -- the worst failure to read.

    Upstream issue #10: on macOS a stale npm-global `codex` shadows the one inside
    ChatGPT.app and is SIGKILLed on launch. Every call then yields empty stdout,
    empty stderr and exit 137, which reads exactly like a hang, an auth failure or
    a bad prompt -- and is none of them. Naming the signature is the whole fix;
    without it the next person spends the same minutes we did.
    """
    lines = [
        f"codex exited {returncode} without writing anything -- no answer, no stderr.",
        f"  binary: {executable}",
    ]
    if returncode in (137, -9):
        lines.append(
            "  Exit 137 is SIGKILL: the process was killed on launch, it did not run. "
            "This is NOT an auth problem, NOT a hang and NOT a bad prompt -- do not retry it."
        )
        bundled = bundled_codex()
        if bundled and os.path.realpath(bundled) != os.path.realpath(executable):
            lines += [
                "  On macOS the current CLI ships inside the ChatGPT app. A stale npm-global",
                "  install shadows it on PATH and is killed by the OS. Found the bundled one at:",
                f"    {bundled}",
                f"  Fix: ln -sfn \"{bundled}\" ~/.local/bin/codex   (a PATH dir ahead of the stale one)",
                "  then: sudo npm uninstall -g @openai/codex",
                f"  Or point this wrapper straight at it: export CLAUDEX_CODEX_BIN=\"{bundled}\"",
                "  Do NOT delete ~/.codex/ -- config.toml, auth.json and the sessions live there",
                "  and the bundled binary still uses them.",
            ]
        elif sys.platform == "darwin":
            lines.append(
                "  On macOS the current CLI ships inside ChatGPT.app "
                "(/Applications/ChatGPT.app/Contents/Resources/codex). Check whether a stale "
                "npm-global install is shadowing it on PATH."
            )
    return "\n".join(lines)


# --- process control ------------------------------------------------------------


def kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child AND its descendants, and say so when that does not work.

    Never swallow the failure: a timeout that leaves a live codex process behind is
    a different problem from a timeout that cleaned up, and the caller can only tell
    them apart if we say which happened. (Audit finding 2026-08-28: the PowerShell
    version had a bare `catch { }` here.)
    """
    if os.name == "nt":
        result = subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        detail = (result.stderr or result.stdout or "").strip()
        warn(f"taskkill failed (rc={result.returncode}): {detail}")
    else:
        import signal

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            return
        except OSError as exc:
            warn(f"killpg failed: {exc}")
    try:
        proc.kill()
    except OSError as exc:
        warn(f"fallback kill failed, a codex process may still be running: {exc}")


def read_thread_id(stream_file: Path) -> str | None:
    if not stream_file.exists():
        return None
    try:
        text = stream_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        warn(f"could not read the event stream ({exc}); no thread id reported.")
        return None
    for line in text.splitlines():
        if '"type":"thread.started"' in line.replace(" ", ""):
            match = THREAD_RE.search(line)
            if match:
                return match.group(1)
    match = THREAD_RE.search(text)
    return match.group(1) if match else None


# --- entry point ----------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="codex_ro.py",
        description="Run codex exec read-only; refuse anything that would open the sandbox.",
    )
    parser.add_argument("--resume", metavar="THREAD_ID", help="continue an existing Codex session")
    parser.add_argument("--prompt", help="the prompt; prefer --prompt-file for longer texts")
    parser.add_argument("--prompt-file", help="file whose content is the prompt; wins over --prompt")
    parser.add_argument("--out-file", required=True, help="target file for Codex's last message (-o)")
    parser.add_argument(
        "--err-file",
        help="target file for stderr; default is next to --out-file. NEVER route this to "
        "/dev/null: an expired token yields exit 0, a valid thread_id and an EMPTY "
        "answer file, and the 401 lives only in stderr.",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"default {DEFAULT_MODEL}")
    parser.add_argument("--effort", default="high", choices=EFFORT_CHOICES)
    parser.add_argument("--timeout", type=int, default=600, metavar="SECONDS")
    parser.add_argument(
        "-c",
        "--config",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="extra codex -c override; sandbox/approval keys are refused with exit 2",
    )
    parser.add_argument(
        "--allow-path",
        action="append",
        default=[],
        metavar="DIR",
        help="additional root that path arguments may point into",
    )
    parser.add_argument(
        "--disable-mcp",
        metavar="NAMES",
        help="comma-separated MCP servers to switch off; default from CLAUDEX_DISABLE_MCP",
    )
    parser.add_argument("--version", action="version", version=f"codex_ro.py {WRAPPER_VERSION}")
    args = parser.parse_args(argv)

    raw_mcp = args.disable_mcp
    if raw_mcp is None:
        raw_mcp = os.environ.get("CLAUDEX_DISABLE_MCP")
    if raw_mcp is None:
        args.disable_mcp = list(DEFAULT_DISABLE_MCP)
    else:
        args.disable_mcp = [name.strip() for name in raw_mcp.split(",") if name.strip()]
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # 1. Refuse anything that would touch the sandbox or the approval policy.
    check_config_overrides(args.config)
    if not MODEL_RE.match(args.model):
        die(
            f"--model may only contain letters, digits, dot, underscore and dash: {args.model!r}",
            EXIT_REFUSED,
        )
    if args.resume and not RESUME_RE.match(args.resume):
        die(f"--resume does not look like a thread id: {args.resume}", EXIT_REFUSED)
    if args.timeout <= 0:
        die(f"--timeout must be positive: {args.timeout}", EXIT_REFUSED)

    # 2. Paths -- resolved and confined before anything is created or deleted.
    roots = allowed_roots(args.allow_path)
    out_file = resolve_in_roots(args.out_file, roots, "--out-file")
    err_file = (
        resolve_in_roots(args.err_file, roots, "--err-file")
        if args.err_file
        else out_file.with_suffix(out_file.suffix + ".stderr.txt")
    )

    # 3. The prompt. Read as UTF-8 explicitly: relying on the platform default means
    #    cp1252 on Windows, which mangles every non-ASCII prompt.
    prompt = args.prompt
    if args.prompt_file:
        prompt_file = resolve_in_roots(args.prompt_file, roots, "--prompt-file")
        if not prompt_file.is_file():
            die(f"--prompt-file not found: {prompt_file}", EXIT_REFUSED)
        prompt = prompt_file.read_text(encoding="utf-8")
    if not prompt or not prompt.strip():
        die("neither --prompt nor --prompt-file provided (or the prompt is empty).", EXIT_REFUSED)

    executable = find_codex()
    argv_child = build_argv(args, out_file)
    stream_file = Path(str(out_file) + ".stream.json")

    for path in (out_file, err_file, stream_file):
        path.parent.mkdir(parents=True, exist_ok=True)
    if out_file.exists():
        out_file.unlink()

    mode = f"resume {args.resume}" if args.resume else "exec (new)"
    print(
        f"# codex read-only | {mode} | {args.model}/{args.effort} "
        f"| timeout {args.timeout}s | wrapper {WRAPPER_VERSION}"
    )

    # 4. Run. stdout (the --json event stream) and stderr go straight to files, so
    #    only stdin is a pipe -- no risk of a full-pipe deadlock, and communicate()
    #    closes stdin, which is the EOF codex exec waits for. No temp file is
    #    involved at all, which is how the leaked-tempfile finding stops being
    #    possible rather than being cleaned up after (audit 2026-08-28).
    platform_kwargs = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    with open(stream_file, "wb") as stream_handle, open(err_file, "wb") as err_handle:
        proc = subprocess.Popen(
            [executable, *argv_child],
            stdin=subprocess.PIPE,
            stdout=stream_handle,
            stderr=err_handle,
            **platform_kwargs,
        )
        try:
            proc.communicate(prompt.encode("utf-8"), timeout=args.timeout)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            try:
                proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                warn("the child did not exit even after the kill.")
            die(
                f"timeout after {args.timeout}s -- treat as a failure, do not blindly "
                f"retry. stderr: {err_file}",
                EXIT_TIMEOUT,
            )

    # 5. Report.
    thread_id = read_thread_id(stream_file)
    if thread_id:
        print(f"THREAD_ID={thread_id}")

    if not out_file.exists() or out_file.stat().st_size == 0:
        stderr_bytes = err_file.stat().st_size if err_file.exists() else 0
        if proc.returncode != 0:
            # Never report a non-zero exit as the auth case. Until 2026-08-28 this
            # branch did exactly that, which turns a dead binary (exit 137, upstream
            # issue #10) into a hunt for a 401 that was never there.
            if stderr_bytes == 0:
                warn(diagnose_silent_death(executable, proc.returncode))
            else:
                warn(
                    f"codex exited {proc.returncode} with an empty answer file. "
                    f"The reason is in stderr: {err_file}"
                )
            return proc.returncode
        warn(
            f"empty answer file on exit 0. This is the typical auth case -- a valid "
            f"thread_id, but the 401 is in stderr: {err_file}"
        )
        return EXIT_EMPTY
    print(f"OUT={out_file}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
