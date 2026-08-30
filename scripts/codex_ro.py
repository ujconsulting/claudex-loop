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

WHAT AN ACCEPTED CALL STILL CANNOT DO (audit 2026-08-30, two CRITICALs)
    - widen its own write confinement. `--allow-path` and CLAUDEX_ALLOWED_PATHS
      arrive on the same unattended approval as the call, and --out-file is
      unlinked while --err-file is truncated. They now widen READS only; write
      targets stay in the repo and the OS temp dir, always.
    - point a write target at a symlink, a directory or a device -- checked before
      the unlink, and opened O_NOFOLLOW so the gap cannot be raced.
    - define or re-enable an MCP server. Codex runs those as separate processes
      OUTSIDE the sandbox, so `-c mcp_servers.*` is refused like the sandbox keys,
      and so is `-c profile=` (a profile carries its own sandbox_mode).

Exit codes:
    0    Codex ran and produced a non-empty answer
    1    Codex exited 0 but the answer file is empty -- the classic expired-token
         case: exit 0, a valid thread_id, and the 401 only in stderr
    2    refused: bad arguments, a path outside the allowed roots, a write target
         that is not a plain file, a file that cannot be read or opened, or a
         config override that would touch the sandbox
    124  timeout -- treat as a failure, do not blindly retry
    127  codex executable not found
    else Codex's own exit code

No filesystem failure escapes as a traceback: every path this wrapper opens,
reads, deletes or creates reports through the codes above instead.
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

WRAPPER_VERSION = "2.2.0"

DEFAULT_MODEL = "gpt-5.6-terra"
EFFORT_CHOICES = ("low", "medium", "high", "xhigh", "max")

# MCP servers bring nothing to a plan review, cost startup time, and -- the part
# that matters -- Codex runs them as separate processes OUTSIDE the shell sandbox.
# So the default is: disable every server this installation actually has, read from
# its config. Set CLAUDEX_DISABLE_MCP (comma-separated) or --disable-mcp to name a
# subset instead. An EMPTY value is refused with exit 2 whenever servers are
# configured -- it would leave them all enabled, which is a caller weakening this
# wrapper from its own command line, exactly like --allow-path widening writes or
# a `-c mcp_servers.*` override. (This comment claimed the opposite until
# CodeRabbit read it against the code, 2026-08-30.)
#
# ⛔ Naming a server that is NOT configured is the opposite of harmless, whatever
# this comment used to claim: `-c mcp_servers.X.enabled=false` SYNTHESISES a server
# table with no `transport`, and Codex then refuses to load its config at all --
# exit 1, empty answer file, and an error naming the user's config rather than us.
# The old default `("n8n", "MCP_DOCKER")` cost this repo's own audit its first four
# sessions (2026-08-30). Hence installed_mcp_servers(): never name one that is not
# there. Note: `-c mcp_servers="{}"` does not work either -- only the dotted path
# per server takes effect.

# The whole point of the wrapper. Refused as `-c` overrides, including any dotted
# child key such as `sandbox_workspace_write.network_access`.
FORBIDDEN_CONFIG_KEYS = (
    "sandbox_mode",
    "approval_policy",
    "sandbox_permissions",
    "sandbox_workspace_write",
    # A profile carries its own sandbox_mode and approval_policy, so allowing it
    # would let the forbidden keys in through the side door rather than the front.
    "profile",
    # The wrapper owns MCP, not the caller: `-c mcp_servers.x.command=...` defines
    # a server that runs outside the sandbox this wrapper exists to pin.
    "mcp_servers",
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


SCRATCH_DIR_ENV = "CLAUDEX_SCRATCH_DIR"


def _is_private_dir(path: Path) -> bool:
    """True when this directory is not writable by other local users.

    On Windows the POSIX mode bits are meaningless -- `os.stat` reports 0o777 for
    everything -- but the per-user temp dir (`%LOCALAPPDATA%\\Temp`) is genuinely
    private, so the answer there is yes without asking. On POSIX the question is
    real, and `/tmp` (mode 1777) is exactly the case this exists to exclude.
    """
    if os.name == "nt":
        return True
    import stat

    # Every ancestor, not just the directory itself: a private leaf under a
    # world-writable parent can be replaced wholesale, which is the same race
    # one level up. Walk upward to the filesystem root.
    for candidate in (path, *path.parents):
        try:
            if os.stat(candidate).st_mode & stat.S_IWOTH:
                return False
        except OSError:
            return False
    return True


def allowed_roots(extra: list[str], for_write: bool = False) -> list[Path]:
    """Roots a path argument may point into: the repo, the OS temp dir, opt-ins.

    The repo, because that is the work. The temp dir, because prompt and verdict
    files are routinely staged there.

    ⛔ `for_write=True` drops the opt-ins, and that asymmetry is the whole fix from
    the audit of 2026-08-30 (CRITICAL). `--allow-path` is an ordinary flag, so it
    matches the same allowlist prefix as the call itself and arrives unattended --
    while --out-file gets unlinked and --err-file truncated inside whatever root it
    named. `--allow-path / --out-file <anything>` was therefore an arbitrary delete
    approved as a "read-only review". A caller may not widen its own confinement
    for writes. Reads keep the opt-in: pointing the wrapper at a prompt file
    somewhere else grants nothing the caller could not do with `cat`.
    """
    cwd = Path.cwd().resolve()
    repo = (_repo_root(cwd) or cwd).resolve()
    roots = [repo, Path(tempfile.gettempdir()).resolve()]
    if for_write:
        # Write targets get a narrower list than reads, because this wrapper
        # DELETES --out-file and truncates --err-file. A world-writable parent is
        # then a real exposure: any local user can swap the directory for a
        # symlink between resolve() and open(), and O_NOFOLLOW only protects the
        # final component. CodeRabbit called for openat-style directory handles;
        # those do not exist on Windows, which is this plugin's main platform, so
        # the exposure is removed instead of raced -- a target whose parent
        # nobody else can write to has no race to lose. (2026-08-30.)
        candidates = [repo, (repo / ".claudex-tmp"), Path(tempfile.gettempdir()).resolve()]
        named = os.environ.get(SCRATCH_DIR_ENV, "").strip()
        if named:
            candidates.append(Path(named).expanduser().resolve())
        # EVERY candidate is screened, not just the temp dir. A repo checked out
        # under /tmp, or a CLAUDEX_SCRATCH_DIR pointed at a shared directory, is
        # the same exposure as /tmp itself -- and the first version of this only
        # asked the question of the temp dir. (CodeRabbit, 2026-08-30.)
        private = [d for d in candidates if _is_private_dir(d)]
        if not private:
            # Fail closed, but say WHY. An empty allowed list rendered as a
            # refusal listing nothing, which reads like a bug in the wrapper
            # rather than a property of the machine. (CodeRabbit, 2026-08-30.)
            rejected = "\n    ".join(str(d) for d in candidates)
            die(
                "no usable write root: every candidate is writable by other local "
                "users, so a target there could be swapped for a symlink between "
                "the check and the open.\n"
                f"  rejected:\n    {rejected}\n"
                f"  Set {SCRATCH_DIR_ENV} to a directory only you can write to "
                f"(and whose parents likewise), or move the repo off a shared path.",
                EXIT_REFUSED,
            )
        return private
    opt_ins = list(extra) + os.environ.get("CLAUDEX_ALLOWED_PATHS", "").split(os.pathsep)
    for raw in opt_ins:
        if raw and raw.strip():
            roots.append(Path(raw.strip()).expanduser().resolve())
    return roots


def prepare_write_target(path: Path, label: str) -> None:
    """Refuse a write target that is anything but a plain file, present or absent.

    The wrapper deletes --out-file and truncates --err-file. A symlink there aims
    that at someone else's file; a directory or device aims it at something worse.
    Checked before the unlink, and the open below is O_NOFOLLOW so the gap between
    the two cannot be raced (audit 2026-08-30).
    """
    if path.is_symlink():
        die(
            f"{label} is a symlink: {path}\n"
            f"  Refusing: this file gets deleted and rewritten, and a symlink points "
            f"that at something else. Name the real path.",
            EXIT_REFUSED,
        )
    if path.exists() and not path.is_file():
        die(f"{label} exists and is not a regular file: {path}", EXIT_REFUSED)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        die(f"{label}: cannot create the directory for {path}: {exc}", EXIT_REFUSED)


def open_for_write(path: Path, label: str):
    """Open a write target without following a link into it.

    O_NOFOLLOW closes the window between prepare_write_target() and here. Windows
    has no such flag; there, creating a symlink needs a privilege most accounts do
    not have, so the earlier check carries that platform on its own.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        return os.fdopen(os.open(path, flags, 0o600), "wb")
    except OSError as exc:
        die(f"{label}: cannot open {path} for writing: {exc}", EXIT_REFUSED)
        raise AssertionError("unreachable")


def _codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex")).expanduser()


MCP_SECTION_RE = re.compile(r"^\s*\[mcp_servers\.(?:\"([^\"]+)\"|'([^']+)'|([^\].]+))\]", re.M)


def installed_mcp_servers() -> set[str]:
    """The MCP servers this installation actually configures.

    Only these may be named in a `-c mcp_servers.<name>.enabled=false` override:
    naming an absent one makes Codex reject its whole config (see the note at the
    top of this file). Parsed with tomllib from Python 3.11, and with a section
    regex on 3.10 (the declared floor, where tomllib does not exist yet), which
    handles every `[mcp_servers.<name>]` spelling the CLI writes. An unreadable or
    absent config yields the empty set -- there is then nothing to disable, and
    nothing to break.
    """
    config = _codex_home() / "config.toml"
    try:
        raw = config.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        # UnicodeError too: a config saved as cp1252 with an umlaut in a path is
        # not exotic on Windows, and a decode error here would be a traceback in
        # a function whose documented answer is "then there is nothing to
        # disable". (CodeRabbit, 2026-08-30.)
        return set()

    try:
        import tomllib
    except ImportError:
        tomllib = None
    if tomllib is not None:
        try:
            return set(tomllib.loads(raw).get("mcp_servers") or {})
        except Exception:  # a config we cannot parse: fall through to the regex
            pass
    return {next(g for g in match.groups() if g) for match in MCP_SECTION_RE.finditer(raw)}


def _within(child: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath([_case_key(str(child)), _case_key(str(root))])
    except ValueError:
        # Different drives on Windows -- commonpath refuses, and rightly so.
        return False
    return common == _case_key(str(root))


def resolve_in_roots(raw: str, roots: list[Path], label: str, widenable: bool = True) -> Path:
    """Normalise a path argument and refuse it if it escapes the allowed roots.

    realpath() first, so a symlink or a `..` cannot smuggle the target out of a
    root that the literal string appears to stay inside.

    `widenable=False` for write targets: --allow-path does not reach them, so
    suggesting it would send the reader after a fix that cannot work.
    """
    path = Path(os.path.realpath(Path(raw).expanduser()))
    if not any(_within(path, root) for root in roots):
        listed = "\n    ".join(str(r) for r in roots)
        advice = (
            "  Add a root with --allow-path or CLAUDEX_ALLOWED_PATHS if that is intended."
            if widenable
            else "  Write targets cannot be widened -- that is deliberate. Choose a path\n"
            "  inside the repo or the OS temp dir."
        )
        die(
            f"{label} points outside the allowed roots: {path}\n"
            f"  allowed:\n    {listed}\n{advice}",
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
    # Only servers this installation has: an override for an absent one makes Codex
    # reject its entire config. Whatever the caller asked for, this is the filter.
    installed = installed_mcp_servers()
    for server in args.disable_mcp:
        if server in installed:
            argv += ["-c", f"mcp_servers.{server}.enabled=false"]
        else:
            warn(f"MCP server '{server}' is not configured here -- not naming it.")
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
        # Default: every server this installation has. build_argv() filters again,
        # so an explicit list can never name one that is not there either.
        args.disable_mcp = sorted(installed_mcp_servers())
    else:
        args.disable_mcp = [name.strip() for name in raw_mcp.split(",") if name.strip()]
        if not args.disable_mcp and installed_mcp_servers():
            # Refused, not warned about. The audit fixed the two other ways a
            # caller could weaken this wrapper from its own command line
            # (--allow-path widening writes, -c mcp_servers.*), and an empty
            # --disable-mcp is the third door to the same room: Codex runs MCP
            # servers as separate processes OUTSIDE the sandbox. A warning on
            # stderr is not a control -- nobody reads stderr on a call that
            # succeeded. (CodeRabbit, 2026-08-30.)
            die(
                "an empty --disable-mcp / CLAUDEX_DISABLE_MCP would leave this "
                "installation's MCP servers enabled, and Codex runs those outside "
                "the read-only sandbox this wrapper exists to pin.\n"
                f"  configured here: {', '.join(sorted(installed_mcp_servers()))}\n"
                "  Name the ones you want off, or drop the flag to disable all of "
                "them. Whoever genuinely needs them on calls codex directly -- and "
                "answers the permission prompt.",
                EXIT_REFUSED,
            )
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
    #    Two root sets on purpose: --allow-path widens reads, never writes. See
    #    allowed_roots(); the caller may not widen its own confinement for the
    #    files this wrapper deletes and truncates.
    read_roots = allowed_roots(args.allow_path)
    write_roots = allowed_roots([], for_write=True)
    if args.allow_path or os.environ.get("CLAUDEX_ALLOWED_PATHS", "").strip():
        warn("--allow-path / CLAUDEX_ALLOWED_PATHS widen --prompt-file only, not the write targets.")
    out_file = resolve_in_roots(args.out_file, write_roots, "--out-file", widenable=False)
    err_file = (
        resolve_in_roots(args.err_file, write_roots, "--err-file", widenable=False)
        if args.err_file
        else out_file.with_suffix(out_file.suffix + ".stderr.txt")
    )

    # 3. The prompt. Read as UTF-8 explicitly: relying on the platform default means
    #    cp1252 on Windows, which mangles every non-ASCII prompt.
    prompt = args.prompt
    if args.prompt_file:
        prompt_file = resolve_in_roots(args.prompt_file, read_roots, "--prompt-file")
        if not prompt_file.is_file():
            die(f"--prompt-file not found: {prompt_file}", EXIT_REFUSED)
        try:
            prompt = prompt_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            # The docstring publishes an exit-code contract; a traceback is not in it.
            die(f"--prompt-file cannot be read as UTF-8: {prompt_file}: {exc}", EXIT_REFUSED)
    if not prompt or not prompt.strip():
        die("neither --prompt nor --prompt-file provided (or the prompt is empty).", EXIT_REFUSED)

    executable = find_codex()
    argv_child = build_argv(args, out_file)
    stream_file = Path(str(out_file) + ".stream.json")

    # Three separate files, and they must stay separate: pointing --err-file at
    # --out-file makes each truncate the other, and the answer file would end up
    # holding stderr or nothing at all -- read as "the model said nothing", which
    # is the auth signature. (CodeRabbit, 2026-08-30.)
    targets = {"--out-file": out_file, "--err-file": err_file, "the event stream": stream_file}
    for label, path in targets.items():
        clashes = [other for other, p in targets.items() if other != label and p == path]
        if clashes:
            die(f"{label} and {clashes[0]} are the same file: {path}", EXIT_REFUSED)
    for label, path in targets.items():
        prepare_write_target(path, label)
    if out_file.exists():
        try:
            out_file.unlink()
        except OSError as exc:
            die(f"--out-file cannot be replaced: {out_file}: {exc}", EXIT_REFUSED)

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
    with open_for_write(stream_file, "the event stream") as stream_handle, open_for_write(
        err_file, "--err-file"
    ) as err_handle:
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
