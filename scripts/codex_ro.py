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
    - point a write target at a symlink, a directory, a device or a Windows
      junction (audit 2026-09-02: `Path.is_symlink()` alone missed junctions,
      which need no special privilege to create -- see `_is_reparse_point`),
      or at a name that already hard-links to other data (`_has_other_hardlinks`)
      -- all checked before the unlink/open, which is O_NOFOLLOW on POSIX so
      that gap cannot be raced there. Windows has no such flag; see the
      residual gap noted for `open_for_write` below.
    - define or re-enable an MCP server. Codex runs those as separate processes
      OUTSIDE the sandbox, so `-c mcp_servers.*` is refused like the sandbox keys,
      and so is `-c profile=` (a profile carries its own sandbox_mode).
    - name an arbitrary write directory via CLAUDEX_SCRATCH_DIR on Windows (audit
      2026-09-02, CRITICAL). Write targets there are limited to the repo, its
      `.claudex-tmp/`, and the OS temp dir -- fixed candidates the wrapper picks
      itself, never one supplied through the environment.
    - replace the Codex executable via CLAUDEX_CODEX_BIN (audit 2026-09-02,
      CRITICAL). That override is gone; only PATH lookup and the fixed macOS
      bundle path resolve which binary runs.

WHY --expect-workdir IS AN ASSERTION, NOT A SELECTOR (2026-09-18, docs/audit/2026-09-11-scope.md §5,
after Codex rejected an earlier `--workdir DIR` selector as CRITICAL in round 1
of that plan's review)
    The cwd this wrapper runs in is not merely "where relative paths resolve" --
    it decides which AGENTS.md Codex auto-loads into the prompt, unasked. That
    makes cwd an EGRESS parameter, not just a scope choice. And because this
    wrapper's own permission allowlist matches only a command PREFIX
    (`Bash(python tools/codex_ro.py*)`), a `--workdir DIR` selector that set
    `Popen(cwd=DIR)` would arrive completely unattended -- exactly the shape of
    mistake this wrapper exists to prevent (the 2026-09-11 incident: eight
    review rounds ran with cwd in a production docs repo instead of the
    intended throwaway one, and Codex silently ingested that repo's AGENTS.md).
    `--expect-workdir DIR` inverts that: it can only ever REFUSE, never
    redirect. A caller cannot reach anywhere with it that it could not already
    reach by starting the session there (measured: a `cd` only holds for the
    single tool call that issues it, and the one call that would `cd` AND
    invoke the wrapper is refused by hooks/wrapper_guard.py).

    Order of the check (pinned by tests, see T20): capture cwd once; refuse
    lexically with NO filesystem access (empty/whitespace, control characters,
    a UNC/device prefix after normalising backslashes to forward slashes,
    anything not `os.path.isabs`); a plain string comparison of the value AS
    TYPED, `normcase(DIR) == normcase(cwd)` give or take one trailing separator
    -- no abspath()/normpath(), which would accept `<cwd>/sub/..` or a trailing
    dot (closing gate, 2026-09-18) -- and no prefix match; the cwd's own alias-freedom,
    `normcase(realpath(cwd)) == normcase(cwd)`; and only then, as a belt,
    `os.path.samefile(cwd, DIR)`. There is no fallback of any kind:
    `os.path.realpath("")` and `os.path.realpath("missing/..")` both equal the
    current directory, which would have let an empty or malformed value
    silently confirm itself -- an earlier draft of this plan proposed exactly
    that fallback and it was measured and dropped (see check_expected_workdir).

    Costs accepted rather than chased:
      - an 8.3 short name for the expectation does not match the long cwd --
        realpath() is applied only to cwd itself, never to the expectation
      - a symlink, junction, `subst` drive or mapped-network-drive ALIAS of
        the cwd is refused, both as the expectation (caught by the plain
        string comparison -- an alias is a different string) and, where the
        platform's own getcwd()/chdir() leave it observable, as the cwd
        itself (caught by the alias-freedom check)
      - on macOS, a case-variant path to the same directory is refused --
        the string comparison is normcase()'d for Windows, not case-folded
        for every platform
      - a mapped network drive (`Z:\repo` on an SMB share) is not detected as
        a network path; it passes the lexical UNC check and reaches
        samefile(), the same accepted residual risk as allowed_roots() above

WHAT 2.6.0 CHANGED (2026-09-30, plan docs/plans/2026-09-23-codex-heben-wrapper-2.6.0)
    Currently measured against codex-cli 0.156.0 -- the one marked line the
    tests hold MEASURED_CODEX_CLI to; the dated measurements elsewhere in this
    file (0.147.0, 0.149.1) are history and stay as they were.

    - The reviewer is isolated from everything but the shell. `--ignore-user-config`
      and `--ignore-rules`, `web_search="disabled"`, and `--disable` for every
      feature in ISOLATION_DISABLE, on exec AND resume. Measured on 0.156.0:
      apps, plugins, browser and computer control, multi-agent, image generation
      and web access are on by default and none of it runs inside the read-only
      shell sandbox; with the isolation, the web, image, plugin-install and MCP
      tools are gone and the pinned `-c` keys still apply. The
      `collaboration.*` tools stay (no switch removes them); a spawned sub-agent
      was measured to inherit read-only and the isolation.
    - A reviewed repo cannot steer its own review through `.codex/config.toml`.
      Measured: in a repo trusted in the user config, Codex loaded that file and
      obeyed a `developer_instructions` line in it. Under `--ignore-user-config`
      there are no trust entries and the file was not loaded; as a second line,
      a `.codex/config.toml` in the working directory or any ancestor refuses
      the run (project_codex_configs()).
    - Blind-run evidence comes from stderr AND the event stream. `succeeded in`
      never appears with `--json` (0 of ~90 real runs), so the old success half
      was dead and one refusal alone meant exit 3. Execution is now counted
      from `command_execution` events of the last turn, the stream must end in
      `turn.completed`, and both files are read line by line under a size cap
      (see blind_run()).
    - The CLI version is probed once and shown in the header. A model with a
      known minimum (MODEL_MIN_CLI) is refused before the run when the version
      is lower or unreadable: `gpt-6-sol` on 0.149.1 is HTTP 400 on every call.
    - Every output file is locked for the run (acquire_locks()), and the
      reparse-point check fails closed (_is_reparse_point()).
    - On Windows Codex is never started through a batch file: `codex.cmd`
      runs via cmd.exe, which re-reads the arguments. find_codex() returns
      [node.exe, codex.js] -- what the npm starter runs -- or a codex.exe, and
      refuses a .cmd/.bat outright.

⛔ RESIDUAL GAPS, stated rather than papered over (audit 2026-09-02):
    - On Windows, the repo, `.claudex-tmp/` and the OS temp dir are still ASSUMED
      private, not verified -- `_is_private_dir()` cannot read a directory's
      ACL/DACL and returns True unconditionally there. A shared checkout or a
      shared temp dir on Windows is not actually screened. Closing this needs
      real Windows ACL/DACL inspection of every ancestor, which this wrapper
      does not implement (see `_is_private_dir`'s docstring). Only the
      environment-settable scratch dir was removed as a candidate, because that
      one-line removal closes a real hole; a half-built ACL check would not.
    - On Windows, the reparse-point/hard-link checks in `prepare_write_target()`
      run, then the file is opened separately in `open_for_write()` -- there is
      no O_NOFOLLOW there, so a second attacker with write access to the SAME
      directory could still swap the leaf between the two calls. This is a
      narrower window than before (it now needs a second attacker inside an
      already-private-assumed directory, not just an env var), not a closed one.
    - PATH-based Codex resolution is unpinned: whichever `codex`/`codex.cmd`
      resolves first on PATH runs, and PATH itself can be attacker-influenced.
      Removing CLAUDEX_CODEX_BIN closes the environment-override door but not
      this one -- pinning PATH resolution needs a decision about what "the
      trusted Codex install" even means on a given machine, which this fix does
      not make for you. The 2.6.0 version probe starts the same launch list
      as the run -- on Windows two files, node.exe and codex.js -- but nothing
      proves that neither was replaced in between.
    - `collaboration.*` (spawning sub-agents) cannot be switched off. A
      sub-agent's commands do not appear in the parent's event stream, so a run
      whose only execution happened in sub-agents and that also shows a stderr
      refusal is reported as blind -- a false alarm in the safe direction.

Exit codes:
    0    Codex ran and produced a non-empty answer
    1    Codex exited 0 but the answer file is empty -- the classic expired-token
         case: exit 0, a valid thread_id, and the 401 only in stderr
    2    refused: bad arguments, a path outside the allowed roots, a write target
         that is not a plain file, a file that cannot be read or opened, a
         config override that would touch the sandbox or the isolation, an
         output another run holds a lock on, a `.codex/config.toml` in the
         working directory or above it, or a model the installed CLI is known
         not to support (or whose CLI version cannot be read)
    3    blind: nothing provably ran (no command in the event stream's last
         turn) AND either a sandbox refusal was logged or the evidence itself
         is unusable (missing, truncated, malformed, over the size cap). Looks
         healthy from outside -- exit 0, a thread_id, a full answer file -- and
         is not a review
    124  timeout -- treat as a failure, do not blindly retry
    127  codex executable not found
    else Codex's own exit code

No filesystem failure escapes as a traceback: every path this wrapper opens,
reads, deletes or creates reports through the codes above instead.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

WRAPPER_VERSION = "2.6.0"

# gpt-5.6-terra was superseded by gpt-6-sol (released 2026-09-22). Measured on
# codex-cli 0.156.0: a real plan-review round took ~4:48 min at `medium`, well
# inside the default timeout. The role config (claudex_roles.py --spec) decides
# what a skill passes; this default only covers a bare call.
DEFAULT_MODEL = "gpt-6-sol"
DEFAULT_EFFORT = "medium"
EFFORT_CHOICES = ("low", "medium", "high", "xhigh", "max")

# The codex-cli version every guarantee in this file was last measured against.
# Held equal to the one marked docstring line by a test; raised only after the
# positive controls in docs/betrieb.md ("Codex heben") pass on the new version.
MEASURED_CODEX_CLI = "0.156.0"

# Models the installed CLI must be at least this new for. `gpt-6-sol` on 0.149.1
# is HTTP 400 "not supported when using Codex with a ChatGPT account" on every
# call (measured 2026-09-22) -- refusing up front names the fix instead.
MODEL_MIN_CLI = {"gpt-6-sol": "0.156.0"}

# ⛔ Read-only pins the SHELL. Everything else Codex can load runs beside it:
# MCP servers from the user config or a trusted project's `.codex/config.toml`,
# and on 0.156.0 a set of features that are on by default -- apps and
# connectors, plugins, browser and computer control, multi-agent, image
# generation, web access. None of that is a reviewer's business. So every call
# ignores the user config and execpolicy rules, switches web search off and
# disables these features (measured 2026-09-30: web, image, plugin-install, MCP
# and goals tools disappear, the shell still reads, the pinned `-c` keys still
# apply). Upstream: chaseai-yt/claudex-loop#28 and #18.
#
# Under `--ignore-user-config` there are no `[mcp_servers]` to switch off one by
# one -- and naming one that is not defined makes Codex SYNTHESISE an incomplete
# server table and refuse its whole config (the reason the old per-server logic
# only ever named installed servers, 2026-08-30). So the per-server overrides are
# gone with 2.6.0; --disable-mcp and CLAUDEX_DISABLE_MCP are accepted and
# reported as ignored.
ISOLATION_DISABLE = (
    "apps",
    "plugins",
    "remote_plugin",
    "browser_use",
    "browser_use_external",
    "browser_use_full_cdp_access",
    "computer_use",
    "in_app_browser",
    "multi_agent",
    "goals",
    "image_generation",
    "skill_mcp_dependency_install",
    "hooks",
    "workspace_dependencies",
    # Reach outward or concern MCP/extensions -- nothing a reviewer needs.
    "plugin_sharing",
    "tool_suggest",
    "skill_search",
    "auth_elicitation",
    "tool_call_mcp_elicitation",
    "realtime_conversation",
    "in_app_local_automation",
    "worktrees",
)
# Default-on features that were looked at and are fine for a read-only reviewer:
# the shell itself and its plumbing, output handling, desktop-app UI. Not passed
# to Codex -- the list exists so that raising the CLI (docs/betrieb.md, "Codex
# heben") can find a NEW default-on feature that is in neither list.
ISOLATION_ALLOWED = (
    "shell_tool",
    "unified_exec",
    "unified_exec_tty",
    "shell_snapshot",
    "view_image",
    "sleep_tool",
    "content_item_kinds",
    "compaction_image_budget",
    "enable_request_compression",
    "fast_mode",
    "guardian_approval",
    "guardian_reuse_parent_compaction",
    "mentions_v2",
    "secret_auth_storage",
    "system_proxy_fallback",
    "unbounded_connection_retries",
    "code_mode_host",
    "in_app_chat",
    "in_app_dictation",
    "in_app_updates",
)

# Every output of a run is locked by a sibling file with this suffix.
LOCK_SUFFIX = ".claudex-lock"

# Upper bound for reading stderr and the event stream. Above it the evidence is
# unusable, not "probably fine" -- see blind_run().
EVIDENCE_LIMIT = 64 * 1024 * 1024
VERSION_PROBE_TIMEOUT = 10
VERSION_PROBE_MAX_BYTES = 256

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
    # Picks WHICH Windows sandbox backend enforces the read-only pin (see
    # WINDOWS_SANDBOX below). Neither accepted value turns enforcement off, but the
    # two behave differently, and a caller swapping the backend under a wrapper
    # whose whole promise is that pin is the same category of change as swapping
    # sandbox_mode itself.
    "windows",
    # 2.6.0, reviewer isolation (see ISOLATION_DISABLE): each of these would
    # undo part of it -- re-enable a feature, turn web search back on, mark a
    # project trusted (which loads its `.codex/config.toml`), or hand the
    # reviewer instructions the caller wrote.
    "features",
    "web_search",
    "projects",
    "developer_instructions",
    "model_instructions_file",
)

# ⛔ Without this key, `codex exec` on Windows refuses EVERY shell command --
# including a plain read -- with `rejected: blocked by policy`, while still
# exiting 0 and answering from the prompt alone. A reviewer that read nothing
# thus returns a confident verdict. Measured here on codex-cli 0.149.1;
# upstream openai/codex#42172 dates the regression to 0.147.0 and #44839/#43633
# report the same signature.
#
# Two backends exist, `elevated` and `unelevated`; there is no "off". Measured
# on 0.149.1, reading a file and attempting a write in each:
#
#   backend      cwd on D:            cwd under %TEMP%
#   elevated     reads, write denied  FAILS (CreateProcessWithLogonW 267)
#   unelevated   reads, write denied  reads, write denied
#
# `elevated` runs the command as another user, which cannot reach a working
# directory inside the calling user's profile -- and the harness scratchpad
# lives exactly there. `unelevated` works in both places and refuses the write
# in both, so it is the one that gets pinned.
WINDOWS_SANDBOX = "unelevated"

MODEL_RE = re.compile(r"^[A-Za-z0-9._-]+$")
RESUME_RE = re.compile(r"^[0-9a-fA-F-]{8,}$")
# What a thread id may look like before it is printed: it comes from the child's
# stream, and a newline in it could forge a wrapper line such as `OUT=...`.
THREAD_ID_RE = re.compile(r"^[0-9A-Za-z._-]{1,128}$")

EXIT_EMPTY = 1
EXIT_REFUSED = 2
# The reviewer ran, answered, and never read anything -- see blind_run(). Its own
# code because it is not an error of the caller (2) and not an empty answer (1):
# it is a full answer that must not be recorded as a review.
EXIT_BLIND = 3
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


# --- --expect-workdir (wrapper 2.5.0) --------------------------------------------
# See the module docstring, "WHY --expect-workdir IS AN ASSERTION, NOT A
# SELECTOR", for the incident and the reasoning. What follows is only the
# mechanics; the order is the control (T20) and is not to be reshuffled.


def capture_cwd() -> str:
    """Read the process's cwd exactly ONCE, so every later use of "the cwd" --
    the --expect-workdir check, the header, _repo_root(), allowed_roots() --
    agrees with what was actually checked. Before this, main() called
    Path.cwd() three separate times; a directory deleted or unmounted between
    the first and a later call would re-open the exact TOCTOU gap
    --expect-workdir exists to close (T24).
    """
    try:
        return os.getcwd()
    except OSError:
        die(
            "<cwd unavailable>: the current working directory could not be "
            "determined.",
            EXIT_REFUSED,
        )
        raise AssertionError("unreachable")


def _escape_path_for_message(raw: str) -> str:
    """Render a path for an error message with every non-printable character
    escaped as \\xNN (byte range) or \\uNNNN (beyond it), and everything else
    -- including "Büro", "café", any ordinary non-ASCII letter -- left alone.

    `raw.encode("unicode_escape")` was rejected as the whole-string shortcut:
    it also mangles every non-ASCII *printable* character, which would have
    turned a perfectly normal "D:\\...\\Büro\\..." path into noise in the one
    place (an error message) where a human most needs to read it. Only
    characters that could smuggle a fake log line into stderr -- the control
    characters T14/T20 refuse as input in the first place -- need hiding, and
    this is also why the message can safely show the raw value even for a
    --expect-workdir that was refused for containing one.
    """
    out = []
    for ch in raw:
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) <= 0xFF:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


def _mismatch_refused(raw: str, cwd: str) -> None:
    """The one message shape every "these do not match" refusal uses. Only the
    two paths, escaped -- never a filesystem exception's own text (T17), which
    would hand an unattended caller a free oracle into this machine's errors.
    """
    die(
        "--expect-workdir does not match the actual working directory; "
        "refusing rather than guess which one is right.\n"
        f"  expected: {_escape_path_for_message(raw)}\n"
        f"  actual:   {_escape_path_for_message(cwd)}",
        EXIT_REFUSED,
    )


def _as_typed(path: str) -> str:
    """The comparison key for --expect-workdir: normcase() and at most ONE
    trailing separator removed. Deliberately NOT abspath()/normpath() -- those
    collapse `..`, `.`, doubled separators and (on Windows) trailing dots and
    spaces, which turns "names this path" into "names something that reduces
    to it". See step 2 of check_expected_workdir().
    """
    key = os.path.normcase(path)
    return key[:-1] if key.endswith(os.sep) else key


def check_expected_workdir(raw: str, cwd: str) -> None:
    """Refuse unless `raw` (--expect-workdir) and `cwd` name the same,
    alias-free place. An ASSERTION, never a selector -- see the module
    docstring. `cwd` is expected to already be capture_cwd()'s result; this
    function never calls os.getcwd() itself.

    Order (T20 pins it -- samefile() must be provably unreached for anything
    refused before it reaches that line):
      1. lexical refusals, no filesystem access at all
      2. a plain string comparison (no prefix match)
      3. the cwd's own alias-freedom (realpath() is applied ONLY to cwd here,
         never to `raw` -- resolving the expectation would defeat the very
         alias check step 2 already performs on it)
      4. samefile() as a belt, reached only once 2 and 3 already agree

    No fallback of any kind (measured, not assumed): os.path.realpath("") and
    os.path.realpath("missing/..") both equal the current directory, so a
    fallback that resolved an unresolvable expectation would have let an
    empty or malformed value silently confirm itself -- a control that is
    worse than none, because it manufactures confidence instead of refusing.
    """
    # 1. Lexical -- deliberately BEFORE any os.path call that could touch the
    #    filesystem for `raw`. An unset $TARGET expands to empty; that must
    #    refuse here, not reach samefile() and produce some OS-specific error.
    if not raw or not raw.strip():
        die(
            "--expect-workdir is empty or whitespace; refusing rather than "
            "guessing the intended scope.",
            EXIT_REFUSED,
        )
    if any(not ch.isprintable() for ch in raw):
        die(
            "--expect-workdir contains a non-printable character; refusing "
            "rather than risk it forging a log line: "
            f"{_escape_path_for_message(raw)}",
            EXIT_REFUSED,
        )
    # `\` -> `/` before the UNC/device check so \\srv, //srv, \\?\ and \\.\
    # are all caught by one test, on every platform -- POSIX included, where
    # it is stricter than necessary but never wrong.
    if raw.replace("\\", "/").startswith("//"):
        die(
            "--expect-workdir is a UNC or device path, not a plain absolute "
            f"directory: {_escape_path_for_message(raw)}",
            EXIT_REFUSED,
        )
    if not os.path.isabs(raw):
        die(
            "--expect-workdir must be an absolute path -- this also catches "
            "'.', './', '.\\', './.' and 'missing/..' in one rule: "
            f"{_escape_path_for_message(raw)}",
            EXIT_REFUSED,
        )

    # 2. Identity by STRING, not by what the filesystem resolves either side
    #    to. No prefix match: a subdirectory or the parent of cwd is not cwd.
    #
    #    ⛔ The value is compared AS TYPED. Until the closing gate (code-review,
    #    2026-09-18) this line ran it through os.path.abspath() first -- and
    #    abspath() is a normaliser: `<cwd>\sub\..`, `<cwd>\.`, a trailing dot or
    #    space and the drive-rooted `\repo` (which ntpath.isabs() accepts up to
    #    Python 3.12) all collapsed to the cwd and were ACCEPTED. The only
    #    tolerance left is normcase() -- case and slash direction, Windows only
    #    -- and one trailing separator. os.getcwd() already returns the fully
    #    qualified, normalised form, so anything else is a different string.
    if _as_typed(raw) != _as_typed(cwd):
        _mismatch_refused(raw, cwd)

    # 3. cwd must be its own real path -- a symlink/junction/subst alias that
    #    happens to normalise to the same STRING as a resolved cwd cannot
    #    exist (resolving `raw` is exactly what step 2 deliberately does not
    #    do), but cwd reaching this point via an alias is still possible on
    #    platforms whose getcwd()/chdir() do not canonicalise it away. Only
    #    cwd is ever resolved here -- never `raw` -- so this cannot become an
    #    oracle for the expectation.
    try:
        cwd_real = os.path.normcase(os.path.realpath(cwd))
    except OSError:
        die(
            "the working directory could not be resolved to its real path; "
            "refusing rather than trust a possible alias.",
            EXIT_REFUSED,
        )
        raise AssertionError("unreachable")
    if cwd_real != os.path.normcase(cwd):
        die(
            "the working directory is reached through a link, junction or "
            "other alias, not its real path. Start the session at the real "
            f"path instead: {_escape_path_for_message(cwd)}",
            EXIT_REFUSED,
        )

    # 4. Belt. Reached only once 2 and 3 already agree -- called through the
    #    module attribute (os.path.samefile) so a test can patch it and prove
    #    it is never reached for anything refused above (T20).
    try:
        identical = os.path.samefile(cwd, raw)
    except (OSError, ValueError):
        die(
            "the working directory could not be confirmed identical to "
            "--expect-workdir even though the two paths compare equal as "
            "strings; refusing rather than trust a filesystem check that "
            "failed.\n"
            f"  expected: {_escape_path_for_message(raw)}\n"
            f"  actual:   {_escape_path_for_message(cwd)}",
            EXIT_REFUSED,
        )
        raise AssertionError("unreachable")
    if not identical:
        _mismatch_refused(raw, cwd)


SCRATCH_DIR_ENV = "CLAUDEX_SCRATCH_DIR"


def _is_private_dir(path: Path) -> bool:
    """True when no other local user can replace this directory or its parents.

    On POSIX the question is real and answered for real. The rule is not "is
    anything world-writable" — that was the first version, and it was wrong in a
    way that only Linux showed: it refused every harness scratchpad under `/tmp`
    while accepting the identical layout on macOS, where `gettempdir()` happens
    to return a per-user path.

    What actually protects a directory entry is the **sticky bit**. `/tmp` is
    `drwxrwxrwt`: world-writable, but only an entry's owner may rename or unlink
    it. That is the whole reason `mkdtemp` is considered safe there. So an
    ancestor passes when it is not world-writable, OR when it is sticky and
    owned by root or by us. The leaf itself must be ours and closed to group
    and other.

    ⛔ On Windows this is NOT a check, it is an assumption: `os.stat` reports
    0o777 for everything, so there is no cheap equivalent of the S_IWOTH test --
    a real answer needs the ACL/DACL of every ancestor, which this function does
    not read (audit 2026-09-02, CRITICAL; a prior version of this docstring
    called the per-user temp dir "genuinely private", which is only usually
    true and was exactly the false confidence the audit flagged). Because this
    predicate cannot actually distinguish a private Windows directory from a
    shared one, `allowed_roots()` below no longer feeds it a directory the
    CALLER chose (CLAUDEX_SCRATCH_DIR) on Windows -- only the fixed candidates
    the wrapper picks itself. Those fixed candidates (the repo, its
    `.claudex-tmp/`, the OS temp dir) still pass through here unverified on
    Windows, which is a deliberately documented residual gap, not a fix: see
    "WHAT AN ACCEPTED CALL STILL CANNOT DO" in the module docstring.
    """
    if os.name == "nt":
        return True
    import stat

    try:
        me = os.geteuid()
    except AttributeError:  # pragma: no cover - POSIX always has it
        return True

    # Every ancestor, not just the directory itself: a private leaf under a
    # parent anyone can rewrite is replaceable wholesale, which is the same race
    # one level up. Walk upward to the filesystem root.
    for depth, candidate in enumerate((path, *path.parents)):
        try:
            st = os.stat(candidate)
        except OSError:
            return False

        if depth == 0:
            # The leaf itself must be ours and writable by nobody else.
            if st.st_uid != me or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
            continue

        if not st.st_mode & stat.S_IWOTH:
            continue  # no outsider can create or rename entries here

        # World-writable AND sticky is the /tmp case, and it is safe: the sticky
        # bit is precisely the rule that only an entry's owner (or the
        # directory's, or root) may rename or unlink it. That is what makes
        # mkdtemp trustworthy, and rejecting it outright — as this did until
        # 2026-09-03 — locked out every harness scratchpad on Linux while
        # letting the same layout through on macOS, where gettempdir() happens
        # to be a per-user path. The owner check matters: a sticky directory
        # owned by someone else still lets its owner remove our entries.
        if st.st_mode & stat.S_ISVTX and st.st_uid in (0, me):
            continue

        return False
    return True


def allowed_roots(
    extra: list[str], for_write: bool = False, cwd: Path | None = None
) -> list[Path]:
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

    `cwd` (2.5.0, docs/audit/2026-09-11-scope.md §5/E-2): `None` keeps the previous `Path.cwd()`
    behaviour, for every caller that does not care where the value came from.
    main() instead passes the SAME cwd it already captured once via
    capture_cwd() and checked against --expect-workdir, so this function never
    calls Path.cwd() a second time during a run. The root POLICY here is
    unchanged -- only the source of "the cwd" is now a parameter. The
    --expect-workdir VALUE itself must never reach this function (T18); only
    the already-verified cwd does.
    """
    cwd = (cwd if cwd is not None else Path.cwd()).resolve()
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
        # ⛔ Audit 2026-09-02, CRITICAL: on Windows, _is_private_dir() cannot tell
        # a genuinely private directory from a shared one -- os.stat() reports
        # 0o777 for everything there and this wrapper does not read the ACL/DACL
        # (see _is_private_dir's docstring). Before this fix, that unconditional
        # "yes" was applied to EVERY candidate, including one named at runtime
        # through CLAUDEX_SCRATCH_DIR. A caller able to set that variable on an
        # unattended, allowlisted invocation -- e.g. via a repo's
        # `.claude/settings.json` `env` block, not just a per-call shell prefix
        # -- could therefore point it at a directory of their own choosing and
        # have it accepted as a write root, where --out-file gets unlinked and
        # --err-file truncated. So on Windows this opt-in is refused outright:
        # a value the wrapper cannot verify is worth nothing here. On POSIX,
        # _is_private_dir() performs a real ancestor stat() check below, so the
        # opt-in stays -- accepting it there does not reopen the hole.
        if named and os.name == "nt":
            warn(
                f"{SCRATCH_DIR_ENV} is ignored on Windows: this wrapper cannot verify "
                "a directory named at runtime is actually private here (see "
                "_is_private_dir's docstring), so it no longer trusts one as a write "
                "root. Use the repo or its .claudex-tmp/ subdirectory instead."
            )
        elif named:
            candidates.append(Path(named).expanduser().resolve())
        # EVERY candidate is screened, not just the temp dir. A repo checked out
        # under /tmp is the same exposure as /tmp itself -- and the first version
        # of this only asked the question of the temp dir. (CodeRabbit, 2026-08-30.)
        private = [d for d in candidates if _is_private_dir(d)]
        if not private:
            # Fail closed, but say WHY. An empty allowed list rendered as a
            # refusal listing nothing, which reads like a bug in the wrapper
            # rather than a property of the machine. (CodeRabbit, 2026-08-30.)
            rejected = "\n    ".join(str(d) for d in candidates)
            hint = (
                f"  {SCRATCH_DIR_ENV} is not accepted on Windows (see above); create "
                "<repo>/.claudex-tmp/ or move the repo off a shared path."
                if os.name == "nt"
                else f"  Set {SCRATCH_DIR_ENV} to a directory only you can write to "
                "(and whose parents likewise), or move the repo off a shared path."
            )
            die(
                "no usable write root: every candidate is writable by other local "
                "users, so a target there could be swapped for a symlink between "
                "the check and the open.\n"
                f"  rejected:\n    {rejected}\n{hint}",
                EXIT_REFUSED,
            )
        return private
    opt_ins = list(extra) + os.environ.get("CLAUDEX_ALLOWED_PATHS", "").split(os.pathsep)
    for raw in opt_ins:
        if raw and raw.strip():
            roots.append(Path(raw.strip()).expanduser().resolve())
    return roots


# FILE_ATTRIBUTE_REPARSE_POINT (Windows). Set on BOTH kinds of reparse point that
# matter here: an NTFS symlink (which Path.is_symlink() already catches) and a
# directory JUNCTION (which it does not -- verified 2026-09-02: `mklink /J` from
# a plain, non-elevated account succeeds, and Path.is_symlink() on the result
# returns False, while os.stat(path, follow_symlinks=False).st_file_attributes
# has this bit set. Unlike an NTFS symlink, a junction needs NO special Windows
# privilege to create, so "creating a symlink needs a privilege most accounts do
# not have" -- this file's own former excuse for not checking further on Windows
# -- was true for symlinks and false for junctions.
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_reparse_point(path: Path) -> bool:
    """True for an NTFS symlink OR any other reparse point, notably a junction.

    Audit 2026-09-02 (part of the CRITICAL "reparse point or hardlink" finding):
    `Path.is_symlink()` alone lets a directory junction through, and a junction
    aimed at someone else's directory is exactly as dangerous a write target as a
    symlink -- --out-file gets deleted and --err-file gets truncated wherever the
    leaf name resolves to.

    ⛔ FAILS CLOSED (2.6.0). Until then any OSError, and a missing
    st_file_attributes on Windows, answered "not a reparse point" -- the one
    answer a safety check must not give when it could not look (review of the
    2.6.0 plan, gpt-6-sol, 2026-09-30). Now every metadata failure counts as
    "unsafe". The single exception is FileNotFoundError: a target that does not
    exist yet is the normal case for --out-file and a freshly created directory,
    and the caller then checks the parent it will create it in.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    if os.name != "nt":
        return False
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is None:
        return True
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def _has_other_hardlinks(path: Path) -> bool:
    """True when an EXISTING target shares its data with another name already.

    Audit 2026-09-02, the other half of the same finding: a hard link is not a
    reparse point at all -- it is a second directory entry for the SAME file
    data, invisible to is_symlink() and to the reparse-point check above. For
    --out-file this is harmless (main() unlinks the old name before recreating
    it, which only ever removes ONE name and leaves shared data and other names
    untouched); for --err-file and the event stream, which are opened directly
    with O_TRUNC and no prior unlink, truncating a hard-linked name truncates
    the SAME data the other name still points at -- silently corrupting a file
    this wrapper was never told about. A freshly created output file has exactly
    one name (nlink == 1); more than that means somebody else already has a
    name for this data, which is refused rather than trusted.
    """
    try:
        return path.exists() and os.stat(path, follow_symlinks=False).st_nlink > 1
    except OSError:
        return False


def prepare_write_target(path: Path, label: str) -> list[Path]:
    """Refuse a write target that is anything but a plain file, present or absent.

    The wrapper deletes --out-file and truncates --err-file. A symlink or
    junction there aims that at someone else's file; a directory or device aims
    it at something worse; a hard-linked file shares its data with a name this
    wrapper never saw. Checked before the unlink/open so the gap between the two
    cannot be raced through the LEAF name (audit 2026-08-30, hardened 2026-09-02
    for reparse points and hard links -- see _is_reparse_point / _has_other_hardlinks).
    """
    if _is_reparse_point(path):
        die(
            f"{label} is a symlink or reparse point (e.g. a Windows junction), or "
            f"could not be inspected: {path}\n"
            f"  Refusing: this file gets deleted and rewritten, and a symlink or "
            f"junction points that at something else. Name the real path.",
            EXIT_REFUSED,
        )
    if path.exists() and not path.is_file():
        die(f"{label} exists and is not a regular file: {path}", EXIT_REFUSED)
    if _has_other_hardlinks(path):
        die(
            f"{label} already has another name pointing at the same data: {path}\n"
            f"  Refusing: truncating or deleting it here would touch that other name's "
            f"content too, and this wrapper does not know what that name is.",
            EXIT_REFUSED,
        )
    return make_parents_checked(path.parent, label)


def _remove_made(made: list[Path]) -> None:
    """Remove directories this call created, innermost first; only empty ones go."""
    for level in reversed(made):
        try:
            level.rmdir()
        except OSError:
            pass


def make_parents_checked(directory: Path, label: str) -> list[Path]:
    """Create missing directories ONE level at a time, each re-checked at once.

    `mkdir(parents=True)` creates a whole chain and checks nothing in between; a
    directory swapped for a junction right after it was made would carry every
    later level -- and the output file -- somewhere else. So: find the nearest
    existing ancestor, then create each missing level below it and verify it is
    a plain directory before the next one is made (review of the 2.6.0 plan,
    gpt-6-sol, round 7). Returns the directories it created, outermost first, so a
    run refused afterwards can remove them again.
    """
    missing = []
    made: list[Path] = []
    current = directory
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for level in reversed(missing):
        try:
            os.mkdir(level)
        except FileExistsError:
            # Someone else created it in the meantime -- not ours to clean up.
            pass
        except OSError as exc:
            _remove_made(made)
            die(f"{label}: cannot create the directory {level}: {exc}", EXIT_REFUSED)
        else:
            made.append(level)
        if _is_reparse_point(level) or not level.is_dir():
            # The caller never receives `made` when this function dies, so the
            # levels created so far are removed here (closing gate, recheck 2).
            _remove_made(made)
            die(
                f"{label}: the directory just created is a symlink or reparse point "
                f"now, or not a directory: {level}\n"
                f"  Refusing: everything below it would land somewhere else.",
                EXIT_REFUSED,
            )
    return made


def open_for_write(path: Path, label: str):
    """Open a write target without following a link into it.

    O_NOFOLLOW closes the window between prepare_write_target() and here on
    POSIX. Windows has no such flag, and no atomic guarantee replaces it here:
    prepare_write_target()'s reparse-point and hard-link checks cover the LEAF
    name at the moment they run, but a second attacker able to write to the
    same directory could still swap that leaf between the check and this open.
    That race needs a real fix (an open handle carried through, not a path
    re-resolved) that this wrapper does not implement -- see "RESIDUAL GAPS" in
    the module docstring. The existing write-root privacy check is what is
    meant to keep a second such attacker out of the directory in the first
    place; it is documented there as an assumption, not a proof, on Windows.
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


def _user_config_paths() -> list[Path]:
    """The user-level Codex configs: the one under CODEX_HOME and ~/.codex's.

    Both sit on the way up from any working directory under the user profile,
    and neither is a PROJECT config: the first is what `--ignore-user-config`
    skips, the second is that same file whenever CODEX_HOME is unset. Exempting
    only the CODEX_HOME one refused every run under the profile as soon as
    CODEX_HOME pointed elsewhere (found while building 2.6.0).
    """
    return [_codex_home() / "config.toml", Path.home() / ".codex" / "config.toml"]


def project_codex_configs(start: Path) -> list[Path]:
    """Every `.codex/config.toml` from `start` up to the filesystem root.

    ⛔ Measured 2026-09-30: in a repo the user config marks as trusted, Codex
    loads that repo's `.codex/config.toml` -- and a `developer_instructions`
    line there decided the reviewer's answer. The repo under review steered its
    own review. `--ignore-user-config` removes the trust entries and the file
    was then not loaded; this is the second line behind that.

    Not only up to the git root: Codex has configurable `project_root_markers`,
    and this wrapper also runs outside git (review of the 2.6.0 plan, round 8).
    A path that cannot be checked counts as a hit. The user-level configs are
    not project configs (_user_config_paths()).
    """
    exempt = []
    for user_config in _user_config_paths():
        try:
            if user_config.exists():
                exempt.append(user_config)
        except OSError:
            pass
    hits = []
    for directory in (start, *start.parents):
        candidate = directory / ".codex" / "config.toml"
        try:
            os.lstat(candidate)
        except FileNotFoundError:
            continue
        except NotADirectoryError:
            continue
        except OSError:
            hits.append(candidate)
            continue
        is_user_config = False
        for user_config in exempt:
            try:
                if os.path.samefile(candidate, user_config):
                    is_user_config = True
                    break
            except OSError:
                pass
        if not is_user_config:
            hits.append(candidate)
    return hits


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

    A RELATIVE `raw` makes realpath() consult the current directory itself
    (os.getcwd() internally); if that directory has vanished since
    capture_cwd() ran -- T24 -- that raises OSError here, and this is refused
    like any other unresolvable path rather than left to become a traceback.
    """
    try:
        path = Path(os.path.realpath(Path(raw).expanduser()))
    except OSError:
        die(f"{label}: the current directory is no longer accessible: {raw}", EXIT_REFUSED)
        raise AssertionError("unreachable")
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
    """The child's argv, as a LIST (no command line to inject into): the read-only pin
    (`-s` on exec, `-c sandbox_mode` on resume), the trust-check flag, the Windows
    backend, model and effort, the 2.6.0 isolation (user config, rules, web search,
    ISOLATION_DISABLE), the caller's checked `-c` overrides, then `--json -o`. The
    prompt is not an argument; it goes over stdin."""
    argv = ["exec"]
    if args.resume:
        # resume knows no -s. Read-only is reachable only via -c there, and since a
        # later -c wins it has to be the ONLY sandbox_mode argument -- which is what
        # check_config_overrides() guarantees.
        argv += ["resume", args.resume, "-c", "sandbox_mode=read-only"]
    else:
        # exec: -s beats any trailing -c sandbox_mode (measured, see module docstring).
        argv += ["-s", "read-only"]
    # Gates a startup TRUST check, not the sandbox — measured on upstream PR #15
    # and reproduced here. Passing it always keeps a non-repo review working; the
    # sandbox is pinned by `-s read-only` / `-c sandbox_mode`, which this flag
    # does not touch.
    argv += ["--skip-git-repo-check"]
    # Selects the backend that ENFORCES the pin above. Windows only: the key does
    # not exist on the other platforms, and naming it there makes Codex reject its
    # whole config. See WINDOWS_SANDBOX for the measurements behind the value.
    if os.name == "nt":
        argv += ["-c", f'windows.sandbox="{WINDOWS_SANDBOX}"']
    argv += ["-m", args.model, "-c", f"model_reasoning_effort={args.effort}"]
    # Reviewer isolation (2.6.0, see ISOLATION_DISABLE): no user config -- and
    # with it no MCP servers and no project trust --, no execpolicy rules, no
    # web search, none of the default-on features that act outside the shell.
    # The pinned keys above are `-c` overrides and still apply (measured).
    argv += ["--ignore-user-config", "--ignore-rules", "-c", 'web_search="disabled"']
    for feature in ISOLATION_DISABLE:
        argv += ["--disable", feature]
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


# The Windows equivalent: the app ships the CLI under a PER-VERSION hash
# directory, and several can sit side by side. Putting one on PATH by hand is
# not a fix — the next update writes a new hash and the entry goes stale.
WINDOWS_BUNDLED_CODEX_GLOB = "OpenAI/Codex/bin/*/codex.exe"


def bundled_codex() -> str | None:
    """The Codex that ships inside the desktop app, if this platform has one.

    A fallback AFTER the PATH lookup, never a redirect: the path is fixed and
    chosen by this wrapper, which is what separates it from the removed
    CLAUDEX_CODEX_BIN. That variable let a CALLER's environment nominate any
    file as "Codex" (audit 2026-09-02, CRITICAL); this cannot be pointed
    anywhere.

    Windows was missing from here until 2026-09-07, and 2.3.0 made that a hard
    stop: with CLAUDEX_CODEX_BIN gone, a machine whose only Codex lives in the
    app directory failed every review with EXIT_NO_CODEX while a perfectly good
    CLI sat on disk, authenticated. Reported from a second workstation.
    """
    if sys.platform == "darwin":
        for candidate in MACOS_BUNDLED_CODEX:
            path = Path(candidate).expanduser()
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        return None

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            return None
        # Newest first: several hash directories coexist after an update, and
        # the stale one is still executable — picking it would run an old CLI
        # with no sign that anything was chosen at all.
        found = sorted(
            (p for p in Path(base).glob(WINDOWS_BUNDLED_CODEX_GLOB) if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if found:
            return str(found[0])
    return None


def _refuse_batch(launch: list[str]) -> list[str]:
    """Belt for every path that resolves a launch: a batch file is never started."""
    if Path(launch[0]).suffix.lower() in (".cmd", ".bat"):
        die(f"refusing to start a batch file: {_escape_path_for_message(launch[0])}\n"
            f"  A .cmd/.bat runs through cmd.exe, which re-reads the arguments. Install "
            f"codex so that node.exe and its codex.js, or a codex.exe, can be started directly.",
            EXIT_NO_CODEX)
    return launch


def _node_launch(starter: Path) -> list[str] | None:
    """[node.exe, codex.js] for an npm starter `codex.cmd`, or None.

    The starter does nothing but run `node.exe` (the one beside it, else the one on
    PATH) with `node_modules/@openai/codex/bin/codex.js` from its own directory;
    this is that, minus cmd.exe. None when the script or node cannot be found --
    the caller then tries the next source and in the end refuses.
    """
    script = starter.parent / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    if not script.is_file():
        return None
    beside = starter.parent / "node.exe"
    node = str(beside) if beside.is_file() else shutil.which("node.exe")
    if not node:
        return None
    return _refuse_batch([node, str(script)])


def find_codex() -> list[str]:
    # ⛔ There used to be a CLAUDEX_CODEX_BIN override here: any existing file
    # named through that variable was launched as "Codex", no further check.
    # Audit 2026-09-02, CRITICAL: this wrapper is meant to be allowlisted for
    # UNATTENDED calls (see the module docstring), which means its environment
    # is not something a human reviews per call -- a caller able to influence
    # it (a `.claude/settings.json` `env` block is enough; no shell prefix on
    # the individual call is needed) could point CLAUDEX_CODEX_BIN at any
    # existing program. That program then receives the prompt and runs with
    # this wrapper's arguments as ITS argv, under no obligation to honour
    # `-s read-only` -- the one guarantee this file exists to enforce would
    # apply to a replaced binary in name only. Removing the override closes
    # that door outright: which binary runs is now decided by PATH lookup and
    # the fixed macOS bundle path below, neither of which a caller's
    # environment variable can redirect through this wrapper.
    #
    # Known residual gap, not fixed here: PATH lookup itself is unpinned (see
    # "RESIDUAL GAPS" in the module docstring). A user whose PATH is wrong and
    # who is not on macOS has to fix PATH now; there is no environment escape
    # hatch left, on purpose.

    if os.name != "nt":
        found = shutil.which("codex")
        if found:
            return [found]
    else:
        # ⛔ 2.6.0: never through a batch file. A `.cmd` always runs via cmd.exe,
        # which re-reads its arguments -- the list this wrapper builds would not
        # reach Codex unchanged (reported as critical in a consumer repo). The npm
        # starter `codex.cmd` only calls `node.exe` with the package's `codex.js`,
        # so the wrapper starts exactly that itself.
        starter = shutil.which("codex.cmd")
        if starter:
            launch = _node_launch(Path(starter))
            if launch:
                return launch
        found = shutil.which("codex.exe")
        if found:
            return _refuse_batch([found])

    # PATH first, so a deliberate install still wins; the bundle is the fallback.
    bundled = bundled_codex()
    if bundled:
        return _refuse_batch([bundled])

    where = "the desktop app's install directory"
    if os.name == "nt":
        where = f"%LOCALAPPDATA%\\{WINDOWS_BUNDLED_CODEX_GLOB.replace('/', chr(92))}"
    elif sys.platform == "darwin":
        where = MACOS_BUNDLED_CODEX[0]
    names = ("codex.cmd with node.exe and its codex.js", "codex.exe") if os.name == "nt" else ("codex",)
    die(
        f"codex not found on PATH (tried: {', '.join(names)}), and not in {where}.\n"
        f"  Install it: npm install -g @openai/codex@{MEASURED_CODEX_CLI}   (the version this\n"
        f"  wrapper was measured against -- never an unpinned latest; see docs/betrieb.md)\n"
        f"  There is deliberately no environment override to point this elsewhere —\n"
        f"  CLAUDEX_CODEX_BIN was removed in 2.3.0 because it let an unattended\n"
        f"  call nominate any file as 'Codex' (audit 2026-09-02, CRITICAL).",
        EXIT_NO_CODEX,
    )
    raise AssertionError("unreachable")


CLI_VERSION_RE = re.compile(rb"\Acodex-cli (\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\r?\n?\Z")


def parse_cli_version(raw: bytes) -> str | None:
    """The version from `codex --version` output, or None for anything else.

    Strict on purpose: the output comes from whatever binary PATH resolved, and
    the caller prints the result. One line, exactly `codex-cli X.Y.Z[-pre]`,
    nothing before or after it -- anything else is `unreadable`, and the raw
    text is never shown.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if len(raw) > VERSION_PROBE_MAX_BYTES:
        return None
    match = CLI_VERSION_RE.match(raw)
    return match.group(1).decode("ascii") if match else None


def _cli_key(version: str) -> tuple:
    """Sort key for a parsed version: numeric parts, then release above pre-release."""
    core, _, pre = version.partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    # A pre-release sorts below its release: 0.156.0-alpha.1 < 0.156.0.
    return numbers + ((0, pre) if pre else (1, ""))


def cli_at_least(found: str, minimum: str) -> bool:
    """True when `found` is the same as or newer than `minimum` (both parse_cli_version()
    results). Numeric per component -- 0.1000.0 is newer than 0.156.0 -- and a
    pre-release of a version is older than that version."""
    return _cli_key(found) >= _cli_key(minimum)


def probe_cli_version(launch, _argv: list[str] | None = None,
                      timeout: int = VERSION_PROBE_TIMEOUT) -> str | None:
    """Ask the resolved binary for its version, once, before the run.

    The event stream carries no CLI version (measured, 76 of 76 streams), so the
    binary is asked directly. Treated like the main launch: the same launch list
    (on Windows node.exe and codex.js), no shell, stdin closed, its own process group, at most
    VERSION_PROBE_MAX_BYTES read, and on timeout the same process-tree kill as
    the run itself. Every failure is None ("unreadable"), never a traceback.
    `_argv` exists for tests only.
    """
    prefix = [launch] if isinstance(launch, str) else list(launch)
    argv = _argv or [*prefix, "--version"]
    platform_kwargs = (
        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt"
        else {"start_new_session": True}
    )
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, **platform_kwargs)
    except (OSError, ValueError):
        return None
    chunks: list[bytes] = []

    def read_head() -> None:
        """Read at most one byte past the cap; the rest of the output is never read."""
        try:
            chunks.append(proc.stdout.read(VERSION_PROBE_MAX_BYTES + 1))
        except (OSError, ValueError):
            pass

    reader = threading.Thread(target=read_head, daemon=True)
    reader.start()
    reader.join(timeout)
    finished = False
    oversized = bool(chunks) and len(chunks[0]) > VERSION_PROBE_MAX_BYTES
    if not reader.is_alive() and not oversized:
        try:
            proc.wait(timeout=max(1, timeout))
            finished = True
        except subprocess.TimeoutExpired:
            pass
    if not finished:
        kill_tree(proc)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            warn("the version probe did not exit even after the kill.")
    try:
        proc.stdout.close()
    except OSError:
        pass
    if not finished or proc.returncode != 0 or not chunks:
        return None
    return parse_cli_version(chunks[0])


def check_model_cli(model: str, version: str | None) -> None:
    """Refuse a model the installed CLI is known not to support.

    Only for models in MODEL_MIN_CLI, and then fail-closed: an unreadable
    version is refused as well, because the property the table exists for would
    otherwise be unproven. Every other model runs; general drift only warns.
    """
    minimum = MODEL_MIN_CLI.get(model)
    if minimum is None:
        if version is None:
            warn("the codex-cli version could not be read; running anyway.")
        elif version != MEASURED_CODEX_CLI:
            warn(f"codex-cli {version} -- this wrapper was measured against "
                 f"{MEASURED_CODEX_CLI}; see docs/betrieb.md, \"Codex heben\".")
        return
    if version is None or not cli_at_least(version, minimum):
        found = version or "an unreadable version"
        die(
            f"{model} needs codex-cli >= {minimum}, found {found}. Older CLIs answer "
            f"every call with HTTP 400.\n"
            f"  npm install -g @openai/codex@{minimum}",
            EXIT_REFUSED,
        )
    if version != MEASURED_CODEX_CLI:
        warn(f"codex-cli {version} -- this wrapper was measured against "
             f"{MEASURED_CODEX_CLI}; see docs/betrieb.md, \"Codex heben\".")


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
                "  (CLAUDEX_CODEX_BIN used to offer a shortcut around fixing PATH; it was",
                "  removed 2026-09-02 -- an unattended, allowlisted wrapper cannot trust an",
                "  environment variable to name its own executable. Fix PATH instead.)",
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
            pgid = os.getpgid(proc.pid)
            if pgid == os.getpgid(0):
                # ⛔ The child shares OUR process group, so killpg would take this
                # wrapper, the shell that launched it, and anything else in the
                # group down with it. Demonstrated 2026-09-03: a test that spawned
                # its child without start_new_session made every POSIX CI job die
                # as "the hosted runner lost communication with the server" — the
                # SIGKILL reached the runner agent. Windows was unaffected because
                # taskkill /T is scoped to the process tree.
                #
                # main() always spawns with start_new_session=True, so this branch
                # should be unreachable there. It exists because the consequence of
                # being wrong is killing the caller, and that is too expensive to
                # leave to an invariant nobody re-checks after a refactor.
                warn("child shares this process group -- killing only the child.")
            else:
                os.killpg(pgid, signal.SIGKILL)
                return
        except OSError as exc:
            warn(f"killpg failed: {exc}")
    try:
        proc.kill()
    except OSError as exc:
        warn(f"fallback kill failed, a codex process may still be running: {exc}")


# A sandbox refusal as Codex logs it to stderr -- an `exec_command failed` line
# carrying the reason. Measured identical on 0.149.1 and 0.156.0 (J0,
# 2026-09-30); on neither does a refused command appear in the event stream.
# The stderr SUCCESS marker the old rule relied on (`succeeded in <ms>`) never
# appears with --json: 0 of ~90 real runs. Execution is counted from the stream.
SANDBOX_REFUSAL_RE = re.compile(
    rb"rejected: blocked by policy|CreateProcessWithLogonW failed", re.IGNORECASE)

EXECUTED_STATUSES = ("completed", "failed")


class StreamEvidence:
    """What the event stream proves about the run -- see read_stream_evidence()."""

    def __init__(self) -> None:
        """Nothing proven yet: every flag starts at its fail-closed value."""
        self.thread_id: str | None = None
        self.executed = 0          # command_execution items that provably ran, last turn
        self.unclassified = 0      # command_execution items that could not be classified
        self.saw_thread = False
        self.saw_turn = False
        self.complete = False      # the last turn ended in turn.completed
        self.turn_failed = False   # the last turn reported turn.failed
        self.turn_closed = False   # turn.completed/turn.failed seen, no new turn yet
        self.order_error = False   # events out of the measured order
        self.bad_lines = 0
        self.oversized = False
        self.missing = False

    @property
    def usable(self) -> bool:
        """True only for a complete, fully read, well-formed stream: present, under the
        size cap, every line JSON, a thread and a turn, and the last turn ended in
        turn.completed."""
        return (not self.missing and not self.oversized and self.bad_lines == 0
                and not self.order_error
                and self.saw_thread and self.saw_turn and self.complete)

    def problem(self) -> str:
        """Why the stream is not usable, in one line for the exit-3 message; "" if it is."""
        if self.missing:
            return "the event stream is missing or unreadable"
        if self.oversized:
            return f"the event stream is larger than {EVIDENCE_LIMIT} bytes"
        if self.bad_lines:
            return f"{self.bad_lines} line(s) of the event stream are not JSON"
        if self.order_error:
            return "the event stream is out of order (thread.started, turn.started, turn.completed)"
        if not self.saw_thread or not self.saw_turn:
            return "the event stream has no thread.started/turn.started"
        if not self.complete:
            return "the last turn did not end in turn.completed (truncated or failed)"
        return ""


def _bounded_lines(path: Path, limit: int):
    """Yield (line, over_limit) reading at most `limit` bytes, one line at a time.

    readline() gets an explicit size every time, so no single read -- not even
    one enormous line -- takes more than what is left of the budget.
    """
    with open(path, "rb") as handle:
        consumed = 0
        while True:
            line = handle.readline(limit - consumed + 1)
            if not line:
                return
            consumed += len(line)
            if consumed > limit:
                yield line, True
                return
            yield line, False


def read_stream_evidence(stream_file: Path, limit: int | None = None) -> StreamEvidence:
    """One bounded pass over the event stream: thread id and execution evidence.

    Counted as EXECUTED: `item.completed` whose item is a `command_execution`
    with an integer `exit_code` (`type(v) is int` -- JSON true is not a process)
    and status `completed` or `failed`. A non-zero exit still ran: the sandbox let
    the process start. Only the LAST turn counts (resume safety); a
    `command_execution` that does not fit is `unclassified`, never executed.
    Every other item type is ignored -- model text in particular can say
    anything. Measured contract (76 of 76 real streams, 0.149.1 and 0.156.0):
    one `thread.started`, one `turn.started`, ending in `turn.completed`.
    """
    limit = EVIDENCE_LIMIT if limit is None else limit
    ev = StreamEvidence()
    try:
        for raw, over in _bounded_lines(stream_file, limit):
            if over:
                ev.oversized = True
                break
            if not raw.strip():
                continue
            try:
                event = json.loads(raw)
            except ValueError:
                ev.bad_lines += 1
                continue
            if not isinstance(event, dict):
                ev.bad_lines += 1
                continue
            kind = event.get("type")
            if kind == "thread.started":
                if ev.saw_turn:
                    ev.order_error = True
                ev.saw_thread = True
                if ev.thread_id is None and isinstance(event.get("thread_id"), str):
                    ev.thread_id = event["thread_id"]
            elif kind == "turn.started":
                ev.saw_turn = True
                ev.turn_closed = False
                ev.complete = False
                ev.turn_failed = False
                ev.executed = 0
                ev.unclassified = 0
            elif kind == "turn.completed":
                if not ev.saw_turn:
                    ev.order_error = True
                ev.complete = ev.saw_turn and not ev.turn_failed
                ev.turn_closed = True
            elif kind == "turn.failed":
                ev.turn_failed = True
                ev.complete = False
                ev.turn_closed = True
            elif isinstance(kind, str) and kind.startswith("item.") and ev.turn_closed:
                # A closed turn takes no more items: an event after turn.completed
                # would otherwise count as execution nobody asked about (closing
                # gate of 2.6.0, recheck 1, reproduced by the reviewer).
                ev.order_error = True
            elif kind == "item.completed" and ev.saw_turn:
                item = event.get("item")
                if isinstance(item, dict) and item.get("type") == "command_execution":
                    code = item.get("exit_code")
                    if type(code) is int and item.get("status") in EXECUTED_STATUSES:
                        ev.executed += 1
                    else:
                        ev.unclassified += 1
    except OSError:
        ev.missing = True
    return ev


def count_stderr_refusals(err_file: Path, limit: int | None = None) -> tuple[int, bool]:
    """(sandbox refusals in stderr, whether all of stderr could be read).

    Line by line over the WHOLE file up to the limit -- the old reader kept only
    the last 200 KiB, so a refusal early in a long log was lost. A missing file
    is not an accusation: (0, True).
    """
    limit = EVIDENCE_LIMIT if limit is None else limit
    if not err_file.exists():
        return 0, True
    refusals = 0
    try:
        for raw, over in _bounded_lines(err_file, limit):
            if over:
                return refusals, False
            if SANDBOX_REFUSAL_RE.search(raw):
                refusals += 1
    except OSError:
        return refusals, False
    return refusals, True


def blind_run(err_file: Path, stream_file: Path, evidence: StreamEvidence | None = None) -> str | None:
    """Reason why this run must not count as a review, or None.

    ⛔ THE FAILURE THIS CATCHES IS SILENT. When the sandbox backend refuses every
    command, Codex still exits 0 and still writes a fluent answer -- produced from
    the prompt alone, by a model that never opened a file. Nothing else here
    notices, and a verdict from a reviewer that reviewed nothing gets recorded.

    Blind = NOTHING provably ran in the last turn AND (a sandbox refusal was
    logged, OR the evidence is unusable, OR a command could not be classified).
    Not "any refusal": a model that reaches for one illegal command, is told no,
    and then does the job has produced a real review -- blocking that would make
    the wrapper block normal work, and such a control gets switched off. And not
    "no command": 12 of 72 real runs answered legitimately with none (resume
    rounds, exposure passes with the content in the prompt). Execution that
    happened only in a sub-agent is invisible here and, with a refusal, reads as
    blind -- a false alarm in the safe direction, documented as such.
    """
    ev = evidence if evidence is not None else read_stream_evidence(stream_file)
    refusals, stderr_whole = count_stderr_refusals(err_file)
    if ev.executed > 0:
        if not ev.usable or not stderr_whole or ev.unclassified:
            problem = (ev.problem() or ("stderr exceeds the size limit" if not stderr_whole else
                       f"{ev.unclassified} command event(s) that cannot be classified"))
            warn(
                f"the run executed commands, but part of its evidence is unusable ({problem}) "
                f"-- read {stream_file} before relying on the answer."
            )
        return None
    reasons = []
    if refusals:
        reasons.append(f"{refusals} refused (stderr)")
    if not ev.usable:
        reasons.append(ev.problem())
    if not stderr_whole:
        reasons.append(f"stderr exceeds {EVIDENCE_LIMIT} bytes or cannot be read")
    if ev.unclassified:
        reasons.append(f"{ev.unclassified} command event(s) that cannot be classified")
    if not reasons:
        return None
    hinweis = (
        f"  On Windows a refusal is usually openai/codex#42172: without `[windows] "
        f"sandbox` no backend is selected and every command is refused. This "
        f"wrapper pins `windows.sandbox=\"{WINDOWS_SANDBOX}\"` -- if you see this "
        f"anyway, the Codex build no longer accepts it.\n"
        if os.name == "nt" and refusals else
        "  A refusal here means the sandbox would not start any process -- check "
        "the platform's sandbox helper (Landlock on Linux, seatbelt on macOS).\n"
        if refusals else
        "  Without usable evidence a run that read nothing cannot be told apart "
        "from one that did.\n"
    )
    return (
        # A refused command never appears in the stream (J0, 0.149.1 and 0.156.0),
        # so the stream count is 0 by construction -- stated, not implied (J5).
        f"the reviewer did not provably run a single command ({'; '.join(reasons)}; "
        f"0 refused (stream); 0 executed (stream)) -- the answer may have been written WITHOUT reading "
        f"anything, and it is not a review.\n" + hinweis
        + f"  Details: {err_file} and {stream_file}"
    )


def acquire_locks(paths: list[Path]) -> list[Path]:
    """Lock every output of this run, in a fixed order, or refuse the run.

    Two calls naming the same --err-file (or the same answer file) would each
    truncate the other's evidence; a second run could even name the first run's
    lock as its own --out-file and delete it (review of the 2.6.0 plan, round 7).
    A lock is a sibling file created with O_CREAT|O_EXCL; any existing lock means
    exit 2 with nothing touched, and the locks this call already took are
    returned. A lock left behind by a crash is reported, and removed by hand only.
    """
    taken: list[Path] = []
    for path in sorted({Path(str(p) + LOCK_SUFFIX) for p in paths}):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            release_locks(taken)
            try:
                holder = path.read_text(encoding="utf-8", errors="replace")[:200]
            except OSError:
                holder = "(unreadable)"
            die(
                f"another run holds {path}: {_escape_path_for_message(holder.strip())}\n"
                f"  Refusing: sharing an output would let the two runs overwrite each "
                f"other's evidence. If no run is active, the lock is left over from a "
                f"crash -- check, then delete it by hand.",
                EXIT_REFUSED,
            )
        except OSError as exc:
            release_locks(taken)
            die(f"cannot create the lock {path}: {exc}", EXIT_REFUSED)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"pid {os.getpid()} since {time.strftime('%Y-%m-%dT%H:%M:%S')}\n")
        taken.append(path)
    return taken


def release_locks(locks: list[Path]) -> None:
    """Remove the given locks. A lock that is already gone is fine; one that cannot be
    removed is reported, never swallowed -- the next run would refuse on it."""
    for path in locks:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            warn(f"could not remove the lock {path}: {exc} -- delete it by hand.")


# --- entry point ----------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the wrapper's own options. Refusals that depend on more than one option
    (paths, overrides, model and version) happen in main(); here only the deprecated
    MCP switches are reported as ignored."""
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
    parser.add_argument("--effort", default=DEFAULT_EFFORT, choices=EFFORT_CHOICES)
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
        help="ignored since 2.6.0: the user config (and with it every MCP server) is "
        "not loaded at all. Accepted so older calls keep working.",
    )
    parser.add_argument(
        "--expect-workdir",
        metavar="DIR",
        help="assert the actual cwd is exactly this absolute path; refuses on any "
        "mismatch, alias (symlink/junction) or ambiguity -- it can ONLY cause a "
        "refusal, never select or change where anything runs. See the module "
        "docstring for why there is no --workdir that would set the child's cwd.",
    )
    parser.add_argument("--version", action="version", version=f"codex_ro.py {WRAPPER_VERSION}")
    args = parser.parse_args(argv)

    # 2.6.0: MCP is not switched off server by server any more -- the user
    # config that defines the servers is not loaded at all (--ignore-user-config,
    # see ISOLATION_DISABLE). An empty value used to be refused because it left
    # servers on; there is nothing left for either spelling to turn on or off.
    if args.disable_mcp is not None or os.environ.get("CLAUDEX_DISABLE_MCP") is not None:
        warn(
            "--disable-mcp / CLAUDEX_DISABLE_MCP is ignored since 2.6.0: the user config "
            "is not loaded, so no MCP server from it starts at all."
        )
    return args


def main(argv: list[str] | None = None) -> int:
    """Refuse, confine, probe, lock, run, judge -- in that order, and nothing is
    created or deleted before every refusal has had its chance. Returns the exit code
    documented in the module docstring; never raises a traceback."""
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

    # 1c. Capture the cwd ONCE, for every run, flag or not (docs/audit/2026-09-11-scope.md §5/E-1).
    #     Everything below that used to call Path.cwd()/os.getcwd() again --
    #     the non-repo warning, allowed_roots(), the header -- now reuses this
    #     same string instead, so a directory deleted or unmounted mid-run
    #     cannot make one part of this function disagree with another (T24).
    cwd = capture_cwd()
    # ⛔ `is not None`, never truthiness. An unset $TARGET expands to "", and ""
    #    is falsy: `if args.expect_workdir:` skipped the whole assertion for
    #    exactly the input it most needs to refuse, so the flag confirmed itself
    #    by vanishing. Caught reading the diff (2026-09-18), not by the unit
    #    tests -- check_expected_workdir("") refused all along.
    if args.expect_workdir is not None:
        check_expected_workdir(args.expect_workdir, cwd)
    try:
        resolved_cwd = Path(cwd).resolve()
    except OSError:
        # Same "no traceback, ever" contract as capture_cwd() and
        # check_expected_workdir() above: Path.resolve() consults the
        # filesystem again (and, on some platforms, os.getcwd() itself --
        # see resolve_in_roots()'s docstring), so a cwd that vanishes in the
        # narrow window right after capture_cwd() returned must land here,
        # not in an uncaught exception (T24).
        die(
            f"the working directory could not be resolved: {_escape_path_for_message(cwd)}",
            EXIT_REFUSED,
        )
        raise AssertionError("unreachable")

    # 1a. A project config anywhere above the working directory could steer the
    #     reviewer (measured 2026-09-30). --ignore-user-config already keeps it
    #     from loading; this is the second line, and it refuses before anything
    #     is created.
    project_configs = project_codex_configs(resolved_cwd)
    if project_configs:
        listed = "\n    ".join(_escape_path_for_message(str(p)) for p in project_configs)
        die(
            "a project Codex config sits in or above the working directory:\n"
            f"    {listed}\n"
            "  A reviewed repo must not configure its own reviewer -- a "
            "`developer_instructions` line there was measured to decide the answer.\n"
            "  Check the file, then remove or rename it. There is no override.",
            EXIT_REFUSED,
        )

    # 1b. Outside a git repo: warn, do not refuse.
    #
    # ⛔ CORRECTION (2026-09-09). This used to die here, on the reasoning --
    # inherited from upstream issue #10 and repeated by this repo without ever
    # measuring it -- that the trust check "scopes Codex's writable root to the
    # repo". @mraol08831 measured it on upstream PR #15 and falsified that:
    # `workspace-write` reports its roots as [cwd, /tmp, $TMPDIR], where cwd is
    # the working directory and NOT the repo root, with and without the flag
    # alike. There is no git-derived writable root for it to remove. The flag
    # gates a startup TRUST check; it does not widen the sandbox.
    #
    # Reproduced here on codex-cli 0.149.1: in a non-git directory, read-only
    # without the flag exits 1 ("Not inside a trusted directory"), with the flag
    # exits 0. So refusing bought no safety and cost every non-repo review.
    #
    # What survives is the diagnostic: the refusal arrives BEFORE the model, with
    # no answer file and no thread.started line -- the exact signature of an
    # expired token. Saying which it is, is worth a line.
    repo_root = _repo_root(resolved_cwd)
    if repo_root is None:
        warn(
            f"not inside a git repository: {cwd}\n"
            "  Proceeding with --skip-git-repo-check. Path confinement still applies,\n"
            "  anchored at this directory instead of a repo root -- so double-check\n"
            "  that this is where you meant to run."
        )

    # 2. Paths -- resolved and confined before anything is created or deleted.
    #    Two root sets on purpose: --allow-path widens reads, never writes. See
    #    allowed_roots(); the caller may not widen its own confinement for the
    #    files this wrapper deletes and truncates. `cwd=resolved_cwd` on both
    #    calls: the source of "the cwd" is the one captured above, not a fresh
    #    Path.cwd() -- and --expect-workdir's own value never reaches here.
    read_roots = allowed_roots(args.allow_path, cwd=resolved_cwd)
    write_roots = allowed_roots([], for_write=True, cwd=resolved_cwd)
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

    launch = find_codex()
    executable = launch[-1]
    # One probe of the SAME resolved launch the run will start (A3). A model with a
    # known minimum is refused here, before any file is created or deleted.
    cli_version = probe_cli_version(launch)
    check_model_cli(args.model, cli_version)
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
        if _case_key(path.name).endswith(_case_key(LOCK_SUFFIX)):
            die(f"{label} names a lock file ({LOCK_SUFFIX}); choose another name: {path}",
                EXIT_REFUSED)
    created: list[Path] = []
    try:
        for label, path in targets.items():
            created += prepare_write_target(path, label)
        locks = acquire_locks(list(targets.values()))
    except SystemExit:
        # A refused run leaves the tree as it found it -- whichever refusal it
        # was: remove, innermost first, the (still empty) directories this call
        # itself created. Never one another session created meanwhile
        # (make_parents_checked() reports only its own successful mkdir).
        for directory in sorted(set(created), key=lambda d: len(d.parts), reverse=True):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
    try:
        return _run_locked(args, launch, argv_child, cli_version, cwd, repo_root,
                           prompt, out_file, err_file, stream_file)
    finally:
        release_locks(locks)


def _run_locked(args, launch, argv_child, cli_version, cwd, repo_root,
                prompt, out_file, err_file, stream_file) -> int:
    """Everything that touches the outputs, run while their locks are held."""
    executable = launch[-1]
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
    # The cheapest part of docs/audit/2026-09-11-scope.md §5 and the one that would have made the
    # 2026-09-11 incident visible: which directory Codex is about to inherit,
    # always -- flag or not. Escaped like every other rendering of `cwd`.
    print(
        f"#   cwd: {_escape_path_for_message(cwd)}   "
        f"({'git repo' if repo_root is not None else 'no git repo'})"
    )
    # Which CLI actually runs -- the stream does not say (A3). Only the parsed
    # version is printed, never the probe's raw output.
    drift = "" if cli_version == MEASURED_CODEX_CLI else f"   (measured against {MEASURED_CODEX_CLI})"
    print(f"#   codex-cli {cli_version or 'unreadable'}{drift}")

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
        try:
            proc = subprocess.Popen(
                [*launch, *argv_child],
                stdin=subprocess.PIPE,
                stdout=stream_handle,
                stderr=err_handle,
                **platform_kwargs,
            )
        except OSError as exc:
            # The binary answered the version probe a moment ago; if it cannot be
            # started now it vanished or was replaced -- an exit code, not a traceback.
            die(f"codex could not be started: {_escape_path_for_message(executable)}: "
                f"{exc.__class__.__name__}", EXIT_NO_CODEX)
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

    # 5. Report. One bounded pass over the stream yields the thread id AND the
    #    execution evidence -- the old separate reader loaded the whole stream
    #    before any limit applied (review of the 2.6.0 plan, round 8).
    evidence = read_stream_evidence(stream_file)
    if evidence.thread_id and THREAD_ID_RE.match(evidence.thread_id):
        print(f"THREAD_ID={evidence.thread_id}")
    elif evidence.thread_id:
        warn(f"the stream carries a malformed thread id; not printed: "
             f"{_escape_path_for_message(evidence.thread_id[:80])}")

    # Before anything is reported as an answer: did the reviewer get to read?
    # This check comes FIRST because the run it catches looks entirely healthy --
    # exit 0, a thread_id, a full answer file.
    blind = blind_run(err_file, stream_file, evidence)
    if blind:
        warn(blind)
        return EXIT_BLIND

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
