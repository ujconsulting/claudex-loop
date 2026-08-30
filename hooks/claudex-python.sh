#!/usr/bin/env bash
# Find a working Python 3 and exec the given hook script with it.
#
# Three platform facts make this shim necessary rather than just calling `python3`:
#
#   1. On Windows + Git Bash, `python3` is usually the Microsoft Store stub, which
#      exits 49 silently in a non-TTY subprocess. Probing each candidate with a
#      trivial program skips it and falls through to the real install.
#   2. Git Bash hands script paths over in POSIX form (/c/Users/...). A Windows
#      python.exe reads the leading slash as the root of the current drive and
#      fails with ENOENT. `cygpath -w` fixes that and is a no-op elsewhere.
#   3. Windows Python defaults its IO encoding to cp1252, which crashes on any
#      path or payload byte outside that codepage. PEP 540 has to be set before
#      the interpreter starts.
#
# Adapted from the same shim in the security-guidance plugin, where each of these
# was learned the expensive way.
set -e

export PYTHONUTF8=1

if command -v cygpath >/dev/null 2>&1; then
    converted=()
    for arg in "$@"; do
        case "$arg" in
            /*) converted+=("$(cygpath -w "$arg")") ;;
            *)  converted+=("$arg") ;;
        esac
    done
    set -- "${converted[@]}"
fi

for candidate in "python3" "python" "py -3"; do
    # shellcheck disable=SC2086
    if $candidate -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        exec $candidate "$@"
    fi
done

# No interpreter. The guard cannot run -- so decide here, and fail CLOSED for the
# only case that matters.
#
# Audit 2026-08-30 (HIGH): this used to `exit 1`. A PreToolUse hook must exit 2 to
# deny; exit 1 is a non-blocking error, so the tool call went ahead with the
# wrapper still on the permission allowlist and nothing guarding it. Exiting 2
# unconditionally is no answer either -- this hook matches EVERY Bash and
# PowerShell call, so that would brick the session over a missing interpreter.
#
# So read the payload and deny only what concerns the wrapper. The match is
# deliberately coarse (any mention, expansion-proof by being substring-free of the
# extension): without Python we cannot do better than "this smells like the thing
# we are meant to protect", and over-denying here costs one prompt.
# `read -d ''` and `printf` are builtins on purpose: the environment that has no
# Python may well have no `cat` either, and the deny path must not need one.
IFS= read -r -d '' payload || true
echo "claudex-loop: no working Python 3.10+ found (tried: python3, python, py -3)." >&2
echo "  The read-only Codex wrapper and its permission guard both need it." >&2

case "$payload" in
    *codex_ro*)
        reason="Refused by claudex-loop: this command mentions the read-only Codex wrapper, but no Python 3.10+ was found, so the guard that keeps an allowlisted wrapper call from carrying a second command could not run. Denying rather than approving an unguarded call. Install Python 3.10+, or remove the wrapper's allowlist entry and answer the prompt per round."
        printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":%s}}\n' \
            "\"$reason\""
        echo "$reason" >&2
        exit 2
        ;;
esac

# Unrelated command: say the interpreter is missing, but do not block the session.
exit 0
