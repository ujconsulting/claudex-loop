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
    if $candidate -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        exec $candidate "$@"
    fi
done

echo "claudex-loop: no working Python 3.8+ found (tried: python3, python, py -3)." >&2
echo "  The read-only Codex wrapper and its permission guard both need it." >&2
exit 1
