"""Mutation probe for hooks/gate_reminder.py: every guard removed must turn a test red.

    python tests/mutation_probe_gate_reminder.py

Not collected by pytest (no `test_` prefix) and not part of CI: it REWRITES the hook for the
duration of each mutant and restores it afterwards (also on Ctrl-C, via `finally`). Run it
after touching the hook or its tests. A mutant that prints `OK` has SURVIVED -- some guard
has no test. That happened three times while this file was written (2026-09-21), each time
because the test that should have caught it skips or is vacuous on Windows: a symlink test
without the privilege to create symlinks, an O_NOFOLLOW assertion on a platform without the
flag, and a per-file cap only ever exercised with its default limit.
"""
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
hook = REPO / "hooks" / "gate_reminder.py"
orig = hook.read_bytes()


def run():
    r = subprocess.run([sys.executable, "-m", "unittest", "tests.test_gate_reminder"],
                       cwd=REPO, capture_output=True, text=True)
    tail = r.stderr.strip().splitlines()
    fails = sorted({ln.split(" (")[0] for ln in tail if ln.startswith(("FAIL:", "ERROR:"))})
    return tail[-1], fails


MUTANTS = {
    "old demand back in the message": (
        b'"`pending` is the NORMAL state while a plan is being built. The closing gate -- the "',
        b'"If this commit belongs to building one of them, the closing gate is owed. Run it now. The "',
    ),
    "due point echoed unfiltered": (
        b"    value = _echoable(d.group(1), MAX_DUE_CHARS)\n",
        b"    value = d.group(1).strip()\n",
    ),
    "path echoed unfiltered": (
        b'        rel = _echoable(str(p.relative_to(root)).replace("\\\\", "/"), MAX_PATH_CHARS)\n',
        b'        rel = str(p.relative_to(root)).replace("\\\\", "/")\n',
    ),
    "allowlist back to Unicode-aware \\w (finding S1)": (
        "ECHOABLE_RE = re.compile(r\"[A-Za-z0-9_äöüÄÖÜß .\\-/#]+\")".encode("utf-8"),
        b'ECHOABLE_RE = re.compile(r"[\\w .\\-/#]+")',
    ),
    "symlinked PLAN.md followed again (finding S2)": (
        b'elif e.name == "PLAN.md" and e.is_file(follow_symlinks=False):',
        b'elif e.name == "PLAN.md":',
    ),
    "line cut back to splitlines() (U+2028)": (
        b'    rest = re.split(r"[\\r\\n]", text[m.end(): m.end() + MAX_MARKER_LINE], maxsplit=1)[0]\n',
        b'    rest = (text[m.end():].splitlines() or [""])[0]\n',
    ),
    "scan budget never decreases (recheck S1)": (
        b'                        budget -= len(text.encode("utf-8", errors="replace"))\n',
        b'                        budget -= 0\n',
    ),
    "file-count cap removed (recheck S1)": (
        b"                        files += 1\n",
        b"                        files += 0\n",
    ),
    "open handle not checked (recheck S2)": (
        b"        if not stat.S_ISREG(info.st_mode):\n",
        b"        if False:\n",
    ),
    "O_NOFOLLOW dropped (recheck S2)": (
        b'getattr(os, "O_NOFOLLOW", 0)',
        b"0",
    ),
    "per-file clamp removed (recheck 2)": (
        b"        limit = max(0, min(limit, MAX_PLAN_BYTES))\n",
        b"        limit = max(0, limit)\n",
    ),
    "word boundary back to \\b": (
        b'pending(?![\\w-])"',
        b'pending\\b"',
    ),
}

SURVIVORS = []
try:
    for name, (old, new) in MUTANTS.items():
        assert orig.count(old) == 1, f"mutant '{name}': anchor found {orig.count(old)}x"
        hook.write_bytes(orig.replace(old, new, 1))
        summary, fails = run()
        if not fails:
            SURVIVORS.append(name)
        print(f"MUTANT {name!r}: {summary}" + ("" if fails else "   <-- SURVIVED"))
        for f in fails:
            print("   ", f)
finally:
    hook.write_bytes(orig)
summary, fails = run()
print(f"RESTORED: {summary} | identical: {hook.read_bytes() == orig}")
sys.exit(0 if not SURVIVORS and summary.startswith("OK") else 1)
