"""Mutation probe for wrapper 2.6.0: every guard removed must turn a test red.

    python tests/mutation_probe_codex_ro_blind.py

Not collected by pytest (no `test_` prefix) and not part of CI: it REWRITES
scripts/codex_ro.py or scripts/wrapper_drift.py for the duration of each mutant
and restores them afterwards (also on Ctrl-C, via `finally`). A mutant that
prints `SURVIVED` names a guard no test notices. Same method as
mutation_probe_gate_reminder.py, which found three such guards on 2026-09-21.
"""
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
WRAPPER = REPO / "scripts" / "codex_ro.py"
DRIFT = REPO / "scripts" / "wrapper_drift.py"
ORIGINALS = {WRAPPER: WRAPPER.read_bytes(), DRIFT: DRIFT.read_bytes()}
SUITES = {
    WRAPPER: ["tests.test_codex_ro_260", "tests.test_codex_ro", "tests.test_gate_findings_260",
              "tests.test_launch_260", "tests.test_gate_recheck1_260"],
    DRIFT: ["tests.test_wrapper_drift_260", "tests.test_wrapper_drift", "tests.test_gate_findings_260",
            "tests.test_gate_recheck1_260"],
}


def run(target):
    r = subprocess.run([sys.executable, "-m", "unittest", *SUITES[target]],
                       cwd=REPO, capture_output=True, text=True)
    tail = r.stderr.strip().splitlines()
    fails = sorted({ln.split(" (")[0] for ln in tail if ln.startswith(("FAIL:", "ERROR:"))})
    return (tail[-1] if tail else "?"), fails


MUTANTS = [
    # --- J: evidence and the blind rule ---
    (WRAPPER, "a non-integer exit code counts as executed",
     b'if type(code) is int and item.get("status") in EXECUTED_STATUSES:',
     b'if code is not None:'),
    (WRAPPER, "JSON true counts as an exit code",
     b'if type(code) is int and item.get("status") in EXECUTED_STATUSES:',
     b'if isinstance(code, int) and item.get("status") in EXECUTED_STATUSES:'),
    (WRAPPER, "earlier turns count again (resume)",
     b"                ev.turn_failed = False\n                ev.executed = 0\n                ev.unclassified = 0\n",
     b"                ev.turn_failed = False\n"),
    (WRAPPER, "a truncated turn is usable",
     b"and self.saw_thread and self.saw_turn and self.complete)",
     b"and self.saw_thread and self.saw_turn)"),
    (WRAPPER, "broken stream lines are ignored",
     b"            except ValueError:\n                ev.bad_lines += 1\n                continue\n",
     b"            except ValueError:\n                continue\n"),
    (WRAPPER, "the size limit is not enforced",
     b"            if consumed > limit:\n                yield line, True\n",
     b"            if False:\n                yield line, True\n"),
    (WRAPPER, "reads are unbounded",
     b"            line = handle.readline(limit - consumed + 1)\n",
     b"            line = handle.readline()\n"),
    (WRAPPER, "a stderr refusal no longer counts",
     b"    if refusals:\n        reasons.append(",
     b"    if False:\n        reasons.append("),
    (WRAPPER, "unusable evidence no longer counts",
     b"    if not ev.usable:\n        reasons.append(ev.problem())",
     b"    if False:\n        reasons.append(ev.problem())"),
    (WRAPPER, "an unclassifiable command no longer counts",
     b"    if ev.unclassified:\n        reasons.append(",
     b"    if False:\n        reasons.append("),
    (WRAPPER, "oversized stderr no longer counts",
     b"    if not stderr_whole:\n        reasons.append(",
     b"    if False:\n        reasons.append("),
    (WRAPPER, "any run passes as having executed",
     b"    if ev.executed > 0:\n", b"    if ev.executed >= 0:\n"),
    # --- A: version ---
    (WRAPPER, "an unreadable version passes for a listed model",
     b"    if version is None or not cli_at_least(version, minimum):",
     b"    if version is not None and not cli_at_least(version, minimum):"),
    (WRAPPER, "a prerelease counts as the release",
     b'    return numbers + ((0, pre) if pre else (1, ""))',
     b'    return numbers + ((1, pre) if pre else (1, ""))'),
    (WRAPPER, "version output accepted with trailing text",
     rb'CLI_VERSION_RE = re.compile(rb"\Acodex-cli (\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\r?\n?\Z")',
     rb'CLI_VERSION_RE = re.compile(rb"\Acodex-cli (\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)")'),
    # --- I: isolation ---
    (WRAPPER, "user config loaded again",
     b'    argv += ["--ignore-user-config", "--ignore-rules", "-c", \'web_search="disabled"\']',
     b'    argv += ["--ignore-rules", "-c", \'web_search="disabled"\']'),
    (WRAPPER, "features no longer disabled",
     b'    for feature in ISOLATION_DISABLE:\n        argv += ["--disable", feature]\n',
     b''),
    (WRAPPER, "a caller may mark a project trusted",
     b'    "projects",\n    "developer_instructions",',
     b'    "developer_instructions",'),
    (WRAPPER, "a project config is not a hit",
     b"        if not is_user_config:\n            hits.append(candidate)",
     b"        if False:\n            hits.append(candidate)"),
    (WRAPPER, "an uncheckable ancestor is not a hit",
     b"        except OSError:\n            hits.append(candidate)\n            continue\n",
     b"        except OSError:\n            continue\n"),
    # --- W1 in the wrapper, J4c locks ---
    (WRAPPER, "reparse check fails open again",
     b"    except FileNotFoundError:\n        return False\n    except OSError:\n        return True\n",
     b"    except FileNotFoundError:\n        return False\n    except OSError:\n        return False\n"),
    (WRAPPER, "missing Windows attribute passes",
     b"    if attrs is None:\n        return True\n", b"    if attrs is None:\n        return False\n"),
    (WRAPPER, "new parents not rechecked",
     b"        if _is_reparse_point(level) or not level.is_dir():",
     b"        if False:"),
    (WRAPPER, "locks are not exclusive",
     b"        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, \"O_BINARY\", 0)",
     b"        flags = os.O_WRONLY | os.O_CREAT | getattr(os, \"O_BINARY\", 0)"),
    (WRAPPER, "a lock file may be named as an output",
     b"        if _case_key(path.name).endswith(_case_key(LOCK_SUFFIX)):",
     b"        if False:"),
    # --- closing-gate fixes (2026-09-30) ---
    (WRAPPER, "a failed turn can be completed afterwards",
     b"                ev.complete = ev.saw_turn and not ev.turn_failed\n",
     b"                ev.complete = ev.saw_turn\n"),
    (WRAPPER, "a forged thread id is printed",
     b"    if evidence.thread_id and THREAD_ID_RE.match(evidence.thread_id):\n",
     b"    if evidence.thread_id:\n"),
    (WRAPPER, "a start failure is a traceback again",
     b"        except OSError as exc:\n            # The binary answered the version probe",
     b"        except ZeroDivisionError as exc:\n            # The binary answered the version probe"),
    (WRAPPER, "a refused run keeps the directories it created",
     b"                directory.rmdir()\n", b"                pass\n"),
    (DRIFT, "a short write is shipped",
     b"        view = view[written:]\n", b"        view = view[len(view):]\n"),
    (DRIFT, "the staged copy is not verified before the replace",
     b"        if hashlib.sha256(staging.read_bytes()).hexdigest() != expected:\n",
     b"        if False:\n"),
    (DRIFT, "only the last folder is rechecked",
     b"    for component in components_between(top, folder):\n        if _is_reparse_point(component):\n            raise Refused(",
     b"    for component in [folder]:\n        if _is_reparse_point(component):\n            raise Refused("),
    (DRIFT, "an unknown drive type counts as local",
     b"    return _drive_type(drive) not in _LOCAL_DRIVE_TYPES\n",
     b"    return _drive_type(drive) == 4\n"),
    (DRIFT, "ownership no longer checked on the chain",
     b"            if problem:\n                raise Refused(f\"{component}: {problem} ({moment})\")\n",
     b"            if False:\n                raise Refused(f\"{component}: {problem} ({moment})\")\n"),
    # --- closing gate, recheck 1 ---
    (WRAPPER, "a closed turn still takes command events",
     b'            elif isinstance(kind, str) and kind.startswith("item.") and ev.turn_closed:\n',
     b'            elif False:\n'),
    (WRAPPER, "a directory someone else created is ours to clean up",
     b"        else:\n            made.append(level)\n",
     b"        finally:\n            made.append(level)\n"),
    (WRAPPER, "only a lock collision cleans up",
     b"    try:\n        for label, path in targets.items():\n            created += prepare_write_target(path, label)\n        locks = acquire_locks(",
     b"    for label, path in targets.items():\n        created += prepare_write_target(path, label)\n    try:\n        locks = acquire_locks("),
    (WRAPPER, "levels made before a failure inside the chain stay behind",
     b"    for level in reversed(made):\n        try:\n            level.rmdir()\n",
     b"    for level in []:\n        try:\n            level.rmdir()\n"),
    # --- Z: no batch file between the wrapper and Codex ---
    (WRAPPER, "a batch file may be started",
     b'    if Path(launch[0]).suffix.lower() in (".cmd", ".bat"):\n',
     b'    if False:\n'),
    (WRAPPER, "the npm starter is used as is",
     b"            launch = _node_launch(Path(starter))\n",
     b"            launch = [starter]\n"),
    (WRAPPER, "node beside the starter is ignored",
     b"    node = str(beside) if beside.is_file() else shutil.which(\"node.exe\")\n",
     b"    node = shutil.which(\"node.exe\")\n"),
    (WRAPPER, "the probe starts something else than the run",
     b"    cli_version = probe_cli_version(launch)\n",
     b"    cli_version = probe_cli_version([executable])\n"),
    # --- W: wrapper_drift ---
    (DRIFT, "update without a private root",
     b"        if not args.private_root:\n", b"        if False:\n"),
    (DRIFT, "scripts-dir allowed with update",
     b"    if writing and args.scripts_dir is not None:\n", b"    if False:\n"),
    (DRIFT, "containment by string prefix",
     b"            if os.path.commonpath([repo_key, root_key]) == root_key:\n",
     b"            if repo_key.startswith(root_key):\n"),
    (DRIFT, "no recheck right after mkstemp",
     b'            _check_chain(top, folder, "right after the staging file was created")\n',
     b''),
    (DRIFT, "no recheck before replace",
     b'        _check_chain(top, folder, "before the replace")\n', b''),
    (DRIFT, "raw repo path not checked",
     b"    for raw in [*args.repo, *args.scan]:\n        problem = check_raw_repo(raw)\n",
     b"    for raw in []:\n        problem = check_raw_repo(raw)\n"),
    (DRIFT, "drive root accepted as private root",
     b'        return "it is a drive or filesystem root"\n', b'        pass\n'),
]

SURVIVORS = []
try:
    for target, name, old, new in MUTANTS:
        orig = ORIGINALS[target]
        if b"\r\n" in orig:
            # A checkout with core.autocrlf=true has CRLF in the working tree.
            old, new = old.replace(b"\n", b"\r\n"), new.replace(b"\n", b"\r\n")
        assert orig.count(old) == 1, f"mutant '{name}': anchor found {orig.count(old)}x"
        target.write_bytes(orig.replace(old, new, 1))
        summary, fails = run(target)
        target.write_bytes(orig)
        if not fails:
            SURVIVORS.append(name)
        print(f"MUTANT {name!r}: {summary}" + ("" if fails else "   <-- SURVIVED"))
finally:
    for target, orig in ORIGINALS.items():
        target.write_bytes(orig)

ok = True
for target in (WRAPPER, DRIFT):
    summary, _ = run(target)
    identical = target.read_bytes() == ORIGINALS[target]
    print(f"RESTORED {target.name}: {summary} | identical: {identical}")
    ok = ok and summary.startswith("OK") and identical
print("SURVIVORS:", SURVIVORS or "none")
sys.exit(0 if not SURVIVORS and ok else 1)
