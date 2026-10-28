#!/usr/bin/env python3
"""Orchestration of the security hunt (audit Step 3c).

Plan A, stage 1, items 4-10 (docs/plans/2026-10-27-sicherheitskette, approved round 7),
revised after post-build inspection round 1. Steps, each its own CLI call:

  prepare     exclusive run directory below the scratch base, frozen redacted snapshot,
              verified per-run copy of the pinned skill, the PRIVATE original manifest
              (written now, under ~/.claudex/hunt-coverage), the coverage classification
              against the last complete run (current / historical / none), the ledger.
  skill-file  one file of the run's skill copy -- the copy is re-verified on every read.
  bundle      a hunter's input: verified snapshot files, numbered, scanned as a whole,
              written exclusively to <run>/work/<--out-name>.
  log-agent   every hunter / critic / candidate-checker answer, appended to the ledger.
  request     the cold verifier prompt for one record, scanned before it may be sent,
              plus its DISPATCH (what was actually sent), both stored with the run.
  judge       the verifier's answer, parsed against the stored dispatch, appended.
  publish     the report next to the ledger (scanned), the coverage list, the ledger entry
              and LAST the completion descriptor binding original manifest and coverage.

Every string of a ledger event -- values AND keys -- passes the redaction raw, before
serialization; if the redaction cannot run, nothing is written and the step fails
(inspection round 1, findings 4 and 5; closing gate B-2). A bundle is scanned as a whole,
file-name headers included (B-1). Every control file (state, manifests, dispatch,
coverage, CLI input) is read through hunt_io: no link followed, no FIFO (B-3).
The hunt never writes the shared LOG_FILE or the baseline. Temporary files live in the
run directory, never in the OS temp directory (finding 22).

Messages are ASCII only.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402
import hunt_snapshot  # noqa: E402
import redact_payload  # noqa: E402
import vendor_skill  # noqa: E402
import verify_record  # noqa: E402

DEFAULT_COVERAGE_ROOT = Path.home() / ".claudex" / "hunt-coverage"
# The hunt's own outputs are never part of its input: a second run would otherwise see
# the first run's report and ledger as new files and call all coverage historical.
OWN_OUTPUTS = ("docs/audit/*-security-hunt-*",)
_ROLE = re.compile(r"^(hunter|critic|checker|recon)$")
_OUT_NAME = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$")
_UNIT = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")


class HuntError(Exception):
    pass


@dataclass
class Run:
    repo: Path
    repo_key: str
    run_id: str
    run_dir: Path
    scratch: Path
    snapshot: hunt_snapshot.Snapshot
    skill_dir: Path | None
    ledger_path: Path
    private_dir: Path
    ledger: hunt_io.Ledger | None = None

    @property
    def tmp(self) -> Path:
        return self.run_dir / "work"  # not "tmp": skills never name a /tmp path


def _vendor_copy(run_dir: Path, base: Path) -> Path | None:
    return vendor_skill.copy_for_run(vendor_skill.vendor(), run_dir, base=base)


def _repo_key(repo: Path) -> str:
    return hashlib.sha256(str(Path(os.path.abspath(repo))).lower().encode()).hexdigest()[:16]


def _json(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def _read(path: Path, root: Path) -> bytes:
    """Bytes of a regular control file (state, manifests, dispatch, coverage, CLI input),
    read through hunt_io BELOW a trusted `root`: no component between root and the file
    is followed if it is a link, no FIFO blocks, the read is bounded (closing gate B-3;
    recheck: the immediate parent used to be the root, so an alias higher up passed).
    A path outside root refuses. Raises OSError so the callers' error handling applies."""
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise OSError(f"{path} is not below {root}") from exc
    status, data = hunt_io.read_at(root, rel)
    if status != "ok":
        raise OSError(f"{path} refused ({data})")
    return data


def _read_json(path: Path, root: Path):
    return json.loads(_read(path, root).decode("utf-8"))


def _redact_text(run: Run, text: str) -> str:
    """Redaction of one text with the second pass, inside the run's own tmp directory."""
    work = hunt_io.make_dir(run.tmp, f"r{secrets.token_hex(6)}", base=run.scratch)
    try:
        hunt_io.create_file(work, "t.txt", text.encode("utf-8"), base=run.scratch)
        redact_payload.redact_tree(work)
        return _read(work / "t.txt", run.scratch).decode("utf-8")
    except redact_payload.RedactError as exc:
        raise HuntError(f"redaction refused, nothing written: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _redact_values(run: Run, obj):
    """Every string inside `obj` redacted RAW, in one scanner pass (one file per string).

    The guard used to redact the serialized JSON line, where quotes are escaped: a direct
    `ledger.append` carrying `password = "..."` reached the file in clear (inspection
    round 2, finding 4)."""
    strings: list[str] = []

    def collect(o):
        if isinstance(o, str):
            strings.append(o)
        elif isinstance(o, dict):
            for k, v in o.items():  # keys too: repository paths are keys (closing gate B-2)
                collect(k)
                collect(v)
        elif isinstance(o, list):
            for v in o:
                collect(v)
    collect(obj)
    if not strings:
        return obj
    work = hunt_io.make_dir(run.tmp, f"v{secrets.token_hex(6)}", base=run.scratch)
    try:
        for i, text in enumerate(strings):
            hunt_io.create_file(work, f"s{i:05d}.txt", text.encode("utf-8"), base=run.scratch)
        redact_payload.redact_tree(work)
        clean = iter([_read(work / f"s{i:05d}.txt", run.scratch).decode("utf-8")
                      for i in range(len(strings))])
    except redact_payload.RedactError as exc:
        raise HuntError(f"redaction refused, nothing written: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)

    def rebuild(o):
        if isinstance(o, str):
            return next(clean)
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                key = next(clean)  # same order as collect(): key, then value
                if key in out:
                    raise HuntError("redaction made two keys equal; refusing to merge them")
                out[key] = rebuild(v)
            return out
        if isinstance(o, list):
            return [rebuild(v) for v in o]
        return o
    return rebuild(obj)


def _guard(run: Run):
    def guard(line: str) -> str:
        return json.dumps(_redact_values(run, json.loads(line)), ensure_ascii=False, sort_keys=True)
    return guard


def latest_complete_run(coverage_root: Path, repo_key: str) -> dict | None:
    """The newest run whose completion descriptor matches both files, else None."""
    root = Path(coverage_root) / repo_key
    for done in sorted(root.glob("*.done.json"), reverse=True):
        try:
            d = _read_json(done, root)
            rid = d["run_id"]
            if not isinstance(rid, str) or not re.fullmatch(r"hunt-[0-9TZ]+-[0-9a-f]{16}", rid):
                continue
            orig_b = _read(root / f"{rid}.original.json", root)
            cov_b = _read(root / f"{rid}.coverage.json", root)
            if (hashlib.sha256(orig_b).hexdigest() == d["original_manifest_sha256"]
                    and hashlib.sha256(cov_b).hexdigest() == d["coverage_sha256"]):
                return {"run_id": rid, "original_manifest": json.loads(orig_b.decode("utf-8")),
                        "coverage": json.loads(cov_b.decode("utf-8"))}
        except (OSError, ValueError, KeyError):
            continue
    return None


def prepare(repo: Path, scratch: Path, excludes: list[str] | None = None,
            coverage_root: Path = DEFAULT_COVERAGE_ROOT) -> tuple[Run, dict]:
    repo = Path(os.path.abspath(repo))
    scratch = Path(os.path.abspath(scratch))
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"hunt-{stamp}-{secrets.token_hex(8)}"
    key = _repo_key(repo)
    try:
        hunt_base = hunt_io.ensure_dirs(scratch / "security-hunt", base=scratch)
        audit_dir = hunt_io.ensure_dirs(repo / "docs" / "audit", base=repo)
        private = hunt_io.ensure_dirs(Path(coverage_root) / key)
        previous = latest_complete_run(coverage_root, key)
        snap = hunt_snapshot.build_snapshot(repo, hunt_base / run_id,
                                            [*OWN_OUTPUTS, *(excludes or [])],
                                            private_dir=private, base=scratch)
        hunt_io.make_dir(snap.run_dir, "work", base=scratch)
        hunt_io.make_dir(snap.run_dir, "requests", base=scratch)
        hunt_io.make_dir(snap.run_dir, "records", base=scratch)  # inputs you write (gate C2)
        hunt_io.make_dir(snap.run_dir, "answers", base=scratch)  # wrapper --out-file target
        skill_dir = _vendor_copy(snap.run_dir, scratch)
        original = hunt_io.create_file(private, f"{run_id}.original.json",
                                       _json(snap.original_manifest))
    except (hunt_snapshot.SnapshotError, hunt_io.HuntIOError,
            vendor_skill.VendorError, OSError) as exc:
        raise HuntError(f"prepare refused: {exc}") from exc
    if previous is None:
        coverage = {"status": "none", "units": []}
    elif previous["original_manifest"] == snap.original_manifest:
        coverage = {"status": "current", "from_run": previous["run_id"], "units": previous["coverage"]}
    else:
        coverage = {"status": "historical", "from_run": previous["run_id"], "units": previous["coverage"]}
    ledger_name = f"{stamp[:8]}-security-hunt-{run_id}.ledger.jsonl"
    run = Run(repo, key, run_id, snap.run_dir, scratch, snap, skill_dir, audit_dir / ledger_name, private)
    run.ledger = hunt_io.Ledger(audit_dir, ledger_name, base=repo, guard=_guard(run))
    hunt_io.create_file(snap.run_dir, "state.json", _json({
        "repo": str(repo), "run_id": run_id, "scratch": str(scratch), "ledger": str(run.ledger_path),
        "private_dir": str(private), "skill": str(skill_dir) if skill_dir else None,
        "manifest": snap.manifest, "manifest_id": snap.manifest_id,
        "original_manifest_file": str(original),
        "original_manifest_sha256": hashlib.sha256(_read(original, private)).hexdigest(),
        "redacted_lines": snap.redacted_lines}), base=scratch)
    run.ledger.append({"event": "prepared", "run_id": run_id, "manifest_id": snap.manifest_id,
                       "refused": snap.manifest["refused"], "redacted_lines": snap.redacted_lines,
                       "coverage_status": coverage["status"]})
    return run, coverage


def load(run_dir: Path) -> Run:
    """Re-open a prepared run; the snapshot AND the skill copy are re-verified."""
    run_dir = Path(run_dir)
    try:
        st = _read_json(run_dir / "state.json", run_dir)
        # Its own parent is the root here; the bytes are then bound by the sha256 that
        # state.json (read below run_dir) carries, so an alias cannot substitute content.
        orig_path = Path(st["original_manifest_file"])
        orig_b = _read(orig_path, orig_path.parent)
        if hashlib.sha256(orig_b).hexdigest() != st["original_manifest_sha256"]:
            raise HuntError("private original manifest changed")
        snap = hunt_snapshot.Snapshot(run_dir, run_dir / "input", st["manifest"], st["manifest_id"],
                                      json.loads(orig_b.decode("utf-8")),
                                      st["redacted_lines"])
        snap.verify()
        skill = Path(st["skill"]) if st.get("skill") else None
        if skill is not None:
            vendor_skill.verify_tree(skill, vendor_skill.MANIFEST_SHA256)
        run = Run(Path(st["repo"]), _repo_key(Path(st["repo"])), st["run_id"], run_dir,
                  Path(st["scratch"]), snap, skill, Path(st["ledger"]), Path(st["private_dir"]))
        run.ledger = hunt_io.Ledger.reopen(run.ledger_path.parent, run.ledger_path.name,
                                           base=run.repo, guard=_guard(run))
    except (OSError, ValueError, KeyError, hunt_snapshot.SnapshotError, hunt_io.HuntIOError,
            vendor_skill.VendorError) as exc:
        raise HuntError(f"cannot load run {run_dir}: {exc}") from exc
    return run


def _verify_snapshot(run: Run) -> None:
    """A tampered snapshot is a refusal (exit 2), not a traceback."""
    try:
        run.snapshot.verify()
    except hunt_snapshot.SnapshotError as exc:
        raise HuntError(f"refused: {exc}") from exc


BUNDLE_MAX = 200_000


def bundle(run: Run, paths: list[str], max_bytes: int = BUNDLE_MAX) -> str:
    """A hunter's input: snapshot files, numbered, each read only after its bytes matched
    the manifest (inspection round 2, finding 8: the skill told Claude to build bundles
    from `input/` by hand, and nothing bound what an agent saw to the manifest)."""
    _verify_snapshot(run)
    if not paths:
        raise HuntError("a bundle needs at least one snapshot path")
    out: list[str] = []
    for rel in dict.fromkeys(paths):
        try:
            lines = verify_record.read_verified(run.snapshot.input_dir, run.snapshot.manifest, rel)
        except verify_record.RecordError as exc:
            raise HuntError(f"bundle refused: {exc}") from exc
        out.append(f"=== {rel} ===")
        out.extend(f"{n:>5}| {line}" for n, line in enumerate(lines, 1))
    text = "\n".join(out) + "\n"
    if len(text.encode("utf-8")) > max_bytes:
        raise HuntError(f"bundle exceeds {max_bytes} bytes: split the unit")
    # The file contents are redacted; the headers carry repository FILE NAMES, which no
    # redaction saw. Anything the scanner still changes refuses the bundle (closing gate B-1).
    if _redact_text(run, text) != text:
        raise HuntError("bundle refused: a file name or line still carries secret material")
    return text


def skill_file(run: Run, rel: str) -> bytes:
    if run.skill_dir is None:
        raise HuntError("this run has no skill copy")
    try:
        return vendor_skill.read_verified(run.skill_dir, rel, vendor_skill.MANIFEST_SHA256)
    except vendor_skill.VendorError as exc:
        raise HuntError(f"skill file refused: {exc}") from exc


def log_agent(run: Run, role: str, unit: str, response: str) -> None:
    """Every agent answer, verbatim and redacted, appended at once (finding 17)."""
    if not _ROLE.match(role) or not _UNIT.match(unit):
        raise HuntError("role must be hunter|critic|checker|recon; unit a plain identifier")
    # The ledger guard redacts every value raw (_redact_values); nothing to do twice here.
    run.ledger.append({"event": "agent_response", "role": role, "unit": unit,
                       "response": response})


def request(run: Run, record: dict) -> Path:
    """Write the cold verifier prompt and its dispatch; refuse if a secret remains."""
    _verify_snapshot(run)
    try:
        text, dispatch = verify_record.build_request(record, run.snapshot.input_dir,
                                                     run.snapshot.manifest, run.snapshot.manifest_id)
    except (verify_record.RecordError, OSError, ValueError, KeyError) as exc:
        raise HuntError(f"request refused: {exc}") from exc
    work = hunt_io.make_dir(run.tmp, f"q{secrets.token_hex(6)}", base=run.scratch)
    try:
        hunt_io.create_file(work, "prompt.txt", text.encode("utf-8"), base=run.scratch)
        try:
            hits = redact_payload.gitleaks_scan(work, work_dir=run.tmp)
        except redact_payload.RedactError as exc:
            raise HuntError(f"request refused, scanner failed: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if hits:
        raise HuntError(f"request for {record.get('id')} still carries {len(hits)} secret(s)")
    for _rule, rx in redact_payload.PATTERNS:
        for m in rx.finditer(text):
            if not m.group("v").startswith("[REDACTED:"):
                raise HuntError(f"request for {record.get('id')} still carries a secret pattern")
    reqs = run.run_dir / "requests"
    hunt_io.create_file(reqs, f"{dispatch['record_id']}.dispatch.json", _json(dispatch), base=run.scratch)
    return hunt_io.create_file(reqs, f"{dispatch['record_id']}.txt", text.encode("utf-8"), base=run.scratch)


def judge(run: Run, record_id: str, answer: str, exit_code: int) -> dict:
    """Parse against the STORED dispatch (finding 6) and append; a failed redaction of the
    ledger line aborts with nothing written and no result returned (finding 5)."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", record_id or ""):
        raise HuntError("record id must be 1-64 of [A-Za-z0-9._-]")
    try:
        dispatch = _read_json(run.run_dir / "requests" / f"{record_id}.dispatch.json", run.run_dir)
    except (OSError, ValueError) as exc:
        raise HuntError(f"no dispatch for {record_id}: request it first ({exc})") from exc
    res = verify_record.parse_answer(answer, dispatch, exit_code, run.snapshot.redacted_lines)
    stored = answer  # the ledger guard redacts every value raw (_redact_values)
    run.ledger.append({"event": "verified", "record_id": record_id, "title": dispatch.get("title", ""),
                       "hunt_status": dispatch["hunt_status"], "answer": stored,
                       "exit_code": exit_code, **res})
    return res


def publish(run: Run, coverage: list, findings: list[dict] | None = None) -> dict:
    """Report (scanned) next to the ledger, coverage, the ledger entry -- and only then the
    completion descriptor. `done` is what a later run trusts as "covered", so it is written
    LAST: a failed ledger append used to leave a done run with no published entry
    (inspection round 2, finding 26)."""
    stamp = run.run_id.split("-")[1][:8]
    report_text = _redact_text(run, _report(run, findings or []))
    try:
        report = hunt_io.create_file(run.ledger_path.parent, f"{stamp}-security-hunt-{run.run_id}.md",
                                     report_text.encode("utf-8"), base=run.repo)
        orig = run.private_dir / f"{run.run_id}.original.json"
        cov = hunt_io.create_file(run.private_dir, f"{run.run_id}.coverage.json", _json(coverage))
        run.ledger.append({"event": "published", "report": report.name})
        done = hunt_io.create_file(run.private_dir, f"{run.run_id}.done.json", _json({
            "run_id": run.run_id,
            "original_manifest_sha256": hashlib.sha256(_read(orig, run.private_dir)).hexdigest(),
            "coverage_sha256": hashlib.sha256(_read(cov, run.private_dir)).hexdigest()}))
    except (hunt_io.HuntIOError, OSError) as exc:
        raise HuntError(f"publish refused: {exc}") from exc
    return {"report": report, "original_manifest": orig, "coverage": cov, "done": done}


def _report(run: Run, findings: list[dict]) -> str:
    lines = [f"# Security hunt {run.run_id}", "",
             f"- manifest_id: `{run.snapshot.manifest_id}`",
             f"- skill: Cloudflare security-audit @ `{vendor_skill.PINNED_COMMIT}`",
             f"- ledger (verbatim, redacted): `{run.ledger_path.name}`",
             f"- refused inputs: {len(run.snapshot.manifest['refused'])}", "",
             "| record | title | baseline status | evidence |", "|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.get('record_id')} | {f.get('title', '')} | {f.get('baseline_status')} | "
                     f"{', '.join(f.get('evidence', []))} |")
    if not findings:
        lines.append("| - | no records | - | - |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="security hunt steps (audit Step 3c)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--repo", required=True)
    p.add_argument("--scratch", required=True)
    p.add_argument("--exclude", action="append", default=[])
    s = sub.add_parser("skill-file")
    s.add_argument("--run", required=True)
    s.add_argument("--path", required=True)
    g = sub.add_parser("log-agent")
    g.add_argument("--run", required=True)
    g.add_argument("--role", required=True)
    g.add_argument("--unit", required=True)
    g.add_argument("--response", required=True)
    b = sub.add_parser("bundle")
    b.add_argument("--run", required=True)
    b.add_argument("--path", action="append", required=True)
    b.add_argument("--max-bytes", type=int, default=BUNDLE_MAX)
    b.add_argument("--out-name", required=True,
                   help="file name below <run>/work/, created exclusively (no shell redirect)")
    r = sub.add_parser("request")
    r.add_argument("--run", required=True)
    r.add_argument("--record", required=True)
    j = sub.add_parser("judge")
    j.add_argument("--run", required=True)
    j.add_argument("--record-id", required=True)
    j.add_argument("--answer", required=True)
    j.add_argument("--exit-code", type=int, required=True)
    u = sub.add_parser("publish")
    u.add_argument("--run", required=True)
    u.add_argument("--coverage", required=True)
    u.add_argument("--findings")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "prepare":
            run, coverage = prepare(Path(a.repo), Path(a.scratch), a.exclude)
            print(json.dumps({"run_dir": str(run.run_dir), "manifest_id": run.snapshot.manifest_id,
                              "input": str(run.snapshot.input_dir), "skill": str(run.skill_dir),
                              "refused": len(run.snapshot.manifest["refused"]),
                              "coverage": coverage}))
            return 0
        run = load(Path(a.run))
        if a.cmd == "skill-file":
            sys.stdout.buffer.write(skill_file(run, a.path))
        elif a.cmd == "bundle":
            if not _OUT_NAME.match(a.out_name):
                raise HuntError("--out-name must be a plain file name [A-Za-z0-9._-], no leading dot")
            try:  # exclusive, checked creation -- a planted link or FIFO refuses (gate C2-4)
                out = hunt_io.create_file(run.run_dir / "work", a.out_name,
                                          bundle(run, a.path, a.max_bytes).encode("utf-8"),
                                          base=run.scratch)
            except hunt_io.HuntIOError as exc:
                raise HuntError(f"bundle not written: {exc}") from exc
            print(out)
        elif a.cmd == "log-agent":
            log_agent(run, a.role, a.unit, _read(Path(a.response), run.run_dir).decode("utf-8"))
        elif a.cmd == "request":
            print(request(run, _read_json(Path(a.record), run.run_dir)))
        elif a.cmd == "judge":
            ans = _read(Path(a.answer), run.run_dir).decode("utf-8") if os.path.lexists(a.answer) else ""
            print(json.dumps(judge(run, a.record_id, ans, a.exit_code)))
        else:
            cov = _read_json(Path(a.coverage), run.run_dir)
            fnd = _read_json(Path(a.findings), run.run_dir) if a.findings else []
            out = publish(run, cov, fnd)
            print(json.dumps({k: str(v) for k, v in out.items()}))
        return 0
    except (HuntError, OSError, ValueError) as exc:
        sys.stderr.write(f"hunt_run: REFUSED - {str(exc).encode('ascii', 'replace').decode('ascii')}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
