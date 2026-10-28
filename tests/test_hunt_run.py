"""hunt_run: orchestration of the security hunt (plan A, stage 1, items 4-10).

Revised after post-build inspection round 1. Each step is its own CLI call:
prepare -> skill-file -> log-agent -> request -> judge -> publish.

- prepare: run directory below the scratch BASE (no redirected component created
  through), private original manifest, coverage classification current/historical/none
  (findings 3, 15, 16);
- every ledger line is redacted whole; a scanner that cannot run aborts the step and
  writes nothing (findings 4, 5); every agent answer is logged (finding 17);
- request stores the DISPATCH; judge parses against it, not against the record (6);
- skill-file re-verifies the skill copy on every read (8).

Scanner: a deterministic fake (finding 21) -- the real gitleaks is covered in
tests/test_redact_payload.py. Written before the revision and seen failing first.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hunt_run as hr  # noqa: E402
import redact_payload  # noqa: E402
import vendor_skill  # noqa: E402

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
WINDOWS = os.name == "nt"


def fake_gitleaks(directory, work_dir=None):
    out = []
    for p in Path(directory).rglob("*"):
        if p.is_file():
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                for m in re.finditer(r"ghp_[A-Za-z0-9]{36}", line):
                    out.append({"File": str(p), "Secret": m.group(0), "RuleID": "github-pat",
                                "StartLine": n})
    return out


@pytest.fixture(autouse=True)
def _no_real_scanner(monkeypatch):
    monkeypatch.setattr(redact_payload, "gitleaks_scan", fake_gitleaks)
    monkeypatch.setattr(hr, "_vendor_copy", lambda run_dir, base: None)  # no network


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
    (r / "db.py").write_text("".join(f"x{i} = {i}\n" for i in range(1, 20)) +
                             f'KEY = "{TOKEN}"\n', encoding="utf-8")
    subprocess.run(["git", "-C", str(r), "add", "db.py"], check=True)
    return r


@pytest.fixture
def scratch(tmp_path):
    s = tmp_path / "scratch"
    s.mkdir()
    return s


@pytest.fixture
def prepared(repo, scratch, tmp_path):
    return hr.prepare(repo, scratch, coverage_root=tmp_path / "cov")


@pytest.fixture
def run(prepared):
    return prepared[0]


RECORD = {"id": "R-1", "title": "t", "claim": "c", "attack": "a", "hunt_status": "confirmed",
          "verdict": "confirmed", "severity": "high", "reasoning": "r",
          "ranges": [{"path": "db.py", "from_line": 1, "to_line": 5}]}


def _answer(run, **over):
    a = {"record_id": "R-1", "manifest_id": run.snapshot.manifest_id, "result": "VERIFIED",
         "evidence": ["db.py:3"]}
    a.update(over)
    return json.dumps(a)


def _ledger(run):
    return [json.loads(x) for x in run.ledger_path.read_text(encoding="utf-8").splitlines()]


def test_prepare_builds_a_redacted_snapshot_and_a_private_original_manifest(run, tmp_path):
    assert run.run_dir.name.startswith("hunt-")
    assert TOKEN not in (run.snapshot.input_dir / "db.py").read_text(encoding="utf-8")
    assert run.snapshot.redacted_lines["db.py"] == [20]
    assert (tmp_path / "cov" / run.repo_key / f"{run.run_id}.original.json").is_file()
    state = (run.run_dir / "state.json").read_text(encoding="utf-8")
    assert run.snapshot.original_manifest["files"]["db.py"] not in state  # finding 16


def test_request_stores_prompt_and_dispatch_and_judge_uses_the_dispatch(run):
    prompt = hr.request(run, RECORD)
    text = prompt.read_text(encoding="utf-8")
    assert run.snapshot.manifest_id in text and TOKEN not in text and "the hunter" not in text
    dispatch = json.loads((run.run_dir / "requests" / "R-1.dispatch.json").read_text(encoding="utf-8"))
    assert dispatch["ranges"] == [{"path": "db.py", "from_line": 1, "to_line": 5}]
    res = hr.judge(run, "R-1", _answer(run), exit_code=0)
    assert res["baseline_status"] == "confirmed"
    assert _ledger(run)[-1]["record_id"] == "R-1"


def test_judge_without_a_request_is_refused(run):
    with pytest.raises(hr.HuntError):
        hr.judge(run, "R-9", "", exit_code=0)


def test_a_request_that_would_carry_a_secret_is_refused(run):
    with pytest.raises(hr.HuntError):
        hr.request(run, dict(RECORD, claim=f"the key {TOKEN} leaks"))


def test_a_record_path_outside_the_snapshot_is_refused(run):
    with pytest.raises(hr.HuntError):
        hr.request(run, dict(RECORD, ranges=[{"path": "../repo/db.py", "from_line": 1, "to_line": 2}]))


def test_no_ledger_field_carries_the_secret(run):
    """Finding 4: the reason and other fields used to bypass the answer's redaction."""
    hr.request(run, RECORD)
    hr.judge(run, "R-1", _answer(run, note=f"key {TOKEN}", evidence=[f"{TOKEN}:1"]), exit_code=0)
    hr.log_agent(run, "hunter", "db", f"I saw {TOKEN} and password = \"horse horse\"")
    raw = run.ledger_path.read_text(encoding="utf-8")
    assert TOKEN not in raw and "horse horse" not in raw


def test_a_failing_scanner_aborts_and_writes_nothing(run, monkeypatch):
    """Finding 5: a scanner failure used to be swallowed and the result kept."""
    hr.request(run, RECORD)
    before = run.ledger_path.read_bytes()

    def broken(directory, work_dir=None):
        raise redact_payload.RedactError("gitleaks exited 2")
    monkeypatch.setattr(redact_payload, "gitleaks_scan", broken)
    with pytest.raises(hr.HuntError):
        hr.judge(run, "R-1", _answer(run), exit_code=0)
    assert run.ledger_path.read_bytes() == before


def test_a_reloaded_run_appends_to_the_same_ledger(run):
    run.ledger.close()
    again = hr.load(run.run_dir)
    hr.log_agent(again, "critic", "db", "no further issue")
    assert [e["event"] for e in _ledger(again)] == ["prepared", "agent_response"]


def test_a_tampered_snapshot_refuses_to_load(run):
    run.ledger.close()
    (run.snapshot.input_dir / "db.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(hr.HuntError):
        hr.load(run.run_dir)


def test_publish_writes_report_coverage_and_a_valid_descriptor(run, repo, tmp_path):
    out = hr.publish(run, coverage=[{"unit": "db", "files": ["db.py"]}])
    assert out["report"].parent == repo / "docs" / "audit"
    done = json.loads(out["done"].read_text(encoding="utf-8"))
    for key in ("original_manifest", "coverage"):
        assert done[key + "_sha256"] == hashlib.sha256(out[key].read_bytes()).hexdigest()
    assert hr.latest_complete_run(tmp_path / "cov", run.repo_key)["run_id"] == run.run_id
    with pytest.raises(hr.HuntError):
        hr.publish(run, coverage=[])  # never overwrites


def test_coverage_is_current_only_while_the_original_bytes_are_unchanged(repo, scratch, tmp_path):
    """Finding 15: the classification used to be computed nowhere."""
    run1, cov1 = hr.prepare(repo, scratch, coverage_root=tmp_path / "cov")
    assert cov1["status"] == "none"
    hr.publish(run1, coverage=[{"unit": "db"}])
    run1.ledger.close()
    _, cov2 = hr.prepare(repo, scratch, coverage_root=tmp_path / "cov")
    assert cov2["status"] == "current"
    # A changed ORIGINAL secret leaves the redacted view identical -- still historical.
    (repo / "db.py").write_text((repo / "db.py").read_text(encoding="utf-8").replace(
        TOKEN, "ghp_" + "Z" * 36), encoding="utf-8")
    _, cov3 = hr.prepare(repo, scratch, coverage_root=tmp_path / "cov")
    assert cov3["status"] == "historical"


def test_a_broken_completion_descriptor_is_ignored(run, tmp_path):
    out = hr.publish(run, coverage=[])
    out["coverage"].write_bytes(b"[]\n tampered")
    assert hr.latest_complete_run(tmp_path / "cov", run.repo_key) is None


def test_skill_file_reverifies_the_copy(run, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(vendor_skill, "read_verified",
                        lambda d, rel, sha: calls.append(rel) or b"ok")
    run.skill_dir = tmp_path
    assert hr.skill_file(run, "skills/security-audit/SKILL.md") == b"ok"
    assert calls == ["skills/security-audit/SKILL.md"]


def _redirect(link, target):
    if WINDOWS:
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_nothing_is_created_through_a_redirected_scratch_component(repo, scratch, tmp_path):
    """Finding 3: mkdir(parents=True) used to create below a junction before any check."""
    outside = tmp_path / "outside"
    outside.mkdir()
    _redirect(scratch / "security-hunt", outside)
    with pytest.raises(hr.HuntError):
        hr.prepare(repo, scratch, coverage_root=tmp_path / "cov")
    assert list(outside.iterdir()) == []


def test_the_hunt_never_touches_the_shared_log_or_the_baseline(run, repo):
    hr.publish(run, coverage=[])
    assert not (repo / "PLAN-REVIEW-LOG.md").exists()
    assert not list((repo / "docs" / "audit").glob("*-baseline.md"))


def test_a_failed_ledger_entry_leaves_no_completion_descriptor(run, tmp_path, monkeypatch):
    """Inspection round 2, finding 26: `done` was written before the ledger entry, so a
    failed append left a run that later counted as covered without a published entry."""
    def fail(event):
        raise OSError("disk full")
    monkeypatch.setattr(run.ledger, "append", fail)
    with pytest.raises(hr.HuntError):
        hr.publish(run, coverage=[{"unit": "db"}])
    assert not list((tmp_path / "cov" / run.repo_key).glob("*.done.json"))
    assert hr.latest_complete_run(tmp_path / "cov", run.repo_key) is None


def test_a_direct_ledger_append_is_redacted_by_the_guard(run):
    """Inspection round 2, finding 4: the guard was only exercised through judge/log_agent;
    any OTHER caller of run.ledger.append must be redacted as well."""
    run.ledger.append({"event": "note", "text": f"saw {TOKEN} and password = \"horse horse\""})
    raw = run.ledger_path.read_text(encoding="utf-8")
    assert TOKEN not in raw and "horse horse" not in raw
    assert _ledger(run)[-1]["event"] == "note"


def test_the_published_report_is_redacted(run):
    """Finding 4: a finding title or evidence carrying a secret must not reach docs/audit."""
    out = hr.publish(run, coverage=[], findings=[{
        "record_id": "R-1", "title": f"hardcoded {TOKEN}", "baseline_status": "new",
        "evidence": [f"db.py:1 {TOKEN}"]}])
    text = out["report"].read_text(encoding="utf-8")
    assert TOKEN not in text and "R-1" in text


def test_bundle_numbers_verified_snapshot_lines(run):
    """Inspection round 2, finding 8: bundles were hand-built from input/, unbound to the
    manifest. `bundle` re-checks every file and carries only snapshot content."""
    text = hr.bundle(run, ["db.py"])
    assert text.startswith("=== db.py ===\n")
    assert "    1| x1 = 1" in text
    assert TOKEN not in text  # the redacted snapshot, never the repository


def test_bundle_refuses_tampering_non_members_and_oversize(run):
    with pytest.raises(hr.HuntError):
        hr.bundle(run, ["../repo/db.py"])
    with pytest.raises(hr.HuntError, match="split"):
        hr.bundle(run, ["db.py"], max_bytes=10)
    (run.snapshot.input_dir / "db.py").write_bytes(b"tampered\n")
    with pytest.raises(hr.HuntError):
        hr.bundle(run, ["db.py"])


def test_a_file_name_carrying_a_secret_never_reaches_a_bundle(repo, scratch, tmp_path):
    """Closing gate B-1: bundle headers carried repository file names nobody scanned."""
    (repo / f"{TOKEN}.py").write_text("x = 1\n", encoding="utf-8")
    run, _ = hr.prepare(repo, scratch, coverage_root=tmp_path / "cov")
    name = next(p for p in run.snapshot.manifest["files"] if p.startswith("ghp_"))
    with pytest.raises(hr.HuntError, match="secret"):
        hr.bundle(run, [name])
    assert hr.bundle(run, ["db.py"])  # other files stay usable


def test_ledger_keys_are_redacted_too(run):
    """Closing gate B-2: the guard redacted values only; paths are keys in `refused`."""
    run.ledger.append({"event": "note", "refused": {f"dir/{TOKEN}.bin": "binary"}})
    assert TOKEN not in run.ledger_path.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="file symlinks need privileges on Windows; a "
                    "junction to a directory fails without the control too, so it proves nothing")
def test_control_files_are_read_without_following_links(run, tmp_path):
    """Closing gate B-3: state, dispatch and coverage files were read by pathname. A link
    to an identical copy must refuse -- with read_bytes() it loaded fine."""
    run.ledger.close()
    state = run.run_dir / "state.json"
    real = tmp_path / "state.copy.json"
    real.write_bytes(state.read_bytes())
    state.unlink()
    state.symlink_to(real)
    with pytest.raises(hr.HuntError):
        hr.load(run.run_dir)


def test_bundle_out_name_is_exclusive_and_plain(run, capsys):
    run.ledger.close()
    assert hr.main(["bundle", "--run", str(run.run_dir), "--path", "db.py", "--out-name", "u1.txt"]) == 0
    assert (run.run_dir / "work" / "u1.txt").read_bytes().startswith(b"=== db.py ===")
    assert hr.main(["bundle", "--run", str(run.run_dir), "--path", "db.py", "--out-name", "u1.txt"]) == 2
    assert hr.main(["bundle", "--run", str(run.run_dir), "--path", "db.py", "--out-name", "../x.txt"]) == 2


def test_prepare_creates_the_input_directories(run):
    for d in ("work", "requests", "records", "answers"):
        assert (run.run_dir / d).is_dir(), d


def test_a_cli_input_outside_the_run_directory_refuses(run, tmp_path):
    """Gate recheck B-3: control files are read below a trusted root, not their parent."""
    run.ledger.close()
    stray = tmp_path / "stray.txt"
    stray.write_text("answer\n", encoding="utf-8")
    assert hr.main(["log-agent", "--run", str(run.run_dir), "--role", "hunter",
                    "--unit", "db", "--response", str(stray)]) == 2


def test_a_redirected_ancestor_below_the_run_dir_refuses_a_control_read(run, tmp_path):
    """Gate recheck B-3: `requests/` replaced by a link to a directory holding a
    `sub/R.dispatch.json` -- the immediate parent looked ordinary."""
    outside = tmp_path / "outside"
    (outside / "sub").mkdir(parents=True)
    (outside / "sub" / "R.json").write_text("{}", encoding="utf-8")
    req = run.run_dir / "requests"
    req.rename(run.run_dir / "requests.old")
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(outside), str(req))
    else:
        req.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        hr._read(req / "sub" / "R.json", run.run_dir)
