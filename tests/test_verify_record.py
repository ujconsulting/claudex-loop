"""verify_record: cold, bound verification of one hunt record (plan A, stage 1, item 6).

- only snapshot-manifest members are read, and only after their bytes matched the
  manifest (inspection round 1, findings 1 and 8);
- the request carries only title, claim, attack path and the SENT ranges -- never the
  hunt's verdict, severity or reasoning (R1-13); what was sent is returned as a DISPATCH;
- the answer is judged against the dispatch: exactly one JSON object, no duplicate keys,
  bound ids, evidence only on sent AND existing lines (R5-4, finding 6);
- the baseline status follows the full two-party matrix (finding 7).

Written before the change it tests and seen failing first.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_record as vr  # noqa: E402

MID = "a" * 64


def _record(**over):
    r = {"id": "R-7", "title": "SQL injection in search", "claim": "user input reaches the query",
         "attack": "GET /search?q=' OR 1=1 --", "hunt_status": "confirmed", "verdict": "confirmed",
         "severity": "high", "reasoning": "the hunter is sure",
         "ranges": [{"path": "app/db.py", "from_line": 10, "to_line": 14}]}
    r.update(over)
    return r


@pytest.fixture
def snap(tmp_path):
    (tmp_path / "app").mkdir()
    data = "".join(f"line {i}\n" for i in range(1, 31)).encode()
    (tmp_path / "app" / "db.py").write_bytes(data)
    (tmp_path.parent / "outside.txt").write_text("OUTSIDE SECRET\n", encoding="utf-8")
    manifest = {"files": {"app/db.py": hashlib.sha256(data).hexdigest()}, "refused": {}}
    return tmp_path, manifest


def _dispatch(snap, **over):
    d, m = snap
    return vr.build_request(_record(**over), d, m, MID)[1]


def _answer(**over):
    base = {"record_id": "R-7", "manifest_id": MID, "result": "VERIFIED", "evidence": ["app/db.py:12"]}
    base.update(over)
    return json.dumps(base)


def test_request_is_cold_and_returns_what_was_sent(snap):
    d, m = snap
    text, dispatch = vr.build_request(_record(), d, m, MID)
    for leaked in ("the hunter is sure", "severity", "verdict", "reasoning"):
        assert leaked not in text, leaked
    assert "  12| line 12" in text and "  20| line 20" not in text
    assert dispatch["ranges"] == [{"path": "app/db.py", "from_line": 10, "to_line": 14}]


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "C:/x", "app/../app/db.py",
                                  "app\\db.py", "nope.py"])
def test_only_manifest_members_are_read(snap, path):
    d, m = snap
    with pytest.raises(vr.RecordError):
        vr.build_request(_record(ranges=[{"path": path, "from_line": 1, "to_line": 2}]), d, m, MID)


def test_a_file_changed_after_the_snapshot_is_refused(snap):
    d, m = snap
    (d / "app" / "db.py").write_text("changed\n", encoding="utf-8")
    with pytest.raises(vr.RecordError):
        vr.build_request(_record(), d, m, MID)


def test_a_same_length_manipulation_is_refused_by_hash(snap):
    """Inspection round 2, finding 27: the old test changed the line count, so a check on
    line count alone would have passed it. Same lines, same length, one byte different."""
    d, m = snap
    data = (d / "app" / "db.py").read_bytes()
    (d / "app" / "db.py").write_bytes(data.replace(b"line 12\n", b"LINE 12\n"))
    assert len((d / "app" / "db.py").read_bytes()) == len(data)
    with pytest.raises(vr.RecordError, match="no longer matches"):
        vr.build_request(_record(), d, m, MID)


def test_ranges_are_clipped_to_the_file(snap):
    d, m = snap
    _, dispatch = vr.build_request(_record(ranges=[{"path": "app/db.py", "from_line": 28,
                                                    "to_line": 999}]), d, m, MID)
    assert dispatch["ranges"][0]["to_line"] == 30


def test_a_record_without_hunt_status_is_refused(snap):
    d, m = snap
    with pytest.raises(vr.RecordError):
        vr.build_request(_record(hunt_status=None), d, m, MID)


def test_a_good_answer_verifies(snap):
    assert vr.parse_answer(_answer(), _dispatch(snap), exit_code=0)["result"] == "VERIFIED"


@pytest.mark.parametrize("text,why", [
    ("", "empty"),
    ("not json", "json"),
    (_answer() + "\n" + _answer(), "exactly one"),
    ('{"record_id":"R-7","manifest_id":"' + MID + '","result":"REFUTED","result":"VERIFIED",'
     '"evidence":["app/db.py:12"]}', "duplicate key"),
    (_answer(record_id="R-8"), "record_id"),
    (_answer(manifest_id="b" * 64), "manifest_id"),
    (_answer(result="MAYBE"), "result"),
    (_answer(evidence=["app/db.py:99"]), "outside"),
    (_answer(evidence=["app/db.py:20"]), "outside"),   # exists in the snapshot, but not sent
    (_answer(evidence=["missing.py:999"]), "outside"),
    (_answer(evidence="app/db.py:12"), "evidence"),
])
def test_anything_off_is_unresolved(snap, text, why):
    res = vr.parse_answer(text, _dispatch(snap), exit_code=0)
    assert res["result"] == "UNRESOLVED"
    assert why in res["reason"]


def test_evidence_beyond_eof_inside_the_claimed_bounds_is_refused(snap):
    """Finding 6: the claimed bound reached past EOF; the dispatch is clipped."""
    disp = _dispatch(snap, ranges=[{"path": "app/db.py", "from_line": 25, "to_line": 999}])
    res = vr.parse_answer(_answer(evidence=["app/db.py:500"]), disp, exit_code=0)
    assert res["result"] == "UNRESOLVED"


def test_a_reason_never_echoes_attacker_text(snap):
    res = vr.parse_answer(_answer(evidence=["SECRET-VALUE:1"]), _dispatch(snap), exit_code=0)
    assert "SECRET-VALUE" not in res["reason"]


@pytest.mark.parametrize("code,why", [(3, "blind"), (124, "timeout"), (1, "exit")])
def test_wrapper_failures_are_unresolved(snap, code, why):
    res = vr.parse_answer(_answer(), _dispatch(snap), exit_code=code)
    assert res["result"] == "UNRESOLVED" and why in res["reason"]


@pytest.mark.parametrize("hunt,result,redacted,expected", [
    ("confirmed", "VERIFIED", {}, "confirmed"),
    ("confirmed", "VERIFIED", {"app/db.py": [12]}, "needs_validation"),
    ("needs_validation", "VERIFIED", {}, "needs_validation"),   # finding 7
    ("confirmed", "REFUTED", {}, "disputed"),
    ("needs_validation", "REFUTED", {}, "disputed"),
    ("confirmed", "UNRESOLVED", {}, "open"),
])
def test_baseline_status_matrix(snap, hunt, result, redacted, expected):
    ans = _answer(result=result, evidence=[] if result == "UNRESOLVED" else ["app/db.py:12"])
    res = vr.parse_answer(ans, _dispatch(snap, hunt_status=hunt), exit_code=0, redacted_lines=redacted)
    assert res["baseline_status"] == expected


def test_excerpt_lines_use_the_redactors_line_rule(tmp_path):
    """Closing gate A2-1: a vertical tab before a redacted secret moved it from line 1
    (redactor) to line 2 (excerpt), and evidence on it came back `confirmed`."""
    data = b"a\vpassword = \"[REDACTED:named-secret-dq]\"\nb\n"
    (tmp_path / "f.py").write_bytes(data)
    m = {"files": {"f.py": hashlib.sha256(data).hexdigest()}, "refused": {}}
    lines = vr.read_verified(tmp_path, m, "f.py")
    assert len(lines) == 2 and lines[0].startswith("a\v")


def test_a_snapshot_member_replaced_by_a_link_is_refused(snap, tmp_path):
    import os
    d, m = snap
    target = d / "app" / "db.py"
    real = target.read_bytes()
    (tmp_path.parent / "copy.py").write_bytes(real)
    target.unlink()
    if os.name == "nt":
        pytest.skip("file symlinks need privileges on Windows")
    target.symlink_to(tmp_path.parent / "copy.py")  # same bytes, but a link
    with pytest.raises(vr.RecordError, match="regular file"):
        vr.read_verified(d, m, "app/db.py")
