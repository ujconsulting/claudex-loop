#!/usr/bin/env python3
"""Cold, bound verification of one security-hunt record.

Plan A, stage 1, item 6 (docs/plans/2026-10-27-sicherheitskette, approved round 7).

build_request() turns a hunt record into the verifier's input and returns it together with
the DISPATCH -- what was actually sent: record id, manifest id, the hunt's own status, and
the line ranges clipped to the file. Only paths that are members of the snapshot manifest
are accepted, and their bytes are read only after their sha256 matched the manifest
(inspection round 1, findings 1 and 8). The hunt's verdict, severity and reasoning are
never sent (R1-13).

parse_answer() judges the answer against the DISPATCH, not against a record that may have
changed since (finding 6): exactly one JSON object, no duplicate keys, record_id and
manifest_id as sent, a known result, evidence only inside the sent and existing lines
(R5-4). Everything else is UNRESOLVED with a reason.

Baseline status -- the full two-party matrix (plan item 10, finding 7):
    hunt confirmed        + VERIFIED -> confirmed (needs_validation if evidence is redacted)
    hunt needs_validation + VERIFIED -> needs_validation (a blocker stays a blocker)
    any                   + REFUTED  -> disputed (to the human, with both positions)
    any                   + UNRESOLVED or invalid -> open

Messages are ASCII only.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import hunt_io
import redact_payload

RESULTS = ("VERIFIED", "REFUTED", "UNRESOLVED")
HUNT_STATUSES = ("confirmed", "needs_validation")
_EVIDENCE = re.compile(r"^(?P<path>[^:\s][^:]*):(?P<line>[1-9][0-9]*)$")
_SAFE_PATH = re.compile(r"^(?!/)(?![A-Za-z]:)[^\\\x00]+$")

INSTRUCTIONS = (
    "You are the independent verifier of ONE security finding. You did not find it. "
    "You are read-only. Judge the claim ONLY against the numbered excerpts below, which "
    "are taken from a frozen, redacted snapshot; [REDACTED:<rule>] marks removed secret "
    "material -- never guess it. Answer with EXACTLY one JSON object and nothing else:\n"
    '{"record_id": "<id>", "manifest_id": "<id>", "result": "VERIFIED" | "REFUTED" | '
    '"UNRESOLVED", "evidence": ["<path>:<line>", ...]}\n'
    "VERIFIED needs evidence lines from the excerpts that show the claim holds; REFUTED "
    "needs lines that show it does not; if the excerpts do not decide it, UNRESOLVED.\n"
)


class RecordError(Exception):
    pass


def _member(path: str, manifest: dict) -> str:
    if (not isinstance(path, str) or not _SAFE_PATH.match(path)
            or any(part in ("", ".", "..") for part in path.split("/"))):
        raise RecordError(f"path {path!r} is not a canonical snapshot path")
    if path not in manifest.get("files", {}):
        raise RecordError(f"path {path!r} is not a member of the snapshot manifest")
    return path


def read_verified(snapshot_dir: Path, manifest: dict, path: str) -> list[str]:
    """Lines of a snapshot file, read only after its bytes matched the manifest."""
    path = _member(path, manifest)
    # Regular file only, no link followed, no FIFO blocking (as vendor_skill, finding 25).
    status, data = hunt_io.read_at(Path(snapshot_dir), path)
    if status != "ok":
        raise RecordError(f"{path} is not a readable regular file in the snapshot ({data})")
    if hashlib.sha256(data).hexdigest() != manifest["files"][path]:
        raise RecordError(f"{path} no longer matches the snapshot manifest")
    # The redactor's line rule, not str.splitlines() (closing gate A2-1).
    return redact_payload.split_lines(data.decode("utf-8"))


def build_request(record: dict, snapshot_dir: Path, manifest: dict,
                  manifest_id: str) -> tuple[str, dict]:
    """(prompt text, dispatch). Raises RecordError for a record that cannot be sent."""
    if record.get("hunt_status") not in HUNT_STATUSES:
        raise RecordError(f"record {record.get('id')!r}: hunt_status must be one of {HUNT_STATUSES}")
    if not isinstance(record.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", record["id"]):
        raise RecordError("record id must be 1-64 of [A-Za-z0-9._-]")
    parts = [INSTRUCTIONS,
             f"record_id: {record['id']}\nmanifest_id: {manifest_id}\n",
             f"Title: {record.get('title', '')}\nClaim: {record.get('claim', '')}\n"
             f"Attack path: {record.get('attack', '')}\n"]
    sent = []
    for r in record.get("ranges") or []:
        lines = read_verified(snapshot_dir, manifest, r.get("path"))
        lo, hi = int(r["from_line"]), min(int(r["to_line"]), len(lines))
        if lo < 1 or lo > hi:
            raise RecordError(f"range {r} selects no existing line")
        body = "\n".join(f"{n:>4}| {lines[n - 1]}" for n in range(lo, hi + 1))
        parts.append(f"=== {r['path']} lines {lo}-{hi} ===\n{body}\n")
        sent.append({"path": r["path"], "from_line": lo, "to_line": hi})
    if not sent:
        raise RecordError(f"record {record['id']!r} sends no excerpt")
    dispatch = {"record_id": record["id"], "manifest_id": manifest_id,
                "hunt_status": record["hunt_status"], "title": record.get("title", ""),
                "ranges": sent}
    return "\n".join(parts), dispatch


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _status(hunt_status: str, result: str, evidence: list[str], redacted: dict) -> str:
    if result == "REFUTED":
        return "disputed"
    if result != "VERIFIED":
        return "open"
    if hunt_status != "confirmed":
        return "needs_validation"
    for ev in evidence:
        m = _EVIDENCE.match(ev)
        if m and int(m["line"]) in set(redacted.get(m["path"], [])):
            return "needs_validation"
    return "confirmed"


def _unresolved(reason: str) -> dict:
    return {"result": "UNRESOLVED", "reason": reason, "evidence": [], "baseline_status": "open"}


def parse_answer(text: str, dispatch: dict, exit_code: int,
                 redacted_lines: dict | None = None) -> dict:
    if exit_code == 3:
        return _unresolved("blind run: the verifier's shell was refused (wrapper exit 3)")
    if exit_code == 124:
        return _unresolved("timeout")
    if exit_code != 0:
        return _unresolved(f"wrapper exit {exit_code}")
    text = (text or "").strip()
    if not text:
        return _unresolved("empty answer")
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates)
    except ValueError as exc:
        why = "duplicate key" if "duplicate key" in str(exc) else (
            "answer is not exactly one JSON object" if text.count("{") > 1 else "answer is not json")
        return _unresolved(why)
    if not isinstance(data, dict):
        return _unresolved("answer is not exactly one JSON object")
    if data.get("record_id") != dispatch["record_id"]:
        return _unresolved("record_id does not match the record sent")
    if data.get("manifest_id") != dispatch["manifest_id"]:
        return _unresolved("manifest_id does not match the snapshot sent")
    result = data.get("result")
    if result not in RESULTS:
        return _unresolved("result is not one of VERIFIED, REFUTED, UNRESOLVED")
    evidence = data.get("evidence")
    if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
        return _unresolved("evidence is not a list of path:line strings")
    for ev in evidence:
        m = _EVIDENCE.match(ev)
        if not m or not any(m["path"] == r["path"] and r["from_line"] <= int(m["line"]) <= r["to_line"]
                            for r in dispatch["ranges"]):
            # The reason names no attacker-chosen text: it may reach the ledger.
            return _unresolved("evidence lies outside the sent and existing lines")
    if result in ("VERIFIED", "REFUTED") and not evidence:
        return _unresolved("a decision without evidence")
    return {"result": result, "reason": "", "evidence": evidence,
            "baseline_status": _status(dispatch["hunt_status"], result, evidence, redacted_lines or {})}
