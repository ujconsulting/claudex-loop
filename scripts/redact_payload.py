#!/usr/bin/env python3
"""Redact a directory tree in place before any of it reaches a model.

Plan A, stage 1, item 7 (docs/plans/2026-10-27-sicherheitskette, approved round 7).
Used on the hunt's frozen snapshot (`<run-dir>/input/`) and on every prompt file bound
for `security-verify`. It works on OUR copies, never on the repository: every read and
every rewrite goes through hunt_io (walk_files / read_at / replace_file), so a link, a
junction or a FIFO anywhere in the tree refuses instead of being followed (closing gate
A1-2; Windows residual R5-1 as in hunt_io).

- Detection: gitleaks with the plugin config (config/gitleaks.toml via -c, so a
  repository .gitleaks.toml is never loaded), `--ignore-gitleaks-allow` (measured
  2026-10-27, gitleaks 8.30.1: without it an inline `gitleaks:allow` comment hides a
  token), and an empty plugin ignore file via -i (a repository .gitleaksignore has no
  effect). Plus fixed patterns for Authorization/Cookie headers, bearer tokens and
  secret-named key/value pairs.
- Replacement is LINE-PRESERVING: every line of a secret becomes `[REDACTED:<rule>]`,
  line endings survive, and the line count before and after must match -- so line n of
  the snapshot is line n of the original (R4-4).
- Fail closed: a scanner error, an unexpected exit code, a broken report, a finding
  outside the tree, a file that is not UTF-8, or a second pass that still finds
  anything raises RedactError. Nothing is half-redacted silently.

Returns which lines of which files were redacted, so a hunt record whose evidence sits
on such a line is capped at needs_validation (R4-5).
Messages are ASCII only.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import hunt_io

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
GITLEAKS_CONFIG = PLUGIN_ROOT / "config" / "gitleaks.toml"
GITLEAKS_IGNORE = PLUGIN_ROOT / "config" / "gitleaksignore.empty"
LEAK_EXIT = 42
SCAN_TIMEOUT = 300

# Value-only patterns: group "v" is what gets replaced. Values never span CR or LF, so a
# CRLF line keeps its CR (inspection round 1, finding 10); a quoted value is taken up to
# its closing quote, spaces included (finding 9).
_NAME = (r"\b[\w.-]*(?:passw(?:or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|"
         r"access[_-]?key|client[_-]?secret)[\w.-]*\b[\"']?[ \t]*[:=][ \t]*")
PATTERNS = [
    ("header-auth", re.compile(r"(?im)^(?P<k>[ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*)(?P<v>[^\r\n]*[^\s\r\n])")),
    ("header-cookie", re.compile(r"(?im)^(?P<k>[ \t]*(?:set-)?cookie[ \t]*:[ \t]*)(?P<v>[^\r\n]*[^\s\r\n])")),
    ("bearer", re.compile(r"(?i)(?P<k>\bbearer[ \t]+)(?P<v>[A-Za-z0-9._~+/=-]{8,})")),
    # Backslash escapes stay inside the value (inspection round 2, finding 24): with
    # [^"]+ a value like "ab\"cd" stopped at the escaped quote and left the tail in clear.
    ("named-secret-dq", re.compile(r"(?i)(?P<k>" + _NAME + r"\")(?P<v>(?:[^\"\\\r\n]|\\[^\r\n]){4,})(?=\")")),
    ("named-secret-sq", re.compile(r"(?i)(?P<k>" + _NAME + r"')(?P<v>(?:[^'\\\r\n]|\\[^\r\n]){4,})(?=')")),
    ("named-secret", re.compile(r"(?i)(?P<k>" + _NAME + r")(?P<v>[^\s\"',;]{4,})")),
]
_LINE_SPLIT = re.compile(r"(\r\n|\n|\r)")


class RedactError(Exception):
    pass


@dataclass
class RedactResult:
    redacted_lines: dict[str, list[int]] = field(default_factory=dict)


def _checked_report(data, returncode: int) -> list[dict]:
    """The report must be a list of findings with file, secret and line (finding 11)."""
    if not isinstance(data, list):
        raise RedactError("gitleaks report is not a list")
    for f in data:
        if (not isinstance(f, dict) or not isinstance(f.get("File"), str) or not f["File"]
                or not isinstance(f.get("Secret"), str) or not f["Secret"]
                or not isinstance(f.get("StartLine"), int)):
            raise RedactError("gitleaks report entry without file, secret or line")
    if (returncode == LEAK_EXIT) != bool(data):
        raise RedactError(f"gitleaks exit {returncode} contradicts a report of {len(data)} finding(s)")
    return data


def gitleaks_scan(directory: Path, work_dir: Path | None = None) -> list[dict]:
    """Scan `directory` with the plugin config; the report comes back on stdout and is
    validated by _checked_report. Raises RedactError on any failure."""
    exe = shutil.which("gitleaks")
    if not exe:
        raise RedactError("gitleaks not found on PATH; refusing to send anything unscanned")
    # `-r -` puts the report on stdout (measured 2026-10-27, gitleaks 8.30.1): the raw
    # report, which holds the secret values, never touches the filesystem, so no write
    # of it can be redirected (gate recheck A1-1). `work_dir` is kept for callers.
    del work_dir
    argv = [exe, "dir", str(directory), "-c", str(GITLEAKS_CONFIG),
            "-i", str(GITLEAKS_IGNORE), "--ignore-gitleaks-allow", "--no-banner",
            "-f", "json", "-r", "-", "--exit-code", str(LEAK_EXIT)]
    try:
        done = subprocess.run(argv, capture_output=True, timeout=SCAN_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RedactError(f"gitleaks did not run: {exc}") from exc
    if done.returncode not in (0, LEAK_EXIT):
        raise RedactError(f"gitleaks exited {done.returncode}")
    try:
        data = json.loads(done.stdout.decode("utf-8"))
    except (ValueError, AttributeError) as exc:
        raise RedactError(f"gitleaks report unreadable: {exc}") from exc
    return _checked_report(data, done.returncode)


def _placeholder_for(secret: str, rule: str) -> str:
    parts = _LINE_SPLIT.split(secret)
    tag = f"[REDACTED:{rule}]"
    return "".join(p if i % 2 else (tag if p else p) for i, p in enumerate(parts))


def _lines_of(text: str, start: int, end: int) -> list[int]:
    first = text.count("\n", 0, start) + text.count("\r", 0, start) - text.count("\r\n", 0, start) + 1
    span = text[start:end]
    n = span.count("\n") + span.count("\r") - span.count("\r\n")
    return list(range(first, first + n + 1))


def _line_count(text: str) -> int:
    return len(_LINE_SPLIT.split(text)) // 2 + 1


def _relative(root: Path, file_field) -> str:
    if not isinstance(file_field, str) or not file_field:
        raise RedactError("scanner finding without a file")
    p = Path(file_field)
    p = p if p.is_absolute() else root / p
    try:
        return Path(os.path.abspath(p)).relative_to(Path(os.path.abspath(root))).as_posix()
    except ValueError as exc:
        raise RedactError(f"scanner finding outside the tree: {file_field}") from exc


def _apply(root: Path, findings, result: RedactResult) -> None:
    if not isinstance(findings, list):
        raise RedactError("scanner report is not a list")
    by_file: dict[str, list[tuple[str, str]]] = {}
    for f in findings:
        if not isinstance(f, dict) or not isinstance(f.get("Secret"), str) or not f["Secret"]:
            raise RedactError("scanner finding without a secret value")
        rel = _relative(root, f.get("File"))
        by_file.setdefault(rel, []).append((f["Secret"], str(f.get("RuleID") or "secret")))
    for rel in _files(root):
        text = _read_text(root, rel)
        before = _line_count(text)
        hit: set[int] = set()
        for secret, rule in sorted(by_file.get(rel, []), key=lambda s: -len(s[0])):
            if secret not in text:
                continue  # already replaced via a longer overlapping secret
            for m in re.finditer(re.escape(secret), text):
                hit.update(_lines_of(text, m.start(), m.end()))
            text = text.replace(secret, _placeholder_for(secret, rule))
        for rule, rx in PATTERNS:
            def sub(m, rule=rule):
                hit.update(_lines_of(text_ref[0], m.start("v"), m.end("v")))
                return m.group("k") + f"[REDACTED:{rule}]"
            text_ref = [text]
            text = rx.sub(sub, text)
        if _line_count(text) != before:
            raise RedactError(f"{rel}: line count changed during redaction")
        if hit:
            try:
                hunt_io.replace_file(root, rel, text.encode("utf-8"))
            except hunt_io.HuntIOError as exc:
                raise RedactError(f"{rel}: cannot rewrite safely: {exc}") from exc
            result.redacted_lines[rel] = sorted(set(result.redacted_lines.get(rel, [])) | hit)


def _files(root: Path) -> list[str]:
    try:
        return hunt_io.walk_files(root)
    except hunt_io.HuntIOError as exc:
        raise RedactError(f"tree refused: {exc}") from exc


def _read_text(root: Path, rel: str) -> str:
    status, data = hunt_io.read_at(root, rel)
    if status != "ok":
        raise RedactError(f"{rel}: refused ({data})")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RedactError(f"{rel}: not UTF-8, cannot redact safely") from exc


def split_lines(text: str) -> list[str]:
    """Lines as the redactor counts them: CR, LF and CRLF only. Every consumer of
    `redacted_lines` must number lines with THIS function -- str.splitlines() also breaks
    at vertical tab, form feed and Unicode separators, which shifted a redacted line off its number and
    let evidence on it be confirmed (closing gate A2-1)."""
    parts = _LINE_SPLIT.split(text)[0::2]
    if parts and parts[-1] == "":
        parts.pop()  # a trailing line ending does not start another line
    return parts


def _scan(scanner, root: Path) -> list[dict]:
    try:
        found = scanner(root)
    except RedactError:
        raise
    except Exception as exc:  # a scanner that breaks is a refusal, never a pass
        raise RedactError(f"scanner failed: {exc}") from exc
    if not isinstance(found, list):  # None, {} or anything else is not "clean" (finding 11)
        raise RedactError("scanner returned no list")
    return found


def redact_tree(root: Path, scanner=None, verify: bool = True) -> RedactResult:
    """Redact every file under `root` in place; raise RedactError on any doubt.

    `scanner` defaults to gitleaks_scan, resolved at CALL time so tests can replace it.
    """
    root = Path(root)
    _files(root)  # refuse a linked or special tree BEFORE a scanner walks it
    scanner = scanner or (lambda d: gitleaks_scan(d))
    result = RedactResult()
    _apply(root, _scan(scanner, root), result)
    if verify:
        again = _scan(scanner, root)
        if again:
            raise RedactError(f"second pass still finds {len(again)} secret(s); refusing")
        for rel in _files(root):
            text = _read_text(root, rel)
            for _rule, rx in PATTERNS:
                for m in rx.finditer(text):
                    if not m.group("v").startswith("[REDACTED:"):
                        raise RedactError(f"{rel}: pattern hit left")
    return result


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        sys.stderr.write("usage: redact_payload.py <directory>\n")
        return 2
    try:
        res = redact_tree(Path(args[0]))
    except RedactError as exc:
        sys.stderr.write(f"redact_payload: REFUSED - {exc}\n")
        return 2
    sys.stdout.write(json.dumps(res.redacted_lines, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
