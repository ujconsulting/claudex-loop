"""redact_payload: real redaction of the hunt snapshot (plan A, stage 1, item 7).

- gitleaks runs with the PLUGIN config only, `--ignore-gitleaks-allow` (measured
  2026-10-27 on gitleaks 8.30.1: without it, a `gitleaks:allow` comment hides the token)
  and an empty plugin ignore file; a repository `.gitleaksignore` has no effect;
- fixed patterns cover Authorization/Cookie headers, bearer tokens and secret-named
  key/value pairs;
- redaction is LINE-PRESERVING: a multi-line secret is replaced line by line, line
  endings (LF/CRLF) survive, the line count is checked (R4-4);
- fail closed: scanner error, broken report, a second pass that still finds anything.

The fake-scanner tests run everywhere; the real-gitleaks tests run where gitleaks is
installed. Written before scripts/redact_payload.py and seen failing first.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import redact_payload as rp  # noqa: E402

# Built at runtime so this file never contains a scanner-recognisable token itself.
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
KEY = ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx1\nAbCdEfGh2\n"
       "-----END " + "RSA PRIVATE KEY-----")
HAVE_GITLEAKS = shutil.which("gitleaks") is not None


def _fake(findings):
    def scan(directory: Path) -> list[dict]:
        return findings(directory)
    return scan


def test_line_preserving_multiline_and_crlf(tmp_path):
    f = tmp_path / "k.txt"
    f.write_bytes(("a\r\n" + KEY.replace("\n", "\r\n") + "\r\nz\r\n").encode())
    secret = KEY.replace("\n", "\r\n")
    res = rp.redact_tree(tmp_path, scanner=_fake(lambda d: [
        {"File": str(f), "Secret": secret, "RuleID": "private-key", "StartLine": 2}]),
        verify=False)
    out = f.read_bytes().decode()
    assert "MIIEow" not in out
    assert out.count("\r\n") == 6 and "\n" not in out.replace("\r\n", "")
    assert out.splitlines()[0] == "a" and out.splitlines()[-1] == "z"
    assert res.redacted_lines["k.txt"] == [2, 3, 4, 5]


def test_patterns_catch_headers_bearer_and_named_values(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("Authorization: Basic dXNlcjpwYXNz\nCookie: sid=abcdef123456\n"
                 "curl -H 'Bearer eyJhbGciOiJIUzI1NiJ9.x.y'\npassword = \"hunter2hunter2\"\n"
                 "ok = 1\n", encoding="utf-8")
    res = rp.redact_tree(tmp_path, scanner=_fake(lambda d: []), verify=False)
    out = f.read_text(encoding="utf-8")
    for leaked in ("dXNlcjpwYXNz", "abcdef123456", "eyJhbGciOiJIUzI1NiJ9", "hunter2hunter2"):
        assert leaked not in out, leaked
    assert "ok = 1" in out
    assert res.redacted_lines["h.txt"] == [1, 2, 3, 4]


def test_quoted_values_are_redacted_completely(tmp_path):
    """Inspection round 1, finding 9: `password = "horse horse"` kept its second word."""
    f = tmp_path / "q.txt"
    f.write_text('password = "horse horse"\napi_key: \'one two three\'\n', encoding="utf-8")
    rp.redact_tree(tmp_path, scanner=_fake(lambda d: []), verify=False)
    out = f.read_text(encoding="utf-8")
    assert "horse" not in out and "two three" not in out and "one" not in out


def test_header_redaction_keeps_crlf(tmp_path):
    """Finding 10: the header value used to swallow the CR of a CRLF line."""
    f = tmp_path / "h.txt"
    f.write_bytes(b"Authorization: Basic dXNlcjpwYXNz\r\nCookie: sid=abcdef123456\r\nx\r\n")
    rp.redact_tree(tmp_path, scanner=_fake(lambda d: []), verify=False)
    out = f.read_bytes()
    assert out.count(b"\r\n") == 3 and b"dXNlcjpwYXNz" not in out and b"abcdef123456" not in out


@pytest.mark.parametrize("report,code", [
    (None, 42), ({}, 42), ([{"File": "a"}], 42), ([], 42), ([{"File": "a", "Secret": "s", "StartLine": 1}], 0),
])
def test_a_malformed_or_contradicting_report_fails_closed(report, code):
    """Finding 11: a leak exit with `null` used to come back as None and pass as clean."""
    with pytest.raises(rp.RedactError):
        rp._checked_report(report, code)


def test_a_scanner_returning_none_is_not_clean(tmp_path):
    (tmp_path / "a.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tmp_path, scanner=lambda d: None, verify=False)


@pytest.mark.parametrize("bad", ["scanner error", "not a list", "missing field"])
def test_scanner_failures_fail_closed(tmp_path, bad):
    (tmp_path / "a.txt").write_text("x\n", encoding="utf-8")

    def scan(d):
        if bad == "scanner error":
            raise rp.RedactError("gitleaks exited 2")
        if bad == "not a list":
            return {"oops": 1}
        return [{"File": str(tmp_path / "a.txt")}]
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tmp_path, scanner=scan, verify=False)


def test_second_pass_must_be_clean(tmp_path):
    (tmp_path / "a.txt").write_text("x\n", encoding="utf-8")
    calls = []

    def scan(d):
        calls.append(1)
        # second pass still reports something the first pass did not fix
        return [] if len(calls) == 1 else [{"File": str(tmp_path / "a.txt"),
                                            "Secret": "zzz", "RuleID": "r", "StartLine": 1}]
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tmp_path, scanner=scan, verify=True)


def test_a_finding_outside_the_tree_is_refused(tmp_path):
    (tmp_path / "a.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tmp_path, scanner=_fake(lambda d: [
            {"File": str(tmp_path.parent / "elsewhere.txt"), "Secret": "x",
             "RuleID": "r", "StartLine": 1}]), verify=False)


@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")
def test_real_gitleaks_ignores_inline_allow_and_repo_ignore(tmp_path):
    (tmp_path / "a.py").write_text(f'y = "{TOKEN}"  # gitleaks:allow\n', encoding="utf-8")
    (tmp_path / ".gitleaksignore").write_text("a.py:github-pat:1\n", encoding="utf-8")
    (tmp_path / ".gitleaks.toml").write_text("[allowlist]\npaths = ['''.*''']\n", encoding="utf-8")
    res = rp.redact_tree(tmp_path)
    assert TOKEN not in (tmp_path / "a.py").read_text(encoding="utf-8")
    assert res.redacted_lines["a.py"] == [1]


@pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks not installed")
def test_real_gitleaks_clean_tree_passes(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    res = rp.redact_tree(tmp_path)
    assert res.redacted_lines == {}
    assert json.loads(json.dumps(res.redacted_lines)) == {}


def test_escaped_quotes_do_not_end_the_value(tmp_path):
    """Inspection round 2, finding 24: `[^"]+` stopped at an escaped quote and left the
    rest of the secret in clear."""
    f = tmp_path / "e.txt"
    f.write_bytes(b'password = "abcd\\"TAILSECRET"\n'
                  b"api_key: 'wxyz\\'SQTAIL'\nok = 1\n")
    rp.redact_tree(tmp_path, scanner=_fake(lambda d: []), verify=False)
    out = f.read_text(encoding="utf-8")
    assert "TAILSECRET" not in out and "SQTAIL" not in out and "abcd" not in out
    assert out.count("\n") == 3 and "ok = 1" in out


class _Done:
    def __init__(self, returncode, stdout=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = b""


def _fake_run(report_text, returncode, seen):
    def run(argv, **kw):
        seen.append(argv)
        return _Done(returncode, (report_text or "").encode("utf-8"))
    return run


@pytest.mark.parametrize("report_text,code", [
    ("null", 42),            # leak exit, no report body
    ("[]", 42),              # leak exit, empty report
    ('[{"File": "a"}]', 42), # entry without secret and line
    ("{not json", 0),        # broken report
    (None, 0),               # no report written at all
    ("[]", 2),               # scanner error exit
])
def test_gitleaks_scan_itself_fails_closed(tmp_path, monkeypatch, report_text, code):
    """Inspection round 2, finding 28: the fail-closed paths were tested only on
    _checked_report, never through gitleaks_scan, so the wiring could break unseen."""
    (tmp_path / "in").mkdir()
    monkeypatch.setattr(rp.shutil, "which", lambda name: "gitleaks")
    seen = []
    monkeypatch.setattr(rp.subprocess, "run", _fake_run(report_text, code, seen))
    with pytest.raises(rp.RedactError):
        rp.gitleaks_scan(tmp_path / "in", work_dir=tmp_path)
    argv = seen[0]
    assert "--ignore-gitleaks-allow" in argv and str(rp.GITLEAKS_CONFIG) in argv
    # gate recheck A1-1: the report goes to stdout and never touches the filesystem
    assert argv[argv.index("-r") + 1] == "-"
    assert [p.name for p in tmp_path.iterdir()] == ["in"]


def test_gitleaks_scan_clean_and_missing_binary(tmp_path, monkeypatch):
    (tmp_path / "in").mkdir()
    monkeypatch.setattr(rp.shutil, "which", lambda name: "gitleaks")
    monkeypatch.setattr(rp.subprocess, "run", _fake_run("[]", 0, []))
    assert rp.gitleaks_scan(tmp_path / "in", work_dir=tmp_path) == []
    monkeypatch.setattr(rp.shutil, "which", lambda name: None)
    with pytest.raises(rp.RedactError, match="not found"):
        rp.gitleaks_scan(tmp_path / "in", work_dir=tmp_path)


def test_a_second_pass_returning_none_is_not_clean(tmp_path):
    (tmp_path / "a.txt").write_text("x\n", encoding="utf-8")
    calls = []

    def scan(d):
        calls.append(1)
        return [] if len(calls) == 1 else None
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tmp_path, scanner=scan, verify=True)


def _junction_or_link(link: Path, target: Path) -> None:
    import os
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_redaction_never_follows_a_link_out_of_its_tree(tmp_path):
    """Closing gate A1-2: rglob/is_file/read_bytes/write_bytes followed links, so a file
    outside the tree holding `password = "..."` was rewritten in place."""
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "cfg.txt"
    victim.write_bytes(b'password = "hunter2hunter2"\n')
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_bytes(b"x\n")
    _junction_or_link(tree / "sub", outside)
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tree, scanner=_fake(lambda d: []), verify=False)
    assert victim.read_bytes() == b'password = "hunter2hunter2"\n'


def test_a_linked_root_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.txt").write_bytes(b'password = "hunter2hunter2"\n')
    _junction_or_link(tmp_path / "alias", real)
    with pytest.raises(rp.RedactError):
        rp.redact_tree(tmp_path / "alias", scanner=_fake(lambda d: []), verify=False)
    assert b"hunter2" in (real / "a.txt").read_bytes()


@pytest.mark.parametrize("exc", ["timeout", "oserror"])
def test_gitleaks_scan_timeout_and_launch_failure_fail_closed(tmp_path, monkeypatch, exc):
    import subprocess as sp
    (tmp_path / "in").mkdir()
    monkeypatch.setattr(rp.shutil, "which", lambda name: "gitleaks")

    def run(argv, **kw):
        raise sp.TimeoutExpired(argv, 1) if exc == "timeout" else OSError("exec format error")
    monkeypatch.setattr(rp.subprocess, "run", run)
    with pytest.raises(rp.RedactError, match="did not run"):
        rp.gitleaks_scan(tmp_path / "in", work_dir=tmp_path)
    assert [p.name for p in tmp_path.iterdir()] == ["in"]  # nothing written


def test_split_lines_counts_only_cr_and_lf():
    """Closing gate A2-1: str.splitlines() also breaks at VT/FF/U+2028."""
    assert rp.split_lines("a\vb\nc\r\nd\re f\n") == ["a\vb", "c", "d", "e f"]
    assert rp.split_lines("") == []
    assert rp.split_lines("x") == ["x"]
