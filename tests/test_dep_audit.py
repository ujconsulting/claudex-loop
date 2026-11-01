"""dep_audit: dependency audit without package tools (plan B1.5, step 7).

The network is never touched: `sandbox_fetch.run_job` is replaced for every test, and every
refusal asserts that it was NEVER called. Every case builds its own throwaway git repository, so
the audited bytes are the committed ones, not the working tree. Written before the behaviour was
checked against mutations (see the mutation tests at the end of the module's report).
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import dep_audit  # noqa: E402
import sandbox_fetch  # noqa: E402
import sandbox_snapshot as ss  # noqa: E402

_GIT = ss.git_version()
pytestmark = pytest.mark.skipif(_GIT is None or _GIT < ss.MIN_GIT,
                                reason=f"git {_GIT} older than {ss.MIN_GIT} (no --no-lazy-fetch)")


def git_env() -> dict:
    """Hermetic git environment, built per call: no system or global config (so no inherited
    commit.gpgsign, hooks path, templates or includes), a fixed identity."""
    return {**os.environ,
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

H1, H2 = "a" * 64, "b" * 64
REQ = f"requests==2.31.0 --hash=sha256:{H1}\nidna==3.4 --hash=sha256:{H2}\n".encode()
LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/left-pad": {"version": "1.3.0",
                              "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
}}).encode()


def git(repo, *args, data=None):
    res = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                          *args], input=data, capture_output=True, env=git_env(), timeout=60)
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    return res.stdout.decode().strip()


def make_repo(root: Path, files: dict, symlinks: dict | None = None) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    for rel, data in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    if files:
        git(repo, "add", *files)
    for rel, target in (symlinks or {}).items():  # a link entry made with plumbing, any OS
        oid = git(repo, "hash-object", "-w", "--stdin", data=target.encode())
        git(repo, "update-index", "--add", "--cacheinfo", f"120000,{oid},{rel}")
    git(repo, "commit", "-q", "-m", "x", "--allow-empty")
    return repo, git(repo, "rev-parse", "HEAD^{tree}")


@pytest.fixture
def scratch(tmp_path):
    d = tmp_path / "scratch"
    d.mkdir()
    return d


def call(repo, tree, scratch, files, *, out=None, results=None, raises=None, extra=()):
    """Run dep_audit.main with run_job faked. Returns (code, stdout KEY dict, stderr, run_job mock)."""
    argv = ["--repo", str(repo), "--tree", tree, "--scratch", str(scratch)]
    for f in files:
        argv += ["--file", f]
    if out:
        argv += ["--out", out]
    argv += list(extra)
    fake = mock.Mock(side_effect=raises) if raises is not None else mock.Mock(return_value=results)
    o, e = io.StringIO(), io.StringIO()
    with mock.patch.object(dep_audit.sandbox_fetch, "run_job", fake), \
            contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = dep_audit.main(argv)
    keys = dict(line.split("=", 1) for line in o.getvalue().splitlines() if "=" in line)
    return code, keys, e.getvalue(), fake


PLUGIN_MODULES = ["dep_audit.py", "sandbox_deps.py", "sandbox_fetch.py", "sandbox_snapshot.py",
                  "sandbox_run.py", "hunt_io.py", "hunt_snapshot.py"]


def plugin_files_expected() -> dict:
    """{file name: sha256 of its bytes} for every module of scripts/ that dep_audit loads."""
    names = dep_audit.plugin_module_names()
    assert set(PLUGIN_MODULES) <= set(names)
    return {n: hashlib.sha256((SCRIPTS / n).read_bytes()).hexdigest() for n in sorted(names)}


def manifest_of(keys):
    return json.loads((Path(keys["RUN_DIR"]) / "audit-manifest.json").read_text())


def clean_results(n):
    return {"ok": True, "results": [[] for _ in range(n)], "details": {}}


@pytest.fixture
def repo_tree(tmp_path):
    return make_repo(tmp_path, {"requirements.txt": REQ, "web/package-lock.json": LOCK,
                                "yarn.lock": b"x\n", "poetry.lock": b"x\n",
                                "requirements-dev.txt": b"pytest==8.0.0\n", "sub/dir.txt": b"x"})


# --- success ---------------------------------------------------------------------------------

def test_clean_exit_0_and_queries_sorted_deduplicated(repo_tree, scratch):
    repo, tree = repo_tree
    code, keys, _err, fake = call(repo, tree, scratch, ["web/package-lock.json", "requirements.txt"],
                                  results=clean_results(3))
    assert code == 0
    assert keys["STATUS"] == "complete" and keys["VULNERABLE_PACKAGES"] == "0" and keys["TREE"] == tree
    job = fake.call_args.args[0]
    assert job["kind"] == "osv"
    assert job["queries"] == [["PyPI", "idna", "3.4"], ["PyPI", "requests", "2.31.0"],
                              ["npm", "left-pad", "1.3.0"]]
    assert fake.call_args.args[2] == 300  # the plan's audit deadline
    report = json.loads(Path(keys["REPORT"]).read_text())
    assert report["status"] == "complete" and report["tree"] == tree
    assert report["coverage"] == "only the dependency inventory in these files; no resolution"
    assert [p["name"] for p in report["packages"]] == ["idna", "requests", "left-pad"]
    assert all(p["vulns"] == [] for p in report["packages"])


def test_vulnerabilities_exit_1_with_fixed_versions(repo_tree, scratch):
    repo, tree = repo_tree
    details = {"GHSA-aaaa-bbbb-cccc": {
        "id": "GHSA-aaaa-bbbb-cccc", "summary": "bad thing",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "Requests"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]},
                        {"type": "ECOSYSTEM", "events": [{"fixed": "2.31.1"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "other"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9"}]}]},
        ]}}
    answer = {"ok": True, "results": [[], ["GHSA-aaaa-bbbb-cccc"]], "details": details}
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=answer)
    assert code == 1 and keys["STATUS"] == "complete" and keys["VULNERABLE_PACKAGES"] == "1"
    pkg = json.loads(Path(keys["REPORT"]).read_text())["packages"][1]
    assert pkg["name"] == "requests"
    assert pkg["vulns"] == [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "bad thing", "severity": "HIGH",
                             "fixed": ["2.31.1", "2.32.0"]}]


def test_severity_falls_back_to_osv_severity_list_then_null():
    assert dep_audit._severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]}) \
        == "CVSS_V3:CVSS:3.1/AV:N"
    assert dep_audit._severity({}) is None
    assert dep_audit._fixed({"affected": "nonsense"}, "PyPI", "x") == []


def test_empty_inventory_is_complete_clean_without_network(tmp_path, scratch):
    repo, tree = make_repo(tmp_path, {"package-lock.json": json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}}}).encode()})
    code, keys, _e, fake = call(repo, tree, scratch, ["package-lock.json"])
    assert code == 0 and keys["STATUS"] == "complete"
    fake.assert_not_called()


# --- manifest --------------------------------------------------------------------------------

def test_manifest_fields_match_snapshot_and_files(repo_tree, scratch):
    repo, tree = repo_tree
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt", "web/package-lock.json"],
                              results=clean_results(3), out="my.json")
    assert code == 0
    mpath = Path(keys["RUN_DIR"]) / "audit-manifest.json"
    assert keys["AUDIT_MANIFEST_SHA256"] == hashlib.sha256(mpath.read_bytes()).hexdigest()
    m = json.loads(mpath.read_text())
    assert m["tree"] == tree and m["status"] == "complete"
    snap = ss.build_snapshot(repo, tree)
    shas = {e[0]: e[2] for e in snap.entries}
    assert m["inputs"] == [{"path": "requirements.txt", "content_sha256": shas["requirements.txt"]},
                           {"path": "web/package-lock.json",
                            "content_sha256": shas["web/package-lock.json"]}]
    queries = [["PyPI", "idna", "3.4"], ["PyPI", "requests", "2.31.0"], ["npm", "left-pad", "1.3.0"]]
    assert m["inventory_sha256"] == hashlib.sha256(
        json.dumps(queries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert m["helper_sha256"] == hashlib.sha256(Path(dep_audit.__file__).read_bytes()).hexdigest()
    assert m["endpoints"] == ["https://api.osv.dev/v1/querybatch", "https://api.osv.dev/v1/vulns/"]
    assert "plugin_version" not in m
    assert m["plugin_files"] == plugin_files_expected()
    report_path = Path(keys["REPORT"])
    assert report_path.name == "my.json"
    assert m["report_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()


def test_working_tree_edit_after_commit_does_not_change_audited_bytes(repo_tree, scratch):
    repo, tree = repo_tree
    (repo / "requirements.txt").write_bytes(f"evil==6.6.6 --hash=sha256:{H1}\n".encode())
    code, keys, _e, fake = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    assert code == 0
    assert [q[1] for q in fake.call_args.args[0]["queries"]] == ["idna", "requests"]
    snap_sha = hashlib.sha256(REQ).hexdigest()
    assert manifest_of(keys)["inputs"][0]["content_sha256"] == snap_sha


# --- refusals --------------------------------------------------------------------------------

@pytest.mark.parametrize("files", [
    ["yarn.lock"], ["poetry.lock"], ["requirements.txt", "yarn.lock"],  # unknown lockfile kind
    ["requirements-dev.txt"],                                           # unhashed requirements
    ["nope/requirements.txt"],                                          # not in the tree
    ["sub"],                                                            # a directory, not a file
    ["../requirements.txt"], ["/etc/requirements.txt"], [".git/requirements.txt"],
    ["requirements.txt", "requirements.txt"], ["requirements.txt/../requirements.txt"],
    ["C:/requirements.txt"],
])
def test_refused_inputs_exit_2_and_never_call_run_job(repo_tree, scratch, files):
    repo, tree = repo_tree
    code, keys, err, fake = call(repo, tree, scratch, files, results=clean_results(1))
    assert code == 2 and keys["STATUS"] == "refused" and "REFUSED" in err
    fake.assert_not_called()
    m = manifest_of(keys)
    assert m["status"] == "refused" and m["report_sha256"] is None and "reason" in m
    assert not any(p.name == "dep-audit.json" for p in Path(keys["RUN_DIR"]).iterdir())


def test_unsupported_lockfile_message_names_the_file(repo_tree, scratch):
    repo, tree = repo_tree
    _c, keys, err, _f = call(repo, tree, scratch, ["yarn.lock"], results=None)
    assert "no sandbox-safe audit yet: yarn.lock" in err
    assert "no sandbox-safe audit yet: yarn.lock" in manifest_of(keys)["reason"]


def test_link_entry_in_tree_refuses_whole_snapshot(tmp_path, scratch):
    repo, tree = make_repo(tmp_path, {"requirements.txt": REQ}, symlinks={"lnk": "requirements.txt"})
    for files in (["lnk"], ["requirements.txt"]):  # the link also poisons the snapshot of the tree
        code, keys, _e, fake = call(repo, tree, scratch, files, results=clean_results(1))
        assert code == 2
        fake.assert_not_called()
        assert manifest_of(keys)["status"] == "refused"


def test_npm_lock_with_link_entry_refused(tmp_path, scratch):
    bad = json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/x": {"resolved": "../x", "link": True}}}).encode()
    repo, tree = make_repo(tmp_path, {"package-lock.json": bad})
    code, keys, _e, fake = call(repo, tree, scratch, ["package-lock.json"], results=clean_results(1))
    assert code == 2
    fake.assert_not_called()
    assert manifest_of(keys)["status"] == "refused"


def test_requirements_with_option_line_refused(tmp_path, scratch):
    repo, tree = make_repo(tmp_path, {"requirements.txt": b"-r other.txt\n"})
    code, _k, _e, fake = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(1))
    assert code == 2
    fake.assert_not_called()


@pytest.mark.parametrize("kwargs", [{"out": "audit-manifest.json"}, {"out": "../x.json"},
                                    {"out": "a/b.json"}])
def test_bad_out_name_refused(repo_tree, scratch, kwargs):
    repo, tree = repo_tree
    code, _k, _e, fake = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2), **kwargs)
    assert code == 2
    fake.assert_not_called()


def test_bad_tree_and_missing_scratch_and_no_file(repo_tree, tmp_path, scratch):
    repo, tree = repo_tree
    code, keys, _e, fake = call(repo, "HEAD", scratch, ["requirements.txt"], results=clean_results(2))
    assert code == 2 and keys["TREE"] == "-"
    assert manifest_of(keys)["tree"] is None
    code, keys, err, _f = call(repo, tree, scratch, [], results=clean_results(2))
    assert code == 2 and "--file" in err
    missing = tmp_path / "nope"
    code, keys, _e, fake2 = call(repo, tree, missing, ["requirements.txt"], results=clean_results(2))
    assert code == 2 and "RUN_DIR" not in keys and not missing.exists()
    fake.assert_not_called()
    fake2.assert_not_called()


def test_unknown_tree_refused_without_run_job(repo_tree, scratch):
    repo, _tree = repo_tree
    code, keys, _e, fake = call(repo, "0" * 40, scratch, ["requirements.txt"], results=clean_results(2))
    assert code == 2
    fake.assert_not_called()
    assert manifest_of(keys)["status"] == "refused"


def test_fetch_refused_from_worker_is_exit_2(repo_tree, scratch):
    repo, tree = repo_tree
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"],
                              raises=sandbox_fetch.FetchRefused("too many queries"))
    assert code == 2 and manifest_of(keys)["status"] == "refused"


# --- infrastructure and incomplete -----------------------------------------------------------

def test_infrastructure_is_exit_5_incomplete_without_report(repo_tree, scratch):
    repo, tree = repo_tree
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"],
                              raises=sandbox_fetch.FetchInfrastructure("incomplete: 503"))
    assert code == 5 and keys["STATUS"] == "incomplete" and "REPORT" not in keys
    m = manifest_of(keys)
    assert m["status"] == "incomplete" and m["report_sha256"] is None
    assert not (Path(keys["RUN_DIR"]) / "dep-audit.json").exists()


def test_unconfirmed_worker_is_exit_5_and_keeps_the_directory(repo_tree, scratch):
    repo, tree = repo_tree
    exc = sandbox_fetch.FetchUnconfirmed("worker not dead", 4242, scratch / "x", None)
    code, keys, err, _f = call(repo, tree, scratch, ["requirements.txt"], raises=exc)
    assert code == 5 and keys["STATUS"] == "incomplete"
    assert Path(keys["RUN_DIR"]).is_dir() and (Path(keys["RUN_DIR"]) / "osv").is_dir()
    m = manifest_of(keys)
    assert m["quarantine"]["pid"] == 4242 and m["quarantine"]["cleanup"] == "unconfirmed"
    assert "4242" in err and "left in place" in err


@pytest.mark.parametrize("answer", [
    {"ok": True, "results": [[]], "details": {}},                               # one result too few
    {"ok": True, "results": [[], [], []], "details": {}},                       # one too many
    {"ok": True, "results": [[], ["GHSA-x"]], "details": {}},                   # id without details
    {"ok": True, "results": [[], "x"], "details": {}},                          # malformed result
    {"ok": True, "results": [[], []]},                                          # no details at all
])
def test_mismatched_answer_is_incomplete_never_clean(repo_tree, scratch, answer):
    repo, tree = repo_tree
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=answer)
    assert code == 5 and keys["STATUS"] == "incomplete"
    assert manifest_of(keys)["report_sha256"] is None
    assert not (Path(keys["RUN_DIR"]) / "dep-audit.json").exists()


def test_report_over_cap_is_incomplete(repo_tree, scratch):
    repo, tree = repo_tree
    with mock.patch.object(dep_audit, "REPORT_CAP", 100):
        code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    assert code == 5 and manifest_of(keys)["status"] == "incomplete"
    assert not (Path(keys["RUN_DIR"]) / "dep-audit.json").exists()


def test_quarantine_records_are_listed_on_stderr_and_nothing_is_deleted(repo_tree, scratch):
    repo, tree = repo_tree
    victim = scratch / "old-dir"
    victim.mkdir()
    (victim / "sentinel").write_text("keep")
    rid = sandbox_fetch.new_run_id()
    sandbox_fetch.write_quarantine_record(scratch, rid, victim, 99999999, 1.0)
    code, _k, err, _f = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    assert code == 0
    assert f"quarantined run {rid}" in err and "remove by hand" in err
    assert (victim / "sentinel").read_text() == "keep"


# --- broken output streams (plan B1.5 hardening) ---------------------------------------------
# For dep_audit exit 1 means "vulnerable": an OSError escaping from a stderr diagnostic was read
# as a finding. Every diagnostic is best effort; a lost stdout KEY=value line is exit 5.

class BrokenStream(io.StringIO):
    """A text stream whose writes (and flushes) raise -- a full redirected log or a closed pipe."""

    def __init__(self, exc):
        super().__init__()
        self.exc, self.attempts = exc, 0

    def write(self, s):
        self.attempts += 1
        raise self.exc

    def flush(self):
        if self.exc is not None:
            raise self.exc

    def close(self):
        self.exc = None  # IOBase.close flushes; the finaliser must not raise
        super().close()


BROKEN = [OSError(28, "No space left on device"), ValueError("I/O operation on closed file.")]


def call_broken(repo, tree, scratch, files, *, results=None, raises=None, err_exc=None, out_exc=None):
    """dep_audit.main with run_job faked and stdout/stderr replaced. Returns (code, out, err, run dir)."""
    argv = ["--repo", str(repo), "--tree", tree, "--scratch", str(scratch)]
    for f in files:
        argv += ["--file", f]
    fake = mock.Mock(side_effect=raises) if raises is not None else mock.Mock(return_value=results)
    out = BrokenStream(out_exc) if out_exc else io.StringIO()
    err = BrokenStream(err_exc) if err_exc else io.StringIO()
    before = set(scratch.glob("dep-audit-*"))
    with mock.patch.object(dep_audit.sandbox_fetch, "run_job", fake), \
            mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
        code = dep_audit.main(argv)
    new = sorted(set(scratch.glob("dep-audit-*")) - before)
    assert len(new) == 1, new
    return code, out, err, new[0]


def manifest_in(run_dir: Path) -> dict:
    return json.loads((run_dir / "audit-manifest.json").read_text())


@pytest.mark.parametrize("exc", BROKEN, ids=["oserror", "valueerror"])
def test_broken_stderr_during_a_refusal_is_exit_2_with_a_manifest(repo_tree, scratch, exc):
    repo, tree = repo_tree
    code, out, err, run_dir = call_broken(repo, tree, scratch, ["yarn.lock"], err_exc=exc)
    assert code == 2
    assert err.attempts > 0
    m = manifest_in(run_dir)
    assert m["status"] == "refused" and "yarn.lock" in m["reason"]
    assert "STATUS=refused" in out.getvalue()


@pytest.mark.parametrize("exc", BROKEN, ids=["oserror", "valueerror"])
def test_broken_stderr_after_an_unconfirmed_worker_is_exit_5_with_quarantine(repo_tree, scratch, exc):
    repo, tree = repo_tree
    unconfirmed = sandbox_fetch.FetchUnconfirmed("worker not dead", 4242, scratch / "x", None)
    code, out, err, run_dir = call_broken(repo, tree, scratch, ["requirements.txt"], raises=unconfirmed,
                                          err_exc=exc)
    assert code == 5  # never 1, which would read as "vulnerable"
    assert (run_dir / "osv").is_dir()  # the job directory stays in place
    m = manifest_in(run_dir)
    assert m["status"] == "incomplete"
    assert m["quarantine"]["pid"] == 4242 and m["quarantine"]["cleanup"] == "unconfirmed"
    assert m["quarantine"]["path"] == str(scratch / "x")
    assert "STATUS=incomplete" in out.getvalue()


def test_broken_stderr_while_listing_quarantine_does_not_stop_a_clean_run(repo_tree, scratch):
    repo, tree = repo_tree
    victim = scratch / "old-dir"
    victim.mkdir()
    sandbox_fetch.write_quarantine_record(scratch, sandbox_fetch.new_run_id(), victim, 99999999, 1.0)
    code, out, err, run_dir = call_broken(repo, tree, scratch, ["requirements.txt"],
                                          results=clean_results(2), err_exc=OSError(28, "full"))
    assert code == 0 and err.attempts > 0
    assert manifest_in(run_dir)["status"] == "complete"
    assert "AUDIT_MANIFEST_SHA256=" in out.getvalue()


@pytest.mark.parametrize("exc", BROKEN, ids=["oserror", "valueerror"])
def test_broken_stdout_on_a_clean_run_is_exit_5_never_0_or_1(repo_tree, scratch, exc):
    repo, tree = repo_tree
    code, _out, err, run_dir = call_broken(repo, tree, scratch, ["requirements.txt"],
                                           results=clean_results(2), out_exc=exc)
    assert code == 5
    assert manifest_in(run_dir)["status"] == "complete"  # the manifest is the evidence
    assert "stdout" in err.getvalue()


def test_broken_stdout_on_a_vulnerable_run_is_exit_5(repo_tree, scratch):
    repo, tree = repo_tree
    vuln = {"ok": True, "results": [[], ["GHSA-aaaa-bbbb-cccc"]],
            "details": {"GHSA-aaaa-bbbb-cccc": {"id": "GHSA-aaaa-bbbb-cccc", "summary": "x"}}}
    code, _o, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=vuln)
    assert code == 1  # control: the same answer with a working stdout is a finding
    code, _out, _err, run_dir = call_broken(repo, tree, scratch, ["requirements.txt"], results=vuln,
                                            out_exc=OSError(32, "broken pipe"))
    assert code == 5
    assert manifest_in(run_dir)["status"] == "complete"


def test_broken_stdout_and_stderr_on_a_refusal_stay_exit_2(repo_tree, scratch):
    repo, tree = repo_tree
    code, _out, _err, run_dir = call_broken(repo, tree, scratch, ["yarn.lock"],
                                            err_exc=OSError(28, "full"), out_exc=OSError(32, "pipe"))
    assert code == 2
    assert manifest_in(run_dir)["status"] == "refused"


def test_each_run_gets_its_own_run_directory(repo_tree, scratch):
    repo, tree = repo_tree
    _c1, k1, _e1, _f1 = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    _c2, k2, _e2, _f2 = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    assert k1["RUN_DIR"] != k2["RUN_DIR"]
    assert Path(k1["RUN_DIR"]).name.startswith("dep-audit-")


def test_output_is_ascii(repo_tree, scratch):
    repo, tree = repo_tree
    _c, keys, err, _f = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    for text in list(keys.values()) + [err]:
        assert text.isascii()


def test_snapshot_bytes_must_match_their_recorded_hash(tmp_path):
    repo, tree = make_repo(tmp_path, {"requirements.txt": REQ})
    snap = ss.build_snapshot(repo, tree)
    forged = [[e[0], e[1], "0" * 64] for e in snap.entries]
    with pytest.raises(dep_audit.Incomplete):
        dep_audit.read_inputs(snap.tar_bytes, forged, ["requirements.txt"])
    good = dep_audit.read_inputs(snap.tar_bytes, snap.entries, ["requirements.txt"])
    assert good["requirements.txt"][0] == REQ


# --- inspection round 1: A4, A7, A8, A11 -----------------------------------------------------

REQ_OTHER = f"requests==2.32.0 --hash=sha256:{H2}\nidna==3.4 --hash=sha256:{H1}\n".encode()


def test_two_files_pinning_different_versions_are_both_audited(tmp_path, scratch):
    """A4: an audit lists inventory pairs; the files need not form one installable set."""
    repo, tree = make_repo(tmp_path, {"a/requirements.txt": REQ, "b/requirements.txt": REQ_OTHER})
    code, keys, _e, fake = call(repo, tree, scratch, ["a/requirements.txt", "b/requirements.txt"],
                                results=clean_results(3))
    assert code == 0 and keys["STATUS"] == "complete"
    assert fake.call_args.args[0]["queries"] == [["PyPI", "idna", "3.4"], ["PyPI", "requests", "2.31.0"],
                                                 ["PyPI", "requests", "2.32.0"]]


def test_same_version_with_disjoint_hashes_is_one_pair(tmp_path, scratch):
    other = f"idna==3.4 --hash=sha256:{H1}\n".encode()  # REQ pins idna 3.4 with H2
    repo, tree = make_repo(tmp_path, {"a/requirements.txt": REQ, "b/requirements.txt": other})
    code, _k, _e, fake = call(repo, tree, scratch, ["a/requirements.txt", "b/requirements.txt"],
                              results=clean_results(2))
    assert code == 0
    assert fake.call_args.args[0]["queries"] == [["PyPI", "idna", "3.4"], ["PyPI", "requests", "2.31.0"]]


def test_unhashed_requirements_are_still_refused_among_several(tmp_path, scratch):
    repo, tree = make_repo(tmp_path, {"a/requirements.txt": REQ, "b/requirements.txt": b"pytest==8.0.0\n"})
    code, _k, _e, fake = call(repo, tree, scratch, ["a/requirements.txt", "b/requirements.txt"],
                              results=clean_results(3))
    assert code == 2
    fake.assert_not_called()


def test_plugin_files_digests_equal_file_bytes_and_cover_every_loaded_module(repo_tree, scratch):
    """A7: the manifest identifies the code that ran (the plugin has no version field)."""
    repo, tree = repo_tree
    _c, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    m = manifest_of(keys)
    assert "plugin_version" not in m
    files = m["plugin_files"]
    assert set(PLUGIN_MODULES) <= set(files)
    for name, digest in files.items():
        assert digest == hashlib.sha256((SCRIPTS / name).read_bytes()).hexdigest()
    assert m["helper_sha256"] == files["dep_audit.py"]


def test_plugin_module_names_follow_the_real_imports():
    names = set(dep_audit.plugin_module_names())
    for needed in ("sandbox_wheels.py", "redact_payload.py", "codex_ro.py"):  # transitive imports
        assert needed in names, needed
    assert "sandbox_driver.py" not in names  # the in-container driver is not loaded by the helper


def test_unconfirmed_quarantine_carries_pid_path_deadline_and_record(repo_tree, scratch):
    """A8: the manifest repeats the exact fields of the quarantine record."""
    repo, tree = repo_tree
    rec = scratch / "quarantine-abc.json"
    exc = sandbox_fetch.FetchUnconfirmed("worker not dead", 4242, scratch / "x", rec)
    exc.deadline_epoch = 1893456000.5  # set by sandbox_fetch itself in the real exception
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], raises=exc)
    assert code == 5
    q = manifest_of(keys)["quarantine"]
    assert q["pid"] == 4242 and q["path"] == str(scratch / "x") and q["record"] == str(rec)
    assert q["deadline_epoch"] == 1893456000.5
    assert q["cleanup"] == "unconfirmed"


def test_unconfirmed_without_deadline_attribute_records_null(repo_tree, scratch):
    repo, tree = repo_tree
    exc = sandbox_fetch.FetchUnconfirmed("worker not dead", 7, scratch / "x", None)
    if hasattr(exc, "deadline_epoch"):
        del exc.deadline_epoch
    _c, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], raises=exc)
    assert manifest_of(keys)["quarantine"]["deadline_epoch"] is None


def test_test_git_ignores_global_signing_config(tmp_path, monkeypatch):
    """A11: a user-level commit.gpgsign (with a gpg program that cannot exist) must not matter."""
    cfg = tmp_path / "gitconfig"
    cfg.write_text("[commit]\n\tgpgsign = true\n[tag]\n\tgpgsign = true\n"
                   "[gpg]\n\tprogram = /nonexistent/gpg-claudex\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(cfg))
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    repo, tree = make_repo(tmp_path, {"requirements.txt": REQ})
    assert len(tree) in (40, 64)
    env = git_env()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull


# --- verification gap V6: the real OSV query (opt-in) ----------------------------------------

NETWORK = os.environ.get("CLAUDEX_NETWORK_TESTS") == "1"

# Hashes taken from https://pypi.org/pypi/<name>/<version>/json on 2026-11-01 (the wheel and the sdist).
JINJA2_2_11_2 = ("jinja2==2.11.2 \\\n"
                 "    --hash=sha256:f0a4641d3cf955324a89c04f3d94663aa4d638abe8f733ecd3582848e1c37035 \\\n"
                 "    --hash=sha256:89aab215427ef59c34ad58735269eb58b1a5808103067f7bb9d5836c651b3bb0\n")
SIX_1_16_0 = ("six==1.16.0 \\\n"
              "    --hash=sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254 \\\n"
              "    --hash=sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926\n")
# OSV answers for PyPI jinja2 2.11.2 on 2026-11-01 include this advisory (ReDoS, fixed in 2.11.3).
JINJA2_ADVISORY = "GHSA-g3rq-g295-4j3m"


def real_audit(tmp_path, scratch, text):
    repo, tree = make_repo(tmp_path, {"requirements.txt": text.encode()})
    argv = ["--repo", str(repo), "--tree", tree, "--scratch", str(scratch), "--file", "requirements.txt"]
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = dep_audit.main(argv)
    keys = dict(line.split("=", 1) for line in o.getvalue().splitlines() if "=" in line)
    return code, keys, e.getvalue()


@pytest.mark.skipif(not NETWORK, reason="set CLAUDEX_NETWORK_TESTS=1 to query the real OSV API")
def test_real_osv_vulnerable_pin_exits_1_naming_the_advisory(tmp_path, scratch):
    code, keys, err = real_audit(tmp_path, scratch, JINJA2_2_11_2)
    assert code == 1, err
    report = json.loads(Path(keys["REPORT"]).read_text())
    ids = {v["id"] for p in report["packages"] for v in p["vulns"]}
    assert JINJA2_ADVISORY in ids, ids


@pytest.mark.skipif(not NETWORK, reason="set CLAUDEX_NETWORK_TESTS=1 to query the real OSV API")
def test_real_osv_clean_pin_exits_0(tmp_path, scratch):
    code, keys, err = real_audit(tmp_path, scratch, SIX_1_16_0)
    assert code == 0, err
    report = json.loads(Path(keys["REPORT"]).read_text())
    assert [p["name"] for p in report["packages"]] == ["six"] and report["packages"][0]["vulns"] == []


# --- inspection round 1, A3: an empty logical line refuses cleanly in the audit ---------------

@pytest.mark.parametrize("tail", [b"\\\n\n", b"\\\n# a comment\n", b"\\\n"], ids=["blank", "comment", "eof"])
def test_empty_continuation_is_refused_with_manifest_and_no_run_job(tmp_path, scratch, tail):
    text = f"idna==3.4 --hash=sha256:{H2}\n".encode() + tail
    repo, tree = make_repo(tmp_path, {"requirements.txt": text})
    code, keys, err, fake = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(1))
    assert code == 2 and keys["STATUS"] == "refused" and "REFUSED" in err
    fake.assert_not_called()
    m = manifest_of(keys)
    assert m["status"] == "refused" and m["report_sha256"] is None
    assert "requirements.txt:2" in m["reason"] and "joins nothing" in m["reason"]
    assert not any(p.name == "dep-audit.json" for p in Path(keys["RUN_DIR"]).iterdir())


# --- closing gate, block A2: input scope, provenance, ASCII paths, usage lines, report budget ---

@pytest.mark.parametrize("path", ["requirements.lock", "locks/test.txt", "deps/prod.in"])
def test_hashed_requirements_under_any_other_name_go_through_the_strict_parser(tmp_path, scratch, path):
    """A2-1: only package-lock.json and the known unsupported lockfiles are classified by name;
    every other file is a requirements file for the strict parser (the runner accepts the same)."""
    repo, tree = make_repo(tmp_path, {path: REQ})
    code, keys, err, fake = call(repo, tree, scratch, [path], results=clean_results(2))
    assert code == 0, err
    assert keys["STATUS"] == "complete"
    assert fake.call_args.args[0]["queries"] == [["PyPI", "idna", "3.4"], ["PyPI", "requests", "2.31.0"]]


UNSUPPORTED = ["yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock",
               "go.sum", "Gemfile.lock", "composer.lock"]


@pytest.mark.parametrize("name", UNSUPPORTED)
def test_known_unsupported_lockfiles_are_refused_by_name_before_any_read(tmp_path, scratch, name):
    repo, tree = make_repo(tmp_path, {f"sub/{name}": REQ})  # even with requirements content
    code, keys, err, fake = call(repo, tree, scratch, [f"sub/{name}"], results=clean_results(2))
    assert code == 2 and keys["STATUS"] == "refused"
    assert f"no sandbox-safe audit yet: {name}" in err
    assert f"no sandbox-safe audit yet: {name}" in manifest_of(keys)["reason"]
    fake.assert_not_called()
    with mock.patch.object(dep_audit.sandbox_run, "supervised_snapshot") as snap:
        call(repo, tree, scratch, [f"sub/{name}"], results=clean_results(2))
    snap.assert_not_called()


def test_other_file_with_non_requirements_content_is_refused_by_the_parser(tmp_path, scratch):
    repo, tree = make_repo(tmp_path, {"package.json": b'{"name": "x"}\n'})
    code, _k, err, fake = call(repo, tree, scratch, ["package.json"], results=clean_results(1))
    assert code == 2 and "REFUSED" in err
    fake.assert_not_called()


def _unreadable_provenance():
    """plugin_module_names lists a module whose bytes cannot be read (an OSError on hashing)."""
    real = dep_audit.plugin_module_names
    return mock.patch.object(dep_audit, "plugin_module_names",
                             lambda: real() + ["zz_missing_module_for_test.py"])


def test_unreadable_provenance_on_success_is_exit_5_with_reason_not_a_traceback(repo_tree, scratch):
    """A2-2: hashing the plugin files is part of the guarded manifest construction."""
    repo, tree = repo_tree
    with _unreadable_provenance():
        code, keys, err, _f = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    assert code == 5
    assert keys["STATUS"] == "incomplete"
    assert "provenance" in err and "Traceback" not in err
    m = manifest_of(keys)
    assert m["status"] == "incomplete" and "provenance" in m["reason"]
    assert m["plugin_files"] is None and m["helper_sha256"] is None
    assert keys["AUDIT_MANIFEST_SHA256"] == hashlib.sha256(
        (Path(keys["RUN_DIR"]) / "audit-manifest.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("kind", ["refused", "infrastructure", "unconfirmed"])
def test_unreadable_provenance_while_handling_another_failure_is_exit_5(repo_tree, scratch, kind):
    repo, tree = repo_tree
    files, kwargs = ["requirements.txt"], {}
    if kind == "refused":
        files = ["yarn.lock"]
        kwargs["results"] = clean_results(1)
    elif kind == "infrastructure":
        kwargs["raises"] = sandbox_fetch.FetchInfrastructure("incomplete: 503")
    else:
        kwargs["raises"] = sandbox_fetch.FetchUnconfirmed("worker not dead", 4242, scratch / "x", None)
    with _unreadable_provenance():
        code, keys, err, _f = call(repo, tree, scratch, files, **kwargs)
    assert code == 5 and keys["STATUS"] == "incomplete"
    assert "provenance" in err and "Traceback" not in err
    m = manifest_of(keys)
    assert m["status"] == "incomplete" and "provenance" in m["reason"]


def test_unserialisable_manifest_field_does_not_escape_as_a_traceback(repo_tree, scratch):
    repo, tree = repo_tree
    exc = sandbox_fetch.FetchUnconfirmed("worker not dead", 7, scratch / "x", None)
    exc.deadline_epoch = object()  # not JSON-serialisable
    code, keys, err, _f = call(repo, tree, scratch, ["requirements.txt"], raises=exc)
    assert code == 5 and "AUDIT_MANIFEST_SHA256" not in keys
    assert "could not be written" in err


def test_non_ascii_scratch_path_is_printed_ascii_escaped(repo_tree, tmp_path):
    """A2-3: RUN_DIR= and REPORT= are ASCII even when the scratch path is not."""
    repo, tree = repo_tree
    scratch = tmp_path / "scrüatch-é"
    scratch.mkdir()
    o, e = io.StringIO(), io.StringIO()
    argv = ["--repo", str(repo), "--tree", tree, "--scratch", str(scratch), "--file", "requirements.txt"]
    with mock.patch.object(dep_audit.sandbox_fetch, "run_job", mock.Mock(return_value=clean_results(2))), \
            contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = dep_audit.main(argv)
    assert code == 0, e.getvalue()
    out = o.getvalue()
    assert out.isascii() and e.getvalue().isascii()
    keys = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    run_dir = next(scratch.glob("dep-audit-*"))
    assert keys["RUN_DIR"] == str(run_dir).encode("ascii", "backslashreplace").decode("ascii")
    assert "\\xfc" in keys["RUN_DIR"] and "\\xe9" in keys["RUN_DIR"]
    assert keys["REPORT"] == str(run_dir / "dep-audit.json").encode("ascii", "backslashreplace").decode()
    assert (run_dir / "dep-audit.json").is_file()


def test_non_ascii_scratch_path_on_refusal_is_ascii(repo_tree, tmp_path):
    repo, tree = repo_tree
    scratch = tmp_path / "ü"
    scratch.mkdir()
    code, keys, err, _f = call(repo, tree, scratch, ["yarn.lock"], results=clean_results(1))
    assert code == 2
    assert all(v.isascii() for v in keys.values()) and err.isascii()


@pytest.mark.parametrize("helper", ["dep_audit.py", "sandbox_run.py"])
def test_helper_docstring_usage_lines_are_plugin_rooted_and_isolated(helper):
    """A2-4: an executable example in a helper's docstring must not name a checkout-relative
    script (`-I` does not authenticate the script being launched)."""
    import ast
    doc = ast.get_docstring(ast.parse((SCRIPTS / helper).read_text(encoding="utf-8"))) or ""
    usage = [ln.strip() for ln in doc.splitlines() if ln.strip().startswith("python")]
    assert usage, f"{helper}: no usage line found"
    for line in usage:
        assert line.startswith(f'python -I "${{CLAUDE_PLUGIN_ROOT}}/scripts/{helper}" '), line
    assert "python -I scripts/" not in doc and "python scripts/" not in doc


AMPLIFY_ID = "GHSA-ampl-ifie-rrrr"


def amplified_answer(n_queries: int, n_fixed: int) -> dict:
    """ONE advisory with a large summary and many fixed versions, referenced by every query."""
    doc = {"id": AMPLIFY_ID, "summary": "s" * 20000, "database_specific": {"severity": "HIGH"},
           "affected": [{"package": {"ecosystem": "npm", "name": "x"},
                         "ranges": [{"type": "SEMVER",
                                     "events": [{"fixed": f"9.{i}.0-{'r' * 100}"}
                                                for i in range(n_fixed)]}]}]}
    return {"ok": True, "results": [[AMPLIFY_ID] for _ in range(n_queries)], "details": {AMPLIFY_ID: doc}}


def amplified_lock(n: int) -> bytes:
    pkgs = {"": {"name": "app"}}
    for i in range(n):
        pkgs[f"node_modules/d{i}/node_modules/x"] = {
            "version": f"1.0.{i}", "resolved": f"https://registry.npmjs.org/x/-/x-1.0.{i}.tgz"}
    return json.dumps({"lockfileVersion": 3, "packages": pkgs}).encode()


def test_repeated_advisory_amplification_stops_at_the_budget_end_to_end(tmp_path, scratch):
    """A2-5/A2-7: one advisory referenced by thousands of queries must not be expanded into an
    unbounded report before the cap is checked. With the cap lowered to 1 MiB, the run must stop
    with incomplete, write no report, and allocate far less than the unbounded report would."""
    import time
    import tracemalloc
    n = 5000
    repo, tree = make_repo(tmp_path, {"package-lock.json": amplified_lock(n)})
    answer = amplified_answer(n, 200)
    cap = 1024 * 1024
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        t0 = time.monotonic()
        with mock.patch.object(dep_audit, "REPORT_CAP", cap):
            code, keys, err, fake = call(repo, tree, scratch, ["package-lock.json"], results=answer)
        elapsed = time.monotonic() - t0
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(fake.call_args.args[0]["queries"]) == n
    assert code == 5 and keys["STATUS"] == "incomplete", err
    assert "cap" in manifest_of(keys)["reason"]
    assert not (Path(keys["RUN_DIR"]) / "dep-audit.json").exists()
    # the unbounded report of this answer is about 20 MiB of JSON (plus its object graph)
    assert peak < 16 * 1024 * 1024, peak
    assert elapsed < 60, elapsed


def test_repeated_advisory_amplification_at_the_real_cap_stops_promptly_and_bounded():
    """The real 16 MiB budget: rendering aborts once the budget is spent, holding at most the
    budget plus a bounded margin -- never the whole (here about 120 MiB) expansion."""
    import time
    import tracemalloc
    n = 10000
    queries = [["npm", "x", f"1.0.{i}"] for i in range(n)]
    answer = amplified_answer(n, 1000)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        t0 = time.monotonic()
        with pytest.raises(dep_audit.Incomplete, match="16 MiB"):
            dep_audit.render_report(tree="a" * 40, inputs=[], queries=queries, answer=answer)
        elapsed = time.monotonic() - t0
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < dep_audit.REPORT_CAP + dep_audit.REPORT_MARGIN, peak
    assert dep_audit.REPORT_MARGIN <= 4 * 1024 * 1024
    assert elapsed < 60, elapsed


def test_fixed_versions_per_advisory_are_capped_with_an_explicit_marker():
    answer = amplified_answer(1, dep_audit.MAX_FIXED + 5)
    data, vulnerable = dep_audit.render_report(tree="a" * 40, inputs=[], queries=[["npm", "x", "1.0.0"]],
                                               answer=answer)
    assert vulnerable == 1
    vuln = json.loads(data)["packages"][0]["vulns"][0]
    assert len(vuln["fixed"]) == dep_audit.MAX_FIXED and vuln["fixed_truncated"] is True
    assert len(vuln["summary"]) == dep_audit.SUMMARY_CAP


def test_rendered_report_is_valid_json_with_the_same_content(repo_tree, scratch):
    repo, tree = repo_tree
    details = {"GHSA-aaaa-bbbb-cccc": {"summary": "über", "affected": []}}
    answer = {"ok": True, "results": [["GHSA-aaaa-bbbb-cccc"], []], "details": details}
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=answer)
    assert code == 1
    raw = Path(keys["REPORT"]).read_bytes()
    assert raw.isascii() and raw.endswith(b"\n")
    report = json.loads(raw)
    assert set(report) == {"coverage", "inputs", "packages", "status", "tree"}
    assert report["packages"] == [
        {"ecosystem": "PyPI", "name": "idna", "version": "3.4",
         "vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "über", "severity": None, "fixed": []}]},
        {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0", "vulns": []}]


def test_malformed_vulnerability_id_is_incomplete(repo_tree, scratch):
    repo, tree = repo_tree
    bad = "x" * 300
    answer = {"ok": True, "results": [[bad], []], "details": {bad: {"summary": ""}}}
    code, keys, _e, _f = call(repo, tree, scratch, ["requirements.txt"], results=answer)
    assert code == 5 and keys["STATUS"] == "incomplete"


# --- finding 8: the successful path holds no second full copy of the report ---------------------

def distinct_advisories_answer(n_queries: int, per_query: int, fixed_len: int = 90) -> tuple[dict, bytes]:
    """`per_query` DISTINCT advisories for each of `n_queries` npm packages x0..: a successful
    render that lands near the 16 MiB cap. Returns (OSV answer, package-lock.json bytes)."""
    details, results = {}, []
    for q in range(n_queries):
        ids = []
        for a in range(per_query):
            vid = f"GHSA-q{q:03d}-a{a:03d}-zzzz"
            ids.append(vid)
            details[vid] = {"id": vid, "summary": "s" * 500, "database_specific": {"severity": "HIGH"},
                            "affected": [{"package": {"ecosystem": "npm", "name": f"x{q:02d}"},
                                          "ranges": [{"type": "SEMVER", "events": [
                                              {"fixed": f"9.{i}.0-{'r' * fixed_len}"}
                                              for i in range(dep_audit.MAX_FIXED)]}]}]}
        results.append(ids)
    pkgs = {"": {"name": "app"}}
    for q in range(n_queries):
        pkgs[f"node_modules/x{q:02d}"] = {"version": "1.0.0",
                                      "resolved": f"https://registry.npmjs.org/x{q:02d}/-/x{q:02d}-1.0.0.tgz"}
    lock = json.dumps({"lockfileVersion": 3, "packages": pkgs}).encode()
    return {"ok": True, "results": results, "details": details}, lock


def test_successful_multi_advisory_report_peak_stays_within_the_documented_bound(tmp_path, scratch):
    """A2 gate recheck 8: 14 queries x 100 distinct advisories render a valid report near the cap;
    the peak allocation of the whole run must stay within REPORT_CAP + REPORT_MARGIN (the old
    parts-list + join held two full copies, about twice the report)."""
    import tracemalloc
    answer, lock = distinct_advisories_answer(14, 100)
    repo, tree = make_repo(tmp_path, {"package-lock.json": lock})
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        code, keys, err, _fake = call(repo, tree, scratch, ["package-lock.json"], results=answer)
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert code == 1 and keys["STATUS"] == "complete", err
    report = Path(keys["REPORT"])
    size = report.stat().st_size
    assert 12 * 1024 * 1024 < size < dep_audit.REPORT_CAP, size
    raw = report.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest_of(keys)["report_sha256"]
    assert len(json.loads(raw)["packages"]) == 14
    del raw
    assert peak < dep_audit.REPORT_CAP + dep_audit.REPORT_MARGIN, (peak, size)
    # and well below two copies of the report
    assert peak < 1.5 * size, (peak, size)


def test_report_stopped_at_the_cap_leaves_no_partial_file(tmp_path, scratch):
    answer, lock = distinct_advisories_answer(14, 100)
    repo, tree = make_repo(tmp_path, {"package-lock.json": lock})
    with mock.patch.object(dep_audit, "REPORT_CAP", 2 * 1024 * 1024):
        code, keys, _err, _f = call(repo, tree, scratch, ["package-lock.json"], results=answer)
    assert code == 5 and keys["STATUS"] == "incomplete"
    assert not (Path(keys["RUN_DIR"]) / "dep-audit.json").exists()
    assert manifest_of(keys)["report_sha256"] is None


# --- gate recheck 2, finding 8: the stated memory bounds are measured, not asserted in prose ------

def wide_advisory(vid: str, n_packages: int = 3110) -> dict:
    """An advisory naming thousands of OTHER PyPI packages, one fixed version each: about 329 KB
    of JSON (the reviewer's probe), well under the 1 MiB detail cap -- a permitted document.
    Per package the old index kept a key tuple, a normalised name and a list."""
    return {"id": vid, "summary": "s", "database_specific": {"severity": "LOW"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": f"Other_{j:05d}"},
                          "ranges": [{"events": [{"fixed": f"1.{j}"}]}]}
                         for j in range(n_packages)]}


def peak_of(fn) -> int:
    """Peak traced allocation while fn() runs; only allocations made inside fn count."""
    import tracemalloc
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        fn()
        _cur, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak


def test_stated_bounds_are_the_sums_the_docstrings_name():
    assert dep_audit.RENDER_AUX_BOUND == (dep_audit.REPORT_MARGIN + dep_audit.ENTRY_CACHE_CAP
                                          + dep_audit.INDEX_CAP)
    # render_report holds the buffer (growth slack <= 1/8) AND the joined copy
    assert dep_audit.RENDER_REPORT_BOUND >= 2 * dep_audit.REPORT_CAP + dep_audit.RENDER_AUX_BOUND


def test_advisory_indexes_of_ten_wide_documents_stay_within_the_stated_aux_bound():
    """Recheck 2 finding 8, the reviewer's probe: ten permitted ~329 KB advisories for ONE query
    rendered a 921-byte report with 11.2 MB peak -- the indexes kept every package of every
    advisory, beyond the claimed piece + entry-cache allowance (6 MiB). Only the queried packages
    are indexed now, so the peak stays below even that old allowance."""
    vids = [f"GHSA-p{i:03d}-aaaa-zzzz" for i in range(10)]
    details = {v: wide_advisory(v) for v in vids}
    assert all(300_000 < len(json.dumps(d)) < 1024 * 1024 for d in details.values())
    answer = {"ok": True, "results": [vids], "details": details}
    sizes = []
    peak = peak_of(lambda: dep_audit.render_to(lambda p: sizes.append(len(p)), "a" * 40, [],
                                               [["PyPI", "x", "1.0.0"]], answer))
    assert sum(sizes) < 4096, sum(sizes)
    assert peak <= dep_audit.RENDER_AUX_BOUND, peak
    assert peak < dep_audit.REPORT_MARGIN + dep_audit.ENTRY_CACHE_CAP, peak  # the old claim, now true


def deep_advisories(n: int, n_fixed: int = 160) -> dict:
    """n advisories naming the QUERIED package x with n_fixed distinct fixed versions each, every
    one over FIXED_CAP characters (so the kept strings are new objects), referenced by the first
    AND the last query (TWO_QUERIES), so every index stays live in between: the index worst case."""
    tail = "r" * (dep_audit.FIXED_CAP + 20)
    details, ids = {}, []
    for a in range(n):
        vid = f"GHSA-d{a:04d}-aaaa-zzzz"
        ids.append(vid)
        details[vid] = {"id": vid, "summary": "s",
                        "affected": [{"package": {"ecosystem": "npm", "name": "x"},
                                      "ranges": [{"type": "SEMVER", "events": [
                                          {"fixed": f"{k:04d}.{a}.0-{tail}"} for k in range(n_fixed)]}]}]}
    return {"ok": True, "results": [ids, ids], "details": details}


TWO_QUERIES = [["npm", "x", "1.0.0"], ["npm", "x", "2.0.0"]]


def per_advisory_index_cost() -> int:
    return (dep_audit.INDEX_VID_COST + dep_audit.INDEX_BUCKET_COST
            + (dep_audit.MAX_FIXED + 1) * (dep_audit.FIXED_CAP + dep_audit.INDEX_ITEM_COST))


def test_index_filled_close_to_its_cap_stays_within_the_stated_aux_bound():
    """The accounting must be conservative: an index charged to ~90 % of INDEX_CAP (kept fixed
    versions are fresh strings) plus a full entry cache must still peak within RENDER_AUX_BOUND."""
    n = int(0.9 * dep_audit.INDEX_CAP) // per_advisory_index_cost()
    answer = deep_advisories(n)
    out = []
    peak = peak_of(lambda: out.append(dep_audit.render_to(lambda p: None, "a" * 40, [],
                                                          TWO_QUERIES, answer)))
    assert out == [2]
    assert peak <= dep_audit.RENDER_AUX_BOUND, (peak, n)


def test_index_over_its_cap_is_incomplete_and_bounded():
    n = 2 * dep_audit.INDEX_CAP // per_advisory_index_cost()
    answer = deep_advisories(n)

    def go():
        with pytest.raises(dep_audit.Incomplete, match="index"):
            dep_audit.render_to(lambda p: None, "a" * 40, [], TWO_QUERIES, answer)
    assert peak_of(go) <= dep_audit.RENDER_AUX_BOUND


def test_kept_fixed_versions_are_the_smallest_distinct_ones_with_the_marker():
    """Keeping only MAX_FIXED + 1 versions per package must not change the report: the first
    MAX_FIXED of the sorted distinct versions, and the marker exactly when there are more."""
    events = [{"fixed": f"{k:03d}"} for k in reversed(range(dep_audit.MAX_FIXED + 7))] * 2
    doc = {"id": "GHSA-aaaa-bbbb-cccc", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "Foo_Bar"}, "ranges": [{"events": events}]}]}
    answer = {"results": [["GHSA-aaaa-bbbb-cccc"]], "details": {"GHSA-aaaa-bbbb-cccc": doc}}
    data, _v = dep_audit.render_report("a" * 40, [], [["PyPI", "foo-bar", "1"]], answer)
    vuln = json.loads(data)["packages"][0]["vulns"][0]
    assert vuln["fixed"] == [f"{k:03d}" for k in range(dep_audit.MAX_FIXED)]
    assert vuln["fixed_truncated"] is True
    exact = {"id": "GHSA-aaaa-bbbb-cccc", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "foo-bar"},
         "ranges": [{"events": [{"fixed": f"{k:03d}"} for k in range(dep_audit.MAX_FIXED)]}]}]}
    answer["details"]["GHSA-aaaa-bbbb-cccc"] = exact
    data, _v = dep_audit.render_report("a" * 40, [], [["PyPI", "foo-bar", "1"]], answer)
    vuln = json.loads(data)["packages"][0]["vulns"][0]
    assert len(vuln["fixed"]) == dep_audit.MAX_FIXED and "fixed_truncated" not in vuln


def test_render_report_peak_stays_within_its_stated_bound():
    """Recheck 2 finding 8: render_report peaked at 29.9 MB against a stated 18.9 MB -- the claim
    left out the joined copy. Its stated bound must hold, measured."""
    answer, _lock = distinct_advisories_answer(14, 100)
    queries = [["npm", f"x{q:02d}", "1.0.0"] for q in range(14)]
    got = []
    peak = peak_of(lambda: got.append(dep_audit.render_report("a" * 40, [], queries, answer)))
    data, vulnerable = got[0]
    assert vulnerable == 14 and len(data) > 12 * 1024 * 1024
    got.clear()
    del data
    assert peak <= dep_audit.RENDER_REPORT_BOUND, peak


# --- gate recheck 2, finding 11: a report that cannot be written is an infrastructure outcome ------

class FailingReport:
    """Wraps the real report file: `write` (after `ok_writes` writes) or `close` raises ENOSPC."""

    def __init__(self, real, on: str, ok_writes: int = 1):
        self.real, self.on, self.ok_writes, self.writes = real, on, ok_writes, 0

    def write(self, data):
        self.writes += 1
        if self.on == "write" and self.writes > self.ok_writes:
            raise OSError(28, "No space left on device")
        return self.real.write(data)

    def close(self):
        self.real.close()
        if self.on == "close":
            raise OSError(28, "No space left on device")

    def __getattr__(self, attr):
        return getattr(self.real, attr)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def call_failing_report(repo, tree, scratch, on, remove=None):
    real_open = dep_audit.hunt_io.open_new
    made = []

    def open_new(parent, name, base=None):
        fh = real_open(parent, name, base=base)
        if name != dep_audit.DEFAULT_OUT:  # the snapshot's own files stay real
            return fh
        made.append(FailingReport(fh, on))
        return made[-1]
    patches = [mock.patch.object(dep_audit.hunt_io, "open_new", open_new)]
    if remove is not None:
        patches.append(mock.patch.object(dep_audit.hunt_io, "remove_file", remove))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        result = call(repo, tree, scratch, ["requirements.txt"], results=clean_results(2))
    assert len(made) == 1
    return result


@pytest.mark.parametrize("on", ["write", "close"])
def test_report_write_or_close_failure_is_exit_5_incomplete_with_cleanup_recorded(repo_tree, scratch, on):
    repo, tree = repo_tree
    code, keys, err, _fake = call_failing_report(repo, tree, scratch, on)
    assert code == 5, err
    assert keys["STATUS"] == "incomplete" and "REPORT" not in keys
    assert "Traceback" not in err
    m = manifest_of(keys)
    assert m["status"] == "incomplete" and m["report_sha256"] is None
    assert "report could not be written" in m["reason"] and "28" in m["reason"]
    assert m["report_cleanup"] == "removed"
    assert not (Path(keys["RUN_DIR"]) / "dep-audit.json").exists()


def test_report_write_failure_with_failed_cleanup_records_the_retained_file(repo_tree, scratch):
    repo, tree = repo_tree
    calls = []

    def remove(parent, name, base=None):
        calls.append(name)
        raise dep_audit.hunt_io.HuntIOError("refusing: cannot remove it")
    code, keys, err, _fake = call_failing_report(repo, tree, scratch, "write", remove=remove)
    assert code == 5, err
    assert calls == ["dep-audit.json"]
    m = manifest_of(keys)
    assert m["status"] == "incomplete"
    assert m["report_cleanup"].startswith("failed")
    assert "cannot remove" in m["report_cleanup"]
    assert "REPORT" not in keys


# --- gate recheck 2, finding 10: the process exit code survives a failed standard stream ----------

@contextlib.contextmanager
def dead_pipe():
    """The write end of a pipe whose read end is already closed: every write fails (EPIPE on
    POSIX, EINVAL on Windows) -- a reader that went away."""
    r, w = os.pipe()
    os.close(r)
    try:
        yield w
    finally:
        os.close(w)


def run_helper(argv, *, stdout, stderr):
    return subprocess.run([sys.executable, "-I", str(SCRIPTS / "dep_audit.py"), *argv],
                          stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL, timeout=180, check=False)


def helper_argv(repo, tree, scratch, files):
    argv = ["--repo", str(repo), "--tree", tree, "--scratch", str(scratch)]
    for f in files:
        argv += ["--file", f]
    return argv


def test_process_exit_is_5_when_stdout_is_lost_on_a_would_be_clean_run(tmp_path, scratch):
    """Recheck 2 finding 10: main() returned 5, but the interpreter's shutdown flush of the broken
    stdout turned the PROCESS exit code into 120. Measured on a real child process."""
    repo, tree = make_repo(tmp_path, {"package-lock.json": json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}}}).encode()})
    argv = helper_argv(repo, tree, scratch, ["package-lock.json"])
    control = run_helper(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert control.returncode == 0, control.stderr
    with dead_pipe() as w:
        res = run_helper(argv, stdout=w, stderr=subprocess.PIPE)
    assert res.returncode == 5, (res.returncode, res.stderr)
    assert b"stdout" in res.stderr
    runs = sorted(scratch.glob("dep-audit-*"))
    assert len(runs) == 2
    assert all(manifest_in(r)["status"] == "complete" for r in runs)


def test_process_exit_is_2_when_stderr_fails_during_a_refusal(repo_tree, scratch):
    repo, tree = repo_tree
    argv = helper_argv(repo, tree, scratch, ["yarn.lock"])
    with dead_pipe() as w:
        res = run_helper(argv, stdout=subprocess.PIPE, stderr=w)
    assert res.returncode == 2, (res.returncode, res.stdout)
    assert b"STATUS=refused" in res.stdout


def test_process_exit_is_2_when_both_streams_fail_during_a_refusal(repo_tree, scratch):
    repo, tree = repo_tree
    argv = helper_argv(repo, tree, scratch, ["yarn.lock"])
    with dead_pipe() as w:
        res = run_helper(argv, stdout=w, stderr=w)
    assert res.returncode == 2, res.returncode
    (run_dir,) = scratch.glob("dep-audit-*")
    assert manifest_in(run_dir)["status"] == "refused"


def test_main_block_goes_through_the_stream_settling_entry():
    tail = (SCRIPTS / "dep_audit.py").read_text(encoding="utf-8").rstrip().splitlines()[-2:]
    assert tail == ['if __name__ == "__main__":', "    sys.exit(entry())"]


# --- finding 9: an ancestor .npmrc and a link entry are never read --------------------------------

class OpenRecorder:
    """Records every path opened through builtins.open, os.open and the pathlib readers."""

    def __init__(self):
        self.paths: list[str] = []

    def _note(self, target):
        if isinstance(target, int):
            return
        try:
            self.paths.append(os.path.normcase(os.path.abspath(os.fspath(target))))
        except (TypeError, ValueError):
            pass

    @contextlib.contextmanager
    def active(self):
        import builtins
        real_open, real_osopen = builtins.open, os.open
        real_rb, real_rt, real_po = Path.read_bytes, Path.read_text, Path.open
        rec = self

        def f_open(file, *a, **k):
            rec._note(file)
            return real_open(file, *a, **k)

        def f_osopen(path, *a, **k):
            rec._note(path)
            return real_osopen(path, *a, **k)

        def f_rb(self_, *a, **k):
            rec._note(self_)
            return real_rb(self_, *a, **k)

        def f_rt(self_, *a, **k):
            rec._note(self_)
            return real_rt(self_, *a, **k)

        def f_po(self_, *a, **k):
            rec._note(self_)
            return real_po(self_, *a, **k)

        with mock.patch("builtins.open", f_open), mock.patch.object(os, "open", f_osopen), \
                mock.patch.object(Path, "read_bytes", f_rb), mock.patch.object(Path, "read_text", f_rt), \
                mock.patch.object(Path, "open", f_po):
            yield self


def hostile_ancestor(tmp_path) -> tuple[Path, Path, Path]:
    """tmp/outer/.npmrc (registry elsewhere) + tmp/outer/sentinel/ (an external package dir);
    returns (outer, npmrc, sentinel dir). The repository is created at outer/repo."""
    outer = tmp_path / "outer"
    sentinel = outer / "sentinel"
    sentinel.mkdir(parents=True)
    npmrc = outer / ".npmrc"
    npmrc.write_text("registry=http://127.0.0.1:9/\n")
    (sentinel / "package.json").write_text('{"name":"sentinel","version":"6.6.6"}')
    return outer, npmrc, sentinel


def assert_never_touched(rec: OpenRecorder, outer: Path, npmrc: Path, sentinel: Path, scratch: Path):
    norm = lambda p: os.path.normcase(os.path.abspath(p))  # noqa: E731
    assert rec.paths, "the recorder saw nothing: it is not wired"
    allowed = (norm(scratch), norm(SCRIPTS))
    for opened in rec.paths:
        assert os.path.basename(opened) != ".npmrc", opened
        assert not opened.startswith(norm(sentinel)), opened
        assert opened != norm(npmrc), opened
        if opened.startswith(norm(outer) + os.sep):  # anything below the ancestor: only the scratch
            assert opened.startswith(allowed[0] + os.sep) or opened == allowed[0], opened


def test_link_entry_with_hostile_ancestor_npmrc_is_refused_without_reading_either(tmp_path):
    outer, npmrc, sentinel = hostile_ancestor(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    bad = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/ext": {"resolved": "../sentinel", "link": True}}}).encode()
    repo, tree = make_repo(outer, {"package-lock.json": bad})
    rec = OpenRecorder()
    with rec.active():
        code, keys, err, fake = call(repo, tree, scratch, ["package-lock.json"], results=clean_results(1))
    assert code == 2 and manifest_of(keys)["status"] == "refused", err
    fake.assert_not_called()
    assert_never_touched(rec, outer, npmrc, sentinel, scratch)


def test_hostile_ancestor_npmrc_without_link_runs_and_is_never_opened(tmp_path):
    outer, npmrc, sentinel = hostile_ancestor(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    repo, tree = make_repo(outer, {"package-lock.json": LOCK})
    rec = OpenRecorder()
    with rec.active():
        code, keys, err, fake = call(repo, tree, scratch, ["package-lock.json"], results=clean_results(1))
    assert code == 0 and keys["STATUS"] == "complete", err
    fake.assert_called_once()
    assert fake.call_args.args[0]["queries"] == [["npm", "left-pad", "1.3.0"]]
    assert_never_touched(rec, outer, npmrc, sentinel, scratch)
