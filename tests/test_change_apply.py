"""change_apply: review from quarantine, then publication (plan B2, approach 8, unit U5).

Every case builds its own throwaway git repository and a fixture change set in the layout the
driver/orchestrator produce (plan B2 approach 7 and the U5 interface below), so nothing here
depends on U3 or U7. Hermetic git: no system or global config, commit.gpgsign off. Written before
scripts/change_apply.py existed and seen failing first (ModuleNotFoundError).

Run-directory layout consumed here (binding for U3/U7, see the module docstring):
  manifest.json   {"tree", "source": worktree_identity(), "build_status", "changes_sha256",
                   "excluded_sha256"}
  changes.json    a JSON list, sorted by path, of {"op", "path", "mode", "base_mode", "sha256",
                   "size", "binary", "base_sha256"}
  change/<i>      the new bytes of entry i (0-based index into changes.json), added/modified only
  excluded.json   {"excluded": [{"path", "reason", "entries"}], "withheld": [paths]} (U3 format)
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import change_apply as ca  # noqa: E402
import sandbox_snapshot as ss  # noqa: E402

_GIT = ss.git_version()
pytestmark = pytest.mark.skipif(_GIT is None or _GIT < ss.MIN_GIT,
                                reason=f"git {_GIT} older than {ss.MIN_GIT} (no --no-lazy-fetch)")
NT = os.name == "nt"


def test_change_total_matches_build_policy():
    policy = json.loads((SCRIPTS.parent / "config/sandbox-policy.json").read_text(encoding="utf-8"))
    assert ca.MAX_TOTAL == policy["build"]["change_caps"]["total_bytes"]


@pytest.mark.parametrize("before,after", [(b"", b"\n"), (b"x", b"x\n\\ No newline at end of file\n")])
def test_diff_inputs_cannot_hide_eof_changes(before, after):
    assert ca._split_text(before) != ca._split_text(after)
    entry = {"op": "modified", "path": "a.txt", "base_mode": "100644", "mode": "100644",
             "base_sha256": "a" * 64, "sha256": "b" * 64}
    shown = ca._file_lines(0, entry, before, after, "full")
    assert any(line.startswith("@@") for line in shown)


def test_mode_read_refuses_multiple_hardlinks(tmp_path):
    source = tmp_path / "outside"
    source.write_bytes(b"x")
    os.link(source, tmp_path / "inside")
    with pytest.raises(ca._Conflict, match="hardlink"):
        ca._read_leaf(tmp_path, None, "inside", 1024, single_link=True)


@pytest.mark.skipif(os.name == "nt", reason="POSIX link publication")
def test_link_publication_cleanup_failure_retains_committed_state(tmp_path, monkeypatch):
    (tmp_path / "temp").write_bytes(b"new")
    fd = os.open(tmp_path, os.O_RDONLY)
    def failed_unlink(*args, **kwargs):
        raise OSError("injected cleanup failure")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(ca.os, "unlink", failed_unlink)
            with pytest.raises(ca._PublishedError):
                ca._place_new("temp", "dest", fd, tmp_path)
        assert (tmp_path / "dest").read_bytes() == b"new"
    finally:
        os.close(fd)


def test_deleted_null_content_metadata():
    entry = {"op": "deleted", "path": "gone.txt", "mode": None,
             "base_mode": "100644", "sha256": None, "base_sha256": "a" * 64,
             "size": None, "binary": None}
    assert ca._validate_entry(0, entry) == entry
    for key, value in (("size", 0), ("sha256", "b" * 64), ("binary", "false")):
        with pytest.raises(ca.ApplyRefused):
            ca._validate_entry(0, {**entry, key: value})
posix_only = pytest.mark.skipif(NT, reason="POSIX permission bits / file names")
nt_only = pytest.mark.skipif(not NT, reason="Windows behaviour")


# --- hermetic git and fixtures --------------------------------------------------------

def git_env() -> dict:
    return {**{k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")},
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def git(repo, *args, data=None, raw=False):
    res = subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                          *args], input=data, capture_output=True, env=git_env(), timeout=60)
    assert res.returncode == 0, res.stderr.decode(errors="replace")
    return res.stdout if raw else res.stdout.decode().strip()


def make_repo(root: Path, files: dict, modes: dict | None = None, ignored: dict | None = None,
              name: str = "repo") -> tuple[Path, str]:
    repo = root / name
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    for rel, data in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    if files:
        git(repo, "--literal-pathspecs", "add", "--", *files)
    for rel, mode in (modes or {}).items():
        git(repo, "--literal-pathspecs", "update-index", f"--chmod={'+x' if mode == '100755' else '-x'}",
            "--", rel)
        if not NT:
            os.chmod(repo / rel, 0o755 if mode == "100755" else 0o644)
    git(repo, "commit", "-q", "-m", "x", "--allow-empty")
    if ignored:
        (repo / ".git" / "info" / "exclude").write_text("".join(f"/{p}\n" for p in ignored))
        for rel, data in ignored.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_bytes(data)
    return repo, git(repo, "rev-parse", "HEAD^{tree}")


def tree_blob(repo, tree, path) -> tuple[bytes, str]:
    out = git(repo, "--literal-pathspecs", "ls-tree", "-z", tree, "--", path, raw=True)
    head = out.split(b"\t", 1)[0].split()
    assert head, f"{path} not in {tree}"
    return git(repo, "cat-file", "blob", head[2].decode(), raw=True), head[0].decode()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def is_bin(b: bytes) -> bool:
    if b"\0" in b[:8192]:
        return True
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


_RUNS = [0]


def make_run(tmp: Path, repo: Path, tree: str, changes: list, *, status: str = "exited",
             excluded: list | None = None, withheld: list | None = None, identity: dict | None = None,
             raw_entries: list | None = None) -> tuple[Path, str]:
    """A run directory as U7 writes it; returns (run_dir, manifest sha256)."""
    _RUNS[0] += 1
    run = tmp / f"run-{_RUNS[0]}"
    (run / "change").mkdir(parents=True)
    entries = []
    changes = sorted(changes, key=lambda c: c["path"])  # the driver writes changes.json sorted by path
    for i, c in enumerate(changes):
        op, path = c["op"], c["path"]
        base, base_mode = (None, None) if op == "added" else tree_blob(repo, tree, path)
        new = c.get("data")
        if op == "added":
            mode = c.get("mode", "100644")
        elif op == "deleted":
            mode = None
        else:
            mode = c.get("mode", base_mode)
        content = new if new is not None else (base if op == "mode" else None)
        e = {"op": op, "path": path, "mode": mode, "base_mode": base_mode,
             "sha256": sha(content) if content is not None else None,
             "size": len(content) if content is not None else None,
             "binary": c.get("binary", is_bin(content if content is not None else (base or b""))),
             "base_sha256": sha(base) if base is not None else None}
        if op in ("added", "modified"):
            (run / "change" / str(i)).write_bytes(new)
        entries.append(e)
    if raw_entries is not None:
        entries = raw_entries
    changes_bytes = json.dumps(entries).encode()
    excluded_bytes = json.dumps({"excluded": excluded or [], "withheld": withheld or []}).encode()
    (run / "changes.json").write_bytes(changes_bytes)
    (run / "excluded.json").write_bytes(excluded_bytes)
    manifest = {"tree": tree, "source": identity or ca.worktree_identity(repo),
                "build_status": status, "changes_sha256": sha(changes_bytes),
                "excluded_sha256": sha(excluded_bytes)}
    mbytes = (json.dumps(manifest, indent=1) + "\n").encode()
    (run / "manifest.json").write_bytes(mbytes)
    return run, sha(mbytes)


def run_cli(capsys, *argv) -> tuple[int, str, str]:
    code = ca.main([str(a) for a in argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def apply(capsys, run, digest, target, *extra):
    return run_cli(capsys, "apply", "--run-dir", run, "--manifest-sha256", digest, "--target", target, *extra)


def show(capsys, run, digest, repo, *extra):
    return run_cli(capsys, "show", "--run-dir", run, "--manifest-sha256", digest, "--repo", repo, *extra)


def kv(out: str) -> dict:
    d: dict = {}
    for line in out.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.isupper():
            d.setdefault(k, []).append(v)
    return d


def jlist(out: str, key: str) -> list:
    return json.loads(kv(out)[key][0])


def snapshot_tree(root: Path) -> dict:
    out = {}
    for dp, dns, fns in os.walk(root):
        if ".git" in Path(dp).relative_to(root).parts[:1]:
            continue
        dns[:] = [d for d in dns if not (Path(dp) == root and d == ".git")]
        for f in fns:
            p = Path(dp) / f
            out[p.relative_to(root).as_posix()] = (p.read_bytes(), os.lstat(p).st_mode)
        for d in dns:
            out[(Path(dp) / d).relative_to(root).as_posix() + "/"] = None
    return out


def run_printed(cmd: str, cwd: Path) -> None:
    """Execute a printed POSIX command line in `cwd` exactly as a shell would split it."""
    argv = shlex.split(cmd, posix=True)
    if argv[0] in ("rm", "rmdir") and shutil.which(argv[0]) is None:  # Windows without coreutils
        assert argv[1] == "--" and len(argv) == 3, argv
        (os.unlink if argv[0] == "rm" else os.rmdir)(cwd / argv[2])
        return
    env = git_env() if argv[0] == "git" else None
    res = subprocess.run(argv, cwd=str(cwd), capture_output=True, env=env, timeout=60)
    assert res.returncode == 0, (cmd, res.stderr.decode(errors="replace"))


@pytest.fixture
def base_repo(tmp_path):
    files = {"README.md": b"# readme\n", "src/app.py": b"print('a')\n", "src/old.py": b"old\n",
             "tools/run.sh": b"#!/bin/sh\necho run\n"}
    repo, tree = make_repo(tmp_path, files, modes={"tools/run.sh": "100755"})
    return repo, tree


# --- pure helpers ---------------------------------------------------------------------

def test_quote_posix():
    assert ca.quote_posix("a b.py") == "'a b.py'"
    assert ca.quote_posix("it's.py") == "'it'\\''s.py'"
    assert shlex.split(ca.quote_posix("it's [ab]*.py")) == ["it's [ab]*.py"]


def test_git_literal():
    assert ca.git_literal(["add"], ["*.py"]) == ["git", "--literal-pathspecs", "add", "--", "*.py"]


@pytest.mark.parametrize("existing,mode,umask,want", [
    (0o600, "100644", 0o022, 0o600),
    (0o600, "100755", 0o022, 0o700),
    (0o640, "100755", 0o022, 0o750),
    (0o755, "100644", 0o022, 0o644),
    (0o644, "100755", 0o077, 0o755),   # replaced: umask irrelevant, read bits decide
    (0o4755, "100755", 0o022, 0o755),  # setuid never carried over
    (None, "100644", 0o077, 0o600),
    (None, "100755", 0o077, 0o700),
    (None, "100644", 0o022, 0o644),
    (None, "100755", 0o022, 0o755),
])
def test_result_permissions(existing, mode, umask, want):
    assert ca.result_permissions(existing, mode, umask) == want


def test_result_permissions_rejects_other_modes():
    with pytest.raises(ca.ApplyRefused):
        ca.result_permissions(None, "120000", 0o022)


@pytest.mark.parametrize("bad", [
    ".git/config", ".GIT/hooks/x", "a/.Git/b", "GIT~1/config", "src/PROGRA~1.py", "con", "CON.txt",
    "src/aux.py", "nul", "com1.log", "LPT9", "foo.", "dir /x", "dir./x", "..", "a/../b", "./a", "a//b",
    "/abs", "a\\b", "C:x", "a:b", "caf\u00e9.py", "tab\there", "", ".codex/config.toml",
    ".CODEX/x",
])
def test_canonical_path_refusals(bad):
    with pytest.raises(ca.ApplyRefused):
        ca.canonical_entry_path(bad, is_nt=False)


@pytest.mark.parametrize("name", ["*.py", "a?b", "x|y", "q\"r", "a<b", "b>c"])
def test_windows_only_name_refusals(name):
    assert ca.canonical_entry_path(name, is_nt=False) == name
    with pytest.raises(ca.ApplyRefused):
        ca.canonical_entry_path(name, is_nt=True)


def test_accepted_odd_names():
    for name in ("[ab].py", "a b.py", "it's.py", "src/.codex/ok", "dir.d/x", "~home", "a~b.py"):
        assert ca.canonical_entry_path(name, is_nt=True) == name


def test_recovery_commands_shape():
    report = {"published": [{"path": "it's.py", "op": "modified"}, {"path": "new dir/n.py", "op": "added"},
                            {"path": "gone.py", "op": "deleted"}, {"path": "m.sh", "op": "mode"}],
              "created_dirs": ["new dir", "new dir/sub"]}
    cmds = ca.recovery_commands(report, "ab" * 20)
    tree = "ab" * 20
    assert cmds == [
        f"git --literal-pathspecs restore --source={tree} --worktree -- 'it'\\''s.py'",
        "rm -- 'new dir/n.py'",
        f"git --literal-pathspecs restore --source={tree} --worktree -- 'gone.py'",
        f"git --literal-pathspecs restore --source={tree} --worktree -- 'm.sh'",
        "rmdir -- 'new dir/sub'",
        "rmdir -- 'new dir'",
    ]


def test_mode_todo_pure():
    entries = [{"op": "modified", "path": "a.sh", "mode": "100755", "base_mode": "100644"},
               {"op": "added", "path": "it's.sh", "mode": "100755", "base_mode": None},
               {"op": "added", "path": "b.txt", "mode": "100644", "base_mode": None},
               {"op": "mode", "path": "c.sh", "mode": "100644", "base_mode": "100755"},
               {"op": "deleted", "path": "d.sh", "mode": None, "base_mode": "100755"},
               {"op": "modified", "path": "e.sh", "mode": "100755", "base_mode": "100755"}]
    index = {"a.sh": "100644", "c.sh": "100755", "d.sh": "100755", "e.sh": "100755"}
    assert ca.mode_todo(entries, index) == [
        "git --literal-pathspecs update-index --chmod=+x -- 'a.sh'",
        "git --literal-pathspecs update-index --chmod=+x -- 'it'\\''s.sh'",
        "git --literal-pathspecs update-index --chmod=-x -- 'c.sh'",
    ]


# --- worktree identity ----------------------------------------------------------------

def _norm(p) -> str:
    return os.path.normcase(os.path.realpath(p))


def test_worktree_identity_plain_repo(base_repo):
    repo, _ = base_repo
    ident = ca.worktree_identity(repo)
    assert _norm(ident["worktree"]) == _norm(repo)
    assert _norm(ident["git_dir"]) == _norm(git(repo, "rev-parse", "--absolute-git-dir"))
    assert _norm(ident["common_dir"]) == _norm(ident["git_dir"])


def test_worktree_identity_gitfile_worktree(base_repo, tmp_path):
    repo, _ = base_repo
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "--detach", str(wt))
    assert (wt / ".git").is_file()
    ident = ca.worktree_identity(wt)
    assert _norm(ident["worktree"]) == _norm(wt)
    assert _norm(ident["git_dir"]) == _norm(git(wt, "rev-parse", "--absolute-git-dir"))
    assert _norm(ident["common_dir"]) == _norm(repo / ".git")


@pytest.mark.parametrize("content", [b"gitdir: nowhere\n", b"gitdir: a\ngitdir: b\n", b"nonsense\n",
                                     b"gitdir: " + b"x" * 5000 + b"\n", b""])
def test_worktree_identity_bad_gitfile(tmp_path, content):
    d = tmp_path / "w"
    d.mkdir()
    (d / ".git").write_bytes(content)
    with pytest.raises(ca.ApplyRefused):
        ca.worktree_identity(d)


def test_worktree_identity_gitfile_to_missing_or_non_git_directory(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / ".git").write_bytes(b"gitdir: ../nowhere\n")
    with pytest.raises(ca.ApplyRefused, match="missing directory"):
        ca.worktree_identity(d)
    (tmp_path / "plain").mkdir()
    (d / ".git").write_bytes(b"gitdir: ../plain\n")
    with pytest.raises(ca.ApplyRefused, match="no HEAD"):
        ca.worktree_identity(d)


def test_worktree_identity_no_git(tmp_path):
    with pytest.raises(ca.ApplyRefused):
        ca.worktree_identity(tmp_path)


# --- apply: the happy path ------------------------------------------------------------

def test_apply_publishes_every_operation(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [
        {"op": "modified", "path": "src/app.py", "data": b"print('b')\n"},
        {"op": "added", "path": "src/new.py", "data": b"new\n"},
        {"op": "added", "path": "pkg/sub/mod.py", "data": b"mod\n", "mode": "100755"},
        {"op": "deleted", "path": "src/old.py"},
        {"op": "mode", "path": "tools/run.sh", "mode": "100644"},
    ])
    code, out, err = apply(capsys, run, digest, repo)
    assert code == 0, err
    d = kv(out)
    assert d["APPLY_STATUS"] == ["published"]
    assert jlist(out, "PUBLISHED") == ["pkg/sub/mod.py", "src/app.py", "src/new.py", "src/old.py",
                                       "tools/run.sh"]
    assert jlist(out, "NOT_PUBLISHED") == []
    assert jlist(out, "CREATED_DIRS") == ["pkg", "pkg/sub"]
    assert (repo / "src/app.py").read_bytes() == b"print('b')\n"
    assert (repo / "src/new.py").read_bytes() == b"new\n"
    assert (repo / "pkg/sub/mod.py").read_bytes() == b"mod\n"
    assert not (repo / "src/old.py").exists()
    assert (repo / "tools/run.sh").read_bytes() == b"#!/bin/sh\necho run\n"
    assert not [p for p in repo.rglob("*") if ".claudex-new" in p.name or ".claudex-pub" in p.name]
    report = json.loads((run / "apply-report.json").read_text())
    assert [p["path"] for p in report["published"]] == jlist(out, "PUBLISHED")
    if NT:
        assert "git --literal-pathspecs update-index --chmod=+x -- 'pkg/sub/mod.py'" in d["MODE_TODO"]
        assert "git --literal-pathspecs update-index --chmod=-x -- 'tools/run.sh'" in d["MODE_TODO"]
    else:
        assert "MODE_TODO" not in d
        assert stat.S_IMODE(os.lstat(repo / "tools/run.sh").st_mode) & 0o111 == 0
        assert stat.S_IMODE(os.lstat(repo / "pkg/sub/mod.py").st_mode) & 0o100


def test_apply_nothing_to_publish(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [])
    code, out, _ = apply(capsys, run, digest, repo)
    assert code == 0 and kv(out)["APPLY_STATUS"] == ["nothing"]


def test_apply_into_detached_worktree(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "--detach", str(wt))
    run, digest = make_run(tmp_path, wt, tree, [{"op": "modified", "path": "README.md", "data": b"# wt\n"}])
    code, _, err = apply(capsys, run, digest, wt)
    assert code == 0, err
    assert (wt / "README.md").read_bytes() == b"# wt\n"
    assert (repo / "README.md").read_bytes() == b"# readme\n"


# --- apply: refusals, nothing written --------------------------------------------------

def _refused(capsys, run, digest, target, *extra):
    before = snapshot_tree(target)
    code, out, err = apply(capsys, run, digest, target, *extra)
    assert code == 2, (out, err)
    assert "REFUSED" in kv(out), out
    assert snapshot_tree(target) == before, "a refusal wrote something"
    return out + err


def test_refuses_manifest_digest_mismatch(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "modified", "path": "README.md", "data": b"x\n"}])
    _refused(capsys, run, "0" * 64, repo)
    _refused(capsys, run, "not-hex", repo)


def test_refuses_tampered_blob(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "modified", "path": "README.md", "data": b"x\n"}])
    (run / "change" / "0").write_bytes(b"y\n")  # same size: only the hash can tell
    assert "sha256" in _refused(capsys, run, digest, repo)


def test_refuses_missing_blob(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"x\n"}])
    (run / "change" / "0").unlink()
    _refused(capsys, run, digest, repo)


def test_refuses_tampered_changes_json(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "modified", "path": "README.md", "data": b"x\n"}])
    data = json.loads((run / "changes.json").read_text())
    data[0]["path"] = "src/app.py"
    (run / "changes.json").write_text(json.dumps(data))
    _refused(capsys, run, digest, repo)


def test_refuses_tampered_excluded_json(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [], excluded=[{"path": ".git", "reason": "git", "entries": 3}])
    (run / "excluded.json").write_text('{"excluded": [], "withheld": []}')
    _refused(capsys, run, digest, repo)


@pytest.mark.parametrize("doc", [
    [],                                                                  # the old list form
    {"excluded": []},                                                    # withheld missing
    {"excluded": [{"path": ".git", "reason": "git"}], "withheld": []},   # entries missing
    {"excluded": [{"path": ".git", "reason": "git", "entries": -1}], "withheld": []},
    {"excluded": [{"path": ".git", "reason": "Git!", "entries": 1}], "withheld": []},
    {"excluded": [], "withheld": [""]},
    {"excluded": [], "withheld": [], "extra": 1},
])
def test_refuses_malformed_excluded_json(base_repo, tmp_path, capsys, doc):
    repo, tree = base_repo
    run, _ = make_run(tmp_path, repo, tree, [])
    data = json.dumps(doc).encode()
    (run / "excluded.json").write_bytes(data)
    m = json.loads((run / "manifest.json").read_text())
    m["excluded_sha256"] = sha(data)
    mbytes = json.dumps(m).encode()
    (run / "manifest.json").write_bytes(mbytes)
    _refused(capsys, run, sha(mbytes), repo)


def test_refuses_unsorted_changes_json(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    entries = [{"op": "added", "path": p, "mode": "100644", "base_mode": None, "sha256": sha(b"x"),
                "size": 1, "binary": False, "base_sha256": None} for p in ("b.py", "a.py")]
    run, digest = make_run(tmp_path, repo, tree, [], raw_entries=entries)
    for i in (0, 1):
        (run / "change" / str(i)).write_bytes(b"x")
    assert "sorted" in _refused(capsys, run, digest, repo)


def test_listed_only_paths_may_be_non_ascii(base_repo, tmp_path, capsys):
    """U3: a non-ASCII or backslash name refuses the set only when it was itself changed;
    excluded and withheld paths are listed (escaped where needed), never published."""
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"n\n"}],
                           excluded=[{"path": "gen/caf\u00e9\\x.pyc", "reason": "generated", "entries": 1},
                                     {"path": "out/\u202eevil", "reason": "empty_dir", "entries": 0}],
                           withheld=[".codex"])
    text = "".join(_pages(capsys, run, digest, repo, "--summary"))
    assert "excluded 'gen/caf\u00e9\\x.pyc' reason=generated entries=1" in text
    assert "\u202e" not in text and "out/\\u{202E}evil" in text
    code, _, err = apply(capsys, run, digest, repo)
    assert code == 0, err


def test_refuses_run_status_not_exited(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"x\n"}],
                           status="timeout")
    _refused(capsys, run, digest, repo)


def test_refuses_identity_mismatch(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    other, _ = make_repo(tmp_path, dict.fromkeys(("README.md", "src/app.py", "src/old.py", "tools/run.sh"),
                                                 b"x"), name="other")
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"x\n"}])
    _refused(capsys, run, digest, other)


def test_refuses_identity_mismatch_worktree_vs_main(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    wt = tmp_path / "wt"
    git(repo, "worktree", "add", "-q", "--detach", str(wt))
    run, digest = make_run(tmp_path, wt, tree, [{"op": "added", "path": "n.py", "data": b"x\n"}])
    _refused(capsys, run, digest, repo)


def test_refuses_plugin_root_inside_target(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    (repo / "plugins" / "claudex").mkdir(parents=True)
    monkeypatch.setattr(ca, "PLUGIN_ROOT", repo / "plugins" / "claudex")
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"x\n"}])
    assert "plugin" in _refused(capsys, run, digest, repo).lower()


def test_refuses_target_inside_plugin_root(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    monkeypatch.setattr(ca, "PLUGIN_ROOT", tmp_path)
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"x\n"}])
    assert "plugin" in _refused(capsys, run, digest, repo).lower()


@pytest.mark.skipif(not (Path(__file__).resolve().parents[1] / ".git").exists(),
                    reason="needs this plugin's own git checkout; the sandbox runner copies the tree "
                           "without .git (T25) -- runs on the host and in CI")
def test_refuses_this_checkout_as_target(tmp_path, capsys):
    """The real plugin root: a self-build is refused by design (plan B2, risks)."""
    real = Path(__file__).resolve().parents[1]
    run, digest = make_run(tmp_path, real, git(real, "rev-parse", "HEAD^{tree}"), [])
    code, out, _ = apply(capsys, run, digest, real)
    assert code == 2 and "plugin" in out.lower()


def test_refuses_case_collision(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "Foo.py", "data": b"1\n"},
                                                  {"op": "added", "path": "foo.py", "data": b"2\n"}])
    _refused(capsys, run, digest, repo)


def test_refuses_implied_directory_case_collision(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "Foo/a.txt", "data": b"a"},
                                                  {"op": "added", "path": "foo/b.txt", "data": b"b"}])
    _refused(capsys, run, digest, repo)
    assert not (repo / "Foo").exists() and not (repo / "foo").exists()


def test_refuses_ancestor_and_descendant(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "a", "data": b"1\n"},
                                                  {"op": "added", "path": "a/b", "data": b"2\n"}])
    _refused(capsys, run, digest, repo)
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "A/b", "data": b"2\n"},
                                                  {"op": "added", "path": "a", "data": b"1\n"}])
    _refused(capsys, run, digest, repo)


def test_refuses_bad_entry_path(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    for bad in (".git/hooks/pre-commit", "GIT~1/config", ".codex/config.toml", "../escape.py"):
        entries = [{"op": "added", "path": bad, "mode": "100644", "base_mode": None, "sha256": sha(b"x"),
                    "size": 1, "binary": False, "base_sha256": None}]
        run, digest = make_run(tmp_path, repo, tree, [], raw_entries=entries)
        (run / "change" / "0").write_bytes(b"x")
        _refused(capsys, run, digest, repo)


@pytest.mark.parametrize("entry", [
    {"op": "added", "path": "n.py", "mode": "120000", "base_mode": None, "binary": False, "base_sha256": None},
    {"op": "renamed", "path": "n.py", "mode": "100644", "base_mode": None, "binary": False,
     "base_sha256": None},
    {"op": "added", "path": "n.py", "mode": "100644", "base_mode": "100644", "binary": False,
     "base_sha256": None},
    {"op": "added", "path": "n.py", "mode": "100644", "base_mode": None, "binary": "no", "base_sha256": None},
    {"op": "added", "path": "n.py", "mode": "100644", "base_mode": None, "binary": False,
     "base_sha256": None, "extra": 1},
])
def test_refuses_malformed_entry(base_repo, tmp_path, capsys, entry):
    repo, tree = base_repo
    e = {"sha256": sha(b"x\n"), "size": 2, **entry}
    run, digest = make_run(tmp_path, repo, tree, [], raw_entries=[e])
    (run / "change" / "0").write_bytes(b"x\n")
    _refused(capsys, run, digest, repo)


def test_added_into_existing_directory_and_into_a_file(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "README.md/x.py", "data": b"x\n"}])
    _refused(capsys, run, digest, repo)
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "src/x.py", "data": b"x\n"}])
    code, out, _ = apply(capsys, run, digest, repo)
    assert code == 0 and jlist(out, "CREATED_DIRS") == []


def test_refuses_added_leaf_present(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    (repo / "src" / "late.py").write_bytes(b"someone else\n")
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "src/late.py", "data": b"x\n"}])
    _refused(capsys, run, digest, repo)


@nt_only
def test_refuses_added_leaf_present_case_insensitively_on_windows(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "readme.MD", "data": b"x\n"}])
    _refused(capsys, run, digest, repo)
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "SRC/x.py", "data": b"x\n"}])
    _refused(capsys, run, digest, repo)


def test_refuses_target_changed_before_apply(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"x\n"},
                                                  {"op": "modified", "path": "src/app.py", "data": b"y\n"}])
    (repo / "src/app.py").write_bytes(b"edited by the user\n")
    _refused(capsys, run, digest, repo)


def test_refuses_deleted_target_missing(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "deleted", "path": "src/old.py"}])
    (repo / "src/old.py").unlink()
    _refused(capsys, run, digest, repo)


def test_refuses_mode_only_target_with_changed_content(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "mode", "path": "tools/run.sh", "mode": "100644"}])
    (repo / "tools/run.sh").write_bytes(b"#!/bin/sh\necho other\n")
    _refused(capsys, run, digest, repo)


@posix_only
def test_refuses_mode_only_target_with_changed_exec_bit(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "mode", "path": "tools/run.sh", "mode": "100644"}])
    os.chmod(repo / "tools/run.sh", 0o644)  # someone else already toggled it
    _refused(capsys, run, digest, repo)


@posix_only
def test_refuses_target_reached_through_symlink(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_bytes(b"print('a')\n")
    shutil.rmtree(repo / "src")
    os.symlink(outside, repo / "src")
    run, digest = make_run(tmp_path, repo, tree, [{"op": "modified", "path": "src/app.py", "data": b"x\n"}])
    _refused(capsys, run, digest, repo)
    assert (outside / "app.py").read_bytes() == b"print('a')\n"


def test_binary_and_large_need_acceptance(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    big = (b"line of text\n" * 90000)  # > 1 MiB: not fully shown
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "img.bin", "data": b"\x00\x01\x02"},
                                                  {"op": "added", "path": "big.txt", "data": big}])
    _refused(capsys, run, digest, repo)
    _refused(capsys, run, digest, repo, "--accept-binary", "img.bin")
    _refused(capsys, run, digest, repo, "--accept-large", "big.txt")
    _refused(capsys, run, digest, repo, "--accept-binary", "img.bin", "--accept-large", "big.txt",
             "--accept-large", "README.md")  # an acceptance nothing needs is a typo: refused
    _refused(capsys, run, digest, repo, "--accept-large", "img.bin", "--accept-binary", "big.txt")
    code, out, err = apply(capsys, run, digest, repo, "--accept-binary", "img.bin", "--accept-large", "big.txt")
    assert code == 0, err
    assert (repo / "big.txt").read_bytes() == big


def test_refuses_binary_flag_that_lies(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree,
                           [{"op": "added", "path": "x.bin", "data": b"\x00evil", "binary": False}])
    _refused(capsys, run, digest, repo)


# --- apply: partial stop --------------------------------------------------------------

def _three(tmp_path, repo, tree):
    return make_run(tmp_path, repo, tree, [
        {"op": "modified", "path": "README.md", "data": b"# one\n"},
        {"op": "modified", "path": "src/app.py", "data": b"print('two')\n"},
        {"op": "added", "path": "zz/new.py", "data": b"three\n"},
    ])


def test_concurrent_edit_detected_at_pre_rename_check(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    run, digest = _three(tmp_path, repo, tree)

    def hook(entry):
        if entry["path"] == "src/app.py":
            (repo / "src/app.py").write_bytes(b"concurrent writer\n")
    monkeypatch.setattr(ca, "_HOOK_BEFORE_RECHECK", hook)
    code, out, _ = apply(capsys, run, digest, repo)
    assert code == 2
    d = kv(out)
    assert d["APPLY_STATUS"] == ["stopped"]
    assert jlist(out, "PUBLISHED") == ["README.md"]
    assert jlist(out, "NOT_PUBLISHED") == ["src/app.py", "zz/new.py"]
    assert jlist(out, "CREATED_DIRS") == ["zz"]
    assert (repo / "src/app.py").read_bytes() == b"concurrent writer\n"
    assert not (repo / "zz" / "new.py").exists()
    assert not [p for p in repo.rglob("*") if "claudex" in p.name]
    rec = d["RECOVERY"]
    tree_q = tree
    assert rec == [f"git --literal-pathspecs restore --source={tree_q} --worktree -- 'README.md'",
                   "rmdir -- 'zz'"]
    report = json.loads((run / "apply-report.json").read_text())
    assert [p["path"] for p in report["not_published"]] == ["src/app.py", "zz/new.py"]
    for cmd in rec:
        run_printed(cmd, repo)
    assert (repo / "README.md").read_bytes() == b"# readme\n"
    assert not (repo / "zz").exists()


def test_io_error_on_second_rename(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    run, digest = _three(tmp_path, repo, tree)
    calls = []
    real = ca._replace

    def flaky(*a, **k):
        calls.append(a)
        if len(calls) == 2:
            raise OSError(5, "injected I/O error")
        return real(*a, **k)
    monkeypatch.setattr(ca, "_replace", flaky)
    code, out, _ = apply(capsys, run, digest, repo)
    assert code == 5
    assert jlist(out, "PUBLISHED") == ["README.md"]
    assert jlist(out, "NOT_PUBLISHED") == ["src/app.py", "zz/new.py"]
    assert (repo / "src/app.py").read_bytes() == b"print('a')\n"
    assert not [p for p in repo.rglob("*") if "claudex" in p.name]


@posix_only
def test_cleanup_failure_reports_linked_addition_as_published(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "new.txt", "data": b"new\n"}])
    real = ca.os.unlink
    failed = False
    def unlink(path, *args, **kwargs):
        nonlocal failed
        if not failed and (repo / "new.txt").exists():
            failed = True
            raise OSError("injected post-publication cleanup failure")
        return real(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(ca.os, "unlink", unlink)
        code, out, err = apply(capsys, run, digest, repo)
    assert code == 5, err
    assert failed
    assert jlist(out, "PUBLISHED") == ["new.txt"]
    assert jlist(out, "NOT_PUBLISHED") == []
    assert (repo / "new.txt").read_bytes() == b"new\n"
    for cmd in kv(out)["RECOVERY"]:
        run_printed(cmd, repo)
    assert not (repo / "new.txt").exists()


def test_added_leaf_appearing_during_publication(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    run, digest = _three(tmp_path, repo, tree)

    def hook(entry):
        if entry["path"] == "zz/new.py":
            (repo / "zz" / "new.py").write_bytes(b"raced\n")
    monkeypatch.setattr(ca, "_HOOK_BEFORE_RECHECK", hook)
    code, out, _ = apply(capsys, run, digest, repo)
    assert code == 2
    assert jlist(out, "PUBLISHED") == ["README.md", "src/app.py"]
    assert jlist(out, "NOT_PUBLISHED") == ["zz/new.py"]
    assert (repo / "zz" / "new.py").read_bytes() == b"raced\n"


# --- permissions ----------------------------------------------------------------------

@posix_only
@pytest.mark.parametrize("before,mode,want", [
    (0o600, "100644", 0o600), (0o600, "100755", 0o700), (0o640, "100755", 0o750), (0o755, "100644", 0o644),
])
def test_replaced_file_keeps_its_bits(tmp_path, capsys, before, mode, want):
    repo, tree = make_repo(tmp_path, {"f.sh": b"one\n"},
                           modes={"f.sh": "100755" if before & 0o100 else "100644"})
    os.chmod(repo / "f.sh", before)
    run, digest = make_run(tmp_path, repo, tree, [{"op": "modified", "path": "f.sh", "data": b"two\n",
                                                   "mode": mode}])
    code, _, err = apply(capsys, run, digest, repo)
    assert code == 0, err
    assert stat.S_IMODE(os.lstat(repo / "f.sh").st_mode) == want


@posix_only
@pytest.mark.parametrize("umask,mode,want", [(0o077, "100644", 0o600), (0o077, "100755", 0o700),
                                             (0o022, "100644", 0o644), (0o022, "100755", 0o755)])
def test_addition_honours_umask(base_repo, tmp_path, capsys, umask, mode, want):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "newdir/n", "data": b"n\n",
                                                   "mode": mode}])
    old = os.umask(umask)
    try:
        code, _, err = apply(capsys, run, digest, repo)
    finally:
        os.umask(old)
    assert code == 0, err
    assert stat.S_IMODE(os.lstat(repo / "newdir/n").st_mode) == want
    assert stat.S_IMODE(os.lstat(repo / "newdir").st_mode) == 0o777 & ~umask


@posix_only
def test_mode_only_toggles_only_exec_bits(tmp_path, capsys):
    repo, tree = make_repo(tmp_path, {"m.sh": b"m\n", "p.sh": b"p\n"}, modes={"m.sh": "100755"})
    os.chmod(repo / "m.sh", 0o750)
    os.chmod(repo / "p.sh", 0o640)
    ino = os.lstat(repo / "m.sh").st_ino
    run, digest = make_run(tmp_path, repo, tree, [{"op": "mode", "path": "m.sh", "mode": "100644"},
                                                  {"op": "mode", "path": "p.sh", "mode": "100755"}])
    code, _, err = apply(capsys, run, digest, repo)
    assert code == 0, err
    assert stat.S_IMODE(os.lstat(repo / "m.sh").st_mode) == 0o640
    assert stat.S_IMODE(os.lstat(repo / "p.sh").st_mode) == 0o750
    assert os.lstat(repo / "m.sh").st_ino == ino  # toggled in place, content untouched
    assert (repo / "m.sh").read_bytes() == b"m\n"


@nt_only
def test_windows_mode_todo_lines(tmp_path, capsys):
    repo, tree = make_repo(tmp_path, {"m.sh": b"m\n", "p.sh": b"p\n", "it's.sh": b"q\n"},
                           modes={"m.sh": "100755"})
    run, digest = make_run(tmp_path, repo, tree, [
        {"op": "mode", "path": "m.sh", "mode": "100644"},
        {"op": "modified", "path": "p.sh", "data": b"p2\n", "mode": "100755"},
        {"op": "modified", "path": "it's.sh", "data": b"q2\n", "mode": "100755"},
        {"op": "added", "path": "n.sh", "data": b"n\n", "mode": "100755"},
        {"op": "added", "path": "n.txt", "data": b"n\n"},
    ])
    code, out, err = apply(capsys, run, digest, repo)
    assert code == 0, err
    todo = kv(out)["MODE_TODO"]
    assert todo == ["git --literal-pathspecs update-index --chmod=+x -- 'it'\\''s.sh'",
                    "git --literal-pathspecs update-index --chmod=-x -- 'm.sh'",
                    "git --literal-pathspecs update-index --chmod=+x -- 'n.sh'",
                    "git --literal-pathspecs update-index --chmod=+x -- 'p.sh'"]
    run_printed(kv(out)["STAGE"][0], repo)
    for cmd in todo:
        run_printed(cmd, repo)
    staged = git(repo, "ls-files", "-s", "-z", raw=True).decode()
    modes = {rec.split("\t")[1]: rec.split()[0] for rec in staged.split("\0") if rec}
    assert modes == {"m.sh": "100644", "p.sh": "100755", "it's.sh": "100755", "n.sh": "100755",
                     "n.txt": "100644"}


# --- literal paths and recovery, executed ---------------------------------------------

def test_printed_commands_touch_exactly_the_named_files(tmp_path, capsys):
    odd = ["[ab].py", "a b.py", "it's.py"] + ([] if NT else ["*.py"])
    files = {n: b"orig " + n.encode() + b"\n" for n in odd + ["x.py", "a.py", "b.py"]}
    repo, tree = make_repo(tmp_path, files)
    run, digest = make_run(tmp_path, repo, tree,
                           [{"op": "modified", "path": n, "data": b"new " + n.encode() + b"\n"} for n in odd])
    for n in ("x.py", "a.py", "b.py"):  # unrelated edits a glob would pick up
        (repo / n).write_bytes(b"unrelated\n")
    code, out, err = apply(capsys, run, digest, repo)
    assert code == 0, err
    d = kv(out)
    run_printed(d["STAGE"][0], repo)
    staged = git(repo, "diff", "--cached", "--name-only", "-z", raw=True).decode().split("\0")
    assert sorted(p for p in staged if p) == sorted(odd)
    res = subprocess.run(shlex.split(d["CHECK"][0]), cwd=str(repo), capture_output=True, env=git_env())
    assert res.returncode == 0
    assert sorted(res.stdout.decode().splitlines()) == sorted(odd)
    git(repo, "reset", "-q")
    for cmd in d["RECOVERY"]:
        run_printed(cmd, repo)
    for n in odd:
        assert (repo / n).read_bytes() == files[n]
    for n in ("x.py", "a.py", "b.py"):
        assert (repo / n).read_bytes() == b"unrelated\n"


def test_wildcard_name_refused_on_windows(tmp_path, capsys):
    repo, tree = make_repo(tmp_path, {"x.py": b"x\n"})
    entries = [{"op": "added", "path": "*.py", "mode": "100644", "base_mode": None, "sha256": sha(b"x"),
                "size": 1, "binary": False, "base_sha256": None}]
    run, digest = make_run(tmp_path, repo, tree, [], raw_entries=entries)
    (run / "change" / "0").write_bytes(b"x")
    code, out, _ = apply(capsys, run, digest, repo)
    if NT:
        assert code == 2
    else:
        assert code == 0 and (repo / "*.py").read_bytes() == b"x"


def test_recovery_restores_input_tree_including_ignored_pinned_input(tmp_path, capsys):
    repo, _ = make_repo(tmp_path, {"tracked.py": b"tracked\n", "gone.py": b"gone\n"},
                        ignored={"docs/spec.md": b"# pinned spec\n"})
    assert git(repo, "check-ignore", "docs/spec.md") == "docs/spec.md"
    idx = tmp_path / "idx"
    idx.mkdir()
    tree = ss.pin_paths(repo, ["docs/spec.md"], idx)
    for oid_path in ("docs/spec.md", "tracked.py"):  # the input tree's objects are in the odb
        git(repo, "cat-file", "-e", f"{tree}:{oid_path}")
    git(repo, "cat-file", "-e", tree)
    run, digest = make_run(tmp_path, repo, tree, [
        {"op": "modified", "path": "tracked.py", "data": b"changed\n"},
        {"op": "modified", "path": "docs/spec.md", "data": b"# spec edited by builder\n"},
        {"op": "deleted", "path": "gone.py"},
        {"op": "added", "path": "fresh/deep/new.py", "data": b"new\n"},
    ])
    before = snapshot_tree(repo)
    code, out, err = apply(capsys, run, digest, repo)
    assert code == 0, err
    assert (repo / "docs/spec.md").read_bytes() == b"# spec edited by builder\n"
    assert kv(out)["RECOVERY_CWD"] == [ca.quote_posix(str(repo))]
    for cmd in kv(out)["RECOVERY"]:
        run_printed(cmd, repo)
    assert snapshot_tree(repo) == before


# --- show -----------------------------------------------------------------------------

def _pages(capsys, run, digest, repo, *sel, inner_in_process=False):
    """Every page of a selection; asserts the PAGE k/N headers and the page bounds.
    inner_in_process: pages 2..N-1 call the worker function directly (same code, no interpreter
    start per page); page 1, page N and the out-of-range page always go through the real worker."""
    code, out, err = show(capsys, run, digest, repo, *sel)
    assert code == 0, err
    first = out.splitlines()[0]
    assert first.startswith("PAGE 1/")
    total = int(first.split("/")[1])
    pages = [out]
    for k in range(2, total + 1):
        if inner_in_process and k < total:
            code, out, err = run_cli(capsys, "--show-worker", "--run-dir", run, "--manifest-sha256", digest,
                                     "--repo", repo, *sel, "--page", k)
        else:
            code, out, err = show(capsys, run, digest, repo, *sel, "--page", k)
        assert code == 0, err
        assert out.splitlines()[0] == f"PAGE {k}/{total}"
        pages.append(out)
    for p in pages:
        assert len(p.encode("utf-8")) <= ca.PAGE_BYTES
        assert len(p.splitlines()) <= ca.PAGE_LINES + 1
    code, _, _ = show(capsys, run, digest, repo, *sel, "--page", total + 1)
    assert code == 2
    return pages


def test_show_summary_and_file(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [
        {"op": "modified", "path": "src/app.py", "data": b"print('b')\n"},
        {"op": "added", "path": "it's new.py", "data": b"new\n", "mode": "100755"},
        {"op": "deleted", "path": "src/old.py"},
        {"op": "mode", "path": "tools/run.sh", "mode": "100644"},
        {"op": "added", "path": "blob.bin", "data": b"\x00\xff"},
    ], excluded=[{"path": ".git", "reason": "git", "entries": 12},
                 {"path": "src/__pycache__/a.pyc", "reason": "generated", "entries": 1}], withheld=[".codex"])
    before = snapshot_tree(repo)
    pages = _pages(capsys, run, digest, repo, "--summary")
    text = "".join(pages)
    assert "modified 'src/app.py' 100644->100644" in text
    assert "added 'it'\\''s new.py' -->100755" in text
    assert "deleted 'src/old.py' 100644->-" in text
    assert "mode 'tools/run.sh' 100755->100644" in text
    assert "binary=yes" in text and "shown=binary" in text
    assert "excluded '.git' reason=git entries=12" in text
    assert "withheld '.codex'" in text
    # changes.json is sorted by path: blob.bin, it's new.py, src/app.py, src/old.py, tools/run.sh
    assert "binary" in "".join(_pages(capsys, run, digest, repo, "--file", 0)).lower()
    assert "+new" in "".join(_pages(capsys, run, digest, repo, "--file", 1))
    diff = "".join(_pages(capsys, run, digest, repo, "--file", 2))
    assert "-print('a')" in diff and "+print('b')" in diff
    assert "-old" in "".join(_pages(capsys, run, digest, repo, "--file", 3))
    assert "mode only" in "".join(_pages(capsys, run, digest, repo, "--file", 4))
    code, _, _ = show(capsys, run, digest, repo, "--file", 5)
    assert code == 2
    assert snapshot_tree(repo) == before, "show must never write the checkout"


def test_show_refuses_digest_mismatch_and_tampered_blob(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"n\n"},
                                                  {"op": "added", "path": "m.py", "data": b"m\n"}])
    code, _, _ = show(capsys, run, "1" * 64, repo, "--summary")
    assert code == 2
    (run / "change" / "1").write_bytes(b"t\n")  # same size as b"m\n"
    code, _, _ = show(capsys, run, digest, repo, "--file", 0)  # every blob, not only the shown one
    assert code == 2


def test_show_refuses_base_that_does_not_match(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    entries = [{"op": "modified", "path": "src/app.py", "mode": "100644", "base_mode": "100644",
                "sha256": sha(b"x\n"), "size": 2, "binary": False, "base_sha256": "f" * 64}]
    run, digest = make_run(tmp_path, repo, tree, [], raw_entries=entries)
    (run / "change" / "0").write_bytes(b"x\n")
    code, _, _ = show(capsys, run, digest, repo, "--file", 0)
    assert code == 2


def test_show_escapes_control_and_bidi_characters(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    evil = "ok = 1 \x1b[2K\r hidden\u202e reversed\u200b\n".encode()
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "e.py", "data": evil}])
    out = "".join(_pages(capsys, run, digest, repo, "--file", 0))
    for ch in ("\x1b", "\r", "\u202e", "\u200b"):
        assert ch not in out
    assert "\\u{001B}" in out and "\\u{202E}" in out


def test_show_one_900_kib_line_in_fragments(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    line = ("abcdefgh\u00e4" * (900 * 1024 // 10))  # multi-byte chars: fragments split on boundaries
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "one.txt",
                                                   "data": line.encode()}])
    pages = _pages(capsys, run, digest, repo, "--file", 0)
    assert len(pages) > 25
    frags = []
    for p in pages:
        for ln in p.splitlines()[1:]:
            if ln.startswith("[line "):
                label, _, body = ln.partition("] ")
                assert len(body.encode()) <= ca.LINE_FRAGMENT
                frags.append((label, body))
    assert frags[0][0].startswith("[line ")
    joined = "".join(b for _, b in frags)
    assert joined == "+" + line
    assert "NOT FULLY SHOWN" not in "".join(pages)


def test_show_not_fully_shown_head_and_tail(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    data = b"".join(b"row %06d\n" % i for i in range(130000))  # > 1 MiB
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "big.txt", "data": data}])
    text = "".join(_pages(capsys, run, digest, repo, "--file", 0))
    assert "NOT FULLY SHOWN" in text
    assert "row 000000" in text and "row 129999" in text and "row 065000" not in text
    code, out, _ = show(capsys, run, digest, repo, "--summary")
    assert "shown=partial" in out


def test_show_summary_20000_entries(tmp_path, capsys):
    repo, tree = make_repo(tmp_path, {"f.sh": b"f\n"})
    base_sha = sha(b"f\n")
    entries = [{"op": "mode", "path": f"d{i // 1000:02d}/file-{i:05d}.sh", "mode": "100755",
                "base_mode": "100644", "sha256": base_sha, "size": 2, "binary": False, "base_sha256": base_sha}
               for i in range(20000)]
    run, digest = make_run(tmp_path, repo, tree, [], raw_entries=entries)
    pages = _pages(capsys, run, digest, repo, "--summary", inner_in_process=True)
    assert len(pages) >= 100
    seen = []
    for p in pages:
        rows = [ln for ln in p.splitlines()[1:] if ln.startswith("[") and " mode " in ln]
        assert len(rows) <= ca.SUMMARY_ENTRIES
        seen += [ln.split("'")[1] for ln in rows]
    assert seen == [e["path"] for e in entries]


def test_paginate_bounds_pure():
    lines = ["x" * 100] * 1000 + ["y" * 5000]
    pages = ca.paginate(ca.fragment_lines(lines), max_lines=400, max_bytes=32 * 1024)
    for p in pages:
        assert len(p) <= 400
        assert sum(len(ln.encode()) + 1 for ln in p) <= 32 * 1024 - ca.HEADER_RESERVE
    assert [ln for p in pages for ln in p][:1000] == lines[:1000]


def test_show_worker_killed_at_the_deadline(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    n = 14000  # interleaved lines: difflib is quadratic here (about 10 s measured)
    a = [b"line %d\n" % i for i in range(n)]
    b = [x for pair in zip(a[: n // 2], a[n // 2:]) for x in pair]
    files = {"slow.txt": b"".join(a)}
    repo2, tree2 = make_repo(tmp_path, files, name="slow")
    run, digest = make_run(tmp_path, repo2, tree2, [{"op": "modified", "path": "slow.txt",
                                                     "data": b"".join(b)}])
    monkeypatch.setattr(ca, "SHOW_DEADLINE", 2)
    code, out, err = show(capsys, run, digest, repo2, "--file", 0)
    assert code == 5
    assert "deadline" in (out + err).lower()


def test_show_runs_in_an_isolated_worker(base_repo, tmp_path, capsys, monkeypatch):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"n\n"}])
    seen = {}
    real = subprocess.run

    def spy(argv, *a, **k):
        seen["argv"] = argv
        seen["timeout"] = k.get("timeout")
        return real(argv, *a, **k)
    monkeypatch.setattr(ca.subprocess, "run", spy)
    code, _, _ = show(capsys, run, digest, repo, "--summary")
    assert code == 0
    assert seen["argv"][:3] == [sys.executable, "-I", "-S"]
    assert "--show-worker" in seen["argv"]
    assert seen["timeout"] == ca.SHOW_DEADLINE == 60


def test_worker_flag_is_not_a_public_subcommand(capsys):
    code = ca.main(["frobnicate"])
    assert code == 2
    capsys.readouterr()


def test_output_is_ascii_for_messages(base_repo, tmp_path, capsys):
    repo, tree = base_repo
    run, digest = make_run(tmp_path, repo, tree, [{"op": "added", "path": "n.py", "data": b"n\n"}])
    code, out, err = apply(capsys, run, "0" * 64, repo)
    assert code == 2
    (out + err).encode("ascii")
