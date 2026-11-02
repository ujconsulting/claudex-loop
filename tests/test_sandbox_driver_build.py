"""sandbox_driver: the B2 modes "probe" and "build" (plan PLAN-B2-build.md, unit U3).

Plan: docs/plans/2026-10-27-sicherheitskette/PLAN-B2-build.md, approaches 4, 5, 6 and 7 and the
interface section ("sandbox_driver.py (U3)"); measurements: PLAN-B2-REVIEW-LOG.md "Step 0
measurements, proxy design (2026-11-01)".

The pure parts run on the host: spec parsing of the new modes (and that an absent or explicit
"run" mode is B1's spec), the Codex argv check, generated/withheld path rules, the baseline from
the snapshot tar bytes, the walk record framing, the change-set computation over a real temp tree,
caps, the probe classification, the default-route parser, the login check and the result shapes.

The container-side behaviour runs in-process INSIDE the image as root (the driver drops to uid
65532 with setuid), with a FAKE `codex` on the driver's PATH -- real Codex never runs and no real
credential exists anywhere in these tests:

  docker --context desktop-linux run --rm --network none -e CLAUDEX_DRIVER_INPROC=1
  -v <repo>:/src:ro -w /tmp/r <codex-build image id> sh -c 'cp -r /src/. /tmp/r &&
  python3 -m unittest -v tests.test_sandbox_driver_build'

One optional real-container probe (CLAUDEX_DOCKER_TESTS=1) starts the driver through the
runner's stdin loader in the codex-build image on --network none; it involves no Codex at all.
Written before the driver change and seen failing first.
"""
from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import sandbox_driver as sd  # noqa: E402

NONCE = "0123456789abcdef0123456789abcdef"
B1_RESULT_KEYS = ["nonce", "command_status", "command_exit", "truncated", "durations", "exports",
                  "infrastructure", "deps"]
POLICY = json.loads((REPO / "config" / "sandbox-policy.json").read_text(encoding="utf-8"))
CAPS = dict(POLICY["build"]["change_caps"])
GENERATED = list(POLICY["build"]["generated_paths"])
WITHHELD = list(POLICY["build"]["withheld_paths"])
BUILD_DISABLE = ["apps", "plugins"]


def codex_argv(last=None, extra=()):
    last = last or (sd.OUT + "/codex-last.txt")
    argv = ["codex", "exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
            "--ignore-user-config", "--ignore-rules", "-c", 'model="gpt-6.1-sol"',
            "-c", 'model_reasoning_effort="high"', "-c", 'sandbox_mode="danger-full-access"',
            "-c", 'approval_policy="never"', "-c", "notify=[]"]
    for feature in BUILD_DISABLE:
        argv += ["--disable", feature]
    argv += list(extra) + ["--json", "-o", last, "-"]
    return argv


def build_spec(**over):
    spec = {"mode": "build", "tar_len": 10, "deps_len": 0, "deps_sha256": "", "deps_timeout": 300,
            "codex_argv": codex_argv(), "proxy_url": "http://10.240.0.2:3128", "ca_len": 5,
            "placeholder_len": 7, "prompt_len": 3, "change_caps": dict(CAPS),
            "generated_paths": list(GENERATED), "withheld_paths": list(WITHHELD), "codex_timeout": 600}
    spec.update(over)
    return spec


def probe_spec(**over):
    spec = {"mode": "probe", "probe_targets": [["tcp", "10.240.0.1", 22], ["udp", "8.8.8.8", 53],
                                               ["tcp", "2001:db8::1", 443], ["dns", "example.com", 0]],
            "probe_deadline": 20, "exclude_addrs": ["10.240.0.2", "10.240.0.3"]}
    spec.update(over)
    return spec


def run_spec(**over):
    spec = {"argv": ["true"], "exports": [], "capture_cap": 1024, "export_cap": 1024, "timeout": 10,
            "tar_len": 0, "deps_len": 0, "deps_sha256": "", "deps_timeout": 10}
    spec.update(over)
    return spec


def tar_of(entries, fmt=tarfile.GNU_FORMAT):
    """entries: (name, bytes or None for a directory, mode)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, content, mode in entries:
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.uid, ti.gid = 0, 65532, 65532
            ti.mode = mode
            if content is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(content)
                tf.addfile(ti, io.BytesIO(content))
    return buf.getvalue()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def placeholder(refresh=True):
    tokens = {"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjF9.c2ln", "access_token": "claudex-placeholder-x",  # gitleaks:allow -- fake expired JWT
              "account_id": "00000000-0000-4000-8000-000000000000"}
    if refresh:
        tokens["refresh_token"] = ""
    return json.dumps({"auth_mode": "chatgpt", "OPENAI_API_KEY": None, "tokens": tokens}).encode()


CA_PEM = b"-----BEGIN CERTIFICATE-----\nTUlJ\n-----END CERTIFICATE-----\n"


# ============================================================================== spec parsing


class RunModeSpecTests(unittest.TestCase):
    """B1/B1.5 unchanged: no mode key, or mode "run", is exactly B1's spec."""

    def test_absent_mode_is_run(self):
        s = sd.parse_spec(run_spec())
        self.assertEqual(s.mode, "run")
        self.assertEqual(s.argv, ["true"])

    def test_explicit_run_mode(self):
        s = sd.parse_spec(run_spec(mode="run"))
        self.assertEqual(s.mode, "run")
        self.assertIsInstance(s, sd.Spec)

    def test_unknown_mode_refused(self):
        for bad in ("RUN", "shell", "", None, 1, ["build"]):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(run_spec(mode=bad))

    def test_build_keys_not_allowed_in_run(self):
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(run_spec(codex_argv=codex_argv()))
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(run_spec(mode="run", probe_targets=[]))


class ProbeSpecTests(unittest.TestCase):
    def test_good(self):
        s = sd.parse_spec(probe_spec())
        self.assertEqual(s.mode, "probe")
        self.assertEqual(s.targets[0], ("tcp", "10.240.0.1", 22))
        self.assertEqual(s.targets[3], ("dns", "example.com", 0))
        self.assertEqual(s.deadline, 20)
        self.assertEqual(s.exclude, ("10.240.0.2", "10.240.0.3"))

    def test_keys_exact(self):
        spec = probe_spec()
        del spec["exclude_addrs"]
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(spec)
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(probe_spec(tar_len=0))

    def test_bad_targets(self):
        for bad in ([], "x", [["tcp", "10.0.0.1"]], [["icmp", "10.0.0.1", 1]],
                    [["tcp", "example.com", 80]], [["tcp", "10.0.0.1", 0]], [["tcp", "10.0.0.1", 65536]],
                    [["udp", "10.0.0.1", True]], [["dns", "10.0.0.1", 0]], [["dns", "exa mple.com", 0]],
                    [["dns", "example.com", 53]], [["tcp", "10.0.0.1", 80]] * 600,
                    [["tcp", "10.0.0.01", 80]]):
            with self.assertRaises(sd.SpecError, msg=repr(bad)[:80]):
                sd.parse_spec(probe_spec(probe_targets=bad))

    def test_excluded_address_as_target_refused(self):
        """Own and proxy addresses are excluded: a target on one of them is an orchestrator bug,
        and probing the proxy would report a reachable host."""
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(probe_spec(probe_targets=[["tcp", "10.240.0.2", 22]]))
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(probe_spec(probe_targets=[["udp", "10.240.0.3", 53]]))

    def test_deadline_and_excludes(self):
        for bad in (0, 61, "20", True):
            with self.assertRaises(sd.SpecError):
                sd.parse_spec(probe_spec(probe_deadline=bad))
        for bad in ("10.0.0.1", ["nope"], [1], ["10.0.0.1"] * 17):
            with self.assertRaises(sd.SpecError):
                sd.parse_spec(probe_spec(exclude_addrs=bad))


class BuildSpecTests(unittest.TestCase):
    def test_good(self):
        s = sd.parse_spec(build_spec())
        self.assertEqual(s.mode, "build")
        self.assertEqual(s.codex_argv, codex_argv())
        self.assertEqual(s.withheld, (".codex",))
        self.assertEqual((s.ca_len, s.placeholder_len, s.prompt_len), (5, 7, 3))
        self.assertEqual(s.caps, CAPS)

    def test_keys_exact(self):
        for key in build_spec():
            if key == "mode":
                continue
            spec = build_spec()
            del spec[key]
            with self.assertRaises(sd.SpecError, msg=key):
                sd.parse_spec(spec)
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(build_spec(argv=["true"]))

    def test_lengths_bounded(self):
        for key, bad in (("prompt_len", 0), ("prompt_len", 1024 * 1024 + 1), ("ca_len", 0),
                         ("ca_len", 65537), ("placeholder_len", 0), ("placeholder_len", 65537),
                         ("codex_timeout", 0), ("codex_timeout", 3601), ("tar_len", -1)):
            with self.assertRaises(sd.SpecError, msg=key):
                sd.parse_spec(build_spec(**{key: bad}))

    def test_proxy_url(self):
        for good in ("http://10.240.0.2:3128", "http://10.240.7.10:3128"):
            self.assertEqual(sd.parse_spec(build_spec(proxy_url=good)).proxy_url, good)
        for bad in ("https://10.240.0.2:3128", "http://proxy:3128", "http://10.240.0.2", "http://10.240.0.2:0",
                    "http://user@10.240.0.2:3128", "http://10.240.0.2:3128/", "http://300.1.1.1:3128",
                    "http://10.240.0.2:3128\n"):
            with self.assertRaises(sd.SpecError, msg=bad):
                sd.parse_spec(build_spec(proxy_url=bad))

    def test_caps(self):
        caps = dict(CAPS)
        del caps["added_files"]
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(build_spec(change_caps=caps))
        for key in CAPS:
            with self.assertRaises(sd.SpecError, msg=key):
                sd.parse_spec(build_spec(change_caps=dict(CAPS, **{key: 0})))
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(build_spec(change_caps=dict(CAPS, extra=1)))
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(build_spec(change_caps=dict(CAPS, total_bytes=1024 ** 3)))

    def test_path_rules(self):
        for bad in (["a/[b]"], ["/abs/**"], ["a\\b"], ["../x"], [""], "x", [1]):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(build_spec(generated_paths=bad))
        for bad in (["**/x/**"], [".codex"], ["*.codex/**"], ["a/../b/**"], ["/x/**"], ["a//b/**"]):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(build_spec(withheld_paths=bad))


class CodexArgvTests(unittest.TestCase):
    """approach 7: the start line is fixed; every -c is from a closed list, sandbox, approval and
    notify carry their fixed values; the prompt comes on stdin ("-")."""

    def test_good(self):
        self.assertEqual(sd.validate_codex_argv(codex_argv()), codex_argv())

    def test_prefix_required(self):
        for drop in ("--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
                     "--ignore-user-config", "--ignore-rules"):
            argv = codex_argv()
            argv.remove(drop)
            with self.assertRaises(sd.SpecError, msg=drop):
                sd.validate_codex_argv(argv)
        argv = codex_argv()
        argv[0] = "/opt/codex/bin/codex"
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv)

    def test_resume_refused(self):
        argv = codex_argv()
        argv.insert(2, "resume")
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv)

    def test_config_overrides_closed_list(self):
        for extra in (["-c", 'mcp_servers.x.command="sh"'], ["-c", 'shell_environment_policy.inherit="all"'],
                      ["-c", 'model_provider="x"'], ["--profile", "x"], ["--cd", "/"], ["--add-dir", "/"],
                      ["--enable", "apps"], ["--disable", "a b"], ["-m", "gpt"], ["--yolo"]):
            with self.assertRaises(sd.SpecError, msg=repr(extra)):
                sd.validate_codex_argv(codex_argv(extra=extra))

    def test_fixed_values(self):
        for old, new in (('sandbox_mode="danger-full-access"', 'sandbox_mode="read-only"'),
                         ('approval_policy="never"', 'approval_policy="on-request"'),
                         ("notify=[]", 'notify=["sh"]'), ('model="gpt-6.1-sol"', 'model="a b"'),
                         ('model_reasoning_effort="high"', "model_reasoning_effort=high")):
            argv = [new if a == old else a for a in codex_argv()]
            with self.assertRaises(sd.SpecError, msg=new):
                sd.validate_codex_argv(argv)

    def test_each_fixed_override_once(self):
        argv = codex_argv()
        argv = argv[:6] + ["-c", 'model="x"'] + argv[6:]
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv)
        argv = [a for a in codex_argv() if a != "notify=[]"]
        argv.remove("-c")  # the -c that preceded it (all -c are equal, any one goes)
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv)

    def test_output_and_stdin_tail(self):
        argv = codex_argv()
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv[:-1])
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(codex_argv(last="/work/repo/last.txt"))
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv([a for a in argv if a != "--json"])
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv[:-1] + ["prompt text"])
        with self.assertRaises(sd.SpecError):
            sd.validate_codex_argv(argv + ["-"])


# ============================================================================== path rules


class PathRuleTests(unittest.TestCase):
    def setUp(self):
        self.gen = sd.parse_generated(GENERATED)

    def test_generated_matches(self):
        for path in ("__pycache__/a.pyc", "src/__pycache__/x.cpython-313.pyc", "a/b/c.pyc", "x.pyc",
                     ".pytest_cache/v/cache/nodeids", "src/.coverage", ".coverage", "src/__pycache__"):
            self.assertTrue(sd.generated_match(self.gen, path), path)
        for path in ("src/a.py", "pycache/a.py", "a.pyc.txt", "coverage", "src/.coveragerc",
                     "__pycache__x/a.py"):
            self.assertFalse(sd.generated_match(self.gen, path), path)

    def test_glob_semantics(self):
        pats = sd.parse_generated(["build/*.o", "**/node_modules/**", "dist/**"])
        self.assertTrue(sd.generated_match(pats, "build/a.o"))
        self.assertFalse(sd.generated_match(pats, "build/x/a.o"))
        self.assertTrue(sd.generated_match(pats, "a/b/node_modules/c/d.js"))
        self.assertTrue(sd.generated_match(pats, "dist/a/b"))
        self.assertFalse(sd.generated_match(pats, "src/dist/a"))

    def test_withheld(self):
        prefixes = sd.parse_withheld([".codex/**", "a/b/**"])
        self.assertEqual(prefixes, (".codex", "a/b"))
        for path in (".codex", ".codex/config.toml", "a/b", "a/b/c/d"):
            self.assertTrue(sd.under_any(prefixes, path), path)
        for path in (".codexx", "x/.codex", "a/bc", "a"):
            self.assertFalse(sd.under_any(prefixes, path), path)

    def test_git_component(self):
        for path in (".git", "a/.git", "a/.git/config", ".GIT/x", "sub/.Git"):
            self.assertTrue(sd.git_component(path), path)
        for path in (".gitignore", "a/.github/x", "git", "a/x.git"):
            self.assertFalse(sd.git_component(path), path)

    def test_change_path_problem(self):
        self.assertIsNone(sd.change_path_problem("src/a b.py"))
        self.assertIsNone(sd.change_path_problem("it's [x].py"))
        for bad in ("a\\b", "café.md", "a\tb", "a\nb", "\x7f", ""):
            self.assertIsNotNone(sd.change_path_problem(bad), repr(bad))


# ============================================================================== baseline


class BaselineTests(unittest.TestCase):
    def test_from_tar_bytes(self):
        tar = tar_of([("src", None, 0o755), ("src/a.py", b"A\n", 0o644), ("run.sh", b"#!/bin/sh\n", 0o755),
                      (".codex", None, 0o755), (".codex/config.toml", b"[mcp_servers]\n", 0o644),
                      ("spec.md", b"pinned, ignored\n", 0o644)])
        base = sd.baseline_from_tar(tar, ("." "codex",))
        self.assertEqual(base.files, {"src/a.py": (sha(b"A\n"), "100644"),
                                      "run.sh": (sha(b"#!/bin/sh\n"), "100755"),
                                      "spec.md": (sha(b"pinned, ignored\n"), "100644")})
        self.assertEqual(base.withheld, [".codex", ".codex/config.toml"])
        self.assertEqual(base.extract, ["src", "src/a.py", "run.sh", "spec.md"])
        self.assertIn("src", base.dirs)
        self.assertNotIn(".codex", base.dirs)

    def test_parents_are_dirs(self):
        base = sd.baseline_from_tar(tar_of([("a/b/c.txt", b"x", 0o644)]), ())
        self.assertEqual(base.dirs, {"a", "a/b"})

    def test_refusals(self):
        cases = [
            [(".git/config", b"x", 0o644)],
            [("sub/.GIT", b"x", 0o644)],
            [("../x", b"x", 0o644)],
            [("/abs", b"x", 0o644)],
            [("a", b"x", 0o644), ("a", b"y", 0o644)],
        ]
        for entries in cases:
            with self.assertRaises(sd.BaselineError, msg=repr(entries)):
                sd.baseline_from_tar(tar_of(entries), ())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
            ti = tarfile.TarInfo("link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)
        with self.assertRaises(sd.BaselineError):
            sd.baseline_from_tar(buf.getvalue(), ())
        with self.assertRaises(sd.BaselineError):
            sd.baseline_from_tar(b"not a tar" * 100, ())

    def test_dot_slash_prefix_normalised(self):
        base = sd.baseline_from_tar(tar_of([("./a.txt", b"x", 0o644)]), ())
        self.assertEqual(list(base.files), ["a.txt"])


# ============================================================================== records + change set


class RecordTests(unittest.TestCase):
    def test_round_trip(self):
        data = (sd.encode_record("F", 0o100644, 3, b"a.txt", b"abc") + sd.encode_record("D", 0o40755, 2, b"src")
                + sd.encode_record("Z", 0, 0, b""))
        self.assertEqual(sd.parse_records(data), [("F", 0o100644, 3, b"a.txt", b"abc"),
                                                  ("D", 0o40755, 2, b"src", b""), ("Z", 0, 0, b"", b"")])

    def test_malformed(self):
        good = sd.encode_record("F", 0o100644, 3, b"a.txt", b"abc")
        z = sd.encode_record("Z", 0, 0, b"")
        for bad in (good, good[:-1] + z, b"Q 0 0 1\nx" + z, b"F 1 2\n" + z, good + z + b"x",
                    b"F 0 0 5000\n" + b"a" * 5000 + z, b"F -1 0 1\nx" + z, b""):
            with self.assertRaises(ValueError, msg=repr(bad[:30])):
                sd.parse_records(bad)


def rec(kind, path, data=b"", mode=0o100644, size=None):
    if size is None:
        size = len(data)
    return (kind, mode, size, path.encode("utf-8"), data if kind in ("F", "E") else b"")


class ComputeChangesTests(unittest.TestCase):
    def setUp(self):
        self.gen = sd.parse_generated(GENERATED)
        self.tar = tar_of([("a.txt", b"A\n", 0o644), ("b.sh", b"B\n", 0o755), ("c.txt", b"C\n", 0o644),
                           ("del.txt", b"D\n", 0o644), ("old.pyc", b"pyc\n", 0o644),
                           (".codex/config.toml", b"x", 0o644)])
        self.base = sd.baseline_from_tar(self.tar, (".codex",))

    def compute(self, records, caps=None):
        return sd.compute_changes(self.base, list(records) + [("Z", 0, 0, b"", b"")], self.gen,
                                  dict(CAPS, **(caps or {})))

    def test_all_operations(self):
        out = self.compute([
            rec("F", "a.txt", b"A2\n"),                       # modified
            rec("F", "b.sh", b"B\n", mode=0o100644),          # mode only 755 -> 644
            rec("F", "c.txt", b"C\n", mode=0o100755),         # mode only 644 -> 755
            rec("F", "old.pyc", b"pyc2\n"),                   # a changed BASELINE path is never excluded
            rec("D", "new", size=1, mode=0o40755),
            rec("F", "new/x.py", b"print(1)\n"),              # added
            rec("F", "img.bin", b"\x89PNG\x00\x01"),          # added binary
            rec("S", "new/__pycache__/x.pyc", size=10),       # generated, skipped by the helper
            rec("D", "new/__pycache__", size=1, mode=0o40755),
            rec("G", ".git", size=12, mode=0o40755),          # builder git init
            rec("D", "empty", size=0, mode=0o40755),          # an added empty directory
        ])
        self.assertEqual(out["status"], "ok", out["reason"])
        ops = {c["path"]: c for c in out["changes"]}
        self.assertEqual([c["path"] for c in out["changes"]],
                         ["a.txt", "b.sh", "c.txt", "del.txt", "img.bin", "new/x.py", "old.pyc"])
        self.assertEqual(ops["a.txt"], {"op": "modified", "path": "a.txt", "mode": "100644", "base_mode": "100644",
                                        "sha256": sha(b"A2\n"), "size": 3, "binary": False,
                                        "base_sha256": sha(b"A\n")})
        self.assertEqual((ops["b.sh"]["op"], ops["b.sh"]["mode"], ops["b.sh"]["base_mode"]),
                         ("mode", "100644", "100755"))
        self.assertEqual(ops["b.sh"]["sha256"], ops["b.sh"]["base_sha256"])
        self.assertEqual((ops["c.txt"]["op"], ops["c.txt"]["mode"]), ("mode", "100755"))
        self.assertEqual(ops["del.txt"], {"op": "deleted", "path": "del.txt", "mode": None, "base_mode": "100644",
                                          "sha256": None, "size": None, "binary": None,
                                          "base_sha256": sha(b"D\n")})
        self.assertEqual((ops["new/x.py"]["op"], ops["new/x.py"]["base_mode"], ops["new/x.py"]["base_sha256"]),
                         ("added", None, None))
        self.assertTrue(ops["img.bin"]["binary"])
        self.assertEqual(ops["old.pyc"]["op"], "modified")
        # blobs: change/<n>, n = index in changes.json, only added and modified
        blobs = dict(out["blobs"])
        idx = {c["path"]: n for n, c in enumerate(out["changes"])}
        self.assertEqual(set(blobs), {idx["a.txt"], idx["img.bin"], idx["new/x.py"], idx["old.pyc"]})
        self.assertEqual(blobs[idx["new/x.py"]], b"print(1)\n")
        excluded = {e["path"]: e for e in out["excluded"]}
        self.assertEqual(excluded[".git"], {"path": ".git", "reason": "git", "entries": 13})
        self.assertEqual(excluded["new/__pycache__/x.pyc"]["reason"], "generated")
        self.assertEqual(excluded["empty"]["reason"], "empty_dir")
        self.assertNotIn("new/__pycache__", excluded, "a non-empty directory is not a difference")
        self.assertEqual(out["withheld"], [".codex/config.toml"])
        self.assertEqual(out["counts"], {"added": 2, "modified": 2, "deleted": 1, "mode": 2, "binary": 1,
                                         "excluded": 3, "withheld": 1})

    def test_withheld_absent_is_not_a_deletion(self):
        out = self.compute([rec("F", n, d, mode=m) for n, d, m in (
            ("a.txt", b"A\n", 0o100644), ("b.sh", b"B\n", 0o100755), ("c.txt", b"C\n", 0o100644),
            ("del.txt", b"D\n", 0o100644), ("old.pyc", b"pyc\n", 0o100644))])
        self.assertEqual((out["status"], out["changes"]), ("ok", []))
        self.assertEqual(out["counts"]["withheld"], 1)

    def test_refusals(self):
        cases = {
            "withheld": [rec("W", ".codex", size=0, mode=0o40755)],
            "symlink": [rec("L", "evil", mode=0o120777)],
            "special": [rec("O", "fifo", mode=0o10644)],
            "symlink on a baseline path": [rec("L", "a.txt", mode=0o120777)],
            "file cap": [rec("B", "big.bin", size=10 ** 9)],
            "entry cap": [("C", 0, 0, b"", b"")],
            "byte cap": [("T", 0, 0, b"", b"")],
            "walk error": [rec("E", "x", b"cannot read")],
            "backslash": [rec("F", "a\\b.txt", b"x")],
            "non-ascii": [rec("F", "café.md", b"x")],
            "not utf-8": [("F", 0o100644, 1, b"\xff.txt", b"x")],
            "non-ascii deletion": [],
        }
        for name, records in cases.items():
            base = self.base
            if name == "non-ascii deletion":
                self.base = sd.baseline_from_tar(tar_of([("café.md", b"x", 0o644)]), ())
            try:
                out = self.compute(records)
            finally:
                self.base = base
            self.assertEqual(out["status"], "refused", name)
            self.assertTrue(out["reason"], name)
            self.assertEqual((out["changes"], out["blobs"]), ([], []), name)
            out["reason"].encode("ascii")

    def test_unchanged_non_ascii_baseline_path_is_fine(self):
        self.base = sd.baseline_from_tar(tar_of([("café.md", b"x", 0o644)]), ())
        out = self.compute([rec("F", "café.md", b"x")])
        self.assertEqual((out["status"], out["changes"]), ("ok", []))

    def test_generated_symlink_and_dir_are_excluded_not_refused(self):
        out = self.compute([rec("L", "src/__pycache__/l", mode=0o120777),
                            rec("D", ".pytest_cache", size=0, mode=0o40755)] + [
            rec("F", n, d, mode=m) for n, d, m in (
                ("a.txt", b"A\n", 0o100644), ("b.sh", b"B\n", 0o100755), ("c.txt", b"C\n", 0o100644),
                ("del.txt", b"D\n", 0o100644), ("old.pyc", b"pyc\n", 0o100644))])
        self.assertEqual(out["status"], "ok", out["reason"])
        self.assertEqual({e["path"]: e["reason"] for e in out["excluded"]},
                         {"src/__pycache__/l": "generated", ".pytest_cache": "generated"})

    def test_caps_in_the_driver(self):
        out = self.compute([rec("F", "n%d.txt" % i, b"x") for i in range(3)], caps={"added_files": 2})
        self.assertEqual(out["status"], "refused")
        self.assertIn("added", out["reason"])
        out = self.compute([rec("F", "big.txt", b"x" * 100)], caps={"file_bytes": 50})
        self.assertEqual(out["status"], "refused")
        out = self.compute([rec("F", "n%d.txt" % i, b"x" * 40) for i in range(3)], caps={"total_bytes": 100})
        self.assertEqual(out["status"], "refused")
        out = self.compute([rec("D", "d%d" % i, size=1, mode=0o40755) for i in range(5)], caps={"entries": 4})
        self.assertEqual(out["status"], "refused")

    def test_missing_end_marker_refused(self):
        out = sd.compute_changes(self.base, [rec("F", "a.txt", b"A\n")], self.gen, CAPS)
        self.assertEqual(out["status"], "refused")

    def test_is_binary(self):
        self.assertFalse(sd.is_binary(b"plain\ntext \xc3\xa9\n"))
        self.assertTrue(sd.is_binary(b"a\x00b"))
        self.assertTrue(sd.is_binary(b"\xff\xfe"))
        self.assertTrue(sd.is_binary(b"x" * 9000 + b"\xff"))   # not UTF-8 anywhere = binary
        self.assertFalse(sd.is_binary(b"x" * 9000 + b"\x00"))  # NUL only counts in the first 8 KiB
        self.assertFalse(sd.is_binary(b""))


class WalkTreeHostTests(unittest.TestCase):
    """walk_tree() itself (the uid-65532 helper body, without the privilege drop) over a real temp
    tree, then the driver's parser and change set -- the parts that are not container-specific."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="walk", dir=str(REPO / ".claudex-tmp")
                                     if (REPO / ".claudex-tmp").is_dir() else None)
        self.addCleanup(shutil.rmtree, self.root, True)

    def put(self, rel, data):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)

    def walk(self, baseline_paths=(), caps=None):
        chunks = []
        sd.walk_tree(os.fsencode(self.root), frozenset(baseline_paths), sd.parse_generated(GENERATED),
                     sd.parse_withheld(WITHHELD), dict(CAPS, **(caps or {})), chunks.append)
        return sd.parse_records(b"".join(chunks))

    def test_tree(self):
        self.put("a.txt", b"A2\n")
        self.put("src/new.py", b"new\n")
        self.put("src/__pycache__/new.cpython-313.pyc", b"\x00pyc")
        self.put(".git/objects/aa/bb", b"blob")
        self.put(".git/HEAD", b"ref: refs/heads/main\n")
        os.mkdir(os.path.join(self.root, "empty"))
        records = self.walk()
        kinds = {(k, p.decode()) for k, _m, _s, p, _d in records}
        self.assertIn(("F", "a.txt"), kinds)
        self.assertIn(("F", "src/new.py"), kinds)
        self.assertIn(("S", "src/__pycache__/new.cpython-313.pyc"), kinds)
        self.assertIn(("G", ".git"), kinds)
        self.assertIn(("D", "empty"), kinds)
        self.assertFalse(any(p.startswith(b".git/") for _k, _m, _s, p, _d in records), "walked into .git")
        self.assertEqual(records[-1][0], "Z")
        git = [r for r in records if r[0] == "G"][0]
        self.assertEqual(git[2], 4)  # objects, objects/aa, objects/aa/bb, HEAD: counted, not sent
        base = sd.baseline_from_tar(tar_of([("a.txt", b"A\n", 0o644), ("gone.txt", b"G\n", 0o644)]), ())
        out = sd.compute_changes(base, records, sd.parse_generated(GENERATED), CAPS)
        self.assertEqual(out["status"], "ok", out["reason"])
        self.assertEqual([(c["op"], c["path"]) for c in out["changes"]],
                         [("modified", "a.txt"), ("deleted", "gone.txt"), ("added", "src/new.py")])
        self.assertEqual({e["path"]: e["reason"] for e in out["excluded"]},
                         {".git": "git", "src/__pycache__/new.cpython-313.pyc": "generated", "empty": "empty_dir"})

    def test_generated_baseline_file_is_read(self):
        self.put("keep/__pycache__/x.pyc", b"changed")
        records = self.walk(baseline_paths={"keep/__pycache__/x.pyc"})
        self.assertIn(("F", b"keep/__pycache__/x.pyc", b"changed"), {(r[0], r[3], r[4]) for r in records})

    def test_withheld_not_descended(self):
        self.put(".codex/config.toml", b"[mcp_servers.x]\n")
        records = self.walk()
        self.assertEqual([(r[0], r[3]) for r in records[:-1]], [("W", b".codex")])

    def test_caps_stop_the_walk(self):
        for i in range(10):
            self.put("f%d.txt" % i, b"x" * 10)
        self.assertEqual(self.walk(caps={"entries": 5})[-2][0], "C")
        self.assertEqual(self.walk(caps={"total_bytes": 35})[-2][0], "T")
        self.put("big.bin", b"y" * 100)
        records = self.walk(caps={"file_bytes": 50})
        self.assertIn(("B", b"big.bin"), {(r[0], r[3]) for r in records})


# ============================================================================== probe, login, env, results


class ProbePureTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(sd.classify_errno(0), "reached")
        self.assertEqual(sd.classify_errno(errno.ECONNREFUSED), "reached")
        for err in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT,
                    errno.EADDRNOTAVAIL, errno.ENETDOWN):
            self.assertEqual(sd.classify_errno(err), "blocked", err)
        self.assertEqual(sd.classify_errno(errno.ETIMEDOUT), "timeout")
        self.assertEqual(sd.classify_errno(errno.EIO), "error")

    def test_status(self):
        self.assertEqual(sd.probe_status(["blocked"] * 3, False, False), "isolated")
        self.assertEqual(sd.probe_status(["blocked", "reached"], False, False), "isolation_failed")
        self.assertEqual(sd.probe_status(["blocked", "reached", None], False, True), "isolation_failed")
        self.assertEqual(sd.probe_status(["blocked"], True, False), "isolation_failed")
        self.assertEqual(sd.probe_status(["blocked", None], False, False), "isolation_unverified")
        self.assertEqual(sd.probe_status(["blocked"], False, True), "isolation_unverified")
        self.assertEqual(sd.probe_status(["blocked", "timeout"], False, False), "isolation_unverified")
        self.assertEqual(sd.probe_status(["error"], False, False), "isolation_unverified")
        self.assertEqual(sd.probe_status([], False, False), "isolation_unverified")

    def test_default_route_v4(self):
        head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        local = "eth0\t0000F00A\t00000000\t0001\t0\t0\t0\tF8FFFFFF\t0\t0\t0\n"
        default = "eth0\t00000000\t0100F00A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        reject = "eth0\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n"
        self.assertFalse(sd.default_route_v4(head + local))
        self.assertTrue(sd.default_route_v4(head + local + default))
        self.assertFalse(sd.default_route_v4(head + reject))
        self.assertFalse(sd.default_route_v4(head))
        with self.assertRaises(ValueError):
            sd.default_route_v4("garbage")

    def test_default_route_v6(self):
        zero = "0" * 32
        unreachable = "%s 00 %s 00 %s ffffffff 00000001 00000000 00200200       lo\n" % (zero, zero, zero)
        default = "%s 00 %s 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" % (
            zero, zero)
        local = "fe800000000000000000000000000000 40 %s 00 %s 00000100 00000001 00000000 00000001 eth0\n" % (
            zero, zero)
        self.assertFalse(sd.default_route_v6(local + unreachable))
        self.assertTrue(sd.default_route_v6(local + default))
        self.assertFalse(sd.default_route_v6(""))


class LoginEnvResultTests(unittest.TestCase):
    def test_login_ok(self):
        self.assertTrue(sd.login_ok(0, b"Logged in using ChatGPT\n"))
        self.assertFalse(sd.login_ok(1, b"Logged in using ChatGPT\n"))
        self.assertFalse(sd.login_ok(0, b"Logged in using an API key - sk-***\n"))
        self.assertFalse(sd.login_ok(0, b"Error checking login status: missing field `refresh_token`"))
        self.assertFalse(sd.login_ok(None, b"Logged in using ChatGPT\n"))
        self.assertFalse(sd.login_ok(0, b"Not logged in\n"))

    def test_codex_env(self):
        env = sd.codex_env("http://10.240.0.2:3128", False)
        self.assertEqual(env["CODEX_HOME"], sd.CODEX_HOME)
        self.assertEqual(env["CODEX_CA_CERTIFICATE"], sd.CODEX_HOME + "/ca.pem")
        for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            self.assertEqual(env[key], "http://10.240.0.2:3128")
        self.assertEqual((env["NO_PROXY"], env["no_proxy"]), ("", ""))
        self.assertTrue(env["PATH"].startswith("/opt/codex/package/vendor/x86_64-unknown-linux-musl/bin:"))
        self.assertNotIn("PYTHONPATH", env)
        self.assertEqual(set(env), {"HOME", "PATH", "LANG", "CODEX_HOME", "CODEX_CA_CERTIFICATE", "HTTPS_PROXY",
                                    "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy"})
        self.assertEqual(sd.codex_env("http://10.240.0.2:3128", True)["PYTHONPATH"], sd.DEPS + "/site")

    def test_build_path_matches_the_image(self):
        dockerfile = (REPO / "config" / "sandbox" / "codex-build.Dockerfile").read_text(encoding="utf-8")
        self.assertIn("/opt/codex/package/vendor/x86_64-unknown-linux-musl/bin", dockerfile)
        self.assertIn(sd.CODEX_HOME, dockerfile)

    def test_build_result_shape(self):
        build = {"codex_exit": 0, "change_status": "ok", "change_reason": None, "login_status": "chatgpt",
                 "counts": {k: 0 for k in sd.COUNT_KEYS}}
        r = sd.build_build_result(NONCE, "exited", 0, False, {}, {"codex-last.txt": "missing"}, None, None, build)
        self.assertEqual(list(r), B1_RESULT_KEYS + ["build"])
        self.assertEqual(list(r["build"]), ["codex_exit", "change_status", "change_reason", "counts",
                                            "login_status"])
        for bad in ({"codex_exit": 1}, {"change_status": "maybe"}, {"login_status": "apikey"},
                    {"counts": {}}, {"change_reason": 3}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                sd.build_build_result(NONCE, "exited", 0, False, {}, {}, None, None, dict(build, **bad))

    def test_probe_result_shape(self):
        r = sd.build_probe_result(NONCE, "isolated", False, False,
                                  [("tcp", "10.0.0.1", 22, "blocked", "ENETUNREACH")], {}, None)
        self.assertEqual(list(r), ["nonce", "mode", "status", "default_route", "child_killed", "counts",
                                   "results", "durations", "infrastructure"])
        self.assertEqual(r["results"], [["tcp", "10.0.0.1", 22, "blocked", "ENETUNREACH"]])
        self.assertEqual(r["counts"], {"reached": 0, "blocked": 1, "timeout": 0, "error": 0, "unreported": 0})
        with self.assertRaises(ValueError):
            sd.build_probe_result(NONCE, "fine", False, False, [], {}, None)

    def test_build_member_names(self):
        for name in ("result.json", "codex-events.jsonl", "codex-last.txt", "codex-stderr.txt", "login.txt",
                     "install.txt", "changes.json", "excluded.json", "change/0", "change/19999"):
            self.assertTrue(sd.build_member_ok(name), name)
        for name in ("stdout.txt", "out/x", "change/", "change/01", "change/a", "change/1/2", "../x"):
            self.assertFalse(sd.build_member_ok(name), name)
        sd.build_result_tar([("change/3", b"x")], name_ok=sd.build_member_ok)
        with self.assertRaises(ValueError):
            sd.build_result_tar([("change/3", b"x")])  # B1's framing is unchanged

    def test_docstring_describes_the_loader(self):
        doc = sd.__doc__
        self.assertIn("loader", doc)
        self.assertNotIn("zlib", doc)
        self.assertNotIn("base85", doc)
        self.assertIn("after the loader block", doc)
        for word in ("probe", "build", "codex login status", "--ignore-user-config", "withheld"):
            self.assertIn(word, doc)


# ============================================================================== in-image, in-process


def _inproc_allowed():
    """As in test_sandbox_driver: quiesce() SIGKILLs every uid-65532 process; only inside a
    throwaway container with the explicit opt-in."""
    return (hasattr(os, "fork") and hasattr(os, "geteuid") and os.geteuid() == 0
            and os.environ.get("CLAUDEX_DRIVER_INPROC") == "1" and os.path.exists("/.dockerenv"))


FAKE_CODEX = r'''#!/usr/local/bin/python3 -I
import json, os, subprocess, sys
args = sys.argv[1:]
home = os.environ.get("CODEX_HOME", "")
if args[:2] == ["login", "status"]:
    try:
        with open(os.path.join(home, "auth.json")) as handle:
            doc = json.load(handle)
        ok = doc.get("auth_mode") == "chatgpt" and doc.get("tokens", {}).get("refresh_token") == ""
    except Exception:
        ok = False
    if ok:
        print("Logged in using ChatGPT")
        sys.exit(0)
    print("Error checking login status: missing field `refresh_token`", file=sys.stderr)
    sys.exit(1)
if args[:1] == ["exec"]:
    prompt = sys.stdin.buffer.read().decode()
    out = args[args.index("-o") + 1]
    st = {n: [os.stat(os.path.join(home, n)).st_uid, oct(os.stat(os.path.join(home, n)).st_mode)]
          for n in ("auth.json", "ca.pem")}
    with open(os.path.join(home, "auth.json"), "rb") as a, open(os.path.join(home, "ca.pem"), "rb") as c:
        auth, ca = a.read().decode(), c.read().decode()
    info = {"argv": ["codex"] + args, "env": dict(os.environ), "cwd": os.getcwd(), "uid": os.getuid(),
            "prompt": prompt, "auth": auth, "ca": ca, "home_stat": st, "dot_codex": os.path.exists(".codex"),
            "dot_git": os.path.exists(".git")}
    with open(out, "w") as handle:
        json.dump(info, handle)
    print(json.dumps({"type": "turn.completed"}))
    sys.stdout.flush()
    script = prompt.split("\n---SCRIPT---\n", 1)[1] if "\n---SCRIPT---\n" in prompt else ""
    sys.exit(subprocess.call(["sh", "-c", script]) if script else 0)
sys.exit(2)
'''


@unittest.skipUnless(_inproc_allowed(), "needs root inside a throwaway container and CLAUDEX_DRIVER_INPROC=1")
class InProcessBuildTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.base = tempfile.mkdtemp(prefix="drvb")
        os.chmod(self.base, 0o755)
        self.dirs = {}
        for name in ("work", "out", "deps", "codex_home"):
            path = os.path.join(self.base, name)
            os.mkdir(path)
            os.chmod(path, 0o1777)
            self.dirs[name] = path
        self.bin = os.path.join(self.base, "bin")
        os.mkdir(self.bin, 0o755)
        fake = os.path.join(self.bin, "codex")
        with open(fake, "w") as handle:
            handle.write(FAKE_CODEX)
        os.chmod(fake, 0o755)
        path = self.bin + ":/usr/local/bin:/usr/bin:/bin"
        for name, value in (("WORK", self.dirs["work"]), ("OUT", self.dirs["out"]), ("DEPS", self.dirs["deps"]),
                            ("SCRATCH", os.path.join(self.base, "scratch")),
                            ("CODEX_HOME", self.dirs["codex_home"]), ("BUILD_PATH", path)):
            patcher = mock.patch.object(sd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Guard: the fake, never a real Codex, is what the driver's PATH resolves.
        self.assertEqual(shutil.which("codex", path=sd.BUILD_PATH), fake)

    def tearDown(self):
        try:
            sd.quiesce(sd.CHILD_UIDS)
        finally:
            shutil.rmtree(self.base, ignore_errors=True)

    def run_main(self, files, script="", auth=None, codex_timeout=60, caps=None, prompt_text="build it"):
        from unittest import mock
        tar = tar_of(files)
        prompt = (prompt_text + ("\n---SCRIPT---\n" + script if script else "")).encode()
        auth = placeholder() if auth is None else auth
        spec = build_spec(tar_len=len(tar), prompt_len=len(prompt), placeholder_len=len(auth), ca_len=len(CA_PEM),
                          codex_timeout=codex_timeout, codex_argv=codex_argv(),
                          change_caps=dict(CAPS, **(caps or {})))
        payload = NONCE.encode() + b"\n" + json.dumps(spec).encode() + b"\n" + tar + prompt + auth + CA_PEM

        class _Std:
            def __init__(self, data=b""):
                self.buffer = io.BytesIO(data)

        fake_in, fake_out = _Std(payload), _Std()
        with mock.patch.object(sys, "stdin", fake_in), mock.patch.object(sys, "stdout", fake_out):
            self.assertEqual(sd.main(), 0)
        members, order = {}, []
        with tarfile.open(fileobj=io.BytesIO(fake_out.buffer.getvalue()), mode="r:") as tf:
            for m in tf.getmembers():
                self.assertTrue(m.isreg())
                order.append(m.name)
                members[m.name] = tf.extractfile(m).read()
        result = json.loads(members["result.json"])
        self.assertEqual(order[0], "result.json")
        self.assertEqual(result["nonce"], NONCE)
        return result, members

    def changes(self, members):
        return {c["path"]: c for c in json.loads(members["changes.json"])}

    BASE = [("a.txt", b"A\n", 0o644), ("b.sh", b"#!/bin/sh\n", 0o755), ("c.txt", b"C\n", 0o644),
            ("del.txt", b"D\n", 0o644), ("src", None, 0o755), ("src/m.py", b"M\n", 0o644)]

    def test_login_rejected_never_starts_codex(self):
        result, members = self.run_main(self.BASE, script="echo X > a.txt", auth=placeholder(refresh=False))
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["build"]["login_status"], "rejected")
        self.assertEqual((result["command_status"], result["command_exit"]), ("not_started", None))
        self.assertEqual(result["build"]["change_status"], "not_computed")
        self.assertEqual(result["exports"], {"codex-last.txt": "missing"})
        self.assertNotIn("codex-last.txt", members)
        self.assertIn(b"refresh_token", members["login.txt"])
        self.assertEqual(json.loads(members["changes.json"]), [])

    def test_launch_argv_env_and_codex_home(self):
        result, members = self.run_main(self.BASE + [(".codex", None, 0o755),
                                                     (".codex/config.toml", b"[mcp_servers.s]\n", 0o644)])
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["build"]["login_status"], "chatgpt")
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0))
        info = json.loads(members["codex-last.txt"])
        self.assertEqual(result["exports"]["codex-last.txt"], sha(members["codex-last.txt"]))
        self.assertEqual(info["argv"], codex_argv())
        self.assertEqual(info["uid"], 65532)
        self.assertEqual(info["cwd"], os.path.join(sd.WORK, "repo"))
        self.assertEqual(info["prompt"], "build it")
        self.assertEqual(info["auth"].encode(), placeholder())
        self.assertEqual(info["ca"].encode(), CA_PEM)
        for name in ("auth.json", "ca.pem"):
            self.assertEqual(info["home_stat"][name][0], 65532)
            self.assertEqual(int(info["home_stat"][name][1], 8) & 0o777, 0o600)
        env = info["env"]
        self.assertEqual(env["CODEX_HOME"], sd.CODEX_HOME)
        self.assertEqual(env["CODEX_CA_CERTIFICATE"], sd.CODEX_HOME + "/ca.pem")
        self.assertEqual(env["HTTPS_PROXY"], "http://10.240.0.2:3128")
        self.assertEqual(env["NO_PROXY"], "")
        self.assertNotIn("CLAUDEX_DRIVER_INPROC", env)
        self.assertFalse(info["dot_codex"], ".codex/ was extracted")
        self.assertFalse(info["dot_git"])
        self.assertEqual(members["codex-events.jsonl"], b'{"type": "turn.completed"}\n')
        self.assertEqual(result["build"]["change_status"], "ok")
        self.assertEqual(json.loads(members["changes.json"]), [], "withheld .codex/ absent is not a deletion")
        excluded = json.loads(members["excluded.json"])
        self.assertEqual(excluded["withheld"], [".codex", ".codex/config.toml"])
        self.assertEqual(result["build"]["counts"]["withheld"], 2)

    def test_change_set_against_real_writes(self):
        script = ("set -e; echo A2 > a.txt; chmod -x b.sh; chmod +x c.txt; rm del.txt; mkdir -p new/deep;"
                  " echo 'print(1)' > new/deep/x.py; printf 'b\\000in' > blob.bin; rm -r src;"
                  " mkdir -p pkg/__pycache__; echo pyc > pkg/__pycache__/m.cpython-313.pyc; touch .coverage;"
                  " mkdir emptydir; id -u > who.txt")
        result, members = self.run_main(self.BASE, script=script)
        self.assertEqual(result["build"]["change_status"], "ok", result["build"]["change_reason"])
        ch = self.changes(members)
        self.assertEqual({p: c["op"] for p, c in ch.items()},
                         {"a.txt": "modified", "b.sh": "mode", "c.txt": "mode", "del.txt": "deleted",
                          "new/deep/x.py": "added", "blob.bin": "added", "src/m.py": "deleted", "who.txt": "added"})
        self.assertEqual((ch["b.sh"]["mode"], ch["b.sh"]["base_mode"]), ("100644", "100755"))
        self.assertEqual((ch["c.txt"]["mode"], ch["c.txt"]["base_mode"]), ("100755", "100644"))
        self.assertTrue(ch["blob.bin"]["binary"])
        order = json.loads(members["changes.json"])
        n = [c["path"] for c in order].index("who.txt")
        self.assertEqual(members["change/%d" % n], b"65532\n")
        self.assertEqual(sha(members["change/%d" % n]), order[n]["sha256"])
        blobs = sorted(m for m in members if m.startswith("change/"))
        self.assertEqual(len(blobs), 4)  # a.txt, new/deep/x.py, blob.bin, who.txt
        excluded = {e["path"]: e["reason"] for e in json.loads(members["excluded.json"])["excluded"]}
        self.assertEqual(excluded, {"pkg/__pycache__/m.cpython-313.pyc": "generated", ".coverage": "generated",
                                    "emptydir": "empty_dir"})
        self.assertEqual(result["build"]["counts"]["added"], 3)

    def test_builder_git_is_excluded_and_reported(self):
        script = ("set -e; echo A2 > a.txt; git init -q; git add -A;"
                  " git -c user.email=b@x -c user.name=b commit -qm build; echo A3 > a.txt;"
                  " mkdir -p sub; git init -q sub; echo n > sub/n.txt")
        result, members = self.run_main(self.BASE, script=script)
        self.assertEqual(result["build"]["change_status"], "ok", result["build"]["change_reason"])
        ch = self.changes(members)
        self.assertEqual(ch["a.txt"]["op"], "modified")
        self.assertEqual(ch["sub/n.txt"]["op"], "added")
        excluded = json.loads(members["excluded.json"])["excluded"]
        gits = {e["path"]: e for e in excluded if e["reason"] == "git"}
        self.assertEqual(set(gits), {".git", "sub/.git"})
        self.assertGreater(gits[".git"]["entries"], 5)
        self.assertFalse(any(p.startswith(".git") or "/.git" in p for p in ch))

    def test_dot_codex_recreated_is_refused(self):
        result, members = self.run_main(self.BASE + [(".codex/config.toml", b"x", 0o644)],
                                        script="mkdir .codex && echo y > .codex/config.toml && echo A2 > a.txt")
        self.assertEqual(result["build"]["change_status"], "refused")
        self.assertIn("withheld", result["build"]["change_reason"])
        self.assertEqual(json.loads(members["changes.json"]), [])
        self.assertFalse([m for m in members if m.startswith("change/")])

    def test_symlink_fifo_and_caps_refuse(self):
        for script, caps, word in (("ln -s /etc/passwd evil", None, "symlink"),
                                   ("mkfifo pipe", None, "special"),
                                   ("head -c 5000 /dev/zero > big.bin", {"file_bytes": 4096}, "cap"),
                                   ("for i in 1 2 3; do echo $i > n$i.txt; done", {"added_files": 2}, "added")):
            result, members = self.run_main(self.BASE, script=script, caps=caps)
            self.assertEqual(result["build"]["change_status"], "refused", script)
            self.assertIn(word, result["build"]["change_reason"], script)
            self.tearDown()
            self.setUp()

    def test_unreadable_builder_files_are_still_compared(self):
        script = "echo A2 > a.txt; chmod 000 a.txt; mkdir locked; echo L > locked/l.txt; chmod 000 locked"
        result, members = self.run_main(self.BASE, script=script)
        self.assertEqual(result["build"]["change_status"], "ok", result["build"]["change_reason"])
        ch = self.changes(members)
        self.assertEqual((ch["a.txt"]["op"], ch["locked/l.txt"]["op"]), ("modified", "added"))

    def test_background_builder_processes_quiesced_before_the_walk(self):
        """A builder that leaves writers behind: every uid-65532 process is dead before the walk
        starts, and nothing they would write later reaches the change set."""
        from unittest import mock
        real = sd.run_walk
        seen = []

        def checked(*args, **kwargs):
            seen.append(sd.scan_proc(sd.PROC, {sd.RUN_UID})[0])
            return real(*args, **kwargs)

        script = ("(while :; do echo x >> bg.txt; done) >/dev/null 2>&1 & "
                  "(sleep 2; echo late > late.txt) >/dev/null 2>&1 & "
                  "while [ ! -s bg.txt ]; do :; done; exit 0")
        with mock.patch.object(sd, "run_walk", checked):
            result, members = self.run_main(self.BASE, script=script)
        self.assertEqual(seen, [[]], "uid-65532 processes alive when the walk started")
        self.assertEqual(result["build"]["change_status"], "ok", result["build"]["change_reason"])
        ch = self.changes(members)
        self.assertIn("bg.txt", ch)
        self.assertNotIn("late.txt", ch)
        time.sleep(2.5)
        self.assertFalse(os.path.exists(os.path.join(sd.WORK, "repo", "late.txt")))

    def test_codex_timeout(self):
        result, members = self.run_main(self.BASE, script="echo A2 > a.txt; sleep 30", codex_timeout=3)
        self.assertEqual((result["command_status"], result["command_exit"]), ("timeout", None))
        self.assertIsNone(result["build"]["codex_exit"])
        self.assertEqual(result["build"]["change_status"], "ok")
        self.assertEqual(self.changes(members)["a.txt"]["op"], "modified")

    def test_codex_nonzero_exit(self):
        result, _members = self.run_main(self.BASE, script="exit 3")
        self.assertEqual((result["command_status"], result["command_exit"], result["build"]["codex_exit"]),
                         ("exited", 3, 3))

    def test_codex_home_must_be_fresh(self):
        with open(os.path.join(sd.CODEX_HOME, "auth.json"), "w") as handle:
            handle.write("{}")
        result, members = self.run_main(self.BASE)
        self.assertIn("codex-home", result["infrastructure"])
        self.assertEqual(result["build"]["change_status"], "not_computed")
        self.assertEqual(result["command_status"], "not_started")

    def test_snapshot_with_git_is_infrastructure(self):
        result, _members = self.run_main(self.BASE + [(".git/config", b"[core]\n", 0o644)])
        self.assertIn(".git", result["infrastructure"])
        self.assertEqual(result["command_status"], "not_started")


@unittest.skipUnless(_inproc_allowed(), "needs root inside a throwaway container and CLAUDEX_DRIVER_INPROC=1")
class InProcessProbeTests(unittest.TestCase):
    def setUp(self):
        from unittest import mock
        self.base = tempfile.mkdtemp(prefix="drvp")
        patcher = mock.patch.object(sd, "SCRATCH", os.path.join(self.base, "scratch"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        try:
            sd.quiesce(sd.CHILD_UIDS)
        finally:
            shutil.rmtree(self.base, ignore_errors=True)

    def run_main(self, targets, deadline=6, exclude=("10.240.0.2",)):
        from unittest import mock
        spec = probe_spec(probe_targets=targets, probe_deadline=deadline, exclude_addrs=list(exclude))
        payload = NONCE.encode() + b"\n" + json.dumps(spec).encode() + b"\n"

        class _Std:
            def __init__(self, data=b""):
                self.buffer = io.BytesIO(data)

        fake_in, fake_out = _Std(payload), _Std()
        with mock.patch.object(sys, "stdin", fake_in), mock.patch.object(sys, "stdout", fake_out):
            self.assertEqual(sd.main(), 0)
        with tarfile.open(fileobj=io.BytesIO(fake_out.buffer.getvalue()), mode="r:") as tf:
            names = tf.getnames()
            result = json.loads(tf.extractfile("result.json").read())
        self.assertEqual(names, ["result.json"])
        return result

    UNREACHABLE = [["tcp", "10.240.0.1", 22], ["tcp", "10.240.0.4", 443], ["udp", "8.8.8.8", 53],
                   ["tcp", "1.1.1.1", 443], ["tcp", "2001:db8::1", 443], ["dns", "example.invalid", 0]]

    def test_network_none_is_isolated(self):
        started = time.monotonic()
        result = self.run_main(self.UNREACHABLE)
        self.assertEqual(result["status"], "isolated", result)
        self.assertEqual(result["counts"]["blocked"], len(self.UNREACHABLE))
        self.assertFalse(result["default_route"])
        self.assertLess(time.monotonic() - started, 6)

    def test_reachable_listener_fails_isolation(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]
        result = self.run_main(self.UNREACHABLE + [["tcp", "127.0.0.1", port], ["tcp", "127.0.0.1", 1]])
        self.assertEqual(result["status"], "isolation_failed")
        by = {(r[1], r[2]): r[3] for r in result["results"]}
        self.assertEqual(by[("127.0.0.1", port)], "reached")
        self.assertEqual(by[("127.0.0.1", 1)], "reached", "a RST is a host answering")

    def test_probe_runs_as_65532_and_concurrently(self):
        from unittest import mock
        def slow_dns(_name):
            time.sleep(1.5)
            return "blocked", "uid=%d euid=%d" % (os.getuid(), os.geteuid())

        with mock.patch.object(sd, "probe_one_dns", slow_dns):
            started = time.monotonic()
            result = self.run_main([["dns", "a.invalid", 0], ["dns", "b.invalid", 0], ["dns", "c.invalid", 0]])
        self.assertEqual(result["status"], "isolated", result)
        self.assertEqual({r[4] for r in result["results"]}, {"uid=65532 euid=65532"})
        self.assertLess(time.monotonic() - started, 4, "the resolutions did not run concurrently")

    def test_hanging_resolver_is_unverified(self):
        from unittest import mock
        with mock.patch.object(sd, "probe_one_dns", lambda _name: time.sleep(600)):
            started = time.monotonic()
            result = self.run_main(self.UNREACHABLE, deadline=3)
        self.assertEqual(result["status"], "isolation_unverified")
        self.assertEqual(result["results"][-1][3], "unreported")
        self.assertLess(time.monotonic() - started, 6)

    def test_child_killed_at_the_deadline_is_unverified(self):
        from unittest import mock
        with mock.patch.object(sd, "probe_child", lambda *_a: time.sleep(600)):
            started = time.monotonic()
            result = self.run_main(self.UNREACHABLE, deadline=2)
        self.assertEqual(result["status"], "isolation_unverified")
        self.assertTrue(result["child_killed"])
        self.assertEqual(result["counts"]["unreported"], len(self.UNREACHABLE))
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(sd.scan_proc(sd.PROC, {sd.RUN_UID})[0], [])

    def test_default_route_fails_isolation(self):
        from unittest import mock
        fake = os.path.join(self.base, "route")
        with open(fake, "w") as handle:
            handle.write("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                         "eth0\t00000000\t0100F00A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n")
        with mock.patch.object(sd, "ROUTE_V4", fake):
            result = self.run_main(self.UNREACHABLE)
        self.assertEqual(result["status"], "isolation_failed")
        self.assertTrue(result["default_route"])


# ============================================================================== real container probe


POLICY_IMAGES = POLICY["images"]
DOCKER_ENV = dict(os.environ, MSYS_NO_PATHCONV="1")


def _docker(*args, input_bytes=None, timeout=120):
    return subprocess.run(["docker", "--context", "desktop-linux", *args], input=input_bytes,
                          capture_output=True, timeout=timeout, env=DOCKER_ENV)


@unittest.skipUnless(os.environ.get("CLAUDEX_DOCKER_TESTS") == "1", "set CLAUDEX_DOCKER_TESTS=1")
class ContainerProbeTests(unittest.TestCase):
    """The probe through the real stdin loader in the codex-build image, no network at all. No
    Codex process is involved in probe mode."""

    def test_probe_on_network_none(self):
        import sandbox_run
        source = (REPO / "scripts" / "sandbox_driver.py").read_bytes()
        argv, prefix = sandbox_run.bootstrap(source)
        name = "claudex-measure-" + uuid.uuid4().hex[:12]
        create = _docker("create", "--name", name, "--label", "claudex.measure=1", "--pull=never",
                         "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "SETUID",
                         "--cap-add", "SETGID", "--cap-add", "KILL", "--security-opt", "no-new-privileges",
                         "--user", "0:0", "--pids-limit", "512", "--memory", "1g", "--log-driver", "none",
                         "--tmpfs", "/tmp:size=16m", "-i", POLICY_IMAGES["codex-build"]["id"], *argv)
        self.assertEqual(create.returncode, 0, create.stderr)
        cid = create.stdout.decode().strip()
        self.addCleanup(_docker, "rm", "-f", cid)
        spec = probe_spec(probe_targets=InProcessProbeTests.UNREACHABLE, probe_deadline=8,
                          exclude_addrs=["10.240.0.2"])
        nonce = uuid.uuid4().hex
        start = _docker("start", "-ai", cid, input_bytes=prefix + nonce.encode() + b"\n"
                        + json.dumps(spec).encode() + b"\n", timeout=60)
        inspect = _docker("inspect", "--format", "{{.State.ExitCode}}", cid)
        self.assertEqual(inspect.stdout.decode().strip(), "0", start.stderr)
        with tarfile.open(fileobj=io.BytesIO(start.stdout), mode="r:") as tf:
            self.assertEqual(tf.getnames(), ["result.json"])
            result = json.loads(tf.extractfile("result.json").read())
        self.assertEqual(result["nonce"], nonce)
        self.assertEqual(result["status"], "isolated", result)
        self.assertFalse(result["default_route"])


if __name__ == "__main__":
    unittest.main()
