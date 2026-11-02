"""sandbox_driver: the in-container driver of the B1 sandbox runner.

Plan B1 (docs/plans/2026-10-27-sicherheitskette, approved round 6), Approach 2 and 5.
The driver runs inside the container through the runner's fixed stdin loader (plan B2
approach 3b, unit U6; it replaced B1.5's zlib+base85 argv bootstrap): argv is
`python3 -I -S -c <sandbox_run.LOADER with the 64-hex sha256 of this source>`, and stdin
starts with `<decimal length>
<source bytes>` -- at most sandbox_run.LOADER_MAX bytes,
hash-checked by the loader, then executed as __main__ -- followed by the driver's own,
unchanged protocol (nonce, spec, snapshot tar, deps tar). The loader itself is tested in
tests/test_sandbox_run.py (LoaderTests). The source must therefore stay one self-contained,
ASCII, top-imports-only file; the pure parts
(spec validation, result.json, tar framing, the zombie-aware /proc parser) are tested on
the host. The container-level behaviour has an OPTIONAL smoke class below, skipped unless
CLAUDEX_DOCKER_TESTS=1. Written before scripts/sandbox_driver.py and seen failing first.

Plan B1.5 (PLAN-B15-deps.md, steps 4-6, B15-interfaces.md unit D) adds the deps tar, the
uid-65531 offline install and the metadata closure check. The pure parts (spec keys, deps
member check, METADATA parser, closure algorithm with an injected `packaging`, permission
decision) run on the host; the real install path runs in-process inside the image
(InProcessDepsTests) with wheels this file builds itself (a wheel is a zip with a dist-info).
Written before the driver change and seen failing first.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time
import types
import unittest
import uuid
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import sandbox_driver as sd  # noqa: E402

NONCE = "0123456789abcdef0123456789abcdef"
B1_RESULT_KEYS = ["nonce", "command_status", "command_exit", "truncated", "durations", "exports",
                  "infrastructure"]
# A valid wheel name over the old 205-character driver limit (inspection round 1, B4): a long
# build tag, which the host parser and pip both accept.
LONG_WHEEL_NAME = "alpha-1.0-1" + "x" * 190 + "-py3-none-any.whl"


def good_spec(**over):
    spec = {"argv": ["python3", "-c", "print(1)"], "exports": ["coverage.xml"],
            "capture_cap": 8 * 1024 * 1024, "export_cap": 16 * 1024 * 1024,
            "timeout": 900, "tar_len": 10, "deps_len": 0, "deps_sha256": "", "deps_timeout": 300}
    spec.update(over)
    return spec


def _host_packaging():
    """The host's `packaging`, shaped like the driver's PACKAGING, or None."""
    try:
        from packaging.requirements import Requirement
        from packaging.version import Version
    except ImportError:
        return None
    return types.SimpleNamespace(Requirement=Requirement, Version=Version)


HOST_PK = _host_packaging()
NEEDS_PK = unittest.skipIf(HOST_PK is None, "the 'packaging' distribution is not installed on this "
                           "interpreter; the closure algorithm is exercised in the image instead")


def dist(name, version, requires=(), extras=()):
    return {"name": name, "version": version, "requires": list(requires), "extras": list(extras)}


def _record_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def make_wheel(name, version, requires=(), extras=(), files=None):
    """(file name, bytes) of a minimal valid pure-Python wheel."""
    di = "%s-%s.dist-info" % (name, version)
    meta = "Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (name, version)
    meta += "".join("Provides-Extra: %s\n" % e for e in extras)
    meta += "".join("Requires-Dist: %s\n" % r for r in requires)
    entries = dict(files if files is not None else {"%s/__init__.py" % name: b"VALUE = 7\n"})
    entries[di + "/METADATA"] = meta.encode()
    entries[di + "/WHEEL"] = (b"Wheel-Version: 1.0\nGenerator: claudex-test\nRoot-Is-Purelib: true\n"
                              b"Tag: py3-none-any\n")
    record = "".join("%s,%s,%d\n" % (p, _record_hash(d), len(d)) for p, d in entries.items())
    record += "%s/RECORD,,\n" % di
    entries[di + "/RECORD"] = record.encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries.items():
            info = zipfile.ZipInfo(path, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return "%s-%s-py3-none-any.whl" % (name, version), buf.getvalue()


def deps_tar(wheels, requirements=None, extra_members=(), fmt=tarfile.USTAR_FORMAT):
    """The deps tar the runner builds: flat regular members, the wheels plus requirements.txt.
    `fmt=tarfile.GNU_FORMAT` is the runner's own format (needed for names over 100 bytes)."""
    if requirements is None:
        lines = []
        for filename, data in sorted(wheels):
            name, version = filename.split("-")[:2]
            lines.append("%s==%s --hash=sha256:%s\n" % (name, version, hashlib.sha256(data).hexdigest()))
        requirements = "".join(lines).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, content in list(wheels) + [("requirements.txt", requirements)]:
            ti = tarfile.TarInfo(name)
            ti.size = len(content)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(content))
        for ti, content in extra_members:
            tf.addfile(ti, io.BytesIO(content) if content is not None else None)
    return buf.getvalue()


class SpecTests(unittest.TestCase):
    def test_good_spec_parses(self):
        s = sd.parse_spec(good_spec())
        self.assertEqual(s.argv, ["python3", "-c", "print(1)"])
        self.assertEqual(s.exports, ["coverage.xml"])
        self.assertEqual((s.capture_cap, s.export_cap, s.timeout, s.tar_len),
                         (8 * 1024 * 1024, 16 * 1024 * 1024, 900, 10))

    def test_unknown_key_rejected(self):
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(good_spec(extra=1))

    def test_missing_key_rejected(self):
        spec = good_spec()
        del spec["timeout"]
        with self.assertRaises(sd.SpecError):
            sd.parse_spec(spec)

    def test_not_an_object_rejected(self):
        for bad in ([], "x", 3, None):
            with self.assertRaises(sd.SpecError):
                sd.parse_spec(bad)

    def test_argv_must_be_nonempty_list_of_strings(self):
        for bad in ("python3 -c x", [], [""], ["a", 3], ["a", None], ["a\x00b"], {"a": 1}):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(good_spec(argv=bad))

    def test_export_names(self):
        for ok in ("coverage.xml", "a", "A_b-c.d", "0", "_x", "-x", "x" * 64):
            self.assertTrue(sd.valid_export_name(ok), ok)
        for bad in ("", ".x", "..", "../x", "/etc/x", "a/b", "a\\b", "C:x", "x" * 65,
                    "a b", "a\n", "caf\u00e9", ".", "x\x00"):
            self.assertFalse(sd.valid_export_name(bad), repr(bad))
        self.assertFalse(sd.valid_export_name(5))

    def test_bad_export_rejected(self):
        for bad in (["../x"], [".x"], "coverage.xml", [1], ["a", "a"], ["a", "b", "c", "d"]):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_spec(good_spec(exports=bad))

    def test_empty_exports_ok(self):
        self.assertEqual(sd.parse_spec(good_spec(exports=[])).exports, [])

    def test_caps_out_of_range(self):
        for key, bad in (("capture_cap", 0), ("capture_cap", -1), ("capture_cap", 10**12),
                         ("export_cap", 0), ("export_cap", 10**12),
                         ("timeout", 0), ("timeout", 3601), ("timeout", -5),
                         ("tar_len", -1), ("tar_len", 10**12),
                         ("timeout", 1.5), ("timeout", "9"), ("timeout", True)):
            with self.assertRaises(sd.SpecError, msg=f"{key}={bad!r}"):
                sd.parse_spec(good_spec(**{key: bad}))

    def test_caps_boundaries_ok(self):
        sd.parse_spec(good_spec(timeout=1, capture_cap=1, export_cap=1, tar_len=0))
        sd.parse_spec(good_spec(timeout=3600))


class DepsSpecTests(unittest.TestCase):
    """B1.5 spec keys deps_len / deps_sha256 / deps_timeout (B15-interfaces.md, unit D)."""

    def test_deps_keys_parse(self):
        s = sd.parse_spec(good_spec())
        self.assertEqual((s.deps_len, s.deps_sha256, s.deps_timeout), (0, "", 300))
        h = "ab" * 32
        s = sd.parse_spec(good_spec(deps_len=1234, deps_sha256=h, deps_timeout=1))
        self.assertEqual((s.deps_len, s.deps_sha256, s.deps_timeout), (1234, h, 1))

    def test_deps_keys_required(self):
        for key in ("deps_len", "deps_sha256", "deps_timeout"):
            spec = good_spec()
            del spec[key]
            with self.assertRaises(sd.SpecError, msg=key):
                sd.parse_spec(spec)

    def test_deps_ranges_and_types(self):
        h = "ab" * 32
        for over in ({"deps_len": -1}, {"deps_len": True}, {"deps_len": "1"},
                     {"deps_len": sd.MAX_DEPS_TAR + 1, "deps_sha256": h},
                     {"deps_timeout": 0}, {"deps_timeout": 3601}, {"deps_timeout": 1.5},
                     {"deps_len": 0, "deps_sha256": h},
                     {"deps_len": 5, "deps_sha256": ""},
                     {"deps_len": 5, "deps_sha256": h.upper()},
                     {"deps_len": 5, "deps_sha256": h[:-1]},
                     {"deps_len": 5, "deps_sha256": 7}):
            with self.assertRaises(sd.SpecError, msg=repr(over)):
                sd.parse_spec(good_spec(**over))

    def test_header_reads_deps_keys(self):
        _n, spec = sd.parse_header(NONCE.encode() + b"\n",
                                   json.dumps(good_spec(deps_len=3, deps_sha256="0" * 64)).encode() + b"\n")
        self.assertEqual(spec.deps_len, 3)


class HeaderTests(unittest.TestCase):
    def test_header_ok(self):
        nonce, spec = sd.parse_header(NONCE.encode() + b"\n", json.dumps(good_spec()).encode() + b"\n")
        self.assertEqual(nonce, NONCE)
        self.assertEqual(spec.tar_len, 10)

    def test_bad_nonce(self):
        for bad in (b"", b"\n", b"xyz\n", NONCE.upper().encode() + b"\n", NONCE.encode(),
                    (NONCE + "0").encode() + b"\n", NONCE[:-1].encode() + b"\n"):
            with self.assertRaises(sd.SpecError, msg=repr(bad)):
                sd.parse_nonce(bad)

    def test_spec_line_must_be_json(self):
        with self.assertRaises(sd.SpecError):
            sd.parse_header(NONCE.encode() + b"\n", b"{not json\n")
        with self.assertRaises(sd.SpecError):
            sd.parse_header(NONCE.encode() + b"\n", b"\xff\xfe\n")
        with self.assertRaises(sd.SpecError):
            sd.parse_header(NONCE.encode() + b"\n", b"")

    def test_nonce_available_even_when_spec_bad(self):
        """The driver can still sign an infrastructure result when only the spec is bad."""
        self.assertEqual(sd.parse_nonce(NONCE.encode() + b"\n"), NONCE)


class ResultTests(unittest.TestCase):
    def test_shape(self):
        r = sd.build_result(NONCE, "exited", 0, False, {"command_ms": 5}, {"a": "ab" * 32}, None)
        # B1's keys in B1's order; B1.5 only appends "deps".
        self.assertEqual(list(r.keys()), B1_RESULT_KEYS + ["deps"])
        self.assertEqual(r["nonce"], NONCE)
        self.assertIsNone(r["infrastructure"])

    def test_status_enum(self):
        for st in ("exited", "timeout", "output_limit", "not_started"):
            sd.build_result(NONCE, st, 0 if st == "exited" else None, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "oom", None, False, {}, {}, None)

    def test_exit_only_when_exited(self):
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "timeout", 0, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "exited", None, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "exited", True, False, {}, {}, None)

    def test_export_value_forms(self):
        sd.build_result(NONCE, "exited", 0, False, {}, {"a": "missing", "b": "refused:not regular",
                                                       "c": hashlib.sha256(b"x").hexdigest()}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "exited", 0, False, {}, {"a": "whatever"}, None)

    def test_json_bytes_ascii_and_canonical(self):
        r = sd.build_result(NONCE, "exited", 3, True, {"b": 1, "a": 2}, {}, "caf\u00e9")
        data = sd.result_json_bytes(r)
        data.decode("ascii")
        self.assertEqual(json.loads(data)["command_exit"], 3)
        self.assertEqual(data, sd.result_json_bytes(r))


class TarTests(unittest.TestCase):
    def _members(self, data):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            return [(m, tf.extractfile(m).read()) for m in tf.getmembers()]

    def test_order_regular_only_deterministic(self):
        mem = [("result.json", b"{}"), ("stdout.txt", b"hi\n"), ("stderr.txt", b""),
               ("out/coverage.xml", b"<x/>")]
        a = sd.build_result_tar(mem)
        b = sd.build_result_tar(mem)
        self.assertEqual(a, b)
        got = self._members(a)
        self.assertEqual([m.name for m, _ in got], [n for n, _ in mem])
        for m, content in got:
            self.assertTrue(m.isreg())
            self.assertEqual((m.mtime, m.uid, m.gid, m.mode), (0, 0, 0, 0o644))
        self.assertEqual([c for _, c in got], [c for _, c in mem])

    def test_bad_member_names_refused(self):
        for bad in ("../x", "/abs", "out/", "a/../b", "", "out/a/b", "x\\y", "out/.x", "other.txt"):
            with self.assertRaises(ValueError, msg=bad):
                sd.build_result_tar([(bad, b"")])

    def test_empty_content_ok(self):
        got = self._members(sd.build_result_tar([("stdout.txt", b"")]))
        self.assertEqual(got[0][1], b"")


class MemberCheckTests(unittest.TestCase):
    def test_member_problem(self):
        ok = sd.member_problem
        self.assertIsNone(ok("a/b.py", "file"))
        self.assertIsNone(ok("a", "dir"))
        self.assertIsNone(ok("./a", "file"))
        for name, kind in (("/abs", "file"), ("../x", "file"), ("a/../../x", "file"),
                           ("a", "symlink"), ("a", "hardlink"), ("a", "fifo"), ("a", "device"),
                           ("", "file"), ("a\x00b", "file"), ("C:/x", "file")):
            self.assertIsNotNone(ok(name, kind), (name, kind))


class DepsResultTests(unittest.TestCase):
    def test_deps_null_is_appended_after_the_b1_keys(self):
        r = sd.build_result(NONCE, "exited", 0, False, {}, {}, None)
        self.assertEqual(list(r.keys()), B1_RESULT_KEYS + ["deps"])
        self.assertIsNone(r["deps"])

    def test_deps_failed_status(self):
        deps = {"status": "failed", "reason": "x", "installed": []}
        r = sd.build_result(NONCE, "deps_failed", None, False, {}, {}, None, deps=deps)
        self.assertEqual(r["command_status"], "deps_failed")
        self.assertIsNone(r["command_exit"])
        self.assertEqual(r["deps"], deps)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "deps_failed", 0, False, {}, {}, None, deps=deps)
        with self.assertRaises(ValueError, msg="deps_failed needs a failed deps object"):
            sd.build_result(NONCE, "deps_failed", None, False, {}, {}, None)
        with self.assertRaises(ValueError):
            sd.build_result(NONCE, "deps_failed", None, False, {}, {}, None,
                            deps={"status": "installed", "reason": None, "installed": []})

    def test_deps_object_shape(self):
        ok = {"status": "installed", "reason": None, "installed": [["alpha", "1.0"]]}
        self.assertEqual(sd.build_result(NONCE, "exited", 0, False, {}, {}, None, deps=ok)["deps"], ok)
        for bad in ({"status": "maybe", "reason": None, "installed": []},
                    {"status": "installed", "reason": None},
                    {"status": "installed", "reason": None, "installed": [], "x": 1},
                    {"status": "installed", "reason": "why", "installed": []},
                    {"status": "failed", "reason": None, "installed": []},
                    {"status": "installed", "reason": None, "installed": [["a"]]},
                    {"status": "installed", "reason": None, "installed": "a"}, "x"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                sd.build_result(NONCE, "exited", 0, False, {}, {}, None, deps=bad)

    def test_install_member_name_allowed(self):
        data = sd.build_result_tar([("result.json", b"{}"), ("install.txt", b"pip")])
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            self.assertEqual(tf.getnames(), ["result.json", "install.txt"])
        for bad in ("install.txt/x", "out/install.txt/", "deps.txt"):
            with self.assertRaises(ValueError, msg=bad):
                sd.build_result_tar([(bad, b"")])


class DepsMemberTests(unittest.TestCase):
    def test_accepts_wheels_and_requirements(self):
        for name in ("requirements.txt", "alpha-1.0-py3-none-any.whl",
                     "MarkupSafe-3.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"):
            self.assertIsNone(sd.deps_member_problem(name, "file"), name)

    def test_refuses(self):
        for name, kind in (("a/alpha-1.0-py3-none-any.whl", "file"), ("alpha.zip", "file"),
                           ("requirements.txt", "dir"), ("x.whl", "symlink"), ("x.whl", "hardlink"),
                           ("../x.whl", "file"), ("/x.whl", "file"), (".x.whl", "file"),
                           ("x.whl\x00", "file"), ("", "file"), ("req.txt", "file"),
                           ("./alpha-1.0-py3-none-any.whl", "file"), ("./requirements.txt", "file"),
                           ("sub", "dir"), ("x\\y.whl", "file"), ("a b.whl", "file"),
                           ("requirements.txt.whl/", "file"), ("x" * 300 + ".whl", "file")):
            self.assertIsNotNone(sd.deps_member_problem(name, kind), (name, kind))

    def test_long_valid_wheel_name_is_accepted(self):
        """Inspection round 1, B4: the driver's old pattern capped a wheel name at 205 characters,
        a limit the host parser does not have; a selected, hash-pinned wheel was then refused."""
        name = LONG_WHEEL_NAME
        self.assertGreater(len(name), 205)
        self.assertIsNone(sd.deps_member_problem(name, "file"), name)

    def test_wheel_name_rule_matches_the_host_parser(self):
        """The driver may not import sandbox_wheels (it is self-contained), so it carries a copy
        of the grammar; this differential test keeps the copy equal to the host's acceptance."""
        import sandbox_wheels
        corpus = [LONG_WHEEL_NAME, "alpha-1.0-py3-none-any.whl", "Foo_Bar-1.0-1-py3-none-any.whl",
                  "a-1.0+local.7-py3-none-any.whl", "a-1!2.0-py3-none-any.whl",
                  "MarkupSafe-3.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                  "a-1.0-py2.py3-none-any.whl", "a.b-1.0-py3-none-any.whl", "A1-0-py3-none-any.whl",
                  # refused by the host
                  "alpha-1.0-none-any.whl", "a-1-2-3-4-5-6.whl", "a--1.0-py3-none-any.whl",
                  "a.-1.0-py3-none-any.whl", "_a-1.0-py3-none-any.whl", "a-1.0-x1-py3-none-any.whl",
                  "a-1.0-py3-none-any..whl", "a-1.0-py3-none-an y.whl", "a-1.0-py3-none-any.zip",
                  "a-1.0-py3-none-any.WHL", "a-1#0-py3-none-any.whl", "a-1.0-py3-no+ne-any.whl",
                  "a-1.0-py3-none-äny.whl", "a-1.0-py3-none-.whl", "x" * 300 + ".whl",
                  "a-1.0-py3-none-" + "any." * 60 + "any.whl"]
        # The host's bounds (gate initial pass, A1-8), on both sides of each limit.
        tags16 = ".".join("t%d" % i for i in range(16))
        tags17 = ".".join("t%d" % i for i in range(17))
        corpus += ["a-1.0-py3-none-%s.whl" % tags16, "a-1.0-py3-none-%s.whl" % tags17,
                   "a-1.0-%s-%s-any.whl" % (tags16, tags16), "a-1.0-%s-%s-x.y.whl" % (tags16, tags16)]
        for total in (255, 256):
            corpus.append("a-1.0-1" + "x" * (total - len("a-1.0-1-py3-none-any.whl")) + "-py3-none-any.whl")
        self.assertEqual((sd.WHEEL_MAX_FILENAME, sd.WHEEL_MAX_TAG_COMPONENTS, sd.WHEEL_MAX_TAG_TRIPLES),
                         (sandbox_wheels.MAX_WHEEL_FILENAME, sandbox_wheels.MAX_TAG_COMPONENTS,
                          sandbox_wheels.MAX_TAG_TRIPLES))
        for name in corpus:
            try:
                sandbox_wheels.parse_wheel_filename(name)
                host_ok = True
            except sandbox_wheels.WheelRefused:
                host_ok = False
            self.assertEqual(sd.deps_member_problem(name, "file") is None, host_ok, name)


class DepsRequirementsTests(unittest.TestCase):
    H = "0123456789abcdef" * 4

    def test_parses_runner_format(self):
        data = ("alpha==1.0 --hash=sha256:%s\nBeta_Two==2.0rc1 --hash=sha256:%s\n" % (self.H, self.H)).encode()
        self.assertEqual(sd.parse_deps_requirements(data), [("alpha", "1.0"), ("beta-two", "2.0rc1")])

    def test_refuses_anything_else(self):
        h = self.H
        for bad in (b"", b"alpha==1.0\n", ("alpha>=1.0 --hash=sha256:%s\n" % h).encode(),
                    ("alpha==1.0 --hash=sha256:%s" % h).encode(),  # no final LF
                    ("alpha==1.0 --hash=md5:%s\n" % h).encode(),
                    ("alpha==1.0 --hash=sha256:%s\nalpha==1.0 --hash=sha256:%s\n" % (h, h)).encode(),
                    ("-r x\nalpha==1.0 --hash=sha256:%s\n" % h).encode(),
                    ("alpha[x]==1.0 --hash=sha256:%s\n" % h).encode(),
                    ("alpha==1.0 --hash=sha256:%s ; python_version<'3'\n" % h).encode(),
                    ("\nalpha==1.0 --hash=sha256:%s\n" % h).encode(),
                    b"\xff\n", ("alpha==1.0 --hash=sha256:%s\r\n" % h).encode()):
            with self.assertRaises(sd.DepsError, msg=repr(bad)):
                sd.parse_deps_requirements(bad)

    def test_bounded(self):
        line = "a%d==1.0 --hash=sha256:%s\n"
        data = "".join(line % (i, self.H) for i in range(sd.MAX_DEPS_REQUIREMENTS + 1)).encode()
        with self.assertRaises(sd.DepsError):
            sd.parse_deps_requirements(data)


class MetadataParserTests(unittest.TestCase):
    def test_parses_headers_only(self):
        text = (b"Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.2.3\n"
                b"Requires-Dist: pluggy<2,>=1.5\nRequires-Dist: colorama>=0.4; sys_platform == \"win32\"\n"
                b"Provides-Extra: Dev_Tools\nSummary: a\n  folded summary\n"
                b"\nRequires-Dist: body-is-not-a-header\n")
        md = sd.parse_metadata(text)
        self.assertEqual(md["name"], "Foo_Bar")
        self.assertEqual(md["version"], "1.2.3")
        self.assertEqual(md["requires"], ["pluggy<2,>=1.5", 'colorama>=0.4; sys_platform == "win32"'])
        self.assertEqual(md["extras"], ["dev-tools"])

    def test_folded_requires_dist(self):
        md = sd.parse_metadata(b"Name: a\nVersion: 1\nRequires-Dist: b\n  >=1\n")
        self.assertEqual(md["requires"], ["b >=1"])

    def test_unparsable(self):
        for bad in (b"", b"Version: 1\n", b"Name: a\n", b"Name: a\nName: b\nVersion: 1\n",
                    b"Name: a\nVersion: 1\nVersion: 2\n", b"Name: a\nVersion: 1\nno colon here\n",
                    b"Name: \xff\nVersion: 1\n", b" continuation first\nName: a\nVersion: 1\n",
                    b"Name: a\x00\nVersion: 1\n", b"Name: a\nVersion: 1\n" + b"X: y\n" * 200000):
            with self.assertRaises(sd.DepsError, msg=repr(bad[:40])):
                sd.parse_metadata(bad)

    # -- gate initial pass, block B, findings 1/4/5: folded lines are bounded, joined once, and
    # the deps deadline is checked INSIDE one file, not only between files.
    def test_folded_lines_count_against_a_physical_line_bound(self):
        """200000 folded lines in three headers (600 KB, well under MAX_METADATA) used to be
        unfolded quadratically with no bound at all; continuations now count as lines."""
        data = b"Name: a\nVersion: 1\nSummary: s\n" + b" x\n" * 200000
        self.assertLess(len(data), sd.MAX_METADATA)
        with self.assertRaises(sd.DepsError) as ctx:
            sd.parse_metadata(data)
        self.assertIn("too many lines", str(ctx.exception))

    def test_line_bound_boundary(self):
        head = b"Name: a\nVersion: 1\nSummary: s\n"
        folds = sd.MAX_METADATA_LINES - 3
        md = sd.parse_metadata(head + b" x\n" * folds + b"\nbody\n" * 10)
        self.assertEqual(md["name"], "a")
        with self.assertRaises(sd.DepsError):
            sd.parse_metadata(head + b" x\n" * (folds + 1))

    def test_many_fragments_are_joined_with_single_spaces(self):
        folds = sd.MAX_METADATA_LINES - 4
        md = sd.parse_metadata(b"Name: a\nVersion: 1\nRequires-Dist: b\n" + b"\t y \n" * folds
                               + b"Requires-Dist: c\n")
        self.assertEqual(md["requires"], ["b" + " y" * folds, "c"])

    def test_deadline_expiring_inside_one_file_stops_parsing(self):
        """The clock passes the deadline after the first check. The file ends in a malformed
        header: a parser that checks only before it starts would reach that line and report it;
        one that checks while it parses stops first, with the timeout."""
        from unittest import mock
        data = b"Name: a\nVersion: 1\nSummary: s\n" + b" x\n" * 5000 + b"no colon here\n"
        with self.assertRaises(sd.DepsError) as ctx:
            sd.parse_metadata(data)
        self.assertIn("without colon", str(ctx.exception))
        calls = []

        def clock():
            calls.append(1)
            return 0.0 if len(calls) == 1 else 1e9

        with mock.patch.object(sd.time, "monotonic", clock):
            with self.assertRaises(sd.DepsError) as ctx:
                sd.parse_metadata(data, deadline=1.0)
        self.assertIn(sd.DEPS_TIMEOUT, str(ctx.exception))
        self.assertIn("while parsing METADATA", str(ctx.exception))
        self.assertGreaterEqual(len(calls), 2, "the deadline was never checked inside the file")

    def test_no_deadline_parses_unchanged(self):
        md = sd.parse_metadata(b"Name: a\nVersion: 1\n", deadline=None)
        self.assertEqual((md["name"], md["version"]), ("a", "1"))

    def test_dist_info_dir_name(self):
        self.assertEqual(sd.dist_info_name("pytest_cov-7.1.0.dist-info"), ("pytest-cov", "7.1.0"))
        self.assertEqual(sd.dist_info_name("Foo.Bar-2.0rc1.dist-info"), ("foo-bar", "2.0rc1"))
        for bad in ("pytest.dist-info", "-1.0.dist-info", "a-.dist-info", "a-1.0.egg-info", "a-1.0"):
            self.assertIsNone(sd.dist_info_name(bad), bad)


@NEEDS_PK
class ClosureTests(unittest.TestCase):
    """The closure algorithm with the host's `packaging` injected (plan step 5, rounds 3/4)."""

    def check(self, deps, image, reqs):
        return sd.check_closure(deps, image, reqs, HOST_PK)

    def fails(self, deps, image, reqs, needle):
        with self.assertRaises(sd.DepsError) as cm:
            self.check(deps, image, reqs)
        self.assertIn(needle, str(cm.exception))
        str(cm.exception).encode("ascii")

    def test_clean(self):
        deps = [dist("alpha", "1.0", ["beta>=1"]), dist("beta", "1.1")]
        self.assertIsNone(self.check(deps, [], [("alpha", "1.0"), ("beta", "1.1")]))

    def test_satisfied_by_image(self):
        self.assertIsNone(self.check([dist("alpha", "1.0", ["pluggy>=1.5"])], [dist("pluggy", "1.7.0")],
                                     [("alpha", "1.0")]))

    def test_missing_partner(self):
        self.fails([dist("alpha", "1.0", ["beta>=1"])], [], [("alpha", "1.0")], "beta")

    def test_version_conflict(self):
        self.fails([dist("alpha", "1.0", ["beta>=2"]), dist("beta", "1.1")], [],
                   [("alpha", "1.0"), ("beta", "1.1")], "beta")

    def test_inactive_marker_is_not_an_edge(self):
        deps = [dist("alpha", "1.0", ['beta; python_version < "3"', 'gamma; extra == "x"'])]
        self.assertIsNone(self.check(deps, [], [("alpha", "1.0")]))

    def test_deps_shadow_image_even_when_the_image_would_satisfy(self):
        deps = [dist("alpha", "1.0", ["pluggy>=1.5"]), dist("pluggy", "1.0.0")]
        self.fails(deps, [dist("pluggy", "1.7.0")], [("alpha", "1.0"), ("pluggy", "1.0.0")], "pluggy")

    def test_unshadowed_image_distribution_is_checked_too(self):
        """Round 4 finding 2: only an old pluggy requested, pytest only in the image."""
        image = [dist("pytest", "9.0.3", ["pluggy<2,>=1.5"]), dist("pluggy", "1.7.0")]
        self.fails([dist("pluggy", "1.0.0")], image, [("pluggy", "1.0.0")], "pytest")

    def test_duplicate_within_a_source(self):
        self.fails([dist("alpha", "1.0"), dist("Alpha", "1.0")], [], [("alpha", "1.0")], "duplicate")
        self.fails([dist("alpha", "1.0")], [dist("x.y", "1"), dist("X_Y", "2")],
                   [("alpha", "1.0")], "duplicate")

    def test_installed_name_not_in_requirements(self):
        self.fails([dist("alpha", "1.0"), dist("stowaway", "1.0")], [], [("alpha", "1.0")], "stowaway")

    def test_requirement_not_installed_or_wrong_version(self):
        self.fails([], [], [("alpha", "1.0")], "alpha")
        self.fails([dist("alpha", "1.1")], [], [("alpha", "1.0")], "alpha")

    def test_transitive_extra(self):
        a = dist("a", "1.0", ["b[x]>=1"])
        b = dist("b", "1.0", ['c; extra == "x"'], extras=["x"])
        self.fails([a, b], [], [("a", "1.0"), ("b", "1.0")], "c")
        self.assertIsNone(self.check([a, b, dist("c", "1.0")], [], [("a", "1.0"), ("b", "1.0"), ("c", "1.0")]))

    def test_extras_propagate_over_two_hops_to_a_fixed_point(self):
        a = dist("a", "1", ["b[x]"])
        b = dist("b", "1", ['c[y]; extra == "x"'], extras=["x"])
        c = dist("c", "1", ['d>=2; extra == "y"'], extras=["y"])
        reqs = [("a", "1"), ("b", "1"), ("c", "1"), ("d", "1")]
        self.fails([a, b, c, dist("d", "1")], [], reqs, "d")
        self.assertIsNone(self.check([a, b, c, dist("d", "2")], [], reqs[:3] + [("d", "2")]))

    def test_extra_names_are_normalised(self):
        a = dist("a", "1", ["b[Dev_Tools]"])
        b = dist("b", "1", ['c; extra == "dev-tools"'], extras=["dev.tools"])
        self.fails([a, b], [], [("a", "1"), ("b", "1")], "c")

    def test_undeclared_extra(self):
        self.fails([dist("a", "1", ["b[nope]"]), dist("b", "1")], [], [("a", "1"), ("b", "1")], "nope")

    def test_unparsable_requirement_or_version(self):
        self.fails([dist("a", "1", ["b >>>= 1"])], [], [("a", "1")], "a")
        self.fails([dist("a", "not a version")], [], [("a", "not a version")], "a")

    def test_url_requirement_refused(self):
        self.fails([dist("a", "1", ["b @ https://example.invalid/b.whl"]), dist("b", "1")], [],
                   [("a", "1"), ("b", "1")], "url")

    def test_prerelease_installed_satisfies(self):
        self.assertIsNone(self.check([dist("a", "1", ["b>=1"]), dist("b", "2.0rc1")], [],
                                     [("a", "1"), ("b", "2.0rc1")]))

    def test_packaging_unavailable_fails_closed(self):
        with self.assertRaises(sd.DepsError) as cm:
            sd.check_closure([dist("a", "1")], [], [("a", "1")], None)
        self.assertIn("packaging unavailable", str(cm.exception))

    def test_expired_deadline_stops_the_closure_check(self):
        """Inspection round 1, B1: the closure check runs inside the deps budget; once it is
        spent the check refuses with a timeout instead of finishing the walk of every edge."""
        deps = [dist("alpha", "1.0", ["beta>=1"]), dist("beta", "1.1")]
        reqs = [("alpha", "1.0"), ("beta", "1.1")]
        self.assertIsNone(sd.check_closure(deps, [], reqs, HOST_PK, deadline=time.monotonic() + 60))
        with self.assertRaises(sd.DepsError) as cm:
            sd.check_closure(deps, [], reqs, HOST_PK, deadline=time.monotonic() - 1)
        self.assertIn("timeout", str(cm.exception))

    def _jumping(self):
        """(patcher, offset): time.monotonic() plus an offset raised at an exact point."""
        from unittest import mock
        real = time.monotonic
        offset = [0.0]
        return mock.patch.object(sd.time, "monotonic", lambda: real() + offset[0]), offset

    def test_deadline_expiring_at_the_first_marker_evaluation_stops_the_edges(self):
        """Inspection round 2, B1: the edge loop (marker and extra evaluation, specifier check)
        had no deadline check, so an expiry during the first marker evaluation still let every
        edge run and check_closure() return success."""
        patcher, offset = self._jumping()
        counts = {"evaluate": 0, "contains": 0}

        class Marker:
            def __init__(self, real):
                self.real = real

            def evaluate(self, env):
                counts["evaluate"] += 1
                offset[0] = 1e6
                return self.real.evaluate(env)

        class Spec:
            def __init__(self, real):
                self.real = real

            def contains(self, *a, **kw):
                counts["contains"] += 1
                return self.real.contains(*a, **kw)

        def requirement(text):
            real = HOST_PK.Requirement(text)
            return types.SimpleNamespace(name=real.name, url=real.url, extras=real.extras,
                                         specifier=Spec(real.specifier),
                                         marker=None if real.marker is None else Marker(real.marker))

        pk = types.SimpleNamespace(Requirement=requirement, Version=HOST_PK.Version)
        on = '; python_version >= "3"'
        deps = [dist("alpha", "1.0", ["beta>=1" + on, "gamma>=1" + on, "delta>=1" + on]),
                dist("beta", "1"), dist("gamma", "1"), dist("delta", "1")]
        reqs = [("alpha", "1.0"), ("beta", "1"), ("gamma", "1"), ("delta", "1")]
        self.assertIsNone(sd.check_closure(deps, [], reqs, pk, deadline=time.monotonic() + 60))
        self.assertEqual(counts, {"evaluate": 3, "contains": 3}, "the sanity run did not reach every edge")
        counts.update(evaluate=0, contains=0)
        offset[0] = 0.0  # the sanity run (unpatched clock) already raised it
        with patcher:
            with self.assertRaises(sd.DepsError) as cm:
                sd.check_closure(deps, [], reqs, pk, deadline=time.monotonic() + 60)
        self.assertIn("timeout", str(cm.exception))
        self.assertEqual(counts, {"evaluate": 1, "contains": 0}, "edges ran past the deadline")

    def test_deadline_expiring_during_indexing_stops_it(self):
        patcher, offset = self._jumping()
        calls = []

        def version(text):
            calls.append(text)
            offset[0] = 1e6
            return HOST_PK.Version(text)

        pk = types.SimpleNamespace(Requirement=HOST_PK.Requirement, Version=version)
        deps = [dist("alpha", "1.0"), dist("beta", "1.1")]
        image = [dist("pluggy", "1.7.0"), dist("pytest", "9.0.3")]
        with patcher:
            with self.assertRaises(sd.DepsError) as cm:
                sd.check_closure(deps, image, [("alpha", "1.0"), ("beta", "1.1")], pk,
                                 deadline=time.monotonic() + 60)
        self.assertIn("timeout", str(cm.exception))
        self.assertEqual(len(calls), 1, "indexing kept parsing versions past the deadline")

    def test_non_ascii_names_in_reasons_are_escaped(self):
        with self.assertRaises(sd.DepsError) as cm:
            self.check([dist("a", "1", ["b\u00e9>=1"])], [], [("a", "1")])
        str(cm.exception).encode("ascii")


class PermissionDecisionTests(unittest.TestCase):
    def st(self, mode, uid=65531):
        return types.SimpleNamespace(st_mode=mode, st_uid=uid)

    def test_good_entries(self):
        for mode in (stat.S_IFREG | 0o644, stat.S_IFREG | 0o755, stat.S_IFREG | 0o444,
                     stat.S_IFREG | 0o604, stat.S_IFDIR | 0o755, stat.S_IFDIR | 0o705):
            self.assertIsNone(sd.deps_entry_problem("x", self.st(mode)), oct(mode))

    def test_entries_the_command_cannot_read_are_refused(self):
        """Inspection round 1, B2: uid 65532 is neither the owner nor in group 65531, so only the
        OTHER bits decide whether the command can import the tree: files o+r, directories o+rx.
        A 0600 module with readable METADATA would pass the closure check and fail at import."""
        for mode, needle in ((stat.S_IFREG | 0o600, "not readable by the command"),
                             (stat.S_IFREG | 0o640, "not readable by the command"),
                             (stat.S_IFREG | 0o700, "not readable by the command"),
                             (stat.S_IFREG | 0o601, "not readable by the command"),
                             (stat.S_IFDIR | 0o700, "not readable and searchable by the command"),
                             (stat.S_IFDIR | 0o750, "not readable and searchable by the command"),
                             (stat.S_IFDIR | 0o754, "not readable and searchable by the command"),
                             (stat.S_IFDIR | 0o751, "not readable and searchable by the command")):
            problem = sd.deps_entry_problem("x", self.st(mode))
            self.assertIsNotNone(problem, oct(mode))
            self.assertIn(needle, problem, oct(mode))

    def test_bad_entries(self):
        for mode, uid in ((stat.S_IFREG | 0o664, 65531), (stat.S_IFREG | 0o646, 65531),
                          (stat.S_IFDIR | 0o775, 65531), (stat.S_IFDIR | 0o757, 65531),
                          (stat.S_IFLNK | 0o777, 65531), (stat.S_IFCHR | 0o644, 65531),
                          (stat.S_IFBLK | 0o644, 65531), (stat.S_IFIFO | 0o644, 65531),
                          (stat.S_IFSOCK | 0o644, 65531), (stat.S_IFREG | 0o4755, 65531),
                          (stat.S_IFREG | 0o2755, 65531), (stat.S_IFDIR | 0o2755, 65531),
                          (stat.S_IFREG | 0o644, 65532), (stat.S_IFREG | 0o644, 0)):
            self.assertIsNotNone(sd.deps_entry_problem("x", self.st(mode, uid)), (oct(mode), uid))

    def test_deps_root_decision(self):
        ok = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
        self.assertIsNone(sd.deps_root_problem(ok, []))
        for st, entries in ((types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0), []),
                            (types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0), []),
                            (types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=65532), []),
                            (types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0), []),
                            (ok, ["planted"])):
            self.assertIsNotNone(sd.deps_root_problem(st, entries), (oct(st.st_mode), st.st_uid, entries))


class UidSetTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual((sd.DEPS_UID, sd.DEPS_GID), (65531, 65531))
        self.assertNotEqual(sd.DEPS_UID, sd.RUN_UID)

    def test_scan_proc_over_a_uid_set(self):
        import tempfile
        tpl = ProcParserTests.TEMPLATE
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for pid, state, uid in ((1, "S (sleeping)", 0), (20, "S (sleeping)", 65532),
                                    (21, "R (running)", 65531), (22, "Z (zombie)", 65531),
                                    (23, "S (sleeping)", 1000)):
                (root / str(pid)).mkdir()
                (root / str(pid) / "status").write_text(tpl.format(state=state, uid=uid), encoding="ascii")
            live, zombies = sd.scan_proc(str(root), {65531, 65532})
            self.assertEqual((sorted(live), zombies), ([20, 21], [22]))
            self.assertEqual(sd.scan_proc(str(root), {65531}), ([21], [22]))
            self.assertEqual(sd.scan_proc(str(root), 65532), ([20], []))


class ProcParserTests(unittest.TestCase):
    TEMPLATE = ("Name:\tsleep\nUmask:\t0022\nState:\t{state}\nTgid:\t12\nPid:\t12\nPPid:\t1\n"
                "Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t65532\t65532\t65532\t65532\n")

    def test_running_sleeping_zombie(self):
        for state, letter in (("R (running)", "R"), ("S (sleeping)", "S"), ("Z (zombie)", "Z"),
                              ("D (disk sleep)", "D"), ("X (dead)", "X")):
            text = self.TEMPLATE.format(state=state, uid=65532)
            self.assertEqual(sd.parse_proc_status(text), (65532, letter))

    def test_root_uid(self):
        self.assertEqual(sd.parse_proc_status(self.TEMPLATE.format(state="S (sleeping)", uid=0)),
                         (0, "S"))

    def test_garbage_raises(self):
        for bad in ("", "Name:\tx\n", "State:\tS (sleeping)\n", "Uid:\t1\n", "Uid:\nState:\tS\n", "Uid:\tx\nState:\tS\n",
                    "State:\n Uid:\tabc\n"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                sd.parse_proc_status(bad)

    def test_scan_proc_separates_zombies(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            def put(pid, state, uid):
                (root / str(pid)).mkdir()
                (root / str(pid) / "status").write_text(
                    self.TEMPLATE.format(state=state, uid=uid), encoding="ascii")
            put(1, "S (sleeping)", 0)
            put(20, "S (sleeping)", 65532)
            put(21, "Z (zombie)", 65532)
            put(22, "R (running)", 65532)
            put(23, "S (sleeping)", 1000)
            (root / "self").mkdir()
            (root / "cpuinfo").write_text("x", encoding="ascii")
            live, zombies = sd.scan_proc(str(root), 65532)
            self.assertEqual(sorted(live), [20, 22])
            self.assertEqual(zombies, [21])

    def test_scan_proc_vanished_process_is_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "30").mkdir()  # no status file: the process exited while scanning
            self.assertEqual(sd.scan_proc(str(root), 65532), ([], []))

    def test_scan_proc_unreadable_proc_fails_closed(self):
        with self.assertRaises(OSError):
            sd.scan_proc(str(REPO / "no-such-proc-dir"), 65532)

    def test_scan_proc_unparseable_status_fails_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "40").mkdir()
            (root / "40" / "status").write_text("garbage", encoding="ascii")
            with self.assertRaises(ValueError):
                sd.scan_proc(str(root), 65532)


class SourceShapeTests(unittest.TestCase):
    """The file travels as the first block on stdin behind the fixed `python3 -I -S -c` loader
    (plan B2 approach 3b) and is executed whole as __main__ after its sha256 is checked; it
    must stay self-contained and within the loader's bound."""

    def setUp(self):
        self.src = (REPO / "scripts" / "sandbox_driver.py").read_text(encoding="utf-8")

    def test_ascii_only(self):
        self.src.encode("ascii")

    def test_imports_stdlib_only_and_at_top(self):
        import ast
        tree = ast.parse(self.src)
        stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else None
        seen_def = False
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                seen_def = True
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertFalse(seen_def, "import after a definition")
        # B1.5: exactly one guarded block may import the image's vendored packaging. It is a
        # top-level `try` before any definition, and it imports only pip._vendor.packaging.*.
        guarded = set()
        seen_def = False
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                seen_def = True
            if isinstance(node, ast.Try):
                inner = [n for n in ast.walk(node) if isinstance(n, (ast.Import, ast.ImportFrom))]
                if inner:
                    self.assertFalse(seen_def, "guarded import after a definition")
                    for n in inner:
                        self.assertIsInstance(n, ast.ImportFrom)
                        self.assertTrue(n.module.startswith("pip._vendor.packaging"), n.module)
                        guarded.add(n)
        self.assertTrue(guarded, "the vendored packaging import is missing")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)) and node not in guarded:
                self.assertIn(node, tree.body, "import not at module top level")
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module]
                for n in names:
                    top = n.split(".")[0]
                    if stdlib is not None:
                        self.assertIn(top, stdlib)
                    self.assertNotIn(top, {"hunt_io", "hunt_run", "codex_ro", "claudex_roles"})

    def test_image_site_is_appended_never_inserted(self):
        """The packaging import must not let /work, /deps or the cwd shadow the image's pip."""
        self.assertIn("sys.path.append(IMAGE_SITE)", self.src)
        self.assertNotIn("sys.path.insert", self.src)
        self.assertEqual(sd.IMAGE_SITE, "/usr/local/lib/python3.13/site-packages")
        self.assertLess(self.src.index("sys.path.append(IMAGE_SITE)"),
                        self.src.index("from pip._vendor.packaging"))

    def test_pip_install_argv_is_the_plan_command(self):
        self.assertEqual(sd.pip_install_argv("/deps"), [
            "python3", "-I", "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes",
            "--only-binary=:all:", "--no-compile", "--no-cache-dir", "--no-warn-script-location",
            "--disable-pip-version-check", "--isolated", "--target", "/deps/site",
            "--find-links", "/deps/wheels", "-r", "/deps/wheels/requirements.txt"])
        self.assertEqual(sd.install_env("/deps"), {"HOME": "/deps/home", "TMPDIR": "/deps/tmp",
                                                   "PATH": "/usr/local/bin:/usr/bin:/bin"})

    def test_main_guard(self):
        self.assertIn('if __name__ == "__main__":', self.src)
        self.assertIn("sys.exit(main())", self.src)

    def test_compiles_as_c_argument(self):
        compile(self.src, "<driver>", "exec")


def _inproc_allowed():
    """Root alone is not enough: quiesce() SIGKILLs every uid-65532 process in /proc, so on a
    real host it could hit unrelated services. Only an explicit opt-in INSIDE a container (own
    PID namespace) runs these tests (inspection round 2, B1 finding 4)."""
    return (hasattr(os, "fork") and hasattr(os, "geteuid") and os.geteuid() == 0
            and os.environ.get("CLAUDEX_DRIVER_INPROC") == "1" and os.path.exists("/.dockerenv"))


class _InProcBase(unittest.TestCase):
    """The driver's real code paths, run in-process against temp directories.

    These need root (the driver drops to uid 65532/65531 with setuid), so they skip on the
    Windows host and on an unprivileged POSIX user; run them as root in the sandbox image
    (the cwd must be the copy, so `tests` is importable):
    docker --context desktop-linux run --rm --network none -e CLAUDEX_DRIVER_INPROC=1
    -v <repo>:/src:ro -w /tmp/r claudex-sandbox-python-test:2 sh -c 'cp -r /src/. /tmp/r &&
    python3 -m unittest -v tests.test_sandbox_driver'
    """

    def setUp(self):
        import tempfile
        from unittest import mock
        self.base = tempfile.mkdtemp(prefix="drv")
        os.chmod(self.base, 0o755)
        self.work = os.path.join(self.base, "work")
        self.out = os.path.join(self.base, "out")
        self.deps = os.path.join(self.base, "deps")
        for path in (self.work, self.out, self.deps):
            os.mkdir(path)
            os.chmod(path, 0o1777)
        self.scratch = os.path.join(self.base, "scratch")
        for name, value in (("WORK", self.work), ("OUT", self.out), ("SCRATCH", self.scratch),
                            ("DEPS", self.deps)):
            patcher = mock.patch.object(sd, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        import shutil
        try:
            sd.quiesce(sd.CHILD_UIDS)
        finally:
            shutil.rmtree(self.base, ignore_errors=True)

    def reset(self):
        """A fresh container state for a second run_main() in the same test."""
        import shutil
        for path in (self.work, self.out, self.deps, self.scratch):
            shutil.rmtree(path, ignore_errors=True)
        for path in (self.work, self.out, self.deps):
            os.mkdir(path)
            os.chmod(path, 0o1777)

    def run_main(self, argv, files=(), exports=(), capture_cap=8 * 1024 * 1024, timeout=20,
                 tar_bytes=None, deps=b"", deps_sha256=None, deps_timeout=120):
        from unittest import mock
        tar = _snapshot_tar(files) if tar_bytes is None else tar_bytes
        if deps_sha256 is None:
            deps_sha256 = hashlib.sha256(deps).hexdigest() if deps else ""
        spec = {"argv": list(argv), "exports": list(exports), "capture_cap": capture_cap,
                "export_cap": 16 * 1024 * 1024, "timeout": timeout, "tar_len": len(tar),
                "deps_len": len(deps), "deps_sha256": deps_sha256, "deps_timeout": deps_timeout}
        payload = NONCE.encode() + b"\n" + json.dumps(spec).encode() + b"\n" + tar + deps

        class _Std:
            def __init__(self, data=b""):
                self.buffer = io.BytesIO(data)

        fake_in, fake_out = _Std(payload), _Std()
        with mock.patch.object(sys, "stdin", fake_in), mock.patch.object(sys, "stdout", fake_out):
            self.assertEqual(sd.main(), 0)
        members = {}
        with tarfile.open(fileobj=io.BytesIO(fake_out.buffer.getvalue()), mode="r:") as tf:
            for m in tf.getmembers():
                members[m.name] = tf.extractfile(m).read()
        return json.loads(members["result.json"]), members


@unittest.skipUnless(_inproc_allowed(), "needs root inside a throwaway container and CLAUDEX_DRIVER_INPROC=1")
class InProcessDriverTests(_InProcBase):
    """B1 behaviour, unchanged by B1.5 (deps_len 0)."""

    def test_no_deps_result_is_b1_plus_deps_null(self):
        result, members = self.run_main(["sh", "-c", "echo ok"])
        self.assertEqual(list(result.keys()), B1_RESULT_KEYS + ["deps"])
        self.assertIsNone(result["deps"])
        self.assertEqual(sorted(members), ["result.json", "stderr.txt", "stdout.txt"])
        self.assertNotIn("deps_ms", result["durations"])
        self.assertEqual(os.listdir(self.deps), [], "a run without deps touched /deps")

    # -- finding 1: output overflow can never satisfy the pass gate
    def test_finite_overflow_with_exit_zero_is_output_limit(self):
        """The command writes more than the cap and exits 0 between two polls."""
        from unittest import mock
        real_sleep = sd.time.sleep
        # Stretch the poll interval so the command is long finished at the next poll: the
        # overflow is first seen by the final check, not by the in-loop check.
        with mock.patch.object(sd.time, "sleep", lambda _s: real_sleep(0.6)):
            result, members = self.run_main(
                ["sh", "-c", "sleep 0.1; head -c 200000 /dev/zero; exit 0"], capture_cap=1000)
        self.assertEqual(result["command_status"], "output_limit")
        self.assertIsNone(result["command_exit"])
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(members["stdout.txt"]), 1000)

    def test_overflow_on_stderr_with_exit_zero_is_output_limit(self):
        from unittest import mock
        real_sleep = sd.time.sleep
        with mock.patch.object(sd.time, "sleep", lambda _s: real_sleep(0.6)):
            result, _ = self.run_main(
                ["sh", "-c", "sleep 0.1; head -c 200000 /dev/zero >&2; exit 0"], capture_cap=1000)
        self.assertEqual((result["command_status"], result["command_exit"]), ("output_limit", None))

    def test_descendant_writing_after_the_command_exited_is_output_limit(self):
        """Closing gate, block B1, SECURITY 3: a background child keeps stdout and writes past
        the cap AFTER the main command exited 0; the capture must still count those bytes and
        never report exited/0.

        Handshake, no timing (closing gate recheck 1, B1 #4): the first quiesce() call is the
        moment after the main child was reaped. It creates `go`; only then does the descendant
        write 2000 bytes (over the 1000-byte cap, under the pipe buffer) and create `done`; only
        then does cleanup proceed."""
        from unittest import mock
        real_quiesce = sd.quiesce
        go, done = os.path.join(self.out, "go"), os.path.join(self.out, "done")
        calls = []

        def handshake_quiesce(*uids):
            if not calls:
                calls.append("first")
                with open(go, "w") as handle:
                    handle.write("1")
                end = time.monotonic() + 15
                while not os.path.exists(done) and time.monotonic() < end:
                    time.sleep(0.01)
                calls.append("written" if os.path.exists(done) else "never written")
            return real_quiesce(*uids)

        script = ("(while [ ! -f %s ]; do sleep 0.01; done; head -c 2000 /dev/zero; echo d > %s) & exit 0"
                  % (go, done))
        with mock.patch.object(sd, "quiesce", handshake_quiesce):
            result, members = self.run_main(["sh", "-c", script], capture_cap=1000)
        self.assertEqual(calls[:2], ["first", "written"], "the descendant never wrote after the exit")
        self.assertEqual((result["command_status"], result["command_exit"]), ("output_limit", None))
        self.assertTrue(result["truncated"])
        self.assertIsNone(result["infrastructure"])
        self.assertLessEqual(len(members["stdout.txt"]), 1000)

    @staticmethod
    def _open_fds():
        return set(os.listdir("/proc/self/fd"))

    def test_failed_quiescence_is_infrastructure_and_skips_exports(self):
        """Closing gate recheck 1, B1 #5: the capture is never finalised on a failed cleanup."""
        from unittest import mock
        before = self._open_fds()
        with mock.patch.object(sd, "quiesce", lambda *_uids: "uid 65532 processes survived SIGKILL"):
            result, members = self.run_main(["sh", "-c", "echo x > %s/e.txt; echo ok"
                                             % self.out], exports=["e.txt"])
        self.assertIn("survived SIGKILL", result["infrastructure"])
        self.assertIsNone(result["command_exit"])
        self.assertEqual(result["exports"], {})
        self.assertNotIn("out/e.txt", members)
        self.assertEqual(self._open_fds() - before, set(), "capture descriptors leaked")

    def test_pipe_held_open_past_the_drain_deadline_is_infrastructure(self):
        """Closing gate recheck 1, B1 #5: a writer that survives (quiesce stubbed to kill nothing)
        keeps the pipe open; the drain gives up within its bound and reports infrastructure."""
        from unittest import mock
        before = self._open_fds()
        started = time.monotonic()
        with mock.patch.object(sd, "quiesce", lambda *_uids: None), mock.patch.object(sd, "QUIESCE_SECONDS", 0.5):
            result, _members = self.run_main(["sh", "-c", "sleep 30 & echo started"])
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("did not close", result["infrastructure"])
        self.assertIsNone(result["command_exit"])
        self.assertEqual(result["exports"], {})
        self.assertEqual(self._open_fds() - before, set(), "capture descriptors leaked")

    def test_truncating_the_capture_does_not_hide_an_overflow(self):
        """Closing gate, block B1, SECURITY 3: with a regular capture file the command could write
        past the cap and ftruncate it back before the size check. A pipe cannot be truncated."""
        code = ("import os\nos.write(1, b'x' * 5000)\n"
                "try:\n    os.ftruncate(1, 0)\nexcept OSError:\n    pass\n")
        result, _ = self.run_main(["python3", "-I", "-c", code], capture_cap=1000)
        self.assertEqual((result["command_status"], result["command_exit"]), ("output_limit", None))

    def test_output_within_cap_is_still_exited(self):
        result, members = self.run_main(["sh", "-c", "echo ok"], capture_cap=1000)
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0))
        self.assertFalse(result["truncated"])
        self.assertEqual(members["stdout.txt"], b"ok\n")

    # -- finding 2: nothing of uid 65532 is alive when the exports are read
    def test_background_writer_is_dead_and_content_stable_at_export_time(self):
        from unittest import mock
        ready = os.path.join(self.out, "ready")
        bg = os.path.join(self.out, "bg.txt")
        script = ("(echo x >> %s; echo r > %s; while :; do echo x >> %s; done) >/dev/null 2>&1 & "
                  "while [ ! -f %s ]; do :; done; echo started" % (bg, ready, bg, ready))
        seen = {}
        real_read_export = sd.read_export

        def spy(name, cap):
            seen["live"] = sd.scan_proc(sd.PROC, sd.RUN_UID)[0]
            first = os.path.getsize(bg)
            sd.time.sleep(0.3)
            seen["grew"] = os.path.getsize(bg) != first
            return real_read_export(name, cap)

        with mock.patch.object(sd, "read_export", spy):
            result, members = self.run_main(["sh", "-c", script], exports=["bg.txt"])
        self.assertEqual(result["command_status"], "exited")
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(members["stdout.txt"], b"started\n")
        self.assertEqual(seen["live"], [], "a uid-65532 process was alive at export time")
        self.assertFalse(seen["grew"], "the exported file was still being written")
        self.assertRegex(result["exports"]["bg.txt"], r"^[0-9a-f]{64}$")

    # -- finding 3: the extraction ownership / writability gate refuses and the command never runs
    def assert_refused_and_not_run(self, result, members):
        self.assertIsNotNone(result["infrastructure"], "the gate let the snapshot through")
        self.assertIn("not owned by 65532 or not writable", result["infrastructure"])
        self.assertEqual(result["command_status"], "not_started")
        self.assertIsNone(result["command_exit"])
        self.assertEqual(members["stdout.txt"], b"")
        self.assertFalse(os.path.exists(os.path.join(self.out, "ran")), "the command started")

    def _marker_cmd(self):
        return ["sh", "-c", "echo x > %s" % os.path.join(self.out, "ran")]

    def test_entry_with_wrong_owner_is_refused(self):
        # A root-owned entry in /work (extraction runs as 65532 and cannot create one).
        planted = os.path.join(self.work, "planted.txt")
        with open(planted, "w") as handle:
            handle.write("x")
        self.assertEqual(os.stat(planted).st_uid, 0)
        result, members = self.run_main(self._marker_cmd(), files=[("a.txt", b"a")])
        self.assert_refused_and_not_run(result, members)

    def test_file_without_owner_write_is_refused(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            ti = tarfile.TarInfo("ro.txt")
            ti.size = 1
            ti.mode = 0o444
            tf.addfile(ti, io.BytesIO(b"x"))
        result, members = self.run_main(self._marker_cmd(), tar_bytes=buf.getvalue())
        self.assert_refused_and_not_run(result, members)

    def test_dir_without_owner_write_is_refused(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            ti = tarfile.TarInfo("d")
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o555
            tf.addfile(ti)
        result, members = self.run_main(self._marker_cmd(), tar_bytes=buf.getvalue())
        self.assert_refused_and_not_run(result, members)

    def test_clean_snapshot_still_passes_the_gate(self):
        result, _ = self.run_main(["sh", "-c", "cat a.txt"], files=[("a.txt", b"a")])
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["command_status"], "exited")


@unittest.skipUnless(_inproc_allowed(), "needs root inside a throwaway container and CLAUDEX_DRIVER_INPROC=1")
class InProcessDepsTests(_InProcBase):
    """B1.5 install path for real: deps tar -> uid-65531 extraction -> offline pip -> quiesce ->
    permission walk -> closure check against the image's site-packages -> command as 65532.
    The wheels are built by make_wheel(); pip runs offline exactly as in production."""

    def marker_cmd(self):
        return ["sh", "-c", "echo x > %s" % os.path.join(self.out, "ran")]

    def assert_deps_failed(self, result, members, needle):
        self.assertEqual(result["command_status"], "deps_failed", result)
        self.assertIsNone(result["command_exit"])
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["deps"]["status"], "failed")
        self.assertIn(needle, result["deps"]["reason"])
        self.assertIn("install.txt", members)
        self.assertFalse(os.path.exists(os.path.join(self.out, "ran")), "the command started")

    def test_image_site_packages_closure_is_clean(self):
        """Measurement: every run seeds the worklist with every image distribution, so the
        image itself must be closure-clean or no deps run could ever pass."""
        self.assertIsNotNone(sd.PACKAGING, "pip._vendor.packaging did not import from IMAGE_SITE")
        image = sd.read_site(sd.IMAGE_SITE)
        self.assertIn("pytest", {sd.normalize_name(d["name"]) for d in image})
        self.assertIsNone(sd.check_closure([], image, [], sd.PACKAGING))

    def test_install_succeeds_and_closure_is_clean(self):
        whl = make_wheel("alpha", "1.0", requires=["pluggy>=1.5"])
        result, members = self.run_main(
            ["python3", "-c", "import alpha, os; print(alpha.VALUE, os.stat(alpha.__file__).st_uid)"],
            deps=deps_tar([whl]))
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["deps"], {"status": "installed", "reason": None,
                                          "installed": [["alpha", "1.0"]]})
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0),
                         members["stderr.txt"])
        self.assertEqual(members["stdout.txt"], b"7 65531\n")
        self.assertIn("install.txt", members)
        self.assertIn(b"alpha", members["install.txt"])
        self.assertIn("deps_ms", result["durations"])
        self.assertEqual(list(members)[:4], ["result.json", "stdout.txt", "stderr.txt", "install.txt"])

    def test_missing_requires_dist_partner(self):
        result, members = self.run_main(self.marker_cmd(),
                                        deps=deps_tar([make_wheel("alpha", "1.0", requires=["beta>=1"])]))
        self.assert_deps_failed(result, members, "requires beta>=1, which is not installed")
        self.assertEqual(result["deps"]["installed"], [])

    def test_transitive_extra_missing_then_present(self):
        a = make_wheel("aaa", "1.0", requires=["bbb[x]>=1"])
        b = make_wheel("bbb", "1.0", requires=['ccc; extra == "x"'], extras=["x"])
        c = make_wheel("ccc", "1.0")
        result, members = self.run_main(self.marker_cmd(), deps=deps_tar([a, b]))
        self.assert_deps_failed(result, members, "ccc")
        self.reset()
        result, members = self.run_main(self.marker_cmd(), deps=deps_tar([a, b, c]))
        self.assertEqual(result["deps"]["status"], "installed", result)
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0))

    def test_old_pluggy_shadowing_the_image_fails(self):
        """Round 4 finding 2: pytest is not in the file, only the image has it; an old pluggy in
        /deps shadows the image's pluggy and pytest's `pluggy<2,>=1.5` must catch it."""
        result, members = self.run_main(self.marker_cmd(),
                                        deps=deps_tar([make_wheel("pluggy", "1.0.0")]))
        self.assert_deps_failed(result, members, "pytest")
        self.assertIn("effective pluggy is 1.0.0 (/deps/site)", result["deps"]["reason"])

    def test_hostile_files_never_run_during_install_and_check(self):
        marks = {k: os.path.join(self.out, "mark-" + k) for k in ("site", "pip", "pth", "wsite", "wpip")}
        code = "import os\nopen(%r, 'w').close()\n"
        evil = make_wheel("evil", "1.0", files={
            "sitecustomize.py": (code % marks["site"]).encode(),
            "pip/__init__.py": (code % marks["pip"]).encode(),
            "evil.pth": ("import os; open(%r, 'w').close()\n" % marks["pth"]).encode(),
            "evil_pkg/__init__.py": b""})
        work = [("sitecustomize.py", (code % marks["wsite"]).encode()),
                ("pip.py", (code % marks["wpip"]).encode())]
        seen = {}
        real_run = sd.run_command
        from unittest import mock

        def spy(spec, *a, **kw):
            seen["before_command"] = sorted(k for k, p in marks.items() if os.path.exists(p))
            return real_run(spec, *a, **kw)

        with mock.patch.object(sd, "run_command", spy):
            result, members = self.run_main(["sh", "-c", "true"], files=work, deps=deps_tar([evil]))
        self.assertEqual(result["deps"]["status"], "installed", (result, members.get("install.txt")))
        self.assertEqual(seen["before_command"], [], "dependency or checkout code ran before the command")
        self.assertEqual([k for k, p in marks.items() if os.path.exists(p)], [])
        self.assertTrue(os.path.exists(os.path.join(self.deps, "site", "sitecustomize.py")))

    def test_leftover_installer_process_is_dead_before_the_walk_and_the_metadata_reads(self):
        """Inspection round 1, B5: the background uid-65531 process must be observed ALIVE once
        pip has exited (else the test proves nothing) and DEAD when the permission walk and the
        METADATA reads begin -- not only at command start, which main() quiesces again anyway.
        Its output goes to /dev/null so a missing quiescence is not masked by the capture drain."""
        from unittest import mock
        real_argv = sd.pip_install_argv
        pid_file = os.path.join(self.deps, "tmp", "bg.pid")  # /deps/tmp: the installer's own dir
        seen = {}
        real_quiesce, real_walk, real_read_site, real_run = (sd.quiesce, sd.walk_deps, sd.read_site,
                                                            sd.run_command)

        def argv_with_background(deps):
            script = 'sleep 300 >/dev/null 2>&1 </dev/null & echo $! > %s; exec "$@"' % pid_file
            return ["sh", "-c", script, "sh"] + real_argv(deps)

        def live():
            return sd.scan_proc(sd.PROC, {sd.DEPS_UID})[0]

        def quiesce_spy(uids=(sd.RUN_UID,)):
            if sd.DEPS_UID in uids and "initial" not in seen:
                seen["initial"] = live()
            return real_quiesce(uids)

        def walk_spy(*a, **kw):
            seen.setdefault("walk", live())
            return real_walk(*a, **kw)

        def read_site_spy(*a, **kw):
            seen.setdefault("metadata", live())
            return real_read_site(*a, **kw)

        def run_spy(spec, *a, **kw):
            seen["command"] = live()
            return real_run(spec, *a, **kw)

        with mock.patch.object(sd, "pip_install_argv", argv_with_background), \
                mock.patch.object(sd, "quiesce", quiesce_spy), mock.patch.object(sd, "walk_deps", walk_spy), \
                mock.patch.object(sd, "read_site", read_site_spy), mock.patch.object(sd, "run_command", run_spy):
            result, _ = self.run_main(["sh", "-c", "true"], deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assertEqual(result["deps"]["status"], "installed", result)
        with open(pid_file) as handle:
            bg = int(handle.read().strip())
        self.assertIn(bg, seen["initial"], "the background installer process never existed")
        self.assertEqual(seen["walk"], [], "a uid-65531 process was alive when the permission walk began")
        self.assertEqual(seen["metadata"], [], "a uid-65531 process was alive when the METADATA reads began")
        self.assertEqual(seen["command"], [], "a uid-65531 process survived into the command")

    def test_entries_the_command_cannot_read_fail_and_the_command_never_starts(self):
        """Inspection round 1, B2: a 0600 module (or a 0700 package directory) passed the gate,
        the closure check read the METADATA and reported installed, and uid 65532 then could
        not import it. Now the walk refuses it and the command never starts."""
        from unittest import mock
        real_argv = sd.pip_install_argv
        for tail, needle in (('chmod 600 "$0"/site/alpha/__init__.py',
                              "/deps/site/alpha/__init__.py: not readable by the command"),
                             ('chmod 700 "$0"/site/alpha',
                              "/deps/site/alpha: not readable and searchable by the command")):
            def argv(deps, tail=tail):
                return ["sh", "-c", '"$@" && ' + tail, deps] + real_argv(deps)
            self.reset()
            with mock.patch.object(sd, "pip_install_argv", argv):
                result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
            self.assert_deps_failed(result, members, needle)
            self.assertEqual(result["deps"]["installed"], [])

    # -- gate initial pass, block B, findings 3/4: installed metadata through read_site()/main()
    def run_with_installer_tail(self, tail, **kw):
        """run_main() with the marker command and alpha 1.0, the installer followed by the sh
        `tail` ($0 = the deps directory) that runs as uid 65531 after pip succeeded."""
        from unittest import mock
        real_argv = sd.pip_install_argv

        def argv(deps):
            return ["sh", "-c", '"$@" && ' + tail, deps] + real_argv(deps)

        with mock.patch.object(sd, "pip_install_argv", argv):
            return self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]), **kw)

    def payload_file(self, data):
        """A root-written file under the 0755 test base, readable by the uid-65531 tail."""
        path = os.path.join(self.base, "payload-%s" % uuid.uuid4().hex)
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o644)
        return path

    def test_corrupt_installed_metadata_fails_and_the_command_never_starts(self):
        result, members = self.run_with_installer_tail(
            "printf 'no colon here\\n' >> \"$0\"/site/alpha-1.0.dist-info/METADATA")
        self.assert_deps_failed(result, members, "METADATA header without colon")
        self.assertEqual(result["deps"]["installed"], [])

    def test_second_dist_info_for_the_same_name_fails(self):
        """`Alpha-1.0.dist-info` normalises to the same name as pip's `alpha-1.0.dist-info`."""
        result, members = self.run_with_installer_tail(
            'cp -R "$0"/site/alpha-1.0.dist-info "$0"/site/Alpha-1.0.dist-info')
        self.assert_deps_failed(result, members, "duplicate distribution alpha in /deps/site")
        self.assertEqual(result["deps"]["installed"], [])

    def test_installed_metadata_over_the_line_bound_fails(self):
        path = self.payload_file(b"Summary: s\n" + b" x\n" * 200000)
        result, members = self.run_with_installer_tail(
            'cat %s >> "$0"/site/alpha-1.0.dist-info/METADATA' % path)
        self.assert_deps_failed(result, members, "too many lines")

    def test_deadline_expiring_while_parsing_one_metadata_stops_before_the_closure(self):
        """The clock jumps right after alpha's METADATA was read, so the next deadline check is
        the parser's own. The appended header ends in a malformed line: reaching it would report
        `without colon`; stopping inside the file reports the timeout. Neither the closure check
        nor the command may run."""
        from unittest import mock
        patcher, offset = self.time_jump()
        path = self.payload_file(b"Summary: s\n" + b" x\n" * 5000 + b"no colon here\n")
        calls = {"closure": 0}
        real_read, real_closure = sd._read_regular_nofollow, sd.check_closure
        site = os.path.join(self.deps, "site")

        def read(p, *a, **kw):
            data = real_read(p, *a, **kw)
            if p.startswith(site):
                offset[0] = 1e6
            return data

        def closure(*a, **kw):
            calls["closure"] += 1
            return real_closure(*a, **kw)

        with patcher, mock.patch.object(sd, "_read_regular_nofollow", read), \
                mock.patch.object(sd, "check_closure", closure):
            result, members = self.run_with_installer_tail(
                'cat %s >> "$0"/site/alpha-1.0.dist-info/METADATA' % path)
        self.assert_deps_failed(result, members, "while parsing METADATA")
        self.assertIn(sd.DEPS_TIMEOUT, result["deps"]["reason"])
        self.assertEqual(calls["closure"], 0, "the closure check ran past the deadline")

    def test_long_wheel_name_is_transported_and_installed(self):
        """Inspection round 1, B4: a valid 218-character wheel name (GNU tar, as the runner
        builds it) is extracted, installed and importable."""
        _name, data = make_wheel("alpha", "1.0")
        self.assertGreater(len(LONG_WHEEL_NAME), 205)
        result, members = self.run_main(["python3", "-c", "import alpha; print(alpha.VALUE)"],
                                        deps=deps_tar([(LONG_WHEEL_NAME, data)], fmt=tarfile.GNU_FORMAT))
        self.assertEqual(result["deps"], {"status": "installed", "reason": None,
                                          "installed": [["alpha", "1.0"]]}, members.get("install.txt"))
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0))
        self.assertEqual(members["stdout.txt"], b"7\n")

    # -- inspection round 1, B1: one deps deadline, enforced in every phase
    def time_jump(self):
        """(patcher, offset): time.monotonic() plus an offset the test raises to jump past
        every deadline at an exact point, with no sleeping and no timing race."""
        from unittest import mock
        real = time.monotonic
        offset = [0.0]
        return mock.patch.object(sd.time, "monotonic", lambda: real() + offset[0]), offset

    def test_extraction_gets_the_remaining_deps_budget(self):
        """Extraction used an independent EXTRACT_SECONDS; a stalled extraction overran the deps
        budget. EXTRACT_SECONDS is lowered to 10 here only so the old behaviour fails fast."""
        from unittest import mock
        real_extractall = tarfile.TarFile.extractall

        def slow(tf, path=".", *a, **kw):
            if str(path).endswith("wheels"):
                time.sleep(30)
            # bandit B202: a pass-through to the driver's own validated call (members, filter).
            return real_extractall(tf, path, *a, **kw)  # nosec B202

        started = time.monotonic()
        with mock.patch.object(tarfile.TarFile, "extractall", slow), mock.patch.object(sd, "EXTRACT_SECONDS", 10):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]),
                                            deps_timeout=2)
        self.assertLess(time.monotonic() - started, 8, "extraction was not held to the deps budget")
        self.assert_deps_failed(result, members, "timeout")

    def test_installer_is_not_started_after_the_budget_expired(self):
        from unittest import mock
        patcher, offset = self.time_jump()
        real_extract = sd.extract_deps
        started = []

        def extract(*a, **kw):
            problem = real_extract(*a, **kw)
            offset[0] = 1e6
            return problem

        def argv(deps):
            started.append(deps)
            return ["true"]

        with patcher, mock.patch.object(sd, "extract_deps", extract), mock.patch.object(sd, "pip_install_argv", argv):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "timeout")
        self.assertEqual(started, [], "pip was started after the deps budget expired")

    def test_deadline_expiring_in_the_permission_walk_stops_it(self):
        from unittest import mock
        patcher, offset = self.time_jump()
        calls = {"walk": 0, "read_site": 0}
        real_entry, real_read_site = sd.deps_entry_problem, sd.read_site

        def entry(label, st):
            calls["walk"] += 1
            offset[0] = 1e6
            return real_entry(label, st)

        def read_site(*a, **kw):
            calls["read_site"] += 1
            return real_read_site(*a, **kw)

        with patcher, mock.patch.object(sd, "deps_entry_problem", entry), mock.patch.object(sd, "read_site", read_site):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "timeout")
        self.assertEqual(calls, {"walk": 1, "read_site": 0}, "the walk or a later phase ran past the deadline")

    def test_deadline_expiring_in_the_metadata_reads_stops_them(self):
        from unittest import mock
        patcher, offset = self.time_jump()
        calls = {"read": 0, "closure": 0}
        real_read, real_closure = sd._read_regular_nofollow, sd.check_closure

        def read(*a, **kw):
            calls["read"] += 1
            offset[0] = 1e6
            return real_read(*a, **kw)

        def closure(*a, **kw):
            calls["closure"] += 1
            return real_closure(*a, **kw)

        with patcher, mock.patch.object(sd, "_read_regular_nofollow", read), \
                mock.patch.object(sd, "check_closure", closure):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "timeout")
        self.assertEqual(calls, {"read": 1, "closure": 0}, "METADATA reads or the closure ran past the deadline")

    def test_deadline_expiring_in_the_closure_check_stops_it(self):
        from unittest import mock
        patcher, offset = self.time_jump()
        calls = []
        real_pk = sd.PACKAGING

        def requirement(text):
            calls.append(text)
            offset[0] = 1e6
            return real_pk.Requirement(text)

        pk = types.SimpleNamespace(Requirement=requirement, Version=real_pk.Version)
        with patcher, mock.patch.object(sd, "PACKAGING", pk):
            result, members = self.run_main(self.marker_cmd(),
                                            deps=deps_tar([make_wheel("alpha", "1.0", requires=["pluggy>=1.5"])]))
        self.assert_deps_failed(result, members, "timeout")
        self.assertEqual(len(calls), 1, "the closure check kept parsing edges past the deadline")

    def test_command_cannot_write_into_deps(self):
        code = ("import errno, os\n"
                "for path, mode in ((%r, 'w'), (%r, 'a')):\n"
                "    try:\n        open(path, mode).write('x')\n        print('WROTE')\n"
                "    except PermissionError as exc:\n        print(errno.errorcode[exc.errno])\n"
                % (os.path.join(self.deps, "site", "x.py"),
                   os.path.join(self.deps, "site", "alpha", "__init__.py")))
        result, members = self.run_main(["python3", "-c", code], deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assertEqual(result["deps"]["status"], "installed")
        self.assertEqual(members["stdout.txt"], b"EACCES\nEACCES\n", members["stderr.txt"])

    def test_digest_mismatch_is_infrastructure(self):
        result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]),
                                        deps_sha256="0" * 64)
        self.assertIn("digest", result["infrastructure"])
        self.assertEqual(result["command_status"], "not_started")
        self.assertEqual(os.listdir(self.deps), [])
        self.assertFalse(os.path.exists(os.path.join(self.out, "ran")))

    def test_short_deps_stream_is_infrastructure(self):
        from unittest import mock
        data = deps_tar([make_wheel("alpha", "1.0")])
        real = sd._read_exact

        def short(stream, count, what="snapshot tar"):
            if what.startswith("deps"):
                count = count + 10
            return real(stream, count, what)

        with mock.patch.object(sd, "_read_exact", short):
            result, _ = self.run_main(self.marker_cmd(), deps=data)
        self.assertIn("shorter", result["infrastructure"])
        self.assertFalse(os.path.exists(os.path.join(self.out, "ran")))

    def test_bad_deps_members_fail(self):
        whl = make_wheel("alpha", "1.0")
        link = tarfile.TarInfo("evil.whl")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        nested = tarfile.TarInfo("sub/alpha-2.0-py3-none-any.whl")
        nested.size = 1
        dup = tarfile.TarInfo("requirements.txt")
        dup.size = 1
        for extra in ([(link, None)], [(nested, b"x")], [(dup, b"x")]):
            self.reset()
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([whl], extra_members=extra))
            self.assert_deps_failed(result, members, "deps tar")
            self.assertFalse(os.path.lexists(os.path.join(self.deps, "site", "alpha")))

    def test_deps_root_not_sticky_fails(self):
        os.chmod(self.deps, 0o777)
        result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "/deps")
        self.assertEqual(os.listdir(self.deps), [])

    def test_group_writable_or_symlink_entry_fails(self):
        from unittest import mock
        real_argv = sd.pip_install_argv
        for tail, needle in (('chmod g+w "$0"/site/alpha/__init__.py', "alpha/__init__.py: group- or other-writable"),
                             ('ln -s /etc/passwd "$0"/site/alpha/link', "/deps/site/alpha/link: symlink")):
            def argv(deps, tail=tail):
                return ["sh", "-c", '"$@" && ' + tail, deps] + real_argv(deps)
            self.reset()
            with mock.patch.object(sd, "pip_install_argv", argv):
                result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
            self.assert_deps_failed(result, members, needle)

    def test_pip_config_file_present_fails(self):
        from unittest import mock
        conf = os.path.join(self.base, "pip.conf")
        with open(conf, "w") as handle:
            handle.write("[global]\nindex-url = https://example.invalid/\n")
        with mock.patch.object(sd, "PIP_CONFIG_PATHS", ("/nonexistent/pip.conf", conf)):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "pip configuration")
        self.assertFalse(os.path.exists(os.path.join(self.deps, "site")))

    def test_install_output_overflow_fails(self):
        from unittest import mock
        with mock.patch.object(sd, "INSTALL_CAP", 16):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "output")
        self.assertLessEqual(len(members["install.txt"]), 16)

    def test_install_timeout_fails(self):
        from unittest import mock
        with mock.patch.object(sd, "pip_install_argv", lambda deps: ["sleep", "30"]):
            started = time.monotonic()
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]),
                                            deps_timeout=1)
        self.assertLess(time.monotonic() - started, 15)
        self.assert_deps_failed(result, members, "timeout")

    def test_pip_failure_fails(self):
        whl_name, whl = make_wheel("alpha", "1.0")
        bad_req = ("alpha==1.0 --hash=sha256:%s\n" % ("0" * 64)).encode()
        result, members = self.run_main(self.marker_cmd(), deps=deps_tar([(whl_name, whl)], requirements=bad_req))
        self.assert_deps_failed(result, members, "pip")
        self.assertIn(b"hash", members["install.txt"].lower())

    def test_packaging_unavailable_fails_closed(self):
        from unittest import mock
        with mock.patch.object(sd, "PACKAGING", None):
            result, members = self.run_main(self.marker_cmd(), deps=deps_tar([make_wheel("alpha", "1.0")]))
        self.assert_deps_failed(result, members, "packaging unavailable")

    def test_deps_budget_counts_against_the_command_timeout(self):
        from unittest import mock
        real_argv = sd.pip_install_argv
        with mock.patch.object(sd, "pip_install_argv",
                               lambda deps: ["sh", "-c", 'sleep 3; exec "$@"', "sh"] + real_argv(deps)):
            result, _ = self.run_main(["sleep", "10"], deps=deps_tar([make_wheel("alpha", "1.0")]),
                                      timeout=8, deps_timeout=7)
        self.assertEqual(result["deps"]["status"], "installed", result)
        self.assertEqual(result["command_status"], "timeout")
        self.assertGreaterEqual(result["durations"]["deps_ms"], 3000)
        self.assertLess(result["durations"]["command_ms"], 6000)


# ----------------------------------------------------------------------------------------
# Optional container smoke test. Needs Docker Desktop (context desktop-linux) and the image
# below present locally. Run with CLAUDEX_DOCKER_TESTS=1. Containers carry the label
# claudex.measure=1 and are removed in tearDown; `docker ps -a --filter label=claudex.measure=1`
# must be empty afterwards.
# ----------------------------------------------------------------------------------------
IMAGE = "python@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb"
DOCKER_ENV = dict(os.environ, MSYS_NO_PATHCONV="1")


def _docker(*args, input_bytes=None, timeout=120):
    return subprocess.run(["docker", "--context", "desktop-linux", *args], input=input_bytes,
                          capture_output=True, timeout=timeout, env=DOCKER_ENV)


def _snapshot_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, content in files:
            ti = tarfile.TarInfo(name)
            ti.size = len(content)
            ti.mode = 0o644
            ti.uid = ti.gid = 65532
            tf.addfile(ti, io.BytesIO(content))
    return buf.getvalue()


@unittest.skipUnless(os.environ.get("CLAUDEX_DOCKER_TESTS") == "1", "set CLAUDEX_DOCKER_TESTS=1")
class ContainerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.ids = []
        # The runner's own launcher (plan B2 approach 3b): argv carries only the fixed loader and
        # the source's sha256; the source goes in first on stdin (self.loader_prefix).
        import sandbox_run
        self.sandbox_run = sandbox_run
        self.source = (REPO / "scripts" / "sandbox_driver.py").read_bytes()
        self.driver_argv, self.loader_prefix = sandbox_run.bootstrap(self.source)

    def tearDown(self):
        for cid in self.ids:
            _docker("rm", "-f", cid, timeout=60)

    def create(self, deps=False):
        """`docker create` with the runner's flags and the loader argv; returns the id."""
        # B1.5: /deps root-owned 1777. --mount tmpfs is noexec by default (measured 2026-11-01:
        # an extension module then fails with "failed to map segment"), so this uses --tmpfs.
        deps_mount = ("--tmpfs", "/deps:rw,exec,nosuid,nodev,size=268435456,mode=1777") if deps else ()
        name = "claudex-measure-" + uuid.uuid4().hex[:12]
        create = _docker(
            "create", "--name", name, "--label", "claudex.measure=1", "--pull=never",
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--cap-add", "SETUID",
            "--cap-add", "SETGID", "--cap-add", "KILL", "--security-opt", "no-new-privileges",
            "--user", "0:0", "--pids-limit", "512", "--memory", "4g", "--memory-swap", "4g",
            "--cpus", "2", "--log-driver", "none",
            "--mount", "type=tmpfs,destination=/work,tmpfs-size=268435456,tmpfs-mode=1777",
            "--mount", "type=tmpfs,destination=/out,tmpfs-size=50331648,tmpfs-mode=1777",
            "--tmpfs", "/tmp:size=268435456", "--tmpfs", "/home/run:size=67108864", *deps_mount,
            "-e", "HOME=/home/run", "-w", "/", "-i", IMAGE, *self.driver_argv)
        self.assertEqual(create.returncode, 0, create.stderr.decode(errors="replace"))
        cid = create.stdout.decode().strip()
        self.ids.append(cid)
        return cid

    def run_driver(self, argv, exports=(), files=(), timeout=60, capture_cap=8 * 1024 * 1024,
                   deps=b""):
        tar = _snapshot_tar(files)
        nonce = uuid.uuid4().hex
        spec = {"argv": list(argv), "exports": list(exports), "capture_cap": capture_cap,
                "export_cap": 16 * 1024 * 1024, "timeout": timeout, "tar_len": len(tar),
                "deps_len": len(deps), "deps_sha256": hashlib.sha256(deps).hexdigest() if deps else "",
                "deps_timeout": 120}
        cid = self.create(deps=bool(deps))
        # the loader block first, then the driver's protocol exactly as before B2
        payload = self.loader_prefix + nonce.encode() + b"\n" + json.dumps(spec).encode() + b"\n" + tar + deps
        start = _docker("start", "-ai", cid, input_bytes=payload, timeout=timeout + 60)
        inspect = _docker("inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", cid)
        self.assertEqual(inspect.stdout.decode().strip(), "0 false", start.stderr.decode(errors="replace"))
        self.assertEqual(start.returncode, 0, start.stderr.decode(errors="replace"))
        members = {}
        order = []
        with tarfile.open(fileobj=io.BytesIO(start.stdout), mode="r:") as tf:
            for m in tf.getmembers():
                self.assertTrue(m.isreg())
                order.append(m.name)
                members[m.name] = tf.extractfile(m).read()
        result = json.loads(members["result.json"])
        self.assertEqual(result["nonce"], nonce)
        self.assertEqual(order[:3], ["result.json", "stdout.txt", "stderr.txt"])
        return result, members

    def test_hello(self):
        result, members = self.run_driver(["python3", "-c", "print('hi')"])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(result["command_exit"], 0)
        self.assertEqual(members["stdout.txt"], b"hi\n")
        self.assertIsNone(result["infrastructure"])

    def test_snapshot_extracted_and_nonzero_exit(self):
        result, members = self.run_driver(
            ["python3", "-c", "import sys;print(open('a.txt').read());sys.exit(2)"],
            files=[("a.txt", b"payload")])
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 2))
        self.assertEqual(members["stdout.txt"], b"payload\n")

    def test_export_with_umask_077(self):
        result, members = self.run_driver(
            ["sh", "-c", "umask 077; echo data > /out/x.txt"], exports=["x.txt", "nope.txt"])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(result["exports"]["x.txt"], hashlib.sha256(b"data\n").hexdigest())
        self.assertEqual(result["exports"]["nope.txt"], "missing")
        self.assertEqual(members["out/x.txt"], b"data\n")
        self.assertNotIn("out/nope.txt", members)

    def test_driver_separation(self):
        script = ("echo forged > /proc/1/fd/1 2>/dev/null && echo WROTE; "
                  "kill -9 1 2>/dev/null && echo KILLED; "
                  "cat /proc/1/fd/0 >/dev/null 2>&1 && echo READ0; "
                  "ls /tmp/driver >/dev/null 2>&1 && echo LISTED; "
                  "id -u; true")
        result, members = self.run_driver(["sh", "-c", script])
        self.assertEqual(result["command_status"], "exited")
        self.assertEqual(members["stdout.txt"].decode().split(), ["65532"])
        self.assertIsNone(result["infrastructure"])

    def test_background_writer_killed_before_packaging(self):
        # The writer announces itself before it loops and the command waits for that, so the
        # writer certainly exists when the command exits. The quiescence itself is asserted in
        # InProcessDriverTests (no live uid-65532 process and a stable file at export time).
        script = ("(echo x >> /out/bg.txt; echo r > /out/ready; while :; do echo x >> /out/bg.txt; done) "
                  ">/dev/null 2>&1 & "
                  "while [ ! -f /out/ready ]; do :; done; echo started")
        result, members = self.run_driver(["sh", "-c", script], exports=["bg.txt"])
        self.assertEqual(result["command_status"], "exited")
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(members["stdout.txt"], b"started\n")
        self.assertRegex(result["exports"]["bg.txt"], r"^[0-9a-f]{64}$")

    def test_timeout(self):
        result, _ = self.run_driver(["sleep", "30"], timeout=2)
        self.assertEqual(result["command_status"], "timeout")
        self.assertIsNone(result["command_exit"])

    def test_output_limit(self):
        result, members = self.run_driver(["sh", "-c", "yes"], capture_cap=65536)
        self.assertEqual(result["command_status"], "output_limit")
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(members["stdout.txt"]), 65536)

    def test_deps_install_in_a_real_container(self):
        """The real `python3 -I -S -c` start: the vendored packaging imports from IMAGE_SITE,
        pip installs as 65531 into a real tmpfs, the command imports the wheel as 65532."""
        whl = make_wheel("alpha", "1.0")
        result, members = self.run_driver(
            ["python3", "-c", "import alpha, os; print(alpha.VALUE, os.getuid(), os.stat(alpha.__file__).st_uid)"],
            deps=deps_tar([whl]), timeout=120)
        self.assertIsNone(result["infrastructure"])
        self.assertEqual(result["deps"], {"status": "installed", "reason": None, "installed": [["alpha", "1.0"]]},
                         members.get("install.txt"))
        self.assertEqual((result["command_status"], result["command_exit"]), ("exited", 0))
        self.assertEqual(members["stdout.txt"], b"7 65532 65531\n")

    def test_deps_missing_partner_in_a_real_container(self):
        result, members = self.run_driver(["sh", "-c", "echo RAN"], timeout=120,
                                          deps=deps_tar([make_wheel("alpha", "1.0", requires=["beta>=1"])]))
        self.assertEqual(result["command_status"], "deps_failed")
        self.assertIn("beta", result["deps"]["reason"])
        self.assertEqual(members["stdout.txt"], b"")

    def test_no_deps_has_deps_null(self):
        result, members = self.run_driver(["true"])
        self.assertEqual(list(result), B1_RESULT_KEYS + ["deps"])
        self.assertIsNone(result["deps"])
        self.assertNotIn("install.txt", members)

    def test_not_started(self):
        result, _ = self.run_driver(["/no/such/binary"])
        self.assertEqual(result["command_status"], "not_started")

    # Plan B2 approach 3b (U6): the loader in the real image ---------------------------------
    def start_raw(self, payload):
        cid = self.create()
        start = _docker("start", "-ai", cid, input_bytes=payload, timeout=120)
        inspect = _docker("inspect", "--format", "{{.State.ExitCode}}", cid)
        return start, inspect.stdout.decode().strip()

    def test_loader_refuses_a_tampered_source_in_the_container(self):
        # same length, one byte changed: the loader's hash check stops it before anything runs
        evil = self.source.replace(b"sandbox_driver", b"sandbox_DRIVER", 1)
        self.assertEqual(len(evil), len(self.source))
        payload = str(len(evil)).encode() + b"\n" + evil + NONCE.encode() + b"\n{}\n"
        start, code = self.start_raw(payload)
        self.assertNotEqual(code, "0")
        self.assertEqual(start.stdout, b"")
        self.assertIn(b"sha256", start.stderr)

    def test_loader_refuses_an_over_long_length_line_in_the_container(self):
        start, code = self.start_raw(b"123456789\n" + self.source)
        self.assertNotEqual(code, "0")
        self.assertEqual(start.stdout, b"")

    def test_argv_shows_only_the_loader_and_the_hash(self):
        # /proc/1/cmdline is world readable: it carries the fixed loader and the source's
        # sha256, never the source, the nonce or the spec
        result, members = self.run_driver(["sh", "-c", "tr '\\0' '\\n' < /proc/1/cmdline"])
        self.assertEqual(result["command_status"], "exited")
        cmdline = members["stdout.txt"].decode().split("\n")
        self.assertEqual(cmdline[:5], self.driver_argv)
        self.assertIn(hashlib.sha256(self.source).hexdigest(), cmdline[4])
        self.assertNotIn(result["nonce"], members["stdout.txt"].decode())


if __name__ == "__main__":
    unittest.main()
