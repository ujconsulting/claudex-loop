"""sandbox_deps: strict requirements parser, merge, canonical digests, lockfile parser (plan B1.5, steps 1 and 7).

Pure module, so no fixtures beyond byte strings. Written before scripts/sandbox_deps.py and seen
failing first (ModuleNotFoundError). Every refusal case asserts the exception AND that nothing
came back (no partial list), and that the message is ASCII and names the label.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sandbox_deps as sd  # noqa: E402


def H(n: int) -> str:
    return f"{n:064x}"


def hline(n: int) -> str:
    return f"--hash=sha256:{H(n)}"


def parse(text: str, label: str = "reqs.txt"):
    return sd.parse_requirements(text.encode("utf-8"), label)


def refused(call, *needles):
    with pytest.raises(sd.DepsRefused) as ei:
        call()
    msg = str(ei.value)
    assert msg.isascii(), msg
    for n in needles:
        assert n in msg, (n, msg)
    return msg


# ------------------------------------------------------------------ normalize / regexes

def test_normalize_name_pep503():
    assert sd.normalize_name("Foo_Bar.baz--Qux") == "foo-bar-baz-qux"
    assert sd.normalize_name("a") == "a"
    assert sd.normalize_name("Zope.Interface") == "zope-interface"


@pytest.mark.parametrize("v", ["1", "1.0", "1.2.3", "0.0.1", "10.20.30", "1.0a1", "1.0b2", "1.0rc3",
                               "1.0.post1", "1.0.dev0", "1.0a1.post2.dev3", "1.0rc1.dev4", "2024.10.1"])
def test_version_re_accepts_canonical(v):
    assert sd.VERSION_RE.fullmatch(v)


@pytest.mark.parametrize("v", ["v1.0", "1.0-1", "1.0.post", "01.0", "1!2.0", "1.0+local", "1.0.0.", "",
                               "1.0_1", "1.0.*", "1.0c1", "1.0.RC1", "1.0A1", "1..0", "1.0.dev", "1.0.00"])
def test_version_re_refuses_noncanonical(v):
    assert not sd.VERSION_RE.fullmatch(v)


def test_hash_re():
    assert sd.HASH_RE.fullmatch(H(1))
    assert not sd.HASH_RE.fullmatch(H(1).upper().replace("0", "A"))  # uppercase letters present
    assert not sd.HASH_RE.fullmatch("ab" * 31)


# ------------------------------------------------------------------ parser: accepted

def test_simple_accepted():
    out = parse(f"foo==1.0 {hline(1)}\n")
    assert out == [sd.Req("foo", "1.0", frozenset({H(1)}))]


def test_req_is_immutable():
    r = parse(f"foo==1.0 {hline(1)}\n")[0]
    with pytest.raises(AttributeError):
        r.version = "2.0"  # type: ignore[misc]


def test_blank_lines_comments_and_trailing_comment():
    text = (f"# header\n\n   \n  # indented comment\n"
            f"Foo_Bar==1.0 {hline(2)} {hline(1)}   # trailing\n")
    out = parse(text)
    assert out == [sd.Req("foo-bar", "1.0", frozenset({H(1), H(2)}))]


def test_crlf_and_no_final_newline():
    out = sd.parse_requirements(f"a==1 {hline(1)}\r\nb==2 {hline(2)}".encode(), "x")
    assert [r.name for r in out] == ["a", "b"]


def test_continuations():
    text = f"foo==1.0 \\\n    {hline(1)} \\\n    {hline(2)}\n"
    assert parse(text)[0].hashes == frozenset({H(1), H(2)})


FIXTURES = Path(__file__).resolve().parent / "fixtures"
# Real compiler output, checked in byte-for-byte unchanged (inspection round 1, A10). Provenance:
#   uv 0.11.5, 2026-11-01, in an empty directory holding requirements.in =
#     six==1.17.0 / markupsafe==3.0.3 / pytest-timeout==2.3.1
#   uv pip compile --generate-hashes --python-version 3.13 --python-platform x86_64-manylinux_2_28
#     --no-cache requirements.in -o requirements.txt
# The command line uv recorded in the header of the file is the authoritative one.
UV_FIXTURE = FIXTURES / "uv-compile-requirements.txt"
UV_FIXTURE_SHA256 = "a507ef7e21bd6e8f2b86e938b3a63455bf3afe689d8b01f46a0e8de147bf7940"
UV_EXPECTED = [("iniconfig", "2.3.1"), ("markupsafe", "3.0.3"), ("packaging", "26.3"), ("pluggy", "1.7.0"),
               ("pygments", "2.21.0"), ("pytest", "9.2.0"), ("pytest-timeout", "2.3.1"), ("six", "1.17.0")]


def _hashes_by_requirement(text: str) -> dict[str, set[str]]:
    """Independent reading of the fixture: every sha256 attributed to the requirement above it."""
    out: dict[str, set[str]] = {}
    current = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw[0].isspace():
            current = stripped.split("==", 1)[0].lower()
            out[current] = set()
        for part in stripped.split():
            if part.startswith("--hash=sha256:"):
                out[current].add(part[len("--hash=sha256:"):])
    return out


def test_real_uv_pip_compile_output_parses_with_every_hash():
    data = UV_FIXTURE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == UV_FIXTURE_SHA256, "fixture must stay byte-for-byte unchanged"
    assert b"\r" not in data and b"uv pip compile --generate-hashes" in data
    out = sd.parse_requirements(data, "uv-compile-requirements.txt")
    assert [(r.name, r.version) for r in out] == UV_EXPECTED
    expected = _hashes_by_requirement(data.decode("ascii"))
    assert {r.name: set(r.hashes) for r in out} == expected
    assert len(out[1].hashes) == 89 and all(len(r.hashes) == 2 for r in out if r.name != "markupsafe")
    assert sum(len(r.hashes) for r in out) == data.count(b"--hash=sha256:")


def test_hand_written_pip_compile_style_file():
    # Secondary case, NOT real compiler output: pip-compile's header style (a `#` banner and
    # multi-line `# via` blocks), hashes are placeholders. The real output is the uv fixture above.
    text = (
        "#\n"
        "# This file is autogenerated by pip-compile with Python 3.13\n"
        "# by the following command:\n"
        "#\n"
        "#    pip-compile --generate-hashes --output-file=requirements.txt requirements.in\n"
        "#\n"
        f"iniconfig==2.0.0 \\\n    {hline(10)} \\\n    {hline(11)}\n"
        "    # via pytest\n"
        f"markupsafe==2.1.5 \\\n    {hline(20)} \\\n    {hline(21)} \\\n    {hline(22)}\n"
        "    # via jinja2\n"
        f"pytest==8.3.3 \\\n    {hline(30)}\n"
        "    # via -r requirements.in\n"
        f"Typing_Extensions==4.12.2 \\\n    {hline(40)}\n"
        "    # via\n"
        "    #   pytest\n"
        "    #   something-else\n"
    )
    out = parse(text)
    assert [(r.name, r.version, len(r.hashes)) for r in out] == [
        ("iniconfig", "2.0.0", 2), ("markupsafe", "2.1.5", 3), ("pytest", "8.3.3", 1),
        ("typing-extensions", "4.12.2", 1)]


def test_comment_inside_continuation_ends_logical_line():
    text = f"foo==1.0 \\\n    {hline(1)} \\\n# note\nbar==2 {hline(2)}\n"
    assert [r.name for r in parse(text)] == ["foo", "bar"]


def test_empty_file_gives_empty_list():
    assert parse("") == []
    assert parse("# only a comment\n") == []


def test_500_requirements_accepted():
    text = "".join(f"p{i}==1.0 {hline(i)}\n" for i in range(500))
    assert len(parse(text)) == 500


# ------------------------------------------------------------------ parser: refused

OPTION_LINES = ["-r other.txt", "-c constraints.txt", "-e .", "-e git+https://x/y", "-i https://x/simple",
                "--index-url https://x/simple", "--extra-index-url https://x/simple", "-f dir",
                "--find-links dir", "--trusted-host example.org", "--pre", "--no-binary :all:",
                "--only-binary :all:", "--require-hashes", "-Z", "--whatever=1"]


@pytest.mark.parametrize("line", OPTION_LINES)
def test_option_lines_refused(line):
    text = f"# c\nok==1.0 {hline(1)}\n{line}\n"
    msg = refused(lambda: parse(text, "my.txt"), "my.txt", ":3", "option")
    assert "pip-compile" in msg or "re-compile" in msg or "option" in msg


def test_option_line_inside_continuation_refused():
    refused(lambda: parse(f"foo==1.0 \\\n    --index-url https://x/simple \\\n    {hline(1)}\n"), ":1", "option")


@pytest.mark.parametrize("line,needle", [
    ("foo @ https://example.org/foo.whl", "URL"),
    ("foo==1.0 @ file:///x", "URL"),
    ("https://example.org/foo.whl", "URL"),
    ("git+https://example.org/foo.git", "URL"),
    ("./local/dir", "path"),
    ("/abs/path/foo.whl", "path"),
    ("..\\win\\foo.whl", "path"),
    ("foo[extra]==1.0", "extra"),
    ('foo==1.0 ; python_version < "3.13"', "marker"),
    ("foo==1.0;sys_platform=='linux'", "marker"),
])
def test_urls_paths_extras_markers_refused(line, needle):
    refused(lambda: parse(f"{line} {hline(1)}\n", "x.txt"), "x.txt:1", needle)


def test_marker_message_does_not_promise_recompile_fixes_it():
    msg = refused(lambda: parse(f'foo==1.0 ; python_version < "3.13" {hline(1)}\n'), "marker")
    assert "markers are not evaluated" in msg


def test_missing_hash_refused():
    refused(lambda: parse("foo==1.0\n", "u.txt"), "u.txt:1", "hash")


def test_missing_hash_hint_compile():
    msg = refused(lambda: parse("foo==1.0\n"), "hash")
    assert "--generate-hashes" in msg


@pytest.mark.parametrize("tok", ["--hash=sha512:" + "a" * 128, "--hash=md5:" + "a" * 32,
                                 "--hash=sha256:" + "a" * 63, "--hash=sha256:" + "a" * 65,
                                 "--hash=sha256:" + "g" * 64, "--hash=sha256:", "--hash=", "--hash"])
def test_bad_hash_refused(tok):
    refused(lambda: parse(f"foo==1.0 {tok}\n"), ":1", "hash")


def test_uppercase_hex_refused():
    refused(lambda: parse(f"foo==1.0 --hash=sha256:{'A' * 64}\n"), "hash", "lowercase")


def test_one_bad_hash_among_good_refused():
    refused(lambda: parse(f"foo==1.0 {hline(1)} --hash=sha512:{'a' * 128}\n"), "hash")


@pytest.mark.parametrize("spec", ["foo>=1.0", "foo<=1.0", "foo~=1.0", "foo!=1.0", "foo===1.0", "foo>1", "foo<2",
                                  "foo", "foo==", "foo==1.*"])
def test_only_double_equals_pins(spec):
    refused(lambda: parse(f"{spec} {hline(1)}\n"), ":1")


@pytest.mark.parametrize("v", ["v1.0", "1.0-1", "1.0.post", "01.0", "1!2.0", "1.0+local", "1.0_1", "1.0.RC1"])
def test_noncanonical_versions_refused(v):
    msg = refused(lambda: parse(f"foo=={v} {hline(1)}\n", "n.txt"), "n.txt:1", "non-canonical version")
    assert "re-compile" in msg


@pytest.mark.parametrize("name", ["-foo", "foo-", ".foo", "foo.", "_foo", "fo$o", "fo o"])
def test_bad_names_refused(name):
    refused(lambda: parse(f"{name}==1.0 {hline(1)}\n"), ":1")


def test_duplicate_after_normalisation_refused():
    text = f"Foo_Bar==1.0 {hline(1)}\nfoo-bar==1.0 {hline(2)}\n"
    refused(lambda: parse(text, "d.txt"), "d.txt:2", "duplicate", "foo-bar")


def test_more_than_500_refused():
    text = "".join(f"p{i}==1.0 {hline(i)}\n" for i in range(501))
    refused(lambda: parse(text), "500")


def test_file_over_1mib_refused():
    big = b"# " + b"x" * sd.MAX_REQ_FILE + b"\n"
    refused(lambda: sd.parse_requirements(big, "big.txt"), "big.txt", "1 MiB")


def test_file_exactly_1mib_is_not_size_refused():
    data = b"#" + b"x" * (sd.MAX_REQ_FILE - 2) + b"\n"
    assert len(data) == sd.MAX_REQ_FILE
    assert sd.parse_requirements(data, "x") == []


def test_non_utf8_refused():
    refused(lambda: sd.parse_requirements(b"# \xff\xfe\nfoo==1 " + hline(1).encode() + b"\n", "e.txt"),
            "e.txt", "UTF-8")


def test_bom_refused():
    refused(lambda: sd.parse_requirements(b"\xef\xbb\xbf" + f"foo==1.0 {hline(1)}\n".encode(), "b.txt"), "b.txt:1")


def test_dangling_continuation_refused():
    refused(lambda: parse(f"foo==1.0 {hline(1)} \\"), ":1", "continuation")


@pytest.mark.parametrize("text,line", [
    ("\\\n\nfoo==1.0 " + hline(1) + "\n", ":1"),          # standalone backslash, then a blank line
    ("\\\n# note\nfoo==1.0 " + hline(1) + "\n", ":1"),    # standalone backslash, then a comment line
    ("   \\\n   \n", ":1"),                               # whitespace only on both halves
    ("ok==1.0 " + hline(1) + "\n\\\n", ":2"),             # standalone backslash before the final newline
    ("ok==1.0 " + hline(1) + "\n\\", ":2"),               # standalone backslash at EOF, no newline
    ("\\\n\\\n\\\n\n", ":1"),                             # a chain of empty continuations
    ("x \\\n  # c\n", None),                              # non-empty first half: an ordinary refusal
])
def test_empty_logical_line_refused_never_indexerror(text, line):
    """Inspection round 1, A3: an empty logical line raised IndexError (tokens[0]) instead of
    a refusal, so neither caller produced its refusal and manifest."""
    needles = ("e.txt",) + ((line, "continuation") if line else ())
    refused(lambda: parse(text, "e.txt"), *needles)


# Inspection round 1, A1: `\s+#.*$` (unanchored, re.sub) rescanned a whitespace run from every
# start position: quadratic. 100 000 spaces exceeded a 3 s probe, the file limit is 1 MiB, and the
# parse runs in the parent outside any fetch deadline. The parse runs in a child process so a
# regression fails the test at the timeout instead of hanging the suite.
PARSE_BOUND_S = 2.0
_SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
_TIMING_CHILD = r"""
import json, re, sys, time
sys.path.insert(0, sys.argv[1])
import sandbox_deps as sd
M = sd.MAX_REQ_FILE
cases = {
    "1MiB spaces": b" " * M,
    "spaces then x": b" " * (M - 1) + b"x",
    "space lines": (b" " * 1023 + b"\n") * 1024,
    "tab/space runs between x": b"x" + (b" \t" * 500 + b"x") * (M // 1001),
    "hash without whitespace": b"x#" * (M // 2),
    "spaces then backslash, blank": b" " * (M - 3) + b"\\\n\n",
    "pin then spaces, no hash": b"foo==1.0" + b" " * (M - 8),
    "long version": b"foo==" + b"1." * ((M - 6) // 2) + b"x",
    "long name": b"a" + b"-" * (M - 2) + b"$",
    "empty continuations": b"\\\n" * (M // 2),
}
if sys.argv[2] == "lock":
    L = sd.MAX_LOCK_FILE - 200
    def doc(key, version):
        return ('{"lockfileVersion":3,"packages":{"":{},"%s":{"version":"%s",'
                '"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}' % (key, version)).encode()
    cases = {
        "nested key": doc("node_modules/a/" * (L // 15) + "node_modules/a!", "1.0.0"),
        "long semver prerelease": doc("node_modules/a", "1.0.0-" + "1a." * (L // 3) + "!"),
        "long semver build": doc("node_modules/a", "1.0.0+" + "a." * (L // 2) + "!"),
    }
    out = {}
    for name, data in cases.items():
        assert len(data) <= sd.MAX_LOCK_FILE, name
        t = time.perf_counter()
        try:
            sd.parse_package_lock(data, "big.json")
            outcome = "accepted"
        except sd.DepsRefused:
            outcome = "refused"
        out[name] = [time.perf_counter() - t, outcome]
    print(json.dumps(out))
    sys.exit(0)
if sys.argv[2] == "old-regex":
    re.compile(r"\s+#.*$").sub("", " " * M)
    print("{}")
    sys.exit(0)
out = {}
for name, data in cases.items():
    assert len(data) <= M, name
    t = time.perf_counter()
    try:
        sd.parse_requirements(data, "big.txt")
        outcome = "accepted"
    except sd.DepsRefused:
        outcome = "refused"
    out[name] = [time.perf_counter() - t, outcome]
print(json.dumps(out))
"""


def _timing_child(mode: str, timeout: float):
    import subprocess  # test-only; the module under test stays process-free
    return subprocess.run([sys.executable, "-I", "-c", _TIMING_CHILD, _SCRIPTS, mode],
                          capture_output=True, text=True, timeout=timeout, check=False)


def test_pathological_whitespace_parses_in_bounded_time():
    proc = _timing_child("parse", timeout=30)
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)
    assert len(results) == 10
    slow = {name: r for name, r in results.items() if r[0] >= PARSE_BOUND_S}
    assert not slow, slow
    assert results["1MiB spaces"][1] == "accepted" and results["space lines"][1] == "accepted"
    assert results["empty continuations"][1] == "refused"


def test_pathological_16mib_lockfile_parses_in_linear_time():
    # Regex audit of the lockfile path: every pattern is linear (16x input ~ 16x time, measured)
    # and versions are capped at 256 characters before the semver regex, so this bound is
    # generous and only a super-linear regression (minutes) can trip it. The json_depth_ok byte
    # loop alone takes ~1.6 s on 16 MiB here.
    proc = _timing_child("lock", timeout=120)
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout)
    assert len(results) == 3
    assert all(outcome == "refused" for _, outcome in results.values()), results
    slow = {name: r for name, r in results.items() if r[0] >= 20.0}
    assert not slow, slow


def test_timing_harness_catches_the_old_comment_regex():
    """Positive control: the regex the fix replaced does NOT finish 1 MiB of spaces in the bound,
    so the bounded-time test above is able to fail, and the slowness was that regex."""
    import subprocess
    with pytest.raises(subprocess.TimeoutExpired):
        _timing_child("old-regex", timeout=PARSE_BOUND_S + 1.0)


def test_comment_stripping_semantics_unchanged():
    # `#` starts a comment only at line start or after whitespace; the whitespace before it goes too
    assert parse(f"foo==1.0 {hline(1)}\t# c # d\n")[0].hashes == frozenset({H(1)})
    refused(lambda: parse(f"foo==1.0#x {hline(1)}\n"), ":1")
    assert parse(f"foo==1.0 \\  # c\n    {hline(1)}\n")[0].hashes == frozenset({H(1)})
    assert parse(f"foo==1.0 {hline(1)} #\n") == [sd.Req("foo", "1.0", frozenset({H(1)}))]
    assert parse(f"foo==1.0 {hline(1)}　# ideographic space\n")[0].name == "foo"


def test_non_ascii_in_requirement_message_is_ascii():
    msg = refused(lambda: parse("föo==1.0 " + hline(1) + "\n", "ä.txt"), ":1")
    assert msg.isascii()


def test_refusal_returns_no_partial_result():
    text = f"ok==1.0 {hline(1)}\nbad\n"
    got = []
    with pytest.raises(sd.DepsRefused):
        got.append(parse(text))
    assert got == []


# ------------------------------------------------------------------ merge

def R(name, version, *hs):
    return sd.Req(name, version, frozenset(H(h) for h in hs))


def test_merge_sorted_and_union_of_names():
    out = sd.merge([[R("b", "1", 1)], [R("a", "2", 2)]])
    assert [r.name for r in out] == ["a", "b"]


def test_merge_intersects_hashes():
    out = sd.merge([[R("a", "1", 1, 2, 3)], [R("a", "1", 2, 3, 4)]])
    assert out == [R("a", "1", 2, 3)]


def test_merge_version_conflict_refused():
    refused(lambda: sd.merge([[R("a", "1.0", 1)], [R("a", "1.1", 1)]]), "a", "1.0", "1.1")


def test_merge_empty_intersection_refused():
    refused(lambda: sd.merge([[R("a", "1", 1)], [R("a", "1", 2)]]), "a", "hash")


def test_merge_three_files_pairwise_overlap_no_common_hash():
    g = [[R("a", "1", 1, 2)], [R("a", "1", 2, 3)], [R("a", "1", 1, 3)]]
    refused(lambda: sd.merge(g), "a", "hash")


def test_merge_single_group_identity_and_empty():
    one = [R("a", "1", 1), R("b", "2", 2)]
    assert sd.merge([one]) == one
    assert sd.merge([]) == []
    assert sd.merge([[], []]) == []


def test_merge_does_not_mutate_inputs():
    a = [R("a", "1", 1, 2)]
    sd.merge([a, [R("a", "1", 2)]])
    assert a == [R("a", "1", 1, 2)]


# ------------------------------------------------------------------ canonical json / digest / render

def test_canonical_json_shape_and_sorting():
    out = sd.canonical_json([R("b", "2", 5, 3), R("a", "1", 1)])
    assert out == json.dumps([["a", "1", [H(1)]], ["b", "2", [H(3), H(5)]]], sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
    assert b" " not in out


def test_canonical_json_deterministic_regardless_of_order_and_set_order():
    a = sd.canonical_json([R("a", "1", 1, 2), R("b", "2", 3)])
    b = sd.canonical_json([R("b", "2", 3), R("a", "1", 2, 1)])
    assert a == b


def test_requirements_sha256():
    reqs = [R("a", "1", 1)]
    assert sd.requirements_sha256(reqs) == hashlib.sha256(sd.canonical_json(reqs)).hexdigest()
    assert sd.requirements_sha256(reqs) != sd.requirements_sha256([R("a", "2", 1)])
    assert sd.requirements_sha256(reqs) != sd.requirements_sha256([R("a", "1", 2)])
    assert len(sd.requirements_sha256([])) == 64


def test_render_requirements():
    out = sd.render_requirements([(R("b", "2", 1, 2), H(2)), (R("a", "1", 3), H(3))])
    assert out == (f"a==1 --hash=sha256:{H(3)}\nb==2 --hash=sha256:{H(2)}\n").encode()
    assert sd.render_requirements([]) == b""


def test_render_requirements_refuses_hash_outside_set():
    with pytest.raises(ValueError):
        sd.render_requirements([(R("a", "1", 1), H(9))])


def test_render_roundtrips_through_parser():
    reqs = [R("a", "1.2.3", 1), R("b-c", "4.5", 2)]
    out = sd.render_requirements([(r, next(iter(r.hashes))) for r in reqs])
    assert sd.parse_requirements(out, "r") == reqs


# ------------------------------------------------------------------ json_depth_ok

def test_depth_limit_exact():
    at = b"[" * 64 + b"]" * 64
    over = b"[" * 65 + b"]" * 65
    assert sd.json_depth_ok(at, 64) is True
    assert sd.json_depth_ok(over, 64) is False
    assert sd.json_depth_ok(b"[" * 3 + b"]" * 3, 2) is False
    assert sd.json_depth_ok(b"[" * 2 + b"]" * 2, 2) is True


def test_depth_default_is_64():
    assert sd.json_depth_ok(b"{\"a\":" * 64 + b"1" + b"}" * 64) is True
    assert sd.json_depth_ok(b"{\"a\":" * 65 + b"1" + b"}" * 65) is False


def test_depth_ignores_brackets_in_strings():
    assert sd.json_depth_ok(b'{"a":"' + b"[" * 500 + b'"}', 4) is True


def test_depth_respects_escaped_quotes():
    # the string ends only at the unescaped quote; the [[[ after it are real nesting
    data = b'["a\\"' + b"[" * 10 + b'", ' + b"[" * 10 + b"1" + b"]" * 10 + b"]"
    assert sd.json_depth_ok(data, 11) is True
    assert sd.json_depth_ok(data, 10) is False


def test_depth_escaped_backslash_before_quote_ends_string():
    # "\\" is a complete string; the following [ is outside it
    data = b'["\\\\", ' + b"[" * 5 + b"]" * 5 + b"]"
    assert sd.json_depth_ok(data, 6) is True
    assert sd.json_depth_ok(data, 5) is False


def test_depth_counts_siblings_not_cumulative():
    assert sd.json_depth_ok(b"[" + b"[],[]," * 1000 + b"[]]", 2) is True


def test_depth_empty_and_scalar():
    assert sd.json_depth_ok(b"") is True
    assert sd.json_depth_ok(b"1") is True


# ------------------------------------------------------------------ package-lock

def lock(packages, version=3, **extra):
    doc = {"name": "x", "lockfileVersion": version, "packages": packages, **extra}
    return json.dumps(doc).encode()


def entry(version="1.0.0", pkg="a", **kw):
    e = {"version": version, "resolved": f"https://registry.npmjs.org/{pkg}/-/{pkg.rsplit('/', 1)[-1]}-{version}.tgz",
         "integrity": "sha512-abc"}
    e.update(kw)
    return e


ROOT = {"": {"name": "x", "version": "1.0.0"}}


def plock(packages, label="package-lock.json", **kw):
    return sd.parse_package_lock(lock(packages, **kw), label)


def test_lock_basic_v3_and_v2():
    pk = {**ROOT, "node_modules/a": entry("1.0.0", "a"), "node_modules/b": entry("2.3.4-beta.1+b5", "b")}
    exp = [("a", "1.0.0"), ("b", "2.3.4-beta.1+b5")]
    assert plock(pk, version=3) == exp
    assert plock(pk, version=2) == exp


def test_lock_ignores_dependencies_key_of_v2():
    pk = {**ROOT, "node_modules/a": entry("1.0.0", "a")}
    out = sd.parse_package_lock(lock(pk, version=2, dependencies={"zzz": {"version": "file:../x"}}), "l")
    assert out == [("a", "1.0.0")]


def test_lock_nested_uses_last_segment_and_dedupes():
    pk = {**ROOT, "node_modules/a": entry("1.0.0", "a"),
          "node_modules/x/node_modules/a": entry("1.0.0", "a"),
          "node_modules/y/node_modules/a": entry("1.1.0", "a")}
    assert plock(pk) == [("a", "1.0.0"), ("a", "1.1.0")]


def test_lock_scoped_package():
    key = "node_modules/@scope/name"
    e = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope/name/-/name-1.0.0.tgz"}
    assert plock({**ROOT, key: e}) == [("@scope/name", "1.0.0")]
    nested = {**ROOT, "node_modules/q/node_modules/@scope/name": e}
    assert plock(nested) == [("@scope/name", "1.0.0")]


def test_lock_scoped_package_encoded_slash_in_resolved():
    e = {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@scope%2fname/-/name-1.0.0.tgz"}
    assert plock({**ROOT, "node_modules/@scope/name": e}) == [("@scope/name", "1.0.0")]


def test_lock_sorted_output():
    pk = {**ROOT, "node_modules/z": entry("1.0.0", "z"), "node_modules/a": entry("1.0.0", "a")}
    assert [n for n, _ in plock(pk)] == ["a", "z"]


def test_lock_empty_packages_ok():
    assert plock(ROOT) == []


def test_lock_name_equal_to_segment_is_not_alias():
    pk = {**ROOT, "node_modules/a": entry("1.0.0", "a", name="a")}
    assert plock(pk) == [("a", "1.0.0")]


@pytest.mark.parametrize("what,pk", [
    ("link", {**ROOT, "node_modules/a": {"resolved": "packages/a", "link": True}}),
    ("link", {**ROOT, "node_modules/a": entry("1.0.0", "a", link=True)}),
    ("workspace", {**ROOT, "packages/a": entry("1.0.0", "a")}),
    ("workspace", {**ROOT, "node_modules/a": entry("1.0.0", "a"), "apps/web": {"version": "1.0.0"}}),
    ("..", {**ROOT, "node_modules/../evil": entry("1.0.0", "evil")}),
    ("..", {**ROOT, "node_modules/a/../b": entry("1.0.0", "b")}),
    ("..", {**ROOT, "../node_modules/a": entry("1.0.0", "a")}),
    ("key", {**ROOT, "node_modules/": entry("1.0.0", "a")}),
    ("key", {**ROOT, "node_modules//a": entry("1.0.0", "a")}),
    ("key", {**ROOT, "node_modules\\a": entry("1.0.0", "a")}),
    ("bundle", {**ROOT, "node_modules/a": entry("1.0.0", "a", bundleDependencies=["b"])}),
    ("bundle", {**ROOT, "node_modules/a": entry("1.0.0", "a", bundledDependencies=["b"])}),
    ("bundle", {"": {"name": "x", "bundleDependencies": ["a"]}, "node_modules/a": entry("1.0.0", "a")}),
    ("file:", {**ROOT, "node_modules/a": {"version": "file:../a", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}),
    ("version", {**ROOT, "node_modules/a": {"version": "git+https://x/y.git#abc", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}),
    ("version", {**ROOT, "node_modules/a": {"version": "https://x/y.tgz", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}),
    ("version", {**ROOT, "node_modules/a": entry("^1.0.0", "a")}),
    ("version", {**ROOT, "node_modules/a": entry("1.0", "a")}),
    ("version", {**ROOT, "node_modules/a": entry("01.0.0", "a")}),
    ("version", {**ROOT, "node_modules/a": entry("1.0.0-01", "a")}),
    ("version", {**ROOT, "node_modules/a": entry("v1.0.0", "a")}),
    ("version", {**ROOT, "node_modules/a": entry("1.0.0 ", "a")}),
    ("version", {**ROOT, "node_modules/a": {"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}),
    ("version", {**ROOT, "node_modules/a": entry(1, "a")}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0"}}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "https://evil.example/a/-/a-1.0.0.tgz"}}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "http://registry.npmjs.org/a/-/a-1.0.0.tgz"}}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/a.git"}}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org.evil.example/a/-/a-1.0.0.tgz"}}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz?x=1"}}),
    ("resolved", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": 5}}),
    ("alias", {**ROOT, "node_modules/a": entry("1.0.0", "a", name="real-pkg")}),
    ("alias", {**ROOT, "node_modules/a": {"version": "1.0.0", "name": "other", "resolved": "https://registry.npmjs.org/other/-/other-1.0.0.tgz"}}),
    ("alias", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/other/-/other-1.0.0.tgz"}}),
    ("alias", {**ROOT, "node_modules/@s/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@t/a/-/a-1.0.0.tgz"}}),
    ("alias", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@s/a/-/a-1.0.0.tgz"}}),
    ("alias", {**ROOT, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-2.0.0.tgz"}}),
    ("entry", {**ROOT, "node_modules/a": "1.0.0"}),
    ("entry", {"node_modules/a": entry("1.0.0", "a"), "": "root"}),
])
def test_lock_refusals(what, pk):
    refused(lambda: plock(pk, label="lk.json"), "lk.json", what)


@pytest.mark.parametrize("root,what", [
    ({"name": "x", "link": True}, "link"),
    ({"name": "x", "link": "true"}, "link"),
    ({"name": "x", "inBundle": True}, "bundle"),
])
def test_lock_root_entry_forbidden_constructs_refused(root, what):
    """Inspection round 1, A5: the root entry returned before the link check, so a lockfile with
    only a `link: true` root parsed as an empty inventory and the audit came back clean."""
    refused(lambda: plock({"": root}, label="root.json"), "root.json", what)
    refused(lambda: plock({"": root, "node_modules/a": entry("1.0.0", "a")}, label="root.json"), what)


def test_lock_semver_length_capped_like_node_semver():
    # node-semver refuses versions over MAX_LENGTH = 256; the cap also bounds the regex work
    at = "1.0.0-" + "a" * 250
    assert len(at) == 256
    assert plock({**ROOT, "node_modules/a": entry(at, "a")}) == [("a", at)]
    over = at + "b"
    refused(lambda: plock({**ROOT, "node_modules/a": entry(over, "a")}, label="sv.json"), "sv.json", "version", "256")


def test_lock_root_entry_link_false_still_ok():
    assert plock({"": {"name": "x", "link": False}, "node_modules/a": entry("1.0.0", "a")}) == [("a", "1.0.0")]


def test_lock_alias_by_name_and_by_resolved_message_names_both_identities():
    msg = refused(lambda: plock({**ROOT, "node_modules/a": entry("1.0.0", "a", name="real")}), "alias", "a", "real")
    assert "node_modules/a" in msg
    msg = refused(lambda: plock({**ROOT, "node_modules/a": {"version": "1.0.0",
                  "resolved": "https://registry.npmjs.org/other/-/other-1.0.0.tgz"}}), "alias", "other")
    assert "node_modules/a" in msg


def test_lock_version1_refused():
    refused(lambda: sd.parse_package_lock(json.dumps({"lockfileVersion": 1, "dependencies": {}}).encode(), "l"),
            "lockfileVersion")
    refused(lambda: plock(ROOT, version=1), "lockfileVersion")


@pytest.mark.parametrize("v", [0, 4, "3", None, 3.0, True, [3]])
def test_lock_bad_lockfile_version_refused(v):
    refused(lambda: sd.parse_package_lock(json.dumps({"lockfileVersion": v, "packages": ROOT}).encode(), "l"),
            "lockfileVersion")


def test_lock_missing_lockfile_version_or_packages_refused():
    refused(lambda: sd.parse_package_lock(b'{"packages":{}}', "l"), "lockfileVersion")
    refused(lambda: sd.parse_package_lock(b'{"lockfileVersion":3}', "l"), "packages")
    refused(lambda: sd.parse_package_lock(b'{"lockfileVersion":3,"packages":[]}', "l"), "packages")


@pytest.mark.parametrize("data", [b"", b"not json", b"[1]", b"null", b'{"lockfileVersion":3,"packages":{}',
                                  b'{"lockfileVersion":NaN}', b"\xff\xfe"])
def test_lock_malformed_refused(data):
    refused(lambda: sd.parse_package_lock(data, "bad.json"), "bad.json")


def test_lock_duplicate_keys_refused():
    data = (b'{"lockfileVersion":3,"packages":{"":{}},"packages":{"node_modules/a":'
            b'{"version":"1.0.0","resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}')
    refused(lambda: sd.parse_package_lock(data, "dup.json"), "duplicate")
    data = (b'{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0","version":"2.0.0",'
            b'"resolved":"https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}')
    refused(lambda: sd.parse_package_lock(data, "dup.json"), "duplicate")


def test_lock_depth_limit_refused_before_parsing():
    deep = b'{"lockfileVersion":3,"packages":{},"x":' + b"[" * 65 + b"]" * 65 + b"}"
    refused(lambda: sd.parse_package_lock(deep, "deep.json"), "deep.json", "nesting")
    ok = b'{"lockfileVersion":3,"packages":{},"x":' + b"[" * 60 + b"]" * 60 + b"}"
    assert sd.parse_package_lock(ok, "ok.json") == []


def test_lock_size_limit():
    big = b" " * (sd.MAX_LOCK_FILE + 1)
    refused(lambda: sd.parse_package_lock(big, "big.json"), "big.json", "16 MiB")


def test_lock_entry_limit():
    pk = {"": {}}
    for i in range(sd.MAX_NPM_ENTRIES):
        pk[f"node_modules/p{i}"] = entry("1.0.0", f"p{i}")
    assert len(sd.parse_package_lock(lock(pk), "l")) == sd.MAX_NPM_ENTRIES  # 10 001 keys incl. root: ok
    pk["node_modules/extra"] = entry("1.0.0", "extra")
    refused(lambda: sd.parse_package_lock(lock(pk), "l"), "10000")


def test_lock_messages_ascii_for_hostile_names():
    pk = {**ROOT, "node_modules/ä": entry("1.0.0", "a")}
    msg = refused(lambda: plock(pk, label="ü.json"), "key")
    assert msg.isascii()


# ------------------------------------------------------------------ module surface

def test_limits_constants():
    assert sd.MAX_REQ_FILE == 1024 * 1024
    assert sd.MAX_REQUIREMENTS == 500
    assert sd.MAX_LOCK_FILE == 16 * 1024 * 1024
    assert sd.MAX_NPM_ENTRIES == 10000
    assert sd.MAX_SEMVER_LENGTH == 256


def test_module_is_stdlib_only_and_pure():
    src = (Path(__file__).resolve().parents[1] / "scripts" / "sandbox_deps.py").read_text(encoding="utf-8")
    assert src.isascii()
    for banned in ("import subprocess", "import socket", "urllib.request", "import http", "import requests", "import packaging",
                   "open(", "os.environ"):
        assert banned not in src, banned
