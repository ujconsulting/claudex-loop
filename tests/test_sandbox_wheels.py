"""sandbox_wheels: wheel tags, file-name grammar and selection by pinned hash (plan B1.5, step 3).

Pure functions, so no fixtures beyond literals. Written before scripts/sandbox_wheels.py and seen
failing first. Every refusal case also asserts the shape of what is NOT returned.
"""
from __future__ import annotations

import sys
import time
import tracemalloc
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sandbox_wheels as sw  # noqa: E402

PLATFORMS = ["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64",
             "manylinux_2_5_x86_64", "manylinux1_x86_64", "any"]
TARGET = {"python": "3.13", "platforms": PLATFORMS}
H1 = "a" * 64
H2 = "b" * 64
H3 = "c" * 64
HOST = "https://files.pythonhosted.org/packages/ab/cd/"


def entry(filename, sha=H1, url=None, yanked=None):
    out = {"filename": filename, "url": HOST + filename if url is None else url,
           "hashes": {"sha256": sha}}
    if yanked is not None:
        out["yanked"] = yanked
    return out


def index(*files, api="1.1"):
    return {"meta": {"api-version": api}, "name": "demo", "files": list(files)}


class AcceptedTagsTests(unittest.TestCase):
    def setUp(self):
        self.tags = sw.accepted_tags(TARGET)

    def test_first_entries_follow_the_plan(self):
        self.assertEqual(self.tags[0], ("cp313", "cp313", "manylinux_2_28_x86_64"))
        self.assertEqual(self.tags[1], ("cp313", "cp313", "manylinux_2_17_x86_64"))
        self.assertEqual(self.tags[4], ("cp313", "cp313", "manylinux1_x86_64"))

    def test_abi3_series_in_order(self):
        first = "manylinux_2_28_x86_64"
        want = [("cp313", "abi3", first)] + [(f"cp3{x}", "abi3", first) for x in range(12, 1, -1)]
        got = [t for t in self.tags if t[1] == "abi3" and t[2] == first]
        self.assertEqual(got, want)
        self.assertIn(("cp32", "abi3", "manylinux1_x86_64"), self.tags)

    def test_group_order_and_py3_none_any_near_the_end(self):
        def pos(t):
            return self.tags.index(t)
        order = [("cp313", "cp313", "manylinux1_x86_64"), ("cp313", "abi3", "manylinux1_x86_64"),
                 ("cp32", "abi3", "manylinux1_x86_64"), ("cp313", "none", "manylinux1_x86_64"),
                 ("py313", "none", "manylinux1_x86_64"), ("py3", "none", "manylinux1_x86_64")]
        positions = [pos(t) for t in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(("py3", "none", "any"), self.tags)
        self.assertIn(("py30", "none", "any"), self.tags)
        self.assertEqual(self.tags[-1], ("py30", "none", "any"))
        self.assertLess(pos(("py3", "none", "any")), pos(("py312", "none", "any")))

    def test_any_only_with_abi_none_and_only_if_listed(self):
        self.assertNotIn(("cp313", "cp313", "any"), self.tags)
        self.assertNotIn(("cp313", "abi3", "any"), self.tags)
        no_any = sw.accepted_tags({"python": "3.13", "platforms": ["manylinux1_x86_64"]})
        self.assertFalse([t for t in no_any if t[2] == "any"])
        self.assertNotIn(("py3", "none", "any"), no_any)

    def test_no_duplicates(self):
        self.assertEqual(len(self.tags), len(set(self.tags)))

    def test_other_minor_is_computed(self):
        tags = sw.accepted_tags({"python": "3.11", "platforms": ["any"]})
        self.assertEqual(tags[0], ("cp311", "none", "any"))
        self.assertIn(("py311", "none", "any"), tags)
        self.assertNotIn(("py312", "none", "any"), tags)

    def test_malformed_targets(self):
        bad = [None, [], {}, {"python": "3.13"}, {"platforms": ["any"]},
               {"python": "3", "platforms": ["any"]}, {"python": "4.1", "platforms": ["any"]},
               {"python": "3.13", "platforms": []}, {"python": "3.13", "platforms": "any"},
               {"python": "3.13", "platforms": ["any", "any"]},
               {"python": "3.13", "platforms": ["a-b"]}, {"python": "3.13", "platforms": [""]},
               {"python": "3.13", "platforms": [1]}, {"python": 3.13, "platforms": ["any"]}]
        for target in bad:
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    sw.accepted_tags(target)


class ParseFilenameTests(unittest.TestCase):
    def test_simple(self):
        name, ver, build, tags = sw.parse_wheel_filename("Foo_Bar-1.2.3-py3-none-any.whl")
        self.assertEqual((name, ver, build), ("foo-bar", "1.2.3", None))
        self.assertEqual(tags, frozenset({("py3", "none", "any")}))

    def test_compressed_tags_expand(self):
        _, _, _, tags = sw.parse_wheel_filename("six-1.16.0-py2.py3-none-any.whl")
        self.assertEqual(tags, frozenset({("py2", "none", "any"), ("py3", "none", "any")}))
        _, _, _, tags = sw.parse_wheel_filename(
            "numpy-2.0.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl")
        self.assertEqual(tags, frozenset({("cp313", "cp313", "manylinux_2_17_x86_64"),
                                          ("cp313", "cp313", "manylinux2014_x86_64")}))

    def test_cross_product_of_all_three_fields(self):
        _, _, _, tags = sw.parse_wheel_filename("x-1-cp312.cp313-abi3.none-any.whl")
        self.assertEqual(len(tags), 4)

    def test_build_tag(self):
        name, ver, build, tags = sw.parse_wheel_filename("pkg-1.0-2-py3-none-any.whl")
        self.assertEqual((name, ver, build), ("pkg", "1.0", "2"))
        self.assertEqual(len(tags), 1)
        self.assertEqual(sw.parse_wheel_filename("pkg-1.0-1abc-py3-none-any.whl")[2], "1abc")

    def test_build_tag_must_start_with_digit(self):
        with self.assertRaises(sw.WheelRefused):
            sw.parse_wheel_filename("pkg-1.0-abc-py3-none-any.whl")

    def test_underscore_in_version_is_kept_verbatim(self):
        # The plan's canonical subset has no '_', so such a wheel never matches a requirement.
        self.assertEqual(sw.parse_wheel_filename("pkg-1_0-py3-none-any.whl")[1], "1_0")

    def test_refused_forms(self):
        bad = ["pkg-1.0-py3-none-any.tar.gz", "pkg-1.0.zip", "pkg-1.0-py3-none-any",
               "pkg-1.0-py3-none.whl", "pkg-1.0-py3-none-any-extra-more.whl",
               "pkg--py3-none-any.whl", "-1.0-py3-none-any.whl", "pkg-1.0--none-any.whl",
               "pkg-1.0-py3--any.whl", "pkg-1.0-py3-none-.whl", "pkg-1.0-py3.-none-any.whl",
               "pkg-1.0-py3-none-any.whl/", "a/b-1.0-py3-none-any.whl",
               "..\\b-1.0-py3-none-any.whl", "pkg-1.0-py3-none-any.WHL", "",
               ".whl", "pkäg-1.0-py3-none-any.whl", "pkg-1.0-py3-n one-any.whl",
               "pkg-1.0-py3-none-any.whl\n", "pkg-1.0-py3-no/ne-any.whl", "pkg-1.0-p y3-none-any.whl",
               "_pkg-1.0-py3-none-any.whl", "pkg-1.0-py3-none-any..whl"]
        for fn in bad:
            with self.subTest(fn=fn):
                with self.assertRaises(sw.WheelRefused):
                    sw.parse_wheel_filename(fn)

    def test_not_a_string(self):
        with self.assertRaises(sw.WheelRefused):
            sw.parse_wheel_filename(None)  # type: ignore[arg-type]


def _peak_bytes(fn):
    """Run fn() under tracemalloc; return (exception or None, peak bytes allocated meanwhile)."""
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        try:
            fn()
            err = None
        except Exception as exc:  # noqa: BLE001 - the caller asserts the type
            err = exc
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return err, peak


class ExpansionBoundTests(unittest.TestCase):
    """Gate A1-8 (HIGH): compressed tags are a Cartesian product an index entry controls. The
    parser must refuse oversized names and component counts BEFORE it expands anything."""

    REAL = (  # shapes of the widest compressed tag sets on PyPI: 2 python tags, 3 macOS
        # platforms, 4 manylinux aliases (psutil); none comes near the limits below
        "six-1.16.0-py2.py3-none-any.whl",
        "MarkupSafe-3.0.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "ruff-0.6.9-py3-none-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl",
        "orjson-3.10.7-cp313-cp313-macosx_10_15_x86_64.macosx_11_0_arm64.macosx_10_15_universal2.whl",
        "ninja-1.11.1.1-py2.py3-none-manylinux1_x86_64.manylinux_2_5_x86_64.whl",
        "cffi-1.15.1-cp310-cp310-manylinux_2_12_x86_64.manylinux2010_x86_64.whl",
        "numpy-1.21.6-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "pyzmq-26.2.0-pp310-pypy310_pp73-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        ("psutil-5.9.8-cp36-abi3-manylinux_2_12_x86_64.manylinux2010_x86_64.manylinux_2_17_x86_64"
         ".manylinux2014_x86_64.whl"),
    )

    def test_real_wheels_still_parse(self):
        for fn in self.REAL:
            with self.subTest(fn=fn):
                self.assertTrue(sw.parse_wheel_filename(fn)[3])

    def test_460_char_name_with_64000_triples_is_refused_without_expanding(self):
        field = ".".join(f"p{i}" for i in range(40))
        fn = f"x-1-{field}-{field}-{field}.whl"
        self.assertLess(len(fn), 470)
        err, peak = _peak_bytes(lambda: sw.parse_wheel_filename(fn))
        self.assertIsInstance(err, sw.WheelRefused)
        # 64000 tuples and a frozenset over them need several MiB; a refusal before expansion
        # allocates a few small strings.
        self.assertLess(peak, 256 * 1024)

    def test_near_8_mib_name_is_refused_promptly(self):
        half = (8 * 1024 * 1024 - 64) // 2
        fn = f"x-1-{'a' * half}.{'b' * half}-none-any.whl"
        self.assertGreater(len(fn), 8 * 1024 * 1024 - 100)
        start = time.perf_counter()
        err, peak = _peak_bytes(lambda: sw.parse_wheel_filename(fn))
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertIsInstance(err, sw.WheelRefused)
        self.assertLess(peak, 64 * 1024)  # not one copy of the name (8 MiB) was made
        self.assertLess(len(str(err)), 400)

    def test_name_length_limit_is_exact(self):
        stem = "-1-py3-none-any.whl"
        ok = "a" * (sw.MAX_WHEEL_FILENAME - len(stem)) + stem
        self.assertEqual(len(ok), sw.MAX_WHEEL_FILENAME)
        self.assertEqual(sw.parse_wheel_filename(ok)[3], frozenset({("py3", "none", "any")}))
        with self.assertRaises(sw.WheelRefused):
            sw.parse_wheel_filename("a" + ok)

    def test_component_limit_per_field_is_exact(self):
        n = sw.MAX_TAG_COMPONENTS
        ok = ".".join(f"t{i}" for i in range(n))
        self.assertEqual(len(sw.parse_wheel_filename(f"x-1-{ok}-none-any.whl")[3]), n)
        bad = ".".join(f"t{i}" for i in range(n + 1))
        for fn in (f"x-1-{bad}-none-any.whl", f"x-1-py3-{bad}-any.whl", f"x-1-py3-none-{bad}.whl"):
            with self.subTest(fn=fn), self.assertRaises(sw.WheelRefused):
                sw.parse_wheel_filename(fn)

    def test_product_limit_is_exact(self):
        # MAX_TAG_TRIPLES is reachable with two fields at the per-field limit; one more factor of
        # two in the third field goes over it.
        n = sw.MAX_TAG_COMPONENTS
        self.assertEqual(n * n, sw.MAX_TAG_TRIPLES)
        a = ".".join(f"a{i}" for i in range(n))
        b = ".".join(f"b{i}" for i in range(n))
        self.assertEqual(len(sw.parse_wheel_filename(f"x-1-{a}-{b}-any.whl")[3]), sw.MAX_TAG_TRIPLES)
        with self.assertRaises(sw.WheelRefused) as cm:
            sw.parse_wheel_filename(f"x-1-{a}-{b}-any.c.whl")
        self.assertIn(str(sw.MAX_TAG_TRIPLES), str(cm.exception))

    def test_select_wheel_skips_an_oversized_pinned_name(self):
        field = ".".join(f"p{i}" for i in range(40))
        bomb = entry(f"demo-1.0-{field}-{field}-{field}.whl", sha=H2)
        good = "demo-1.0-py3-none-any.whl"
        got = sw.select_wheel(index(bomb, entry(good, sha=H3)), "demo", "1.0",
                              frozenset({H2, H3}), TARGET)
        self.assertEqual(got["filename"], good)
        with self.assertRaises(sw.WheelRefused):
            sw.select_wheel(index(bomb), "demo", "1.0", frozenset({H2}), TARGET)


class CompatibilityTests(unittest.TestCase):
    def compatible(self, filename):
        tags = set(sw.accepted_tags(TARGET))
        return bool(sw.parse_wheel_filename(filename)[3] & tags)

    def test_accepted(self):
        for fn in ["a-1-py3-none-any.whl", "a-1-py2.py3-none-any.whl",
                   "a-1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                   "a-1-cp38-abi3-manylinux2014_x86_64.whl",
                   "a-1-cp313-cp313-manylinux_2_28_x86_64.whl",
                   "a-1-py39-none-any.whl", "a-1-cp313-none-any.whl",
                   "a-1-cp313-abi3-manylinux1_x86_64.whl"]:
            with self.subTest(fn=fn):
                self.assertTrue(self.compatible(fn))

    def test_rejected(self):
        for fn in ["a-1-cp313-cp313-musllinux_1_2_x86_64.whl", "a-1-cp313-cp313-win_amd64.whl",
                   "a-1-cp313-cp313-macosx_11_0_arm64.whl", "a-1-cp312-cp312-manylinux2014_x86_64.whl",
                   "a-1-cp313-cp313-manylinux2014_aarch64.whl", "a-1-py314-none-any.whl",
                   "a-1-cp314-abi3-manylinux2014_x86_64.whl", "a-1-cp313-cp313t-manylinux2014_x86_64.whl",
                   "a-1-cp313-cp313-manylinux_2_34_x86_64.whl", "a-1-py2-none-any.whl"]:
            with self.subTest(fn=fn):
                self.assertFalse(self.compatible(fn))


class SelectWheelTests(unittest.TestCase):
    def sel(self, idx, name="demo", version="1.0", hashes=frozenset({H1}), target=TARGET):
        return sw.select_wheel(idx, name, version, frozenset(hashes), target)

    def test_basic(self):
        got = self.sel(index(entry("demo-1.0-py3-none-any.whl")))
        self.assertEqual(got, {"filename": "demo-1.0-py3-none-any.whl",
                               "url": HOST + "demo-1.0-py3-none-any.whl", "sha256": H1})

    def test_name_normalised_on_both_sides(self):
        got = self.sel(index(entry("Demo_Pkg-1.0-py3-none-any.whl")), name="demo.pkg")
        self.assertEqual(got["filename"], "Demo_Pkg-1.0-py3-none-any.whl")

    def test_hash_not_in_set_refused(self):
        with self.assertRaises(sw.WheelRefused) as cm:
            self.sel(index(entry("demo-1.0-py3-none-any.whl", sha=H2)))
        self.assertIn("demo==1.0", str(cm.exception))

    def test_hash_comparison_is_exact_and_sha256_only(self):
        idx = index({"filename": "demo-1.0-py3-none-any.whl", "url": HOST + "d.whl",
                     "hashes": {"sha512": H1, "md5": H1}})
        with self.assertRaises(sw.WheelRefused):
            self.sel(idx)
        with self.assertRaises(sw.WheelRefused):
            self.sel(index(entry("demo-1.0-py3-none-any.whl", sha=H1.upper())))

    def test_sdist_only_refused(self):
        with self.assertRaises(sw.WheelRefused) as cm:
            self.sel(index(entry("demo-1.0.tar.gz")))
        self.assertIn("demo==1.0", str(cm.exception))

    def test_empty_files_refused(self):
        with self.assertRaises(sw.WheelRefused):
            self.sel(index())

    def test_wrong_version_in_filename(self):
        with self.assertRaises(sw.WheelRefused):
            self.sel(index(entry("demo-1.0.1-py3-none-any.whl")))
        with self.assertRaises(sw.WheelRefused):
            self.sel(index(entry("demo-1.0.0-py3-none-any.whl")))

    def test_wrong_name_in_filename(self):
        with self.assertRaises(sw.WheelRefused):
            self.sel(index(entry("other-1.0-py3-none-any.whl")))

    def test_incompatible_tag_refused(self):
        with self.assertRaises(sw.WheelRefused):
            self.sel(index(entry("demo-1.0-cp313-cp313-musllinux_1_2_x86_64.whl")))

    def test_unparsable_filename_is_skipped_not_fatal(self):
        got = self.sel(index(entry("demo-1.0-bogus.whl"), entry("demo-1.0-py3-none-any.whl")))
        self.assertEqual(got["filename"], "demo-1.0-py3-none-any.whl")

    def test_priority_beats_filename_order(self):
        compiled = "demo-1.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
        pure = "demo-1.0-py3-none-any.whl"
        got = self.sel(index(entry(pure), entry(compiled, sha=H2)), hashes={H1, H2})
        self.assertEqual(got["filename"], compiled)
        self.assertEqual(got["sha256"], H2)

    def test_best_triple_of_a_compressed_set_counts(self):
        a = "demo-1.0-cp313-cp313-manylinux_2_28_x86_64.manylinux1_x86_64.whl"
        b = "demo-1.0-cp313-cp313-manylinux_2_17_x86_64.whl"
        got = self.sel(index(entry(b, sha=H2), entry(a, sha=H3)), hashes={H2, H3})
        self.assertEqual(got["filename"], a)

    def test_tie_broken_by_filename(self):
        a = "demo-1.0-1-py3-none-any.whl"
        b = "demo-1.0-2-py3-none-any.whl"
        got = self.sel(index(entry(b, sha=H2), entry(a, sha=H3)), hashes={H2, H3})
        self.assertEqual(got["filename"], a)

    def test_equal_priority_tie_is_by_filename_whatever_the_yank_status(self):
        # Gate A1-1/A1-5: the interface breaks ties by file name only. Both files are pinned, so
        # both are artifacts the requirements file names; yank status does not reorder them.
        a = "demo-1.0-1-py3-none-any.whl"   # sorts first by name
        b = "demo-1.0-2-py3-none-any.whl"
        for ya, yb in ((True, None), ("broken", False), ("", None), (None, True), (True, True)):
            with self.subTest(yanked_a=ya, yanked_b=yb):
                got = self.sel(index(entry(b, sha=H3, yanked=yb), entry(a, sha=H2, yanked=ya)),
                               hashes={H2, H3})
                self.assertEqual(got["filename"], a)
                self.assertEqual(got["sha256"], H2)

    def test_yanked_pinned_file_alone_is_still_accepted(self):
        fn = "demo-1.0-py3-none-any.whl"
        self.assertEqual(self.sel(index(entry(fn, yanked=True)))["filename"], fn)

    def test_yanked_does_not_outrank_priority(self):
        compiled = "demo-1.0-cp313-cp313-manylinux_2_28_x86_64.whl"
        pure = "demo-1.0-py3-none-any.whl"
        got = self.sel(index(entry(compiled, sha=H2, yanked=True), entry(pure)), hashes={H1, H2})
        self.assertEqual(got["filename"], compiled)

    def test_api_version_major_must_be_1(self):
        for api in ("2.0", "0.9", "2"):
            with self.subTest(api=api):
                with self.assertRaises(sw.WheelRefused):
                    self.sel(index(entry("demo-1.0-py3-none-any.whl"), api=api))
        for api in ("1.0", "1.1", "1.7", "1"):
            with self.subTest(api=api):
                self.assertTrue(self.sel(index(entry("demo-1.0-py3-none-any.whl"), api=api)))

    def test_wrong_url_host_refused(self):
        bad = ["https://evil.example/demo-1.0-py3-none-any.whl",
               "http://files.pythonhosted.org/x/demo-1.0-py3-none-any.whl",
               "https://files.pythonhosted.org.evil.example/demo-1.0-py3-none-any.whl",
               "https://files.pythonhosted.org@evil.example/x.whl",
               "https://files.pythonhosted.org:443/x.whl",
               "//files.pythonhosted.org/x.whl", "files.pythonhosted.org/x.whl",
               "https://pypi.org/x.whl", "", "https://files.pythonhosted.org/x y.whl",
               "https://files.pythonhosted.org/\\x.whl"]
        for url in bad:
            with self.subTest(url=url):
                with self.assertRaises(sw.WheelRefused):
                    self.sel(index(entry("demo-1.0-py3-none-any.whl", url=url)))

    def test_bad_url_candidate_does_not_hide_a_good_one(self):
        good = "demo-1.0-1-py3-none-any.whl"
        bad = entry("demo-1.0-py3-none-any.whl", sha=H2, url="https://evil.example/x.whl")
        got = self.sel(index(bad, entry(good, sha=H3)), hashes={H2, H3})
        self.assertEqual(got["filename"], good)

    def test_malformed_index_is_value_error(self):
        ok = entry("demo-1.0-py3-none-any.whl")
        bad = [None, [], "x", {}, {"files": [ok]}, {"meta": {}, "files": [ok]},
               {"meta": [], "files": [ok]}, {"meta": {"api-version": 1.1}, "files": [ok]},
               {"meta": {"api-version": "x"}, "files": [ok]},
               {"meta": {"api-version": ""}, "files": [ok]},
               {"meta": {"api-version": "1.1"}}, {"meta": {"api-version": "1.1"}, "files": {}},
               {"meta": {"api-version": "1.1"}, "files": ["x"]},
               {"meta": {"api-version": "1.1"}, "files": [{"filename": "a.whl"}]},
               {"meta": {"api-version": "1.1"}, "files": [{**ok, "filename": 5}]},
               {"meta": {"api-version": "1.1"}, "files": [{**ok, "url": None}]},
               {"meta": {"api-version": "1.1"}, "files": [{**ok, "hashes": []}]},
               {"meta": {"api-version": "1.1"}, "files": [{**ok, "hashes": {"sha256": 5}}]}]
        for idx in bad:
            with self.subTest(idx=idx):
                with self.assertRaises(ValueError):
                    self.sel(idx)

    def test_bad_arguments_are_value_error(self):
        idx = index(entry("demo-1.0-py3-none-any.whl"))
        with self.assertRaises(ValueError):
            sw.select_wheel(idx, "", "1.0", frozenset({H1}), TARGET)
        with self.assertRaises(ValueError):
            sw.select_wheel(idx, "demo", "1.0", frozenset(), TARGET)
        with self.assertRaises(ValueError):
            sw.select_wheel(idx, "demo", "1.0", frozenset({H1}), {"python": "x"})

    def test_result_has_exactly_three_keys(self):
        got = self.sel(index(entry("demo-1.0-py3-none-any.whl")))
        self.assertEqual(set(got), {"filename", "url", "sha256"})

    def test_messages_are_ascii(self):
        with self.assertRaises(sw.WheelRefused) as cm:
            self.sel(index(entry("demo-1.0.tar.gz")), name="Démo")
        str(cm.exception).encode("ascii")


class ModuleHygieneTests(unittest.TestCase):
    def test_source_is_ascii_and_stdlib_only(self):
        src = (Path(sw.__file__)).read_bytes()
        src.decode("ascii")
        text = src.decode()
        self.assertNotIn("import packaging", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("urllib", text)


if __name__ == "__main__":
    unittest.main()
