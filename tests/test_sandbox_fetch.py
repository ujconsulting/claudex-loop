"""sandbox_fetch: network worker, supervision, quarantine (plan B1.5 steps 3 and 7, unit C).

WHY THIS FILE EXISTS. sandbox_fetch is the only code on the host that talks to the network on
behalf of a repository under review. Each promise of the plan is pinned here by a test that
fails when the promise is broken:

- HTTP rules: https only, an exact host allowlist per job kind, no userinfo, no port, any
  redirect refused, environment proxies ignored, a 30 s socket timeout, caps enforced WHILE
  reading (the read stops at cap + 1 and no oversized file is left), sha256 while streaming.
  The network is never touched: `sandbox_fetch._open` is replaced by a fake for every test,
  and a refused request asserts that the fake was never called.
- Error mapping: 404 on a PyPI index -> refused; 503, URLError, TLS errors, timeouts,
  malformed JSON -> infrastructure; WheelRefused -> refused.
- OSV: batches, one result per query, paging bound, repeated token, the detail cache, budgets.
- Supervision with REAL processes: the worker command line is replaced through the
  `_worker_argv` seam (no test-only job kind exists in production code): a sleeper is killed
  at the deadline, a SIGTERM-ignoring worker is killed and reaped, an unconfirmed death
  writes the quarantine record and leaves the directory in place, a record that cannot be
  written puts path/pid/status on stderr, KeyboardInterrupt kills and confirms, a bogus or
  missing result is infrastructure. A fault while closing the parent's copies of the output
  handles (KeyboardInterrupt, OSError) also kills and confirms (inspection A2), and
  FetchUnconfirmed.deadline_epoch equals the record's deadline (inspection A8).
- Quarantine listing never deletes, renames or follows a recorded path.
- verify_download trusts nothing the worker said.

Written before scripts/sandbox_fetch.py and seen failing first.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import itertools
import json
import os
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

# sandbox_wheels is built by a parallel unit; these tests never depend on its implementation.
# If the real module is missing, a stand-in with the two names the fetcher uses is inserted.
_REAL_WHEELS = (SCRIPTS / "sandbox_wheels.py").is_file()
if not _REAL_WHEELS and "sandbox_wheels" not in sys.modules:
    _fake = types.ModuleType("sandbox_wheels")

    class WheelRefused(Exception):
        pass

    def _select_wheel(*_a, **_k):
        raise AssertionError("tests must patch select_wheel")

    _fake.WheelRefused = WheelRefused
    _fake.select_wheel = _select_wheel
    sys.modules["sandbox_wheels"] = _fake

import sandbox_fetch as sf  # noqa: E402

MiB = 1024 * 1024
H1 = hashlib.sha256(b"wheel-one").hexdigest()
TARGET = {"python": "3.13", "platforms": ["manylinux_2_28_x86_64", "any"]}
INDEX_URL = "https://pypi.org/simple/demo/"
WHEEL_URL = "https://files.pythonhosted.org/packages/aa/bb/demo-1.0-py3-none-any.whl"
WHEEL_NAME = "demo-1.0-py3-none-any.whl"


# --- fakes -----------------------------------------------------------------------------------

class FakeResp:
    """Just enough of http.client.HTTPResponse: status, headers, read(n), geturl, close."""

    def __init__(self, body=b"", status=200, url=None, headers=None, endless=False):
        self._buf = io.BytesIO(body)
        self.status = status
        self.headers = headers or {}
        self._url = url
        self.endless = endless
        self.reads = []
        self.closed = False
        self.delivered = 0

    def read(self, n=-1):
        self.reads.append(n)
        if self.endless:
            assert n is not None and 0 < n <= sf.CHUNK, f"unbounded read({n})"
            self.delivered += n
            return b"x" * n
        data = self._buf.read(n)
        self.delivered += len(data)
        return data

    def geturl(self):
        return self._url

    def close(self):
        self.closed = True


class FakeNet:
    """Replaces sandbox_fetch._open. `routes` maps (method, url) -> response, exception, or
    a callable(request) returning one of those."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.calls = []

    def __call__(self, req, timeout):
        method = req.get_method()
        self.calls.append((method, req.full_url, req.data, timeout, dict(req.header_items())))
        key = (method, req.full_url)
        if key not in self.routes:
            raise AssertionError(f"unexpected request {key}")
        out = self.routes[key]
        if callable(out) and not isinstance(out, (FakeResp, BaseException)):
            out = out(req)
        if isinstance(out, BaseException):
            raise out
        if out._url is None:
            out._url = req.full_url
        return out


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "x", hdrs={}, fp=io.BytesIO(b""))


def index_json():
    return json.dumps({"meta": {"api-version": "1.1"}, "name": "demo",
                       "files": [{"filename": WHEEL_NAME, "url": WHEEL_URL,
                                  "hashes": {"sha256": H1}}]}).encode()


def select_ok(index, name, version, hashes, target):
    assert isinstance(index, dict) and name == "demo" and version == "1.0"
    assert H1 in hashes and target == TARGET
    return {"filename": WHEEL_NAME, "url": WHEEL_URL, "sha256": H1}


class TempMixin:
    def tmp(self) -> Path:
        d = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(d.cleanup)
        return Path(d.name).resolve()

    def net(self, routes=None) -> FakeNet:
        fake = FakeNet(routes)
        p = mock.patch.object(sf, "_open", fake)
        p.start()
        self.addCleanup(p.stop)
        return fake

    def wheels(self, select=select_ok):
        p = mock.patch.object(sf.sandbox_wheels, "select_wheel", select)
        p.start()
        self.addCleanup(p.stop)


def wheels_job(reqs=None, max_file=MiB, max_total=4 * MiB):
    return {"kind": "wheels", "requirements": reqs if reqs is not None else [["demo", "1.0", [H1]]],
            "target": TARGET, "max_file": max_file, "max_total": max_total}


# --- run ids ---------------------------------------------------------------------------------

class RunIdTests(unittest.TestCase):
    def test_new_run_id_matches_the_shared_pattern(self):
        for _ in range(50):
            self.assertIsNotNone(sf.RUN_ID_RE.fullmatch(sf.new_run_id()))

    def test_pattern_is_fullmatch_only(self):
        self.assertIsNone(sf.RUN_ID_RE.fullmatch("0123456789abcdef\n"))
        self.assertIsNone(sf.RUN_ID_RE.fullmatch("0123456789ABCDEF"))
        self.assertIsNone(sf.RUN_ID_RE.fullmatch("../../etc/passwd"))


# --- URL rules and opener --------------------------------------------------------------------

class UrlRuleTests(TempMixin, unittest.TestCase):
    def refused_before_open(self, url, hosts=sf.WHEEL_HOSTS):
        fake = self.net()
        with self.assertRaises(sf.FetchRefused):
            sf._request(url, hosts, 1024)
        self.assertEqual(fake.calls, [], "a refused URL must never reach the opener")

    def test_http_refused(self):
        self.refused_before_open("http://pypi.org/simple/demo/")

    def test_other_schemes_refused(self):
        for url in ("file:///etc/passwd", "ftp://pypi.org/x", "data:,x", "HTTPS://pypi.org/x"):
            self.refused_before_open(url)

    def test_wrong_host_refused(self):
        for url in ("https://evil.example/simple/demo/", "https://pypi.org.evil.example/x",
                    "https://PYPI.org/simple/demo/", "https://files.pythonhosted.org.evil/x"):
            self.refused_before_open(url)

    def test_host_of_the_other_kind_refused(self):
        self.refused_before_open("https://api.osv.dev/v1/querybatch", sf.WHEEL_HOSTS)
        self.refused_before_open("https://pypi.org/simple/demo/", sf.OSV_HOSTS)

    def test_userinfo_and_port_refused(self):
        for url in ("https://user@pypi.org/simple/demo/", "https://u:p@pypi.org/simple/demo/",
                    "https://pypi.org:443/simple/demo/", "https://pypi.org:8443/simple/demo/",
                    "https://pypi.org:/simple/demo/", "https://evil.example@pypi.org/x"):
            self.refused_before_open(url)

    def test_control_characters_and_spaces_refused(self):
        for url in ("https://pypi.org/simple/de mo/", "https://pypi.org/simple/demo/\r\nX: y",
                    "https://pypi.org/simple/d\x00/"):
            self.refused_before_open(url)

    def test_socket_timeout_is_30_seconds(self):
        fake = self.net({("GET", INDEX_URL): FakeResp(b"{}")})
        sf._request(INDEX_URL, sf.WHEEL_HOSTS, 1024)
        self.assertEqual(sf.SOCKET_TIMEOUT, 30)
        self.assertEqual(fake.calls[0][3], 30)

    def test_redirect_handler_raises(self):
        handler = sf._NoRedirect()
        req = urllib.request.Request(INDEX_URL)
        with self.assertRaises(sf.FetchRefused):
            handler.redirect_request(req, None, 302, "Found", {}, "https://pypi.org/elsewhere/")

    def test_redirected_final_url_refused(self):
        fake = self.net({("GET", INDEX_URL): FakeResp(b"{}", url="https://pypi.org/other/")})
        with self.assertRaises(sf.FetchRefused):
            sf._request(INDEX_URL, sf.WHEEL_HOSTS, 1024)
        self.assertEqual(len(fake.calls), 1)

    def test_opener_has_no_plain_http_no_file_no_proxy_no_cookies(self):
        opener = sf._build_opener()
        kinds = [type(h) for h in opener.handlers]
        for banned in (urllib.request.HTTPHandler, urllib.request.FileHandler,
                       urllib.request.FTPHandler, urllib.request.DataHandler,
                       urllib.request.HTTPCookieProcessor, urllib.request.UnknownHandler):
            self.assertNotIn(banned, kinds)
        self.assertNotIn(urllib.request.HTTPRedirectHandler, kinds)
        self.assertIn(sf._NoRedirect, kinds)
        # ProxyHandler({}) has no <scheme>_open method, so OpenerDirector keeps no proxy
        # handler at all: nothing in the opener can route through a proxy.
        proxies = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual([h.proxies for h in proxies if h.proxies], [])
        https = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual(len(https), 1)
        ctx = https[0]._context
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_environment_proxy_is_ignored(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy":
                                          "http://127.0.0.1:9"}):
            opener = sf._build_opener()
        proxies = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual([h.proxies for h in proxies if h.proxies], [])
        self.assertFalse(any(hasattr(h, "https_open") and isinstance(h, urllib.request.ProxyHandler)
                             for h in opener.handlers))

    def test_non_200_success_is_infrastructure(self):
        self.net({("GET", INDEX_URL): FakeResp(b"", status=204)})
        with self.assertRaises(sf.FetchInfrastructure):
            sf._request(INDEX_URL, sf.WHEEL_HOSTS, 1024)


class BoundedReadTests(TempMixin, unittest.TestCase):
    def test_cap_hit_while_streaming_stops_at_cap_plus_one(self):
        resp = FakeResp(endless=True)
        self.net({("GET", INDEX_URL): resp})
        with self.assertRaises(sf.FetchRefused):
            sf._request(INDEX_URL, sf.WHEEL_HOSTS, 100_000)
        self.assertLessEqual(resp.delivered, 100_001, "the read must stop at cap + 1")
        self.assertTrue(all(0 < n <= sf.CHUNK for n in resp.reads))
        self.assertTrue(resp.closed)

    def test_content_length_over_cap_refused_before_reading(self):
        resp = FakeResp(b"x" * 10, headers={"Content-Length": "999999999"})
        self.net({("GET", INDEX_URL): resp})
        with self.assertRaises(sf.FetchRefused):
            sf._request(INDEX_URL, sf.WHEEL_HOSTS, 1024)
        self.assertEqual(resp.reads, [])

    def test_exactly_cap_is_accepted(self):
        self.net({("GET", INDEX_URL): FakeResp(b"y" * 1000)})
        self.assertEqual(sf._request(INDEX_URL, sf.WHEEL_HOSTS, 1000), b"y" * 1000)

    def test_read_timeout_is_infrastructure(self):
        class Slow(FakeResp):
            def read(self, n=-1):
                raise TimeoutError("timed out")
        self.net({("GET", INDEX_URL): Slow()})
        with self.assertRaises(sf.FetchInfrastructure):
            sf._request(INDEX_URL, sf.WHEEL_HOSTS, 1024)


class ErrorMappingTests(TempMixin, unittest.TestCase):
    def run_index(self, exc):
        self.net({("GET", INDEX_URL): exc})
        self.wheels()
        return sf._job_wheels(wheels_job(), self.tmp())

    def test_404_on_the_index_is_refused(self):
        with self.assertRaises(sf.FetchRefused) as cm:
            self.run_index(http_error(INDEX_URL, 404))
        self.assertIn("404", str(cm.exception))

    def test_503_is_infrastructure(self):
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            self.run_index(http_error(INDEX_URL, 503))
        self.assertNotIsInstance(cm.exception, sf.FetchRefused)

    def test_other_errors_are_infrastructure(self):
        for exc in (urllib.error.URLError("dns"), ssl.SSLError("bad cert"),
                    TimeoutError("timed out"), ConnectionResetError("reset"),
                    http_error(INDEX_URL, 403), http_error(INDEX_URL, 500)):
            with self.subTest(exc=exc), self.assertRaises(sf.FetchInfrastructure):
                self.run_index(exc)

    def test_404_on_a_download_is_infrastructure(self):
        self.net({("GET", INDEX_URL): FakeResp(index_json()),
                  ("GET", WHEEL_URL): http_error(WHEEL_URL, 404)})
        self.wheels()
        with self.assertRaises(sf.FetchInfrastructure):
            sf._job_wheels(wheels_job(), self.tmp())

    def test_malformed_index_json_is_infrastructure(self):
        for body in (b"<html>", b"[1, 2", b"\xff\xfe", b"[]", b"[" * 100000):
            with self.subTest(body=body[:10]), self.assertRaises(sf.FetchInfrastructure):
                self.run_index(FakeResp(body))

    def test_wheel_refused_is_refused(self):
        def refuse(*_a):
            raise sf.sandbox_wheels.WheelRefused("no wheel for the image's platform")
        fake = self.net({("GET", INDEX_URL): FakeResp(index_json())})
        self.wheels(refuse)
        d = self.tmp()
        with self.assertRaises(sf.FetchRefused):
            sf._job_wheels(wheels_job(), d)
        self.assertEqual([c[1] for c in fake.calls], [INDEX_URL], "no download after a refusal")
        self.assertEqual(os.listdir(d), [])

    def test_value_error_from_select_is_infrastructure(self):
        def bad(*_a):
            raise ValueError("malformed target")
        self.net({("GET", INDEX_URL): FakeResp(index_json())})
        self.wheels(bad)
        with self.assertRaises(sf.FetchInfrastructure):
            sf._job_wheels(wheels_job(), self.tmp())


# --- wheels job ------------------------------------------------------------------------------

class WheelsJobTests(TempMixin, unittest.TestCase):
    def test_happy_path_downloads_and_hashes(self):
        fake = self.net({("GET", INDEX_URL): FakeResp(index_json()),
                         ("GET", WHEEL_URL): FakeResp(b"wheel-one")})
        self.wheels()
        d = self.tmp()
        out = sf._job_wheels(wheels_job(), d)
        self.assertEqual(out, {"ok": True, "files": [["demo", "1.0", WHEEL_NAME, H1, 9]]})
        self.assertEqual((d / WHEEL_NAME).read_bytes(), b"wheel-one")
        self.assertEqual(fake.calls[0][4].get("Accept"), "application/vnd.pypi.simple.v1+json")

    def test_hash_mismatch_refused_and_no_file_left(self):
        self.net({("GET", INDEX_URL): FakeResp(index_json()),
                  ("GET", WHEEL_URL): FakeResp(b"something else")})
        self.wheels()
        d = self.tmp()
        with self.assertRaises(sf.FetchRefused) as cm:
            sf._job_wheels(wheels_job(), d)
        self.assertIn("sha256", str(cm.exception))
        self.assertEqual(os.listdir(d), [])

    def test_per_file_cap_hit_while_streaming_leaves_no_oversized_file(self):
        resp = FakeResp(endless=True)
        self.net({("GET", INDEX_URL): FakeResp(index_json()), ("GET", WHEEL_URL): resp})
        self.wheels()
        d = self.tmp()
        with self.assertRaises(sf.FetchRefused):
            sf._job_wheels(wheels_job(max_file=200_000), d)
        self.assertLessEqual(resp.delivered, 200_001)
        self.assertEqual(os.listdir(d), [], "the partial file is removed")

    def test_total_cap_counts_across_files(self):
        h2 = hashlib.sha256(b"B" * 600).hexdigest()
        url2 = "https://files.pythonhosted.org/packages/cc/two-1.0-py3-none-any.whl"
        ha = hashlib.sha256(b"A" * 600).hexdigest()
        url1 = "https://files.pythonhosted.org/packages/cc/one-1.0-py3-none-any.whl"

        def select(index, name, version, hashes, target):
            return {"one": {"filename": "one-1.0-py3-none-any.whl", "url": url1, "sha256": ha},
                    "two": {"filename": "two-1.0-py3-none-any.whl", "url": url2, "sha256": h2}}[name]
        second = FakeResp(b"B" * 600)
        self.net({("GET", "https://pypi.org/simple/one/"): FakeResp(b"{}"),
                  ("GET", "https://pypi.org/simple/two/"): FakeResp(b"{}"),
                  ("GET", url1): FakeResp(b"A" * 600), ("GET", url2): second})
        self.wheels(select)
        d = self.tmp()
        with self.assertRaises(sf.FetchRefused):
            sf._job_wheels(wheels_job([["one", "1.0", [ha]], ["two", "1.0", [h2]]],
                                      max_file=1000, max_total=1000), d)
        self.assertLessEqual(second.delivered, 401)
        self.assertEqual(os.listdir(d), ["one-1.0-py3-none-any.whl"])

    def test_selection_with_a_hash_outside_the_set_refused(self):
        def select(*_a):
            return {"filename": WHEEL_NAME, "url": WHEEL_URL, "sha256": "0" * 64}
        fake = self.net({("GET", INDEX_URL): FakeResp(index_json())})
        self.wheels(select)
        with self.assertRaises(sf.FetchRefused):
            sf._job_wheels(wheels_job(), self.tmp())
        self.assertEqual(len(fake.calls), 1)

    def test_unsafe_selected_filename_refused(self):
        for name in ("../x.whl", "job.json", "worker-result.json", "a/b.whl", "x.zip", "c:x.whl"):
            def select(*_a, _n=name):
                return {"filename": _n, "url": WHEEL_URL, "sha256": H1}
            fake = self.net({("GET", INDEX_URL): FakeResp(index_json())})
            self.wheels(select)
            d = self.tmp()
            with self.subTest(name=name), self.assertRaises(sf.FetchRefused):
                sf._job_wheels(wheels_job(), d)
            self.assertEqual(len(fake.calls), 1)
            self.assertEqual(os.listdir(d), [])

    def test_selected_url_on_a_foreign_host_refused_before_open(self):
        def select(*_a):
            return {"filename": WHEEL_NAME, "url": "https://evil.example/demo.whl", "sha256": H1}
        fake = self.net({("GET", INDEX_URL): FakeResp(index_json())})
        self.wheels(select)
        with self.assertRaises(sf.FetchRefused):
            sf._job_wheels(wheels_job(), self.tmp())
        self.assertEqual(len(fake.calls), 1)

    def test_selected_url_on_pypi_org_refused(self):
        def select(*_a):
            return {"filename": WHEEL_NAME, "url": "https://pypi.org/demo.whl", "sha256": H1}
        fake = self.net({("GET", INDEX_URL): FakeResp(index_json())})
        self.wheels(select)
        with self.assertRaises(sf.FetchRefused):
            sf._job_wheels(wheels_job(), self.tmp())
        self.assertEqual(len(fake.calls), 1)

    def test_worker_accepts_the_parsers_whole_domain(self):
        # Gate A1-2: the worker once refused names > 200 and versions > 100 characters that
        # sandbox_deps.parse_requirements accepts. Whatever the parser emits, the worker takes.
        import sandbox_deps
        long_name = "a" * 201
        long_version = "1." * 60 + "0"  # 121 characters, canonical
        line = f"{long_name}=={long_version} --hash=sha256:{H1}\n".encode()
        (req,) = sandbox_deps.parse_requirements(line, "requirements.txt")
        self.assertEqual((req.name, req.version), (long_name, long_version))
        out = sf._wheel_reqs(wheels_job([[req.name, req.version, sorted(req.hashes)]]))
        self.assertEqual(out, [(long_name, long_version, frozenset({H1}))])
        for name, version in (("a-b-c", "1.0rc1.post2.dev3"), ("x" * 500, "0"),
                              ("demo", "1" + ".0" * 200)):
            with self.subTest(name=name[:20], version=version[:20]):
                self.assertEqual(sf._wheel_reqs(wheels_job([[name, version, [H1]]]))[0][:2],
                                 (name, version))

    def test_worker_refuses_what_the_parser_never_emits(self):
        for name, version in (("Demo", "1.0"), ("a_b", "1.0"), ("a--b", "1.0"), ("-a", "1.0"),
                              ("demo", "1..0"), ("demo", "01.0"), ("demo", "1.0.x"),
                              ("demo", ""), ("", "1.0")):
            with self.subTest(name=name, version=version), self.assertRaises(sf.FetchRefused):
                sf._wheel_reqs(wheels_job([[name, version, [H1]]]))

    def test_malformed_job_refused_before_any_request(self):
        fake = self.net()
        self.wheels()
        for job in (wheels_job([["Demo_X", "1.0", [H1]]]), wheels_job([["demo", "1.0", []]]),
                    wheels_job([["demo", "1.0", ["ABC"]]]), wheels_job([["demo/../x", "1.0", [H1]]]),
                    wheels_job(max_file=0), wheels_job(max_total=True), {"kind": "wheels"}):
            with self.subTest(job=job), self.assertRaises((sf.FetchRefused, sf.FetchInfrastructure)):
                sf._job_wheels(job, self.tmp())
        self.assertEqual(fake.calls, [])


# --- OSV job ---------------------------------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def osv_vuln_url(vid):
    return f"https://api.osv.dev/v1/vulns/{vid}"


class OsvServer:
    """A fake OSV: `pages[(name, token)]` -> (ids, next_token)."""

    def __init__(self, pages=None, details=None, count_delta=0, extra=None):
        self.pages = pages or {}
        self.details = details or {}
        self.count_delta = count_delta
        self.extra = extra or {}
        self.batches = []
        self.detail_calls = []

    def batch(self, req):
        body = json.loads(req.data)
        self.batches.append(body)
        results = []
        for q in body["queries"]:
            ids, token = self.pages.get((q["package"]["name"], q.get("page_token")), ([], None))
            r = {}
            if ids:
                r["vulns"] = [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]
            if token:
                r["next_page_token"] = token
            r.update(self.extra)
            results.append(r)
        if self.count_delta < 0:
            results = results[:self.count_delta]
        elif self.count_delta > 0:
            results += [{}] * self.count_delta
        return FakeResp(json.dumps({"results": results}).encode())

    def routes(self):
        out = {("POST", OSV_BATCH_URL): self.batch}
        for vid in self.details:
            def detail(req, _v=vid):
                self.detail_calls.append(_v)
                return FakeResp(json.dumps(self.details[_v]).encode())
            out[("GET", osv_vuln_url(vid))] = detail
        return out


def osv_job(queries, **budgets):
    return {"kind": "osv", "queries": queries, **budgets}


class OsvTests(TempMixin, unittest.TestCase):
    def test_results_in_order_and_details_fetched_once(self):
        srv = OsvServer(pages={("a", None): (["GHSA-1", "PYSEC-2"], None),
                               ("b", None): (["GHSA-1"], None)},
                        details={"GHSA-1": {"id": "GHSA-1", "summary": "s1"},
                                 "PYSEC-2": {"id": "PYSEC-2"}})
        self.net(srv.routes())
        out = sf._job_osv(osv_job([["PyPI", "a", "1.0"], ["PyPI", "b", "2.0"], ["npm", "c", "3.0.0"]]))
        self.assertEqual(out["results"], [["GHSA-1", "PYSEC-2"], ["GHSA-1"], []])
        self.assertEqual(sorted(out["details"]), ["GHSA-1", "PYSEC-2"])
        self.assertEqual(sorted(srv.detail_calls), ["GHSA-1", "PYSEC-2"], "each id exactly once")
        self.assertEqual(srv.batches[0]["queries"][0],
                         {"package": {"name": "a", "ecosystem": "PyPI"}, "version": "1.0"})

    def test_batches_of_at_most_1000(self):
        srv = OsvServer()
        self.net(srv.routes())
        out = sf._job_osv(osv_job([["PyPI", f"p{i}", "1"] for i in range(2500)]))
        self.assertEqual([len(b["queries"]) for b in srv.batches], [1000, 1000, 500])
        self.assertEqual(len(out["results"]), 2500)

    def test_result_count_mismatch_is_incomplete(self):
        for delta in (-1, 1):
            srv = OsvServer(count_delta=delta)
            self.net(srv.routes())
            with self.subTest(delta=delta), self.assertRaises(sf.FetchInfrastructure) as cm:
                sf._job_osv(osv_job([["PyPI", "a", "1"], ["PyPI", "b", "1"]]))
            self.assertTrue(str(cm.exception).startswith("incomplete:"))

    def test_errored_result_is_incomplete(self):
        srv = OsvServer(extra={"error": "boom"})
        self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            sf._job_osv(osv_job([["PyPI", "a", "1"]]))
        self.assertIn("incomplete", str(cm.exception))

    def test_paging_is_followed_with_the_single_query(self):
        srv = OsvServer(pages={("a", None): (["V-1"], "t1"), ("a", "t1"): (["V-2"], None)},
                        details={"V-1": {"id": "V-1"}, "V-2": {"id": "V-2"}})
        self.net(srv.routes())
        out = sf._job_osv(osv_job([["PyPI", "a", "1"], ["PyPI", "b", "1"]]))
        self.assertEqual(out["results"], [["V-1", "V-2"], []])
        self.assertEqual(srv.batches[1], {"queries": [{"package": {"name": "a", "ecosystem": "PyPI"},
                                                       "version": "1", "page_token": "t1"}]})

    def test_ten_pages_allowed_token_after_tenth_incomplete(self):
        pages = {("a", None): ([], "t1")}
        for i in range(1, 9):
            pages[("a", f"t{i}")] = ([], f"t{i + 1}")
        pages[("a", "t9")] = ([], None)  # page 10 ends cleanly
        srv = OsvServer(pages=pages)
        self.net(srv.routes())
        sf._job_osv(osv_job([["PyPI", "a", "1"]]))
        self.assertEqual(len(srv.batches), 10)

        pages[("a", "t9")] = ([], "t10")  # still a token after page 10
        srv = OsvServer(pages=pages)
        self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            sf._job_osv(osv_job([["PyPI", "a", "1"]]))
        self.assertTrue(str(cm.exception).startswith("incomplete:"))
        self.assertEqual(len(srv.batches), 10, "never more than 10 pages")

    def test_repeated_token_is_incomplete(self):
        srv = OsvServer(pages={("a", None): ([], "t1"), ("a", "t1"): ([], "t1")})
        self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            sf._job_osv(osv_job([["PyPI", "a", "1"]]))
        self.assertIn("repeated", str(cm.exception))
        self.assertEqual(len(srv.batches), 2)

    def test_invalid_vuln_id_is_incomplete_and_never_requested(self):
        srv = OsvServer(pages={("a", None): (["../../x"], None)})
        fake = self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure):
            sf._job_osv(osv_job([["PyPI", "a", "1"]]))
        self.assertTrue(all("vulns" not in c[1] for c in fake.calls))

    def test_detail_id_mismatch_is_incomplete(self):
        srv = OsvServer(pages={("a", None): (["V-1"], None)}, details={"V-1": {"id": "V-9"}})
        self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure):
            sf._job_osv(osv_job([["PyPI", "a", "1"]]))

    def test_detail_over_one_mib_is_incomplete(self):
        srv = OsvServer(pages={("a", None): (["V-1"], None)})
        big = FakeResp(endless=True)
        routes = srv.routes()
        routes[("GET", osv_vuln_url("V-1"))] = big
        self.net(routes)
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            sf._job_osv(osv_job([["PyPI", "a", "1"]]))
        self.assertIn("incomplete", str(cm.exception))
        self.assertLessEqual(big.delivered, MiB + 1)

    def test_query_budget_refused_before_any_request(self):
        fake = self.net()
        with self.assertRaises(sf.FetchRefused):
            sf._job_osv(osv_job([["PyPI", f"p{i}", "1"] for i in range(sf.OSV_MAX_QUERIES + 1)]))
        self.assertEqual(fake.calls, [])
        with self.assertRaises(sf.FetchRefused):
            sf._job_osv(osv_job([["PyPI", "a", "1"], ["PyPI", "b", "1"]], max_queries=1))
        self.assertEqual(fake.calls, [])

    def test_budgets_cannot_be_raised_by_the_job(self):
        fake = self.net()
        for key in ("max_queries", "max_details", "max_total_bytes"):
            with self.subTest(key=key), self.assertRaises(sf.FetchRefused):
                sf._job_osv(osv_job([["PyPI", "a", "1"]], **{key: 10 ** 12}))
        self.assertEqual(fake.calls, [])

    def test_detail_budget_is_incomplete(self):
        ids = [f"V-{i}" for i in range(3)]
        srv = OsvServer(pages={("a", None): (ids, None)}, details={i: {"id": i} for i in ids})
        self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            sf._job_osv(osv_job([["PyPI", "a", "1"]], max_details=2))
        self.assertTrue(str(cm.exception).startswith("incomplete:"))
        self.assertEqual(srv.detail_calls, [], "budget checked before any detail request")

    def test_total_response_byte_budget_is_incomplete(self):
        srv = OsvServer(pages={("a", None): (["V-1"], None)}, details={"V-1": {"id": "V-1", "x": "y" * 500}})
        self.net(srv.routes())
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            sf._job_osv(osv_job([["PyPI", "a", "1"]], max_total_bytes=300))
        self.assertTrue(str(cm.exception).startswith("incomplete:"))

    def test_malformed_osv_json_is_infrastructure(self):
        for body in (b"nope", b"[]", b'{"results": {}}', b'{"results": [{"vulns": {}}]}',
                     b'{"results": [{"vulns": [{"id": 5}]}]}'):
            self.net({("POST", OSV_BATCH_URL): FakeResp(body)})
            with self.subTest(body=body), self.assertRaises(sf.FetchInfrastructure):
                sf._job_osv(osv_job([["PyPI", "a", "1"]]))

    def test_malformed_queries_refused(self):
        fake = self.net()
        for q in ([["Cargo", "a", "1"]], [["PyPI", "", "1"]], [["PyPI", "a"]], [["PyPI", "a\n", "1"]]):
            with self.subTest(q=q), self.assertRaises(sf.FetchRefused):
                sf._job_osv(osv_job(q))
        self.assertEqual(fake.calls, [])


# --- worker entry (in process) ----------------------------------------------------------------

class WorkerMainTests(TempMixin, unittest.TestCase):
    def run_worker(self, job):
        d = self.tmp()
        (d / "job.json").write_text(json.dumps(job), encoding="utf-8")
        rc = sf.worker_main(d / "job.json")
        return rc, json.loads((d / "worker-result.json").read_text(encoding="ascii")), d

    def test_ok_result(self):
        self.net({("GET", INDEX_URL): FakeResp(index_json()), ("GET", WHEEL_URL): FakeResp(b"wheel-one")})
        self.wheels()
        rc, res, _ = self.run_worker(wheels_job())
        self.assertEqual(rc, 0)
        self.assertEqual(res, {"ok": True, "files": [["demo", "1.0", WHEEL_NAME, H1, 9]]})

    def test_refused_and_infrastructure_results(self):
        self.net({("GET", INDEX_URL): http_error(INDEX_URL, 404)})
        self.wheels()
        _, res, _ = self.run_worker(wheels_job())
        self.assertEqual((res["ok"], res["kind"]), (False, "refused"))
        self.net({("GET", INDEX_URL): http_error(INDEX_URL, 503)})
        _, res, _ = self.run_worker(wheels_job())
        self.assertEqual((res["ok"], res["kind"]), (False, "infrastructure"))

    def test_unknown_kind_is_infrastructure(self):
        _, res, _ = self.run_worker({"kind": "shell"})
        self.assertEqual((res["ok"], res["kind"]), (False, "infrastructure"))

    def test_reason_is_ascii(self):
        def refuse(*_a):
            raise sf.sandbox_wheels.WheelRefused("no wheel for démo")
        self.net({("GET", INDEX_URL): FakeResp(index_json())})
        self.wheels(refuse)
        _, res, d = self.run_worker(wheels_job())
        (d / "worker-result.json").read_bytes().decode("ascii")
        self.assertTrue(res["reason"].isascii())

    def test_worker_starts_no_process(self):
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no process")), \
                mock.patch.object(os, "system", side_effect=AssertionError("no process")):
            _, res, _ = self.run_worker({"kind": "osv", "queries": []})
        self.assertEqual(res, {"ok": True, "results": [], "details": {}})


# --- supervision with real processes ---------------------------------------------------------

def script_argv(code: str):
    """A replacement for _worker_argv: runs `code` with the job path in sys.argv[1]."""
    def argv(job_path):
        return [sys.executable, "-I", "-c", textwrap.dedent(code), str(job_path)]
    return argv


SLEEPER = "import time\ntime.sleep(120)\n"
IGNORES_TERM = """
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(120)
"""


class SupervisionTests(TempMixin, unittest.TestCase):
    def setUp(self):
        self.procs = []
        real = subprocess.Popen

        def capture(*a, **k):
            p = real(*a, **k)
            self.procs.append(p)
            return p
        patcher = mock.patch.object(sf.subprocess, "Popen", side_effect=capture)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.scratch = self.tmp()
        self.addCleanup(self._reap_all)  # LIFO: runs BEFORE the temp dir is removed
        self.job_dir = self.scratch / "deps"
        self.job_dir.mkdir()

    def _reap_all(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait(10)

    def argv(self, code):
        p = mock.patch.object(sf, "_worker_argv", script_argv(code))
        p.start()
        self.addCleanup(p.stop)

    def job(self, deadline=30.0):
        return sf.run_job({"kind": "osv", "queries": []}, self.job_dir, deadline,
                          self.scratch, sf.new_run_id())

    def test_deadline_kills_a_sleeping_worker(self):
        self.argv(SLEEPER)
        t0 = time.monotonic()
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            self.job(deadline=1.0)
        self.assertNotIsInstance(cm.exception, sf.FetchUnconfirmed)
        self.assertLess(time.monotonic() - t0, 15)
        self.assertIsNotNone(self.procs[0].poll(), "the worker is dead and reaped")
        self.assertFalse((self.scratch / "claudex-quarantine").exists())

    def test_worker_ignoring_sigterm_is_killed(self):
        self.argv(IGNORES_TERM)
        with self.assertRaises(sf.FetchInfrastructure):
            self.job(deadline=1.5)
        self.assertIsNotNone(self.procs[0].poll())

    def test_production_argv_is_isolated(self):
        argv = sf._worker_argv(Path("j.json"))
        self.assertEqual(argv[:3], [sys.executable, "-I", "-S"])
        self.assertEqual(Path(argv[3]), Path(sf.__file__).resolve())
        self.assertEqual(argv[4:], ["--worker", "j.json"])

    def test_popen_contract(self):
        self.argv("import sys\nsys.exit(0)\n")
        with self.assertRaises(sf.FetchInfrastructure):
            self.job()
        _, kwargs = sf.subprocess.Popen.call_args
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(Path(kwargs["cwd"]), self.job_dir)
        if os.name != "nt":
            self.assertTrue(kwargs.get("start_new_session"))
        self.assertEqual(sorted(os.listdir(self.job_dir)),
                         ["job.json", "worker-stderr.txt", "worker-stdout.txt"])

    def test_missing_result_is_infrastructure(self):
        self.argv("import sys\nsys.exit(0)\n")
        with self.assertRaises(sf.FetchInfrastructure) as cm:
            self.job()
        self.assertIn("result", str(cm.exception))

    def test_bogus_results_are_infrastructure(self):
        for body in ("not json", "[]", '{"ok": false, "kind": "other", "reason": "x"}',
                     '{"ok": "yes"}', '{"ok": false, "kind": "refused"}'):
            d = self.scratch / f"d{abs(hash(body))}"
            d.mkdir()
            code = f"import sys, pathlib\npathlib.Path(sys.argv[1]).with_name('worker-result.json').write_text({body!r})\n"
            self.argv(code)
            with self.subTest(body=body), self.assertRaises(sf.FetchInfrastructure) as cm:
                sf.run_job({"kind": "osv", "queries": []}, d, 30, self.scratch, sf.new_run_id())
            self.assertNotIsInstance(cm.exception, sf.FetchRefused)

    def test_symlinked_result_is_infrastructure(self):
        target = self.scratch / "elsewhere.json"
        target.write_text('{"ok": true}')
        code = (f"import sys, os, pathlib\nos.symlink({str(target)!r}, "
                "str(pathlib.Path(sys.argv[1]).with_name('worker-result.json')))\n")
        self.argv(code)
        try:
            os.symlink(target, self.scratch / "probe-link")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(sf.FetchInfrastructure):
            self.job()

    def test_error_results_are_mapped(self):
        for kind, exc in (("refused", sf.FetchRefused), ("infrastructure", sf.FetchInfrastructure)):
            d = self.scratch / f"m-{kind}"
            d.mkdir()
            body = json.dumps({"ok": False, "kind": kind, "reason": "because"})
            self.argv(f"import sys, pathlib\npathlib.Path(sys.argv[1]).with_name('worker-result.json').write_text({body!r})\n")
            with self.subTest(kind=kind), self.assertRaises(exc) as cm:
                sf.run_job({"kind": "osv", "queries": []}, d, 30, self.scratch, sf.new_run_id())
            self.assertIn("because", str(cm.exception))
            if kind == "infrastructure":
                self.assertNotIsInstance(cm.exception, sf.FetchRefused)

    def test_nonzero_exit_is_infrastructure_even_with_ok_result(self):
        body = json.dumps({"ok": True, "results": [], "details": {}})
        self.argv(f"import sys, pathlib\npathlib.Path(sys.argv[1]).with_name('worker-result.json').write_text({body!r})\nsys.exit(3)\n")
        with self.assertRaises(sf.FetchInfrastructure):
            self.job()

    def test_ok_result_is_returned(self):
        body = json.dumps({"ok": True, "results": [], "details": {}})
        self.argv(f"import sys, pathlib\npathlib.Path(sys.argv[1]).with_name('worker-result.json').write_text({body!r})\n")
        self.assertEqual(self.job(), {"ok": True, "results": [], "details": {}})

    def test_unconfirmed_death_writes_quarantine_record(self):
        self.argv(SLEEPER)
        run_id = sf.new_run_id()
        with mock.patch.object(sf, "_confirm_dead", return_value=False), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, run_id)
        exc = cm.exception
        self.assertIsInstance(exc, sf.FetchInfrastructure)
        self.assertEqual(exc.pid, self.procs[0].pid)
        self.assertEqual(Path(exc.path), self.job_dir)
        rec = json.loads((self.scratch / "claudex-quarantine" / f"{run_id}.json").read_text())
        self.assertEqual(rec["pid"], self.procs[0].pid)
        self.assertEqual(Path(rec["path"]), self.job_dir)
        self.assertEqual(rec["cleanup"], "unconfirmed")
        self.assertIn("deadline_epoch", rec)
        self.assertTrue(self.job_dir.is_dir(), "the directory is left in place")

    def _assert_error_counts_as_unconfirmed(self, target, error):
        # Gate A1-3/A1-7: an exception from the kill/confirm path is an unconfirmed death:
        # quarantine record, FetchUnconfirmed (chaining the original), directory left in place.
        self.argv(SLEEPER)
        run_id = sf.new_run_id()
        with mock.patch.object(sf, target, side_effect=error), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, run_id)
        exc = cm.exception
        rec_path = self.scratch / "claudex-quarantine" / f"{run_id}.json"
        self.assertTrue(rec_path.is_file(), "the quarantine record was written")
        rec = json.loads(rec_path.read_text())
        self.assertEqual(rec["cleanup"], "unconfirmed")
        self.assertEqual(rec["pid"], self.procs[0].pid)
        self.assertEqual(Path(rec["path"]), self.job_dir)
        self.assertIsInstance(exc.deadline_epoch, float)
        self.assertEqual(exc.deadline_epoch, rec["deadline_epoch"])
        self.assertEqual(exc.record, rec_path)
        self.assertIs(exc.__cause__, error, "the original error is chained")
        self.assertTrue(self.job_dir.is_dir(), "the directory is left in place")
        self.assertIn("job.json", os.listdir(self.job_dir))
        self.assertIn("QUARANTINE", err.getvalue())

    def test_oserror_at_confirmation_quarantines(self):
        self._assert_error_counts_as_unconfirmed("_confirm_dead", OSError(5, "confirm failed"))

    def test_any_exception_at_confirmation_quarantines(self):
        self._assert_error_counts_as_unconfirmed("_confirm_dead", RuntimeError("defect"))

    def test_oserror_at_kill_quarantines(self):
        self._assert_error_counts_as_unconfirmed("_kill", OSError(1, "kill failed"))

    # Gate recheck 1, block A1, finding 9: a diagnostic write that fails (a full redirected
    # log: OSError; a closed stream: ValueError) must neither skip the quarantine record nor
    # let a raw error escape in place of FetchUnconfirmed -- the caller's cleanup keys on it.
    def _broken_stderr(self, kind):
        if kind == "closed":
            s = io.StringIO()
            s.close()
            return s
        s = mock.Mock()
        s.write.side_effect = OSError(28, "No space left on device")
        return s

    def test_confirmation_error_with_failing_stderr_still_quarantines(self):
        for kind in ("oserror", "closed"):
            with self.subTest(stderr=kind):
                d = self.scratch / f"deps-{kind}"
                d.mkdir()
                self.argv(SLEEPER)
                run_id = sf.new_run_id()
                error = OSError(5, "confirm failed")
                real_record = sf.write_quarantine_record
                calls = []

                def record(*a, _calls=calls, _real=real_record, **k):
                    _calls.append(a)
                    return _real(*a, **k)
                with mock.patch.object(sf, "_confirm_dead", side_effect=error), \
                        mock.patch.object(sf, "write_quarantine_record", side_effect=record), \
                        mock.patch.object(sf.sys, "stderr", self._broken_stderr(kind)), \
                        self.assertRaises(sf.FetchUnconfirmed) as cm:
                    sf.run_job({"kind": "osv", "queries": []}, d, 1.0, self.scratch, run_id)
                self.assertEqual(len(calls), 1, "the quarantine record was attempted")
                rec_path = self.scratch / "claudex-quarantine" / f"{run_id}.json"
                self.assertTrue(rec_path.is_file())
                self.assertEqual(cm.exception.record, rec_path,
                                 "a written record is reported even when its log line fails")
                self.assertIs(cm.exception.__cause__, error)
                self.assertTrue(d.is_dir())

    def test_record_failure_with_failing_stderr_still_raises_unconfirmed(self):
        # Every write on the unconfirmed path fails AND the record cannot be written.
        self.argv(SLEEPER)
        (self.scratch / "claudex-quarantine").write_text("a file, not a directory")
        with mock.patch.object(sf, "_confirm_dead", return_value=False), \
                mock.patch.object(sf.sys, "stderr", self._broken_stderr("oserror")), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            self.job(deadline=1.0)
        self.assertIsNone(cm.exception.record)
        self.assertTrue(self.job_dir.is_dir())

    def test_terminate_unit_failing_stderr(self):
        # In memory, no process: the confirmation raises, every stderr write raises.
        proc = mock.Mock(pid=4242, returncode=None)
        error = RuntimeError("defect")
        with mock.patch.object(sf, "_kill"), \
                mock.patch.object(sf, "_confirm_dead", side_effect=error), \
                mock.patch.object(sf, "write_quarantine_record",
                                  return_value=Path("rec.json")) as rec, \
                mock.patch.object(sf.sys, "stderr", self._broken_stderr("oserror")), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            sf._terminate(proc, self.job_dir, self.scratch, sf.new_run_id(), 1.0)
        rec.assert_called_once()
        self.assertEqual(cm.exception.record, Path("rec.json"))
        self.assertIs(cm.exception.__cause__, error)

    def _fetch_deps_state(self):
        import sandbox_run
        state = sandbox_run._Run()
        state.scratch = self.scratch
        state.open_run_dir()
        reqs = [types.SimpleNamespace(name="demo", version="1.0", hashes={H1})]
        cfg = {"wheel_target": TARGET, "max_file": MiB, "max_bytes": MiB}
        return sandbox_run, state, reqs, cfg

    def test_fetch_deps_keeps_the_directory_when_the_fetch_log_fails(self):
        # Through the caller: sandbox_run.fetch_deps must not remove the job directory after an
        # unconfirmed termination whose diagnostics failed. Only sandbox_fetch's lines fail
        # here, so the caller's own handling is observed unchanged.
        sandbox_run, state, reqs, cfg = self._fetch_deps_state()
        self.argv(SLEEPER)
        real_stderr = sys.stderr

        class FetchLogFails:
            def write(self, s):
                if not s.startswith("sandbox_run:"):
                    raise OSError(28, "No space left on device")
                return real_stderr.write(s)

            def flush(self):
                pass
        rmtree_calls = []
        real_rmtree = shutil.rmtree
        with mock.patch.object(sandbox_run, "FETCH_DEADLINE", 1.0), \
                mock.patch.object(sf, "_confirm_dead", side_effect=OSError(5, "confirm failed")), \
                mock.patch.object(sandbox_run.shutil, "rmtree",
                                  side_effect=lambda p, *a, **k: (rmtree_calls.append(p),
                                                                  real_rmtree(p, *a, **k))), \
                mock.patch.object(sys, "stderr", FetchLogFails()), \
                self.assertRaises(sandbox_run.Infrastructure):
            sandbox_run.fetch_deps(state, reqs, cfg)
        job_dir = state.run_dir / "deps"
        self.assertEqual(rmtree_calls, [], "no directory removal after an unconfirmed death")
        self.assertTrue(job_dir.is_dir())
        self.assertEqual(state.fields["cleanup"], "unconfirmed")
        self.assertIsNotNone(state.fields["quarantine"]["record"])

    def test_live_child_with_cwd_in_the_directory_no_rename(self):
        # The kill is suppressed, so a REAL live process keeps its cwd in job_dir (on Windows
        # that blocks a rename). The runner records and raises; it attempts no rename.
        self.argv(SLEEPER)
        run_id = sf.new_run_id()
        with mock.patch.object(sf, "_kill", lambda proc: None), \
                mock.patch.object(sf, "KILL_WAIT", 0.5), \
                mock.patch.object(os, "rename", side_effect=AssertionError("rename")), \
                mock.patch.object(os, "replace", side_effect=AssertionError("replace")), \
                mock.patch.object(shutil, "rmtree", side_effect=AssertionError("rmtree")), \
                mock.patch.object(shutil, "move", side_effect=AssertionError("move")), \
                self.assertRaises(sf.FetchUnconfirmed):
            sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, run_id)
        self.assertIsNone(self.procs[0].poll(), "the child really is still alive")
        self.assertTrue((self.scratch / "claudex-quarantine" / f"{run_id}.json").is_file())
        self.assertTrue(self.job_dir.is_dir())

    def test_record_that_cannot_be_written_goes_to_stderr(self):
        self.argv(SLEEPER)
        (self.scratch / "claudex-quarantine").write_text("a file, not a directory")
        err = io.StringIO()
        with mock.patch.object(sf, "_confirm_dead", return_value=False), \
                contextlib.redirect_stderr(err), self.assertRaises(sf.FetchUnconfirmed) as cm:
            self.job(deadline=1.0)
        line = err.getvalue()
        self.assertIn(str(self.procs[0].pid), line)
        self.assertIn("unconfirmed", line)
        self.assertIn("deps", line)
        self.assertTrue(line.isascii())
        self.assertIsNone(cm.exception.record)

    def test_keyboard_interrupt_kills_confirms_and_reraises(self):
        self.argv(SLEEPER)
        with mock.patch.object(sf, "_wait_deadline", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            self.job()
        self.assertIsNotNone(self.procs[0].poll(), "killed and reaped before re-raising")
        self.assertFalse((self.scratch / "claudex-quarantine").exists())

    def test_keyboard_interrupt_unconfirmed_quarantines(self):
        self.argv(SLEEPER)
        with mock.patch.object(sf, "_wait_deadline", side_effect=KeyboardInterrupt), \
                mock.patch.object(sf, "_confirm_dead", return_value=False), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            try:
                self.job()
            except KeyboardInterrupt:  # an escaping interrupt would stop the whole pytest run
                self.fail("unconfirmed death must surface as FetchUnconfirmed, not the interrupt")
        self.assertIsInstance(cm.exception.__context__, KeyboardInterrupt)
        self.assertEqual(len(os.listdir(self.scratch / "claudex-quarantine")), 1)
        rec = json.loads(next((self.scratch / "claudex-quarantine").iterdir()).read_text())
        self.assertEqual(cm.exception.deadline_epoch, rec["deadline_epoch"])

    # --- A2: every exit path after Popen returned kills and confirms (handle closes included)

    def _faulty_handle(self, stack, name, exc):
        """Make run_job's own copy of the worker's stdout/stderr file raise `exc` on its first
        close(); the real file is closed by the test's cleanup."""
        real_open_new = sf.hunt_io.open_new

        class CloseFault:
            def __init__(self, fh):
                self._fh, self._exc = fh, exc

            def fileno(self):
                return self._fh.fileno()

            def close(self):
                pending, self._exc = self._exc, None
                if pending is not None:
                    raise pending
                self._fh.close()

        def open_new(parent, fname, base=None):
            fh = real_open_new(parent, fname, base=base)
            if fname != name:
                return fh
            self.addCleanup(fh.close)
            return CloseFault(fh)
        stack.enter_context(mock.patch.object(sf.hunt_io, "open_new", open_new))

    def _spies(self, stack, confirmed=True):
        kill = stack.enter_context(mock.patch.object(sf, "_kill", wraps=sf._kill))
        confirm = stack.enter_context(
            mock.patch.object(sf, "_confirm_dead", wraps=sf._confirm_dead) if confirmed
            else mock.patch.object(sf, "_confirm_dead", return_value=False))
        return kill, confirm

    def test_close_fault_after_start_kills_and_confirms(self):
        self.argv(SLEEPER)
        for name, exc, expect in ((sf.STDOUT_NAME, KeyboardInterrupt(), KeyboardInterrupt),
                                  (sf.STDERR_NAME, KeyboardInterrupt(), KeyboardInterrupt),
                                  (sf.STDOUT_NAME, OSError("close failed"), sf.FetchInfrastructure),
                                  (sf.STDERR_NAME, OSError("close failed"), sf.FetchInfrastructure)):
            with self.subTest(handle=name, fault=type(exc).__name__), contextlib.ExitStack() as st:
                self.job_dir = self.scratch / f"close-{name}-{type(exc).__name__}"
                self.job_dir.mkdir()
                self._faulty_handle(st, name, exc)
                kill, confirm = self._spies(st)
                before = len(self.procs)
                try:
                    with self.assertRaises(expect) as cm:
                        self.job()
                except KeyboardInterrupt:  # never let a probe interrupt stop the pytest run
                    self.fail("the wrong exception escaped")
                self.assertNotIsInstance(cm.exception, sf.FetchUnconfirmed)
                self.assertEqual(len(self.procs), before + 1, "the worker was started")
                proc = self.procs[-1]
                kill.assert_called_once_with(proc)
                self.assertTrue(confirm.called, "the kill was confirmed")
                self.assertIsNotNone(proc.poll(), "killed and reaped before the exception left")
                self.assertFalse((self.scratch / "claudex-quarantine").exists())

    def test_close_fault_unconfirmed_death_quarantines(self):
        self.argv(SLEEPER)
        for name, exc in ((sf.STDOUT_NAME, KeyboardInterrupt()), (sf.STDERR_NAME, OSError("x"))):
            with self.subTest(handle=name, fault=type(exc).__name__), contextlib.ExitStack() as st:
                self.job_dir = self.scratch / f"q-{name}-{type(exc).__name__}"
                self.job_dir.mkdir()
                self._faulty_handle(st, name, exc)
                kill, _ = self._spies(st, confirmed=False)
                run_id = sf.new_run_id()
                try:
                    with self.assertRaises(sf.FetchUnconfirmed) as cm:
                        sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 30.0,
                                   self.scratch, run_id)
                except KeyboardInterrupt:
                    self.fail("unconfirmed death must surface as FetchUnconfirmed")
                proc = self.procs[-1]
                kill.assert_called_once_with(proc)
                self.assertEqual(cm.exception.pid, proc.pid)
                self.assertEqual(Path(cm.exception.path), self.job_dir)
                rec_path = self.scratch / "claudex-quarantine" / f"{run_id}.json"
                self.assertEqual(Path(cm.exception.record), rec_path)
                rec = json.loads(rec_path.read_text())
                self.assertEqual(rec["pid"], proc.pid)
                self.assertEqual(cm.exception.deadline_epoch, rec["deadline_epoch"])
                self.assertTrue(self.job_dir.is_dir(), "the directory is left in place")

    def test_both_handles_closed_even_when_the_first_close_fails(self):
        closed = []
        real_open_new = sf.hunt_io.open_new

        def open_new(parent, fname, base=None):
            fh = real_open_new(parent, fname, base=base)
            orig = fh.close

            def close():
                closed.append(fname)
                orig()
                if fname == sf.STDOUT_NAME:
                    raise OSError("close failed")
            fh.close = close
            return fh
        self.argv(SLEEPER)
        with mock.patch.object(sf.hunt_io, "open_new", open_new), \
                self.assertRaises(sf.FetchInfrastructure):
            self.job()
        self.assertEqual(sorted(closed), sorted([sf.STDOUT_NAME, sf.STDERR_NAME]))
        self.assertIsNotNone(self.procs[0].poll())

    def test_interrupt_while_reading_the_result_after_exit(self):
        # The worker exited and was reaped: nothing to kill, the interrupt propagates.
        body = json.dumps({"ok": True, "results": [], "details": {}})
        self.argv(f"import sys, pathlib\npathlib.Path(sys.argv[1]).with_name('worker-result.json').write_text({body!r})\n")
        with mock.patch.object(sf, "_read_result", side_effect=KeyboardInterrupt), \
                mock.patch.object(sf, "_kill", side_effect=AssertionError("kill after reap")), \
                self.assertRaises(KeyboardInterrupt):
            try:
                self.job()
            except AssertionError as exc:
                self.fail(str(exc))
        self.assertIsNotNone(self.procs[0].poll())

    # --- a second interrupt during kill/confirm never skips confirmation or quarantine

    def test_interrupt_inside_confirm_still_confirms(self):
        self.argv(SLEEPER)
        real = sf._confirm_dead
        answers = []

        def confirm(proc, timeout):
            if not answers:
                answers.append("interrupted")
                raise KeyboardInterrupt
            ok = real(proc, timeout)
            answers.append(ok)
            return ok
        with mock.patch.object(sf, "_confirm_dead", side_effect=confirm), \
                self.assertRaises(KeyboardInterrupt):
            try:
                self.job(deadline=1.0)
            except sf.FetchUnconfirmed:
                self.fail("the worker was confirmed dead; no quarantine expected")
        self.assertEqual(answers, ["interrupted", True], "confirmation completed before the "
                                                          "interrupt propagated")
        self.assertIsNotNone(self.procs[0].poll())
        self.assertFalse((self.scratch / "claudex-quarantine").exists())

    def test_interrupt_on_every_confirm_quarantines(self):
        self.argv(SLEEPER)
        run_id = sf.new_run_id()
        with mock.patch.object(sf, "_confirm_dead", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            try:
                sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, run_id)
            except KeyboardInterrupt:
                self.fail("an unconfirmed worker must surface as FetchUnconfirmed")
        rec_path = self.scratch / "claudex-quarantine" / f"{run_id}.json"
        self.assertTrue(rec_path.is_file(), "the quarantine record was written")
        self.assertEqual(cm.exception.deadline_epoch,
                         json.loads(rec_path.read_text())["deadline_epoch"])

    @unittest.skipUnless(hasattr(signal, "raise_signal"), "signal.raise_signal unavailable")
    def test_real_sigint_during_confirm_is_deferred(self):
        self.argv(SLEEPER)
        real = sf._confirm_dead
        answers = []
        before = signal.getsignal(signal.SIGINT)

        def confirm(proc, timeout):
            signal.raise_signal(signal.SIGINT)  # a real Ctrl+C while the kill is confirmed
            ok = real(proc, timeout)
            answers.append(ok)
            return ok
        with mock.patch.object(sf, "_confirm_dead", side_effect=confirm), \
                self.assertRaises(KeyboardInterrupt):
            self.job(deadline=1.0)
        self.assertEqual(answers, [True], "the SIGINT waited until the kill was confirmed")
        self.assertIsNotNone(self.procs[0].poll())
        self.assertIs(signal.getsignal(signal.SIGINT), before, "previous handler restored")

    def test_terminate_off_the_main_thread_installs_no_handler(self):
        self.argv(SLEEPER)
        errors, before = [], signal.getsignal(signal.SIGINT)

        def run():
            try:
                self.job(deadline=1.0)
            except sf.FetchInfrastructure:
                pass
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
        t = threading.Thread(target=run)
        t.start()
        t.join(30)
        self.assertEqual(errors, [])
        self.assertIsNotNone(self.procs[0].poll())
        self.assertIs(signal.getsignal(signal.SIGINT), before)

    # --- A8: one deadline, the same float in the record and on the exception

    def test_unconfirmed_deadline_equals_the_record(self):
        self.argv(SLEEPER)
        run_id = sf.new_run_id()
        t0 = time.time()
        with mock.patch.object(sf, "_confirm_dead", return_value=False), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, run_id)
        rec = json.loads((self.scratch / "claudex-quarantine" / f"{run_id}.json").read_text())
        self.assertIsInstance(cm.exception.deadline_epoch, float)
        self.assertEqual(cm.exception.deadline_epoch, rec["deadline_epoch"])
        self.assertGreaterEqual(rec["deadline_epoch"], t0 + 1.0)
        self.assertLess(rec["deadline_epoch"], t0 + 10.0)

    def test_deadline_is_computed_once(self):
        self.argv(SLEEPER)
        run_id = sf.new_run_id()
        clock = itertools.count(1000.0)  # every reading differs: a second reading would show
        with mock.patch.object(sf, "time", types.SimpleNamespace(time=lambda: next(clock))), \
                mock.patch.object(sf, "_confirm_dead", return_value=False), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, run_id)
        rec = json.loads((self.scratch / "claudex-quarantine" / f"{run_id}.json").read_text())
        self.assertEqual(rec["deadline_epoch"], 1001.0, "the first clock reading plus deadline_s")
        self.assertEqual(cm.exception.deadline_epoch, 1001.0)

    def test_record_failure_still_carries_the_deadline(self):
        self.argv(SLEEPER)
        (self.scratch / "claudex-quarantine").write_text("a file, not a directory")
        with mock.patch.object(sf, "_confirm_dead", return_value=False), \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(sf.FetchUnconfirmed) as cm:
            self.job(deadline=1.0)
        self.assertIsNone(cm.exception.record)
        self.assertIsInstance(cm.exception.deadline_epoch, float)

    def test_invalid_run_id_refused_before_start(self):
        self.argv(SLEEPER)
        with self.assertRaises(ValueError):
            sf.run_job({"kind": "osv", "queries": []}, self.job_dir, 1.0, self.scratch, "../x")
        self.assertEqual(self.procs, [])


@unittest.skipUnless(_REAL_WHEELS, "the real worker imports sandbox_wheels, not built yet")
class RealWorkerTests(TempMixin, unittest.TestCase):
    """The production command line, end to end, without network (empty job lists)."""

    def test_real_worker_empty_jobs(self):
        scratch = self.tmp()
        for job, expect in (({"kind": "osv", "queries": []}, {"ok": True, "results": [], "details": {}}),
                            (wheels_job([]), {"ok": True, "files": []})):
            d = scratch / job["kind"]
            d.mkdir()
            self.assertEqual(sf.run_job(job, d, 60, scratch, sf.new_run_id()), expect)

    def test_real_worker_unknown_kind_is_rejected_by_the_parent(self):
        scratch = self.tmp()
        d = scratch / "x"
        d.mkdir()
        with self.assertRaises(ValueError):
            sf.run_job({"kind": "shell"}, d, 60, scratch, sf.new_run_id())
        self.assertEqual(os.listdir(d), [])


# --- quarantine listing ----------------------------------------------------------------------

class QuarantineTests(TempMixin, unittest.TestCase):
    def no_destruction(self):
        stack = contextlib.ExitStack()
        for target, name in ((os, "remove"), (os, "unlink"), (os, "rmdir"), (os, "rename"),
                             (os, "replace"), (os, "removedirs"), (shutil, "rmtree"), (shutil, "move"),
                             (sf.hunt_io, "remove_file"), (sf.hunt_io, "rename_entry")):
            stack.enter_context(mock.patch.object(target, name, side_effect=AssertionError(name)))
        self.addCleanup(stack.close)
        return stack

    def test_record_written_by_the_real_generator_lists(self):
        scratch = self.tmp()
        run_id = sf.new_run_id()
        rec = sf.write_quarantine_record(scratch, run_id, scratch / "deps", 4242, 1700000000.0)
        self.assertEqual(rec, scratch / "claudex-quarantine" / f"{run_id}.json")
        lines = sf.list_quarantine(scratch)
        self.assertEqual(len(lines), 1)
        self.assertIn(run_id, lines[0])
        self.assertIn("4242", lines[0])
        self.assertIn("remove by hand after checking that pid 4242 is gone", lines[0])

    def test_record_is_never_overwritten(self):
        scratch = self.tmp()
        run_id = sf.new_run_id()
        sf.write_quarantine_record(scratch, run_id, scratch / "a", 1, 1.0)
        with self.assertRaises(sf.hunt_io.HuntIOError):
            sf.write_quarantine_record(scratch, run_id, scratch / "b", 2, 1.0)
        self.assertIn('"pid": 1', (scratch / "claudex-quarantine" / f"{run_id}.json").read_text())

    def test_write_refuses_invalid_run_id(self):
        scratch = self.tmp()
        for bad in ("../x", "0123456789ABCDEF", "abc", "0123456789abcdef.json"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sf.write_quarantine_record(scratch, bad, scratch, 1, 1.0)
        self.assertFalse((scratch / "claudex-quarantine").exists())

    def test_no_directory_lists_nothing(self):
        self.assertEqual(sf.list_quarantine(self.tmp()), [])

    def test_forged_record_is_listed_as_data_and_nothing_is_touched(self):
        scratch = self.tmp()
        victim = self.tmp()
        (victim / "sentinel.txt").write_text("keep me")
        (victim / "sub").mkdir()
        (victim / "sub" / "deep.txt").write_text("keep me too")
        qdir = scratch / "claudex-quarantine"
        qdir.mkdir()
        forged = {"run_id": "0123456789abcdef", "path": str(victim), "pid": 999999,
                  "deadline_epoch": 1.0, "cleanup": "unconfirmed\nrm -rf /"}
        (qdir / "0123456789abcdef.json").write_text(json.dumps(forged))
        before = sorted(p.relative_to(victim).as_posix() for p in victim.rglob("*"))
        self.no_destruction()
        with mock.patch.object(os, "listdir", wraps=os.listdir) as ld, \
                mock.patch.object(os, "scandir", wraps=os.scandir) as sd:
            lines = sf.list_quarantine(scratch)
        for call in ld.call_args_list + sd.call_args_list:
            self.assertNotEqual(Path(call.args[0]).resolve(), victim, "recorded path is never opened")
        self.assertEqual(len(lines), 1)
        self.assertIn("999999", lines[0])
        self.assertNotIn("\n", lines[0], "fields are escaped, a newline cannot start a new line")
        self.assertTrue(lines[0].isascii())
        after = sorted(p.relative_to(victim).as_posix() for p in victim.rglob("*"))
        self.assertEqual(before, after)
        self.assertEqual((victim / "sentinel.txt").read_text(), "keep me")
        self.assertTrue((qdir / "0123456789abcdef.json").is_file(), "the record itself stays")

    def test_invalid_run_id_names_are_unreadable(self):
        scratch = self.tmp()
        qdir = scratch / "claudex-quarantine"
        qdir.mkdir()
        for name in ("notanid.json", "0123456789ABCDEF.json", "0123456789abcdef.txt", "xé.json"):
            (qdir / name).write_text("{}")
        self.no_destruction()
        lines = sf.list_quarantine(scratch)
        self.assertEqual(len(lines), 4)
        self.assertTrue(all(line.startswith("unreadable record ") for line in lines))
        self.assertTrue(all(line.isascii() for line in lines))

    def test_malformed_record_is_unreadable(self):
        scratch = self.tmp()
        qdir = scratch / "claudex-quarantine"
        qdir.mkdir()
        (qdir / "0123456789abcdef.json").write_text("not json")
        (qdir / "1123456789abcdef.json").write_text(json.dumps({"run_id": "ffffffffffffffff", "path": "x",
                                                                "pid": 1, "deadline_epoch": 1,
                                                                "cleanup": "unconfirmed"}))
        (qdir / "2123456789abcdef.json").write_text(json.dumps({"run_id": "2123456789abcdef"}))
        lines = sf.list_quarantine(scratch)
        self.assertEqual(len(lines), 3)
        self.assertTrue(all(line.startswith("unreadable record ") for line in lines))

    def test_symlink_record_is_unreadable_and_not_followed(self):
        scratch = self.tmp()
        outside = self.tmp() / "secret.json"
        outside.write_text(json.dumps({"run_id": "0123456789abcdef", "path": "SECRET", "pid": 1,
                                       "deadline_epoch": 1, "cleanup": "unconfirmed"}))
        qdir = scratch / "claudex-quarantine"
        qdir.mkdir()
        try:
            os.symlink(outside, qdir / "0123456789abcdef.json")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.no_destruction()
        lines = sf.list_quarantine(scratch)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("unreadable record "))
        self.assertNotIn("SECRET", lines[0])

    def test_symlinked_quarantine_directory_is_not_followed(self):
        scratch = self.tmp()
        outside = self.tmp()
        (outside / "0123456789abcdef.json").write_text("{}")
        if os.name == "nt":
            import _winapi  # a junction needs no admin rights
            _winapi.CreateJunction(str(outside), str(scratch / "claudex-quarantine"))
        else:
            os.symlink(outside, scratch / "claudex-quarantine", target_is_directory=True)
        lines = sf.list_quarantine(scratch)
        self.assertEqual(len(lines), 1)
        self.assertIn("unreadable", lines[0])
        self.assertNotIn("0123456789abcdef", lines[0])


# --- verify_download -------------------------------------------------------------------------

class VerifyDownloadTests(TempMixin, unittest.TestCase):
    def setUp(self):
        self.d = self.tmp()
        for name in sf.WORKER_FILES:
            (self.d / name).write_text("{}")
        (self.d / WHEEL_NAME).write_bytes(b"wheel-one")
        self.expected = [("demo", "1.0", WHEEL_NAME)]

    def test_ok(self):
        out = sf.verify_download(self.d, self.expected, MiB, MiB)
        self.assertEqual(out, [("demo", "1.0", WHEEL_NAME, H1, 9)])

    def test_selected_hash_checked_when_given(self):
        out = sf.verify_download(self.d, [("demo", "1.0", WHEEL_NAME, H1)], MiB, MiB)
        self.assertEqual(out[0][3], H1)
        out = sf.verify_download(self.d, [("demo", "1.0", WHEEL_NAME, frozenset({H1, "0" * 64}))], MiB, MiB)
        self.assertEqual(out[0][3], H1)

    def test_hash_the_worker_misreported_is_rejected(self):
        with self.assertRaises(sf.FetchRefused):
            sf.verify_download(self.d, [("demo", "1.0", WHEEL_NAME, "0" * 64)], MiB, MiB)
        with self.assertRaises(sf.FetchRefused):
            sf.verify_download(self.d, [("demo", "1.0", WHEEL_NAME, frozenset({"0" * 64}))], MiB, MiB)

    def test_extra_file_rejected(self):
        (self.d / "extra.whl").write_bytes(b"x")
        with self.assertRaises(sf.FetchInfrastructure):
            sf.verify_download(self.d, self.expected, MiB, MiB)

    def test_extra_directory_rejected(self):
        (self.d / "sub").mkdir()
        with self.assertRaises(sf.FetchInfrastructure):
            sf.verify_download(self.d, self.expected, MiB, MiB)

    def test_missing_file_rejected(self):
        (self.d / WHEEL_NAME).unlink()
        with self.assertRaises(sf.FetchInfrastructure):
            sf.verify_download(self.d, self.expected, MiB, MiB)

    def test_missing_worker_file_rejected(self):
        (self.d / "worker-stderr.txt").unlink()
        with self.assertRaises(sf.FetchInfrastructure):
            sf.verify_download(self.d, self.expected, MiB, MiB)

    def test_symlink_rejected(self):
        real = self.tmp() / "real.whl"
        real.write_bytes(b"wheel-one")
        (self.d / WHEEL_NAME).unlink()
        try:
            os.symlink(real, self.d / WHEEL_NAME)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(sf.FetchInfrastructure):
            sf.verify_download(self.d, self.expected, MiB, MiB)

    def test_size_caps(self):
        with self.assertRaises(sf.FetchRefused):
            sf.verify_download(self.d, self.expected, 8, MiB)
        with self.assertRaises(sf.FetchRefused):
            sf.verify_download(self.d, self.expected, MiB, 8)

    def test_total_cap_across_files(self):
        other = "other-1.0-py3-none-any.whl"
        (self.d / other).write_bytes(b"12345")
        with self.assertRaises(sf.FetchRefused):
            sf.verify_download(self.d, self.expected + [("other", "1.0", other)], 9, 12)
        self.assertEqual(len(sf.verify_download(self.d, self.expected + [("other", "1.0", other)], 9, 14)), 2)

    def test_hash_is_recomputed_not_taken_from_the_result(self):
        (self.d / "worker-result.json").write_text(json.dumps(
            {"ok": True, "files": [["demo", "1.0", WHEEL_NAME, "0" * 64, 1]]}))
        out = sf.verify_download(self.d, self.expected, MiB, MiB)
        self.assertEqual(out[0][3:], (H1, 9))

    def test_unsafe_expected_names_rejected(self):
        for name in ("../demo.whl", "job.json", "a.zip", "x/y.whl"):
            with self.subTest(name=name), self.assertRaises(sf.FetchInfrastructure):
                sf.verify_download(self.d, [("demo", "1.0", name)], MiB, MiB)

    def test_duplicate_expected_rejected(self):
        with self.assertRaises(sf.FetchInfrastructure):
            sf.verify_download(self.d, self.expected * 2, MiB, MiB)


class CliTests(unittest.TestCase):
    def test_no_worker_flag_is_usage_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(sf.main([]), 2)
            self.assertEqual(sf.main(["--worker"]), 2)
        self.assertTrue(err.getvalue().isascii())


if __name__ == "__main__":
    unittest.main()
