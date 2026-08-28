#!/usr/bin/env python3
"""Tests for the egress rule in the fallback reviewer.

The rule exists because the check it replaced fired only when an API key was
set: a keyless endpoint received the plan and the entire review log in the
clear, to any host. What is worth protecting is the plan, not the key.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import fallback_review  # noqa: E402


class SchemeRuleTests(unittest.TestCase):
    """Plain http may only ever reach the machine it started on."""

    def test_https_to_a_remote_host_passes(self):
        fallback_review.check_egress("https://openrouter.ai/api/v1")

    def test_plain_http_to_a_remote_host_is_refused_without_a_key(self):
        # The regression this whole rule is about.
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.check_egress("http://evil.example/v1")
        self.assertIn("plain http", str(caught.exception))

    def test_plain_http_to_loopback_passes(self):
        for host in ("127.0.0.1:1234", "localhost:1234", "host.docker.internal:1234"):
            with self.subTest(host=host):
                fallback_review.check_egress(f"http://{host}/v1")

    def test_a_non_http_scheme_is_refused(self):
        for url in ("file:///etc/passwd", "ftp://example.org/x", "gopher://example.org"):
            with self.subTest(url=url):
                with self.assertRaises(fallback_review.EgressDenied):
                    fallback_review.check_egress(url)

    def test_a_url_without_a_host_is_refused(self):
        with self.assertRaises(fallback_review.EgressDenied):
            fallback_review.check_egress("https:///v1")


class HostAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.previous = os.environ.get(fallback_review.EGRESS_ALLOW_ENV)
        self.addCleanup(self._restore)

    def _restore(self):
        if self.previous is None:
            os.environ.pop(fallback_review.EGRESS_ALLOW_ENV, None)
        else:
            os.environ[fallback_review.EGRESS_ALLOW_ENV] = self.previous

    def test_unset_means_no_host_restriction(self):
        os.environ.pop(fallback_review.EGRESS_ALLOW_ENV, None)
        fallback_review.check_egress("https://anything.example/v1")

    def test_a_listed_host_passes(self):
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "openrouter.ai, api.openai.com"
        fallback_review.check_egress("https://openrouter.ai/api/v1")

    def test_an_unlisted_host_is_refused(self):
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "openrouter.ai"
        with self.assertRaises(fallback_review.EgressDenied):
            fallback_review.check_egress("https://elsewhere.example/v1")

    def test_a_suffix_lookalike_does_not_match(self):
        """`api.openai.com.attacker.test` ends in an allowed name. Exact only."""
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "api.openai.com"
        with self.assertRaises(fallback_review.EgressDenied):
            fallback_review.check_egress("https://api.openai.com.attacker.test/v1")

    def test_matching_ignores_case(self):
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "OpenRouter.AI"
        fallback_review.check_egress("https://openrouter.ai/api/v1")


VALID_ALLOWLIST = """\
version: 1
hosts:
  - host: 127.0.0.1
    schemes: [http, https]
    why: LM Studio on loopback.
  - host: openrouter.ai
    schemes: [https]
    why: Fallback reviewer; the plan leaves the house.
"""


class FileAllowlistTests(unittest.TestCase):
    """A configured file is authoritative — and fail-closed when unusable."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "allowed_egress.yaml"
        self.path.write_text(VALID_ALLOWLIST, encoding="utf-8")
        self.saved = os.environ.get(fallback_review.EGRESS_FILE_ENV)
        os.environ[fallback_review.EGRESS_FILE_ENV] = str(self.path)
        self.addCleanup(self._restore)

    def _restore(self):
        if self.saved is None:
            os.environ.pop(fallback_review.EGRESS_FILE_ENV, None)
        else:
            os.environ[fallback_review.EGRESS_FILE_ENV] = self.saved

    def test_a_listed_host_with_a_listed_scheme_passes(self):
        fallback_review.check_egress("https://openrouter.ai/api/v1")
        fallback_review.check_egress("http://127.0.0.1:1234/v1")

    def test_an_unlisted_host_is_refused_even_over_https(self):
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.check_egress("https://elsewhere.example/v1")
        self.assertIn("not in the egress allowlist", str(caught.exception))

    def test_a_scheme_the_entry_does_not_list_is_refused(self):
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.check_egress("http://openrouter.ai/api/v1")
        self.assertIn("openrouter.ai", str(caught.exception))

    def test_a_named_file_that_is_absent_stops_everything(self):
        os.environ[fallback_review.EGRESS_FILE_ENV] = str(self.path) + ".gone"
        with self.assertRaises(fallback_review.AllowlistUnreadable) as caught:
            fallback_review.check_egress("https://openrouter.ai/api/v1")
        self.assertIn("does not exist", str(caught.exception))

    def test_broken_yaml_stops_everything(self):
        self.path.write_text("hosts: [ this is not: valid: yaml", encoding="utf-8")
        with self.assertRaises(fallback_review.AllowlistUnreadable):
            fallback_review.check_egress("https://openrouter.ai/api/v1")

    def test_a_file_without_a_hosts_list_stops_everything(self):
        self.path.write_text("version: 1\n", encoding="utf-8")
        with self.assertRaises(fallback_review.AllowlistUnreadable):
            fallback_review.check_egress("https://openrouter.ai/api/v1")

    def test_a_missing_parser_does_not_lift_the_restriction(self):
        original = fallback_review._yaml_module

        def no_parser():
            raise fallback_review.AllowlistUnreadable("PyYAML is not installed")

        fallback_review._yaml_module = no_parser
        try:
            with self.assertRaises(fallback_review.AllowlistUnreadable):
                fallback_review.check_egress("https://openrouter.ai/api/v1")
        finally:
            fallback_review._yaml_module = original

    def test_the_file_wins_over_the_env_list(self):
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "elsewhere.example"
        self.addCleanup(lambda: os.environ.pop(fallback_review.EGRESS_ALLOW_ENV, None))
        with self.assertRaises(fallback_review.EgressDenied):
            fallback_review.check_egress("https://elsewhere.example/v1")


class InlineKeyTests(unittest.TestCase):
    """An inline key is refused, not warned about.

    Adopted from a sister repo's audit: a warning nobody reads is not
    enforcement, and the key sits in the file the whole time it is ignored.
    """

    def setUp(self):
        self.saved = {k: v for k, v in os.environ.items() if k.startswith("CLAUDEX_REVIEWER_T_")}
        self.addCleanup(self._restore)
        os.environ["CLAUDEX_REVIEWER_T_BASE_URL"] = "https://example.test/v1"
        os.environ["CLAUDEX_REVIEWER_T_MODEL"] = "m"

    def _restore(self):
        for key in list(os.environ):
            if key.startswith("CLAUDEX_REVIEWER_T_"):
                del os.environ[key]
        os.environ.update(self.saved)

    def test_an_inline_key_stops_the_run(self):
        os.environ["CLAUDEX_REVIEWER_T_API_KEY"] = "sk-secret"
        with self.assertRaises(SystemExit) as caught:
            fallback_review.profile("t")
        self.assertIn("API_KEY_ENV", str(caught.exception))
        self.assertNotIn("sk-secret", str(caught.exception), "the key must not be echoed back")

    def test_a_key_from_an_env_var_is_accepted(self):
        os.environ["CLAUDEX_REVIEWER_T_API_KEY_ENV"] = "SOME_INJECTED_VAR"
        os.environ["SOME_INJECTED_VAR"] = "sk-secret"
        self.addCleanup(lambda: os.environ.pop("SOME_INJECTED_VAR", None))
        self.assertEqual(fallback_review.profile("t")["api_key"], "sk-secret")


class RequestSiteTests(unittest.TestCase):
    """The guard has to sit at the request, not only at the configuration."""

    def test_the_get_helper_checks_before_opening_the_connection(self):
        opened = []
        original = fallback_review.urllib.request.urlopen
        fallback_review.urllib.request.urlopen = lambda *a, **k: opened.append(a)
        try:
            with self.assertRaises(fallback_review.EgressDenied):
                fallback_review.http_get_json("http://evil.example/models", {})
        finally:
            fallback_review.urllib.request.urlopen = original
        self.assertEqual(opened, [], "nothing may be sent before the check passes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
