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


class EgressEnvIsolation(unittest.TestCase):
    """Both egress variables, every time.

    setUp used to save only CLAUDEX_EGRESS_ALLOW while CLAUDEX_EGRESS_ALLOWLIST
    stayed live, so a developer or CI box with a file allowlist configured got
    different results from the host-list tests -- a suite that can pass or fail on
    ambient environment is not measuring the code (audit 2026-08-30).
    """

    def setUp(self):
        self._saved = {
            name: os.environ.get(name)
            for name in (fallback_review.EGRESS_ALLOW_ENV, fallback_review.EGRESS_FILE_ENV)
        }
        for name in self._saved:
            os.environ.pop(name, None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class SchemeRuleTests(EgressEnvIsolation):
    """Plain http may only ever reach the machine it started on."""

    def test_https_to_an_allowlisted_remote_host_passes(self):
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "openrouter.ai"
        fallback_review.check_egress("https://openrouter.ai/api/v1")

    def test_plain_http_to_a_remote_host_is_refused_without_a_key(self):
        # The regression this whole rule is about.
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "evil.example"
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.check_egress("http://evil.example/v1")
        self.assertIn("plain http", str(caught.exception))

    def test_plain_http_to_loopback_passes(self):
        for host in ("127.0.0.1:1234", "localhost:1234"):
            with self.subTest(host=host):
                fallback_review.check_egress(f"http://{host}/v1")

    def test_host_docker_internal_is_not_a_loopback_name(self):
        """It is an ordinary DNS name and is no longer in the set at all.

        On Docker Desktop it points at the host ACROSS A BRIDGE. Keeping it in
        LOOPBACK_HOSTS and merely verifying it by resolution was still wrong in
        one place: _opener() keyed its proxy bypass on set membership, so this
        name got its proxy stripped while not being local. (Audit 2026-08-30,
        then CodeRabbit the same day.)
        """
        self.assertNotIn("host.docker.internal", fallback_review.LOOPBACK_HOSTS)
        self.assertFalse(fallback_review._is_loopback_host("host.docker.internal"))
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "host.docker.internal"
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.check_egress("http://host.docker.internal:1234/v1")
        self.assertIn("clear", str(caught.exception))

    def test_the_proxy_bypass_uses_the_verified_answer_not_the_name(self):
        """Set a proxy, so the assertion can actually fail.

        The first version fell back to `or not os.environ.get("HTTP_PROXY")`,
        which made it pass vacuously on any machine without a proxy configured --
        i.e. every developer box. (CodeRabbit, 2026-08-30.)
        """
        proxy = "http://proxy.invalid:3128"
        for name in ("http_proxy", "HTTP_PROXY"):
            saved = os.environ.get(name)
            os.environ[name] = proxy
            self.addCleanup(
                lambda n=name, v=saved: os.environ.__setitem__(n, v)
                if v is not None
                else os.environ.pop(n, None)
            )
        proxy_cls = fallback_review.urllib.request.ProxyHandler
        handlers = [
            h
            for h in fallback_review._opener("http://host.docker.internal:1234/v1").handlers
            if isinstance(h, proxy_cls)
        ]
        self.assertTrue(handlers, "a non-loopback host must not get the proxy stripped")
        self.assertIn(proxy, str(handlers[0].proxies.values()))

    def test_a_non_http_scheme_is_refused(self):
        for url in ("file:///etc/passwd", "ftp://example.org/x", "gopher://example.org"):
            with self.subTest(url=url):
                with self.assertRaises(fallback_review.EgressDenied):
                    fallback_review.check_egress(url)

    def test_a_url_without_a_host_is_refused(self):
        with self.assertRaises(fallback_review.EgressDenied):
            fallback_review.check_egress("https:///v1")


class HostAllowlistTests(EgressEnvIsolation):
    def test_unset_means_refusal_not_permission(self):
        """Audit 2026-08-30, HIGH: absence of a policy was read as permission.

        With no allowlist file and the variable unset, ANY https host was
        accepted -- and the refusal message for a listed host even suggested
        unsetting the variable "to drop the host restriction". A repo-supplied
        `.env` could name an arbitrary provider and the plan went there.
        """
        with self.assertRaises(fallback_review.EgressDenied) as caught:
            fallback_review.check_egress("https://anything.example/v1")
        message = str(caught.exception)
        self.assertIn("no egress allowlist", message)
        self.assertIn(fallback_review.EGRESS_ALLOW_ENV, message, "say how to fix it")

    def test_loopback_needs_no_allowlist_whichever_allowlist_exists(self):
        """A rule that tightens as you configure more policy is a trap.

        Loopback used to be free only while NOTHING was configured: adding
        `openrouter.ai` to reach a remote reviewer then silently broke the local
        LM Studio profile. Verified loopback bypasses every allowlist source.
        (CodeRabbit, 2026-08-30.)
        """
        fallback_review.check_egress("http://127.0.0.1:1234/v1")

        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "openrouter.ai"
        fallback_review.check_egress("http://127.0.0.1:1234/v1")
        fallback_review.check_egress("https://localhost:1234/v1")

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            listed = Path(tmp) / "allowed_egress.yaml"
            listed.write_text(
                "version: 1\nhosts:\n  - host: openrouter.ai\n    schemes: [https]\n"
                "    why: remote reviewer, loopback deliberately absent\n",
                encoding="utf-8",
            )
            os.environ[fallback_review.EGRESS_FILE_ENV] = str(listed)
            fallback_review.check_egress("http://127.0.0.1:1234/v1")

    def test_a_remote_host_is_still_refused_when_an_allowlist_omits_it(self):
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "openrouter.ai"
        with self.assertRaises(fallback_review.EgressDenied):
            fallback_review.check_egress("https://elsewhere.example/v1")

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


class InlineKeyTests(EgressEnvIsolation):
    """An inline key is refused, not warned about.

    Adopted from a sister repo's audit: a warning nobody reads is not
    enforcement, and the key sits in the file the whole time it is ignored.
    """

    def setUp(self):
        super().setUp()
        self.saved = {k: v for k, v in os.environ.items() if k.startswith("CLAUDEX_REVIEWER_T_")}
        self.addCleanup(self._restore)
        os.environ["CLAUDEX_REVIEWER_T_BASE_URL"] = "https://example.test/v1"
        os.environ["CLAUDEX_REVIEWER_T_MODEL"] = "m"
        # profile() vets base_url through check_egress, which now fails closed.
        os.environ[fallback_review.EGRESS_ALLOW_ENV] = "example.test"

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
