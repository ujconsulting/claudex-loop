#!/usr/bin/env python3
"""Tests for the opt-in model autoload in the fallback reviewer.

Ported from the LM-Studio-specific predecessor (`lms_review.py`), which is
otherwise fully superseded by the generic adapter. It earns its place because
`--check` cannot catch what it fixes: LM Studio's GET /models lists the models
it has DOWNLOADED, not the one it has LOADED — so preflight goes green and the
run fails right afterwards.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import fallback_review  # noqa: E402


def make_profile(**overrides):
    profile = {
        "name": "lmstudio",
        "base_url": "http://127.0.0.1:1234/v1",
        "model": "qwen/qwen3.8-27b",
        "api_key": None,
        "autoload": True,
        "context": 32768,
    }
    profile.update(overrides)
    return profile


class _Patched:
    """Swap module attributes for the duration of a block."""

    def __init__(self, **attrs):
        self.attrs = attrs
        self.saved = {}

    def __enter__(self):
        for name, value in self.attrs.items():
            self.saved[name] = getattr(fallback_review, name)
            setattr(fallback_review, name, value)
        return self

    def __exit__(self, *exc):
        for name, value in self.saved.items():
            setattr(fallback_review, name, value)
        return False


class NoOpTests(unittest.TestCase):
    """Silence unless the profile asked for it. The adapter stays generic."""

    def test_without_the_opt_in_nothing_happens(self):
        ok, detail = fallback_review.ensure_model_loaded(make_profile(autoload=False))
        self.assertTrue(ok)
        self.assertEqual(detail, "")

    def test_a_remote_endpoint_is_never_autoloaded(self):
        remote = make_profile(base_url="https://openrouter.ai/api/v1")
        ok, detail = fallback_review.ensure_model_loaded(remote)
        self.assertTrue(ok)
        self.assertEqual(detail, "", "loading a model on someone else's server is nonsense")


class AutoloadTests(unittest.TestCase):
    def test_a_missing_lms_cli_is_reported_not_ignored(self):
        with _Patched(shutil=type("S", (), {"which": staticmethod(lambda _: None)})):
            ok, detail = fallback_review.ensure_model_loaded(make_profile())
        self.assertFalse(ok)
        self.assertIn("not on PATH", detail)

    def test_an_already_loaded_model_with_enough_context_is_left_alone(self):
        calls = []
        loaded = {"data": [{"id": "qwen/qwen3.8-27b", "state": "loaded",
                            "loaded_context_length": 32768}]}
        with _Patched(
            shutil=type("S", (), {"which": staticmethod(lambda _: "/usr/bin/lms")}),
            http_get_json=lambda *a, **k: loaded,
            subprocess=type("P", (), {"run": staticmethod(lambda *a, **k: calls.append(a))}),
        ):
            ok, detail = fallback_review.ensure_model_loaded(make_profile())
        self.assertTrue(ok)
        self.assertIn("already loaded", detail)
        self.assertEqual(calls, [], "no reload when the window is already big enough")

    def test_a_loaded_model_with_too_small_a_window_is_reloaded(self):
        calls = []
        loaded = {"data": [{"id": "qwen/qwen3.8-27b", "state": "loaded",
                            "loaded_context_length": 4096}]}

        class Result:
            returncode = 0
            stdout = stderr = ""

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return Result()

        with _Patched(
            shutil=type("S", (), {"which": staticmethod(lambda _: "/usr/bin/lms")}),
            http_get_json=lambda *a, **k: loaded,
            subprocess=type("P", (), {"run": staticmethod(fake_run)}),
        ):
            ok, detail = fallback_review.ensure_model_loaded(make_profile())
        self.assertTrue(ok)
        self.assertIn("unload", " ".join(calls[0]))
        self.assertIn("--context-length", calls[1])
        self.assertIn("32768", calls[1])

    def test_a_failed_load_is_a_failure_not_a_shrug(self):
        class Result:
            returncode = 1
            stdout = ""
            stderr = "no such model"

        with _Patched(
            shutil=type("S", (), {"which": staticmethod(lambda _: "/usr/bin/lms")}),
            http_get_json=lambda *a, **k: {"data": []},
            subprocess=type("P", (), {"run": staticmethod(lambda *a, **k: Result())}),
        ):
            ok, detail = fallback_review.ensure_model_loaded(make_profile())
        self.assertFalse(ok)
        self.assertIn("no such model", detail)

    def test_a_runtime_without_the_status_endpoint_still_tries_to_load(self):
        """Ollama and friends have no /api/v0 — the load attempt is the verdict."""
        class Result:
            returncode = 0
            stdout = stderr = ""

        def exploding_get(*a, **k):
            raise OSError("404")

        with _Patched(
            shutil=type("S", (), {"which": staticmethod(lambda _: "/usr/bin/lms")}),
            http_get_json=exploding_get,
            subprocess=type("P", (), {"run": staticmethod(lambda *a, **k: Result())}),
        ):
            ok, _ = fallback_review.ensure_model_loaded(make_profile())
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
