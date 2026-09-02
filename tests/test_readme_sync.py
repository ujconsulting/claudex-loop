#!/usr/bin/env python3
"""README.md and README_DE.md must not drift, and neither may point at upstream.

A translation rots silently: prose diverges and nobody notices, but the parts a
reader COPIES — install commands, env vars, the flow diagram — are exactly the
parts where drift does damage. Those are compared literally here. Prose is not,
because comparing prose across languages is not a thing a test can do.

The install check is the one with teeth. Both files inherited upstream's
`/plugin marketplace add chaseai-yt/claudex-loop` from the fork point, so anyone
following THIS repo's README installed the ORIGINAL plugin — without the
read-only wrapper, without the PreToolUse guard, without any of the hardening the
same README goes on to describe. A reader could not have discovered that; the
Safety section would simply have been describing controls they did not have.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EN = REPO / "README.md"
DE = REPO / "README_DE.md"

FENCE_RE = re.compile(r"^```([a-zA-Z]*)\n(.*?)^```", re.M | re.S)

# This repo's own marketplace. Upstream is referenced for attribution and for
# linking issues/PRs, which is fine — but never as something to install.
FORK = "ujconsulting/claudex-loop"
UPSTREAM = "chaseai-yt/claudex-loop"


def blocks(path, lang=None):
    found = FENCE_RE.findall(path.read_text(encoding="utf-8"))
    return [body for tag, body in found if lang is None or tag == lang]


class BothReadmesExist(unittest.TestCase):
    def test_the_german_translation_is_present(self):
        self.assertTrue(DE.is_file(), "README_DE.md is referenced by CLAUDE.md and must exist")

    def test_the_german_file_points_at_the_english_original(self):
        self.assertIn("README.md", DE.read_text(encoding="utf-8")[:1200])


class InstallTargetTests(unittest.TestCase):
    """An install command in THIS repo installs THIS repo."""

    def test_no_readme_tells_the_reader_to_install_upstream(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                for body in blocks(path):
                    self.assertNotIn(
                        f"marketplace add {UPSTREAM}",
                        body,
                        f"{path.name} installs the upstream plugin — the reader gets "
                        f"neither the wrapper nor the guard this README describes",
                    )

    def test_both_readmes_install_this_fork(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(f"marketplace add {FORK}", path.read_text(encoding="utf-8"))

    def test_upstream_may_still_be_linked_for_attribution(self):
        # Guard against over-correcting: issue/PR references upstream are correct
        # and must survive. This test fails if someone strips them wholesale.
        self.assertIn(f"github.com/{UPSTREAM}/", EN.read_text(encoding="utf-8"))


class TranslationSyncTests(unittest.TestCase):
    """Commands and the diagram are copied, not translated — so they must match."""

    def test_the_flow_diagram_is_identical(self):
        en, de = blocks(EN, "mermaid"), blocks(DE, "mermaid")
        self.assertEqual(len(en), 1, "expected exactly one flow diagram in README.md")
        self.assertEqual(en, de, "the mermaid diagram drifted between the two READMEs")

    def test_the_same_shell_and_yaml_blocks_appear_in_both(self):
        for lang in ("bash", "yaml"):
            with self.subTest(lang=lang):
                self.assertEqual(
                    blocks(EN, lang),
                    blocks(DE, lang),
                    f"a {lang} block differs between README.md and README_DE.md — "
                    f"commands are copied verbatim, so this is drift, not translation",
                )

    def test_both_carry_the_same_number_of_sections(self):
        count = lambda p: len(re.findall(r"^## ", p.read_text(encoding="utf-8"), re.M))
        self.assertEqual(
            count(EN), count(DE),
            "one README gained or lost a section — translate it or remove it there too",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
