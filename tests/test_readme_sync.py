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

    def test_both_carry_the_same_language_switcher(self):
        """Cross-linked in BOTH directions, or the translation is undiscoverable.

        README.md linked nothing: a German reader landing there had no way to
        find README_DE.md at all. Convention borrowed from upstream PR #6, which
        adds Chinese and Japanese the same way. (2026-09-03.)
        """
        switcher = "[English](README.md) | [Deutsch](README_DE.md)"
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(switcher, path.read_text(encoding="utf-8")[:2500])


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


class ExpectWorkdirDocumentationTests(unittest.TestCase):
    """--expect-workdir (wrapper 2.5.0): an ASSERTION, not a selector.

    docs/audit/2026-09-11-scope.md §5 / E-1: the flag compares the wrapper's actual cwd against an
    absolute DIR and can only refuse (exit 2) — it never sets where Codex runs.
    A translator could drop the whole paragraph and every other sync test
    here would stay green (no mermaid/bash/yaml drift, same section count),
    so this class checks presence directly, anchor by anchor, in both files.
    The anchors are exactly the fragments this repo's own convention keeps
    verbatim across languages: the flag name, the two-word contrast that
    prevents the "it selects the cwd" misreading, and the wrapper's own
    header-line format, which is a literal string, not prose.
    """

    ANCHOR_FLAG = "--expect-workdir"
    ANCHOR_ASSERTION = "ASSERTION, not a SELECTOR"
    ANCHOR_REFUSE_ONLY = "can only refuse"
    ANCHOR_DEFAULT = "unset, behaviour as in 2.4.0"
    ANCHOR_HEADER = "#   cwd:"

    def test_both_readmes_name_the_flag(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(self.ANCHOR_FLAG, path.read_text(encoding="utf-8"))

    def test_both_readmes_call_it_an_assertion_not_a_selector(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(self.ANCHOR_ASSERTION, path.read_text(encoding="utf-8"))

    def test_both_readmes_say_it_can_only_refuse(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(self.ANCHOR_REFUSE_ONLY, path.read_text(encoding="utf-8"))

    def test_both_readmes_state_the_default_is_unset(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(self.ANCHOR_DEFAULT, path.read_text(encoding="utf-8"))

    def test_both_readmes_show_the_cwd_header_line(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertIn(self.ANCHOR_HEADER, path.read_text(encoding="utf-8"))

    def test_the_expect_workdir_example_invocation_is_identical(self):
        """The example command is copied, not translated — same rule as any other."""

        def block_with_flag(path):
            for body in blocks(path, "bash"):
                if self.ANCHOR_FLAG in body:
                    return body
            return None

        en_block, de_block = block_with_flag(EN), block_with_flag(DE)
        self.assertIsNotNone(en_block, "README.md has no bash example using --expect-workdir")
        self.assertEqual(
            en_block, de_block,
            "the --expect-workdir example invocation drifted between the two READMEs",
        )


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

    def test_the_centring_divs_are_balanced_in_both(self):
        """README_DE shipped with an unclosed <div> — GitHub then centres the rest.

        Caught by eye, not by a test, which is why there is one now.
        """
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(
                    text.count("<div"), text.count("</div>"),
                    f"{path.name}: unbalanced <div> — everything after it renders centred",
                )

    def test_neither_readme_carries_promotional_links(self):
        """Attribution stays, marketing does not. MIT compels the first, not the second.

        The credits (Matt Pocock, Peter Steinberger, Chase AI) are attribution and
        a licence obligation; the paid-community pitch that sat under them was
        neither, and this fork does not carry it.
        """
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                self.assertNotIn("skool.com", path.read_text(encoding="utf-8"))

    def test_the_licence_pointer_and_attribution_survive(self):
        for path in (EN, DE):
            with self.subTest(readme=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn("LICENSE", text, "the licence pointer is not optional")
                self.assertIn("mattpocock", text, "MIT attribution must not be dropped")

    def test_both_carry_the_same_number_of_sections(self):
        count = lambda p: len(re.findall(r"^## ", p.read_text(encoding="utf-8"), re.M))
        self.assertEqual(
            count(EN), count(DE),
            "one README gained or lost a section — translate it or remove it there too",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
