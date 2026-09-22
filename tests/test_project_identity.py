#!/usr/bin/env python3
"""Who ships this, where it came from, and where a vulnerability goes.

On 2026-09-22 the repo left GitHub's fork network. Three things the fork header
had been doing silently stopped with it, and none of them would have failed a
test:

- The "forked from" line was the only provenance near the top. Without it the
  origin survives only as one credits line at the very bottom.
- The plugin manifests still named the original author as author and
  marketplace owner. Whoever installs this plugin would take it for that
  author's product and report its bugs there — about controls that author
  never wrote.
- A fork's security reports go upstream. A standalone project needs its own
  channel, and the order matters: private vulnerability reporting first, THEN
  a SECURITY.md that points at it with a reachable address. A SECURITY.md that
  forbids public issues and names no working channel closes the only open door.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SECURITY = REPO / "SECURITY.md"
PLUGIN = REPO / ".claude-plugin" / "plugin.json"
MARKETPLACE = REPO / ".claude-plugin" / "marketplace.json"
LICENSE = REPO / "LICENSE"
READMES = (REPO / "README.md", REPO / "README_DE.md")

THIS_REPO = "ujconsulting/claudex-loop"
ORIGIN = "chaseai-yt/claudex-loop"
ORIGIN_AUTHOR = "Chase AI"
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


class SecurityPolicyTests(unittest.TestCase):
    def test_there_is_a_security_policy(self):
        self.assertTrue(SECURITY.is_file(), "a standalone project needs its own reporting channel")

    def test_it_names_the_private_channel_of_this_repo(self):
        text = SECURITY.read_text(encoding="utf-8")
        self.assertIn(f"github.com/{THIS_REPO}/security/advisories/new", text)

    def test_it_names_a_reachable_address(self):
        self.assertRegex(SECURITY.read_text(encoding="utf-8"), EMAIL_RE)

    def test_it_does_not_send_reports_to_the_origin(self):
        self.assertNotIn(ORIGIN, SECURITY.read_text(encoding="utf-8"))

    def test_both_readmes_point_at_it(self):
        for path in READMES:
            with self.subTest(readme=path.name):
                self.assertIn("SECURITY.md", path.read_text(encoding="utf-8"))


class ManifestTests(unittest.TestCase):
    def test_the_plugin_author_is_not_the_origin_author(self):
        author = json.loads(PLUGIN.read_text(encoding="utf-8"))["author"]["name"]
        self.assertNotIn(ORIGIN_AUTHOR, author)

    def test_the_marketplace_owner_is_not_the_origin_author(self):
        owner = json.loads(MARKETPLACE.read_text(encoding="utf-8"))["owner"]["name"]
        self.assertNotIn(ORIGIN_AUTHOR, owner)

    def test_the_homepage_is_this_repo(self):
        homepage = json.loads(PLUGIN.read_text(encoding="utf-8"))["homepage"]
        self.assertEqual(homepage, f"https://github.com/{THIS_REPO}")


class ProvenanceTests(unittest.TestCase):
    """Credit moves out of the manifests — it must not move out of the project."""

    def test_both_readmes_state_the_origin_near_the_top(self):
        for path in READMES:
            with self.subTest(readme=path.name):
                head = path.read_text(encoding="utf-8")[:3000]
                self.assertIn(f"github.com/{ORIGIN}", head)
                self.assertIn(ORIGIN_AUTHOR, head)

    def test_the_original_copyright_notice_stays(self):
        # MIT: "The above copyright notice ... shall be included in all copies."
        self.assertIn(f"Copyright (c) 2026 {ORIGIN_AUTHOR}", LICENSE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
