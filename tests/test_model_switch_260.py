#!/usr/bin/env python3
"""Wrapper 2.6.0, package K: the model switch reaches every place that states it.

gpt-5.6-terra was superseded by gpt-6-sol on 2026-09-22. A default is written
down in the resolver, the wrapper, the example config, ROLES.md, both READMEs
and the skills -- and a copy that is not updated keeps telling readers (and the
model that reads the skills) the old value. These tests compare STRUCTURED
statements only: model lines, `--spec` example output, header examples, minimum
CLI versions, install commands. Warnings about the old `-codex` slugs and dated
historical measurements are allowed.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import claudex_roles  # noqa: E402
import codex_ro  # noqa: E402

SKILLS = sorted((REPO / "skills").glob("*/SKILL.md"))
DOCS = [REPO / "README.md", REPO / "README_DE.md", REPO / "ROLES.md", REPO / ".claudex.yaml.example"]

DATED = re.compile(r"20\d\d-\d\d-\d\d|\b\d\d\.\d\d\.20\d\d\b")
SLUG_WARNING = re.compile(r"-codex\b|\*-codex|gpt-5\.x")
MODEL_LINE = re.compile(r"""\bmodel\s*[:=]\s*["']?(gpt-[\w.\-]+)""")
SPEC_LINE = re.compile(r"model=(gpt-[\w.\-]+)\s+effort=(\w+)")
HEADER_LINE = re.compile(r"\|\s*(gpt-[\w.\-]+)/(\w+)\s*\|\s*timeout")
MIN_CLI = re.compile(r"(?:≥|>=)\s*0\.(\d{3})(?:\.\d+)?")
INSTALL = re.compile(r"@openai/codex@([\w.\-]+)")


def _default():
    spec = claudex_roles.actor_spec(claudex_roles.DEFAULTS, "code-review")[0]
    return spec["model"], spec["effort"]


def _lines(paths):
    for path in paths:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            yield path, number, line


def _exempt(line):
    return bool(DATED.search(line) or SLUG_WARNING.search(line))


class StructuredDefaultsTests(unittest.TestCase):
    """K-T2 / K-T3."""

    def test_the_resolver_and_the_wrapper_agree(self):
        self.assertEqual(_default(), (codex_ro.DEFAULT_MODEL, codex_ro.DEFAULT_EFFORT))

    def test_model_lines_name_the_current_default(self):
        model, _ = _default()
        for path, number, line in _lines(SKILLS + DOCS):
            for found in MODEL_LINE.findall(line):
                if _exempt(line):
                    continue
                with self.subTest(file=f"{path.parent.name}/{path.name}", line=number):
                    self.assertEqual(found, model, line.strip())

    def test_spec_and_header_examples_name_the_current_default(self):
        model, effort = _default()
        for path, number, line in _lines(SKILLS + DOCS + [REPO / "docs" / "betrieb.md"]):
            if _exempt(line):
                continue
            for pattern in (SPEC_LINE, HEADER_LINE):
                for found in pattern.findall(line):
                    with self.subTest(file=f"{path.parent.name}/{path.name}", line=number):
                        self.assertEqual(found, (model, effort), line.strip())

    def test_minimum_cli_statements_match_the_wrapper(self):
        minimum = codex_ro.MODEL_MIN_CLI[codex_ro.DEFAULT_MODEL]
        for path, number, line in _lines(SKILLS + DOCS):
            if "codex" not in line.lower() or _exempt(line):
                continue
            for found in MIN_CLI.findall(line):
                with self.subTest(file=f"{path.parent.name}/{path.name}", line=number):
                    self.assertEqual(f"0.{found}.0", minimum, line.strip())


class ResolverPathTests(unittest.TestCase):
    """K-T4: relative `python scripts/claudex_roles.py` does not exist in a consumer repo."""

    def test_no_skill_calls_the_resolver_relatively(self):
        for path, number, line in _lines(SKILLS):
            with self.subTest(skill=path.parent.name, line=number):
                self.assertNotIn("python scripts/claudex_roles.py", line)


class InstallCommandTests(unittest.TestCase):
    """K-T5: never an unpinned latest; always the measured version."""

    def test_install_commands_pin_the_measured_version(self):
        for path, number, line in _lines(SKILLS + DOCS + [REPO / "docs" / "betrieb.md"]):
            for found in INSTALL.findall(line):
                if _exempt(line):
                    continue
                with self.subTest(file=f"{path.parent.name}/{path.name}", line=number):
                    self.assertEqual(found, codex_ro.MEASURED_CODEX_CLI, line.strip())


class ReadmeContentTests(unittest.TestCase):
    def test_both_readmes_carry_the_2_6_0_upgrade_note(self):
        for path, heading in ((REPO / "README.md", "## Upgrading to 2.6.0"),
                              (REPO / "README_DE.md", "## Umstieg auf 2.6.0")):
            with self.subTest(readme=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn(heading, text)
                self.assertIn("--ignore-user-config", text)
                self.assertIn("mxc", text, "three measured windows.sandbox values, not two")
                self.assertIn(".codex/config.toml", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
