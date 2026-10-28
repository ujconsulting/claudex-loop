#!/usr/bin/env python3
"""Stage 0 of plan A (docs/plans/2026-10-27-sicherheitskette): Claude reviewers without the
session's tools.

Measured 2026-10-27 in a fresh `claude -p --plugin-dir <repo>` session:

- an agent WITHOUT a `tools:` line got ToolSearch and through it found
  `mcp__claude_ai_Notion__notion-search`, `...notion-create-database` -- the session's
  write-capable connectors (Gmail, Drive, Calendar, Notion, Canva, Gamma, a CRM);
- `claudex-reader` (`tools: Read, Grep, Glob`) listed exactly Read, Grep, Glob and had no
  ToolSearch, so no MCP tool is reachable;
- `claudex-hunter` (`tools: ""`) listed no tools at all;
- an agent whose list resolves to nothing recognised (`tools: TodoWrite`) is refused at
  launch ("would be spawned with zero tools") -- `""` is the form that yields an empty set.

These tests hold the files to exactly what was measured. Written before the skill texts
and seen failing first.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AGENTS = REPO / "agents"
ACTOR_SKILLS = ("audit", "build", "claudex-loop", "code-review", "docs-backfill", "plan-review")
RULE = ("When an adversary role resolves to `claude`, it runs as the plugin agent "
        "`claudex-reader`")


def frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, f"{path}: no frontmatter"
    out = {}
    for line in m.group(1).splitlines():
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out


class AgentFiles(unittest.TestCase):
    def test_reader_has_exactly_read_grep_glob(self):
        fm = frontmatter(AGENTS / "claudex-reader.md")
        self.assertEqual(fm.get("name"), "claudex-reader")
        self.assertEqual(fm.get("tools"), "Read, Grep, Glob")

    def test_hunter_has_no_tools(self):
        fm = frontmatter(AGENTS / "claudex-hunter.md")
        self.assertEqual(fm.get("name"), "claudex-hunter")
        self.assertEqual(fm.get("tools"), '""', 'the measured form for an empty tool set is tools: ""')

    def test_no_agent_file_grants_a_shell_write_network_or_mcp_tool(self):
        banned = re.compile(r"\b(Bash|Write|Edit|NotebookEdit|WebFetch|WebSearch|ToolSearch|Agent|Skill)\b|mcp__")
        for path in sorted(AGENTS.glob("*.md")):
            with self.subTest(agent=path.name):
                tools = frontmatter(path).get("tools")
                self.assertIsNotNone(tools, f"{path.name}: a missing tools line inherits every tool")
                self.assertIsNone(banned.search(tools), f"{path.name}: {tools}")

    def test_the_agent_names_are_not_configurable(self):
        roles = (REPO / "scripts" / "claudex_roles.py").read_text(encoding="utf-8")
        self.assertNotIn('"agent"', roles, "agent names are plugin constants, not a .claudex.yaml key")


class SkillsUseTheReader(unittest.TestCase):
    def test_every_actor_section_routes_claude_reviewers_to_the_reader(self):
        for name in ACTOR_SKILLS:
            text = (REPO / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            start = text.find("## Actor")
            end = text.find("\n## ", start + 1)
            with self.subTest(skill=name):
                self.assertNotEqual(start, -1)
                self.assertIn(RULE, text[start:end])

    def test_the_hunt_step_uses_the_toolless_hunter_and_the_snapshot_only(self):
        text = (REPO / "skills" / "audit" / "SKILL.md").read_text(encoding="utf-8")
        start = text.find("### Step 3c")
        step = text[start:text.find("\n### ", start + 1)]
        self.assertNotEqual(start, -1)
        self.assertIn("claudex-loop:claudex-hunter", step)
        # Inspection round 2, finding 8: the bundle comes from the verified `bundle`
        # command, never hand-built from input/.
        self.assertIn("Never hand-built from `input/`", step)
        self.assertIn("--spec security-verify", step)
        for sub in ("prepare", "skill-file", "bundle", "log-agent", "request", "judge", "publish"):
            self.assertIn(f"hunt_run.py\" {sub}", step, sub)
        self.assertIn("not a read boundary", step, "the redaction must not be oversold")

    def test_roles_doc_names_the_reader(self):
        self.assertIn("claudex-reader", (REPO / "ROLES.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
