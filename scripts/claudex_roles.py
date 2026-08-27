#!/usr/bin/env python3
"""Resolve and enforce the claudex role assignment.

Which model does which step is configuration, not something baked into a skill
name. This script is the single place that answers it -- and the place where the
two rules that make the whole arrangement worth anything are enforced:

  producer_never_reviews  the actor that made an artefact never grades it
  write_access            only whitelisted roles may run with an open sandbox

Both exit non-zero when violated. A doctrine that is only written down gets
skipped on the day it is inconvenient; this one refuses to resolve.

Config is looked up repo-first, then user, then built-in defaults:

    ./.claudex.yaml
    ~/.claude/claudex.yaml
    (defaults below)

Usage:
    python scripts/claudex_roles.py                # resolved table, gates checked
    python scripts/claudex_roles.py --role build   # just the actor, for scripting
    python scripts/claudex_roles.py --json
    python scripts/claudex_roles.py --explain      # table plus why each gate passed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# --- what a workflow is made of ------------------------------------------------
# Each artefact is produced by one role and graded by another. The pairing is
# what the producer_never_reviews gate walks.
PAIRS = {
    "plan": "plan-review",
    "build": "code-review",
    "docs": "docs-review",
}
PRODUCER_ROLES = tuple(PAIRS.keys())
ADVERSARY_ROLES = tuple(PAIRS.values())
ALL_ROLES = PRODUCER_ROLES + ADVERSARY_ROLES
KNOWN_ACTORS = ("claude", "codex")

DEFAULTS = {
    "roles": {
        "plan": "claude",
        "plan-review": "codex",
        "build": "claude",
        "code-review": "codex",
        "docs": "claude",
        "docs-review": "codex",
    },
    "actors": {
        "codex": {"model": "gpt-5.6-terra", "effort": "high", "sandbox": "read-only"},
        "claude": {"fresh_subagent": True},
        "fallback": ["lmstudio"],
    },
    "rules": {
        "producer_never_reviews": True,
        "write_access": ["plan", "build", "docs"],
        "adversary_read_only": True,
    },
}


class ConfigError(Exception):
    """Raised for anything the strict parser or the gates reject."""


# --- YAML -----------------------------------------------------------------------
# PyYAML when it is there; otherwise a deliberately tiny parser for exactly the
# grammar this config uses. It refuses what it does not understand rather than
# guessing -- a config silently misread is worse than one that fails to load.

def _parse_scalar(raw: str):
    v = raw.strip()
    if v.startswith(("'", '"')) and v.endswith(("'", '"')) and len(v) >= 2:
        return v[1:-1]
    if v.lower() in ("true", "yes", "on"):
        return True
    if v.lower() in ("false", "no", "off"):
        return False
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [_parse_scalar(p) for p in inner.split(",")] if inner else []
    try:
        return int(v)
    except ValueError:
        return v


def _parse_minimal_yaml(text: str) -> dict:
    """Nested mappings, scalars and inline lists. Two-space indent. Nothing else."""
    root: dict = {}
    stack = [(-1, root)]
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.split("#", 1)[0].rstrip() if " #" in line else line.rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip())
        if stripped.lstrip().startswith("- "):
            raise ConfigError(
                f"line {lineno}: block lists are not supported -- write [a, b] inline"
            )
        if ":" not in stripped:
            raise ConfigError(f"line {lineno}: expected 'key: value', got {stripped!r}")
        key, _, rest = stripped.strip().partition(":")
        key = key.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ConfigError(f"line {lineno}: indentation does not nest under anything")
        parent = stack[-1][1]
        if rest.strip() == "":
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _parse_scalar(rest)
    return root


def _load_yaml(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
    except ImportError:
        return _parse_minimal_yaml(text)
    data = yaml.safe_load(text)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def find_config(start: Path | None = None) -> Path | None:
    """Repo config wins over user config; neither is required."""
    here = (start or Path.cwd()).resolve()
    for candidate in [here, *here.parents]:
        p = candidate / ".claudex.yaml"
        if p.is_file():
            return p
        if (candidate / ".git").exists():
            break
    user = Path.home() / ".claude" / "claudex.yaml"
    return user if user.is_file() else None


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load(start: Path | None = None) -> tuple[dict, Path | None]:
    path = find_config(start)
    cfg = _merge(DEFAULTS, _load_yaml(path)) if path else dict(DEFAULTS)
    _validate_shape(cfg)
    return cfg, path


def _validate_shape(cfg: dict) -> None:
    roles = cfg.get("roles", {})
    unknown = set(roles) - set(ALL_ROLES)
    if unknown:
        raise ConfigError(
            f"unknown role(s): {sorted(unknown)}. Known: {list(ALL_ROLES)}"
        )
    for role in ALL_ROLES:
        if role not in roles:
            raise ConfigError(f"role '{role}' is unset and has no default")
        actors = roles[role] if isinstance(roles[role], list) else [roles[role]]
        if role in ADVERSARY_ROLES and roles[role] == "cross":
            continue
        for a in actors:
            if a not in KNOWN_ACTORS:
                raise ConfigError(
                    f"role '{role}': unknown actor {a!r}. Known: {list(KNOWN_ACTORS)}"
                )
    for role in cfg.get("rules", {}).get("write_access", []):
        if role not in ALL_ROLES:
            raise ConfigError(f"write_access names unknown role {role!r}")


# --- the gates -------------------------------------------------------------------

def check(cfg: dict) -> list[str]:
    """Return violations. Empty list means the arrangement is sound."""
    roles, rules = cfg["roles"], cfg.get("rules", {})
    problems: list[str] = []

    if rules.get("producer_never_reviews", True):
        for producer, reviewer in PAIRS.items():
            made_by = roles[producer]
            graded_by = roles[reviewer]
            if isinstance(made_by, list):
                # Dual draft: each draft is graded by the other author, so the
                # reviewer must be that cross-check and not a single actor who
                # also wrote one of the drafts.
                if graded_by != "cross":
                    problems.append(
                        f"'{producer}' has {len(made_by)} authors {made_by}, so "
                        f"'{reviewer}' must be 'cross' (each draft graded by the "
                        f"other author) -- it is '{graded_by}', who co-wrote one."
                    )
            elif graded_by == "cross":
                problems.append(
                    f"'{reviewer}' is 'cross' but '{producer}' has a single "
                    f"author -- there is nothing to cross-check."
                )
            elif made_by == graded_by:
                problems.append(
                    f"'{made_by}' both produces '{producer}' and grades it as "
                    f"'{reviewer}' -- the maker never grades the thing."
                )

    if rules.get("adversary_read_only", True):
        for reviewer in ADVERSARY_ROLES:
            for actor in _actors_for(roles, reviewer):
                spec = cfg["actors"].get(actor, {})
                if actor == "codex" and spec.get("sandbox") != "read-only":
                    problems.append(
                        f"'{reviewer}' runs codex with sandbox "
                        f"{spec.get('sandbox')!r}; adversary roles are read-only."
                    )
                if actor == "claude" and not spec.get("fresh_subagent"):
                    problems.append(
                        f"'{reviewer}' runs claude without fresh_subagent -- the "
                        f"orchestrator would be grading its own work."
                    )

    allowed = set(rules.get("write_access", []))
    for role in ALL_ROLES:
        if role in ADVERSARY_ROLES and role in allowed:
            problems.append(f"'{role}' is an adversary role and cannot hold write_access.")
        if role in PRODUCER_ROLES and role not in allowed:
            problems.append(f"'{role}' produces an artefact but lacks write_access.")
    return problems


def _actors_for(roles: dict, role: str) -> list[str]:
    """Resolve 'cross' to the concrete authors it stands for."""
    value = roles[role]
    if value == "cross":
        producer = next(p for p, r in PAIRS.items() if r == role)
        authors = roles[producer]
        return authors if isinstance(authors, list) else [authors]
    return value if isinstance(value, list) else [value]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--role", help="print only this role's actor(s)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--explain", action="store_true", help="show why each gate passed")
    args = ap.parse_args(argv)

    try:
        cfg, path = load()
    except ConfigError as exc:
        print(f"claudex-roles: {exc}", file=sys.stderr)
        return 2

    problems = check(cfg)

    if args.role:
        if args.role not in ALL_ROLES:
            print(f"claudex-roles: unknown role {args.role!r}", file=sys.stderr)
            return 2
        if problems:
            print("claudex-roles: refusing to resolve, gates violated:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print(",".join(_actors_for(cfg["roles"], args.role)))
        return 0

    if args.json:
        print(json.dumps(
            {"config": str(path) if path else None, "roles": cfg["roles"],
             "actors": cfg["actors"], "rules": cfg.get("rules", {}),
             "violations": problems}, indent=2))
        return 1 if problems else 0

    print(f"config: {path or 'built-in defaults (no .claudex.yaml found)'}")
    print()
    for producer, reviewer in PAIRS.items():
        made = cfg["roles"][producer]
        made_s = " + ".join(made) if isinstance(made, list) else made
        graded = ", ".join(_actors_for(cfg["roles"], reviewer))
        note = "  (cross-check)" if cfg["roles"][reviewer] == "cross" else ""
        print(f"  {producer:<6} {made_s:<16} -> {reviewer:<12} {graded}{note}")
    print()
    if args.explain:
        rules = cfg.get("rules", {})
        print(f"  producer_never_reviews : {rules.get('producer_never_reviews', True)}")
        print(f"  adversary_read_only    : {rules.get('adversary_read_only', True)}")
        print(f"  write_access           : {rules.get('write_access', [])}")
        print()
    if problems:
        print("GATES VIOLATED -- the run must not start:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("gates OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
