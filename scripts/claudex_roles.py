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
    python scripts/claudex_roles.py --spec exposure-review   # actor + model/effort/sandbox
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
# Each artefact is produced by one role and graded by one or more adversary
# roles. The pairing is what the producer_never_reviews gate walks. `build` has
# two graders: the acceptance review and the exposure review, which looks only at
# the parts of the change that face the network and runs on its own model/effort
# (a stronger model at bounded effort over a bounded input -- see ROLES.md).
PAIRS = {
    "plan": ("plan-review",),
    "build": ("code-review", "exposure-review"),
    "docs": ("docs-review",),
}
PRODUCER_ROLES = tuple(PAIRS.keys())
PAIRED_ADVERSARY_ROLES = tuple(r for rs in PAIRS.values() for r in rs)

# Standalone adversary roles judge something nobody in this workflow produced --
# a codebase that predates the loop. There is no producer to pair them with, so
# producer_never_reviews has nothing to compare; every OTHER adversary rule still
# applies, and that is the point of listing them here rather than special-casing
# them at each check.
STANDALONE_ADVERSARY_ROLES = ("audit",)

ADVERSARY_ROLES = PAIRED_ADVERSARY_ROLES + STANDALONE_ADVERSARY_ROLES
ALL_ROLES = PRODUCER_ROLES + ADVERSARY_ROLES
KNOWN_ACTORS = ("claude", "codex")

DEFAULTS = {
    "roles": {
        "plan": "claude",
        "plan-review": "codex",
        "build": "claude",
        "code-review": "codex",
        "exposure-review": "codex",
        "docs": "claude",
        "docs-review": "codex",
        "audit": "codex",
    },
    "actors": {
        "codex": {
            "model": "gpt-5.6-terra",
            "effort": "high",
            "sandbox": "read-only",
            # Per-role overrides of model and effort only. The sandbox is not
            # overridable here: an adversary role stays read-only whatever the
            # model, and the gate below checks the actor's sandbox, not a copy.
            "roles": {
                "exposure-review": {"model": "gpt-5.6-sol", "effort": "medium"},
            },
        },
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
    # Every failure below becomes a ConfigError: main() catches that and exits 2
    # with one line. A traceback here exits 1 and reads like a crash in the tool
    # rather than a problem in the file the user just edited (audit 2026-08-30).
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"{path} cannot be read: {exc}") from exc
    try:
        import yaml  # type: ignore
    except ImportError:
        return _parse_minimal_yaml(text)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return data


def find_config(start: Path | None = None) -> Path | None:
    """The REPO ROOT's config, else the user's; neither is required.

    ⛔ The repo root, and only the repo root. This used to walk every ancestor of
    the working directory and take the first `.claudex.yaml` it met, so standing
    in `services/api/` let a nested file override the repository's own policy --
    while ROLES.md promised "in the repo root" (audit 2026-08-30). Policy that a
    subdirectory can redefine is not policy.
    """
    here = (start or Path.cwd()).resolve()
    root = next((c for c in [here, *here.parents] if (c / ".git").exists()), here)
    candidate = root / ".claudex.yaml"
    if candidate.is_file():
        return candidate
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


# Rules that exist to be enforced, not chosen. A config that could switch them off
# would let the repo under review decide whether it gets reviewed -- and the
# resolver would still print "gates OK" (audit 2026-08-30, HIGH). ROLES.md states
# both as mandatory; this is that sentence made executable.
UNSWITCHABLE_RULES = ("producer_never_reviews", "adversary_read_only")


def _require_mapping(value, what: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{what}: expected a mapping, got {type(value).__name__}")
    return value


def _validate_shape(cfg: dict) -> None:
    roles = _require_mapping(cfg.get("roles", {}), "roles")
    rules = _require_mapping(cfg.get("rules", {}), "rules")
    _require_mapping(cfg.get("actors", {}), "actors")

    for rule in UNSWITCHABLE_RULES:
        if rule in rules and not rules[rule]:
            raise ConfigError(
                f"rules.{rule} is not switchable. It is the doctrine this tool "
                f"exists to enforce (ROLES.md), and a repo that could turn it off "
                f"would be deciding whether it gets reviewed. Remove the line."
            )

    # The adversary sandbox is likewise not a preference. The gate below would
    # catch it too, but refusing here says WHY instead of listing consequences.
    codex = cfg.get("actors", {}).get("codex")
    if isinstance(codex, dict) and codex.get("sandbox", "read-only") != "read-only":
        raise ConfigError(
            f"actors.codex.sandbox is {codex.get('sandbox')!r}; adversary roles run "
            f"read-only, always. A build that needs to write does not get there "
            f"through this file."
        )

    write_access = rules.get("write_access", [])
    if not isinstance(write_access, list):
        raise ConfigError("rules.write_access: expected a list of role names")

    unknown = set(roles) - set(ALL_ROLES)
    if unknown:
        raise ConfigError(
            f"unknown role(s): {sorted(unknown)}. Known: {list(ALL_ROLES)}"
        )
    for role in ALL_ROLES:
        if role not in roles:
            raise ConfigError(f"role '{role}' is unset and has no default")
        if roles[role] == "cross":
            if role not in PAIRED_ADVERSARY_ROLES:
                raise ConfigError(
                    f"role '{role}': 'cross' only means something for a paired "
                    f"adversary role {list(PAIRED_ADVERSARY_ROLES)} -- there is no "
                    f"second draft here to cross-check against"
                )
            continue
        actors = roles[role] if isinstance(roles[role], list) else [roles[role]]
        for a in actors:
            if a not in KNOWN_ACTORS:
                raise ConfigError(
                    f"role '{role}': unknown actor {a!r}. Known: {list(KNOWN_ACTORS)}"
                )
    for role in write_access:
        if role not in ALL_ROLES:
            raise ConfigError(f"write_access names unknown role {role!r}")
    for actor, spec in cfg.get("actors", {}).items():
        if not isinstance(spec, dict):
            continue
        per_role = spec.get("roles") or {}
        _require_mapping(per_role, f"actors.{actor}.roles")
        for role, over in per_role.items():
            if role not in ALL_ROLES:
                raise ConfigError(f"actors.{actor}.roles names unknown role {role!r}")
            if not isinstance(over, dict):
                raise ConfigError(
                    f"actors.{actor}.roles.{role}: expected a mapping of model/effort"
                )
            illegal = set(over) - {"model", "effort"}
            if illegal:
                raise ConfigError(
                    f"actors.{actor}.roles.{role}: only model and effort may be "
                    f"overridden per role, not {sorted(illegal)} -- the sandbox is "
                    f"a property of the actor, and adversary roles stay read-only"
                )


# --- the gates -------------------------------------------------------------------

def check(cfg: dict) -> list[str]:
    """Return violations. Empty list means the arrangement is sound.

    None of the three checks below asks a config flag whether it should run.
    producer_never_reviews and adversary_read_only used to be consulted here and
    could therefore be set false by the repo under review -- which reported "gates
    OK" for an arrangement where the author graded itself with an open sandbox
    (audit 2026-08-30). _validate_shape() now refuses such a config outright, and
    these checks are unconditional so there is no second way in.
    """
    roles, rules = cfg["roles"], cfg.get("rules", {})
    return (
        _producer_never_reviews(roles)
        + _adversaries_are_read_only(cfg, roles)
        + _write_access_matches_the_roles(rules)
    )


def _producer_never_reviews(roles: dict) -> list[str]:
    problems: list[str] = []
    for producer, reviewer in _pairs():
        made_by, graded_by = roles[producer], roles[reviewer]
        if isinstance(made_by, list):
            # Dual draft: each draft is graded by the other author, so the
            # reviewer must be that cross-check and not a single actor who also
            # wrote one of the drafts.
            if len(set(made_by)) < 2:
                # A one-element or repeated author list used to sail through here:
                # `plan: [claude]` + `plan-review: cross` resolved to "claude
                # cross-checks claude" and reported gates OK. There is no second
                # reader in that arrangement, only the word for one.
                problems.append(
                    f"'{producer}' is a dual draft but names {made_by} -- a "
                    f"cross-check needs two DISTINCT authors, so that each draft "
                    f"is graded by the one who did not write it."
                )
            elif graded_by != "cross":
                problems.append(
                    f"'{producer}' has {len(made_by)} authors {made_by}, so "
                    f"'{reviewer}' must be 'cross' (each draft graded by the "
                    f"other author) -- it is '{graded_by}', who co-wrote one."
                )
        elif graded_by == "cross":
            problems.append(
                f"'{reviewer}' is 'cross' but '{producer}' has a single author "
                f"-- there is nothing to cross-check."
            )
        elif made_by == graded_by:
            problems.append(
                f"'{made_by}' both produces '{producer}' and grades it as "
                f"'{reviewer}' -- the maker never grades the thing."
            )
    return problems


def _adversaries_are_read_only(cfg: dict, roles: dict) -> list[str]:
    problems: list[str] = []
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
    return problems


def _write_access_matches_the_roles(rules: dict) -> list[str]:
    problems: list[str] = []
    allowed = set(rules.get("write_access", []))
    for role in ALL_ROLES:
        if role in ADVERSARY_ROLES and role in allowed:
            problems.append(f"'{role}' is an adversary role and cannot hold write_access.")
        if role in PRODUCER_ROLES and role not in allowed:
            problems.append(f"'{role}' produces an artefact but lacks write_access.")
    return problems


def _pairs() -> list[tuple[str, str]]:
    """Flatten PAIRS to (producer, reviewer) tuples, one per grader."""
    return [(p, r) for p, rs in PAIRS.items() for r in rs]


def _actors_for(roles: dict, role: str) -> list[str]:
    """Resolve 'cross' to the concrete authors it stands for."""
    value = roles[role]
    if value == "cross":
        producer = next(p for p, rs in PAIRS.items() if role in rs)
        authors = roles[producer]
        return authors if isinstance(authors, list) else [authors]
    return value if isinstance(value, list) else [value]


def actor_spec(cfg: dict, role: str) -> list[dict]:
    """The concrete actor(s) for a role with per-role model/effort applied.

    One dict per actor: {"actor", "model", "effort", "sandbox", "fresh_subagent"}
    as far as the actor defines them. This is what a skill reads to build the
    wrapper call -- the skill never chooses a model itself.
    """
    out = []
    for actor in _actors_for(cfg["roles"], role):
        base = {k: v for k, v in cfg["actors"].get(actor, {}).items() if k != "roles"}
        over = (cfg["actors"].get(actor, {}).get("roles") or {}).get(role, {})
        spec = {"actor": actor, **base, **over}
        out.append(spec)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--role", help="print only this role's actor(s)")
    ap.add_argument("--spec", metavar="ROLE",
                    help="print the role's actor with model/effort/sandbox resolved "
                         "(per-role overrides applied); one line per actor")
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

    if args.spec:
        if args.spec not in ALL_ROLES:
            print(f"claudex-roles: unknown role {args.spec!r}", file=sys.stderr)
            return 2
        if problems:
            print("claudex-roles: refusing to resolve, gates violated:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        for spec in actor_spec(cfg, args.spec):
            fields = " ".join(f"{k}={v}" for k, v in spec.items() if k != "actor")
            print(f"{spec['actor']} {fields}".rstrip())
        return 0

    if args.json:
        print(json.dumps(
            {"config": str(path) if path else None, "roles": cfg["roles"],
             "actors": cfg["actors"], "rules": cfg.get("rules", {}),
             "violations": problems}, indent=2))
        return 1 if problems else 0

    print(f"config: {path or 'built-in defaults (no .claudex.yaml found)'}")
    print()
    for producer, reviewer in _pairs():
        made = cfg["roles"][producer]
        made_s = " + ".join(made) if isinstance(made, list) else made
        graded = ", ".join(
            f"{sp['actor']}" + (f" ({sp['model']}/{sp['effort']})" if sp.get("model") else "")
            for sp in actor_spec(cfg, reviewer)
        )
        note = "  (cross-check)" if cfg["roles"][reviewer] == "cross" else ""
        print(f"  {producer:<6} {made_s:<16} -> {reviewer:<16} {graded}{note}")
    for role in STANDALONE_ADVERSARY_ROLES:
        graded = ", ".join(_actors_for(cfg["roles"], role))
        print(f"  {'(bestand)':<6} {'-':<16} -> {role:<16} {graded}")
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
