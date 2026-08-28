"""claudex_roles: the exposure-review role and per-role model overrides.

The exposure pass runs on a different model/effort than the acceptance review,
but the choice lives in the role config, not in the skill. These tests pin the
contract the skills rely on: `--spec exposure-review` yields sol/medium by
default, the sandbox cannot be overridden per role, and the build's second
grader is walked by producer_never_reviews like the first.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import claudex_roles as cr  # noqa: E402


def _cfg(**over):
    cfg = copy.deepcopy(cr.DEFAULTS)
    cfg = cr._merge(cfg, over)
    cr._validate_shape(cfg)
    return cfg


def test_defaults_pass_the_gates():
    assert cr.check(_cfg()) == []


def test_exposure_review_is_a_second_grader_of_build():
    assert "exposure-review" in cr.PAIRED_ADVERSARY_ROLES
    assert ("build", "exposure-review") in cr._pairs()
    assert ("build", "code-review") in cr._pairs()


def test_exposure_review_spec_defaults_to_sol_medium_read_only():
    (spec,) = cr.actor_spec(_cfg(), "exposure-review")
    assert spec["actor"] == "codex"
    assert spec["model"] == "gpt-5.6-sol"
    assert spec["effort"] == "medium"
    assert spec["sandbox"] == "read-only"


def test_code_review_spec_is_untouched_by_the_override():
    (spec,) = cr.actor_spec(_cfg(), "code-review")
    assert spec["model"] == "gpt-5.6-terra"
    assert spec["effort"] == "high"


def test_sandbox_cannot_be_overridden_per_role():
    with pytest.raises(cr.ConfigError, match="only model and effort"):
        _cfg(actors={"codex": {"roles": {"exposure-review": {"sandbox": "danger-full-access"}}}})


def test_override_for_unknown_role_is_rejected():
    with pytest.raises(cr.ConfigError, match="unknown role"):
        _cfg(actors={"codex": {"roles": {"pentest": {"model": "x"}}}})


def test_delegation_needs_the_exposure_grader_to_flip_too():
    # build: codex with code-review flipped to claude but exposure-review left on
    # codex -- the maker would grade its own exposed surface.
    problems = cr.check(_cfg(roles={"build": "codex", "code-review": "claude"}))
    assert any("exposure-review" in p for p in problems)
    ok = cr.check(_cfg(roles={"build": "codex", "code-review": "claude",
                              "exposure-review": "claude"}))
    assert ok == []


def test_spec_cli_prints_model_and_effort(capsys):
    rc = cr.main(["--spec", "exposure-review"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("codex ")
    assert "model=gpt-5.6-sol" in out and "effort=medium" in out and "sandbox=read-only" in out
