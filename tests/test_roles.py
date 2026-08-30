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


# --- audit 2026-08-30: the gates could be switched off by the reviewed repo -----
#
# A `.claudex.yaml` found in the working directory (or, before the fix, ANY
# ancestor of it) could set producer_never_reviews and adversary_read_only to
# false and hand codex `sandbox: danger-full-access` -- and the resolver printed
# "gates OK", exit 0, then reported that sandbox through --spec. The component
# whose only job is to answer "who may grade this" could be talked into "the
# author does, with write access", by a file inside the repo being reviewed.


def test_producer_never_reviews_cannot_be_switched_off():
    with pytest.raises(cr.ConfigError, match="not switchable"):
        _cfg(rules={"producer_never_reviews": False})


def test_adversary_read_only_cannot_be_switched_off():
    with pytest.raises(cr.ConfigError, match="not switchable"):
        _cfg(rules={"adversary_read_only": False})


def test_an_open_adversary_sandbox_is_refused_outright():
    with pytest.raises(cr.ConfigError, match="read-only"):
        _cfg(actors={"codex": {"sandbox": "danger-full-access"}})


def test_the_gate_fires_even_with_the_flag_forced_false_in_the_dict():
    """check() must not consult the flags at all, not merely default them true.

    _validate_shape() refuses a CONFIG that sets them false, so the only way to
    test the second line of defence is to poke the resolved dict directly --
    which is exactly the state an attacker would be aiming for. Asserting
    against defaults would have passed even if check() still read the flag.
    (CodeRabbit, 2026-08-30.)
    """
    cfg = _cfg(roles={"plan": "codex", "plan-review": "codex"})
    cfg["rules"]["producer_never_reviews"] = False
    cfg["rules"]["adversary_read_only"] = False
    assert any("never grades" in p for p in cr.check(cfg))


# --- audit 2026-08-30: `cross` certified a review that did not exist -----------


def test_cross_with_a_single_author_is_refused():
    problems = cr.check(_cfg(roles={"plan": ["claude"], "plan-review": "cross"}))
    assert any("two" in p and "plan" in p for p in problems)


def test_cross_with_no_authors_is_refused():
    problems = cr.check(_cfg(roles={"plan": [], "plan-review": "cross"}))
    assert problems


def test_cross_with_the_same_author_twice_is_refused():
    problems = cr.check(_cfg(roles={"plan": ["claude", "claude"], "plan-review": "cross"}))
    assert any("distinct" in p or "two" in p for p in problems)


def test_a_real_dual_draft_still_passes():
    assert cr.check(_cfg(roles={"plan": ["claude", "codex"], "plan-review": "cross"})) == []


# --- audit 2026-08-30: config was read from any ancestor, not the repo root ----


def test_the_config_comes_from_the_repo_root_not_a_nested_directory(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".claudex.yaml").write_text("roles:\n  audit: codex\n", encoding="utf-8")
    nested = repo / "services" / "api"
    nested.mkdir(parents=True)
    (nested / ".claudex.yaml").write_text("roles:\n  audit: claude\n", encoding="utf-8")
    monkeypatch.setattr(cr.Path, "home", staticmethod(lambda: tmp_path / "nohome"))
    assert cr.find_config(nested) == repo / ".claudex.yaml"


# --- audit 2026-08-30: malformed config escaped as a traceback, exit 1 ---------


def _run_with_config(tmp_path, monkeypatch, text):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".claudex.yaml").write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cr.Path, "home", staticmethod(lambda: tmp_path / "nohome"))
    return cr.main(["--explain"])


def test_a_list_where_a_mapping_belongs_exits_two_without_a_traceback(tmp_path, monkeypatch, capsys):
    rc = _run_with_config(tmp_path, monkeypatch, "actors:\n  - codex\n  - claude\n")
    assert rc == 2
    err = capsys.readouterr().err
    assert "claudex-roles:" in err
    # The prefix alone does not prove the absence of a traceback -- and the
    # traceback was the finding. (CodeRabbit, 2026-08-30.)
    assert "Traceback (most recent call last)" not in err
    assert "AttributeError" not in err


def test_a_scalar_roles_block_exits_two(tmp_path, monkeypatch):
    assert _run_with_config(tmp_path, monkeypatch, "roles: codex\n") == 2


def test_an_actor_roles_list_exits_two(tmp_path, monkeypatch):
    assert _run_with_config(tmp_path, monkeypatch, "actors:\n  codex:\n    roles:\n      - audit\n") == 2


def test_a_write_access_scalar_exits_two(tmp_path, monkeypatch):
    assert _run_with_config(tmp_path, monkeypatch, "rules:\n  write_access: plan\n") == 2
