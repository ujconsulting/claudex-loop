"""claudex_roles: the security hunt's producer/verifier pair (plan A, stage 1).

docs/plans/2026-10-27-sicherheitskette/PLAN.md, approved in round 7:

- `hunt` is a PRODUCER role, fixed to `claude` (the hunt runs in `claudex-hunter` agents,
  so the actual producer is Claude; any other value is refused);
- `security-verify` is its PAIRED adversary, default `codex`; `security-verify` == `hunt`
  is refused by producer_never_reviews like every other pair;
- `audit` stays a standalone adversary, untouched (round 2: making it a producer broke
  the gates);
- a legacy `.claudex.yaml` that sets its own `rules.write_access` without `hunt` keeps
  working: every old role resolves, `--explain` exits 0 and reports the hunt as not
  configured, and ONLY `--spec/--role hunt|security-verify` refuse.

Written before the resolver change and seen failing first.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import claudex_roles as cr  # noqa: E402

LEGACY = "rules:\n  write_access: [plan, build, docs]\n"


def _cfg(**over):
    cfg = cr._merge(copy.deepcopy(cr.DEFAULTS), over)
    cr._validate_shape(cfg)
    return cfg


def _repo(tmp_path, monkeypatch, text):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".claudex.yaml").write_text(text, encoding="utf-8")
    monkeypatch.chdir(tmp_path)


def test_defaults_carry_the_pair_and_pass():
    cfg = _cfg()
    assert cfg["roles"]["hunt"] == "claude"
    assert cfg["roles"]["security-verify"] == "codex"
    assert "hunt" in cfg["rules"]["write_access"]
    assert ("hunt", "security-verify") in cr._pairs(cfg["rules"])
    assert cr.check(cfg) == []


def test_audit_stays_a_standalone_adversary():
    assert "audit" in cr.STANDALONE_ADVERSARY_ROLES
    assert "audit" not in cr.PRODUCER_ROLES
    assert "hunt" in cr.PRODUCER_ROLES
    assert "security-verify" in cr.PAIRED_ADVERSARY_ROLES


def test_hunt_must_be_claude():
    cfg = _cfg(roles={"hunt": "codex", "security-verify": "claude"})
    assert any("hunt" in p and "claude" in p for p in cr.check(cfg))


def test_the_verifier_must_not_be_the_hunter():
    cfg = _cfg(roles={"security-verify": "claude"})
    assert any("security-verify" in p for p in cr.check(cfg))


def test_security_verify_cannot_hold_write_access():
    cfg = _cfg(rules={"write_access": ["plan", "build", "docs", "hunt", "security-verify"]})
    assert any("security-verify" in p and "write_access" in p for p in cr.check(cfg))


def test_security_verify_spec_is_read_only_codex(capsys):
    (spec,) = cr.actor_spec(_cfg(), "security-verify")
    assert (spec["actor"], spec["sandbox"]) == ("codex", "read-only")


def test_legacy_config_explain_stays_green(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, LEGACY)
    assert cr.main(["--explain"]) == 0
    out = capsys.readouterr().out
    assert "gates OK" in out
    assert "hunt" in out and "not configured" in out


def test_legacy_config_resolves_old_roles(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, LEGACY)
    for role in ("plan-review", "code-review", "exposure-review", "docs-review", "audit"):
        assert cr.main(["--spec", role]) == 0, role


def test_legacy_config_that_only_overrides_roles_does_not_enable_the_hunt(tmp_path, monkeypatch, capsys):
    """Inspection round 1, finding 18: a legacy file without write_access used to inherit
    the new roles AND hunt's write access, silently enabling the hunt."""
    _repo(tmp_path, monkeypatch, "roles:\n  plan: claude\n  plan-review: codex\n")
    assert cr.main(["--explain"]) == 0
    assert "not configured" in capsys.readouterr().out
    assert cr.main(["--spec", "security-verify"]) == 2


def test_a_config_naming_the_pair_enables_it(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, "roles:\n  hunt: claude\n  security-verify: codex\n")
    assert cr.main(["--spec", "security-verify"]) == 0


def test_the_repo_cannot_declare_the_pair_through_the_internal_flag(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, "rules:\n  _hunt_declared: true\nroles:\n  plan: claude\n")
    assert cr.main(["--spec", "security-verify"]) == 2


def test_legacy_config_refuses_only_the_hunt_roles(tmp_path, monkeypatch, capsys):
    _repo(tmp_path, monkeypatch, LEGACY)
    for role in ("hunt", "security-verify"):
        assert cr.main(["--spec", role]) == 2, role
        assert cr.main(["--role", role]) == 2, role
    err = capsys.readouterr().err
    assert "not configured" in err


import pytest  # noqa: E402


@pytest.mark.parametrize("value", [["claude"], ["codex"], [], ["claude", "codex"]])
def test_the_hunt_verifier_is_exactly_one_actor(value):
    """Inspection round 2, finding 29: `security-verify: [claude]` compared the string
    producer against a list and passed -- Claude graded its own hunt; `[]` named nobody."""
    with pytest.raises(cr.ConfigError):
        _cfg(roles={"security-verify": value})


def test_a_list_hunt_producer_is_refused():
    with pytest.raises(cr.ConfigError):
        _cfg(roles={"hunt": ["claude"]})


def test_a_list_reviewer_containing_the_producer_is_caught_for_every_pair():
    """The same comparison sat in producer_never_reviews for every pair, not only the hunt."""
    cfg = copy.deepcopy(cr.DEFAULTS)
    cfg["roles"]["plan"] = "claude"
    cfg["roles"]["plan-review"] = ["claude"]
    assert any("plan-review" in p for p in cr._producer_never_reviews(cfg["roles"], cfg["rules"]))


def test_an_empty_actor_list_is_refused_for_any_role():
    with pytest.raises(cr.ConfigError, match="empty"):
        _cfg(roles={"code-review": []})


def test_a_roles_only_legacy_config_names_the_missing_declarations(tmp_path, monkeypatch, capsys):
    """Closing gate C1: with write_access defaulted to include hunt, the refusal still said
    write_access was missing -- following that advice left the role unresolved."""
    _repo(tmp_path, monkeypatch, "roles:\n  plan: claude\n")
    assert cr.main(["--spec", "security-verify"]) == 2
    err = capsys.readouterr()
    text = err.out + err.err
    assert "does not declare both" in text
    assert "write_access does not list" not in text
