"""sandbox_auth: the host side of B2's credential split (PLAN-B2-build.md section 6, unit U4).

The builder never holds a real token. This module reads the host's `auth.json` once,
read-only, and produces from that one source: the placeholder `auth.json` for the builder's
CODEX_HOME, the placeholder and the real header maps, the TOKEN message for the proxy, the
needle set for the response scan and the lifetime check against the run's deadline.

Every test works on FIXTURE files with fake values below pytest's tmp path. None reads the
real ~/.codex/auth.json, none runs a Codex login.

Written before scripts/sandbox_auth.py and seen failing first (module missing).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sandbox_auth  # noqa: E402

WINDOWS = os.name == "nt"
NOW = 1_800_000_000.0
DAY = 86400


# --------------------------------------------------------------------------- fixtures


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt(payload: dict, header: dict | None = None) -> str:
    header = header or {"alg": "RS256", "typ": "JWT", "kid": "fixture-kid"}
    return ".".join([
        _b64url(json.dumps(header).encode()),
        _b64url(json.dumps(payload).encode()),
        _b64url(secrets.token_bytes(64)),
    ])


class Fixture:
    """A fake host login. Every value is random per test and NOT a real credential."""

    def __init__(self, exp: int | None = None):
        self.account_id = "acct-" + secrets.token_hex(16)
        self.email = "fixture-" + secrets.token_hex(6) + "@example.invalid"
        self.user_id = "user-" + secrets.token_hex(10)
        self.refresh_token = "rt_fixture_" + secrets.token_urlsafe(40)
        self.api_key = "sk-fixture-" + secrets.token_hex(20)
        self.extra_secret = "extra-" + secrets.token_hex(12)
        self.exp = int(NOW + 10 * DAY) if exp is None else exp
        self.access_payload = {
            "exp": self.exp, "iat": int(NOW), "sub": self.user_id,
            "https://api.openai.com/auth": {"chatgpt_account_id": self.account_id},
        }
        self.access_token = _jwt(self.access_payload)
        self.id_payload = {
            "aud": ["app_fixture"], "email": self.email, "email_verified": True,
            "exp": int(NOW + 3600), "iat": int(NOW), "auth_time": int(NOW) - 60,
            "iss": "https://auth.openai.com", "sub": self.user_id,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": self.account_id,
                "chatgpt_plan_type": "fixtureplan",
                "chatgpt_user_id": self.user_id,
                "organizations": [{"id": "org-" + secrets.token_hex(8), "is_default": True}],
            },
        }
        self.id_token = _jwt(self.id_payload)

    def doc(self) -> dict:
        return {
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": None,
            "tokens": {
                "id_token": self.id_token,
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "account_id": self.account_id,
            },
            "last_refresh": "2026-10-30T10:00:00Z",
            "extra_field": self.extra_secret,
        }

    def secrets(self) -> list[str]:
        """Every value that must never show up in a message, a repr or the placeholder."""
        return [self.access_token, self.account_id, self.refresh_token, self.id_token,
                self.email, self.user_id, self.api_key, self.extra_secret,
                self.access_token.split(".")[1], self.access_token.split(".")[2],
                self.id_token.split(".")[1], self.id_token.split(".")[2]]


def write_home(tmp_path: Path, doc, name: str = "codex-home") -> Path:
    home = tmp_path / name
    home.mkdir()
    data = doc if isinstance(doc, bytes) else json.dumps(doc, indent=2).encode()
    (home / "auth.json").write_bytes(data)
    return home


def load(home: Path, min_exp: float = NOW + 3600 + 600, days: int = 30):
    return sandbox_auth.load(home, min_exp, days, now=NOW)


@pytest.fixture
def fx():
    return Fixture()


@pytest.fixture
def auth(tmp_path, fx):
    return load(write_home(tmp_path, fx.doc()))


def _decode_jwt_part(part: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def _names(obj) -> set:
    """Every key at every depth of a JSON value, nested objects in lists included."""
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k)
            out |= _names(v)
    elif isinstance(obj, list):
        for v in obj:
            out |= _names(v)
    return out


# --------------------------------------------------------------------------- placeholder


def test_placeholder_auth_json_has_the_measured_shape(auth):
    doc = json.loads(auth.placeholder_auth_json)
    assert doc["auth_mode"] == "chatgpt"
    assert doc["OPENAI_API_KEY"] is None
    tokens = doc["tokens"]
    # measurement 2026-11-01 (a): the key must be PRESENT and empty, else Codex silently
    # runs unauthenticated in API mode.
    assert "refresh_token" in tokens and tokens["refresh_token"] == ""
    assert isinstance(tokens["access_token"], str) and tokens["access_token"]
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        tokens["account_id"])
    parts = tokens["id_token"].split(".")
    assert len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts)
    assert _decode_jwt_part(parts[0])["alg"]


def test_placeholder_id_token_keeps_claim_names_only(auth, fx):
    tokens = json.loads(auth.placeholder_auth_json)["tokens"]
    payload = _decode_jwt_part(tokens["id_token"].split(".")[1])
    assert _names(payload) == _names(fx.id_payload)
    claim = payload["https://api.openai.com/auth"]
    # the account id claim names the PLACEHOLDER account, consistently with the header map
    assert claim["chatgpt_account_id"] == tokens["account_id"]
    assert isinstance(payload["email_verified"], bool)  # the claim keeps its JSON type
    assert isinstance(payload["aud"], list) and isinstance(payload["iat"], int)


def test_every_placeholder_exp_lies_placeholder_exp_days_ahead(tmp_path, fx):
    a = load(write_home(tmp_path, fx.doc()), days=30)
    payload = _decode_jwt_part(json.loads(a.placeholder_auth_json)["tokens"]["id_token"].split(".")[1])
    assert payload["exp"] == int(NOW) + 30 * DAY


def test_placeholder_contains_no_real_value(auth, fx):
    text = auth.placeholder_auth_json.decode("utf-8")
    for value in fx.secrets():
        assert value not in text
    for needle in auth.needles:
        assert needle not in auth.placeholder_auth_json


def test_placeholder_does_not_copy_unknown_top_level_keys(auth):
    doc = json.loads(auth.placeholder_auth_json)
    assert set(doc) == {"auth_mode", "OPENAI_API_KEY", "tokens", "last_refresh"}
    assert set(doc["tokens"]) == {"id_token", "access_token", "refresh_token", "account_id"}


def test_placeholders_are_fresh_per_load(tmp_path, fx):
    home = write_home(tmp_path, fx.doc())
    a, b = load(home), load(home)
    assert a.placeholder_map != b.placeholder_map


def test_placeholder_auth_json_is_ascii_utf8_without_bom(auth):
    assert not auth.placeholder_auth_json.startswith(b"\xef\xbb\xbf")
    auth.placeholder_auth_json.decode("ascii")


# --------------------------------------------------------------------------- header maps, message


def test_header_maps_share_lower_case_keys(auth):
    assert set(auth.placeholder_map) == set(auth.real_map) == {"authorization", "chatgpt-account-id"}
    for key in auth.real_map:
        assert key == key.lower()


def test_placeholder_map_matches_the_placeholder_file(auth):
    tokens = json.loads(auth.placeholder_auth_json)["tokens"]
    assert auth.placeholder_map == {
        "authorization": "Bearer " + tokens["access_token"],
        "chatgpt-account-id": tokens["account_id"],
    }


def test_real_map_carries_the_host_values(auth, fx):
    assert auth.real_map == {
        "authorization": "Bearer " + fx.access_token,
        "chatgpt-account-id": fx.account_id,
    }


def test_placeholder_and_real_values_differ(auth):
    for key in auth.real_map:
        assert auth.real_map[key] != auth.placeholder_map[key]
        assert auth.real_map[key] not in auth.placeholder_map[key]


def test_token_message_is_framed_as_the_interface_says(auth, fx):
    msg = auth.token_message
    head, _, body = msg.partition(b"\n")
    m = re.fullmatch(rb"TOKEN (\d+)", head)
    assert m and int(m.group(1)) == len(body)
    doc = json.loads(body)
    assert doc == {"headers": auth.real_map,
                   "needles_from": {"access_token": fx.access_token, "account_id": fx.account_id}}


def test_sha256_is_over_the_canonical_real_map(auth):
    canon = json.dumps(auth.real_map, sort_keys=True, separators=(",", ":")).encode()
    assert auth.sha256 == hashlib.sha256(canon).hexdigest()
    assert auth.mode == "chatgpt"


def test_exp_is_the_access_tokens_exp(auth, fx):
    assert auth.exp == fx.exp


def test_auth_json_without_auth_mode_and_without_api_key_is_chatgpt(tmp_path, fx):
    doc = fx.doc()
    del doc["auth_mode"]
    a = load(write_home(tmp_path, doc))
    assert a.mode == "chatgpt"


def test_chatgpt_mode_with_a_stored_api_key_is_accepted_and_the_key_dropped(tmp_path, fx):
    doc = fx.doc()
    doc["OPENAI_API_KEY"] = fx.api_key
    a = load(write_home(tmp_path, doc))
    assert fx.api_key.encode() not in a.placeholder_auth_json
    assert fx.api_key.encode() not in a.token_message


# --------------------------------------------------------------------------- needles


def _embedded_b64(secret: bytes, prefix_len: int, urlsafe: bool, tail: bytes) -> bytes:
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return enc(secrets.token_bytes(prefix_len) + secret + tail)


@pytest.mark.parametrize("component", ["token", "account", "header"])
def test_needles_catch_every_listed_encoding(auth, fx, component):
    secret = {"token": fx.access_token, "account": fx.account_id,
              "header": "Bearer " + fx.access_token}[component].encode()
    samples = [secret, secret.hex().encode(), secret.hex().upper().encode(),
               urllib.parse.quote(secret, safe="").encode(),
               urllib.parse.quote_plus(secret, safe="").encode(),
               "".join("%%%02X" % b for b in secret).encode(),
               "".join("%%%02x" % b for b in secret).encode()]
    for prefix_len in range(6):
        for urlsafe in (False, True):
            samples.append(_embedded_b64(secret, prefix_len, urlsafe, b"tail-bytes"))
            samples.append(_embedded_b64(secret, prefix_len, urlsafe, b""))  # padded, at the end
            samples.append(_embedded_b64(secret, prefix_len, urlsafe, b"").rstrip(b"="))
    for sample in samples:
        wrapped = b'{"data":"' + sample + b'"}'
        assert any(n in wrapped for n in auth.needles), (component, len(sample))


def test_needles_contain_the_bare_components(auth, fx):
    assert fx.access_token.encode() in auth.needles
    assert fx.account_id.encode() in auth.needles
    assert ("Bearer " + fx.access_token).encode() in auth.needles


def test_needles_are_unique_bytes_and_not_trivially_short(auth):
    assert len(auth.needles) == len(set(auth.needles))
    assert all(isinstance(n, bytes) and len(n) >= 8 for n in auth.needles)


def test_module_needles_function_matches_load(auth, fx):
    assert sandbox_auth.needles(fx.access_token, fx.account_id,
                                list(auth.real_map.values())) == auth.needles


def test_bare_token_in_json_body_is_caught_independently_of_the_header(auth, fx):
    # round 4 finding 1: an upstream that parsed the scheme away reflects only T.
    for body in (json.dumps({"access_token": fx.access_token}).encode(),
                 base64.b64encode(json.dumps({"access_token": fx.access_token}).encode())):
        hits = [n for n in auth.needles if n in body]
        assert hits
        assert not any(n.startswith(b"Bearer") for n in hits)


def test_needles_refuse_bad_components():
    with pytest.raises(sandbox_auth.AuthRefused):
        sandbox_auth.needles("", "acct-123456789", [])
    with pytest.raises(sandbox_auth.AuthRefused):
        sandbox_auth.needles("tok-123456789", "short", [])


# --------------------------------------------------------------------------- scan_and_redact


def test_scan_and_redact_removes_every_encoding(auth, fx):
    token = fx.access_token.encode()
    pieces = [token, fx.account_id.encode(), b"Bearer " + token, token.hex().encode(),
              base64.b64encode(b"x" + token), base64.urlsafe_b64encode(b"xy" + token),
              urllib.parse.quote(b"Bearer " + token, safe="").encode()]
    for piece in pieces:
        data = b"log line before " + piece + b" after\n"
        out, hits = sandbox_auth.scan_and_redact(data, auth.needles)
        assert hits >= 1
        assert not any(n in out for n in auth.needles)
        assert out.startswith(b"log line before ") and out.endswith(b" after\n")
        assert b"[REDACTED]" in out


def test_scan_and_redact_leaves_clean_data_alone(auth):
    data = b'{"host":"chatgpt.com","route":"forward","status":200}\n' * 3
    assert sandbox_auth.scan_and_redact(data, auth.needles) == (data, 0)


def test_scan_and_redact_merges_overlapping_hits(auth, fx):
    token = fx.access_token.encode()
    data = b"A" + b"Bearer " + token + token + b"Z"
    out, hits = sandbox_auth.scan_and_redact(data, auth.needles)
    assert out == b"A[REDACTED]Z" and hits == 1


def test_scan_and_redact_takes_bytes_only(auth):
    with pytest.raises(TypeError):
        sandbox_auth.scan_and_redact("text", auth.needles)


# --------------------------------------------------------------------------- lifetime


def test_token_expiring_before_the_run_deadline_is_refused(tmp_path):
    f = Fixture(exp=int(NOW + 1000))
    home = write_home(tmp_path, f.doc())
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(home, min_exp=NOW + 3600 + 600)
    assert "lifetime" in str(ei.value)
    _assert_clean(ei.value, f)


def test_token_exactly_at_min_exp_is_refused(tmp_path):
    f = Fixture(exp=int(NOW + 4200))
    with pytest.raises(sandbox_auth.AuthRefused):
        load(write_home(tmp_path, f.doc()), min_exp=NOW + 4200)


def test_placeholder_lifetime_must_outlast_the_run(tmp_path):
    f = Fixture(exp=int(NOW + 400 * DAY))
    with pytest.raises(sandbox_auth.AuthRefused):
        load(write_home(tmp_path, f.doc()), min_exp=NOW + 2 * DAY, days=1)


@pytest.mark.parametrize("days", [0, -1, True, 1.5, "30", 366])
def test_placeholder_exp_days_is_validated(tmp_path, fx, days):
    with pytest.raises(sandbox_auth.AuthRefused):
        load(write_home(tmp_path, fx.doc()), days=days)


@pytest.mark.parametrize("min_exp", [True, "1", None, float("nan"), float("inf")])
def test_min_exp_is_validated(tmp_path, fx, min_exp):
    with pytest.raises(sandbox_auth.AuthRefused):
        load(write_home(tmp_path, fx.doc()), min_exp=min_exp)


def test_now_defaults_to_the_clock(tmp_path):
    f = Fixture(exp=int(time.time() + 10 * DAY))
    a = sandbox_auth.load(write_home(tmp_path, f.doc()), time.time() + 4200, 30)
    assert a.exp == f.exp


# --------------------------------------------------------------------------- refusals


def _assert_clean(exc: BaseException, f: Fixture) -> None:
    """No secret in the message, args or repr; no chained exception holding the document."""
    texts = [str(exc), repr(exc)] + [repr(a) for a in exc.args]
    for t in texts:
        for value in f.secrets():
            assert value not in t
        t.encode("ascii")
    assert exc.__cause__ is None
    assert exc.__context__ is None


def _mutate(f: Fixture, change) -> dict:
    doc = f.doc()
    change(doc)
    return doc


REFUSALS = {
    "api_key_mode": lambda d: d.update(auth_mode="apikey"),
    "api_key_without_mode": lambda d: (d.pop("auth_mode"), d.update(OPENAI_API_KEY="sk-fixture-x" * 3)),
    "unknown_mode": lambda d: d.update(auth_mode="chatgptAuthTokens"),
    "mode_not_string": lambda d: d.update(auth_mode=1),
    "api_key_not_string": lambda d: (d.pop("auth_mode"), d.update(OPENAI_API_KEY=5)),
    "no_tokens": lambda d: d.pop("tokens"),
    "tokens_not_object": lambda d: d.update(tokens=["x"]),
    "no_access_token": lambda d: d["tokens"].pop("access_token"),
    "empty_access_token": lambda d: d["tokens"].update(access_token=""),
    "access_token_not_jwt": lambda d: d["tokens"].update(access_token="opaque-" + "a" * 40),
    "access_token_bad_payload": lambda d: d["tokens"].update(
        access_token="eyJhbGciOiJub25lIn0." + _b64url(b"not json") + ".c2ln"),  # gitleaks:allow -- malformed fixture
    "access_token_payload_not_object": lambda d: d["tokens"].update(
        access_token="eyJhbGciOiJub25lIn0." + _b64url(b"[1,2]") + ".c2ln"),  # gitleaks:allow -- malformed fixture
    "access_token_without_exp": lambda d: d["tokens"].update(access_token=_jwt({"sub": "x"})),
    "access_token_exp_not_int": lambda d: d["tokens"].update(access_token=_jwt({"exp": "soon"})),
    "access_token_exp_bool": lambda d: d["tokens"].update(access_token=_jwt({"exp": True})),
    "access_token_header_injection": lambda d: d["tokens"].update(
        access_token=d["tokens"]["access_token"] + "\r\nX-Evil: 1"),
    "access_token_not_string": lambda d: d["tokens"].update(access_token=12345),
    "no_account_id": lambda d: d["tokens"].pop("account_id"),
    "account_id_bad_chars": lambda d: d["tokens"].update(account_id="acct 1234\r\nx: y"),
    "account_id_too_short": lambda d: d["tokens"].update(account_id="abc"),
    "account_id_not_string": lambda d: d["tokens"].update(account_id=None),
    "no_id_token": lambda d: d["tokens"].pop("id_token"),
    "id_token_not_jwt": lambda d: d["tokens"].update(id_token="not-a-jwt"),
    "id_token_payload_not_object": lambda d: d["tokens"].update(
        id_token="eyJhbGciOiJub25lIn0." + _b64url(b'"str"') + ".c2ln"),  # gitleaks:allow -- malformed fixture
    "id_token_bad_chars": lambda d: d["tokens"].update(id_token="aaa.b!b.ccc"),
    "id_token_undecodable": lambda d: d["tokens"].update(id_token="aaa.b.ccc"),
}


def test_a_placeholder_that_would_carry_a_real_value_is_refused(tmp_path, fx, monkeypatch):
    # the last check before returning: the builder-side artefacts are scanned with the needles
    class Same:
        def __str__(self):
            return fx.account_id
    monkeypatch.setattr(sandbox_auth.uuid, "uuid4", lambda: Same())
    with pytest.raises(sandbox_auth.AuthRefused, match="placeholder artefact") as ei:
        load(write_home(tmp_path, fx.doc()))
    _assert_clean(ei.value, fx)


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_every_malformed_or_foreign_login_is_refused_without_values(tmp_path, fx, case):
    home = write_home(tmp_path, _mutate(fx, REFUSALS[case]))
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(home)
    _assert_clean(ei.value, fx)


def test_api_key_mode_says_so(tmp_path, fx):
    home = write_home(tmp_path, _mutate(fx, REFUSALS["api_key_mode"]))
    with pytest.raises(sandbox_auth.AuthRefused, match="API-key"):
        load(home)


@pytest.mark.parametrize("raw", [b"", b"{not json", b"[1, 2]", b"null", b'"string"',
                                 b"\xff\xfe{}", b'{"a": 1, "a": 2}'])
def test_unreadable_documents_are_refused(tmp_path, fx, raw):
    # the secrets are mixed into the bytes so a leaking parser error would show them
    data = raw + b" " + fx.access_token.encode() if raw.startswith(b"{not") else raw
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(write_home(tmp_path, data))
    _assert_clean(ei.value, fx)


def test_invalid_json_with_a_secret_inside_does_not_leak_it(tmp_path, fx):
    data = json.dumps(fx.doc()).encode()[:-1] + b",,}"
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(write_home(tmp_path, data))
    _assert_clean(ei.value, fx)


def test_oversized_file_is_refused(tmp_path, fx):
    doc = fx.doc()
    doc["padding"] = "x" * (64 * 1024)
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(write_home(tmp_path, doc))
    _assert_clean(ei.value, fx)


def test_missing_file_is_refused(tmp_path):
    home = tmp_path / "empty-home"
    home.mkdir()
    with pytest.raises(sandbox_auth.AuthRefused):
        load(home)


def test_missing_codex_home_is_refused(tmp_path):
    with pytest.raises(sandbox_auth.AuthRefused):
        load(tmp_path / "does-not-exist")


def test_directory_named_auth_json_is_refused(tmp_path):
    home = tmp_path / "h"
    (home / "auth.json").mkdir(parents=True)
    with pytest.raises(sandbox_auth.AuthRefused):
        load(home)


def test_linked_auth_json_is_refused(tmp_path, fx):
    real = write_home(tmp_path, fx.doc(), "real-home")
    home = tmp_path / "linked-home"
    home.mkdir()
    try:
        os.symlink(real / "auth.json", home / "auth.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available to this user")
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(home)
    _assert_clean(ei.value, fx)


def test_linked_codex_home_is_refused(tmp_path, fx):
    real = write_home(tmp_path, fx.doc(), "real-home")
    link = tmp_path / "linked-home"
    if WINDOWS:
        import _winapi
        _winapi.CreateJunction(str(real), str(link))
    else:
        link.symlink_to(real, target_is_directory=True)
    with pytest.raises(sandbox_auth.AuthRefused) as ei:
        load(link)
    _assert_clean(ei.value, fx)


@pytest.mark.skipif(WINDOWS, reason="FIFOs are POSIX only")
def test_fifo_auth_json_is_refused_without_blocking(tmp_path):
    home = tmp_path / "h"
    home.mkdir()
    os.mkfifo(home / "auth.json")
    with pytest.raises(sandbox_auth.AuthRefused):
        load(home)


def test_codex_home_must_be_a_path_like(fx):
    with pytest.raises(sandbox_auth.AuthRefused):
        sandbox_auth.load(None, NOW + 4200, 30, now=NOW)


# --------------------------------------------------------------------------- no value anywhere


def test_auth_repr_and_str_show_no_value(auth, fx):
    for text in (repr(auth), str(auth)):
        for value in fx.secrets():
            assert value not in text
        for value in auth.placeholder_map.values():
            assert value not in text
        assert "chatgpt" in text


def test_auth_has_no_instance_dict_to_dump(auth):
    with pytest.raises(TypeError):
        vars(auth)


def test_load_never_writes_the_host_file_or_its_directory(tmp_path, fx):
    home = write_home(tmp_path, fx.doc())
    before = (home / "auth.json").read_bytes()
    st = os.stat(home / "auth.json")
    load(home)
    assert (home / "auth.json").read_bytes() == before
    assert os.stat(home / "auth.json").st_mtime_ns == st.st_mtime_ns
    assert sorted(p.name for p in home.iterdir()) == ["auth.json"]


def test_nothing_is_printed(tmp_path, fx, capsys):
    home = write_home(tmp_path, fx.doc())
    load(home)
    bad = write_home(tmp_path, _mutate(fx, REFUSALS["api_key_mode"]), "bad-home")
    with pytest.raises(sandbox_auth.AuthRefused):
        load(bad)
    out, err = capsys.readouterr()
    assert out == "" and err == ""


def test_module_is_stdlib_only():
    source = (Path(sandbox_auth.__file__)).read_text(encoding="utf-8")
    imported = set(re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)", source, re.M))
    allowed = {"__future__", "base64", "hashlib", "json", "math", "os", "re", "secrets", "sys",
               "time", "urllib", "uuid", "pathlib", "hunt_io", "binascii", "typing"}
    assert imported <= allowed, imported - allowed


def test_module_messages_are_ascii():
    source = (Path(sandbox_auth.__file__)).read_bytes()
    source.decode("ascii")
