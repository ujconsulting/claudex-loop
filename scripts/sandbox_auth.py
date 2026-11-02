#!/usr/bin/env python3
"""The host side of the B2 credential split: the builder never holds a real token.

Plan: docs/plans/2026-10-27-sicherheitskette/PLAN-B2-build.md, approach 6 (unit U4), with the
measured facts of PLAN-B2-REVIEW-LOG.md "Step 0 measurements, proxy design (2026-11-01)".

`load()` reads `$CODEX_HOME/auth.json` ONCE, read-only, through hunt_io.read_at (no link or
reparse point at the home or the file, regular file, at most 64 KiB). It never writes, prints or
logs anything. From that one source it produces:

  placeholder_auth_json  the builder's auth.json: auth_mode "chatgpt", a JWT-shaped id_token that
                         keeps only the real token's claim NAMES (fake values of the same JSON
                         type, random signature), an opaque random access_token, the key
                         "refresh_token" present and EMPTY (measurement (a): without the key Codex
                         silently runs unauthenticated in API mode), a fake UUID account id, every
                         "exp" `placeholder_exp_days` ahead (an exp in the past caused a refresh
                         storm). Unknown top-level keys of the host file are never copied.
  placeholder_map        {"authorization": "Bearer <placeholder>", "chatgpt-account-id": <fake>}
                         -- goes into the proxy's spec;
  real_map               the same keys with the host's values -- only in `token_message`;
  token_message          b"TOKEN <len>\\n" + JSON {"headers": real_map, "needles_from":
                         {"access_token": ..., "account_id": ...}}, no trailing newline;
  needles                for the bare access token, the account id and every complete real header
                         value: raw, base64 standard and URL-safe at all three alignments (inner
                         core, padded tail, unpadded tail), lower and upper hex, percent-encoding
                         (quote, quote_plus, every byte escaped in both cases);
  exp, mode, sha256      the access token's JWT exp, "chatgpt", sha256 of the canonical real map
                         (what the manifest records).

Refused (AuthRefused): API-key mode (auth_mode "apikey", or no auth_mode with an OPENAI_API_KEY),
any other auth_mode, a malformed document (invalid UTF-8 or JSON, duplicate keys, not an object),
missing or malformed tokens, an access token that is not JWT-shaped or has no numeric exp (its
lifetime cannot be checked), a header-unsafe token or account id, an access token whose exp is not
beyond `min_exp` (the caller passes now + timeout + 600 s), a placeholder lifetime that would not
outlast the run, and a link, special file, missing or oversized file.

No refusal carries a value: messages name fields only, and every AuthRefused is raised outside the
except block that detected the problem, so neither __cause__ nor __context__ holds a parser error
(json.JSONDecodeError keeps the whole document in `.doc`). `repr(Auth)` shows mode, exp, the hash
and counts, never a value. The proxy, not this module, injects the real values; see
scripts/sandbox_proxy.py.

Stdlib only. Messages are ASCII only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hunt_io  # noqa: E402

MAX_AUTH_BYTES = 64 * 1024
MAX_TOKEN_CHARS = 16 * 1024
MAX_PLACEHOLDER_DAYS = 365
DAY = 86400
HEADER_KEYS = ("authorization", "chatgpt-account-id")
REDACTED = b"[REDACTED]"
MIN_NEEDLE = 8

_JWT_PART = re.compile(r"[A-Za-z0-9_-]+")
_ACCOUNT_ID = re.compile(r"[A-Za-z0-9_-]{8,128}")
_CLAIM_NAME = re.compile(r"[\x21-\x7e]{1,128}")
_ACCOUNT_CLAIMS = {"chatgpt_account_id", "account_id"}
_NOW_CLAIMS = {"iat", "nbf", "auth_time"}
_MAX_DEPTH = 6
_MAX_LIST = 16


class AuthRefused(Exception):
    """The host login cannot be used for a sandboxed build. The message never holds a value."""


class Auth:
    """Result of load(). Attributes hold real values; repr/str show none of them."""

    __slots__ = ("placeholder_auth_json", "placeholder_map", "real_map", "token_message",
                 "exp", "mode", "sha256", "needles")

    def __init__(self, *, placeholder_auth_json: bytes, placeholder_map: dict, real_map: dict,
                 token_message: bytes, exp: int, mode: str, sha256: str, needles: list):
        self.placeholder_auth_json = placeholder_auth_json
        self.placeholder_map = placeholder_map
        self.real_map = real_map
        self.token_message = token_message
        self.exp = exp
        self.mode = mode
        self.sha256 = sha256
        self.needles = needles

    def __repr__(self) -> str:
        return (f"Auth(mode={self.mode!r}, exp={self.exp}, sha256={self.sha256}, "
                f"headers={sorted(self.real_map)}, needles={len(self.needles)})")

    __str__ = __repr__

    def __reduce__(self):  # no pickling: a pickle would carry the real values to disk
        raise TypeError("Auth is not serialisable")


# --------------------------------------------------------------------------- parsing helpers


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _json_object(data: bytes, what: str) -> dict:
    """Parse `data` as one JSON object. The refusal is raised OUTSIDE the except block."""
    doc, ok = None, True
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (UnicodeDecodeError, ValueError, RecursionError):
        ok = False
    if not ok:
        raise AuthRefused(f"refusing: {what} is not valid UTF-8 JSON without duplicate keys")
    if not isinstance(doc, dict):
        raise AuthRefused(f"refusing: {what} is not a JSON object")
    return doc


def _b64url_decode(part: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (ValueError, TypeError):
        return None


def _jwt_payload(token: str, what: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3 or not all(_JWT_PART.fullmatch(p) for p in parts):
        raise AuthRefused(f"refusing: {what} is not JWT-shaped")
    raw = _b64url_decode(parts[1])
    if raw is None:
        raise AuthRefused(f"refusing: {what} has an undecodable payload")
    return _json_object(raw, f"the payload of {what}")


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _token_string(tokens: dict, key: str) -> str:
    value = tokens.get(key)
    if not isinstance(value, str) or not value:
        raise AuthRefused(f"refusing: tokens.{key} is missing or not a non-empty string")
    if len(value) > MAX_TOKEN_CHARS:
        raise AuthRefused(f"refusing: tokens.{key} is longer than {MAX_TOKEN_CHARS} characters")
    return value


def _resolve_mode(doc: dict) -> str:
    mode = doc.get("auth_mode")
    api_key = doc.get("OPENAI_API_KEY")
    if api_key is not None and not isinstance(api_key, str):
        raise AuthRefused("refusing: OPENAI_API_KEY is neither null nor a string")
    if mode is None:
        # codex-rs resolves a missing auth_mode to API-key mode when a key is stored.
        if api_key:
            raise AuthRefused("refusing: API-key mode (OPENAI_API_KEY without auth_mode); "
                              "the sandboxed build needs a ChatGPT login (codex login)")
        return "chatgpt"
    if not isinstance(mode, str):
        raise AuthRefused("refusing: auth_mode is not a string")
    if mode.lower() == "apikey":
        raise AuthRefused("refusing: API-key mode (auth_mode apikey); "
                          "the sandboxed build needs a ChatGPT login (codex login)")
    if mode != "chatgpt":
        raise AuthRefused("refusing: auth_mode is not chatgpt")
    return "chatgpt"


# --------------------------------------------------------------------------- placeholder


def _fake(name: str | None, value, ctx: dict, depth: int):
    """A value of the same JSON type that carries nothing of the original."""
    if depth > _MAX_DEPTH:
        return None
    if isinstance(value, dict):
        return {k: _fake(k, v, ctx, depth + 1)
                for k, v in value.items() if isinstance(k, str) and _CLAIM_NAME.fullmatch(k)}
    if isinstance(value, list):
        return [_fake(None, v, ctx, depth + 1) for v in value[:_MAX_LIST]]
    if isinstance(value, bool):
        return False
    if name == "exp":
        return ctx["exp"]
    if name in _NOW_CLAIMS and _is_number(value):
        return ctx["now"]
    if name in _ACCOUNT_CLAIMS and isinstance(value, str):
        return ctx["account_id"]
    if isinstance(value, (int, float)):
        return 0
    if isinstance(value, str):
        return "placeholder"
    return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _placeholder_id_token(real_claims: dict, ctx: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": "claudex-placeholder"}
    claims = _fake(None, real_claims, ctx, 0)
    claims["exp"] = ctx["exp"]  # always present, also when the real id_token had none
    return ".".join([_b64url(json.dumps(header, separators=(",", ":")).encode("ascii")),
                     _b64url(json.dumps(claims, separators=(",", ":")).encode("ascii")),
                     _b64url(secrets.token_bytes(256))])


# --------------------------------------------------------------------------- needles


def _b64_forms(secret: bytes) -> list[bytes]:
    """base64 forms of `secret` embedded at any offset: for each of the three alignments the
    position-independent inner core, the padded tail and the unpadded tail."""
    out = []
    for align in range(3):
        start = -(-8 * align // 6)                # first char determined by `secret` alone
        stop = (8 * (align + len(secret))) // 6   # one past the last such char
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            full = enc(b"\x00" * align + secret)
            out += [full[start:stop], full[start:], full[start:].rstrip(b"=")]
    return out


def _forms(secret: bytes) -> list[bytes]:
    out = [secret]
    out += _b64_forms(secret)
    out += [secret.hex().encode("ascii"), secret.hex().upper().encode("ascii")]
    out += [urllib.parse.quote(secret, safe="").encode("ascii"),
            urllib.parse.quote_plus(secret, safe="").encode("ascii"),
            "".join("%%%02X" % b for b in secret).encode("ascii"),
            "".join("%%%02x" % b for b in secret).encode("ascii")]
    return out


def needles(access_token: str, account_id: str, header_values) -> list[bytes]:
    """Byte strings the response scan must never let through (PLAN-B2 approach 6, round 4
    finding 1): every encoding of the bare token, the account id and each full header value."""
    components = [access_token, account_id, *list(header_values)]
    for c in components:
        if not isinstance(c, str) or len(c) < MIN_NEEDLE:
            raise AuthRefused(f"refusing: a needle component is not a string of at least "
                              f"{MIN_NEEDLE} characters")
    out, seen = [], set()
    for c in dict.fromkeys(components):
        for n in _forms(c.encode("utf-8")):
            if len(n) >= MIN_NEEDLE and n not in seen:
                seen.add(n)
                out.append(n)
    return out


def scan_and_redact(data: bytes, needle_list) -> tuple[bytes, int]:
    """Replace every occurrence of any needle with [REDACTED]; return (bytes, number of merged
    hits). Overlapping or adjacent hits are merged into one redaction."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("scan_and_redact takes bytes")
    data = bytes(data)
    spans = []
    for n in needle_list:
        if not isinstance(n, (bytes, bytearray)) or not n:
            raise TypeError("needles must be non-empty bytes")
        i = data.find(n)
        while i != -1:
            spans.append((i, i + len(n)))
            i = data.find(n, i + 1)
    if not spans:
        return data, 0
    spans.sort()
    merged = [list(spans[0])]
    for a, b in spans[1:]:
        if a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    out, pos = [], 0
    for a, b in merged:
        out += [data[pos:a], REDACTED]
        pos = b
    out.append(data[pos:])
    return b"".join(out), len(merged)


# --------------------------------------------------------------------------- load


def _read_auth_file(codex_home) -> bytes:
    if not isinstance(codex_home, (str, os.PathLike)):
        raise AuthRefused("refusing: codex_home is not a path")
    status, value = hunt_io.read_at(Path(codex_home), "auth.json", MAX_AUTH_BYTES)
    if status != "ok":
        # `value` is a fixed reason word from hunt_io (missing, link, special, size, ...)
        raise AuthRefused(f"refusing: CODEX_HOME/auth.json is not usable ({value}); it must be a "
                          f"regular file of at most {MAX_AUTH_BYTES} bytes reached without links")
    return value


def load(codex_home, min_exp, placeholder_exp_days, *, now: float | None = None) -> Auth:
    """Read the host login once and build every B2 credential artefact from it.

    `min_exp`: the access token must expire strictly after this epoch (now + timeout + 600 s).
    `placeholder_exp_days`: policy `build.placeholder_exp_days`. `now`: injectable clock."""
    if not _is_number(min_exp):
        raise AuthRefused("refusing: min_exp is not a finite number")
    if (not isinstance(placeholder_exp_days, int) or isinstance(placeholder_exp_days, bool)
            or not 1 <= placeholder_exp_days <= MAX_PLACEHOLDER_DAYS):
        raise AuthRefused(f"refusing: placeholder_exp_days is not an integer in "
                          f"1..{MAX_PLACEHOLDER_DAYS}")
    now_i = int(time.time() if now is None else now)
    placeholder_exp = now_i + placeholder_exp_days * DAY
    if placeholder_exp <= min_exp:
        raise AuthRefused("refusing: the placeholder lifetime (placeholder_exp_days) does not "
                          "outlast the run")

    doc = _json_object(_read_auth_file(codex_home), "CODEX_HOME/auth.json")
    mode = _resolve_mode(doc)
    tokens = doc.get("tokens")
    if not isinstance(tokens, dict):
        raise AuthRefused("refusing: tokens is missing or not an object")

    access_token = _token_string(tokens, "access_token")
    exp = _jwt_payload(access_token, "tokens.access_token").get("exp")
    if not _is_number(exp) or exp <= 0:
        raise AuthRefused("refusing: tokens.access_token has no numeric exp; its lifetime "
                          "cannot be checked")
    exp = int(exp)
    account_id = tokens.get("account_id")
    if not isinstance(account_id, str) or not _ACCOUNT_ID.fullmatch(account_id):
        raise AuthRefused("refusing: tokens.account_id is missing or not 8..128 characters of "
                          "[A-Za-z0-9_-]")
    id_claims = _jwt_payload(_token_string(tokens, "id_token"), "tokens.id_token")
    if exp <= min_exp:
        raise AuthRefused("refusing: the access token's remaining lifetime does not cover the run "
                          "(exp <= now + timeout + 600 s); refresh the host login with a Codex "
                          "call on the host, then retry")

    ph_account = str(uuid.uuid4())
    ph_access = "claudex-placeholder-" + secrets.token_urlsafe(48)
    ctx = {"exp": placeholder_exp, "now": now_i, "account_id": ph_account}
    placeholder_doc = {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": _placeholder_id_token(id_claims, ctx),
            "access_token": ph_access,
            "refresh_token": "",
            "account_id": ph_account,
        },
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_i)),
    }
    placeholder_auth_json = (json.dumps(placeholder_doc, indent=2) + "\n").encode("ascii")
    placeholder_map = {"authorization": "Bearer " + ph_access, "chatgpt-account-id": ph_account}
    real_map = {"authorization": "Bearer " + access_token, "chatgpt-account-id": account_id}
    needle_list = needles(access_token, account_id, list(real_map.values()))

    # Defence in depth: nothing real may have slipped into the builder's artefacts.
    builder_side = placeholder_auth_json + json.dumps(placeholder_map).encode("ascii")
    if scan_and_redact(builder_side, needle_list)[1]:
        raise AuthRefused("refusing: a placeholder artefact contains a real credential")

    body = json.dumps({"headers": real_map,
                       "needles_from": {"access_token": access_token, "account_id": account_id}},
                      separators=(",", ":")).encode("ascii")
    canon = json.dumps(real_map, sort_keys=True, separators=(",", ":")).encode("ascii")
    return Auth(
        placeholder_auth_json=placeholder_auth_json,
        placeholder_map=placeholder_map,
        real_map=real_map,
        token_message=b"TOKEN %d\n" % len(body) + body,
        exp=exp,
        mode=mode,
        sha256=hashlib.sha256(canon).hexdigest(),
        needles=needle_list,
    )
