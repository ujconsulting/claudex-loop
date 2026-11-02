"""U2 x U4 x U7: the real sandbox_auth output drives the real proxy (plan B2, Verification 1,
"integration").

PLAN-B2-build.md approach 6 splits one credential over three units: sandbox_auth.py (U4) reads the
host login and produces the placeholder map, the real map, the TOKEN message and the needles;
sandbox_build.py (U7) puts the placeholder map into the proxy's spec and the TOKEN message on the
proxy's stdin; sandbox_proxy.py (U2) replaces the placeholders by the real values and scans every
forwarded response for the needles. Each unit has its own tests with its own fixtures -- this file
checks that the three AGREE, by feeding what U4 really returns into what U2 really parses:

- `rebuild_request` on a request carrying exactly U4's placeholder values, header names in mixed
  case, injects exactly U4's real values; a placeholder that differs by one byte is refused;
- U2's `validate_token` on U4's TOKEN message derives the SAME needles U4 computed, byte for
  byte and in the same order (the proxy is self-contained and recomputes them);
- U4's needles fed to U2's `Scanner` catch the bare token, its encodings, the account id and the
  full header value, and release clean bytes unchanged;
- the spec U7 builds from the installed policy and U4's placeholder map passes U2's
  `validate_spec`; U2's local accounts/check answer carries U4's placeholder account id;
- in process, end to end: a client holding only U4's placeholders talks through U2's proxy (armed
  with U4's TOKEN message) to a TLS stub upstream on 127.0.0.1 -- the stub sees the real values,
  the client never does, and a reflected token aborts the proxy before a byte reaches the client.

FIXTURES ONLY: every auth.json here is written by this file into a temporary directory with
random fake values; the real ~/.codex/auth.json is never read, and nothing contacts the internet
(the upstream is a stub on 127.0.0.1 reached through the proxy's constructor seam).
Written before scripts/sandbox_build.py existed and seen failing first (module missing).
"""
from __future__ import annotations

import base64
import json
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sandbox_auth  # noqa: E402
import sandbox_build as sb  # noqa: E402
import sandbox_proxy as sp  # noqa: E402
import sandbox_run as sr  # noqa: E402

HOST = "chatgpt.com"
FWD = "/backend-api/codex/responses"
CHECK = "/backend-api/wham/accounts/check"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fake_jwt(claims: dict) -> str:
    """JWT-shaped, random signature. NOT a credential."""
    head = {"alg": "RS256", "typ": "JWT", "kid": "fixture"}
    return ".".join([_b64url(json.dumps(head).encode()), _b64url(json.dumps(claims).encode()),
                     _b64url(secrets.token_bytes(256))])


def write_fixture_home(root: Path, *, exp_days=8, mode="chatgpt", api_key=None) -> dict:
    """A fixture CODEX_HOME/auth.json with fake values; returns the values."""
    now = int(time.time())
    account = str(uuid.uuid4())
    access = fake_jwt({"aud": ["https://api.openai.com/v1"], "client_id": "app_fixture",
                       "exp": now + exp_days * 86400, "iat": now - 86400,
                       "https://api.openai.com/auth": {"chatgpt_account_id": account},
                       "jti": str(uuid.uuid4()), "scp": ["openid"], "sub": "fixture-user"})
    id_token = fake_jwt({"email": "fixture@example.invalid", "exp": now - 3600, "iat": now - 7200,
                         "https://api.openai.com/auth": {"chatgpt_account_id": account}})
    doc = {"auth_mode": mode, "OPENAI_API_KEY": api_key,
           "tokens": {"id_token": id_token, "access_token": access,
                      "refresh_token": "fixture-refresh-" + secrets.token_urlsafe(40),
                      "account_id": account},
           "last_refresh": "2026-11-01T00:00:00Z"}
    root.mkdir(parents=True, exist_ok=True)
    (root / "auth.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return {"access_token": access, "account_id": account, "refresh_token": doc["tokens"]["refresh_token"]}


def load_fixture(tmp: Path, **kw):
    values = write_fixture_home(tmp / "codex-home", **kw)
    auth = sandbox_auth.load(tmp / "codex-home", time.time() + 4200, 30)
    return auth, values


def policy_build() -> dict:
    return sb.build_policy(sr.load_policy())


def proxy_spec(auth, *, deadline=None, listen=0) -> dict:
    bcfg = policy_build()
    obj = sb.proxy_spec(bcfg, auth.placeholder_map, deadline or int(time.time()) + 600,
                        ["10.240.0.0/29", "10.210.26.0/24"])
    obj["listen"] = listen
    return obj


def raw_request(method, target, headers, body=b"") -> bytes:
    lines = [f"{method} {target} HTTP/1.1"] + [f"{n}: {v}" for n, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


class TempMixin:
    def tmp(self) -> Path:
        d = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(d.cleanup)
        return Path(d.name)


# --------------------------------------------------------------------------- pure integration


class RebuildWithAuthOutput(TempMixin, unittest.TestCase):
    def setUp(self):
        self.auth, self.values = load_fixture(self.tmp())
        self.spec = sp.validate_spec(proxy_spec(self.auth), time.time())
        self.endpoint = self.spec["endpoints"][HOST]

    def head(self, auth_value=None, account_value=None, names=("AuThOrIzAtIoN", "chatgpt-ACCOUNT-id")):
        ph = self.auth.placeholder_map
        headers = [("hOsT", HOST),
                   (names[0], ph["authorization"] if auth_value is None else auth_value),
                   (names[1], ph["chatgpt-account-id"] if account_value is None else account_value),
                   ("Content-Type", "application/json"), ("Content-Encoding", "zstd"),
                   ("Accept", "text/event-stream"), ("Content-Length", "4")]
        return sp.parse_request_head(raw_request("POST", FWD, headers), 65536)

    def test_mixed_case_placeholders_get_the_real_values(self):
        out = sp.rebuild_request(self.head(), self.endpoint, self.spec["placeholders"], self.auth.real_map)
        self.assertIsInstance(out, bytes, out)
        text = out.decode("ascii")
        self.assertIn("\r\nauthorization: Bearer " + self.values["access_token"] + "\r\n", text)
        self.assertIn("\r\nchatgpt-account-id: " + self.values["account_id"] + "\r\n", text)
        for value in self.auth.placeholder_map.values():
            self.assertNotIn(value, text)
        self.assertTrue(text.startswith("POST " + FWD + " HTTP/1.1\r\nHost: chatgpt.com\r\n"))
        self.assertIn("\r\naccept-encoding: identity\r\n", text)
        self.assertIn("\r\nconnection: close\r\n", text)

    def test_a_placeholder_one_byte_off_is_refused(self):
        ph = self.auth.placeholder_map
        bad_auth = ph["authorization"][:-1] + ("A" if ph["authorization"][-1] != "A" else "B")
        bad_acct = ph["chatgpt-account-id"][:-1] + ("0" if ph["chatgpt-account-id"][-1] != "0" else "1")
        for head in (self.head(auth_value=bad_auth), self.head(account_value=bad_acct)):
            out = sp.rebuild_request(head, self.endpoint, self.spec["placeholders"], self.auth.real_map)
            self.assertIsInstance(out, sp.Refusal)

    def test_the_real_values_themselves_are_refused_as_placeholders(self):
        # a builder that somehow holds the real token must not get it accepted as a placeholder
        head = self.head(auth_value=self.auth.real_map["authorization"])
        out = sp.rebuild_request(head, self.endpoint, self.spec["placeholders"], self.auth.real_map)
        self.assertIsInstance(out, sp.Refusal)

    def test_key_sets_agree(self):
        self.assertEqual(set(self.auth.placeholder_map), set(self.auth.real_map))
        self.assertEqual(set(self.auth.placeholder_map), set(self.endpoint["placeholder_headers"]))
        self.assertEqual(set(self.auth.placeholder_map), sp.KEYS)


class NeedleAgreement(TempMixin, unittest.TestCase):
    def setUp(self):
        self.auth, self.values = load_fixture(self.tmp())

    def token_obj(self):
        header, _, body = self.auth.token_message.partition(b"\n")
        self.assertEqual(header, b"TOKEN %d" % len(body))
        return sp._json(body)

    def test_proxy_recomputes_exactly_the_u4_needles(self):
        armed = sp.validate_token(self.token_obj(), self.auth.placeholder_map)
        self.assertEqual(armed["needles"], self.auth.needles)
        self.assertEqual(armed["headers"], self.auth.real_map)

    def test_the_two_needle_functions_agree(self):
        args = (self.values["access_token"], self.values["account_id"], list(self.auth.real_map.values()))
        self.assertEqual(sp.needles(*args), sandbox_auth.needles(*args))

    def test_u4_needles_cover_every_component(self):
        token, account = self.values["access_token"].encode(), self.values["account_id"].encode()
        bearer = self.auth.real_map["authorization"].encode()
        for must in (token, account, bearer, token.hex().encode(), base64.b64encode(token)):
            self.assertTrue(any(must == n or n in must for n in self.auth.needles), must[:20])

    def test_scanner_with_u4_needles_catches_the_bare_token(self):
        token = self.values["access_token"].encode()
        cases = [b'{"access_token":"' + token + b'"}', base64.b64encode(b"x" + token),
                 base64.urlsafe_b64encode(b"xy" + token), token.hex().upper().encode(),
                 self.values["account_id"].encode(), self.auth.real_map["authorization"].encode()]
        for body in cases:
            scanner = sp.Scanner(self.auth.needles)
            with self.assertRaises(sp.Hit):
                released = scanner.feed(body[: len(body) // 2])
                released += scanner.feed(body[len(body) // 2:])
                scanner.finalize()

    def test_scanner_releases_clean_bytes_unchanged(self):
        clean = b"data: " + json.dumps({"type": "response.output_text.delta", "delta": "ok"}).encode() * 300
        scanner = sp.Scanner(self.auth.needles)
        out = b"".join(scanner.feed(clean[i:i + 97]) for i in range(0, len(clean), 97)) + scanner.finalize()
        self.assertEqual(out, clean)

    def test_placeholder_artefacts_carry_no_needle(self):
        blob = self.auth.placeholder_auth_json + json.dumps(self.auth.placeholder_map).encode()
        self.assertEqual(sandbox_auth.scan_and_redact(blob, self.auth.needles)[1], 0)
        self.assertEqual(sandbox_auth.scan_and_redact(json.dumps(proxy_spec(self.auth)).encode(),
                                                      self.auth.needles)[1], 0)
        self.assertNotIn(self.values["refresh_token"].encode(), blob + self.auth.token_message)


class SpecAgreement(TempMixin, unittest.TestCase):
    def setUp(self):
        self.auth, self.values = load_fixture(self.tmp())

    def test_u7_spec_from_the_installed_policy_passes_u2(self):
        spec = sp.validate_spec(proxy_spec(self.auth, listen=sb.PROXY_PORT), time.time())
        self.assertEqual(spec["listen"], 3128)
        self.assertEqual(spec["placeholders"], self.auth.placeholder_map)
        self.assertEqual(spec["refused_hosts_fatal"], ["auth.openai.com"])

    def test_u2_refuses_a_spec_whose_deadline_is_more_than_an_hour_ahead(self):
        # Orchestrator contract (U7): the proxy deadline is capped below one hour.
        obj = proxy_spec(self.auth, deadline=int(time.time()) + 3700)
        with self.assertRaises(sp.SpecError):
            sp.validate_spec(obj, time.time())
        self.assertLess(sb.PROXY_LIFETIME_MAX, 3600)

    def test_local_accounts_check_uses_the_u4_placeholder_account(self):
        answer = sp.local_answer("local", self.auth.placeholder_map)
        body = json.loads(answer.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(body["default_account_id"], self.auth.placeholder_map["chatgpt-account-id"])
        self.assertEqual(body["accounts"][0]["id"], self.auth.placeholder_map["chatgpt-account-id"])
        self.assertNotIn(self.values["account_id"].encode(), answer)


# --------------------------------------------------------------------------- in process, end to end


class StubUpstream:
    """A TLS server for chatgpt.com on 127.0.0.1 with its own CA; records each request head and
    body, answers with `respond(head, body) -> bytes`."""

    def __init__(self, tmp: Path, respond):
        cert = sp.make_ca(HOST, int(time.time()) + 600)
        chain = tmp / "stub-chain.pem"
        chain.write_bytes(cert.leaf_pem + cert.leaf_key_pem)
        self.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_ctx.load_cert_chain(str(chain))
        chain.unlink()
        self.client_ctx = ssl.create_default_context(cadata=cert.ca_pem.decode("ascii"))
        self.respond, self.seen = respond, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.server_ctx.wrap_socket(raw, server_side=True) as conn:
                    conn.settimeout(10)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        data += conn.recv(4096)
                    head, body = data.split(b"\r\n\r\n", 1)
                    lines = head.decode("ascii").split("\r\n")
                    headers = {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
                    if "content-length" in headers:
                        while len(body) < int(headers["content-length"]):
                            body += conn.recv(4096)
                    else:  # chunked, as the proxy re-frames it
                        while not body.endswith(b"0\r\n\r\n"):
                            body += conn.recv(4096)
                    self.seen.append((lines[0], headers, body))
                    conn.sendall(self.respond(headers, body))
            except (OSError, ssl.SSLError):
                continue

    def close(self):
        self.sock.close()


class InProcessEndToEnd(TempMixin, unittest.TestCase):
    def start(self, respond):
        tmp = self.tmp()
        self.auth, self.values = load_fixture(tmp)
        self.stub = StubUpstream(tmp, respond)
        self.addCleanup(self.stub.close)
        self.lines = []
        spec = sp.validate_spec(proxy_spec(self.auth), time.time())
        upstream = sp.Upstream(port=self.stub.port, resolve=lambda host: ["127.0.0.1"],
                               context=self.stub.client_ctx, address_check=lambda ip, nets: True)
        self.proxy = sp.Proxy("1" * 32, spec, self.lines.append, bind_host="127.0.0.1",
                              upstream=upstream, keydir=tmp)
        ca_pem = self.proxy.start()
        self.addCleanup(self.proxy.stop)
        header, _, body = self.auth.token_message.partition(b"\n")
        self.proxy.arm(sp.validate_token(sp._json(body), self.auth.placeholder_map))
        self.client_ctx = ssl.create_default_context(cadata=ca_pem.decode("ascii"))
        self.client_ctx.set_alpn_protocols(["http/1.1"])

    def client(self, method, target, body=b""):
        """What a builder holding only the placeholder auth.json can send."""
        ph = self.auth.placeholder_map
        raw = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10)
        raw.sendall(b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = raw.recv(1)
            if not chunk:
                break
            reply += chunk
        self.assertTrue(reply.startswith(b"HTTP/1.1 200"), reply)
        conn = self.client_ctx.wrap_socket(raw, server_hostname=HOST)
        headers = [("Host", HOST), ("Authorization", ph["authorization"]),
                   ("ChatGPT-Account-Id", ph["chatgpt-account-id"]), ("Content-Type", "application/json"),
                   ("Accept", "text/event-stream"), ("Content-Length", str(len(body)))]
        conn.sendall(raw_request(method, target, headers, body))
        got = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                got += chunk
        except (OSError, ssl.SSLError):
            pass
        conn.close()
        return got

    def test_upstream_sees_the_real_values_the_client_never_does(self):
        self.start(lambda headers, body: b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                         b"Content-Length: 12\r\n\r\ndata: ok\r\n\r\n")
        got = self.client("POST", FWD, b'{"x":1}')
        self.assertIn(b"200", got.split(b"\r\n", 1)[0])
        self.assertIn(b"data: ok", got)
        self.assertEqual(len(self.stub.seen), 1)
        line, headers, body = self.stub.seen[0]
        self.assertEqual(line, "POST " + FWD + " HTTP/1.1")
        self.assertEqual(headers["authorization"], self.auth.real_map["authorization"])
        self.assertEqual(headers["chatgpt-account-id"], self.auth.real_map["chatgpt-account-id"])
        self.assertEqual(body, b'{"x":1}')
        self.assertEqual(sandbox_auth.scan_and_redact(got, self.auth.needles)[1], 0)
        # one bounded log line, no value in it
        end = time.monotonic() + 2
        logs = [ln for ln in self.lines if ln.startswith("{")]
        while not logs and time.monotonic() < end:
            time.sleep(0.01)
            logs = [ln for ln in self.lines if ln.startswith("{")]
        self.assertTrue(logs, "the forwarded request must be logged within two seconds")
        self.assertEqual(json.loads(logs[-1])["route"], "forward")
        self.assertEqual(sandbox_auth.scan_and_redact("\n".join(self.lines).encode(), self.auth.needles)[1], 0)

    def test_a_reflected_token_aborts_before_any_byte_reaches_the_client(self):
        def reflect(headers, body):
            token = headers["authorization"][len("Bearer "):].encode()
            payload = b'data: {"access_token":"' + token + b'"}\n\n'
            return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
        self.start(reflect)
        got = self.client("POST", FWD, b"{}")
        self.assertEqual(sandbox_auth.scan_and_redact(got, self.auth.needles)[1], 0)
        self.assertNotIn(self.values["access_token"].encode(), got)
        self.assertIn("ABORT " + "1" * 32 + " credential", self.lines)

    def test_local_route_never_reaches_upstream(self):
        self.start(lambda headers, body: b"HTTP/1.1 500 X\r\nContent-Length: 0\r\n\r\n")
        got = self.client("GET", CHECK)
        self.assertEqual(self.stub.seen, [])
        body = json.loads(got.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(body["default_account_id"], self.auth.placeholder_map["chatgpt-account-id"])


if __name__ == "__main__":
    unittest.main()
