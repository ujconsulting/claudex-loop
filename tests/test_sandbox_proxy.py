"""sandbox_proxy: the injecting proxy of plan B2 (PLAN-B2-build.md approach 5/6, unit U2).

The proxy terminates TLS for chatgpt.com only, forwards exactly one route, rebuilds that request
itself, injects the real credential headers, answers accounts/check locally, refuses everything
else and scans every forwarded response for the real values before a byte reaches the builder.

Every test runs locally: the upstream is a TLS stub on 127.0.0.1 with its own test CA, the
"real" token is a random fixture value, nothing contacts the internet. The framing tests use a
real HTTP client (http.client through the proxy with CONNECT), as the round-5 review asked.
The image self-test (cryptography imported from the APPENDED image site path under -I -S) runs
only with CLAUDEX_DOCKER_TESTS=1.

Written before scripts/sandbox_proxy.py and seen failing first (module missing).
"""
from __future__ import annotations

import ast
import base64
import datetime
import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import os
import queue
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sandbox_auth  # noqa: E402
import sandbox_proxy as sp  # noqa: E402

HOST = "chatgpt.com"
FWD = "/backend-api/codex/responses"
CHECK = "/backend-api/wham/accounts/check"
POLICY = json.loads((ROOT / "config" / "sandbox-policy.json").read_text(encoding="utf-8"))
BUILD = POLICY["build"]

# --------------------------------------------------------------------------- fixture values


def fake_token() -> str:
    """JWT-shaped like the real access token (about 1.8 KB). NOT a credential."""
    return "eyJ" + secrets.token_urlsafe(30) + "." + secrets.token_urlsafe(1300) + "." + \
        secrets.token_urlsafe(40)


class Creds:
    def __init__(self):
        self.token = fake_token()
        self.account = str(uuid.uuid4())
        self.ph_token = "claudex-placeholder-" + secrets.token_urlsafe(48)
        self.ph_account = str(uuid.uuid4())
        self.placeholders = {"authorization": "Bearer " + self.ph_token,
                             "chatgpt-account-id": self.ph_account}
        self.real = {"authorization": "Bearer " + self.token, "chatgpt-account-id": self.account}
        self.token_obj = {"headers": dict(self.real),
                          "needles_from": {"access_token": self.token, "account_id": self.account}}
        self.needles = sandbox_auth.needles(self.token, self.account, list(self.real.values()))


def spec_obj(creds: Creds, *, caps=None, deadline=None, listen=0, deny_nets=None) -> dict:
    return {
        "endpoints": json.loads(json.dumps(BUILD["endpoints"])),
        "placeholders": dict(creds.placeholders),
        "refused_hosts_fatal": list(BUILD["refused_hosts_fatal"]),
        "listen": listen,
        "caps": dict(caps or BUILD["proxy_caps"]),
        "deadline": deadline if deadline is not None else time.time() + 600,
        "deny_nets": deny_nets if deny_nets is not None else ["10.240.0.0/29", "10.240.0.8/29"],
    }


def endpoint(creds: Creds | None = None) -> dict:
    return sp.validate_spec(spec_obj(creds or Creds()), time.time())["endpoints"][HOST]


def head(raw: bytes):
    return sp.parse_request_head(raw, 65536)


def req(method="POST", target=FWD, headers=None, extra=b"") -> bytes:
    headers = [("Host", HOST)] if headers is None else headers
    lines = [f"{method} {target} HTTP/1.1".encode()]
    lines += [f"{n}: {v}".encode("latin-1") for n, v in headers]
    return b"\r\n".join(lines) + b"\r\n\r\n" + extra


def fwd_headers(creds: Creds, *, body_len=None, more=()):
    h = [("Host", HOST), ("Authorization", creds.placeholders["authorization"]),
         ("ChatGPT-Account-Id", creds.placeholders["chatgpt-account-id"]),
         ("Content-Type", "application/json"), ("Content-Encoding", "zstd"),
         ("Accept", "text/event-stream"), ("originator", "codex_exec"),
         ("session-id", "s-1")]
    h += list(more)
    if body_len is not None:
        h.append(("Content-Length", str(body_len)))
    return h


# --------------------------------------------------------------------------- test PKI


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_test_pki(tmp_path: Path, host=HOST):
    """An independent CA + leaf for the UPSTREAM stub (not the proxy's make_ca)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("stub-ca")).issuer_name(_name("stub-ca"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(_name(host)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    chain = tmp_path / f"stub-{secrets.token_hex(4)}.pem"
    chain.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(chain))
    chain.unlink()
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cadata=ca.public_bytes(serialization.Encoding.PEM).decode())
    return server_ctx, client_ctx


def _read_until(sock, marker: bytes, cap=1 << 20) -> tuple[bytes, bytes]:
    buf = b""
    while marker not in buf:
        data = sock.recv(65536)
        if not data:
            raise ConnectionError("eof before marker")
        buf += data
        assert len(buf) < cap
    i = buf.index(marker) + len(marker)
    return buf[:i], buf[i:]


def _dechunk_simple(sock, rest: bytes) -> bytes:
    """Test-side chunked decoder (independent of the proxy's BodyReframer)."""
    buf, out = rest, b""
    while True:
        while b"\r\n" not in buf:
            buf += sock.recv(65536)
        line, buf = buf.split(b"\r\n", 1)
        size = int(line.split(b";")[0], 16)
        if size == 0:
            while not buf.endswith(b"\r\n") and b"\r\n\r\n" not in b"\r\n" + buf:
                buf += sock.recv(65536)
            return out
        while len(buf) < size + 2:
            buf += sock.recv(65536)
        out += buf[:size]
        buf = buf[size + 2:]


class Stub:
    """TLS upstream on 127.0.0.1. Records every request it receives; answers with `respond(req)`,
    a list of byte pieces sent with a pause between them (separate reads on the proxy side)."""

    def __init__(self, server_ctx, respond):
        self.ctx = server_ctx
        self.respond = respond
        self.received: "queue.Queue[tuple[bytes, bytes]]" = queue.Queue()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.alive = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.alive:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            conn.settimeout(10)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            tls = self.ctx.wrap_socket(conn, server_side=True)
            h, rest = _read_until(tls, b"\r\n\r\n")
            low = h.lower()
            m = re.search(rb"\r\ncontent-length: *([0-9]+)", low)
            if b"transfer-encoding: chunked" in low:
                body = _dechunk_simple(tls, rest)
            else:
                n = int(m.group(1)) if m else 0
                body = rest
                while len(body) < n:
                    body += tls.recv(65536)
            self.received.put((h, body))
            for i, piece in enumerate(self.respond((h, body))):
                if i:
                    time.sleep(0.05)
                tls.sendall(piece)
            try:
                tls.unwrap()
            except (ssl.SSLError, OSError):
                pass
        except (OSError, ssl.SSLError, ConnectionError, ValueError):
            pass
        finally:
            conn.close()

    def requests(self):
        out = []
        while not self.received.empty():
            out.append(self.received.get_nowait())
        return out

    def close(self):
        self.alive = False
        self.sock.close()


def resp_cl(body: bytes, extra=b"") -> list[bytes]:
    return [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" + extra +
            b"Content-Length: %d\r\n\r\n" % len(body) + body]


def resp_chunked(pieces: list[bytes], extra=b"", trailers=b"") -> list[bytes]:
    out = [b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n" + extra +
           b"Transfer-Encoding: chunked\r\n\r\n"]
    out += [b"%x\r\n" % len(p) + p + b"\r\n" for p in pieces]
    out.append(b"0\r\n" + trailers + b"\r\n")
    return out


# --------------------------------------------------------------------------- proxy harness


class Harness:
    def __init__(self, tmp_path, respond, *, creds=None, caps=None, armed=True, deadline=None):
        self.creds = creds or Creds()
        self.events: list[str] = []
        self.lock = threading.Lock()
        server_ctx, self.stub_client_ctx = make_test_pki(tmp_path)
        self.stub = Stub(server_ctx, respond)
        self.spec = sp.validate_spec(spec_obj(self.creds, caps=caps, deadline=deadline),
                                     time.time())
        upstream = sp.Upstream(port=self.stub.port, resolve=lambda host: ["127.0.0.1"],
                               context=self.stub_client_ctx,
                               address_check=lambda ip, nets: True)
        self.proxy = sp.Proxy("0" * 32, self.spec, self._emit, bind_host="127.0.0.1",
                              upstream=upstream, keydir=tmp_path)
        self.ca_pem = self.proxy.start()
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.ctx.load_verify_locations(cadata=self.ca_pem.decode("ascii"))
        if armed:
            self.proxy.arm(sp.validate_token(self.creds.token_obj, self.creds.placeholders))

    def _emit(self, line: str):
        with self.lock:
            self.events.append(line)

    def logs(self):
        with self.lock:
            return [json.loads(e) for e in self.events if e.startswith("{")]

    def wait_event(self, prefix, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                hits = [e for e in self.events if e.startswith(prefix)]
            if hits:
                return hits
            time.sleep(0.02)
        return []

    def http(self, timeout=10):
        conn = http.client.HTTPSConnection("127.0.0.1", self.proxy.port, context=self.ctx,
                                           timeout=timeout)
        conn.set_tunnel(HOST, 443)
        return conn

    def raw_connect(self, target=f"{HOST}:443", timeout=10):
        s = socket.create_connection(("127.0.0.1", self.proxy.port), timeout=timeout)
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        h, rest = _read_until(s, b"\r\n\r\n")
        return s, h, rest

    def raw_tls(self, request: bytes, sni=HOST, timeout=10) -> bytes:
        """CONNECT, TLS with `sni`, send `request`, return every byte received until EOF."""
        s, h, _ = self.raw_connect(timeout=timeout)
        assert h.startswith(b"HTTP/1.1 200"), h
        ctx = self.ctx
        if sni != HOST:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(s, server_hostname=sni)
        tls.sendall(request)
        out = b""
        try:
            while True:
                data = tls.recv(65536)
                if not data:
                    break
                out += data
        except (ssl.SSLError, OSError):
            pass
        tls.close()
        return out

    def close(self):
        self.proxy.stop("test")
        self.stub.close()


@pytest.fixture
def harness(tmp_path):
    made = []

    def make(respond=lambda r: resp_cl(b'{"ok":true}'), **kw):
        h = Harness(tmp_path, respond, **kw)
        made.append(h)
        return h

    yield make
    for h in made:
        h.close()


def forward_request(creds: Creds, body: bytes, more=()) -> bytes:
    return req(headers=fwd_headers(creds, body_len=len(body), more=more), extra=body)


# =========================================================================== pure helpers


class TestConnect:
    def test_only_chatgpt_443_is_terminated(self):
        spec = sp.validate_spec(spec_obj(Creds()), time.time())
        assert sp.allowed_connect("chatgpt.com", 443, spec) == "tls"
        for host, port in [("chatgpt.com", 80), ("chatgpt.com", 8443), ("api.openai.com", 443),
                           ("github.com", 443), ("api.github.com", 443), ("1.1.1.1", 443),
                           ("example.com", 443), ("chatgpt.com.", 443), ("xchatgpt.com", 443),
                           ("sub.chatgpt.com", 443)]:
            assert sp.allowed_connect(host, port, spec) == "refuse", (host, port)

    def test_auth_openai_is_fatal_on_any_port(self):
        spec = sp.validate_spec(spec_obj(Creds()), time.time())
        assert sp.allowed_connect("auth.openai.com", 443, spec) == "fatal"
        assert sp.allowed_connect("AUTH.OPENAI.COM", 443, spec) == "fatal"
        assert sp.allowed_connect("auth.openai.com", 80, spec) == "fatal"

    def test_parse_authority(self):
        assert sp.parse_authority("chatgpt.com:443") == ("chatgpt.com", 443)
        assert sp.parse_authority("ChatGPT.com:443") == ("chatgpt.com", 443)
        for bad in ["chatgpt.com", "[::1]:443", "chatgpt.com:0443", "chatgpt.com:99999",
                    "chatgpt.com:443/x", "user@chatgpt.com:443", "", "*", "/x", "a b:443"]:
            assert sp.parse_authority(bad) is None, bad


def client_hello(server_name) -> bytes:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=server_name)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return out.read()


class TestSni:
    def test_sni_must_equal_host(self):
        assert sp.sni_ok(client_hello("chatgpt.com"), "chatgpt.com")
        assert not sp.sni_ok(client_hello("evil.example"), "chatgpt.com")
        assert not sp.sni_ok(client_hello("api.openai.com"), "chatgpt.com")

    def test_missing_sni_and_garbage_refused(self):
        assert not sp.sni_ok(client_hello(None), "chatgpt.com")
        hello = client_hello("chatgpt.com")
        for bad in [b"", b"\x16\x03\x01", hello[:40], b"GET / HTTP/1.1\r\n\r\n",
                    b"\x17" + hello[1:], hello[:5] + b"\x02" + hello[6:]]:
            assert not sp.sni_ok(bad, "chatgpt.com")


class TestParseHead:
    def test_good_head(self):
        h = head(req(headers=[("Host", HOST), ("X-A", " v  ")]))
        assert (h.method, h.target, h.version) == ("POST", FWD, "HTTP/1.1")
        assert h.headers == [("host", HOST), ("x-a", "v")]

    @pytest.mark.parametrize("raw", [
        b"POST / HTTP/1.1\nHost: chatgpt.com\r\n\r\n",                 # bare LF
        b"POST / HTTP/1.1\r\nHost: chatgpt.com\n\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: chatgpt.com\rX: y\r\n\r\n",          # bare CR
        b"POST / HTTP/1.1\r\nHost: chatgpt.com\r\n folded\r\n\r\n",      # obs-fold
        b"POST / HTTP/1.1\r\nHost: chatgpt.com\r\n\tfolded\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost : chatgpt.com\r\n\r\n",               # space before colon
        b"POST / HTTP/1.1\r\nNoColon\r\n\r\n",
        b"POST / HTTP/1.0\r\nHost: chatgpt.com\r\n\r\n",
        b"POST  / HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n",
        b"post / HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n",
        b"\r\nPOST / HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n",            # leading empty line
        b"POST /\xc3\xa4 HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n",        # non-ASCII target
        b"POST / HTTP/1.1\r\nHost: chatgpt.com\r\nX: a\x00b\r\n\r\n",  # control in value
        b"POST / HTTP/1.1\r\nHost: chatgpt.com\r\n",                    # no terminator
    ])
    def test_hostile_heads_refused(self, raw):
        with pytest.raises(sp.Refusal):
            sp.parse_request_head(raw, 65536)

    def test_over_long_head_refused(self):
        raw = req(headers=[("Host", HOST), ("X-Big", "a" * 70000)])
        with pytest.raises(sp.Refusal):
            sp.parse_request_head(raw, 65536)

    def test_too_many_headers_refused(self):
        raw = req(headers=[("Host", HOST)] + [(f"X-{i}", "v") for i in range(200)])
        with pytest.raises(sp.Refusal):
            sp.parse_request_head(raw, 65536)


class TestClassify:
    def classify(self, method, target, headers=None):
        hs = [("Host", HOST)] if headers is None else headers
        return sp.classify(method, target, hs, endpoint())

    def test_forward_and_local(self):
        assert self.classify("POST", FWD) == "forward"
        assert self.classify("GET", CHECK) == "local"
        assert self.classify("POST", FWD, [("host", "ChatGPT.com:443")]) == "forward"

    def test_other_routes_404(self):
        for m, t in [("GET", FWD), ("PUT", FWD), ("POST", CHECK),
                     ("GET", "/backend-api/codex/models?client_version=0.162.1"),
                     ("POST", "/backend-api/ps/mcp"), ("GET", "/backend-api/wham/settings/user"),
                     ("POST", "/backend-api/codex/analytics-events/events"),
                     ("POST", FWD + "X"), ("POST", FWD + "?"), ("POST", FWD + "?a=b"),
                     ("POST", FWD + "/"), ("GET", CHECK + "?x=1"), ("POST", "/backend-api/codex")]:
            assert self.classify(m, t) == 404, (m, t)

    @pytest.mark.parametrize("target", [
        "/backend-api/codex/../codex/responses", "/backend-api/codex/%72esponses",
        "/backend-api%2Fcodex/responses", "/backend-api/codex/responses%00",
        "/backend-api/codex/responses?x=%5C", "//backend-api/codex/responses",
        "/backend-api/codex/./responses", "/backend-api/codex/responses#frag",
        "/backend-api/codex/responses\\", "/backend-api/codex/résponses",
        "https://chatgpt.com/backend-api/codex/responses", "chatgpt.com:443", "*",
        "/backend-api//codex/responses", "/", "", "/backend-api/codex/responses ",
    ])
    def test_malformed_targets_refused(self, target):
        for method in ("POST", "GET"):
            assert self.classify(method, target) in (403, 404)
            assert self.classify(method, target) not in ("forward", "local")

    def test_percent_and_traversal_are_403(self):
        assert self.classify("POST", "/backend-api/codex/%72esponses") == 403
        assert self.classify("POST", "/backend-api/codex/../codex/responses") == 403
        assert self.classify("POST", "https://chatgpt.com" + FWD) == 403
        assert self.classify("OPTIONS", "*") == 403

    def test_websocket_upgrade_403(self):
        hs = [("Host", HOST), ("Upgrade", "websocket"), ("Connection", "Upgrade")]
        assert self.classify("GET", FWD, hs) == 403
        assert self.classify("POST", FWD, hs) == 403

    def test_trace_options_connect_never_forwarded(self):
        for m in ("TRACE", "OPTIONS", "CONNECT"):
            assert self.classify(m, FWD) == 403

    def test_host_binding(self):
        assert self.classify("POST", FWD, []) == 403
        assert self.classify("POST", FWD, [("Host", HOST), ("Host", HOST)]) == 403
        assert self.classify("POST", FWD, [("Host", "api.openai.com")]) == 403
        assert self.classify("POST", FWD, [("Host", "chatgpt.com:8443")]) == 403
        assert self.classify("POST", FWD, [("Host", "chatgpt.com.evil")]) == 403


class TestRebuild:
    def rebuild(self, creds, headers, body=b"", real="default"):
        h = head(req(headers=headers, extra=b""))
        r = creds.real if real == "default" else real
        return sp.rebuild_request(h, endpoint(creds), creds.placeholders, r)

    def test_only_listed_headers_real_values_injected(self):
        c = Creds()
        hs = fwd_headers(c, body_len=10, more=[("X-Forwarded-Host", "evil"), ("Cookie", "a=b"),
                                               ("Proxy-Authorization", "x"), ("Expect", "x"),
                                               ("thread-id", "t-1")])
        out = self.rebuild(c, hs)
        assert isinstance(out, bytes)
        lines = out.split(b"\r\n")
        assert lines[0] == b"POST /backend-api/codex/responses HTTP/1.1"
        assert out.endswith(b"\r\n\r\n")
        names = [ln.split(b":", 1)[0].lower() for ln in lines[1:] if ln]
        allowed = set(BUILD["endpoints"][HOST]["request_headers"]) | {
            "host", "authorization", "chatgpt-account-id", "accept-encoding", "connection",
            "content-length"}
        assert {n.decode() for n in names} <= allowed
        assert len(names) == len(set(names))
        low = out.lower()
        assert b"x-forwarded-host" not in low and b"cookie" not in low and b"expect" not in low
        assert b"proxy-authorization" not in low
        assert b"\r\nhost: chatgpt.com\r\n" in low
        assert b"\r\naccept-encoding: identity\r\n" in low
        assert b"\r\nconnection: close\r\n" in low
        assert b"\r\ncontent-length: 10\r\n" in low
        assert ("authorization: Bearer " + c.token).encode() in out
        assert ("chatgpt-account-id: " + c.account).encode() in out
        assert c.ph_token.encode() not in out and c.ph_account.encode() not in out
        assert b"thread-id: t-1" in out and b"content-encoding: zstd" in out
        assert sp.dropped_headers(head(req(headers=hs)), endpoint(c)) == [
            "x-forwarded-host", "cookie", "proxy-authorization", "expect"]

    def test_mixed_case_names_accepted(self):
        c = Creds()
        hs = [("hOST", HOST), ("AUTHORIZATION", c.placeholders["authorization"]),
              ("chatgpt-ACCOUNT-id", c.placeholders["chatgpt-account-id"]),
              ("Content-Length", "0")]
        out = self.rebuild(c, hs)
        assert isinstance(out, bytes) and ("Bearer " + c.token).encode() in out

    def test_placeholder_must_match_exactly(self):
        c = Creds()
        for name in ("authorization", "chatgpt-account-id"):
            value = c.placeholders[name]
            for forged in (value[:-1] + chr(ord(value[-1]) ^ 1), value + "x", "", value[:-1],
                           "Bearer " + c.token if name == "authorization" else c.account):
                hs = [(n, forged if n.lower() == name else v) for n, v in fwd_headers(c, body_len=0)]
                out = self.rebuild(c, hs)
                assert isinstance(out, sp.Refusal), (name, forged[:12])

    def test_missing_or_second_placeholder_refused(self):
        c = Creds()
        hs = [(n, v) for n, v in fwd_headers(c, body_len=0) if n != "Authorization"]
        assert isinstance(self.rebuild(c, hs), sp.Refusal)
        hs = fwd_headers(c, body_len=0) + [("Authorization", c.placeholders["authorization"])]
        assert isinstance(self.rebuild(c, hs), sp.Refusal)

    def test_duplicate_allowed_header_refused(self):
        c = Creds()
        hs = fwd_headers(c, body_len=0) + [("Accept", "x")]
        assert isinstance(self.rebuild(c, hs), sp.Refusal)

    def test_framing(self):
        c = Creds()
        both = fwd_headers(c, body_len=5) + [("Transfer-Encoding", "chunked")]
        assert isinstance(self.rebuild(c, both), sp.Refusal)
        two = fwd_headers(c, body_len=5) + [("Content-Length", "5")]
        assert isinstance(self.rebuild(c, two), sp.Refusal)
        for bad in ("gzip", "chunked, gzip", "gzip, chunked", "identity"):
            hs = fwd_headers(c) + [("Transfer-Encoding", bad)]
            assert isinstance(self.rebuild(c, hs), sp.Refusal), bad
        for bad in ("-1", "5, 5", "0x10", "+5", "1" * 20):
            hs = fwd_headers(c) + [("Content-Length", bad)]
            assert isinstance(self.rebuild(c, hs), sp.Refusal), bad
        chunked = self.rebuild(c, fwd_headers(c) + [("Transfer-Encoding", "Chunked")])
        assert b"\r\ntransfer-encoding: chunked\r\n" in chunked.lower()
        assert b"content-length" not in chunked.lower()
        none = self.rebuild(c, fwd_headers(c))
        assert b"\r\ncontent-length: 0\r\n" in none.lower()

    def test_not_armed_or_key_mismatch_refused(self):
        c = Creds()
        assert isinstance(self.rebuild(c, fwd_headers(c, body_len=0), real=None), sp.Refusal)
        wrong = {"authorization": c.real["authorization"]}
        assert isinstance(self.rebuild(c, fwd_headers(c, body_len=0), real=wrong), sp.Refusal)


class TestLocalAnswer:
    def test_accounts_check_uses_placeholder_id(self):
        c = Creds()
        raw = sp.local_answer("local", c.placeholders)
        h, body = raw.split(b"\r\n\r\n", 1)
        assert h.startswith(b"HTTP/1.1 200 ")
        assert b"\r\nContent-Length: %d" % len(body) in h
        assert b"\r\nConnection: close" in h
        assert json.loads(body) == {
            "accounts": [{"id": c.ph_account, "workspace_backend_origin": "https://chatgpt.com",
                          "account_routing_override": "NO_CONSTRAINT"}],
            "default_account_id": c.ph_account}

    def test_refusal_answers(self):
        c = Creds()
        assert sp.local_answer(404, c.placeholders).startswith(b"HTTP/1.1 404 ")
        assert sp.local_answer(403, c.placeholders).startswith(b"HTTP/1.1 403 ")
        for status in (403, 404):
            assert c.ph_token.encode() not in sp.local_answer(status, c.placeholders)


class TestNeedles:
    def test_same_as_sandbox_auth(self):
        c = Creds()
        values = list(c.real.values())
        assert sp.needles(c.token, c.account, values) == \
            sandbox_auth.needles(c.token, c.account, values)

    def test_token_message_builds_the_needles(self):
        c = Creds()
        tok = sp.validate_token(c.token_obj, c.placeholders)
        assert tok["headers"] == c.real
        assert tok["needles"] == c.needles

    @pytest.mark.parametrize("mutate", [
        lambda o: o["headers"].pop("chatgpt-account-id"),
        lambda o: o["headers"].__setitem__("x-extra", "abcdefghij"),
        lambda o: o.__setitem__("extra", 1),
        lambda o: o["needles_from"].pop("account_id"),
        lambda o: o["needles_from"].__setitem__("access_token", "short"),
        lambda o: o["headers"].__setitem__("authorization", "Bearer a\r\nX: y"),
        lambda o: o["headers"].__setitem__("Authorization", o["headers"].pop("authorization")),
    ])
    def test_bad_token_message_refused(self, mutate):
        c = Creds()
        obj = json.loads(json.dumps(c.token_obj))
        mutate(obj)
        with pytest.raises(sp.SpecError):
            sp.validate_token(obj, c.placeholders)


class TestScanner:
    def test_clean_stream_released_byte_identical(self):
        c = Creds()
        data = secrets.token_bytes(200_000)
        s = sp.Scanner(c.needles)
        out = b""
        for i in range(0, len(data), 7777):
            out += s.feed(data[i:i + 7777])
        out += s.finalize()
        assert out == data

    def test_holds_back_longest_needle_minus_one(self):
        c = Creds()
        s = sp.Scanner(c.needles)
        longest = max(len(n) for n in c.needles)
        assert s.feed(b"a" * (longest - 1)) == b""
        assert s.feed(b"b") == b"a"
        assert s.finalize() == b"a" * (longest - 2) + b"b"

    def test_token_split_at_every_position_caught(self):
        c = Creds()
        payload = b'data: {"access_token":"' + c.token.encode() + b'"}\n\n'
        for cut in range(1, len(payload), 97):
            s = sp.Scanner(c.needles)
            released = s.feed(b"x" * 9000 + payload[:cut])
            with pytest.raises(sp.Hit):
                released += s.feed(payload[cut:])
                released += s.finalize()
            assert c.token.encode()[:16] not in released

    def test_token_in_last_bytes_caught_by_finalize(self):
        c = Creds()
        s = sp.Scanner(c.needles)
        released = s.feed(b"y" * 50_000)
        with pytest.raises(sp.Hit):
            s.finalize_with = None  # noqa: B018 -- attribute probe, ignored
            released += s.feed(c.account.encode())
            s.finalize()
        assert c.account.encode() not in released

    def test_hit_carries_no_value(self):
        c = Creds()
        s = sp.Scanner(c.needles)
        with pytest.raises(sp.Hit) as e:
            s.feed(c.token.encode())
        assert c.token not in repr(e.value) and c.token not in str(e.value)

    def test_every_encoding_caught(self):
        c = Creds()
        for n in c.needles:
            s = sp.Scanner(c.needles)
            with pytest.raises(sp.Hit):
                s.feed(b"prefix " + n + b" suffix")
                s.finalize()

    def test_feed_after_finalize_refused(self):
        s = sp.Scanner([b"abcdefgh"])
        s.finalize()
        with pytest.raises(RuntimeError):
            s.feed(b"x")


class TestReframer:
    def test_content_length(self):
        r = sp.BodyReframer("length", 10)
        assert r.feed(b"0123") == b"0123" and not r.done
        assert r.feed(b"456789EXTRA") == b"456789" and r.done
        assert r.extra == b"EXTRA"

    def test_content_length_truncated(self):
        r = sp.BodyReframer("length", 10)
        r.feed(b"012")
        with pytest.raises(ValueError):
            r.eof()

    def test_chunked_with_ext_and_trailers_split_everywhere(self):
        wire = (b"4;ext=1\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n"
                b"X-Trailer: secret\r\nY: z\r\n\r\n")
        for cut in range(1, len(wire)):
            r = sp.BodyReframer("chunked")
            out = r.feed(wire[:cut])
            out += r.feed(wire[cut:])
            assert r.done, cut
            assert out == b"Wikipedia in\r\n\r\nchunks.", cut
            assert b"secret" not in out

    def test_chunked_byte_by_byte(self):
        wire = b"3\r\nabc\r\n0\r\n\r\n"
        r = sp.BodyReframer("chunked")
        out = b"".join(r.feed(wire[i:i + 1]) for i in range(len(wire)))
        assert out == b"abc" and r.done

    @pytest.mark.parametrize("wire", [b"zz\r\nabc\r\n", b"3\r\nabcX\r\n", b"-1\r\n",
                                      b"3 \r\nabc\r\n", b"\r\n", b"3\nabc\r\n",
                                      b"1" * 20 + b"\r\n", b"3;" + b"e" * 5000 + b"\r\n"])
    def test_malformed_chunked(self, wire):
        r = sp.BodyReframer("chunked")
        with pytest.raises(ValueError):
            r.feed(wire)
            r.feed(b"\r\n" * 3)
            r.eof()

    def test_chunked_truncated(self):
        r = sp.BodyReframer("chunked")
        r.feed(b"5\r\nab")
        with pytest.raises(ValueError):
            r.eof()

    def test_close_delimited(self):
        r = sp.BodyReframer("close")
        assert r.feed(b"abc") == b"abc" and not r.done
        r.eof()
        assert r.done

    def test_chunk_framing(self):
        assert sp.BodyReframer.chunk(b"hello") == b"5\r\nhello\r\n"
        assert sp.BodyReframer.chunk(b"") == b""
        assert sp.BodyReframer.LAST == b"0\r\n\r\n"


class TestAddress:
    def test_address_ok(self):
        deny = ["10.240.0.0/29", "8.8.4.0/24"]
        assert sp.address_ok("8.8.8.8", deny)
        assert sp.address_ok("104.18.32.47", deny)
        for bad in ["8.8.4.4", "10.240.0.2", "10.0.0.1", "127.0.0.1", "169.254.169.254",
                    "192.168.65.254", "0.0.0.0", "100.64.0.1", "::1", "2606:4700::6810:84e5",
                    "::ffff:8.8.8.8", "garbage", "", "8.8.8.8 "]:
            assert not sp.address_ok(bad, deny), bad

    def test_upstream_refuses_non_global_resolution(self):
        calls = []
        up = sp.Upstream(resolve=lambda host: calls.append(host) or ["10.0.0.5", "127.0.0.1"])
        with pytest.raises(sp.Refusal):
            up.connect(HOST, ["10.240.0.0/29"])
        assert calls == [HOST]

    def test_upstream_ignores_environment_proxies(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        src = (ROOT / "scripts" / "sandbox_proxy.py").read_text(encoding="utf-8")
        assert "urllib.request" not in src and "getproxies" not in src
        assert "http.client" not in src


class TestCa:
    def test_certificate_loader_without_linux_memfd(self, tmp_path, monkeypatch):
        # macOS and Windows use a deleted temporary leaf file; the CA key
        # never enters that file.
        monkeypatch.delattr(sp.os, "memfd_create", raising=False)
        cert = sp.make_ca(HOST, int(time.time()) + 60)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        assert sp._load_chain(ctx, cert.leaf_pem + cert.leaf_key_pem, tmp_path) is False
        assert list(tmp_path.iterdir()) == []

    def test_ca_shape(self):
        deadline = int(time.time()) + 3600
        b = sp.make_ca(HOST, deadline)
        ca = x509.load_pem_x509_certificate(b.ca_pem)
        assert isinstance(ca.public_key(), ec.EllipticCurvePublicKey)
        assert ca.public_key().curve.name == "secp256r1"
        nc = ca.extensions.get_extension_for_class(x509.NameConstraints)
        assert nc.critical
        assert nc.value.permitted_subtrees == [x509.DNSName(HOST)]
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical and bc.value.ca and bc.value.path_length == 0
        assert int(ca.not_valid_after_utc.timestamp()) == deadline
        leaf = x509.load_pem_x509_certificate(b.leaf_pem)
        assert leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [HOST]
        assert int(leaf.not_valid_after_utc.timestamp()) <= deadline
        assert not hasattr(b, "ca_key") and b"PRIVATE KEY" not in b.ca_pem

    def _handshake(self, ca_pem, chain_pem, tmp_path, sni):
        f = tmp_path / f"chain-{secrets.token_hex(4)}.pem"
        f.write_bytes(chain_pem)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(f))
        f.unlink()
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.load_verify_locations(cadata=ca_pem.decode())
        a, b = socket.socketpair()
        a.settimeout(5)
        b.settimeout(5)
        err = []

        def server():
            try:
                sctx.wrap_socket(a, server_side=True).recv(1)
            except (ssl.SSLError, OSError) as e:
                err.append(e)

        t = threading.Thread(target=server, daemon=True)
        t.start()
        try:
            c = cctx.wrap_socket(b, server_hostname=sni)
            c.close()
            return True
        except ssl.SSLCertVerificationError:
            return False
        finally:
            a.close()
            b.close()
            t.join(5)

    def test_leaf_validates_and_constraints_reject_other_host(self, tmp_path):
        deadline = int(time.time()) + 3600
        b = sp.make_ca(HOST, deadline)
        assert self._handshake(b.ca_pem, b.leaf_pem + b.leaf_key_pem, tmp_path, HOST)
        # Same constrained CA, a leaf for another host: the client must reject it.
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = sp._ca_cert(ca_key, HOST, deadline)
        evil_key = ec.generate_private_key(ec.SECP256R1())
        evil = sp._leaf_cert(ca, ca_key, "evil.example", deadline, evil_key)
        chain = evil.public_bytes(serialization.Encoding.PEM) + evil_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        ca_pem = ca.public_bytes(serialization.Encoding.PEM)
        assert not self._handshake(ca_pem, chain, tmp_path, "evil.example")
        good = sp._leaf_cert(ca, ca_key, HOST, deadline, evil_key)
        chain = good.public_bytes(serialization.Encoding.PEM) + evil_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        assert self._handshake(ca_pem, chain, tmp_path, HOST)


class TestSpec:
    def test_policy_values_accepted(self):
        s = sp.validate_spec(spec_obj(Creds()), time.time())
        assert s["endpoints"][HOST]["host"] == HOST
        assert s["caps"] == BUILD["proxy_caps"]

    @pytest.mark.parametrize("mutate", [
        lambda o: o.pop("deny_nets"),
        lambda o: o.__setitem__("extra", 1),
        lambda o: o["caps"].pop("requests"),
        lambda o: o["caps"].__setitem__("requests", 0),
        lambda o: o["caps"].__setitem__("requests", True),
        lambda o: o.__setitem__("deadline", 1),
        lambda o: o["placeholders"].pop("authorization"),
        lambda o: o["placeholders"].__setitem__("x-more", "abcdefgh"),
        lambda o: o["placeholders"].__setitem__("authorization", "a\r\nb"),
        lambda o: o["endpoints"][HOST]["forward"].__setitem__("query", True),
        lambda o: o["endpoints"][HOST]["forward"].__setitem__("method", "TRACE"),
        lambda o: o["endpoints"][HOST]["forward"].__setitem__("path", "/a/../b"),
        lambda o: o["endpoints"][HOST]["request_headers"].append("host"),
        lambda o: o["endpoints"][HOST]["request_headers"].append("transfer-encoding"),
        lambda o: o["endpoints"][HOST]["request_headers"].append("Accept"),
        lambda o: o["deny_nets"].append("not-a-net"),
        lambda o: o.__setitem__("listen", 70000),
        lambda o: o.__setitem__("refused_hosts_fatal", "auth.openai.com"),
    ])
    def test_malformed_spec_refused(self, mutate):
        obj = spec_obj(Creds())
        mutate(obj)
        with pytest.raises(sp.SpecError):
            sp.validate_spec(obj, time.time())


class TestSource:
    """The module is self-contained and imports cryptography from the APPENDED image path."""

    def test_imports_only_stdlib_and_cryptography(self):
        tree = ast.parse((ROOT / "scripts" / "sandbox_proxy.py").read_text(encoding="utf-8"))
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
        assert mods - {"cryptography", "__future__"} <= set(sys.stdlib_module_names)
        assert "sandbox_auth" not in mods and "hunt_io" not in mods

    def test_image_site_appended_before_cryptography_import(self):
        src = (ROOT / "scripts" / "sandbox_proxy.py").read_text(encoding="utf-8")
        assert sp.IMAGE_SITE == "/usr/local/lib/python3.13/site-packages"
        append = src.index("sys.path.append(IMAGE_SITE)")
        first_crypto = src.index("from cryptography")
        # The module docstring documents stdin; only executable reads matter.
        first_stdin = src.index("sys.stdin.buffer")
        assert append < first_crypto < first_stdin
        assert "sys.path.insert" not in src
        assert sys.path[-1] == sp.IMAGE_SITE or sp.IMAGE_SITE in sys.path

    def test_no_file_dependency_under_the_loader(self):
        src = (ROOT / "scripts" / "sandbox_proxy.py").read_text(encoding="utf-8")
        assert "__file__" not in src
        assert src.isascii()


class TestBindHost:
    """No implicit all-interfaces bind (bandit B104): only the container entry names 0.0.0.0."""

    def test_proxy_requires_bind_host(self):
        with pytest.raises(TypeError):
            sp.Proxy("0" * 32, {}, lambda line: None)

    def test_serve_requires_bind_host(self):
        with pytest.raises(TypeError):
            sp.serve(io.BytesIO(), io.BytesIO())

    def test_container_entry_binds_all_interfaces_explicitly(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(sp, "serve", lambda reader, writer, **kw: seen.update(kw) or 0)
        assert sp.main([], io.BytesIO(), io.BytesIO()) == 0
        assert seen == {"bind_host": "0.0.0.0"}

    def test_self_test_flag_skips_serve(self, monkeypatch):
        monkeypatch.setattr(sp, "self_test", lambda: 7)
        monkeypatch.setattr(sp, "serve", lambda *a, **kw: pytest.fail("serve called"))
        assert sp.main(["--self-test"], None, None) == 7

    def test_one_all_interfaces_literal_with_its_reason(self):
        src = (ROOT / "scripts" / "sandbox_proxy.py").read_text(encoding="utf-8")
        hits = [line for line in src.splitlines() if '"0.0.0.0"' in line]
        assert len(hits) == 1 and "# nosec B104" in hits[0]


# =========================================================================== through the server


class TestFraming:
    """Real HTTP client through CONNECT: re-framed as chunked, framing headers replaced,
    trailer declarations dropped (round-5 note)."""

    def test_content_length_response_via_http_client(self, harness):
        body = json.dumps({"x": secrets.token_hex(3000)}).encode()
        h = harness(lambda r: resp_cl(body, extra=b"X-Up: 1\r\n"))
        c = h.creds
        conn = h.http()
        payload = secrets.token_bytes(5000)
        conn.request("POST", FWD, body=payload, headers=dict(fwd_headers(c)))
        r = conn.getresponse()
        assert r.status == 200
        assert r.getheader("Transfer-Encoding") == "chunked"
        assert r.getheader("Content-Length") is None
        assert r.getheader("Connection") == "close"
        assert r.getheader("X-Up") == "1"
        assert r.read() == body
        conn.close()
        (uh, ub), = h.stub.requests()
        assert ub == payload

    def test_chunked_sse_with_trailers_via_http_client(self, harness):
        events = [b"event: a\ndata: " + secrets.token_hex(n).encode() + b"\n\n"
                  for n in (10, 3000, 1, 8000, 40)]
        h = harness(lambda r: resp_chunked(events, extra=b"Trailer: X-T\r\n",
                                           trailers=b"X-T: v\r\n"))
        conn = h.http()
        conn.request("POST", FWD, body=b"z", headers=dict(fwd_headers(h.creds)))
        r = conn.getresponse()
        assert r.status == 200
        assert r.getheader("Trailer") is None
        assert r.getheader("Content-Type") == "text/event-stream"
        assert r.read() == b"".join(events)
        conn.close()

    def test_wire_framing_exact(self, harness):
        body = b"hello world" * 100
        h = harness(lambda r: resp_cl(body))
        raw = h.raw_tls(forward_request(h.creds, b"q"))
        rhead, rest = raw.split(b"\r\n\r\n", 1)
        low = rhead.lower()
        assert low.count(b"transfer-encoding:") == 1 and b"\r\ntransfer-encoding: chunked" in low
        assert b"content-length" not in low and b"trailer" not in low
        assert rest.endswith(b"0\r\n\r\n")

    def test_close_delimited_response(self, harness):
        body = secrets.token_bytes(20000)
        h = harness(lambda r: [b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n",
                               body])
        conn = h.http()
        conn.request("POST", FWD, body=b"z", headers=dict(fwd_headers(h.creds)))
        r = conn.getresponse()
        assert r.read() == body
        conn.close()

    def test_chunked_request_body_reframed_upstream(self, harness):
        h = harness()
        payload = secrets.token_bytes(30000)
        conn = h.http()
        hs = dict(fwd_headers(h.creds))
        conn.request("POST", FWD, body=iter([payload[:1000], payload[1000:]]), headers=hs,
                     encode_chunked=True)
        r = conn.getresponse()
        assert r.status == 200
        r.read()
        (uh, ub), = h.stub.requests()
        assert ub == payload
        assert b"\r\ntransfer-encoding: chunked\r\n" in uh.lower()

    def test_upstream_receives_rebuilt_request_only(self, harness):
        h = harness()
        c = h.creds
        body = secrets.token_bytes(4096)  # zstd body, passed through unread
        out = h.raw_tls(forward_request(c, body, more=[("X-Forwarded-Host", "evil")]))
        assert out.startswith(b"HTTP/1.1 200 ")
        (uh, ub), = h.stub.requests()
        assert ub == body
        assert uh.startswith(b"POST /backend-api/codex/responses HTTP/1.1\r\nHost: chatgpt.com\r\n")
        assert ("authorization: Bearer " + c.token).encode() in uh
        assert ("chatgpt-account-id: " + c.account).encode() in uh
        assert c.ph_token.encode() not in uh and b"evil" not in uh.lower()
        assert b"accept-encoding: identity" in uh and b"connection: close" in uh
        # The client sees EOF as soon as the worker closes the socket; its audit
        # record is emitted in the worker's finally block immediately afterward.
        end = time.time() + 2
        while time.time() < end and not any(e.get("route") == "forward" for e in h.logs()):
            time.sleep(0.01)
        logs = h.logs()
        fwd = [entry for entry in logs if entry["route"] == "forward"]
        assert len(fwd) == 1 and fwd[0]["status"] == 200 and "x-forwarded-host" in fwd[0]["dropped"]
        for line in h.events:
            assert len(line.encode()) <= 1024
            for secret in (c.token, c.account, c.ph_token, c.ph_account, "evil"):
                assert secret not in line

    def test_hostile_dropped_header_name_is_not_logged(self, harness):
        h = harness()
        # HTTP token syntax permits dots, so a JWT-shaped token can be a
        # header name. Its prefix must not survive the bounded audit record.
        h.raw_tls(forward_request(h.creds, b"q", more=[(h.creds.token, "x")]))
        end = time.time() + 2
        while time.time() < end and not any(e.get("route") == "forward" for e in h.logs()):
            time.sleep(0.01)
        assert any("other" in e["dropped"] for e in h.logs())
        assert all(h.creds.token[:48] not in line for line in h.events)


REFLECT = {
    "json_access_token": lambda c: b'{"access_token":"' + c.token.encode() + b'"}',
    "account_id_alone": lambda c: b'{"id":"' + c.account.encode() + b'"}',
    "bearer_header_value": lambda c: b"echo: Bearer " + c.token.encode(),
    "hex_lower": lambda c: c.token.encode().hex().encode(),
    "hex_upper": lambda c: c.token.encode().hex().upper().encode(),
    "percent": lambda c: urllib.parse.quote(c.token, safe="").encode(),
    "percent_all": lambda c: "".join("%%%02X" % b for b in c.token.encode()).encode(),
}
for _align in range(3):
    REFLECT[f"b64_std_{_align}"] = (lambda a: lambda c: base64.b64encode(
        b"x" * a + c.token.encode()))(_align)
    REFLECT[f"b64_url_{_align}"] = (lambda a: lambda c: base64.urlsafe_b64encode(
        b"x" * a + c.token.encode()).rstrip(b"="))(_align)
    REFLECT[f"b64_bearer_{_align}"] = (lambda a: lambda c: base64.b64encode(
        b"x" * a + ("Bearer " + c.token).encode()))(_align)


def assert_no_needle(data: bytes, creds: Creds):
    for n in creds.needles:
        assert n not in data
    assert creds.token.encode()[:32] not in data


class TestResponseScan:
    @pytest.mark.parametrize("kind", sorted(REFLECT))
    def test_reflective_upstream_aborts(self, harness, kind):
        def respond(r, holder={}):
            return resp_cl(b'{"pad":"' + b"p" * 9000 + b'","v":"' + REFLECT[kind](holder["c"]) +
                           b'"}')
        holder = {}
        h = harness(lambda r: respond(r, holder))
        holder["c"] = h.creds
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert_no_needle(out, h.creds)
        assert h.wait_event("ABORT ") == ["ABORT " + "0" * 32 + " credential"]
        assert h.proxy.stopped.is_set()

    def test_reflection_of_what_upstream_received(self, harness):
        """Regression: an upstream that echoes the request headers it received."""
        h = harness(lambda r: resp_chunked([b"data: ", r[0], b"\n\n"]))
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert_no_needle(out, h.creds)
        assert h.wait_event("ABORT ")

    def test_token_split_across_two_body_reads(self, harness):
        holder = {}

        def respond(r):
            t = holder["c"].token.encode()
            return [b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % (9000 + len(t)),
                    b"a" * 9000 + t[:700], t[700:]]
        h = harness(respond)
        holder["c"] = h.creds
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert_no_needle(out, h.creds)
        assert h.wait_event("ABORT ")

    @pytest.mark.parametrize("framing", ["length", "close", "chunked"])
    def test_token_in_last_bytes_caught_by_finalize(self, harness, framing):
        holder = {}

        def respond(r):
            tail = holder["c"].account.encode()
            body = b"b" * 20000 + tail
            if framing == "length":
                return resp_cl(body)
            if framing == "chunked":
                return resp_chunked([b"b" * 20000, tail])
            return [b"HTTP/1.1 200 OK\r\n\r\n", body]
        h = harness(respond)
        holder["c"] = h.creds
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert_no_needle(out, h.creds)
        assert not out.endswith(b"0\r\n\r\n")
        assert h.wait_event("ABORT ")

    def test_token_only_in_response_header(self, harness):
        holder = {}

        def respond(r):
            return [b"HTTP/1.1 200 OK\r\nX-Echo: " + holder["c"].token.encode() +
                    b"\r\nContent-Length: 2\r\n\r\nok"]
        h = harness(respond)
        holder["c"] = h.creds
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert out == b""
        assert h.wait_event("ABORT ")

    def test_token_in_chunked_sse_stream(self, harness):
        holder = {}

        def respond(r):
            t = holder["c"].token.encode()
            return resp_chunked([b"data: {}\n\n" * 50, b"data: {\"t\":\"" + t[:900],
                                 t[900:] + b"\"}\n\n", b"data: [DONE]\n\n"])
        h = harness(respond)
        holder["c"] = h.creds
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert_no_needle(out, h.creds)
        assert h.wait_event("ABORT ")

    @pytest.mark.parametrize("enc", ["gzip", "br", "zstd", "deflate", "identity, gzip"])
    def test_content_encoding_aborts(self, harness, enc):
        body = gzip.compress(b"hello")
        h = harness(lambda r: resp_cl(body, extra=b"Content-Encoding: " + enc.encode() + b"\r\n"))
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert body not in out and not out.startswith(b"HTTP/1.1 200")
        assert h.wait_event("ABORT ") == ["ABORT " + "0" * 32 + " content_encoding"]

    def test_identity_content_encoding_passes(self, harness):
        h = harness(lambda r: resp_cl(b"plain", extra=b"Content-Encoding: identity\r\n"))
        conn = h.http()
        conn.request("POST", FWD, body=b"z", headers=dict(fwd_headers(h.creds)))
        assert conn.getresponse().read() == b"plain"
        conn.close()
        assert not h.wait_event("ABORT ", timeout=0.3)

    def test_upstream_401_passed_through(self, harness):
        h = harness(lambda r: [b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nno"])
        conn = h.http()
        conn.request("POST", FWD, body=b"z", headers=dict(fwd_headers(h.creds)))
        r = conn.getresponse()
        assert r.status == 401 and r.read() == b"no"
        conn.close()


class TestRouting:
    def _get(self, h, method, target, headers=None, body=None):
        conn = h.http()
        hs = {"Host": HOST} if headers is None else headers
        conn.request(method, target, body=body, headers=hs)
        r = conn.getresponse()
        out = (r.status, r.read())
        conn.close()
        return out

    def test_local_and_refused_routes_never_reach_upstream(self, harness):
        h = harness()
        st, body = self._get(h, "GET", CHECK)
        assert st == 200 and json.loads(body)["default_account_id"] == h.creds.ph_account
        assert self._get(h, "GET", "/backend-api/codex/models?client_version=0.162.1")[0] == 404
        assert self._get(h, "POST", "/backend-api/ps/mcp", body=b"{}")[0] == 404
        assert self._get(h, "GET", FWD)[0] == 404
        assert self._get(h, "GET", FWD, headers={"Host": HOST, "Upgrade": "websocket",
                                                 "Connection": "Upgrade"})[0] == 403
        assert self._get(h, "POST", "/backend-api/codex/%72esponses", body=b"x")[0] == 403
        assert self._get(h, "POST", FWD, headers={"Host": "api.openai.com"}, body=b"x")[0] == 403
        assert self._get(h, "TRACE", FWD)[0] == 403
        time.sleep(0.2)
        assert h.stub.requests() == []
        routes = [entry["route"] for entry in h.logs()]
        assert routes.count("local") == 1 and "forward" not in routes

    def test_forged_authorization_refused(self, harness):
        h = harness()
        c = h.creds
        hs = [(n, ("Bearer " + c.token) if n == "Authorization" else v)
              for n, v in fwd_headers(c, body_len=1)]
        out = h.raw_tls(req(headers=hs, extra=b"q"))
        assert out.startswith(b"HTTP/1.1 403 ")
        time.sleep(0.2)
        assert h.stub.requests() == []

    def test_absolute_form_refused(self, harness):
        h = harness()
        out = h.raw_tls(req(target="https://chatgpt.com" + FWD,
                            headers=fwd_headers(h.creds, body_len=0)))
        assert out.startswith(b"HTTP/1.1 403 ")
        assert h.stub.requests() == []

    def test_nothing_forwarded_before_token(self, harness):
        h = harness(armed=False)
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert out.startswith(b"HTTP/1.1 403 ")
        st, _ = TestRouting._get(self, h, "GET", CHECK)
        assert st == 403
        time.sleep(0.2)
        assert h.stub.requests() == []
        h.proxy.arm(sp.validate_token(h.creds.token_obj, h.creds.placeholders))
        assert h.raw_tls(forward_request(h.creds, b"q")).startswith(b"HTTP/1.1 200 ")

    def test_second_arm_refused(self, harness):
        h = harness()
        with pytest.raises(sp.SpecError):
            h.proxy.arm(sp.validate_token(h.creds.token_obj, h.creds.placeholders))


class TestConnectServer:
    def test_refused_hosts(self, harness):
        h = harness()
        for target in ("api.openai.com:443", "github.com:443", "1.1.1.1:443", "chatgpt.com:80",
                       "example.com:443", "[::1]:443"):
            s, rh, _ = h.raw_connect(target)
            assert rh.startswith(b"HTTP/1.1 403 "), target
            s.close()
        assert not h.wait_event("EVENT ", timeout=0.2)

    def test_auth_openai_is_refresh_attempt(self, harness):
        h = harness()
        # Fatal means the proxy exits on the first refresh attempt.
        s, rh, _ = h.raw_connect("auth.openai.com:443")
        assert rh.startswith(b"HTTP/1.1 403 ")
        s.close()
        assert h.wait_event("EVENT ") == ["EVENT " + "0" * 32 + " refresh_attempt"]

    def test_plain_http_proxy_request_refused(self, harness):
        h = harness()
        s = socket.create_connection(("127.0.0.1", h.proxy.port), timeout=5)
        s.sendall(b"GET http://chatgpt.com/ HTTP/1.1\r\nHost: chatgpt.com\r\n\r\n")
        rh, _ = _read_until(s, b"\r\n\r\n")
        assert rh.startswith(b"HTTP/1.1 403 ")
        s.close()

    def test_wrong_sni_refused(self, harness):
        h = harness()
        # The TLS alert occurs during the client handshake.
        with pytest.raises(ssl.SSLError):
            h.raw_tls(forward_request(h.creds, b"q"), sni="evil.example")
        time.sleep(0.2)
        assert h.stub.requests() == []
        assert any(entry.get("reason") == "sni" for entry in h.logs())

    def test_alpn_http11_only(self, harness):
        h = harness()
        s, rh, _ = h.raw_connect()
        ctx = h.ctx
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        tls = ctx.wrap_socket(s, server_hostname=HOST)
        assert tls.selected_alpn_protocol() == "http/1.1"
        tls.close()


class TestCaps:
    def test_requests_cap(self, harness):
        caps = dict(BUILD["proxy_caps"], requests=3)
        h = harness(caps=caps)
        assert h.raw_tls(forward_request(h.creds, b"q")).startswith(b"HTTP/1.1 200 ")
        # CONNECT and the inner request each consume a request slot. A denied
        # third slot may reset on Windows before a refusal reaches the client.
        try:
            out = h.raw_tls(forward_request(h.creds, b"q"))
        except (OSError, AssertionError):
            out = b""
        assert not out.startswith(b"HTTP/1.1 200 ")
        assert len(h.stub.requests()) == 1

    def test_header_block_cap(self, harness):
        caps = dict(BUILD["proxy_caps"], header_block=4096)
        h = harness(caps=caps)
        out = h.raw_tls(forward_request(h.creds, b"q", more=[("x-codex-turn-metadata",
                                                               "m" * 5000)]))
        assert out.startswith(b"HTTP/1.1 403 ")
        assert h.stub.requests() == []

    def test_response_header_block_cap(self, harness):
        caps = dict(BUILD["proxy_caps"], header_block=4096)
        h = harness(lambda r: [b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 8000 +
                               b"\r\nContent-Length: 0\r\n\r\n"], caps=caps)
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert not out.startswith(b"HTTP/1.1 200")

    def test_bytes_up_cap(self, harness):
        caps = dict(BUILD["proxy_caps"], bytes_up=1000)
        h = harness(caps=caps)
        out = h.raw_tls(forward_request(h.creds, b"q" * 2000))
        assert out.startswith(b"HTTP/1.1 403 ")
        assert h.stub.requests() == []

    def test_empty_request_still_charges_rebuilt_headers(self, harness):
        caps = dict(BUILD["proxy_caps"], bytes_up=100)
        h = harness(caps=caps)
        out = h.raw_tls(forward_request(h.creds, b""))
        assert out.startswith(b"HTTP/1.1 403 ")
        assert h.stub.requests() == []

    def test_chunk_extension_bytes_count_toward_ingress_cap(self, harness):
        h = harness(caps=dict(BUILD["proxy_caps"], bytes_up=3000))
        body = b"1;" + b"x" * 4090 + b"\r\nq\r\n0\r\n\r\n"
        request = req(headers=fwd_headers(h.creds) + [("Transfer-Encoding", "chunked")], extra=body)
        out = h.raw_tls(request)
        assert not out.startswith(b"HTTP/1.1 200")
        assert h.stub.requests() == []

    def test_bytes_down_cap(self, harness):
        caps = dict(BUILD["proxy_caps"], bytes_down=10000)
        h = harness(lambda r: resp_cl(b"d" * 50000), caps=caps)
        out = h.raw_tls(forward_request(h.creds, b"q"))
        assert not out.endswith(b"0\r\n\r\n")
        assert out.count(b"d") < 20000

    def test_concurrent_cap(self, harness):
        caps = dict(BUILD["proxy_caps"], concurrent=1)
        h = harness(caps=caps)
        hold, rh, _ = h.raw_connect()   # occupies the single slot (TLS never started)
        assert rh.startswith(b"HTTP/1.1 200 ")
        s = socket.create_connection(("127.0.0.1", h.proxy.port), timeout=5)
        s.sendall(f"CONNECT {HOST}:443 HTTP/1.1\r\n\r\n".encode())
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        assert not data.startswith(b"HTTP/1.1 200")
        s.close()
        hold.close()


class TestLifecycle:
    def test_deadline_stops_the_proxy(self, harness):
        h = harness(deadline=time.time() + 1.5)
        assert h.proxy.stopped.wait(5)
        with pytest.raises(OSError):
            s = socket.create_connection(("127.0.0.1", h.proxy.port), timeout=1)
            s.sendall(b"CONNECT chatgpt.com:443 HTTP/1.1\r\n\r\n")
            if not s.recv(10):
                raise OSError("closed")

    def _serve(self, tmp_path, chunks, creds, *, spec=None, close_after=True, wait=None):
        r, w = os.pipe()
        out = []

        class Out:
            def write(self, b):
                out.append(bytes(b))

            def flush(self):
                pass

        rd = os.fdopen(r, "rb", buffering=0)
        res = {}

        def target():
            res["code"] = sp.serve(rd, Out(), bind_host="127.0.0.1", keydir=tmp_path)

        t = threading.Thread(target=target, daemon=True)
        t.start()
        for chunk in chunks:
            if callable(chunk):
                chunk(out)
                continue
            os.write(w, chunk)
            time.sleep(0.1)
        if close_after:
            os.close(w)
        t.join(10)
        if not close_after:
            os.close(w)
        return res.get("code"), b"".join(out).decode("ascii")

    def test_protocol_ready_token_eof(self, tmp_path):
        c = Creds()
        nonce = secrets.token_hex(16)
        spec = json.dumps(spec_obj(c), separators=(",", ":")).encode()
        body = json.dumps(c.token_obj, separators=(",", ":")).encode()

        def wait_ready(out):
            end = time.time() + 5
            while time.time() < end and not b"".join(out).startswith(b"READY"):
                time.sleep(0.05)

        code, text = self._serve(tmp_path, [nonce.encode() + b"\n", spec + b"\n", wait_ready,
                                            b"TOKEN %d\n" % len(body) + body], c)
        assert code == 0
        lines = text.splitlines()
        m = re.fullmatch(r"READY ([0-9a-f]{32}) ([A-Za-z0-9+/=]+)", lines[0])
        assert m and m.group(1) == nonce
        ca = x509.load_pem_x509_certificate(base64.b64decode(m.group(2)))
        assert ca.extensions.get_extension_for_class(x509.NameConstraints)
        assert re.fullmatch(r"END [0-9a-f]{32} \{.*\}", lines[-1])
        assert json.loads(lines[-1].split(" ", 2)[2])["forwarded"] == 0
        assert c.token not in text and c.account not in text

    def test_token_from_sandbox_auth_message_accepted(self, tmp_path):
        """U4's exact framing: b"TOKEN <len>\\n" + compact JSON, no newline after it."""
        c = Creds()
        body = json.dumps({"headers": c.real, "needles_from": {"access_token": c.token,
                                                               "account_id": c.account}},
                          separators=(",", ":")).encode("ascii")
        msg = b"TOKEN %d\n" % len(body) + body
        nonce = secrets.token_hex(16)
        spec = json.dumps(spec_obj(c)).encode()
        code, text = self._serve(tmp_path, [nonce.encode() + b"\n", spec + b"\n", msg], c)
        assert code == 0 and "ABORT" not in text

    @pytest.mark.parametrize("bad", [
        lambda n, s, c: [b"nothex\n", s + b"\n"],
        lambda n, s, c: [n + b"\n", b"{not json}\n"],
        lambda n, s, c: [n + b"\n", s + b"\n", b"TOKEN 5\nabcde"],
        lambda n, s, c: [n + b"\n", s + b"\n", b"TOKEN 05\n"],
        lambda n, s, c: [n + b"\n", s + b"\n", b"HELLO\n"],
        lambda n, s, c: [n + b"\n", s + b"\n", c + b"\n"],          # newline after the JSON
    ])
    def test_protocol_errors_exit_2(self, tmp_path, bad):
        c = Creds()
        nonce = secrets.token_hex(16).encode()
        spec = json.dumps(spec_obj(c)).encode()
        body = json.dumps(c.token_obj, separators=(",", ":")).encode()
        tok = b"TOKEN %d\n" % len(body) + body
        code, text = self._serve(tmp_path, bad(nonce, spec, tok), c)
        assert code == 2
        assert c.token not in text

    def test_spec_error_never_ready(self, tmp_path):
        c = Creds()
        obj = spec_obj(c)
        obj["placeholders"]["x"] = "abcdefgh"
        nonce = secrets.token_hex(16).encode()
        code, text = self._serve(tmp_path, [nonce + b"\n", json.dumps(obj).encode() + b"\n"], c)
        assert code == 2 and "READY" not in text
        assert text.startswith("ABORT " + nonce.decode() + " spec")


# =========================================================================== image self-test

DOCKER = os.environ.get("CLAUDEX_DOCKER_TESTS") == "1"


@pytest.mark.skipif(not DOCKER, reason="set CLAUDEX_DOCKER_TESTS=1")
def test_self_test_in_image_imports_cryptography_from_image_site():
    """python3 -I -S through U6's loader in the pinned python-test:3 image, --network none:
    cryptography resolves from the APPENDED IMAGE_SITE, a CA + leaf handshake runs in memory."""
    import sandbox_run
    img = POLICY["images"]["python-test"]["id"]
    source = (ROOT / "scripts" / "sandbox_proxy.py").read_bytes()
    tail, stdin = sandbox_run.bootstrap(source)
    name = "claudex-measure-" + uuid.uuid4().hex[:12]
    argv = ["docker", "--context", POLICY["context"], "run", "--rm", "-i", "--name", name,
            "--label", "claudex.measure=1", "--network", "none", "--pull=never", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532",
            "--tmpfs", "/tmp:size=16m", img, *tail, "--self-test"]
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, timeout=120)
    finally:
        subprocess.run(["docker", "--context", POLICY["context"], "rm", "-f", name],
                       capture_output=True, timeout=60)
    out = p.stdout.decode("ascii", "replace")
    assert p.returncode == 0, (out, p.stderr.decode("ascii", "replace")[-2000:])
    assert re.search(r"^SELFTEST ok cryptography=50\.0\.2 "
                     r"from=/usr/local/lib/python3\.13/site-packages/cryptography/", out, re.M)
    assert "memfd=1" in out and "handshake=ok" in out and "roots=1" in out
