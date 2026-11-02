"""Per-run CONNECT/TLS token proxy, loaded under -I -S from trusted plugin bytes.

The binary stdin protocol supplies a nonce, bounded spec and deferred TOKEN.
Only the fixed Codex responses endpoint receives injected host credentials;
all downstream bytes are scanned before release. EOF or the lifetime timer
closes the listener and active sockets. No builder-controlled imports are used.
"""
from __future__ import annotations

import base64
import datetime
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import namedtuple

IMAGE_SITE = "/usr/local/lib/python3.13/site-packages"
sys.path.append(IMAGE_SITE)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HOST = "chatgpt.com"
FORWARD = "/backend-api/codex/responses"
LOCAL = "/backend-api/wham/accounts/check"
KEYS = {"authorization", "chatgpt-account-id"}
COPY_HEADERS = {"content-type", "content-encoding", "accept", "originator", "version", "session-id", "thread-id", "x-client-request-id", "x-codex-window-id", "x-codex-turn-metadata", "x-codex-routing-hint"}
CAPS = {"requests": 2000, "concurrent": 16, "bytes_up": 268435456, "bytes_down": 2147483648, "header_block": 65536}
TOKEN_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
Head = namedtuple("Head", "method target version headers")
Certificate = namedtuple("Certificate", "ca_pem leaf_pem leaf_key_pem")

class Refusal(ValueError):
    """A malformed or disallowed client request that must not reach upstream."""
    pass

class SpecError(ValueError):
    """Invalid trusted bootstrap or TOKEN data; the proxy cannot safely serve."""
    pass

class Hit(Exception):
    """A credential needle was found; buffered bytes must not be released."""
    pass

def _safe(value, minimum=1, maximum=16384):
    return isinstance(value, str) and minimum <= len(value) <= maximum and all(32 <= ord(c) < 127 for c in value)

def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise SpecError("duplicate key")
        out[k] = v
    return out

def _json(data):
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise SpecError("invalid document") from None
    if not isinstance(value, dict):
        raise SpecError("invalid document")
    return value

def validate_spec(obj, now=None):
    """Validate exact routes, placeholders, caps and a deadline within one hour; return a detached spec or raise SpecError."""
    now = time.time() if now is None else now
    try:
        if set(obj) != {"endpoints", "placeholders", "refused_hosts_fatal", "listen", "caps", "deadline", "deny_nets"}:
            raise ValueError
        if set(obj["endpoints"]) != {HOST}:
            raise ValueError
        ep = obj["endpoints"][HOST]
        if set(ep) != {"forward", "local", "request_headers", "placeholder_headers"}:
            raise ValueError
        if ep["forward"] != {"method": "POST", "path": FORWARD, "query": False} or ep["local"] != {"method": "GET", "path": LOCAL, "query": False}:
            raise ValueError
        hs = ep["request_headers"]
        if not isinstance(hs, list) or len(hs) != len(set(hs)) or not set(hs) <= COPY_HEADERS:
            raise ValueError
        if sorted(ep["placeholder_headers"]) != sorted(KEYS):
            raise ValueError
        ph = obj["placeholders"]
        if set(ph) != KEYS or not all(_safe(v, 8) for v in ph.values()) or not ph["authorization"].startswith("Bearer "):
            raise ValueError
        if obj["refused_hosts_fatal"] != ["auth.openai.com"]:
            raise ValueError
        if set(obj["caps"]) != set(CAPS):
            raise ValueError
        for k, v in obj["caps"].items():
            if type(v) is not int or not 1 <= v <= CAPS[k]:
                raise ValueError
        if type(obj["listen"]) is not int or not 0 <= obj["listen"] <= 65535:
            raise ValueError
        d = obj["deadline"]
        if type(d) not in (float, int) or not math.isfinite(d) or not now < d <= now + 3600:
            raise ValueError
        if not isinstance(obj["deny_nets"], list) or not obj["deny_nets"]:
            raise ValueError
        for net in obj["deny_nets"]:
            ipaddress.ip_network(net)
        result = json.loads(json.dumps(obj))
        result["endpoints"][HOST]["host"] = HOST
        return result
    except (ValueError, TypeError, KeyError, OverflowError):
        raise SpecError("invalid spec") from None

def validate_token(obj, placeholders):
    """Validate header/needle consistency and derive scan variants; raise SpecError without disclosing supplied values."""
    try:
        if set(obj) != {"headers", "needles_from"} or set(obj["headers"]) != set(placeholders):
            raise ValueError
        h, c = obj["headers"], obj["needles_from"]
        if set(c) != {"access_token", "account_id"} or set(h) != KEYS:
            raise ValueError
        if not all(_safe(v, 8) for v in [*h.values(), *c.values()]):
            raise ValueError
        if h["authorization"] != "Bearer " + c["access_token"] or h["chatgpt-account-id"] != c["account_id"]:
            raise ValueError
        return {"headers": dict(h), "needles": needles(c["access_token"], c["account_id"], h.values())}
    except (ValueError, TypeError, KeyError):
        raise SpecError("invalid token") from None

def allowed_connect(host, port, spec):
    """Classify a CONNECT authority as tls, fatal refresh attempt, or refuse."""
    if host.lower() in spec["refused_hosts_fatal"]:
        return "fatal"
    return "tls" if host.lower() == HOST and port == 443 else "refuse"

def parse_authority(value):
    """Parse an explicit host:port authority and reject ambiguous or malformed CONNECT targets."""
    m = re.fullmatch(r"([A-Za-z0-9.-]+):([1-9][0-9]{0,4})", value)
    if not m or int(m[2]) > 65535:
        return None
    return m[1].lower(), int(m[2])

def sni_ok(client_hello, host):
    """Read a complete TLS ClientHello record; substring matches cannot authorize SNI."""
    try:
        b = client_hello
        if len(b) < 9 or b[0] != 22 or int.from_bytes(b[3:5], "big") != len(b) - 5 or b[5] != 1:
            return False
        if int.from_bytes(b[6:9], "big") != len(b) - 9:
            return False
        i = 43
        i += 1 + b[i]
        n = int.from_bytes(b[i:i+2], "big"); i += 2 + n
        i += 1 + b[i]
        n = int.from_bytes(b[i:i+2], "big"); i += 2
        end = i + n
        if end != len(b):
            return False
        found = []
        while i < end:
            kind = int.from_bytes(b[i:i+2], "big")
            size = int.from_bytes(b[i+2:i+4], "big"); i += 4
            data = b[i:i+size]; i += size
            if len(data) != size:
                return False
            if kind == 0:
                if len(data) < 5 or int.from_bytes(data[:2], "big") != len(data)-2 or data[2] != 0:
                    return False
                if int.from_bytes(data[3:5], "big") != len(data)-5:
                    return False
                found.append(data[5:].decode("ascii"))
        return i == end and found == [host]
    except (IndexError, UnicodeError, ValueError):
        return False

def _headers(lines):
    if len(lines) > 128:
        raise Refusal("headers")
    out = []
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep or not TOKEN_NAME.fullmatch(name) or not all(32 <= ord(c) < 127 or c == '\t' for c in value):
            raise Refusal("headers")
        out.append((name.lower(), value.strip(" \t")))
    return out

def parse_request_head(data, cap):
    """Parse a bounded ASCII HTTP head, rejecting invalid request lines and headers with Refusal."""
    if len(data) > cap or not data.endswith(b"\r\n\r\n"):
        raise Refusal("head")
    try:
        lines = data[:-4].decode("ascii").split("\r\n")
    except UnicodeError:
        raise Refusal("head") from None
    m = re.fullmatch(r"([A-Z]+) ([\x21-\x7e]+) (HTTP/1\.[01])", lines[0])
    if not m or (m[3] != "HTTP/1.1" and m[1] != "CONNECT"):
        raise Refusal("request line")
    return Head(m[1], m[2], m[3], _headers(lines[1:]))

def _values(headers, name):
    return [v for k, v in headers if k.lower() == name]

def classify(method, raw_target, headers, endpoint):
    """Return forward/local or a refusal status after exact authority, method and raw-target checks."""
    if method in ("TRACE", "OPTIONS", "CONNECT"):
        return 403
    if [v.lower() for v in _values(headers, "host")] not in ([HOST], [HOST + ":443"]):
        return 403
    if any(v.lower() == "websocket" for v in _values(headers, "upgrade")):
        return 403
    path = raw_target.split("?", 1)[0]
    if ("%" in raw_target or "#" in raw_target or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]*", path)
            or any(p in ("", ".", "..") for p in path.split("/")[1:-1])
            or (path.endswith("//") or "//" in path)):
        return 403
    if "?" in raw_target:
        return 404
    for route in ("forward", "local"):
        r = endpoint[route]
        if method == r["method"] and raw_target == r["path"]:
            return route
    return 404

def _framing(headers, response=False):
    lengths, transfers = _values(headers, "content-length"), _values(headers, "transfer-encoding")
    if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers):
        raise Refusal("framing")
    if transfers:
        if transfers[0].lower() != "chunked":
            raise Refusal("framing")
        return "chunked", None
    if lengths:
        if not re.fullmatch(r"[0-9]{1,16}", lengths[0]):
            raise Refusal("framing")
        return "length", int(lengths[0])
    return ("close", None) if response else ("length", 0)

def dropped_headers(head, endpoint):
    """Return only names of discarded request headers, never their potentially sensitive values."""
    keep = set(endpoint["request_headers"]) | KEYS | {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}
    return list(dict.fromkeys(k for k, _ in head.headers if k not in keep))

def rebuild_request(head, endpoint, placeholders, real):
    """Build a fresh upstream head with real credentials only after exact placeholder checks; return Refusal on rejection."""
    try:
        if real is None or set(real) != set(placeholders) or set(real) != KEYS:
            raise Refusal("unarmed")
        if classify(head.method, head.target, head.headers, endpoint) != "forward":
            raise Refusal("route")
        for k in KEYS:
            if _values(head.headers, k) != [placeholders[k]] or not _safe(real[k]):
                raise Refusal("placeholder")
        mode, size = _framing(head.headers)
        out = ["POST " + FORWARD + " HTTP/1.1", "Host: " + HOST]
        for k in endpoint["request_headers"]:
            vs = _values(head.headers, k)
            if len(vs) > 1:
                raise Refusal("duplicate header")
            if vs:
                out.append(k + ": " + vs[0])
        out += [k + ": " + real[k] for k in sorted(KEYS)]
        out += ["accept-encoding: identity", "connection: close"]
        out += ["transfer-encoding: chunked" if mode == "chunked" else "content-length: " + str(size)]
        return ("\r\n".join(out) + "\r\n\r\n").encode("ascii")
    except Refusal as e:
        return e

def local_answer(route, placeholders):
    """Build a local HTTP response; account discovery uses placeholder identity and never contacts upstream."""
    status = 200 if route == "local" else int(route)
    body = b""
    if route == "local":
        account = placeholders["chatgpt-account-id"]
        body = json.dumps({"accounts": [{"id": account, "workspace_backend_origin": "https://chatgpt.com",
                                         "account_routing_override": "NO_CONSTRAINT"}],
                           "default_account_id": account}, separators=(",", ":")).encode("ascii")
    return (f"HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)

def needles(access_token, account_id, header_values):
    """Wire-compatible with U4, while keeping this loader source self-contained."""
    out, seen = [], set()
    for c in dict.fromkeys([access_token, account_id, *list(header_values)]):
        if not _safe(c, 8):
            raise SpecError("needle component")
        secret = c.encode("utf-8")
        forms = [secret]
        for align in range(3):
            start, stop = -(-8 * align // 6), (8 * (align + len(secret))) // 6
            for enc in (base64.b64encode, base64.urlsafe_b64encode):
                full = enc(b"\x00" * align + secret)
                forms += [full[start:stop], full[start:], full[start:].rstrip(b"=")]
        forms += [secret.hex().encode(), secret.hex().upper().encode(),
                  urllib.parse.quote(secret, safe="").encode(), urllib.parse.quote_plus(secret, safe="").encode(),
                  "".join("%%%02X" % b for b in secret).encode(), "".join("%%%02x" % b for b in secret).encode()]
        for n in forms:
            if len(n) >= 8 and n not in seen:
                seen.add(n); out.append(n)
    return out

class Scanner:
    """Streaming credential detector that retains enough overlap to catch needles spanning arbitrary read boundaries."""
    def __init__(self, needles):
        self.needles = list(needles)
        if not self.needles or any(not isinstance(n, bytes) or not n for n in self.needles):
            raise ValueError("needles")
        self.overlap = max(map(len, self.needles)) - 1
        self.tail = b""
        self.closed = False

    def feed(self, chunk):
        """Return only the safe prefix, retaining overlap; raise Hit before releasing any bytes from a matching chunk."""
        if self.closed:
            raise RuntimeError("scanner finished")
        data = self.tail + chunk
        if any(n in data for n in self.needles):
            self.closed = True; self.tail = b""
            raise Hit("credential")
        cut = max(0, len(data) - self.overlap)
        self.tail = data[cut:]
        return data[:cut]

    def finalize(self):
        """Scan and release the remaining tail at EOF, then reject further input."""
        out = self.feed(b"") + self.tail
        self.closed = True; self.tail = b""
        return out

class BodyReframer:
    """Incremental HTTP body parser; trailers never become payload."""
    LAST = b"0\r\n\r\n"

    def __init__(self, mode, length=None):
        if mode not in ("length", "chunked", "close"):
            raise ValueError("mode")
        self.mode, self.remaining = mode, length
        self.done = mode == "length" and length == 0
        self.extra = b""
        self.buf = b""
        self.state = "size"
        self.trailer_bytes = 0

    @staticmethod
    def chunk(data):
        """Encode payload as a downstream HTTP chunk; an empty payload produces no chunk."""
        return (b"%x\r\n" % len(data) + data + b"\r\n") if data else b""

    def feed(self, data):
        """Consume upstream framing and yield payload only; reject malformed chunks and retain incomplete framing."""
        if self.done:
            self.extra += data
            return b""
        if self.mode == "close":
            return data
        if self.mode == "length":
            out = data[:self.remaining]
            self.remaining -= len(out)
            if self.remaining == 0:
                self.done = True; self.extra = data[len(out):]
            return out
        self.buf += data
        out = []
        while not self.done:
            if self.state in ("size", "trailer"):
                at = self.buf.find(b"\r\n")
                if at < 0:
                    if len(self.buf) > 4096 or b"\n" in self.buf:
                        raise ValueError("chunk line")
                    break
                if at > 4096:
                    raise ValueError("chunk line")
                line, self.buf = self.buf[:at], self.buf[at+2:]
                if self.state == "trailer":
                    self.trailer_bytes += at + 2
                    if self.trailer_bytes > 65536:
                        raise ValueError("trailers")
                    if not line:
                        self.done = True; self.extra = self.buf; self.buf = b""
                    else:
                        _headers([line.decode("ascii")])
                    continue
                if not re.fullmatch(rb"[0-9a-fA-F]{1,16}(;[\x20-\x7e]*)?", line):
                    raise ValueError("chunk size")
                self.remaining = int(line.split(b";", 1)[0], 16)
                self.state = "data" if self.remaining else "trailer"
            elif self.state == "data":
                size = min(len(self.buf), self.remaining)
                out.append(self.buf[:size]); self.buf = self.buf[size:]; self.remaining -= size
                if self.remaining:
                    break
                self.state = "crlf"
            else:
                if len(self.buf) < 2:
                    break
                if not self.buf.startswith(b"\r\n"):
                    raise ValueError("chunk delimiter")
                self.buf = self.buf[2:]; self.state = "size"
        return b"".join(out)

    def eof(self):
        """Finish close-delimited bodies or reject truncated length/chunked framing."""
        if self.mode == "close":
            self.done = True
        if not self.done:
            raise ValueError("truncated body")

def address_ok(ip, deny_nets):
    """Allow only global unicast IPv4 addresses outside every supplied deny network; invalid addresses fail closed."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and addr.is_global and not addr.is_multicast and all(addr not in ipaddress.ip_network(n) for n in deny_nets)
    except ValueError:
        return False

def _name(host):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])

def _ca_cert(key, host, not_after):
    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(_name("claudex ephemeral CA")).issuer_name(_name("claudex ephemeral CA"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(datetime.datetime.fromtimestamp(not_after, datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.NameConstraints([x509.DNSName(host)], None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))

def _leaf_cert(ca, ca_key, host, not_after, key):
    return (x509.CertificateBuilder().subject_name(_name(host)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1))
            .not_valid_after(datetime.datetime.fromtimestamp(not_after, datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))

def make_ca(host, not_after):
    """Generate a per-run CA and host-only leaf expiring at not_after; return PEMs without exporting the CA private key."""
    if host != HOST:
        raise SpecError("CA host")
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = _ca_cert(key, host, not_after)
    leaf = _leaf_cert(ca, key, host, not_after, leaf_key)
    return Certificate(ca.public_bytes(serialization.Encoding.PEM), leaf.public_bytes(serialization.Encoding.PEM),
                       leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

def _load_chain(context, pem, keydir=None):
    # OpenSSL needs a path for load_cert_chain. Linux memfd avoids even tmpfs
    # persistence of the short-lived leaf key; Windows tests use a deleted file.
    if hasattr(os, "memfd_create"):
        fd = os.memfd_create("claudex-leaf", getattr(os, "MFD_CLOEXEC", 0))
        try:
            view = memoryview(pem)
            while view:
                written = os.write(fd, view)
                if written == 0:
                    raise OSError("short certificate write")
                view = view[written:]
            context.load_cert_chain(f"/proc/self/fd/{fd}")
        finally:
            os.close(fd)
        return True
    fd, path = tempfile.mkstemp(dir=keydir, prefix="claudex-leaf-", suffix=".pem")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        context.load_cert_chain(path)
    finally:
        os.unlink(path)
    return False

class Upstream:
    """Direct address-pinned sockets, independent of environment proxy settings.

    Constructor injection allows hermetic tests; the wire spec has no dial options.
    """
    def __init__(self, port=443, resolve=None, context=None, address_check=address_ok):
        self.port, self.resolve, self.context, self.address_check = port, resolve, context, address_check

    def open(self, host, deny_nets, timeout=10):
        """Resolve and validate every upstream address, then connect with certificate-verified TLS to the allowed host."""
        addrs = self.resolve(host) if self.resolve else list(dict.fromkeys(a[4][0] for a in socket.getaddrinfo(host, self.port, socket.AF_INET, socket.SOCK_STREAM)))
        if not addrs or not all(self.address_check(a, deny_nets) for a in addrs):
            raise Refusal("upstream address")
        ctx = self.context or ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(timeout)
            raw.connect((addrs[0], self.port))
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise

    connect = open

def _read_head(sock, cap):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        b = sock.recv(1)
        if not b or len(data) >= cap:
            raise Refusal("head")
        data.extend(b)
    return bytes(data)

def _response_head(raw):
    try:
        lines = raw[:-4].decode("ascii").split("\r\n")
        m = re.fullmatch(r"HTTP/1\.[01] ([2-5][0-9]{2}) [\x20-\x7e]*", lines[0])
        if not m:
            raise ValueError
        return int(m[1]), _headers(lines[1:])
    except (ValueError, UnicodeError):
        raise Refusal("response head") from None

class Proxy:
    """Per-run TLS injection proxy with shared caps, deadline, credential scanning and supervised connection cleanup."""
    def __init__(self, nonce, spec, emit, *, bind_host="0.0.0.0", upstream=None, keydir=None):
        self.nonce, self.spec, self.emit = nonce, spec, emit
        self.bind_host, self.upstream, self.keydir = bind_host, upstream or Upstream(), keydir
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.sockets, self.workers = set(), set()
        self.token = None
        self.counts = {"requests": 0, "forwarded": 0, "bytes_up": 0, "bytes_down": 0}
        self.active = 0
        self.exitcode = 0
        self.listener = None
        self.timer = None

    def _emit(self, line):
        with self.lock:
            self.emit(line)

    def arm(self, token):
        """Install validated TOKEN data exactly once; refuse replacement or arming after shutdown."""
        with self.lock:
            if self.token is not None or self.stopped.is_set():
                raise SpecError("already armed or stopped")
            self.token = token

    def start(self):
        """Create the ephemeral TLS identity, start the listener and deadline timer, and announce READY with the public CA."""
        cert = make_ca(HOST, self.spec["deadline"])
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.set_alpn_protocols(["http/1.1"])
        def check_sni(sock, name, context):
            return None if name == HOST else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        self.ctx.set_servername_callback(check_sni)
        _load_chain(self.ctx, cert.leaf_pem + cert.leaf_key_pem, self.keydir)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((self.bind_host, self.spec["listen"]))
        self.listener.listen(self.spec["caps"]["concurrent"])
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.timer = threading.Timer(max(0, self.spec["deadline"] - time.time()), self.stop, args=("deadline",))
        self.timer.daemon = True; self.timer.start()
        self.acceptor = threading.Thread(target=self._accept, daemon=True)
        self.acceptor.start()
        return cert.ca_pem

    def stop(self, reason="eof"):
        """Stop accepting requests, close active sockets and cancel the timer; safe to call repeatedly."""
        with self.lock:
            if self.stopped.is_set():
                return
            self.stopped.set()
            if self.timer:
                self.timer.cancel()
            if self.listener:
                self.listener.close()
            for sock in list(self.sockets):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    def abort(self, reason, code=5):
        """Announce the fatal reason once and shut down the entire run rather than forwarding more bytes."""
        with self.lock:
            if not self.stopped.is_set():
                self.exitcode = code
                self._emit("ABORT " + self.nonce + " " + reason)
                self.stop(reason)

    def _charge(self, key, n):
        with self.lock:
            if self.stopped.is_set() or self.counts[key] + n > self.spec["caps"][key]:
                raise Refusal("cap")
            self.counts[key] += n

    def _track(self, sock):
        with self.lock:
            if self.stopped.is_set():
                sock.close(); raise Refusal("stopped")
            self.sockets.add(sock)
        return sock

    def _accept(self):
        while not self.stopped.is_set():
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                if self.active >= self.spec["caps"]["concurrent"]:
                    sock.close(); continue
                self.active += 1
                self.sockets.add(sock)
                t = threading.Thread(target=self._handle, args=(sock,), daemon=True)
                self.workers.add(t); t.start()

    def _handle(self, sock):
        owned = [sock]
        route, status, method, host, dropped = 403, 403, "invalid", "refused", []
        start = time.monotonic()
        up_bytes, down_bytes = 0, 0
        try:
            sock.settimeout(min(10, max(.1, self.spec["deadline"] - time.time())))
            self._charge("requests", 1)
            head = parse_request_head(_read_head(sock, self.spec["caps"]["header_block"]), self.spec["caps"]["header_block"])
            authority = parse_authority(head.target)
            if head.method != "CONNECT" or authority is None:
                raise Refusal("connect")
            h, port = authority
            decision = allowed_connect(h, port, self.spec)
            host = h if h in (HOST, "auth.openai.com") else "refused"
            method = "CONNECT"
            if decision == "fatal":
                sock.sendall(local_answer(403, {}))
                self._emit("EVENT " + self.nonce + " refresh_attempt")
                self.exitcode = 5; self.stop("refresh_attempt"); return
            if decision != "tls":
                raise Refusal("connect")
            sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            sock = self._track(self.ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False))
            owned.append(sock)
            sock.do_handshake()
            self._charge("requests", 1)
            raw = _read_head(sock, self.spec["caps"]["header_block"])
            head = parse_request_head(raw, self.spec["caps"]["header_block"])
            if self.token is None:
                self._drain_rejected(sock, head)
                raise Refusal("unarmed")
            method = head.method if head.method in {"POST", "GET", "TRACE", "OPTIONS", "CONNECT", "PUT", "DELETE", "HEAD", "PATCH"} else "other"
            endpoint = self.spec["endpoints"][HOST]
            route = classify(head.method, head.target, head.headers, endpoint)
            if route != "forward":
                status = 200 if route == "local" else route
                self._drain_rejected(sock, head)
                sock.sendall(local_answer(route, self.spec["placeholders"])); return
            rebuilt = rebuild_request(head, endpoint, self.spec["placeholders"], self.token["headers"])
            if isinstance(rebuilt, Refusal):
                route = 403; raise rebuilt
            mode, length = _framing(head.headers)
            if length is not None and length + len(rebuilt) > self.spec["caps"]["bytes_up"] - self.counts["bytes_up"]:
                raise Refusal("cap")
            # A hostile header name can itself contain a token fragment. Keep
            # names in the audit only when they are from this fixed vocabulary.
            known_dropped = {"x-forwarded-host", "cookie", "proxy-authorization", "expect"}
            dropped = [k if k in known_dropped else "other" for k in dropped_headers(head, endpoint)[:8]]
            up = self._track(self.upstream.open(HOST, self.spec["deny_nets"]))
            owned.append(up)
            self._charge("bytes_up", len(rebuilt))
            up.sendall(rebuilt)
            parser = BodyReframer(mode, length)
            while not parser.done:
                data = sock.recv(65536)
                if not data:
                    parser.eof(); break
                # Chunk extensions and trailers consume ingress bandwidth and
                # parser work even when they never become upstream payload.
                self._charge("bytes_up", len(data))
                body = parser.feed(data)
                wire = BodyReframer.chunk(body) if mode == "chunked" else body
                self._charge("bytes_up", len(wire)); up_bytes += len(wire)
                up.sendall(wire)
            if mode == "chunked":
                self._charge("bytes_up", len(BodyReframer.LAST))
                up.sendall(BodyReframer.LAST)
            with self.lock:
                self.counts["forwarded"] += 1
            response = _read_head(up, self.spec["caps"]["header_block"])
            self._charge("bytes_down", len(response))
            scanner = Scanner(self.token["needles"])
            scanner.feed(response); scanner.finalize()
            status, hs = _response_head(response)
            if any(v.lower() != "identity" for v in _values(hs, "content-encoding")):
                self.abort("content_encoding"); return
            mode, length = _framing(hs, response=True)
            hop = {"content-length", "transfer-encoding", "trailer", "connection", "keep-alive", "upgrade", "proxy-authenticate", "proxy-authorization"}
            for value in _values(hs, "connection"):
                hop.update(x.strip().lower() for x in value.split(","))
            out = f"HTTP/1.1 {status} Reply\r\n" + "".join(k + ": " + v + "\r\n" for k, v in hs if k not in hop)
            out += "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            sock.sendall(out.encode("ascii"))
            parser = BodyReframer("length", 0) if status in (204, 304) else BodyReframer(mode, length)
            scanner = Scanner(self.token["needles"])
            while not parser.done:
                data = up.recv(65536)
                if not data:
                    parser.eof(); break
                self._charge("bytes_down", len(data)); down_bytes += len(data)
                clean = scanner.feed(parser.feed(data))
                sock.sendall(BodyReframer.chunk(clean))
            sock.sendall(BodyReframer.chunk(scanner.finalize()) + BodyReframer.LAST)
        except Hit:
            self.abort("credential")
        except ssl.SSLError:
            # A wrong SNI is rejected during TLS handshake, before inner HTTP.
            reason = "sni"
        except (OSError, ValueError):
            try:
                if status == 403:
                    sock.sendall(local_answer(403, {}))
            except OSError:
                pass
        finally:
            for s in owned:
                s.close()
            with self.lock:
                for s in owned:
                    self.sockets.discard(s)
                self.active -= 1
                self.workers.discard(threading.current_thread())
                record = json.dumps({"host": host, "method": method, "route": route, "status": status,
                                     "bytes_up": up_bytes, "bytes_down": down_bytes,
                                     "ms": int((time.monotonic()-start)*1000), "dropped": dropped,
                                     "reason": locals().get("reason", "")}, separators=(",", ":"))
                if self.token and any(n in record.encode() for n in self.token["needles"]):
                    self.abort("credential")
                else:
                    self._emit(record)

    def _drain_rejected(self, sock, head):
        try:
            mode, length = _framing(head.headers)
            if mode != "length" or length > 65536:
                return
            remaining = length
            while remaining:
                data = sock.recv(min(remaining, 65536))
                if not data:
                    return
                remaining -= len(data)
        except (OSError, ValueError):
            return

def serve(reader, writer, *, bind_host="0.0.0.0", keydir=None):
    """Use a binary stdin reader; the main thread enforces an absolute deadline."""
    import queue
    nonce, proxy = "0" * 32, None
    output_lock = threading.Lock()
    def emit(line):
        with output_lock:
            writer.write((line + "\n").encode("ascii")); writer.flush()
    try:
        messages = queue.Queue(maxsize=2)
        def control():
            try:
                n = reader.readline(34)
                s = reader.readline(65538)
                messages.put(("start", n, s))
                while True:
                    line = reader.readline(80)
                    if not line:
                        messages.put(("eof",)); return
                    m = re.fullmatch(rb"TOKEN ([1-9][0-9]{0,5})\n", line)
                    if not m or int(m[1]) > 131072:
                        raise SpecError("protocol")
                    size = int(m[1]); data = bytearray()
                    while len(data) < size:
                        part = reader.read(size-len(data))
                        if not part:
                            raise SpecError("protocol")
                        data.extend(part)
                    messages.put(("token", bytes(data)))
            except Exception:
                messages.put(("error",))
        thread = threading.Thread(target=control, daemon=True); thread.start()
        msg = messages.get(timeout=20)
        if msg[0] != "start" or not re.fullmatch(rb"[0-9a-f]{32}\n", msg[1]):
            raise SpecError("protocol")
        nonce = msg[1][:-1].decode()
        if not msg[2].endswith(b"\n") or len(msg[2]) > 65536:
            raise SpecError("spec")
        spec = validate_spec(_json(msg[2]), time.time())
        proxy = Proxy(nonce, spec, emit, bind_host=bind_host, keydir=keydir)
        ca = proxy.start()
        emit("READY " + nonce + " " + base64.b64encode(ca).decode())
        while not proxy.stopped.is_set():
            try:
                msg = messages.get(timeout=.1)
            except queue.Empty:
                continue
            if msg[0] == "eof":
                proxy.stop(); break
            if msg[0] != "token":
                raise SpecError("protocol")
            proxy.arm(validate_token(_json(msg[1]), spec["placeholders"]))
        return proxy.exitcode
    except (SpecError, ValueError, TypeError, queue.Empty):
        emit("ABORT " + nonce + " spec")
        return 2
    except Exception:
        emit("ABORT " + nonce + " runtime")
        return 5
    finally:
        if proxy:
            proxy.stop()
            end = time.monotonic() + 2
            for t in list(proxy.workers):
                t.join(max(0, end - time.monotonic()))
            emit("END " + nonce + " " + json.dumps(proxy.counts, separators=(",", ":")))

def self_test():
    """Verify cryptography import and an ephemeral CA TLS handshake; print only public diagnostics and return 0 or 5."""
    import cryptography
    cert = make_ca(HOST, int(time.time()) + 60)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    memfd = _load_chain(server, cert.leaf_pem + cert.leaf_key_pem)
    client = ssl.create_default_context(cadata=cert.ca_pem.decode("ascii"))
    a, b = socket.socketpair()
    errors = []
    def handshake():
        try:
            with server.wrap_socket(a, server_side=True) as conn:
                conn.recv(1)
        except OSError:
            errors.append(True)
    thread = threading.Thread(target=handshake)
    thread.start()
    try:
        with client.wrap_socket(b, server_hostname=HOST) as conn:
            conn.sendall(b"x")
    finally:
        thread.join(5)
        a.close(); b.close()
    if errors or thread.is_alive():
        return 5
    print(f"SELFTEST ok cryptography={cryptography.__version__} from={cryptography.__path__[0]}/__init__.py memfd={int(memfd)} handshake=ok roots=1")
    return 0

if __name__ == "__main__":
    raise SystemExit(self_test() if sys.argv[1:] == ["--self-test"] else serve(sys.stdin.buffer, sys.stdout.buffer))
