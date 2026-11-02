"""sandbox_build: the B2 orchestrator (plan PLAN-B2-build.md, unit U7; Verification 1, 2, 4, 8).

WHY THIS FILE EXISTS. sandbox_build.py wires five units together -- the shared transport (U6),
the driver's probe and build modes (U3), the host auth split (U4), the injecting proxy (U2) and
the run-directory contract of change_apply (U5) -- and decides the ORDER in which a real token
comes near a container. Every promise about that order has to fail a test when it is broken:

- Part A (always, docker faked; no container, no network, no token): the policy's build section
  is validated strictly; the pure helpers (codex_argv, draw_subnet, probe_targets, the create
  argv of probe, proxy and builder, network args and inspect check, published-port parsing)
  hold the plan's values, and every create command line stays below 8 000 characters (this runs
  on the Windows CI job too); a whole run against a fake docker, a fake driver stream (results
  framed by sandbox_driver's own builders) and a fake proxy session proves: the probe runs before
  any proxy exists, TOKEN goes out only after the probe passed and READY came, the builder only
  after TOKEN; isolation_failed / isolation_unverified are exit 5 with no proxy, no TOKEN and no
  builder; credential_exposed, auth_failed (refresh_attempt, placeholder_rejected), oom and
  change_refused are reported as the plan says; every builder-controlled channel is scanned
  before any host write; the manifest is written on every outcome and the run directory is
  accepted by change_apply.load_change_set (U5); containers and networks are removed on every
  exit path, an unconfirmed removal is exit 5 with `cleanup: UNCONFIRMED`.
- Part B (only with CLAUDEX_DOCKER_TESTS=1): real containers, WITHOUT internet and without the
  real login. A throwaway image derived from codex-build replaces the Codex binary with a fake
  that talks to the real proxy over the real isolated network (CONNECT refusals, the locally
  answered accounts/check, a direct-egress attempt) and edits the tree; the policy is patched to
  that image only. The proxy's upstream is never reached: the fake never sends the one forwarded
  route (sandbox_proxy has no wire-level upstream seam, only a constructor seam used in
  tests/test_proxy_auth_integration.py). A negative control on a network WITHOUT the isolated
  gateway mode must fail the probe. Nothing labelled claudex.run of these runs is left behind.

FIXTURES ONLY: CODEX_HOME points at a temporary directory with a fake auth.json in every test;
the real ~/.codex/auth.json is never read. Written before scripts/sandbox_build.py existed and
seen failing first (module missing).
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_isolation  # noqa: E402
import change_apply  # noqa: E402
import sandbox_build as sb  # noqa: E402
import sandbox_driver as sd  # noqa: E402
import sandbox_run as sr  # noqa: E402
import sandbox_snapshot as ss  # noqa: E402

DOCKER_TESTS = os.environ.get("CLAUDEX_DOCKER_TESTS") == "1"
CONTEXT = "desktop-linux"
POLICY = json.loads((ROOT / "config" / "sandbox-policy.json").read_text(encoding="utf-8"))
BCFG = sb.build_policy(POLICY)
TREE = "b" * 40
CA_PEM = b"-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n"
_GIT_OK = (ss.git_version() or (0, 0)) >= ss.MIN_GIT


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fake_jwt(claims: dict) -> str:
    """JWT-shaped, random signature. NOT a credential."""
    return ".".join([_b64url(b'{"alg":"RS256","typ":"JWT"}'), _b64url(json.dumps(claims).encode()),
                     _b64url(secrets.token_bytes(64))])


def write_auth(home: Path, *, exp_days=8, mode="chatgpt") -> dict:
    """A FIXTURE CODEX_HOME/auth.json with random fake values."""
    now = int(time.time())
    account = str(uuid.uuid4())
    access = fake_jwt({"exp": now + exp_days * 86400, "iat": now, "sub": "fixture"})
    doc = {"auth_mode": mode, "OPENAI_API_KEY": "sk-fixture" if mode == "apikey" else None,
           "tokens": {"id_token": fake_jwt({"exp": now, "email": "f@example.invalid"}), "access_token": access,
                      "refresh_token": "fixture-refresh", "account_id": account},
           "last_refresh": "2026-11-01T00:00:00Z"}
    home.mkdir(parents=True, exist_ok=True)
    (home / "auth.json").write_text(json.dumps(doc), encoding="utf-8")
    return {"access_token": access, "account_id": account}


ROLES_YAML = ("roles:\n  build: codex\n  code-review: claude\n  exposure-review: claude\n"
              "actors:\n  codex:\n    model: gpt-6.1-sol\n    effort: medium\n")


def make_checkout(root: Path) -> Path:
    """A directory with a .git directory holding HEAD (worktree_identity) and a .claudex.yaml whose
    build role is codex. Not a real repository: the snapshot is faked in part A."""
    repo = root / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (repo / ".claudex.yaml").write_text(ROLES_YAML, encoding="ascii")
    return repo


def tar_of(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(data), 0o644, 0
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


SNAP_FILES = {"a.txt": b"old\n", "keep.txt": b"keep\n"}
SNAP_TAR = tar_of(SNAP_FILES)


def fake_snapshot(repo, tree, pin, work, deadline=None):
    info = {"tree": tree or TREE, "input_sha256": "c" * 64, "files": len(SNAP_FILES),
            "entries": [[n, "100644", sha(d)] for n, d in SNAP_FILES.items()]}
    return info, SNAP_TAR


def entry(op, path, new=None, base=None, mode="100644", base_mode="100644"):
    return {"op": op, "path": path, "mode": None if op == "deleted" else mode,
            "base_mode": None if op == "added" else base_mode,
            "sha256": sha(new) if new is not None else (sha(base) if op == "mode" else None),
            "size": len(new) if new is not None else (len(base) if op == "mode" else None),
            "binary": False, "base_sha256": sha(base) if base is not None else None}


DEFAULT_CHANGES = [(entry("modified", "a.txt", b"new\n", b"old\n"), b"new\n"),
                   (entry("added", "src/new.py", b"print('new')\n"), b"print('new')\n")]


def build_tar(nonce, *, status="exited", code=0, login="chatgpt", change_status="ok", changes=None,
              excluded=None, events=b'{"type":"turn.completed"}\n', last=b"done\n", stderr=b"",
              deps=None):
    """A build result exactly as sandbox_driver frames it (its own builders)."""
    pairs = DEFAULT_CHANGES if changes is None and change_status == "ok" else (changes or [])
    pairs = sorted(pairs, key=lambda p: p[0]["path"])
    counts = {k: 0 for k in sd.COUNT_KEYS}
    for e, _blob in pairs:
        counts[e["op"]] += 1
    excluded = excluded if excluded is not None else [{"path": "src/__pycache__", "reason": "generated", "entries": 2}]
    counts["excluded"] = len(excluded)
    exports = {sd.LAST_NAME: sha(last)} if last is not None else {sd.LAST_NAME: "missing"}
    code = code if status == "exited" else None
    result = sd.build_build_result(nonce, status, code, False, {}, exports, None, deps,
                                   {"codex_exit": code, "change_status": change_status,
                                    "change_reason": "a symlink at x" if change_status == "refused" else None,
                                    "counts": counts, "login_status": login})
    members = [("result.json", sd.result_json_bytes(result)), ("codex-events.jsonl", events),
               ("codex-stderr.txt", stderr), ("login.txt", b"Logged in using ChatGPT\n")]
    if deps is not None:
        members.append(("install.txt", b"ok\n"))
    if last is not None:
        members.append((sd.LAST_NAME, last))
    members.append(("changes.json", json.dumps([e for e, _b in pairs], separators=(",", ":")).encode()))
    members.append(("excluded.json", json.dumps({"excluded": excluded, "withheld": []}).encode()))
    members += [(f"change/{i}", blob) for i, (_e, blob) in enumerate(pairs) if blob is not None]
    return sd.build_result_tar(members, sd.build_member_ok)


def probe_tar(nonce, targets, *, outcome=lambda t: "blocked", default_route=False, killed=False, status=None):
    rows = [(t[0], t[1], t[2], outcome(t), "x") for t in targets]
    outs = [r[3] for r in rows]
    st = status or sd.probe_status(outs, default_route, killed)
    doc = sd.build_probe_result(nonce, st, default_route, killed, rows, {}, None)
    return sd.build_result_tar([("result.json", sd.result_json_bytes(doc))])


def split_stdin(stdin: bytes):
    """loader block, nonce, spec, rest."""
    length, rest = stdin.split(b"\n", 1)
    source, rest = rest[:int(length)], rest[int(length):]
    nonce, rest = rest.split(b"\n", 1)
    spec, rest = rest.split(b"\n", 1)
    return source, nonce.decode(), json.loads(spec), rest


def done(code=0, out=b"", err=b""):
    return subprocess.CompletedProcess([], code, stdout=out, stderr=err)


class World:
    """One fake docker daemon + driver streams + proxy session, with one shared event log."""

    def __init__(self, test):
        self.test = test
        self.events, self.calls = [], []
        self.engine = b"29.8.2"
        self.published = b""
        self.networks_q = b""
        self.overlaps = 0
        self.inspect_doc = None          # callable(args) -> dict for the internal network
        self.rm_fail = set()
        self.container_state = {}        # name prefix -> "exit oom"
        self.probe_outcome = lambda t: "blocked"
        self.probe_kw = {}
        self.build_kw = {}
        self.build_hook = None           # called with (world) while the builder "runs"
        self.build_stdin = None
        self.probe_spec = None
        self.created_args = {}
        self.proxy_ready = True
        self.proxy_log = [b'{"host":"refused","method":"CONNECT","route":403,"status":403}\n',
                          b'{"host":"chatgpt.com","method":"GET","route":"local","status":200}\n',
                          b'{"host":"chatgpt.com","method":"POST","route":"forward","status":200}\n']
        self.proxies = []
        self.stream_raises = {}
        ids = {POLICY["images"][n]["ref"]: POLICY["images"][n]["id"] for n in ("codex-build", "python-test")}
        self.ids = ids
        self.last_subnet = None

    # docker -----------------------------------------------------------------------------
    def docker(self, context, *args, timeout=None, data=None):
        self.calls.append(args)
        a = args
        if a[0] == "version":
            return done(0, self.engine + b"\n")
        if a[:2] == ("image", "inspect"):
            return done(0, self.ids[a[-1]].encode() + b"\n")
        if a[0] == "ps" and "-a" in a:
            return done(0)                     # janitor: nothing expired
        if a[0] == "ps":
            return done(0, self.published)
        if a[:2] == ("network", "ls") and "--filter" in a:
            return done(0)                     # janitor
        if a[:2] == ("network", "ls"):
            return done(0, self.networks_q)
        if a[:2] == ("network", "inspect"):
            name = a[-1]
            if "{{json .}}" in a:
                doc = self.inspect_doc(self.created_args[name]) if self.inspect_doc else self._doc(self.created_args[name])
                return done(0, json.dumps(doc).encode())
            if name.startswith("claudex-egr-"):
                return done(0, b"10.210.26.0/24 \n")
            return done(0, b"172.17.0.0/16 \n" * (len(a) - 4))
        if a[:2] == ("network", "create"):
            self.events.append(("network-create", a[-1]))
            if self.overlaps and a[-1].startswith("claudex-int-"):
                self.overlaps -= 1
                return done(1, err=b"Error response from daemon: invalid pool request: Pool overlaps with other one")
            self.created_args[a[-1]] = a
            return done(0, b"netid\n")
        if a[:2] == ("network", "connect"):
            self.events.append(("network-connect", a[-1]))
            return done(0)
        if a[:2] == ("network", "rm"):
            self.events.append(("network-rm", a[-1]))
            return done(0)
        if a[0] == "create":
            name = a[a.index("--name") + 1]
            self.events.append(("create", name))
            self.created_args[name] = a
            return done(0, b"cid\n")
        if a[0] == "inspect" and "--format" in a:
            name = a[-1]
            for prefix, state in self.container_state.items():
                if name.startswith(prefix):
                    return done(0, state.encode())
            return done(0, b"0 false\n")
        if a[0] == "inspect" and "--type" in a:
            kind, name = a[2], a[3]
            if name in self.rm_fail:
                return done(0, b"[{}]")
            if kind == "network":
                return done(1, err=f"Error response from daemon: network {name} not found".encode())
            return done(1, err=f"Error response from daemon: No such container: {name}".encode())
        if a[0] == "rm":
            self.events.append(("rm", a[-1]))
            return done(0)
        if a[0] == "kill":
            self.events.append(("kill", a[-1]))
            return done(0)
        raise AssertionError(f"unexpected docker call {a}")

    @staticmethod
    def _doc(args):
        subnet = args[args.index("--subnet") + 1]
        opts = {}
        for i, x in enumerate(args):
            if x == "-o":
                k, _, v = args[i + 1].partition("=")
                opts[k] = v
        return {"Internal": "--internal" in args, "EnableIPv6": False, "Options": opts,
                "IPAM": {"Driver": "default", "Options": {}, "Config": [{"Subnet": subnet}]}}

    # stream_start -------------------------------------------------------------------------
    def stream(self, context, cid, stdin, timeout, result_cap=None):
        self.events.append(("stream", cid))
        if cid in self.stream_raises:
            raise self.stream_raises[cid]
        source, nonce, spec, rest = split_stdin(stdin)
        loader = self.created_args[cid][-1]
        self.test.assertEqual(loader, sr.LOADER % sha(source), "stdin source does not match the loader hash")
        self.test.assertEqual(source, sr.DRIVER_FILE.read_bytes())
        if cid.startswith("claudex-probe-"):
            self.probe_spec = spec
            self.test.assertEqual(rest, b"")
            targets = sd.parse_probe_spec(spec).targets
            return probe_tar(nonce, [list(t) for t in targets], outcome=self.probe_outcome, **self.probe_kw), b""
        self.test.assertTrue(cid.startswith("claudex-build-"))
        self.build_stdin = (spec, rest)
        sd.parse_build_spec(spec)  # the driver accepts what the orchestrator sends
        if self.build_hook:
            out = self.build_hook(self)
            if out is not None:
                return out, b""
        deps = {"status": "installed", "reason": None, "installed": [["alpha", "1.0"]]} if spec["deps_len"] else None
        return build_tar(nonce, deps=deps, **self.build_kw), b""

    def proxy_class(self):
        world = self

        class FakeProxy(sb.ProxySession):
            def __init__(self, context, name, nonce, log_cap, on_alarm=None, argv=None):
                super().__init__(context, name, nonce, log_cap, on_alarm=on_alarm)
                self.name, self.tokens, self.head = name, [], None
                world.proxies.append(self)
                world.events.append(("proxy-session", name))

            def start(self, head):
                world.events.append(("proxy-start", self.name))
                self.head = head
                source, nonce, spec, rest = split_stdin(head)
                world.test.assertEqual(source, sb.PROXY_FILE.read_bytes())
                world.test.assertEqual(world.created_args[self.name][-1], sr.LOADER % sha(source))
                world.test.assertEqual(rest, b"")
                self.spec = spec
                if world.proxy_ready:
                    self._line(b"READY " + nonce.encode() + b" " + base64.b64encode(CA_PEM) + b"\n")
                else:
                    self.finished.set()

            def send_token(self, message):
                world.events.append(("token", self.name))
                self.tokens.append(message)

            def close_stdin(self):
                world.events.append(("proxy-eof", self.name))
                for line in world.proxy_log:
                    self._line(line)
                self._line(b"END " + self.nonce + b' {"requests":3,"forwarded":1}\n')

            def wait(self, timeout):
                self.returncode = 0
                return 0

            def stop(self):
                world.events.append(("proxy-stop", self.name))

        return FakeProxy

    def names(self, kind):
        return [n for k, n in self.events if k == kind]


class Harness(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.repo = make_checkout(self.root)
        self.home = self.root / "codex-home"
        self.values = write_auth(self.home)
        self.prompt = self.root / "prompt.txt"
        self.prompt.write_bytes(b"build the thing\n")
        env = mock.patch.dict(os.environ, {"CODEX_HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        for var in [k for k in os.environ if k.upper().startswith("DOCKER_")]:
            os.environ.pop(var)
        self.world = World(self)
        self._patch(sr, "docker", self.world.docker)
        self._patch(sr, "stream_start", self.world.stream)
        self._patch(sr, "supervised_snapshot", fake_snapshot)
        self._patch(sb, "ProxySession", self.world.proxy_class())

    def _patch(self, obj, name, value):
        p = mock.patch.object(obj, name, value)
        p.start()
        self.addCleanup(p.stop)

    def run_build(self, *extra, tree=TREE):
        argv = ["run", "--repo", str(self.repo), "--scratch", str(self.scratch), "--prompt-file", str(self.prompt)]
        argv += ["--tree", tree] if tree else []
        argv += list(extra)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sb.main(argv)
        info = dict(line.split("=", 1) for line in out.getvalue().splitlines() if "=" in line)
        return code, info, err.getvalue()

    def manifest(self, info):
        raw = (Path(info["RUN_DIR"]) / "manifest.json").read_bytes()
        self.assertEqual(sha(raw), info["MANIFEST_SHA256"])
        return json.loads(raw)

    def assert_clean(self):
        """Every created container and network was removed, containers before networks."""
        w = self.world
        created = {n for k, n in w.events if k in ("create", "network-create")}
        removed = {n for k, n in w.events if k in ("rm", "network-rm")}
        self.assertEqual(created - removed, set(), w.events)
        # the probe is removed early (to free .3); every other container goes before any network
        rms = [i for i, (k, n) in enumerate(w.events) if k == "rm" and not n.startswith("claudex-probe-")]
        nets = [i for i, (k, _n) in enumerate(w.events) if k == "network-rm"]
        if rms and nets:
            self.assertLess(max(rms), min(nets), w.events)

    def no_needle(self, data: bytes, what=""):
        auth = [self.values["access_token"].encode(), self.values["account_id"].encode()]
        for n in auth:
            self.assertNotIn(n, data, what)


# --- part A: policy and pure helpers ---------------------------------------------------------------


class PolicyTests(unittest.TestCase):
    def test_installed_policy_validates(self):
        self.assertEqual(BCFG["subnet_prefix"], 29)
        self.assertEqual(BCFG["probe"]["deadline"], 20)
        self.assertNotIn(3128, BCFG["probe"]["ports"])
        self.assertEqual(BCFG["change_caps"], POLICY["build"]["change_caps"])

    def mutated(self, fn):
        policy = json.loads(json.dumps(POLICY))
        fn(policy["build"])
        return policy

    def test_malformed_sections_are_refused(self):
        cases = [
            lambda b: b.pop("probe"), lambda b: b.update(extra=1), lambda b: b.update(subnet_prefix=28),
            lambda b: b["probe"]["ports"].append(3128), lambda b: b.update(subnet_pool="8.8.0.0/16"),
            lambda b: b.update(engines=[]), lambda b: b["endpoints"]["chatgpt.com"]["forward"].update(path="/x"),
            lambda b: b["change_caps"].pop("entries"), lambda b: b.update(timeout_default=7200),
            lambda b: b.update(withheld_paths=[".codex"]), lambda b: b.update(memory="6 GB"),
            lambda b: b["proxy_caps"].update(requests=0), lambda b: b.update(refused_hosts_fatal=[]),
            lambda b: b["probe"].update(max_targets=True),
        ]
        for fn in cases:
            with self.assertRaises(sr.Refused):
                sb.build_policy(self.mutated(fn))
        with self.assertRaises(sr.Refused):
            sb.build_policy({k: v for k, v in POLICY.items() if k != "build"})

    def test_comment_keys_are_ignored(self):
        self.assertEqual(sb.build_policy(self.mutated(lambda b: b.update(_note="x"))), BCFG)


class CodexArgvTests(unittest.TestCase):
    def argv(self, **kw):
        spec = {"model": "gpt-6.1-sol", "effort": "medium", "disable": list(build_isolation.BUILD_DISABLE)}
        spec.update(kw)
        return sb.codex_argv(spec)

    def test_accepted_by_the_driver(self):
        argv = self.argv()
        self.assertEqual(sd.validate_codex_argv(argv), argv)
        self.assertEqual(tuple(argv[:6]), sd.CODEX_PREFIX)
        self.assertIn("--ignore-user-config", argv)
        self.assertIn("--ignore-rules", argv)
        self.assertEqual(argv[-4:], ["--json", "-o", "/out/codex-last.txt", "-"])
        disabled = [argv[i + 1] for i, x in enumerate(argv) if x == "--disable"]
        self.assertEqual(disabled, list(build_isolation.BUILD_DISABLE))
        self.assertIn('model="gpt-6.1-sol"', argv)
        self.assertIn('model_reasoning_effort="medium"', argv)

    def test_constants_match_the_driver(self):
        self.assertEqual(sb.CODEX_PREFIX, sd.CODEX_PREFIX)
        self.assertEqual(sb.CHANGE_CAP_BOUNDS, sd.CAP_BOUNDS)
        self.assertEqual(sb.OUT_LAST, sd.OUT + "/" + sd.LAST_NAME)

    def test_bad_model_or_effort_refused(self):
        for kw in ({"model": 'x" -c y'}, {"effort": "High"}, {"model": ""}, {"disable": ["a b"]}):
            with self.assertRaises(sr.Refused):
                self.argv(**kw)


class SubnetTests(unittest.TestCase):
    class Seq:
        def __init__(self, values):
            self.values, self.calls = list(values), 0

        def randrange(self, n):
            self.calls += 1
            return self.values.pop(0) % n

    def test_avoids_taken(self):
        rng = self.Seq([0, 1])
        got = sb.draw_subnet("10.240.0.0/28", ["10.240.0.0/29"], 29, rng=rng)
        self.assertEqual(got, "10.240.0.8/29")
        self.assertEqual(rng.calls, 2)

    def test_gives_up_after_three(self):
        rng = self.Seq([0, 0, 0, 0])
        with self.assertRaises(sr.Infrastructure):
            sb.draw_subnet("10.240.0.0/28", ["10.240.0.0/16"], 29, rng=rng)
        self.assertEqual(rng.calls, 3)

    def test_inside_pool_and_ignores_garbage(self):
        for _ in range(50):
            got = ipaddress.ip_network(sb.draw_subnet("10.240.0.0/16", ["fd00::/64", "nonsense", "172.17.0.0/16"]))
            self.assertEqual(got.prefixlen, 29)
            self.assertTrue(got.subnet_of(ipaddress.ip_network("10.240.0.0/16")))


class ProbeTargetsTests(unittest.TestCase):
    SUB = "10.240.7.8/29"

    def targets(self, published=()):
        return sb.probe_targets(BCFG, self.SUB, "10.240.7.11", "10.240.7.10", published)

    def test_todays_policy_within_budget(self):
        t = self.targets()
        self.assertLessEqual(len(t), BCFG["probe"]["max_targets"])
        self.assertEqual(len(t), 6 * 8 + 2 * 8 + 8 + 6)
        self.assertEqual(len({tuple(x) for x in t}), len(t))
        hosts = {x[1] for x in t}
        self.assertNotIn("10.240.7.11", hosts)
        self.assertNotIn("10.240.7.10", hosts)
        for must in ("10.240.7.8", "10.240.7.9", "10.240.7.15", "192.168.65.254", "192.168.65.7",
                     "169.254.169.254", "1.1.1.1", "8.8.8.8", "example.com", "host.docker.internal",
                     "gateway.docker.internal"):
            self.assertIn(must, hosts)
        self.assertIn(["udp", "8.8.8.8", 53], t)
        self.assertTrue(any(":" in x[1] for x in t))
        self.assertNotIn(3128, {x[2] for x in t})
        sd.parse_probe_spec({"mode": "probe", "probe_targets": t, "probe_deadline": 20,
                             "exclude_addrs": ["10.240.7.11", "10.240.7.10"]})

    def test_published_ports_extend_the_vm_addresses(self):
        t = self.targets([18765, 9999, 9999])
        self.assertIn(["tcp", "192.168.65.254", 9999], t)
        self.assertNotIn(["tcp", "10.240.7.9", 9999], t)
        self.assertLessEqual(len(self.targets(range(1000, 1016))), BCFG["probe"]["max_targets"])

    def test_forty_published_ports_refused(self):
        with self.assertRaises(sr.Refused):
            self.targets(range(1000, 1040))

    def test_over_max_targets_refused(self):
        small = json.loads(json.dumps(BCFG))
        small["probe"]["max_targets"] = 20
        with self.assertRaises(sr.Refused):
            sb.probe_targets(small, self.SUB, "10.240.7.11", "10.240.7.10", [])


class PublishedPortsTests(unittest.TestCase):
    def test_parse(self):
        text = ("0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\n127.0.0.1:18766->1/tcp\n80/tcp\n"
                "0.0.0.0:7000-7002->7000-7002/tcp\n:::5432->5432/tcp\n\n")
        self.assertEqual(sb.published_ports(text), [5432, 7000, 7001, 7002, 8080, 18766])
        self.assertEqual(sb.published_ports(""), [])


LOADER_ARGV = sr.bootstrap(b"print(1)\n")[0]


class CreateArgsTests(unittest.TestCase):
    def common(self, args):
        joined = " ".join(args)
        for flag in ("--read-only", "--pull=never", "--log-driver", "no-new-privileges", "--cap-drop"):
            self.assertIn(flag, args if flag.startswith("--") and "=" not in flag else joined)
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        for bad in ("-v", "--volume", "--privileged", "--network=host", "docker.sock", "type=bind", "--publish",
                    "-p", "--cap-add=ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW"):
            self.assertNotIn(bad, args)
            self.assertNotIn("docker.sock", joined)
        self.assertIn(f"{sr.LABEL}=r1", args)
        self.assertIn("claudex.deadline=99", args)
        self.assertEqual(args[-5:], LOADER_ARGV)
        self.assertEqual(args[args.index("--network") + 1], "claudex-int-r1")

    def test_builder(self):
        args = sb.builder_create_args("r1", 99, "sha256:" + "a" * 64, LOADER_ARGV, "claudex-int-r1", "10.240.0.3", BCFG)
        self.common(args)
        self.assertEqual(args[args.index("--ip") + 1], "10.240.0.3")
        self.assertEqual(args[args.index("--name") + 1], "claudex-build-r1")
        self.assertEqual(args[args.index("--user") + 1], "0:0")
        self.assertEqual([args[i + 1] for i, x in enumerate(args) if x == "--cap-add"], ["SETUID", "SETGID", "KILL"])
        self.assertIn("type=tmpfs,destination=/codex-home,tmpfs-size=256m,tmpfs-mode=1777", args)
        self.assertIn("type=tmpfs,destination=/work,tmpfs-size=2g,tmpfs-mode=1777", args)
        self.assertEqual(args[args.index("--memory") + 1], "6g")
        self.assertEqual(args[args.index("--pids-limit") + 1], "1024")
        self.assertFalse(any(a.startswith("/deps") for a in args))
        with_deps = sb.builder_create_args("r1", 99, "sha256:" + "a" * 64, LOADER_ARGV, "claudex-int-r1",
                                           "10.240.0.3", BCFG, deps_tmpfs="2g")
        self.assertIn("/deps:rw,exec,nosuid,nodev,size=2g,mode=1777", with_deps)

    def test_probe_has_the_builders_flags(self):
        b = sb.builder_create_args("r1", 99, "img", LOADER_ARGV, "claudex-int-r1", "10.240.0.3", BCFG)
        p = sb.probe_create_args("r1", 99, "img", LOADER_ARGV, "claudex-int-r1", "10.240.0.3", BCFG)
        self.assertEqual(p[p.index("--name") + 1], "claudex-probe-r1")
        self.assertEqual([x for x in p if x != "claudex-probe-r1"], [x for x in b if x != "claudex-build-r1"])

    def test_proxy(self):
        args = sb.proxy_create_args("r1", 99, "sha256:" + "b" * 64, LOADER_ARGV, "claudex-int-r1", "10.240.0.2")
        self.common(args)
        self.assertEqual(args[args.index("--user") + 1], "65532:65532")
        self.assertNotIn("--cap-add", args)
        self.assertNotIn("--mount", args)
        self.assertEqual(args[args.index("--pids-limit") + 1], "64")
        self.assertEqual(args[args.index("--memory") + 1], "256m")
        self.assertEqual(args[args.index("--tmpfs") + 1], "/tmp:size=16m")  # nosec B108 - in the container
        self.assertEqual(args[args.index("--ip") + 1], "10.240.0.2")

    def test_loader_argv_is_checked(self):
        with self.assertRaises(ValueError):
            sb.builder_create_args("r1", 99, "img", ["python3", "-c", "x"], "n", "10.240.0.3", BCFG)
        with self.assertRaises(ValueError):
            sb.proxy_create_args("r1", 99, "img", [*LOADER_ARGV[:4], "import os"], "n", "10.240.0.2")

    def test_every_create_variant_below_8000_characters(self):
        # plan approach 3b; this test also runs in the Windows CI job (no skip)
        run_id = sb.sandbox_fetch.new_run_id()
        img = "sha256:" + "f" * 64
        drv = sr.bootstrap(sr.DRIVER_FILE.read_bytes())[0]
        prx = sr.bootstrap(sb.PROXY_FILE.read_bytes())[0]
        variants = [
            sr.create_args(run_id, 2 ** 31, img, drv),
            sr.create_args(run_id, 2 ** 31, img, drv, deps_tmpfs="2g"),
            sb.probe_create_args(run_id, 2 ** 31, img, drv, f"claudex-int-{run_id}", "10.240.255.251", BCFG),
            sb.builder_create_args(run_id, 2 ** 31, img, drv, f"claudex-int-{run_id}", "10.240.255.251", BCFG,
                                   deps_tmpfs="2g"),
            sb.proxy_create_args(run_id, 2 ** 31, img, prx, f"claudex-int-{run_id}", "10.240.255.250"),
            sb.network_create_args("10.240.255.248/29", run_id=run_id, deadline=2 ** 31),
            sb.egress_create_args(run_id=run_id, deadline=2 ** 31),
        ]
        for args in variants:
            full = ["docker", "--context", "desktop-linux", *args]
            self.assertLess(sr.cmdline_length(full), sb.CMDLINE_MAX)
            self.assertEqual(sr.cmdline_length(full), len(subprocess.list2cmdline(full)))


class NetworkTests(unittest.TestCase):
    def test_internal_args(self):
        a = sb.network_create_args("10.240.1.0/29", run_id="r1", deadline=99)
        for flag in ("--internal", "--ipv6=false", "com.docker.network.bridge.gateway_mode_ipv4=isolated"):
            self.assertIn(flag, a)
        self.assertEqual(a[a.index("--subnet") + 1], "10.240.1.0/29")
        self.assertEqual(a[-1], "claudex-int-r1")
        self.assertIn(f"{sr.LABEL}=r1", a)

    def test_egress_args(self):
        a = sb.egress_create_args(run_id="r1", deadline=99)
        self.assertNotIn("--internal", a)
        self.assertIn("com.docker.network.bridge.enable_icc=false", a)
        self.assertIn("--ipv6=false", a)
        self.assertEqual(a[-1], "claudex-egr-r1")

    MEASURED = {"Name": "claudex-m-int", "Driver": "bridge", "EnableIPv4": True, "EnableIPv6": False,
                "IPAM": {"Driver": "default", "Options": {}, "Config": [{"Subnet": "10.240.77.0/29"}]},
                "Internal": True, "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                                              "com.docker.network.enable_ipv4": "true"}}

    def test_measured_inspect_accepted(self):
        # docker 29.8.2, measured 2026-11-01 (this session): no Gateway key in isolated mode
        sb.check_network(self.MEASURED, "10.240.77.0/29")

    def test_deviations_refused(self):
        def mut(fn):
            doc = json.loads(json.dumps(self.MEASURED))
            fn(doc)
            return doc
        for doc in (mut(lambda d: d.update(Internal=False)), mut(lambda d: d.update(EnableIPv6=True)),
                    mut(lambda d: d["Options"].pop("com.docker.network.bridge.gateway_mode_ipv4")),
                    mut(lambda d: d["IPAM"]["Config"][0].update(Gateway="10.240.77.1")),
                    mut(lambda d: d["IPAM"]["Config"].append({"Subnet": "fd00::/64"})),
                    mut(lambda d: d["IPAM"]["Config"][0].update(Subnet="10.240.77.8/29"))):
            with self.assertRaises(sr.Refused):
                sb.check_network(doc, "10.240.77.0/29")


class ProxySessionTests(unittest.TestCase):
    NONCE = "a" * 32

    def session(self, cap=4096):
        alarms = []
        s = sb.ProxySession("ctx", "p", self.NONCE, cap, on_alarm=alarms.append)
        return s, alarms

    def test_protocol_lines(self):
        s, alarms = self.session()
        s._line(b"READY " + b"b" * 32 + b" " + base64.b64encode(CA_PEM) + b"\n")   # foreign nonce
        self.assertFalse(s.ready.is_set())
        s._line(b"READY " + self.NONCE.encode() + b" " + base64.b64encode(CA_PEM) + b"\n")
        self.assertEqual(s.wait_ready(1), CA_PEM)
        s._line(b'{"route":"forward","status":200}\n')
        s._line(b'{"route":404,"status":404}\n')
        s._line(b'{"route":403,"status":403}\n')
        s._line(b'{"route":"local","status":200}\n')
        s._line(b"END " + self.NONCE.encode() + b' {"requests":4,"forwarded":1}\n')
        sm = s.summary()
        self.assertEqual((sm["forwarded"], sm["refused"], sm["local"], sm["records"]), (1, 2, 1, 4))
        self.assertEqual(sm["end"], {"requests": 4, "forwarded": 1})
        self.assertEqual(sm["bad_lines"], 1)
        self.assertNotIn(base64.b64encode(CA_PEM), bytes(s.log).split(self.NONCE.encode())[-1])
        self.assertEqual(alarms, [])

    def test_alarms_once(self):
        s, alarms = self.session()
        s._line(b"EVENT " + self.NONCE.encode() + b" refresh_attempt\n")
        s._line(b"ABORT " + self.NONCE.encode() + b" credential\n")
        self.assertEqual(alarms, ["refresh_attempt"])
        self.assertEqual((s.alarm, s.abort, s.event), ("refresh_attempt", "credential", "refresh_attempt"))
        s2, alarms2 = self.session()
        s2._line(b"ABORT " + self.NONCE.encode() + b" credential\n")
        self.assertEqual(alarms2, ["credential"])
        s3, alarms3 = self.session()
        s3._line(b"ABORT " + self.NONCE.encode() + b" content_encoding\n")
        self.assertEqual(alarms3, ["abort"])

    def test_log_cap_and_long_lines(self):
        s, _ = self.session(cap=100)
        for _ in range(10):
            s._line(b'{"route":404,"status":404,"pad":"xxxxxxxxxx"}\n')
        self.assertTrue(s.summary()["log_truncated"])
        self.assertLessEqual(len(s.log), 100)
        self.assertEqual(s.refused, 10)
        s2, _ = self.session()
        s2._line(b"x" * (sb.PROXY_LINE_MAX + 1))       # over-long: skipped up to its LF
        s2._line(b"tail of the long line\n")
        s2._line(b'{"route":"forward"}\n')
        self.assertEqual((s2.bad_lines, s2.forwarded), (1, 1))

    def test_not_ready_when_the_proxy_ends(self):
        s, _ = self.session()
        s.finished.set()
        with self.assertRaises(sr.Infrastructure):
            s.wait_ready(5)

    def test_unexpected_eof_alarms_even_after_ready(self):
        s, alarms = self.session()
        s.proc = mock.Mock(stdout=io.BytesIO(b""))
        s.ready.set()
        s._read_out()
        self.assertEqual(alarms, ["abort"])
        self.assertTrue(s.finished.is_set())

    def test_stalled_stdin_is_bounded_and_child_is_reaped(self):
        s = sb.ProxySession("ctx", "p", self.NONCE, 4096,
                            argv=[sys.executable, "-I", "-c", "import time; time.sleep(60)"])
        start = time.monotonic()
        try:
            with mock.patch.object(sb, "PROXY_EXIT_SECONDS", 0.2):
                with self.assertRaisesRegex(sr.Infrastructure, "write timed out"):
                    s.start(b"x" * (4 * 1024 * 1024))
            self.assertIsNotNone(s.proc.poll())
            self.assertLess(time.monotonic() - start, 15)
        finally:
            s.stop()

    def test_supervised_process_with_deferred_eof(self):
        script = (
            "import sys,base64\n"
            "i,o=sys.stdin.buffer,sys.stdout.buffer\n"
            "n=i.readline().strip()\n"
            "o.write(b'READY '+n+b' '+base64.b64encode(" + repr(CA_PEM) + ")+b'\\n');o.flush()\n"
            "t=i.readline()\n"
            "body=i.read(int(t.split()[1]))\n"
            "o.write(b'{\"route\":\"forward\",\"len\":%d}\\n' % len(body));o.flush()\n"
            "rest=i.read()\n"   # blocks until the deferred EOF
            "o.write(b'END '+n+b' {\"requests\":1}\\n');o.flush()\n"
            "sys.exit(0 if rest==b'' else 3)\n")
        s = sb.ProxySession("ctx", "p", self.NONCE, 4096, argv=[sys.executable, "-I", "-c", script])
        try:
            s.start(self.NONCE.encode() + b"\n")
            self.assertEqual(s.wait_ready(20), CA_PEM)
            s.send_token(b"TOKEN 5\nhello")
            time.sleep(0.3)
            self.assertIsNone(s.proc.poll(), "the proxy must keep running until stdin closes")
            s.close_stdin()
            self.assertEqual(s.wait(20), 0)
        finally:
            s.stop()
        self.assertEqual(s.summary()["end"], {"requests": 1})
        self.assertEqual(s.forwarded, 1)


# --- part A: whole runs against fakes ---------------------------------------------------------------


class RunTests(Harness):
    def test_incomplete_proxy_shutdown_never_publishes_changes(self):
        for exit_code, end in ((0, None), (1, {"requests": 3}), (None, {"requests": 3})):
            with self.subTest(exit_code=exit_code, end=end):
                proxy_type = self.world.proxy_class()
                def wait(proxy, timeout):
                    proxy.end = end
                    return exit_code
                with mock.patch.object(sb, "ProxySession", proxy_type), mock.patch.object(proxy_type, "wait", wait):
                    code, info, err = self.run_build()
                self.assertNotEqual(code, 0)
                self.assertFalse((Path(info["RUN_DIR"]) / "changes.json").exists())

    def test_happy_path_and_the_run_dir_contract(self):
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "exited")
        self.assertEqual(info["CODEX_EXIT"], "0")
        self.assertEqual(info["TREE"], TREE)
        self.assertEqual((info["CHANGES"], info["BINARY"], info["EXCLUDED"]), ("2", "0", "1"))
        self.assertEqual((info["PROXY_FORWARDED"], info["PROXY_REFUSED"]), ("1", "1"))
        self.assertEqual(list(info), ["RUN_DIR", "TREE", "BUILD_STATUS", "CODEX_EXIT", "CHANGES", "BINARY",
                                      "EXCLUDED", "PROXY_FORWARDED", "PROXY_REFUSED", "MANIFEST_SHA256"])
        m = self.manifest(info)
        run_dir = Path(info["RUN_DIR"])
        self.assertEqual(run_dir.parent, self.scratch / "sandbox")
        self.assertEqual(m["tree"], TREE)
        self.assertEqual(m["build_status"], "exited")
        self.assertEqual(m["source"], change_apply.worktree_identity(self.repo))
        self.assertEqual(m["changes_sha256"], sha((run_dir / "changes.json").read_bytes()))
        self.assertEqual(m["excluded_sha256"], sha((run_dir / "excluded.json").read_bytes()))
        self.assertEqual(m["cleanup"], "confirmed")
        self.assertEqual(m["auth"]["mode"], "chatgpt")
        self.assertEqual(m["model"], "gpt-6.1-sol")
        self.assertTrue(m["token_sent"])
        self.assertEqual(m["probe"]["status"], "isolated")
        # U5 accepts the run directory as it is
        cs = change_apply.load_change_set(run_dir, info["MANIFEST_SHA256"])
        self.assertEqual([e["path"] for e in cs.entries], ["a.txt", "src/new.py"])
        self.assertEqual(cs.blobs[0], b"new\n")
        for name in ("codex-events.jsonl", "codex-last.txt", "codex-stderr.txt", "login.txt", "proxy.log",
                     "result.json", "change/0", "change/1"):
            self.assertTrue((run_dir / name).is_file(), name)
        # nothing real on disk
        for path in run_dir.rglob("*"):
            if path.is_file():
                self.no_needle(path.read_bytes(), str(path))
        self.assert_clean()

    def test_order_probe_then_proxy_then_token_then_builder(self):
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        ev = self.world.events
        kinds = [(k, n.split("-")[1] if k in ("create", "stream", "network-create") else n) for k, n in ev]
        pos = {}
        for i, item in enumerate(kinds):
            pos.setdefault(item, i)
        self.assertLess(pos[("network-create", "int")], pos[("create", "probe")])
        self.assertLess(pos[("create", "probe")], pos[("stream", "probe")])
        probe_rm = next(i for i, (k, n) in enumerate(ev) if k == "rm" and n.startswith("claudex-probe-"))
        self.assertLess(pos[("stream", "probe")], probe_rm)
        egr = next(i for i, (k, n) in enumerate(ev) if k == "network-create" and n.startswith("claudex-egr-"))
        proxy_create = next(i for i, (k, n) in enumerate(ev) if k == "create" and n.startswith("claudex-proxy-"))
        token = next(i for i, (k, _n) in enumerate(ev) if k == "token")
        build_create = next(i for i, (k, n) in enumerate(ev) if k == "create" and n.startswith("claudex-build-"))
        eof = next(i for i, (k, _n) in enumerate(ev) if k == "proxy-eof")
        build_stream = next(i for i, (k, n) in enumerate(ev) if k == "stream" and n.startswith("claudex-build-"))
        self.assertLess(probe_rm, egr)
        self.assertLess(egr, proxy_create)
        self.assertLess(proxy_create, token)
        self.assertLess(token, build_create)
        self.assertLess(build_stream, eof)
        # the builder takes the probe's address, the proxy .2
        w = self.world
        bname = w.names("create")[-1]
        pname = [n for n in w.names("create") if n.startswith("claudex-probe-")][0]
        xname = [n for n in w.names("create") if n.startswith("claudex-proxy-")][0]
        ip = lambda n: w.created_args[n][w.created_args[n].index("--ip") + 1]  # noqa: E731
        self.assertEqual(ip(bname), ip(pname))
        net = ipaddress.ip_network(self.manifest(info)["network"]["subnet"])
        self.assertEqual(ip(xname), str(net.network_address + 2))
        self.assertEqual(ip(bname), str(net.network_address + 3))
        self.assertTrue(net.subnet_of(ipaddress.ip_network("10.240.0.0/16")))
        self.assertEqual(net.prefixlen, 29)
        self.assertIn(("network-connect", xname), ev)

    def test_what_each_party_receives(self):
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        proxy = self.world.proxies[0]
        auth_doc = json.loads((self.home / "auth.json").read_text())
        real_token = auth_doc["tokens"]["access_token"]
        # the proxy's spec: placeholders only; the real values only in the TOKEN message
        self.no_needle(proxy.head, "proxy spec")
        self.assertEqual(len(proxy.tokens), 1)
        self.assertTrue(proxy.tokens[0].startswith(b"TOKEN "))
        self.assertIn(real_token.encode(), proxy.tokens[0])
        self.assertEqual(set(proxy.spec["placeholders"]), {"authorization", "chatgpt-account-id"})
        self.assertEqual(proxy.spec["listen"], 3128)
        self.assertIn(self.manifest(info)["network"]["subnet"], proxy.spec["deny_nets"])
        # the builder: placeholder auth.json and the proxy's CA, in the driver's stdin order
        spec, rest = self.world.build_stdin
        self.no_needle(json.dumps(spec).encode() + rest, "builder stdin")
        tar = rest[:spec["tar_len"]]
        self.assertEqual(tar, SNAP_TAR)
        rest = rest[spec["tar_len"] + spec["deps_len"]:]
        prompt, rest = rest[:spec["prompt_len"]], rest[spec["prompt_len"]:]
        placeholder, ca = rest[:spec["placeholder_len"]], rest[spec["placeholder_len"]:]
        self.assertEqual(prompt, b"build the thing\n")
        self.assertEqual(json.loads(placeholder)["tokens"]["refresh_token"], "")
        self.assertEqual(ca, CA_PEM)
        self.assertEqual(len(ca), spec["ca_len"])
        self.assertEqual(spec["proxy_url"], f"http://{self.manifest(info)['network']['proxy_ip']}:3128")
        self.assertEqual(spec["codex_timeout"], BCFG["timeout_default"])
        self.assertLessEqual(BCFG["timeout_max"] + sb.PROXY_DEADLINE_SLACK,
                             sb.PROXY_LIFETIME_MAX)
        # no create argv carries a value
        for name, args in self.world.created_args.items():
            self.no_needle(" ".join(args).encode(), name)

    def test_isolation_failed_no_proxy_no_token_no_builder(self):
        self.world.probe_outcome = lambda t: "reached" if t[1] == "192.168.65.254" and t[2] == 18765 else "blocked"
        code, info, err = self.run_build()
        self.assertEqual(code, 5)
        self.assertIn("isolation_failed", err)
        m = self.manifest(info)
        self.assertEqual(m["isolation"], "isolation_failed")
        self.assertEqual(m["probe"]["status"], "isolation_failed")
        self.assertTrue(m["probe"]["reached"])
        self.assertEqual(m["runner_status"], "infrastructure")
        self.assertFalse(m["token_sent"])
        self.assertEqual(self.world.proxies, [])
        self.assertFalse(any(n.startswith(("claudex-proxy-", "claudex-build-")) for n in self.world.names("create")))
        self.assertFalse(any(n.startswith("claudex-egr-") for n in self.world.names("network-create")))
        self.assert_clean()

    def test_isolation_unverified(self):
        for kw in ({"outcome": lambda t: "timeout" if t[1] == "1.1.1.1" else "blocked"},
                   {"outcome": lambda t: "blocked", "killed": True},
                   {"outcome": lambda t: "blocked", "status": "isolation_unverified"}):
            with self.subTest(kw=list(kw)):
                self.world.probe_outcome = kw.pop("outcome")
                self.world.probe_kw = kw
                self.world.proxies.clear()
                code, info, err = self.run_build()
                self.assertEqual(code, 5, err)
                self.assertEqual(self.manifest(info)["isolation"], "isolation_unverified")
                self.assertEqual(self.world.proxies, [])

    def test_default_route_fails(self):
        self.world.probe_kw = {"default_route": True}
        code, info, _err = self.run_build()
        self.assertEqual(code, 5)
        self.assertEqual(self.manifest(info)["isolation"], "isolation_failed")

    def test_probe_targets_and_exclusions_sent(self):
        self.world.published = b"0.0.0.0:18765->80/tcp\n"
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        spec = self.world.probe_spec
        m = self.manifest(info)
        self.assertEqual(spec["exclude_addrs"], [m["network"]["builder_ip"], m["network"]["proxy_ip"]])
        self.assertEqual(spec["probe_deadline"], 20)
        self.assertEqual(spec["probe_targets"],
                         sb.probe_targets(BCFG, m["network"]["subnet"], m["network"]["builder_ip"],
                                          m["network"]["proxy_ip"], [18765]))

    def test_forty_published_ports_refused_before_any_network(self):
        self.world.published = "\n".join(f"0.0.0.0:{p}->80/tcp" for p in range(2000, 2040)).encode()
        code, info, err = self.run_build()
        self.assertEqual(code, 2, err)
        self.assertEqual(self.world.names("network-create"), [])
        self.assertEqual(self.world.names("create"), [])

    def test_network_without_isolation_refused_before_any_container(self):
        self.world.inspect_doc = lambda args: dict(World._doc(args), Options={})
        code, info, err = self.run_build()
        self.assertEqual(code, 2, err)
        self.assertIn("isolated gateway", err)
        self.assertEqual(self.world.names("create"), [])
        self.assert_clean()

    def test_subnet_overlap_retried_then_given_up(self):
        self.world.overlaps = 2
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.world.overlaps = 3
        self.world.events.clear()
        code, info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertEqual(len(self.world.names("network-create")), 3)
        self.assertEqual(self.world.names("create"), [])

    def test_taken_subnets_are_avoided(self):
        self.world.networks_q = b"n1\nn2\n"
        rng = SubnetTests.Seq([0, 5])
        orig = self.world.docker

        def docker(context, *a, **kw):
            if a[:2] == ("network", "inspect") and "n1" in a:
                return done(0, b"10.240.0.0/29 172.17.0.0/16 \n")
            return orig(context, *a, **kw)
        self._patch(sr, "docker", docker)
        with mock.patch.object(sb.secrets, "SystemRandom", lambda: rng):
            code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.manifest(info)["network"]["subnet"], "10.240.0.40/29")

    def test_static_refusals_happen_before_any_docker_call(self):
        cases = [
            (["--timeout", "0"], None), (["--timeout", "3601"], None), ([], "deadbeef"),
            (["--deps", "a", "--deps", "a"], None),
        ]
        for extra, tree in cases:
            with self.subTest(extra=extra, tree=tree):
                self.world.calls.clear()
                code, info, err = self.run_build(*extra, tree=tree or TREE)
                self.assertEqual(code, 2, err)
                self.assertEqual(self.world.calls, [])
                self.assertEqual(self.manifest(info)["runner_status"], "refused")

    def test_docker_host_refused(self):
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://elsewhere:2375"}):
            code, _info, err = self.run_build()
        self.assertEqual(code, 2)
        self.assertIn("DOCKER_HOST", err)
        self.assertEqual(self.world.calls, [])

    def test_prompt_file_checked(self):
        for content in (b"", b"x" * (sb.MAX_PROMPT + 1)):
            self.prompt.write_bytes(content)
            code, _info, _err = self.run_build()
            self.assertEqual(code, 2)
        self.prompt.unlink()
        code, _info, _err = self.run_build()
        self.assertEqual(code, 2)
        self.assertEqual(self.world.calls, [])

    def test_build_role_must_be_codex(self):
        (self.repo / ".claudex.yaml").write_text("roles:\n  build: claude\n", encoding="ascii")
        code, _info, err = self.run_build()
        self.assertEqual(code, 2)
        self.assertIn("codex", err)
        self.assertEqual(self.world.calls, [])

    def test_not_a_checkout_refused(self):
        (self.repo / ".git" / "HEAD").unlink()
        code, _info, _err = self.run_build()
        self.assertEqual(code, 2)
        self.assertEqual(self.world.calls, [])

    def test_engine_not_listed_refused_before_any_container(self):
        self.world.engine = b"30.0.0"
        code, info, err = self.run_build()
        self.assertEqual(code, 2, err)
        self.assertEqual(self.world.names("create"), [])
        self.assertEqual(self.world.names("network-create"), [])

    def test_wrong_image_id_refused(self):
        ref = POLICY["images"]["python-test"]["ref"]
        self.world.ids[ref] = "sha256:" + "0" * 64
        code, _info, err = self.run_build()
        self.assertEqual(code, 2, err)
        self.assertEqual(self.world.names("create"), [])

    def test_janitor_collects_containers_and_networks(self):
        code, _info, err = self.run_build()
        self.assertEqual(code, 0, err)
        calls = self.world.calls
        self.assertTrue(any(a[0] == "ps" and "-a" in a for a in calls))
        self.assertTrue(any(a[:2] == ("network", "ls") and "--filter" in a for a in calls))

    def test_api_key_login_refused(self):
        write_auth(self.home, mode="apikey")
        code, info, err = self.run_build()
        self.assertEqual(code, 2, err)
        self.assertIn("API-key", err)
        self.assertEqual(self.world.names("create"), [])

    def test_short_lived_token_refused(self):
        write_auth(self.home, exp_days=0)
        code, _info, err = self.run_build()
        self.assertEqual(code, 2, err)
        self.assertEqual(self.world.names("create"), [])

    def test_proxy_never_ready_no_token_no_builder(self):
        self.world.proxy_ready = False
        with mock.patch.object(sb, "READY_SECONDS", 0.5):
            code, info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertEqual(self.world.proxies[0].tokens, [])
        self.assertFalse(any(n.startswith("claudex-build-") for n in self.world.names("create")))
        self.assertFalse(self.manifest(info)["token_sent"])
        self.assert_clean()

    def test_credential_abort_kills_the_builder(self):
        def hook(world):
            world.proxies[0]._line(b"ABORT " + world.proxies[0].nonce + b" credential\n")
            return b""   # the killed driver produced nothing
        self.world.build_hook = hook
        self.world.container_state = {"claudex-build-": "137 false\n"}
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "credential_exposed")
        self.assertEqual(info["CHANGES"], "0")
        self.assertTrue(any(k == "kill" and n.startswith("claudex-build-") for k, n in self.world.events))
        run_dir = Path(info["RUN_DIR"])
        self.assertFalse((run_dir / "changes.json").exists())
        m = self.manifest(info)
        self.assertNotIn("changes_sha256", m)
        with self.assertRaises(change_apply.ApplyRefused):
            change_apply.load_change_set(run_dir, info["MANIFEST_SHA256"])
        self.assert_clean()

    def test_refresh_attempt_is_auth_failed(self):
        def hook(world):
            world.proxies[0]._line(b"EVENT " + world.proxies[0].nonce + b" refresh_attempt\n")
            return b""
        self.world.build_hook = hook
        self.world.container_state = {"claudex-build-": "137 false\n"}
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "auth_failed")
        self.assertEqual(self.manifest(info)["auth_reason"], "refresh_attempt")

    def test_other_proxy_abort_is_infrastructure(self):
        def hook(world):
            world.proxies[0]._line(b"ABORT " + world.proxies[0].nonce + b" content_encoding\n")
            return b""
        self.world.build_hook = hook
        code, info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertIn("content_encoding", err)
        self.assertTrue((Path(info["RUN_DIR"]) / "proxy.log").is_file())
        self.assert_clean()

    def test_placeholder_rejected_is_auth_failed(self):
        self.world.build_kw = {"status": "not_started", "login": "rejected", "change_status": "not_computed",
                               "last": None}
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "auth_failed")
        self.assertEqual(info["CODEX_EXIT"], "-")
        self.assertEqual(self.manifest(info)["auth_reason"], "placeholder_rejected")

    def test_change_refused(self):
        self.world.build_kw = {"change_status": "refused", "changes": []}
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "change_refused")
        self.assertEqual(info["CHANGES"], "0")
        self.assertIn("symlink", self.manifest(info)["change_reason"])

    def test_timeout_and_nonzero_exit(self):
        self.world.build_kw = {"status": "timeout", "change_status": "ok"}
        code, info, err = self.run_build()
        self.assertEqual((code, info["BUILD_STATUS"], info["CODEX_EXIT"]), (0, "timeout", "-"), err)
        self.world.build_kw = {"code": 3}
        code, info, err = self.run_build()
        self.assertEqual((code, info["BUILD_STATUS"], info["CODEX_EXIT"]), (0, "exited", "3"), err)

    def test_oom(self):
        self.world.container_state = {"claudex-build-": "137 true\n"}
        self.world.build_hook = lambda world: b""
        code, info, err = self.run_build()
        self.assertEqual((code, info["BUILD_STATUS"]), (0, "oom"), err)

    def test_driver_crash_is_infrastructure_and_cleaned(self):
        self.world.container_state = {"claudex-build-": "1 false\n"}
        code, info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertEqual(self.manifest(info)["cleanup"], "confirmed")
        self.assert_clean()

    def test_stream_failure_still_cleans(self):
        def hook(world):
            raise sr.Infrastructure("no result within 3840s")
        self.world.build_hook = hook
        code, info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assert_clean()

    def test_builder_output_with_a_needle_is_credential_exposed_and_redacted(self):
        token = json.loads((self.home / "auth.json").read_text())["tokens"]["access_token"]
        self.world.build_kw = {"events": b'{"leak":"' + token.encode() + b'"}\n'}
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "credential_exposed")
        run_dir = Path(info["RUN_DIR"])
        events = (run_dir / "codex-events.jsonl").read_bytes()
        self.assertIn(b"[REDACTED]", events)
        for path in run_dir.rglob("*"):
            if path.is_file():
                self.no_needle(path.read_bytes(), str(path))
        self.assertFalse((run_dir / "changes.json").exists())
        self.assertEqual(self.manifest(info)["credential_hits"], {"codex-events.jsonl": 1})

    def test_proxy_log_with_a_needle_is_redacted(self):
        account = json.loads((self.home / "auth.json").read_text())["tokens"]["account_id"]
        self.world.proxy_log = [b'{"route":404,"dropped":["' + account.encode() + b'"]}\n']
        code, info, err = self.run_build()
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "credential_exposed")
        log = (Path(info["RUN_DIR"]) / "proxy.log").read_bytes()
        self.assertIn(b"[REDACTED]", log)
        self.no_needle(log)

    def test_tampered_blob_is_infrastructure(self):
        # a change/<n> whose bytes do not match changes.json
        pairs = [(entry("added", "x.txt", b"aaa\n"), b"bbb\n")]
        self.world.build_kw = {"changes": pairs}
        code, info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertIn("sha256", err)
        self.assertFalse((Path(info["RUN_DIR"]) / "changes.json").exists())

    def test_wrong_nonce_is_infrastructure(self):
        self.world.build_hook = lambda world: build_tar("f" * 32)
        code, _info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertIn("nonce", err)

    def test_unconfirmed_cleanup_is_exit_5(self):
        def docker(context, *a, **kw):
            if a[:2] == ("inspect", "--type") and a[3].startswith("claudex-proxy-"):
                return done(0, b"[{}]")
            return self.world.docker(context, *a, **kw)
        self._patch(sr, "docker", docker)
        code, info, err = self.run_build()
        self.assertEqual(code, 5)
        self.assertIn("cleanup: UNCONFIRMED", err)
        m = self.manifest(info)
        self.assertEqual(m["cleanup"], "UNCONFIRMED")
        self.assertTrue(any(s.startswith("container claudex-proxy-") for s in m["cleanup_unconfirmed"]))
        # the pass went on: the networks were still removed
        self.assertEqual(len(self.world.names("network-rm")), 2)

    def test_unconfirmed_cleanup_keeps_the_first_failure(self):
        self.world.container_state = {"claudex-build-": "1 false\n"}

        def docker(context, *a, **kw):
            if a[:2] == ("inspect", "--type") and a[3].startswith("claudex-int-"):
                return done(0, b"[{}]")
            return self.world.docker(context, *a, **kw)
        self._patch(sr, "docker", docker)
        code, info, err = self.run_build()
        self.assertEqual(code, 5)
        m = self.manifest(info)
        self.assertIn("cleanup: UNCONFIRMED", m["reason"])
        self.assertIn("build driver ended with exit 1", m["first_failure"])

    def test_command_line_limit_enforced(self):
        with mock.patch.object(sb, "CMDLINE_MAX", 200):
            code, _info, err = self.run_build()
        self.assertEqual(code, 5, err)
        self.assertIn("command line", err)

    def test_manifest_on_static_refusal(self):
        code, info, _err = self.run_build("--timeout", "0")
        self.assertEqual(code, 2)
        m = self.manifest(info)
        self.assertEqual(m["runner_status"], "refused")
        self.assertEqual(m["mode"], "build")

    def test_deps_are_handed_to_the_driver(self):
        tar = b"deps-tar-bytes"

        def fetch(state, reqs, cfg):
            state.fields["deps"]["deps_tar_sha256"] = sha(tar)
            return tar
        self._patch(sr, "read_deps_files", lambda info, tar_bytes, paths: [("req.txt", "e" * 64, b"x")])
        self._patch(sr, "parse_deps", lambda files: ["alpha"])
        self._patch(sr, "fetch_deps", fetch)
        self._patch(sb.sandbox_deps, "requirements_sha256", lambda reqs: "d" * 64)
        code, info, err = self.run_build("--deps", "req.txt")
        self.assertEqual(code, 0, err)
        self.assertEqual(info["REQUIREMENTS_SHA256"], "d" * 64)
        spec, rest = self.world.build_stdin
        self.assertEqual(spec["deps_len"], len(tar))
        self.assertEqual(spec["deps_sha256"], sha(tar))
        self.assertEqual(rest[spec["tar_len"]:spec["tar_len"] + len(tar)], tar)
        bname = [n for n in self.world.names("create") if n.startswith("claudex-build-")][0]
        self.assertIn("/deps:rw,exec,nosuid,nodev,size=2g,mode=1777", self.world.created_args[bname])
        self.assertTrue((Path(info["RUN_DIR"]) / "install.txt").is_file())

    @unittest.skipUnless(_GIT_OK, "git older than 2.44: the snapshot refuses it by design")
    def test_with_the_real_snapshot(self):
        # the supervised snapshot of a real throwaway repository, --pin, everything else faked
        repo = self.root / "real"
        repo.mkdir()
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", *a],  # noqa: E731
                                      check=True, capture_output=True, env=env, timeout=60)
        g("init", "-q")
        (repo / "a.txt").write_bytes(b"old\n")
        (repo / ".claudex.yaml").write_text(ROLES_YAML, encoding="ascii")
        g("add", "a.txt", ".claudex.yaml")
        g("commit", "-q", "-m", "x")
        (repo / "spec.md").write_bytes(b"the spec\n")
        self.repo = repo
        self._patch(sr, "supervised_snapshot", REAL_SNAPSHOT)
        code, info, err = self.run_build("--pin", "spec.md", tree=None)
        self.assertEqual(code, 0, err)
        spec, rest = self.world.build_stdin
        with tarfile.open(fileobj=io.BytesIO(rest[:spec["tar_len"]])) as tf:
            self.assertEqual(sorted(tf.getnames()), [".claudex.yaml", "a.txt", "spec.md"])
        tree = info["TREE"]
        self.assertEqual(subprocess.run(["git", "-C", str(repo), "cat-file", "-t", tree], capture_output=True,
                                        timeout=60).stdout.strip(), b"tree")


REAL_SNAPSHOT = sr.supervised_snapshot


# --- part B: real containers, no internet ------------------------------------------------------------

FAKE_CODEX = r'''#!/usr/local/bin/python3 -I
import json, os, socket, ssl, subprocess, sys
args = sys.argv[1:]
home = os.environ.get("CODEX_HOME", "")
def auth():
    with open(os.path.join(home, "auth.json")) as handle:
        return json.load(handle)
if args[:2] == ["login", "status"]:
    doc = auth()
    if doc.get("auth_mode") == "chatgpt" and doc.get("tokens", {}).get("refresh_token") == "":
        print("Logged in using ChatGPT"); sys.exit(0)
    sys.exit(1)
if args[:1] != ["exec"]:
    sys.exit(2)
prompt = sys.stdin.buffer.read().decode()
out = args[args.index("-o") + 1]
proxy = os.environ["HTTPS_PROXY"][len("http://"):]
phost, pport = proxy.rsplit(":", 1)
report = {"uid": os.getuid(), "argv": args, "dot_git": os.path.exists(".git"),
          "dot_codex": os.path.exists(".codex"), "env_keys": sorted(os.environ)}
def connect(target):
    s = socket.create_connection((phost, int(pport)), timeout=10)
    s.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        c = s.recv(1)
        if not c:
            break
        head += c
    return s, head.split(b"\r\n", 1)[0].decode(errors="replace")
def request(method, path):
    s, status = connect("chatgpt.com:443")
    if " 200 " not in status:
        return status, None
    ctx = ssl.create_default_context(cafile=os.environ["CODEX_CA_CERTIFICATE"])
    ctx.set_alpn_protocols(["http/1.1"])
    t = ctx.wrap_socket(s, server_hostname="chatgpt.com")
    tok = auth()["tokens"]
    t.sendall(("%s %s HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: Bearer %s\r\nChatGPT-Account-Id: %s\r\n"
               "Content-Length: 0\r\n\r\n" % (method, path, tok["access_token"], tok["account_id"])).encode())
    data = b""
    while True:
        c = t.recv(65536)
        if not c:
            break
        data += c
    head, _, body = data.partition(b"\r\n\r\n")
    return head.split(b"\r\n", 1)[0].decode(errors="replace"), body.decode(errors="replace")
report["connect_example"] = connect("example.com:443")[1]
report["connect_ip"] = connect("1.1.1.1:443")[1]
report["accounts_check"] = request("GET", "/backend-api/wham/accounts/check")
report["models"] = request("GET", "/backend-api/codex/models?client_version=0.162.1")[0]
report["placeholder_account"] = auth()["tokens"]["account_id"]
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close()
    report["direct"] = "connected"
except OSError as exc:
    report["direct"] = "blocked %s" % exc.errno
if "---REFRESH---" in prompt:
    report["refresh"] = connect("auth.openai.com:443")[1]
    import time; time.sleep(60)
with open(out, "w") as handle:
    json.dump(report, handle)
print(json.dumps({"type": "turn.completed"})); sys.stdout.flush()
script = prompt.split("\n---SCRIPT---\n", 1)[1] if "\n---SCRIPT---\n" in prompt else ""
sys.exit(subprocess.call(["sh", "-c", script]) if script else 0)
'''


def _docker(*args, timeout=300):
    return subprocess.run(["docker", "--context", CONTEXT, *args], capture_output=True, timeout=timeout,
                          env=sr.client_env())


def _label_left(kind: str, run_ids) -> list:
    out = []
    for rid in run_ids:
        cmd = ["ps", "-a"] if kind == "container" else ["network", "ls"]
        res = _docker(*cmd, "--filter", f"label={sr.LABEL}={rid}", "-q", timeout=60)
        out += res.stdout.decode().split()
    return out


@unittest.skipUnless(DOCKER_TESTS, "real containers need CLAUDEX_DOCKER_TESTS=1 and the local images")
class ContainerRuns(unittest.TestCase):
    owned: set = set()

    @classmethod
    def setUpClass(cls):
        cls._dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(cls._dir.name)
        ctx = root / "image"
        ctx.mkdir()
        (ctx / "codex").write_bytes(FAKE_CODEX.encode())
        bin_dir = "/opt/codex/package/vendor/x86_64-unknown-linux-musl/bin"
        (ctx / "Dockerfile").write_text(
            f"FROM {POLICY['images']['codex-build']['ref']}\nCOPY --chmod=0755 codex {bin_dir}/codex\n",
            encoding="ascii")
        cls.tag = f"claudex-test-fakecodex:{secrets.token_hex(4)}"
        res = _docker("build", "--pull=false", "--network", "none", "-q", "-t", cls.tag,
                      "--label", "claudex.measure=1", str(ctx))
        if res.returncode != 0:
            raise unittest.SkipTest("cannot build the fake-codex test image: " + res.stderr.decode()[-300:])
        cls.image_id = res.stdout.decode().strip().splitlines()[-1]
        policy = json.loads(json.dumps(POLICY))
        policy["images"]["codex-build"]["ref"] = cls.tag
        policy["images"]["codex-build"]["id"] = cls.image_id
        cls.policy_file = root / "policy.json"
        cls.policy_file.write_text(json.dumps(policy), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        try:
            _docker("image", "rm", "-f", cls.tag, timeout=120)
        finally:
            cls._dir.cleanup()

    def setUp(self):
        d = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.home = self.root / "codex-home"
        self.values = write_auth(self.home)
        patches = [mock.patch.dict(os.environ, {"CODEX_HOME": str(self.home)}),
                   mock.patch.object(sr, "POLICY_FILE", self.policy_file)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        for var in [k for k in os.environ if k.upper().startswith("DOCKER_")]:
            os.environ.pop(var)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.git = lambda *a: subprocess.run(["git", "-C", str(self.repo), "-c", "commit.gpgsign=false", *a],  # noqa
                                             check=True, capture_output=True, env=env, timeout=60)
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        (self.repo / "a.txt").write_bytes(b"old\n")
        (self.repo / ".claudex.yaml").write_text(ROLES_YAML, encoding="ascii")
        (self.repo / ".codex").mkdir()
        (self.repo / ".codex" / "config.toml").write_text("[mcp_servers.x]\ncommand='touch'\n", encoding="ascii")
        self.git("add", "a.txt", ".claudex.yaml", ".codex/config.toml")
        self.git("commit", "-q", "-m", "x")

    def build(self, prompt: str, timeout=300, patches=()):
        (self.root / "prompt.txt").write_bytes(prompt.encode("ascii"))  # LF kept on Windows too
        tree = self.git("rev-parse", "HEAD^{tree}").stdout.decode().strip()
        argv = ["run", "--repo", str(self.repo), "--scratch", str(self.scratch), "--tree", tree,
                "--prompt-file", str(self.root / "prompt.txt"), "--timeout", str(timeout)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = sb.main(argv)
        info = dict(line.split("=", 1) for line in out.getvalue().splitlines() if "=" in line)
        runs = self.scratch / "sandbox"
        ids = {p.name[len("build-"):] for p in runs.glob("build-*")} if runs.is_dir() else set()
        ContainerRuns.owned |= ids
        self.assertEqual(_label_left("container", ids), [], "containers left behind")
        self.assertEqual(_label_left("network", ids), [], "networks left behind")
        return code, info, err.getvalue()

    def test_end_to_end_with_the_fake_codex(self):
        script = "printf 'new\\n' > a.txt && mkdir -p src && printf 'x = 1\\n' > src/n.py"
        code, info, err = self.build("build it\n---SCRIPT---\n" + script)
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "exited", err)
        self.assertEqual(info["CODEX_EXIT"], "0")
        self.assertEqual(info["CHANGES"], "2")
        self.assertEqual(info["PROXY_FORWARDED"], "0")
        self.assertGreaterEqual(int(info["PROXY_REFUSED"]), 3)
        run_dir = Path(info["RUN_DIR"])
        report = json.loads((run_dir / "codex-last.txt").read_bytes())
        self.assertEqual(report["uid"], 65532)
        self.assertFalse(report["dot_git"])
        self.assertFalse(report["dot_codex"], "withheld .codex/ reached the builder")
        self.assertIn("403", report["connect_example"])
        self.assertIn("403", report["connect_ip"])
        self.assertIn("404", report["models"])
        status, body = report["accounts_check"]
        self.assertIn("200", status)
        self.assertEqual(json.loads(body)["default_account_id"], report["placeholder_account"])
        self.assertNotEqual(report["placeholder_account"], self.values["account_id"])
        self.assertTrue(report["direct"].startswith("blocked"), report["direct"])
        m = json.loads((run_dir / "manifest.json").read_bytes())
        self.assertEqual(m["probe"]["status"], "isolated")
        self.assertEqual(m["probe"]["reached"], [])
        self.assertEqual(m["cleanup"], "confirmed")
        self.assertEqual(m["proxy"]["exit_code"], 0)
        for path in run_dir.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(self.values["access_token"].encode(), data, path)
                self.assertNotIn(self.values["account_id"].encode(), data, path)
        # U5 shows and publishes it
        res = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "change_apply.py"), "show",
                              "--run-dir", str(run_dir), "--manifest-sha256", info["MANIFEST_SHA256"],
                              "--repo", str(self.repo), "--summary"], capture_output=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stderr.decode(errors="replace"))
        self.assertIn(b"src/n.py", res.stdout)
        before = (self.repo / "a.txt").read_bytes()
        self.assertEqual(before, b"old\n", "nothing is published before apply")
        res = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "change_apply.py"), "apply",
                              "--run-dir", str(run_dir), "--manifest-sha256", info["MANIFEST_SHA256"],
                              "--target", str(self.repo)], capture_output=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stdout.decode(errors="replace") + res.stderr.decode(errors="replace"))
        self.assertEqual((self.repo / "a.txt").read_bytes(), b"new\n")
        self.assertEqual((self.repo / "src" / "n.py").read_bytes(), b"x = 1\n")

    def test_refresh_attempt_ends_the_run(self):
        code, info, err = self.build("go\n---REFRESH---\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(info["BUILD_STATUS"], "auth_failed")
        m = json.loads((Path(info["RUN_DIR"]) / "manifest.json").read_bytes())
        self.assertEqual(m["auth_reason"], "refresh_attempt")
        self.assertEqual(m["proxy"]["event"], "refresh_attempt")

    def test_negative_control_without_isolated_gateway(self):
        # Verification 2: the same probe on a network WITHOUT the isolated gateway mode must reach
        # the bridge gateway -> isolation_failed, no proxy, no TOKEN, no builder.
        isolated = sb.network_create_args

        def plain(subnet, *, run_id, deadline):
            args = isolated(subnet, run_id=run_id, deadline=deadline)
            i = args.index("-o")
            return args[:i] + args[i + 2:]
        sessions = []

        class NoProxy(sb.ProxySession):
            def __init__(self, *a, **k):
                sessions.append(a)
                raise AssertionError("a proxy was started although the probe failed")
        patches = [mock.patch.object(sb, "network_create_args", plain),
                   mock.patch.object(sb, "check_network", lambda doc, subnet: None),
                   mock.patch.object(sb, "ProxySession", NoProxy)]
        code, info, err = self.build("never runs\n", patches=patches)
        self.assertEqual(code, 5, err)
        m = json.loads((Path(info["RUN_DIR"]) / "manifest.json").read_bytes())
        self.assertEqual(m["isolation"], "isolation_failed", m.get("probe"))
        self.assertTrue(m["probe"]["reached"])
        self.assertFalse(m["token_sent"])
        self.assertEqual(sessions, [])

    def test_zz_nothing_left_behind(self):
        self.assertEqual(_label_left("container", ContainerRuns.owned), [])
        self.assertEqual(_label_left("network", ContainerRuns.owned), [])


class DeletedEntryContract(unittest.TestCase):
    """U3's deleted entry with null content metadata is accepted by U5."""

    def test_driver_deleted_entry_is_accepted_by_change_apply(self):
        base = sd.Baseline({"gone.txt": (sha(b"x\n"), "100644")}, set(), [], [])
        records = [("Z", 0, 0, b"", b"")]
        change = sd.compute_changes(base, records, (), dict(sd.CAP_BOUNDS))
        self.assertEqual(change["status"], "ok", change["reason"])
        change_apply._validate_entry(0, change["changes"][0])


if __name__ == "__main__":
    unittest.main()
