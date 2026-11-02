#!/usr/bin/env python3
"""Run the Codex build in a hardened, disposable container -- never raw on the host (plan B2).

Plan: docs/plans/2026-10-27-sicherheitskette/PLAN-B2-build.md (approved in round 5), unit U7;
measurements: PLAN-B2-REVIEW-LOG.md "Step 0 measurements" and "Step 0 measurements, proxy
design" (2026-11-01). It shares B1's lifecycle (sandbox_run.py): policy, docker client,
image pinning, snapshot, deps, stdin loader, framed result stream, janitor, absence proof.

    python -I "${CLAUDE_PLUGIN_ROOT}/scripts/sandbox_build.py" run --repo <checkout> \\
        --scratch "$SCRATCH_DIR" (--tree <sha> | --pin <path>...) --prompt-file <file> \\
        [--deps <tree path>]... [--timeout S]

ONE RUN, in this order (every docker object carries claudex.run=<id> and claudex.deadline):

  static   arguments, the policy's `build` section (build_policy), REDIRECTING_VARS, both image
           entries, the deps settings, the probe budget, the prompt file (hunt_io.read_at,
           regular, <= 1 MiB), model and effort from claudex_roles (role `build`, actor codex),
           the Codex argv, the source worktree identity (change_apply.worktree_identity) --
           all before any docker call; a refusal is exit 2.
  engine   the daemon's version must be in `engines`; both images must have the pinned id
           (--pull=never); the janitor removes expired containers AND networks.
  auth     sandbox_auth.load() reads $CODEX_HOME/auth.json once (placeholder auth.json,
           placeholder and real header maps, TOKEN message, needles); the access token must
           live past now + timeout + 600 s. Nothing real is written, printed or logged.
  input    the pinned tree through the supervised snapshot; --deps as B1.5.
  network  claudex-int-<id>: --internal --ipv6=false gateway_mode_ipv4=isolated with a /29
           drawn from `subnet_pool` (at most 3 attempts on overlap); `docker network inspect`
           must show Internal, no IPv6, the isolated option, exactly that subnet and NO IPAM
           gateway. Fixed addresses: proxy .2, probe .3, builder .3 (after the probe is gone).
  probe    BEFORE the proxy exists: a container from the build image with the builder's flags
           runs the driver in mode "probe" against a budget computed before any network (the
           /29 minus probe and proxy, the Docker Desktop VM addresses with the daemon's
           published ports, the metadata address, an IPv6 literal, 1.1.1.1:443, UDP
           8.8.8.8:53, three names). One reached target or a default route ->
           isolation_failed; anything not blocked -> isolation_unverified; both exit 5, the
           proxy is never started, no TOKEN is ever sent, no builder exists.
  proxy    claudex-egr-<id> (ICC off) for the proxy only; scripts/sandbox_proxy.py in the
           python-test image as uid 65532 through the same stdin loader; nonce + spec (U2
           protocol) on stdin, `READY <nonce> <ca>` awaited (30 s), then -- the probe having
           passed -- `TOKEN <len>\\n<real header map>`; stdin stays open (deferred EOF after the
           builder). A supervised `docker start -ai` with its own reader thread keeps one line
           per request under `proxy_log_cap`. `EVENT refresh_attempt` -> auth_failed and
           `ABORT credential` -> credential_exposed: the builder is killed at once.
  build    the driver in mode "build" (U3): snapshot tar, deps tar, prompt, placeholder
           auth.json, CA certificate on stdin; the result is read under `result_cap` with
           sandbox_run.read_framed and every blob re-hashed against changes.json.
  clean    on every exit path: the builder, probe and proxy containers, then both networks,
           each proved absent by docker's own "No such ..." answer; unproven -> exit 5,
           `cleanup: UNCONFIRMED` with the names on stderr.
  scan     every builder-controlled channel (all result members, the proxy log) is scanned for
           the needles BEFORE anything is written to the host; a hit -> credential_exposed,
           the text members are written redacted and no change set is written at all.
  output   RUN_DIR/manifest.json on every outcome; on success also changes.json,
           excluded.json, change/<n> (the contract of scripts/change_apply.py, U5: manifest keys
           tree, source, build_status, changes_sha256, excluded_sha256) and the Codex outputs.

stdout on exit 0: RUN_DIR=, TREE=, BUILD_STATUS= (exited | timeout | oom | output_limit |
not_started | deps_failed | change_refused | auth_failed | credential_exposed), CODEX_EXIT=,
CHANGES=, BINARY=, EXCLUDED=, PROXY_FORWARDED=, PROXY_REFUSED=, REQUIREMENTS_SHA256= (with
--deps), MANIFEST_SHA256=. Exit codes: 0 the run happened (a round succeeds only with
BUILD_STATUS=exited, CODEX_EXIT=0 and a non-empty codex-last.txt), 2 refused, 5 infrastructure
(isolation_failed / isolation_unverified included, with the probe report in the manifest).
There is no host fallback of any kind. Messages are ASCII only.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_isolation  # noqa: E402
import change_apply  # noqa: E402
import claudex_roles  # noqa: E402
import hunt_io  # noqa: E402
import sandbox_auth  # noqa: E402
import sandbox_deps  # noqa: E402
import sandbox_fetch  # noqa: E402
import sandbox_run as sr  # noqa: E402
import sandbox_snapshot  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
PROXY_FILE = SCRIPTS / "sandbox_proxy.py"

EXIT_OK, EXIT_REFUSED, EXIT_INFRA = 0, 2, 5
BUILD_IMAGE, PROXY_IMAGE = "codex-build", "python-test"
LABEL = sr.LABEL
CMDLINE_MAX = 8000             # plan approach 3b: every create argv stays below this (Windows)
PROXY_PORT = 3128
OUT_LAST = "/out/codex-last.txt"
MAX_PROMPT = 1024 * 1024
PROBE_RESULT_CAP = 2 * 1024 * 1024
READY_SECONDS = 30.0
PROXY_EXIT_SECONDS = 20.0
PROBE_SLACK = 60
BUILD_SLACK = 240
DEADLINE_SLACK = 900
# Leave margin between the Codex budget and the proxy's independent deadline.
PROXY_LIFETIME_MAX = 3540
PROXY_DEADLINE_SLACK = 300
SUBNET_ATTEMPTS = 3
PROXY_LINE_MAX = 64 * 1024
MAX_CA = 64 * 1024
NETWORK_BATCH = 40
GATEWAY_MODE = "com.docker.network.bridge.gateway_mode_ipv4"
ICC = "com.docker.network.bridge.enable_icc"
# Docker Desktop's VM-side addresses (measurement 2026-11-01: host-services and DNS forwarder)
VM_ADDRS = ("192.168.65.254", "192.168.65.7")
METADATA_ADDR = "169.254.169.254"
FIXED_TARGETS = (("tcp", "2606:4700:4700::1111", 443), ("tcp", "1.1.1.1", 443), ("udp", "8.8.8.8", 53),
                 ("dns", "example.com", 0), ("dns", "host.docker.internal", 0),
                 ("dns", "gateway.docker.internal", 0))
PROXY_OFFSET, PROBE_OFFSET = 2, 3   # proxy .2, probe .3, builder .3 (approach 5)

# The driver's Codex start line (sandbox_driver.CODEX_PREFIX / CODEX_FIXED; tests hold them equal).
CODEX_PREFIX = ("codex", "exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
                "--ignore-user-config", "--ignore-rules")
MODEL_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")
EFFORT_RE = re.compile(r"[a-z]{1,16}")
FEATURE_RE = re.compile(r"[a-z0-9_]{1,64}")

BUILD_STATUSES = ("exited", "timeout", "oom", "output_limit", "not_started", "deps_failed",
                  "change_refused", "auth_failed", "credential_exposed")
COMMAND_STATUSES = ("exited", "timeout", "output_limit", "not_started", "deps_failed")
COUNT_KEYS = ("added", "modified", "deleted", "mode", "binary", "excluded", "withheld")
SLACK = 4096
MEMBER_CAPS = {"result.json": 1024 * 1024, "codex-events.jsonl": 16 * 1024 * 1024 + SLACK,
               "codex-stderr.txt": 1024 * 1024 + SLACK, "login.txt": 64 * 1024 + SLACK,
               "codex-last.txt": 1024 * 1024, "changes.json": 32 * 1024 * 1024,
               "excluded.json": 32 * 1024 * 1024}
INSTALL_CAP = 64 * 1024 + SLACK
TEXT_MEMBERS = ("codex-events.jsonl", "codex-stderr.txt", "codex-last.txt", "login.txt", "install.txt")

# --- the policy's build section (plan approach 2) -----------------------------------------------

BUILD_KEYS = ("endpoints", "refused_hosts_fatal", "engines", "subnet_pool", "subnet_prefix",
              "timeout_default", "timeout_max", "work_tmpfs", "memory", "pids", "codex_home_tmpfs",
              "placeholder_exp_days", "change_caps", "generated_paths", "withheld_paths", "result_cap",
              "proxy_log_cap", "proxy_caps", "probe")
ENDPOINT_HOST = "chatgpt.com"
ENDPOINT_KEYS = ("forward", "local", "request_headers", "placeholder_headers")
FORWARD_ROUTE = {"method": "POST", "path": "/backend-api/codex/responses", "query": False}
LOCAL_ROUTE = {"method": "GET", "path": "/backend-api/wham/accounts/check", "query": False}
PLACEHOLDER_HEADERS = ("authorization", "chatgpt-account-id")
CHANGE_CAP_BOUNDS = {"entries": 200000, "total_bytes": 256 * 1024 * 1024, "file_bytes": 64 * 1024 * 1024,
                     "added_files": 100000}   # sandbox_driver.CAP_BOUNDS
PROXY_CAP_KEYS = ("requests", "concurrent", "bytes_up", "bytes_down", "header_block")
PROBE_KEYS = ("deadline", "ports", "max_published", "max_targets")
SIZE_RE = re.compile(r"[1-9][0-9]{0,5}[kmg]")
HEADER_RE = re.compile(r"[a-z0-9-]{1,64}")
HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
ENGINE_RE = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}")
GLOB_RE = re.compile(r"(?:\*\*|[A-Za-z0-9._*?-]+)(?:/(?:\*\*|[A-Za-z0-9._*?-]+))*")
WITHHELD_RE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*/\*\*")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class IsolationFailed(sr.Infrastructure):
    """The probe reached something, or could not prove that nothing is reachable (exit 5)."""

    def __init__(self, status: str):
        super().__init__(f"{status}: the probe container did not prove the run's network isolated; "
                         f"no proxy was armed and no builder was created")
        self.status = status


def _ascii(text) -> str:
    return sr._ascii(text)


def _int(obj: dict, key: str, low: int, high: int) -> int:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise sr.Refused(f"sandbox policy: build.{key} must be an integer {low}..{high}")
    return value


def _size(obj: dict, key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not SIZE_RE.fullmatch(value):
        raise sr.Refused(f"sandbox policy: build.{key} must be a size like '2g'")
    return value


def _exact_keys(obj, keys, what: str) -> dict:
    if not isinstance(obj, dict):
        raise sr.Refused(f"sandbox policy: {what} must be an object")
    real = {k for k in obj if not (isinstance(k, str) and k.startswith("_"))}
    if real != set(keys):
        raise sr.Refused(f"sandbox policy: {what} must hold exactly {', '.join(keys)}")
    return obj


def build_policy(policy: dict) -> dict:
    """The installed policy's `build` section, validated as strictly as deps_policy(): every key
    present, nothing unknown (keys starting with `_` are comments), every value in range. A
    missing or malformed section refuses every build. Returns a clean copy."""
    raw = policy.get("build") if isinstance(policy, dict) else None
    if raw is None:
        raise sr.Refused("sandbox policy has no build section; no sandboxed build is possible")
    b = _exact_keys(raw, BUILD_KEYS, "build")
    endpoints = _exact_keys(b["endpoints"], (ENDPOINT_HOST,), "build.endpoints")
    ep = _exact_keys(endpoints[ENDPOINT_HOST], ENDPOINT_KEYS, f"build.endpoints.{ENDPOINT_HOST}")
    if ep["forward"] != FORWARD_ROUTE or ep["local"] != LOCAL_ROUTE:
        raise sr.Refused("sandbox policy: build.endpoints routes are not the measured forward/local routes")
    headers = ep["request_headers"]
    if not isinstance(headers, list) or not headers or len(headers) > 32 or len(set(headers)) != len(headers) \
            or not all(isinstance(h, str) and HEADER_RE.fullmatch(h) for h in headers) \
            or set(headers) & set(PLACEHOLDER_HEADERS):
        raise sr.Refused("sandbox policy: build request_headers must be distinct lower-case names")
    if not isinstance(ep["placeholder_headers"], list) or sorted(ep["placeholder_headers"]) != sorted(PLACEHOLDER_HEADERS):
        raise sr.Refused("sandbox policy: build placeholder_headers must be authorization and chatgpt-account-id")
    fatal = b["refused_hosts_fatal"]
    if not isinstance(fatal, list) or not fatal or not all(isinstance(h, str) and HOST_RE.fullmatch(h) for h in fatal):
        raise sr.Refused("sandbox policy: build.refused_hosts_fatal must be a list of host names")
    engines = b["engines"]
    if not isinstance(engines, list) or not engines or not all(isinstance(e, str) and ENGINE_RE.fullmatch(e)
                                                               for e in engines):
        raise sr.Refused("sandbox policy: build.engines must list docker engine versions")
    prefix = _int(b, "subnet_prefix", 29, 29)
    try:
        pool = ipaddress.ip_network(b["subnet_pool"]) if isinstance(b["subnet_pool"], str) else None
    except ValueError:
        pool = None
    if pool is None or pool.version != 4 or not pool.is_private or pool.prefixlen > prefix - 1:
        raise sr.Refused("sandbox policy: build.subnet_pool must be a private IPv4 network larger than a /29")
    timeout_max = _int(b, "timeout_max", 1, sr.MAX_TIMEOUT)
    timeout_default = _int(b, "timeout_default", 1, timeout_max)
    if timeout_max + PROXY_DEADLINE_SLACK > PROXY_LIFETIME_MAX:
        raise sr.Refused("build timeout exceeds the proxy's independent lifetime budget")
    caps = _exact_keys(b["change_caps"], tuple(CHANGE_CAP_BOUNDS), "build.change_caps")
    change_caps = {k: _int(caps, k, 1, high) for k, high in CHANGE_CAP_BOUNDS.items()}
    gen, held = b["generated_paths"], b["withheld_paths"]
    if not isinstance(gen, list) or len(gen) > 64 or not all(isinstance(g, str) and len(g) <= 256
                                                             and GLOB_RE.fullmatch(g) for g in gen):
        raise sr.Refused("sandbox policy: build.generated_paths must be root-relative globs")
    if not isinstance(held, list) or len(held) > 64 or not all(
            isinstance(w, str) and len(w) <= 256 and WITHHELD_RE.fullmatch(w)
            and not any(seg in (".", "..") for seg in w.split("/")) for w in held):
        raise sr.Refused("sandbox policy: build.withheld_paths must be '<path>/**' entries")
    pcaps = _exact_keys(b["proxy_caps"], PROXY_CAP_KEYS, "build.proxy_caps")
    proxy_caps = {"requests": _int(pcaps, "requests", 1, 2000), "concurrent": _int(pcaps, "concurrent", 1, 16),
                  "bytes_up": _int(pcaps, "bytes_up", 1, 268435456),
                  "bytes_down": _int(pcaps, "bytes_down", 1, 2147483648),
                  "header_block": _int(pcaps, "header_block", 1024, 65536)}
    probe = _exact_keys(b["probe"], PROBE_KEYS, "build.probe")
    ports = probe["ports"]
    if not isinstance(ports, list) or not 1 <= len(ports) <= 32 or len(set(ports)) != len(ports) \
            or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports) \
            or PROXY_PORT in ports:
        raise sr.Refused("sandbox policy: build.probe.ports must be 1..32 distinct ports, never 3128")
    exp_days = _int(b, "placeholder_exp_days", 1, sandbox_auth.MAX_PLACEHOLDER_DAYS)
    return {
        "endpoints": {ENDPOINT_HOST: {"forward": dict(FORWARD_ROUTE), "local": dict(LOCAL_ROUTE),
                                      "request_headers": list(headers),
                                      "placeholder_headers": list(ep["placeholder_headers"])}},
        "refused_hosts_fatal": list(fatal), "engines": list(engines), "subnet_pool": str(pool),
        "subnet_prefix": prefix, "timeout_default": timeout_default, "timeout_max": timeout_max,
        "work_tmpfs": _size(b, "work_tmpfs"), "memory": _size(b, "memory"), "pids": _int(b, "pids", 64, 65536),
        "codex_home_tmpfs": _size(b, "codex_home_tmpfs"), "placeholder_exp_days": exp_days,
        "change_caps": change_caps, "generated_paths": list(gen), "withheld_paths": list(held),
        "result_cap": _int(b, "result_cap", 1024 * 1024, sr.MAX_RESULT_CAP),
        "proxy_log_cap": _int(b, "proxy_log_cap", 1024, 64 * 1024 * 1024), "proxy_caps": proxy_caps,
        "probe": {"deadline": _int(probe, "deadline", 1, 60), "ports": list(ports),
                  "max_published": _int(probe, "max_published", 0, 64),
                  "max_targets": _int(probe, "max_targets", 1, 512)},
    }


def check_build_image(entry: dict) -> None:
    """The codex-build entry must carry codex_version and list codex among its tools."""
    if not isinstance(entry.get("codex_version"), str) or not VERSION_RE.fullmatch(entry["codex_version"]) \
            or "codex" not in entry["tools"]:
        raise sr.Refused(f"image {BUILD_IMAGE!r} in the sandbox policy lacks codex_version or the codex tool")


# --- pure parts: addresses, probe budget, argv ---------------------------------------------------

def address(subnet: str, offset: int) -> str:
    """Return the indexed address inside the selected per-run subnet."""
    net = ipaddress.ip_network(subnet)
    return str(net.network_address + offset)


def draw_subnet(pool: str, taken, prefix: int = 29, rng=None, attempts: int = SUBNET_ATTEMPTS) -> str:
    """A random /`prefix` inside `pool` that overlaps none of `taken` (subnet strings; non-IPv4
    and unparsable entries are ignored). At most `attempts` draws, then Infrastructure."""
    rng = rng or secrets.SystemRandom()
    net = ipaddress.ip_network(pool)
    blocked = []
    for item in taken:
        try:
            cand = ipaddress.ip_network(str(item), strict=False)
        except ValueError:
            continue
        if cand.version == 4:
            blocked.append(cand)
    size = 2 ** (32 - prefix)
    count = 2 ** (prefix - net.prefixlen)
    for _ in range(attempts):
        index = rng.randrange(count)
        cand = ipaddress.ip_network((int(net.network_address) + index * size, prefix))
        if not any(cand.overlaps(b) for b in blocked):
            return str(cand)
    raise sr.Infrastructure(f"no free /{prefix} in {pool} after {attempts} draws")


def probe_targets(policy: dict, subnet: str, own: str, proxy: str, published_ports) -> list:
    """The probe budget (approach 5), computed before any network exists: every address of the
    run's /29 except the probe's and the proxy's x `ports`; the Docker Desktop VM addresses x
    (`ports` + the daemon's published host ports); the metadata address x `ports`; an IPv6
    literal, TCP 1.1.1.1:443, UDP 8.8.8.8:53 and three names. Deduplicated, in that order.
    `policy` is build_policy()'s result. More published ports than `max_published`, or more
    targets than `max_targets`, is a refusal -- never sampled."""
    probe = policy["probe"]
    published = sorted({int(p) for p in published_ports})
    if len(published) > probe["max_published"]:
        raise sr.Refused(f"the docker daemon publishes {len(published)} host ports, more than the probe "
                         f"covers ({probe['max_published']}); refusing rather than sampling")
    ports = probe["ports"]
    out, seen = [], set()

    def add(item):
        if item not in seen:
            seen.add(item)
            out.append(list(item))

    for addr in ipaddress.ip_network(subnet):
        text = str(addr)
        if text in (own, proxy):
            continue
        for port in ports:
            add(("tcp", text, port))
    vm_ports = list(dict.fromkeys([*ports, *published]))
    for text in VM_ADDRS:
        for port in vm_ports:
            add(("tcp", text, port))
    for port in ports:
        add(("tcp", METADATA_ADDR, port))
    for item in FIXED_TARGETS:
        add(item)
    if len(out) > probe["max_targets"]:
        raise sr.Refused(f"the probe budget is {len(out)} targets, more than max_targets "
                         f"({probe['max_targets']}); refusing rather than sampling")
    return out


PORT_RE = re.compile(r"(?:\[[0-9A-Fa-f:.]*\]|[0-9.]*):([0-9]{1,5})(?:-([0-9]{1,5}))?->")


def published_ports(text: str) -> list[int]:
    """Host ports from `docker ps --format {{.Ports}}` lines ("0.0.0.0:8080->80/tcp, [::]:8080->...",
    ranges "a-b->"). Unpublished exposed ports ("80/tcp") carry no "->" and are not counted."""
    ports = set()
    for match in PORT_RE.finditer(text):
        low = int(match.group(1))
        high = int(match.group(2) or match.group(1))
        if not 1 <= low <= high <= 65535:
            raise sr.Infrastructure("docker ps reported an impossible published port")
        ports.update(range(low, high + 1))
    return sorted(ports)


def codex_argv(spec: dict) -> list[str]:
    """The Codex start line the driver validates (approach 7): CODEX_PREFIX, -c model / effort /
    sandbox_mode / approval_policy / notify, one --disable per feature, then
    `--json -o /out/codex-last.txt -` (prompt on stdin). `spec`: model, effort, disable."""
    model, effort = spec.get("model"), spec.get("effort")
    if not isinstance(model, str) or not MODEL_RE.fullmatch(model):
        raise sr.Refused("the build role's model is not a plain model name")
    if not isinstance(effort, str) or not EFFORT_RE.fullmatch(effort):
        raise sr.Refused("the build role's effort is not a plain effort word")
    argv = list(CODEX_PREFIX)
    argv += ["-c", f'model="{model}"', "-c", f'model_reasoning_effort="{effort}"',
             "-c", 'sandbox_mode="danger-full-access"', "-c", 'approval_policy="never"', "-c", "notify=[]"]
    for feature in spec.get("disable", ()):
        if not isinstance(feature, str) or not FEATURE_RE.fullmatch(feature):
            raise sr.Refused("a disabled Codex feature has an unexpected name")
        argv += ["--disable", feature]
    return argv + ["--json", "-o", OUT_LAST, "-"]


def _labels(run_id: str, deadline: int) -> list[str]:
    return ["--label", f"{LABEL}={run_id}", "--label", f"claudex.deadline={deadline}"]


def _check_loader(loader_argv) -> list[str]:
    if not isinstance(loader_argv, list) or len(loader_argv) != 5 or loader_argv[:4] != sr.DRIVER_PREFIX \
            or not isinstance(loader_argv[4], str) or not sr.LOADER_RE.fullmatch(loader_argv[4]):
        raise ValueError("loader argv must be python3 -I -S -c <loader>")
    return list(loader_argv)


def network_create_args(subnet: str, *, run_id: str, deadline: int) -> list[str]:
    """The run's internal network (approach 5; measurement 2026-11-01: plain --internal leaves
    the bridge gateway reachable, the isolated gateway mode is mandatory)."""
    return ["network", "create", "--driver", "bridge", "--internal", "--ipv6=false",
            "-o", f"{GATEWAY_MODE}=isolated", "--subnet", subnet, *_labels(run_id, deadline),
            f"claudex-int-{run_id}"]


def egress_create_args(*, run_id: str, deadline: int) -> list[str]:
    """The proxy's egress network: an ordinary bridge without IPv6, inter-container traffic off."""
    return ["network", "create", "--driver", "bridge", "--ipv6=false", "-o", f"{ICC}=false",
            *_labels(run_id, deadline), f"claudex-egr-{run_id}"]


def builder_create_args(run_id: str, deadline: int, image_id: str, loader_argv: list[str], network: str,
                        ip: str, policy: dict, deps_tmpfs: str | None = None, name: str | None = None) -> list[str]:
    """`docker create` for the builder (and, with name=claudex-probe-<id>, the probe): B1's
    hardening (read-only root, all capabilities dropped but the driver's SETUID/SETGID/KILL,
    no-new-privileges, no mount from the host) on the run's internal network at a fixed address,
    with the policy's limits and a root-owned 1777 tmpfs CODEX_HOME (the driver requires it)."""
    deps = [] if deps_tmpfs is None else ["--tmpfs", f"/deps:rw,exec,nosuid,nodev,size={deps_tmpfs},mode=1777"]
    return [
        "create", "--name", name or f"claudex-build-{run_id}", *_labels(run_id, deadline), "--pull=never",
        "--network", network, "--ip", ip, "--read-only",
        "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
        "--security-opt", "no-new-privileges", "--user", "0:0", "--pids-limit", str(policy["pids"]),
        "--memory", policy["memory"], "--memory-swap", policy["memory"], "--cpus", "2", "--log-driver", "none",
        "--mount", f"type=tmpfs,destination=/work,tmpfs-size={policy['work_tmpfs']},tmpfs-mode=1777",
        "--mount", "type=tmpfs,destination=/out,tmpfs-size=48m,tmpfs-mode=1777",
        "--mount", f"type=tmpfs,destination=/codex-home,tmpfs-size={policy['codex_home_tmpfs']},tmpfs-mode=1777",
        # bandit B108: tmpfs mounts INSIDE the container, not the host's /tmp.
        "--tmpfs", "/tmp:size=256m",  # nosec B108
        "--tmpfs", "/home/run:size=64m", *deps,
        "-e", "HOME=/home/run", "-w", "/", "-i", image_id, *_check_loader(loader_argv),
    ]


def probe_create_args(run_id: str, deadline: int, image_id: str, loader_argv: list[str], network: str,
                      ip: str, policy: dict) -> list[str]:
    """The probe container: the build image with exactly the builder's flags (approach 5)."""
    return builder_create_args(run_id, deadline, image_id, loader_argv, network, ip, policy,
                               name=f"claudex-probe-{run_id}")


def proxy_create_args(run_id: str, deadline: int, image_id: str, loader_argv: list[str], network: str,
                      ip: str) -> list[str]:
    """The proxy container (approach 6): python-test, uid 65532, no capabilities, read-only root,
    64 pids, 256 MiB, a 16 MiB /tmp, no mount; created on the internal network at its fixed
    address, connected to the egress network afterwards."""
    return [
        "create", "--name", f"claudex-proxy-{run_id}", *_labels(run_id, deadline), "--pull=never",
        "--network", network, "--ip", ip, "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "256m",
        "--memory-swap", "256m", "--cpus", "1",
        "--tmpfs", "/tmp:size=16m",  # nosec B108 - inside the container
        "--log-driver", "none", "-w", "/", "-i", image_id, *_check_loader(loader_argv),
    ]


def proxy_spec(policy: dict, placeholders: dict, deadline: int, deny_nets) -> dict:
    """The proxy's spec line (U2 protocol): endpoints and caps from the policy, the PLACEHOLDER
    map from sandbox_auth -- never a real value."""
    ep = policy["endpoints"][ENDPOINT_HOST]
    return {"endpoints": {ENDPOINT_HOST: {k: json.loads(json.dumps(ep[k])) for k in ENDPOINT_KEYS}},
            "placeholders": dict(placeholders), "refused_hosts_fatal": list(policy["refused_hosts_fatal"]),
            "listen": PROXY_PORT, "caps": dict(policy["proxy_caps"]), "deadline": int(deadline),
            "deny_nets": list(dict.fromkeys(deny_nets))}


def check_network(doc, subnet: str) -> None:
    """`docker network inspect` of the internal network must show what was asked for: Internal,
    no IPv6, the isolated gateway mode, exactly the requested subnet and NO IPAM gateway."""
    if not isinstance(doc, dict):
        raise sr.Refused("network inspect returned no object")
    if doc.get("Internal") is not True:
        raise sr.Refused("the run's network is not internal")
    if doc.get("EnableIPv6") is not False:
        raise sr.Refused("the run's network has IPv6 enabled")
    if (doc.get("Options") or {}).get(GATEWAY_MODE) != "isolated":
        raise sr.Refused("the run's network lacks the isolated gateway mode (engine not as measured)")
    ipam = doc.get("IPAM") or {}
    configs = ipam.get("Config")
    if not isinstance(configs, list) or len(configs) != 1 or not isinstance(configs[0], dict):
        raise sr.Refused("the run's network does not have exactly one IPAM config")
    cfg = configs[0]
    if cfg.get("Subnet") != subnet or cfg.get("Gateway") or cfg.get("IPRange") or cfg.get("AuxiliaryAddresses"):
        raise sr.Refused("the run's network has another subnet, an IPAM gateway, a range or aux addresses")


def evaluate_probe(result: dict, targets: list) -> tuple[str, dict]:
    """The host's own verdict on the probe result: isolation_failed on one reached target or a
    default route; isolation_unverified when the child was killed, a row is missing or does not
    match its target, or any outcome is not `blocked`; else isolated. The driver's status can
    only make it stricter. Returns (status, report for the manifest)."""
    rows = result.get("results")
    if result.get("mode") != "probe" or not isinstance(rows, list):
        raise sr.Infrastructure("the probe result is not a probe report")
    reached, open_rows = [], []
    complete = len(rows) == len(targets)
    for i, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 5 or i >= len(targets) or row[:3] != targets[i]:
            complete = False
            continue
        if row[3] == "reached":
            reached.append(row[:4])
        elif row[3] != "blocked":
            open_rows.append(row[:4])
    default_route = result.get("default_route") is True
    if reached or default_route or result.get("status") == "isolation_failed":
        status = "isolation_failed"
    elif not complete or open_rows or result.get("child_killed") is not False or result.get("status") != "isolated":
        status = "isolation_unverified"
    else:
        status = "isolated"
    report = {"status": status, "driver_status": _ascii(result.get("status"))[:40],
              "default_route": default_route, "child_killed": result.get("child_killed") is True,
              "targets": len(targets), "rows": len(rows), "reached": reached[:20], "not_blocked": open_rows[:20],
              "counts": result.get("counts") if isinstance(result.get("counts"), dict) else None}
    return status, report


# --- the proxy's supervised attach (approach 5) -------------------------------------------------

class ProxySession:
    """A supervised `docker start -ai` of the proxy container: stdin stays open (TOKEN later,
    deferred EOF after the builder), a reader thread parses the U2 stdout protocol as it comes
    -- READY / EVENT / ABORT / END with this run's nonce, one JSON log line per request -- and
    keeps the log under `log_cap`. `on_alarm(kind)` is called once, from the reader thread, on
    `EVENT refresh_attempt` ("refresh_attempt"), `ABORT credential` ("credential") or any other
    ABORT ("abort"). `argv` replaces the docker client in tests."""

    def __init__(self, context: str, name: str, nonce: str, log_cap: int, on_alarm=None, argv=None):
        self.argv = argv or ["docker", "--context", context, "start", "-ai", name]
        self.nonce = nonce.encode("ascii")
        self.log_cap = log_cap
        self.on_alarm = on_alarm
        self.proc = None
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.ca_pem = None
        self.alarm = None
        self.abort = None
        self.event = None
        self.end = None
        self.returncode = None
        self.log = bytearray()
        self.log_truncated = False
        self.records = self.forwarded = self.refused = self.local = self.bad_lines = 0
        self._skipping = False
        self._threads = []
        self._closing = False

    # -- process --
    def start(self, head: bytes) -> None:
        """Start the attach client and protocol readers, then send the bounded source/spec prelude."""
        try:
            self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, env=sr.client_env())
        except OSError as exc:
            raise sr.Infrastructure(f"docker not available: {exc}") from exc
        for target in (self._read_out, self._drain_err):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self._threads.append(thread)
        self._write(head)

    def _write(self, data: bytes) -> None:
        done = threading.Event()
        errors = []
        def writer():
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (OSError, ValueError, AttributeError):
                errors.append(True)
            finally:
                done.set()
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        if not done.wait(PROXY_EXIT_SECONDS):
            # A full attach pipe must not prevent cleanup on Windows or POSIX.
            self.proc.kill()
            self.proc.wait(timeout=10)
            thread.join(2)
            raise sr.Infrastructure("proxy stdin write timed out")
        if errors:
            raise sr.Infrastructure("the proxy's stdin is closed")

    def wait_ready(self, timeout: float) -> bytes:
        """Wait at most timeout seconds for the public CA; raise Infrastructure on early termination or timeout."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.ready.wait(0.1):
                return self.ca_pem
            if self.finished.is_set():
                break
        raise sr.Infrastructure(f"the proxy did not report READY within {timeout:.0f}s"
                                + (f" (ABORT {self.abort})" if self.abort else ""))

    def send_token(self, message: bytes) -> None:
        """Send the private TOKEN message through the supervised stdin pipe without logging it."""
        self._write(message)

    def close_stdin(self) -> None:
        """Signal intentional completion only after the builder has finished; the proxy must subsequently emit END."""
        self._closing = True
        if self.proc is not None and self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except (OSError, ValueError):
                pass

    def wait(self, timeout: float):
        """Wait for the attach process and drain readers; return its exit code or None on timeout."""
        if self.proc is None:
            return None
        try:
            self.returncode = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        for thread in self._threads:
            thread.join(5)
        return self.returncode

    def stop(self) -> None:
        """Never outlives the run: kill the local docker client (the container goes in cleanup)."""
        self._closing = True
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                stream.close()
            except (OSError, ValueError, AttributeError):
                pass

    def _drain_err(self) -> None:
        try:
            while self.proc.stderr.read(65536):
                pass
        except (OSError, ValueError):
            pass

    def _read_out(self) -> None:
        try:
            while True:
                line = self.proc.stdout.readline(PROXY_LINE_MAX + 1)
                if not line:
                    return
                self._line(line)
        except (OSError, ValueError):
            return
        finally:
            self.finished.set()
            if not self._closing:
                self._raise_alarm("abort")

    # -- protocol --
    def _keep(self, raw: bytes) -> None:
        with self.lock:
            if len(self.log) + len(raw) > self.log_cap:
                self.log_truncated = True
            else:
                self.log.extend(raw)

    def _raise_alarm(self, kind: str) -> None:
        with self.lock:
            if self.alarm is not None:
                return
            self.alarm = kind
            callback = self.on_alarm
        if callback is not None:
            try:
                callback(kind)
            except Exception:  # noqa: BLE001 - the alarm is recorded; the kill is best effort
                pass

    def _line(self, raw: bytes) -> None:
        """One stdout line (with its LF). An over-long line is counted as bad and skipped up to
        its LF; a READY is not kept in the log (it only carries the public CA certificate)."""
        if self._skipping:
            self._skipping = not raw.endswith(b"\n")
            return
        if not raw.endswith(b"\n"):
            with self.lock:
                self.bad_lines += 1
            self._skipping = len(raw) > PROXY_LINE_MAX
            return
        text = raw[:-1]
        if text.startswith(b"{"):
            try:
                record = json.loads(text.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                record = None
            with self.lock:
                if isinstance(record, dict):
                    self.records += 1
                    route = record.get("route")
                    if route == "forward":
                        self.forwarded += 1
                    elif route == "local":
                        self.local += 1
                    elif route in (403, 404):
                        self.refused += 1
                else:
                    self.bad_lines += 1
            self._keep(raw)
            return
        parts = text.split(b" ", 2)
        if len(parts) == 3 and parts[1] == self.nonce:
            word, arg = parts[0], parts[2]
            if word == b"READY" and not self.ready.is_set():
                try:
                    pem = base64.b64decode(arg, validate=True)
                except (binascii.Error, ValueError):
                    pem = b""
                if pem.startswith(b"-----BEGIN CERTIFICATE-----") and len(pem) <= MAX_CA:
                    self.ca_pem = pem
                    self.ready.set()
                    return
            elif word == b"EVENT" and re.fullmatch(rb"[a-z_]{1,32}", arg):
                self.event = arg.decode("ascii")
                self._keep(raw)
                if arg == b"refresh_attempt":
                    self._raise_alarm("refresh_attempt")
                return
            elif word == b"ABORT" and re.fullmatch(rb"[a-z_]{1,32}", arg):
                self.abort = arg.decode("ascii")
                self._keep(raw)
                self._raise_alarm("credential" if arg == b"credential" else "abort")
                return
            elif word == b"END":
                try:
                    counts = json.loads(arg.decode("ascii"))
                except (UnicodeDecodeError, ValueError):
                    counts = None
                if isinstance(counts, dict) and all(isinstance(k, str) and isinstance(v, int)
                                                    for k, v in counts.items()):
                    self.end = {k[:32]: v for k, v in list(counts.items())[:8]}
                    self._keep(raw)
                    return
        with self.lock:
            self.bad_lines += 1
        self._keep(raw)

    def summary(self) -> dict:
        """Return bounded protocol counts and termination metadata, excluding token bytes and the CA."""
        with self.lock:
            return {"forwarded": self.forwarded, "refused": self.refused, "local": self.local,
                    "records": self.records, "bad_lines": self.bad_lines, "abort": self.abort,
                    "event": self.event, "end": self.end, "log_truncated": self.log_truncated,
                    "exit_code": self.returncode}


# --- the run -------------------------------------------------------------------------------

class _BuildRun(sr._Run):
    """sandbox_run's run state with a build run directory, the docker objects this run created
    (in creation order) and the needles for the manifest's last-line redaction."""

    def __init__(self):
        super().__init__()
        self.fields.update({"mode": "build", "build_status": None})
        self.created: list[tuple[str, str]] = []
        self.removed: set = set()
        self.needles: list[bytes] = []

    def open_run_dir(self) -> Path:
        if self.run_dir is None:
            self.run_dir = hunt_io.ensure_dirs(self.scratch / "sandbox" / f"build-{self.run_id}",
                                               base=self.scratch)
        return self.run_dir

    def write(self, runner_status: str, reason: str = "") -> str | None:
        if self.run_dir is None:
            return None
        manifest = dict(self.fields, runner_status=runner_status)
        if reason:
            manifest["reason"] = _ascii(reason)[:300]
        data = (json.dumps(manifest, sort_keys=True, indent=1) + "\n").encode("utf-8")
        if self.needles:
            # backstop: no field may carry a credential value (none is ever put there)
            data, _hits = sandbox_auth.scan_and_redact(data, self.needles)
        try:
            hunt_io.create_file(self.run_dir, "manifest.json", data, base=self.scratch)
        except hunt_io.HuntIOError:
            return None
        return hashlib.sha256(data).hexdigest()


def _register(state: _BuildRun, kind: str, name: str) -> None:
    if (kind, name) not in state.created:
        state.created.append((kind, name))


def _create(context: str, state: _BuildRun, kind: str, name: str, args: list[str]):
    """One docker create, registered for cleanup BEFORE the call (a create whose client times
    out is still removed by name); the full client command line stays below CMDLINE_MAX."""
    full = ["docker", "--context", context, *args]
    if sr.cmdline_length(full) >= CMDLINE_MAX:
        raise sr.Infrastructure(f"the {kind} create command line is {sr.cmdline_length(full)} characters "
                                f"(limit {CMDLINE_MAX})")
    _register(state, kind, name)
    return sr.docker(context, *args)


def _remove_now(context: str, state: _BuildRun, kind: str, name: str) -> None:
    sr.remove_object(context, kind, name)
    state.removed.add((kind, name))


def cleanup(context: str, state: _BuildRun) -> None:
    """Remove every object this run created -- containers first, then networks -- each proved
    absent; the pass goes on past a failure, then Infrastructure names every survivor."""
    order = [o for o in reversed(state.created) if o[0] == "container"] \
        + [o for o in reversed(state.created) if o[0] == "network"]
    survivors = []
    for kind, name in order:
        if (kind, name) in state.removed:
            continue
        try:
            _remove_now(context, state, kind, name)
        except sr.Infrastructure:
            survivors.append(f"{kind} {name}")
    if survivors:
        state.fields["cleanup"] = "UNCONFIRMED"
        state.fields["cleanup_unconfirmed"] = survivors
        sr._diagnostic(lambda: f"sandbox_build: cleanup: UNCONFIRMED {' '.join(survivors)}\n")
        raise sr.Infrastructure(f"cleanup: UNCONFIRMED {', '.join(survivors)}")
    state.fields["cleanup"] = "confirmed" if state.created else "not_needed"


def engine_version(context: str) -> str:
    """Read the selected Docker daemon version; raise Infrastructure if it cannot be determined."""
    done = sr.docker(context, "version", "--format", "{{.Server.Version}}")
    text = done.stdout.decode("ascii", "replace").strip() if done.returncode == 0 else ""
    if not text:
        raise sr.Infrastructure("the docker daemon of the policy's context is not reachable")
    return text


def taken_subnets(context: str) -> list[str]:
    """Inspect existing Docker networks in bounded batches; fail closed on inspection errors."""
    done = sr.docker(context, "network", "ls", "--no-trunc", "-q")
    if done.returncode != 0:
        raise sr.Infrastructure("cannot list docker networks")
    ids = done.stdout.decode("ascii", "replace").split()
    out = []
    for i in range(0, len(ids), NETWORK_BATCH):
        res = sr.docker(context, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
                        *ids[i:i + NETWORK_BATCH])
        if res.returncode != 0:
            raise sr.Infrastructure("cannot inspect docker networks")
        out += res.stdout.decode("ascii", "replace").split()
    return out


def _network_subnets(context: str, name: str) -> list[str]:
    res = sr.docker(context, "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", name)
    if res.returncode != 0:
        raise sr.Infrastructure(f"cannot inspect network {name}")
    subnets = []
    for token in res.stdout.decode("ascii", "replace").split():
        try:
            subnets.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            raise sr.Infrastructure(f"network {name} reports an unreadable subnet") from None
    if not subnets:
        raise sr.Infrastructure(f"network {name} has no subnet")
    return subnets


def create_internal_network(context: str, state: _BuildRun, policy: dict, taken: list, deadline: int) -> tuple[str, str]:
    """Create and verify a per-run isolated network, retrying subnet overlaps within the policy limit."""
    name = f"claudex-int-{state.run_id}"
    taken = list(taken)
    for _attempt in range(SUBNET_ATTEMPTS):
        subnet = draw_subnet(policy["subnet_pool"], taken, policy["subnet_prefix"])
        done = _create(context, state, "network", name,
                       network_create_args(subnet, run_id=state.run_id, deadline=deadline))
        if done.returncode == 0:
            break
        if b"overlap" in done.stderr.lower():
            taken.append(subnet)
            continue
        raise sr.Infrastructure(f"docker network create failed: {sr._tail(done.stderr)}")
    else:
        raise sr.Infrastructure(f"no free subnet in {policy['subnet_pool']} after {SUBNET_ATTEMPTS} attempts")
    res = sr.docker(context, "network", "inspect", "--format", "{{json .}}", name)
    if res.returncode != 0:
        raise sr.Infrastructure("cannot inspect the run's network")
    try:
        doc = json.loads(res.stdout.decode("utf-8"))
    except ValueError:
        raise sr.Infrastructure("network inspect is not JSON") from None
    check_network(doc, subnet)
    return name, subnet


def _container_state(context: str, name: str) -> tuple[str, bool]:
    st = sr.docker(context, "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name)
    words = st.stdout.decode("ascii", "replace").split() if st.returncode == 0 else []
    if len(words) != 2:
        raise sr.Infrastructure("cannot inspect the finished container")
    return words[0], words[1] == "true"


def read_prompt(path: str) -> bytes:
    """--prompt-file through hunt_io.read_at: a regular file reached without links, 1..1 MiB."""
    p = Path(os.path.abspath(path))
    status, data = hunt_io.read_at(p.parent, p.name, MAX_PROMPT)
    if status != "ok":
        raise sr.Refused(f"--prompt-file is not a regular file of at most {MAX_PROMPT} bytes ({data})")
    if not data:
        raise sr.Refused("--prompt-file is empty")
    return data


def build_model(repo: Path) -> tuple[str, str]:
    """Model and effort of the `build` role (claudex_roles, as `--spec build`): one actor,
    codex, with both set -- with --ignore-user-config they cannot come from config.toml."""
    try:
        cfg, _path = claudex_roles.load(repo)
    except claudex_roles.ConfigError as exc:
        raise sr.Refused(f"role config: {_ascii(exc)}") from None
    problems = claudex_roles.check(cfg)
    if problems:
        raise sr.Refused(f"role config violates a gate: {_ascii(problems[0])}")
    specs = claudex_roles.actor_spec(cfg, "build")
    if len(specs) != 1 or specs[0].get("actor") != "codex":
        raise sr.Refused("the build role is not the codex actor; the sandboxed build runs Codex only")
    model, effort = specs[0].get("model"), specs[0].get("effort")
    if not model or not effort:
        raise sr.Refused("the build role has no model or effort (claudex_roles.py --spec build)")
    return str(model), str(effort)


def load_auth(timeout: int, policy: dict):
    """Load host login without printing secrets; require token validity beyond the requested run and cleanup margin."""
    home = os.environ.get("CODEX_HOME") or str(Path.home() / ".codex")
    return sandbox_auth.load(Path(home), time.time() + timeout + 600, policy["placeholder_exp_days"])


def read_build_result(data: bytes, nonce: str, policy: dict, with_deps: bool):
    """The build result (U3): read_framed under result_cap with the member caps; required members
    present; result.json's command and build objects valid; every change/<n> exactly the added
    and modified entries of changes.json, each re-hashed. Returns (result, members, changes,
    excluded document)."""
    caps = dict(MEMBER_CAPS)
    if with_deps:
        caps["install.txt"] = INSTALL_CAP
    result, got = sr.read_framed(data, nonce, caps, {"change/": policy["change_caps"]["file_bytes"]},
                                 policy["result_cap"])
    need = ["codex-events.jsonl", "codex-stderr.txt", "login.txt", "changes.json", "excluded.json"]
    for name in need + (["install.txt"] if with_deps else []):
        if name not in got:
            raise sr.Infrastructure(f"result member {name} missing")
    status = result.get("command_status")
    if status not in COMMAND_STATUSES:
        raise sr.Infrastructure("result has no valid command_status")
    sr._check_result_deps(result.get("deps"), status, with_deps)
    build = result.get("build")
    if not isinstance(build, dict) or set(build) != {"codex_exit", "change_status", "change_reason", "counts",
                                                      "login_status"}:
        raise sr.Infrastructure("result has no valid build object")
    if build["login_status"] not in ("chatgpt", "rejected", None) \
            or build["change_status"] not in ("ok", "refused", "not_computed"):
        raise sr.Infrastructure("result build object has an unknown status")
    counts = build["counts"]
    if not isinstance(counts, dict) or set(counts) != set(COUNT_KEYS) \
            or any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in counts.values()):
        raise sr.Infrastructure("result build counts are malformed")
    exports = result.get("exports")
    last = exports.get("codex-last.txt") if isinstance(exports, dict) else None
    if ("codex-last.txt" in got) != (isinstance(last, str) and re.fullmatch(r"[0-9a-f]{64}", last) is not None) \
            or ("codex-last.txt" in got and hashlib.sha256(got["codex-last.txt"]).hexdigest() != last):
        raise sr.Infrastructure("codex-last.txt does not match the result's export record")
    try:
        changes = json.loads(got["changes.json"].decode("utf-8"))
        excluded = json.loads(got["excluded.json"].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise sr.Infrastructure("changes.json or excluded.json is not JSON") from None
    if not isinstance(changes, list) or not isinstance(excluded, dict) \
            or set(excluded) != {"excluded", "withheld"} or not isinstance(excluded["excluded"], list):
        raise sr.Infrastructure("changes.json or excluded.json has the wrong shape")
    expected = {}
    for i, entry in enumerate(changes):
        if not isinstance(entry, dict) or entry.get("op") not in ("added", "modified", "deleted", "mode"):
            raise sr.Infrastructure(f"changes.json entry {i} is malformed")
        if entry["op"] in ("added", "modified"):
            expected[f"change/{i}"] = entry
    present = {n for n in got if n.startswith("change/")}
    if present != set(expected):
        raise sr.Infrastructure("the change/<n> members do not match the added and modified entries")
    for name, entry in expected.items():
        blob = got[name]
        if len(blob) != entry.get("size") or hashlib.sha256(blob).hexdigest() != entry.get("sha256"):
            raise sr.Infrastructure(f"{name} does not match its size and sha256 in changes.json")
    if build["change_status"] != "ok" and changes:
        raise sr.Infrastructure("a change set that was not computed carries entries")
    if sum(counts[k] for k in ("added", "modified", "deleted", "mode")) != len(changes):
        raise sr.Infrastructure("the result counts do not match changes.json")
    return result, got, changes, excluded


def decide_status(alarm, credential_hit: bool, oom: bool, result: dict | None) -> tuple[str, str | None]:
    """BUILD_STATUS and the auth_failed reason, strongest first: credential_exposed, auth_failed
    (refresh_attempt, placeholder_rejected), oom, the command's own non-success, change_refused,
    exited."""
    if alarm == "credential" or credential_hit:
        return "credential_exposed", None
    if alarm == "refresh_attempt":
        return "auth_failed", "refresh_attempt"
    if oom:
        return "oom", None
    if result is None:
        raise sr.Infrastructure("no build result")
    build = result["build"]
    if build["login_status"] == "rejected":
        return "auth_failed", "placeholder_rejected"
    status = result["command_status"]
    if status != "exited":
        return status, None
    if build["change_status"] == "refused":
        return "change_refused", None
    return "exited", None


def run(args, state: _BuildRun) -> int:
    # Known before any check, so that a static refusal can still be recorded.
    """Validate inputs, probe isolation, supervise proxy and builder, clean resources, then publish quarantine results."""
    state.scratch = Path(os.path.abspath(args.scratch))
    state.fields.update({"image": BUILD_IMAGE, "proxy_image": PROXY_IMAGE, "timeout": args.timeout})
    for line in sandbox_fetch.list_quarantine(state.scratch):
        sr._diagnostic(lambda q=line: f"sandbox_build: QUARANTINE {q}\n")
    policy = sr.load_policy()
    bcfg = build_policy(policy)
    sr.check_environment()
    context = policy["context"]
    timeout = bcfg["timeout_default"] if args.timeout is None else args.timeout
    if not 1 <= timeout <= bcfg["timeout_max"]:
        raise sr.Refused(f"--timeout must be 1..{bcfg['timeout_max']}")
    state.fields["timeout"] = timeout
    if not args.pin and (not args.tree or not sr.TREE_RE.fullmatch(args.tree)):
        raise sr.Refused("--tree must be a full tree id (or use --pin)")
    for rel in args.pin or ():
        sandbox_snapshot.canonical_path(rel)
    paths = sr.deps_paths(list(args.deps))
    entry = sr.policy_entry(policy, BUILD_IMAGE)
    check_build_image(entry)
    sr.policy_entry(policy, PROXY_IMAGE)
    cfg = sr.deps_policy(entry)
    if paths and cfg is None:
        raise sr.Refused(f"image {BUILD_IMAGE!r} has no wheel_target; --deps is not available for it")
    pool_first = str(next(ipaddress.ip_network(bcfg["subnet_pool"]).subnets(new_prefix=bcfg["subnet_prefix"])))
    probe_targets(bcfg, pool_first, address(pool_first, PROBE_OFFSET), address(pool_first, PROXY_OFFSET), [])
    prompt = read_prompt(args.prompt_file)
    repo = Path(os.path.abspath(args.repo))
    model, effort = build_model(repo)
    argv = codex_argv({"model": model, "effort": effort, "disable": list(build_isolation.BUILD_DISABLE)})
    try:
        source = change_apply.worktree_identity(repo)
    except change_apply.ApplyRefused as exc:
        raise sr.Refused(f"--repo: {_ascii(exc)}") from None
    driver = sr.DRIVER_FILE.read_bytes()
    proxy_src = PROXY_FILE.read_bytes()
    state.fields.update({"source": source, "model": model, "effort": effort, "codex_argv": argv,
                         "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
                         "driver_sha256": hashlib.sha256(driver).hexdigest(),
                         "proxy_sha256": hashlib.sha256(proxy_src).hexdigest()})
    # Everything above is static: no docker call has happened.
    scratch = state.scratch
    state.open_run_dir()

    engine = engine_version(context)
    state.fields["engine"] = _ascii(engine)[:40]
    if engine not in bcfg["engines"]:
        raise sr.Refused(f"docker engine {_ascii(engine)[:40]} is not one of the measured engines "
                         f"({', '.join(bcfg['engines'])})")
    state.fields["image_id"] = sr.resolve_image(policy, BUILD_IMAGE)
    state.fields["proxy_image_id"] = sr.resolve_image(policy, PROXY_IMAGE)
    sr.janitor(context, kinds=("container", "network"))

    try:
        auth = load_auth(timeout, bcfg)
    except sandbox_auth.AuthRefused as exc:
        raise sr.Refused(f"host login: {_ascii(exc)}") from None
    state.needles = list(auth.needles)
    state.fields["auth"] = {"mode": auth.mode, "exp": auth.exp, "real_map_sha256": auth.sha256}

    work = hunt_io.make_dir(state.run_dir, "snapshot", base=scratch)
    try:
        info, tar_bytes = sr.supervised_snapshot(repo, None if args.pin else args.tree, args.pin, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    tree = info["tree"]
    state.fields.update({"tree": tree, "input_sha256": info["input_sha256"], "files": info["files"]})

    deps_tar = b""
    if paths:
        files = sr.read_deps_files(info, tar_bytes, paths)
        reqs = sr.parse_deps(files)
        state.fields["deps"] = {
            "files": [{"path": p, "content_sha256": h} for p, h, _data in files],
            "requirements_sha256": sandbox_deps.requirements_sha256(reqs),
            "wheel_target": cfg["wheel_target"], "requirements": None, "deps_tar_sha256": None,
            "install": None, "install_txt_sha256": None,
        }
        deps_tar = sr.fetch_deps(state, reqs, cfg)

    ps = sr.docker(context, "ps", "--format", "{{.Ports}}")
    if ps.returncode != 0:
        raise sr.Infrastructure("cannot list running containers for the probe budget")
    published = published_ports(ps.stdout.decode("ascii", "replace"))
    # The budget with the daemon's published ports, BEFORE any network exists (approach 5): its size
    # does not depend on which /29 is drawn later.
    probe_targets(bcfg, pool_first, address(pool_first, PROBE_OFFSET), address(pool_first, PROXY_OFFSET),
                  published)
    taken = taken_subnets(context)

    deadline = int(time.time()) + timeout + DEADLINE_SLACK
    state.fields.update({"deadline": deadline, "cleanup": "pending", "token_sent": False})
    run_id = state.run_id
    probe_name, proxy_name, build_name = (f"claudex-probe-{run_id}", f"claudex-proxy-{run_id}",
                                          f"claudex-build-{run_id}")
    proxy = None
    builder = {"name": None}
    oom = False
    result = got = changes = excluded = None
    first_failure: list = [None]

    def kill_builder(_kind):
        name = builder["name"]
        if name:
            try:
                sr.docker(context, "kill", name)
            except sr.Infrastructure:
                pass

    try:
        int_net, subnet = create_internal_network(context, state, bcfg, taken, deadline)
        proxy_ip, probe_ip = address(subnet, PROXY_OFFSET), address(subnet, PROBE_OFFSET)
        state.fields["network"] = {"internal": int_net, "subnet": subnet, "proxy_ip": proxy_ip,
                                   "builder_ip": probe_ip}

        # -- the probe, before any proxy exists ------------------------------------------------
        targets = probe_targets(bcfg, subnet, probe_ip, proxy_ip, published)
        probe_nonce = secrets.token_hex(16)
        pspec = {"mode": "probe", "probe_targets": targets, "probe_deadline": bcfg["probe"]["deadline"],
                 "exclude_addrs": [probe_ip, proxy_ip]}
        loader_argv, loader_block = sr.bootstrap(driver)
        done = _create(context, state, "container", probe_name,
                       probe_create_args(run_id, deadline, state.fields["image_id"], loader_argv, int_net,
                                         probe_ip, bcfg))
        if done.returncode != 0:
            raise sr.Infrastructure(f"docker create (probe) failed: {sr._tail(done.stderr)}")
        out, _err = sr.stream_start(context, probe_name, loader_block + (probe_nonce + "\n").encode()
                                    + (json.dumps(pspec, sort_keys=True) + "\n").encode(),
                                    bcfg["probe"]["deadline"] + PROBE_SLACK, result_cap=PROBE_RESULT_CAP)
        exit_code, probe_oom = _container_state(context, probe_name)
        if probe_oom or exit_code != "0":
            raise sr.Infrastructure(f"the probe driver ended with exit {exit_code}")
        presult, _members = sr.read_framed(out, probe_nonce, {"result.json": PROBE_RESULT_CAP}, {},
                                           PROBE_RESULT_CAP)
        status, report = evaluate_probe(presult, targets)
        state.fields["probe"] = report
        _remove_now(context, state, "container", probe_name)  # frees .3 for the builder
        if status != "isolated":
            state.fields["isolation"] = status
            raise IsolationFailed(status)

        # -- the proxy: egress network, container, READY, then TOKEN ------------------------------
        egr_name = f"claudex-egr-{run_id}"
        done = _create(context, state, "network", egr_name, egress_create_args(run_id=run_id, deadline=deadline))
        if done.returncode != 0:
            raise sr.Infrastructure(f"docker network create (egress) failed: {sr._tail(done.stderr)}")
        egress_subnets = _network_subnets(context, egr_name)
        state.fields["network"]["egress"] = egr_name
        state.fields["network"]["egress_subnets"] = egress_subnets
        p_argv, p_block = sr.bootstrap(proxy_src)
        done = _create(context, state, "container", proxy_name,
                       proxy_create_args(run_id, deadline, state.fields["proxy_image_id"], p_argv, int_net,
                                         proxy_ip))
        if done.returncode != 0:
            raise sr.Infrastructure(f"docker create (proxy) failed: {sr._tail(done.stderr)}")
        done = sr.docker(context, "network", "connect", egr_name, proxy_name)
        if done.returncode != 0:
            raise sr.Infrastructure(f"docker network connect failed: {sr._tail(done.stderr)}")
        proxy_nonce = secrets.token_hex(16)
        proxy_deadline = int(time.time()) + min(timeout + PROXY_DEADLINE_SLACK, PROXY_LIFETIME_MAX)
        spec = proxy_spec(bcfg, auth.placeholder_map, proxy_deadline,
                          [subnet, *egress_subnets, bcfg["subnet_pool"]])
        state.fields["proxy_deadline"] = proxy_deadline
        proxy = ProxySession(context, proxy_name, proxy_nonce, bcfg["proxy_log_cap"], on_alarm=kill_builder)
        proxy.start(p_block + (proxy_nonce + "\n").encode() + (json.dumps(spec, sort_keys=True) + "\n").encode())
        ca_pem = proxy.wait_ready(READY_SECONDS)
        state.fields["ca_sha256"] = hashlib.sha256(ca_pem).hexdigest()
        proxy.send_token(auth.token_message)  # the probe passed: only now
        state.fields["token_sent"] = True

        # -- the builder -------------------------------------------------------------------------
        if proxy.alarm is None:
            build_nonce = secrets.token_hex(16)
            bspec = {"mode": "build", "tar_len": len(tar_bytes), "deps_len": len(deps_tar),
                     "deps_sha256": hashlib.sha256(deps_tar).hexdigest() if deps_tar else "",
                     "deps_timeout": cfg["install_timeout"] if cfg else sr.DEFAULT_DEPS_TIMEOUT,
                     "codex_argv": argv, "proxy_url": f"http://{proxy_ip}:{PROXY_PORT}", "ca_len": len(ca_pem),
                     "placeholder_len": len(auth.placeholder_auth_json), "prompt_len": len(prompt),
                     "change_caps": dict(bcfg["change_caps"]), "generated_paths": list(bcfg["generated_paths"]),
                     "withheld_paths": list(bcfg["withheld_paths"]), "codex_timeout": timeout}
            b_argv, b_block = sr.bootstrap(driver)
            done = _create(context, state, "container", build_name,
                           builder_create_args(run_id, deadline, state.fields["image_id"], b_argv, int_net,
                                               probe_ip, bcfg, deps_tmpfs=cfg["tmpfs"] if deps_tar else None))
            if done.returncode != 0:
                raise sr.Infrastructure(f"docker create (builder) failed: {sr._tail(done.stderr)}")
            stdin = (b_block + (build_nonce + "\n").encode() + (json.dumps(bspec, sort_keys=True) + "\n").encode()
                     + tar_bytes + deps_tar + prompt + auth.placeholder_auth_json + ca_pem)
            builder["name"] = build_name
            if proxy.alarm is not None:
                kill_builder(proxy.alarm)
            try:
                out, _err = sr.stream_start(context, build_name, stdin, timeout + BUILD_SLACK,
                                            result_cap=bcfg["result_cap"])
            except sr.Infrastructure:
                if proxy.alarm is None:
                    raise
                out = b""
            builder["name"] = None
            if proxy.alarm is None:
                exit_code, oom = _container_state(context, build_name)
                if not oom and exit_code != "0":
                    raise sr.Infrastructure(f"the build driver ended with exit {exit_code}")
                if not oom:
                    result, got, changes, excluded = read_build_result(out, build_nonce, bcfg, bool(deps_tar))
        # deferred EOF: the proxy stops serving and reports END
        proxy.close_stdin()
        proxy_exit = proxy.wait(PROXY_EXIT_SECONDS)
        if proxy.alarm is None and (proxy_exit != 0 or proxy.end is None):
            raise sr.Infrastructure("proxy did not complete with exit 0 and END")
    except BaseException as exc:
        first_failure[0] = exc
        raise
    finally:
        if proxy is not None:
            proxy.stop()
            state.fields["proxy"] = proxy.summary()
        try:
            cleanup(context, state)
        except sr.Infrastructure:
            # the cleanup failure decides the exit code; the manifest keeps what failed first
            if first_failure[0] is not None:
                state.fields["first_failure"] = _ascii(first_failure[0])[:300]
            raise

    return finish(state, proxy, auth, tree, oom, result, got, changes, excluded)


def finish(state: _BuildRun, proxy: ProxySession, auth, tree: str, oom: bool, result, got, changes,
           excluded) -> int:
    """After cleanup: scan every builder-controlled channel, then (and only then) write to the
    host -- proxy.log, the Codex outputs, the change set -- then the manifest and the lines."""
    scratch, run_dir = state.scratch, state.run_dir
    hits = {}
    log, log_hits = sandbox_auth.scan_and_redact(bytes(proxy.log), auth.needles)
    if log_hits:
        hits["proxy.log"] = log_hits
    if proxy.alarm == "abort":
        hunt_io.create_file(run_dir, "proxy.log", log, base=scratch)
        state.fields["proxy_log_sha256"] = hashlib.sha256(log).hexdigest()
        raise sr.Infrastructure(f"the proxy aborted the run: {_ascii(proxy.abort)}")
    scanned = {}
    for name, data in sorted((got or {}).items()):
        clean, n = sandbox_auth.scan_and_redact(data, auth.needles)
        scanned[name] = clean
        if n:
            hits[name] = n
    build_status, auth_reason = decide_status(proxy.alarm, bool(hits), oom, result)
    state.fields["credential_hits"] = hits
    hunt_io.create_file(run_dir, "proxy.log", log, base=scratch)
    state.fields["proxy_log_sha256"] = hashlib.sha256(log).hexdigest()

    written = {}
    if build_status == "credential_exposed":
        names = [n for n in TEXT_MEMBERS if n in scanned]
    else:
        names = sorted(scanned)
    for name in names:
        data = scanned[name]
        if name.startswith("change/"):
            hunt_io.make_tree(run_dir, "change", base=scratch)
            hunt_io.create_file(run_dir / "change", name[len("change/"):], data, base=scratch)
        else:
            hunt_io.create_file(run_dir, name, data, base=scratch)
        written[name] = hashlib.sha256(data).hexdigest()
    with_set = build_status != "credential_exposed" and result is not None
    if with_set:
        state.fields["changes_sha256"] = written["changes.json"]
        state.fields["excluded_sha256"] = written["excluded.json"]
    build = result["build"] if result is not None else None
    command_status = result["command_status"] if result is not None else ("oom" if oom else "not_started")
    codex_exit = result.get("command_exit") if result is not None and command_status == "exited" else None
    state.fields.update({
        "build_status": build_status, "auth_reason": auth_reason, "command_status": command_status,
        "codex_exit": codex_exit, "truncated": bool(result.get("truncated")) if result else False,
        "login_status": build["login_status"] if build else None,
        "change_status": build["change_status"] if build else None,
        "change_reason": _ascii(build["change_reason"])[:300] if build and build["change_reason"] else None,
        "counts": build["counts"] if build else None, "written": written,
    })
    if isinstance(state.fields.get("deps"), dict) and result is not None:
        state.fields["deps"]["install"] = result.get("deps")
        if "install.txt" in scanned:
            state.fields["deps"]["install_txt_sha256"] = hashlib.sha256(scanned["install.txt"]).hexdigest()
    summary = proxy.summary()
    digest = state.write("ok")
    if digest is None:
        raise sr.Infrastructure("the run manifest could not be written")
    n_changes = len(changes) if with_set and changes else 0
    n_binary = sum(1 for e in changes if e.get("binary") is True) if with_set and changes else 0
    n_excluded = len(excluded["excluded"]) if with_set and excluded else 0
    lines = [f"RUN_DIR={run_dir}", f"TREE={tree}", f"BUILD_STATUS={build_status}",
             f"CODEX_EXIT={codex_exit if codex_exit is not None else '-'}", f"CHANGES={n_changes}",
             f"BINARY={n_binary}", f"EXCLUDED={n_excluded}", f"PROXY_FORWARDED={summary['forwarded']}",
             f"PROXY_REFUSED={summary['refused']}"]
    if state.requirements_sha256():
        lines.append(f"REQUIREMENTS_SHA256={state.requirements_sha256()}")
    lines.append(f"MANIFEST_SHA256={digest}")
    if not sr._emit(lines):
        sr._diagnostic(lambda: f"sandbox_build: INFRASTRUCTURE - the result lines could not be written to "
                               f"stdout; manifest {ascii(str(run_dir))}/manifest.json\n")
        return EXIT_INFRA
    return EXIT_OK


def parse_args(argv):
    """Parse the public run command, including repository, pinned tree, prompt and timeout arguments."""
    ap = argparse.ArgumentParser(description="run the Codex build in a hardened container (plan B2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="one build round")
    r.add_argument("--repo", required=True)
    r.add_argument("--scratch", required=True, help="the session scratch dir; run dirs go below it")
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--tree", help="the pinned git tree id")
    src.add_argument("--pin", nargs="+", metavar="PATH",
                     help="build a tree from HEAD plus these paths, without repository filters")
    r.add_argument("--prompt-file", required=True)
    r.add_argument("--deps", action="append", default=[], metavar="PATH",
                   help="a fully hashed requirements file of the pinned tree (at most 4; plan B1.5)")
    r.add_argument("--timeout", type=int, default=None)
    return ap.parse_args(argv)


def main(argv=None) -> int:
    """Execute a build and record refusal or infrastructure manifests with public exit codes 2 or 5."""
    try:
        args = parse_args(argv)
    except SystemExit as exc:
        return EXIT_REFUSED if exc.code else EXIT_OK
    state = _BuildRun()
    try:
        return run(args, state)
    except (sr.Refused, sandbox_snapshot.SnapshotRefused, hunt_io.HuntIOError) as exc:
        kind = {sandbox_snapshot.SnapshotRefused: " (snapshot)", hunt_io.HuntIOError: " (run dir)"}.get(type(exc), "")
        sr._diagnostic(lambda e=exc: f"sandbox_build: REFUSED{kind} - {_ascii(e)}\n")
        _report_failure(state, "refused", exc)
        return EXIT_REFUSED
    except sr.Infrastructure as exc:
        sr._diagnostic(lambda e=exc: f"sandbox_build: INFRASTRUCTURE - {_ascii(e)}\n")
        _report_failure(state, "infrastructure", exc)
        return EXIT_INFRA


def _report_failure(state: _BuildRun, status: str, exc: Exception) -> None:
    """A failed run still leaves a manifest with what is known -- a static refusal too, as long
    as the scratch directory exists (the runner never creates it). Best-effort stdout lines."""
    if state.run_dir is None and state.scratch is not None and state.scratch.is_dir():
        try:
            state.open_run_dir()
        except hunt_io.HuntIOError:
            pass
    digest = state.write(status, str(exc))
    if digest:
        lines = [f"RUN_DIR={state.run_dir}"]
        if state.requirements_sha256():
            lines.append(f"REQUIREMENTS_SHA256={state.requirements_sha256()}")
        lines.append(f"MANIFEST_SHA256={digest}")
        if not sr._emit(lines):
            sr._diagnostic(lambda: "sandbox_build: the result lines could not be written to stdout\n")


def entry(argv=None) -> int:
    """main(), then sandbox_run.settle_std_streams(), so main()'s exit code is the process's."""
    code = main(argv)
    sr.settle_std_streams()
    return code


if __name__ == "__main__":
    sys.exit(entry())
