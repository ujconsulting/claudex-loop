#!/usr/bin/env python3
"""Fallback plan reviewer over any OpenAI-compatible chat endpoint.

Part of the claudex-loop quota-exhaustion protocol (see FALLBACK.md). Invoked
ONLY after the user explicitly chose to switch reviewers — never automatically,
never silently. Configuring a chain order in CLAUDEX_REVIEWERS is that consent
in standing form: `--chain` walks the configured order and REPORTS every
provider it skipped and why; it never invents a reviewer the user did not list.

Safety model (the two findings from issue #7, addressed by construction):

1. "Read-only" is not read off vendor docs — it is structural. The model gets
   NO file or tool access at all: the plan (and optionally the review log so
   far) is inlined into the prompt, the reply is text. There is nothing to
   escalate, so per-vendor sandbox audits are unnecessary.
2. Rubber-stamping does not count. A reply must end with a VERDICT line, and
   an APPROVED in round 1 with fewer than --min-findings numbered findings is
   treated as an INVALID review (exit 3), not as an approval.

Plan-hash binding: the SHA256 of the plan file is stamped into the verdict
header. A verdict is only valid for exactly that plan state; editing the plan
afterwards self-demotes the approval.

Configuration is environment-driven (process env, plus a `.env` file in the
working directory if present). Reviewers are named profiles:

    CLAUDEX_REVIEWERS=lmstudio,openrouter          # chain order, first = default
    CLAUDEX_REVIEWER_LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
    CLAUDEX_REVIEWER_LMSTUDIO_MODEL=qwen/qwen3.8-27b
    CLAUDEX_REVIEWER_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
    CLAUDEX_REVIEWER_OPENROUTER_MODEL=deepseek/deepseek-r1
    CLAUDEX_REVIEWER_OPENROUTER_API_KEY_ENV=OPENROUTER_API_KEY

Any OpenAI-compatible endpoint works: LM Studio, Ollama, OpenRouter, OpenAI,
Google Gemini (…/v1beta/openai) and Anthropic (api.anthropic.com/v1) included.
See .env.example for ready-made profiles.

Egress, in three tiers — plain http reaches loopback only in all of them. The
plan and the whole review log travel in that request, so the old rule ("no
cleartext *if a key is set*") had it backwards and left keyless endpoints
unprotected.

1. Nothing configured: the scheme rule alone. Stdlib-only, the default.
2. CLAUDEX_EGRESS_ALLOW=host,host — an exact-match host list. No wildcards and
   no suffixes: `api.openai.com.attacker.test` ends in an allowed name.
3. A file allowlist — CLAUDEX_EGRESS_ALLOWLIST=<path>, or `config/allowed_egress.yaml`
   at the repo root, whose mere presence is the opt-in. Per-host schemes and a
   place to write down WHY a host is listed. **Fail-closed:** if the file is
   named but missing, unparseable, or PyYAML is not installed, nothing is sent.
   Not installing the parser does not lift the restriction. This is the only
   tier that needs a dependency, and only for whoever chooses it.

Preflight (`--check`, and automatically per provider in `--chain`): local
endpoints (127.0.0.1/localhost) only need to be reachable; remote providers
get an auth-validity probe (GET /models), and OpenRouter — the only listed
provider with a real balance API — additionally reports remaining credits via
GET /credits. OpenAI/Gemini/Anthropic expose no balance endpoint: exhaustion
there only shows up as HTTP 429/402 on use, which the chain treats as
terminal for that provider and moves on.

Usage:
    python scripts/fallback_review.py --plan PLAN.md [--reviewer NAME | --chain]
        [--log PLAN-REVIEW-LOG.md] [--round N] [--out verdict.txt]
        [--min-findings 3] [--list] [--check]

Exit codes: 0 = valid review with verdict; 2 = config/transport error (or, in
--chain mode, every configured provider failed preflight or errored); 3 =
invalid review (no verdict line, or rubber-stamp suspicion). Never treat exit
2/3 as an approval.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

SYSTEM_PROMPT = (
    "You are an adversarial reviewer for an implementation plan. Be skeptical "
    "and specific — your job is to find what breaks, not to be agreeable. "
    "Identify concrete flaws: security holes, race conditions, missing edge "
    "cases, schema conflicts, wrong assumptions, observability gaps, simpler "
    "alternatives. Number your findings; anchor each one to a section or line "
    "of the plan and state what concretely goes wrong if the plan ships as-is, "
    "plus a one-line fix. You only see the text you are given — if a claim "
    "cannot be verified from the plan itself, flag it as unverified rather "
    "than assuming it holds. Do NOT reproduce, re-list or line-number the "
    "material you were given — cite it by section or file:line and move on; "
    "your output budget is for findings. End your reply with EXACTLY one line: "
    "'VERDICT: APPROVED' if the plan is sound enough to implement, or "
    "'VERDICT: REVISE' if it still has material problems."
)


def load_dotenv(path=".env"):
    """Minimal .env loader — process env wins over file values."""
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8-sig") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)
    except OSError:
        pass


def reviewer_names():
    names = [n.strip() for n in os.environ.get("CLAUDEX_REVIEWERS", "").split(",") if n.strip()]
    if names:
        return names
    # No explicit order: derive from any configured profile blocks.
    found = set()
    for key in os.environ:
        m = re.match(r"CLAUDEX_REVIEWER_([A-Z0-9_]+)_BASE_URL$", key)
        if m:
            found.add(m.group(1).lower())
    return sorted(found)


def profile(name):
    prefix = "CLAUDEX_REVIEWER_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper() + "_"

    def get(suffix, default=None):
        return os.environ.get(prefix + suffix, default)

    base_url = get("BASE_URL")
    model = get("MODEL")
    if not base_url or not model:
        raise SystemExit(
            f"Reviewer '{name}' is not configured: set {prefix}BASE_URL and "
            f"{prefix}MODEL (env or .env). See .env.example.")
    api_key = get("API_KEY")
    key_env = get("API_KEY_ENV")
    if api_key:
        # Was a warning until 2026-08-28. A warning nobody reads is not
        # enforcement, and the key sits in a file the whole time it is ignored.
        raise SystemExit(
            f"Reviewer '{name}': {prefix}API_KEY holds the key inline. Use "
            f"{prefix}API_KEY_ENV=<VARNAME> instead and let your secret manager "
            "inject that variable, so the key never sits in a file.")
    if not api_key and key_env:
        api_key = os.environ.get(key_env)
        if not api_key:
            raise SystemExit(
                f"Reviewer '{name}': {prefix}API_KEY_ENV points at '{key_env}' "
                "but that variable is empty. Refusing to call without the key.")
    base_url = base_url.rstrip("/")
    try:
        check_egress(base_url)
    except (EgressDenied, AllowlistUnreadable) as exc:
        raise SystemExit(f"Reviewer '{name}': {exc}") from exc

    def num(suffix, default, cast):
        raw = get(suffix, default)
        try:
            return cast(raw)
        except (TypeError, ValueError):
            raise SystemExit(
                f"Reviewer '{name}': {prefix}{suffix}='{raw}' is not a number.") from None

    return {
        "name": name,
        "base_url": base_url,
        "model": model,
        "api_key": api_key,
        "temperature": num("TEMPERATURE", "0.7", float),
        "max_tokens": num("MAX_TOKENS", "8192", int),
        "timeout": num("TIMEOUT", "1800", int),
        # Opt-in, local endpoints only: ask the runtime to load the model first.
        "autoload": (get("AUTOLOAD", "") or "").strip().lower() in ("1", "true", "yes", "on"),
        "context": num("CONTEXT", "32768", int),
    }


def auth_headers(p):
    headers = {"Content-Type": "application/json"}
    if p["api_key"]:
        headers["Authorization"] = "Bearer " + p["api_key"]
        if "anthropic" in (urlsplit(p["base_url"]).hostname or ""):
            # Anthropic also accepts its native header form; sending both is
            # harmless on the compatibility endpoint and required on native ones.
            headers["x-api-key"] = p["api_key"]
            headers["anthropic-version"] = "2023-06-01"
    return headers


# Hosts where plain http is harmless because the traffic never leaves the
# machine. `host.docker.internal` belongs here: Docker Desktop maps it to the
# host of the same box.
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "host.docker.internal"})

EGRESS_ALLOW_ENV = "CLAUDEX_EGRESS_ALLOW"
EGRESS_FILE_ENV = "CLAUDEX_EGRESS_ALLOWLIST"

# Looked for from the repo root when no file is named explicitly. Its mere
# presence is the opt-in: a repo that ships this file means the rule.
DEFAULT_ALLOWLIST_RELATIVE = os.path.join("config", "allowed_egress.yaml")


class EgressDenied(Exception):
    """The destination is not allowed to receive the plan."""


class AllowlistUnreadable(Exception):
    """The allowlist was asked for but cannot be read.

    Deliberately distinct from EgressDenied and deliberately fatal: "I cannot
    tell whether this is allowed" must not degrade into "go ahead". A missing
    file, broken YAML or a missing parser all land here.
    """


def _repo_root(start=None):
    here = os.path.abspath(start or os.getcwd())
    while True:
        if os.path.exists(os.path.join(here, ".git")):
            return here
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def _allowlist_source():
    """Where the host allowlist comes from: (path, explicit) or (None, False).

    Resolved at call time, not as a default argument — a module-level default
    binds at import and cannot be redirected in a test.
    """
    named = os.environ.get(EGRESS_FILE_ENV, "").strip()
    if named:
        return named, True
    root = _repo_root()
    if root:
        candidate = os.path.join(root, DEFAULT_ALLOWLIST_RELATIVE)
        if os.path.exists(candidate):
            return candidate, False
    return None, False


def _yaml_module():
    """Imported here, not at module scope: the parser is only needed by whoever
    actually keeps a file allowlist. Everyone else stays stdlib-only."""
    try:
        import yaml
    except ImportError as exc:
        raise AllowlistUnreadable(
            "a file allowlist is configured but PyYAML is not installed. Install "
            "it, or drop the file and use " + EGRESS_ALLOW_ENV + " instead. Not "
            "installing it does NOT lift the restriction.") from exc
    return yaml


def load_allowlist(path):
    """Read the allowlist file and return {host: {allowed schemes}}.

    Format (the one already in the wild):

        version: 1
        hosts:
          - host: 127.0.0.1
            schemes: [http, https]
            why: LM Studio, loopback only
    """
    yaml = _yaml_module()
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise AllowlistUnreadable(f"{path} cannot be read: {exc}") from exc
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise AllowlistUnreadable(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("hosts"), list):
        raise AllowlistUnreadable(f"{path}: expected a mapping with a 'hosts' list")

    allowed = {}
    for entry in doc["hosts"]:
        if not isinstance(entry, dict) or not entry.get("host"):
            raise AllowlistUnreadable(f"{path}: entry without 'host': {entry!r}")
        schemes = entry.get("schemes") or ["https"]
        if isinstance(schemes, str):
            schemes = [schemes]
        allowed[str(entry["host"]).lower()] = frozenset(s.lower() for s in schemes)
    if not allowed:
        raise AllowlistUnreadable(f"{path}: no hosts listed")
    return allowed


def check_egress(url):
    """Refuse a destination before anything is sent to it.

    Two rules, and the first one is the reason this exists:

    1. **Plain http only to loopback.** The check this replaced fired only when
       an API key was set — so a keyless endpoint received the plan and the whole
       review log in the clear, to any host. The protected content is the plan,
       not the key. (Found by the audit in a sister repo, 2026-08-28.)
    2. **Exact host match** against CLAUDEX_EGRESS_ALLOW when that is set — a
       comma-separated list of hostnames. No wildcards and no suffix matching:
       `api.openai.com.attacker.test` ends in an allowed name and would otherwise
       slip through. Unset means no host restriction; the scheme rule still holds.

    Raises EgressDenied. Never logs and continues — an allowlist you can ignore
    is not one.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    scheme = (parts.scheme or "").lower()
    if not host or not scheme:
        raise EgressDenied(f"destination has no host or scheme: {url!r}")

    if scheme not in ("http", "https"):
        raise EgressDenied(f"scheme '{scheme}' is not allowed for review traffic.")

    path, explicit = _allowlist_source()
    if path:
        if explicit and not os.path.exists(path):
            raise AllowlistUnreadable(
                f"{EGRESS_FILE_ENV} points at '{path}', which does not exist. "
                "Refusing to send anything rather than treating a missing "
                "allowlist as permission.")
        allowed = load_allowlist(path)
        schemes = allowed.get(host)
        if schemes is None:
            raise EgressDenied(
                f"host '{host}' is not in the egress allowlist {path}. Add it "
                "deliberately, with a reason — that is the question the review "
                "will ask anyway.")
        if scheme not in schemes:
            raise EgressDenied(
                f"scheme '{scheme}' is not allowed for host '{host}' in {path} "
                f"(allowed: {', '.join(sorted(schemes))}).")
    else:
        raw_allow = os.environ.get(EGRESS_ALLOW_ENV, "").strip()
        if raw_allow:
            names = {h.strip().lower() for h in raw_allow.split(",") if h.strip()}
            if host not in names:
                raise EgressDenied(
                    f"host '{host}' is not in {EGRESS_ALLOW_ENV} "
                    f"({', '.join(sorted(names))}). Add it deliberately, or unset "
                    "the variable to drop the host restriction.")

    # The floor, checked last so a more specific message wins: cleartext never
    # leaves the machine, no matter what any allowlist says.
    if scheme == "http" and host not in LOOPBACK_HOSTS:
        raise EgressDenied(
            f"refusing plain http to the non-loopback host '{host}'. The plan and "
            f"the review log would travel in the clear, whether or not a key goes "
            f"with them. Use https.")


def is_local(p):
    host = urlsplit(p["base_url"]).hostname or ""
    return host in LOOPBACK_HOSTS


def http_get_json(url, headers, timeout=15):
    check_egress(url)  # every request, not just the one the profile declared
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def ensure_model_loaded(p):
    """Have the local runtime load this profile's model, if the profile asked.

    Returns (ok, detail). A no-op — (True, "") — unless ALL of these hold: the
    profile sets AUTOLOAD, the endpoint is local, and `lms` is on PATH. The
    adapter is generic and must not assume LM Studio is what is listening.

    Why it exists at all: preflight probes GET /models, and LM Studio lists the
    models it has DOWNLOADED, not the one it has LOADED. So the check goes green
    and the run fails afterwards. This was the one thing the LM-Studio-specific
    predecessor did better than the generic adapter; here it is, as an option.
    """
    if not p.get("autoload") or not is_local(p):
        return True, ""
    if not shutil.which("lms"):
        return False, ("AUTOLOAD is set but the `lms` CLI is not on PATH — cannot "
                       "load the model. Load it in LM Studio, or unset AUTOLOAD.")

    model, context = p["model"], p["context"]
    root = p["base_url"].rsplit("/v1", 1)[0]
    try:
        data = http_get_json(root + "/api/v0/models", {})
        for entry in data.get("data", []):
            if entry.get("id") != model or entry.get("state") != "loaded":
                continue
            if (entry.get("loaded_context_length") or 0) >= context:
                return True, f"{model} already loaded"
            # Loaded, but too small a window for a plan plus the log so far.
            subprocess.run(["lms", "unload", model], capture_output=True)
            break
    except (EgressDenied, AllowlistUnreadable):
        raise
    except (urllib.error.URLError, OSError, ValueError):
        pass  # no /api/v0 here; let the load attempt below be the verdict

    result = subprocess.run(
        ["lms", "load", model, "--context-length", str(context), "--yes"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:300]
        return False, f"`lms load {model}` failed: {detail}"
    return True, f"{model} loaded (context {context})"


def preflight(p):
    """Cheap availability probe BEFORE burning a review round.

    Returns (ok, detail). Local endpoints: reachability only. Remote: auth
    probe via GET /models; OpenRouter additionally reports remaining credits
    (the only listed provider with a balance API — elsewhere exhaustion only
    shows on use, as 429/402, which the caller handles).
    """
    headers = auth_headers(p)
    host = urlsplit(p["base_url"]).hostname or ""

    loaded, detail = ensure_model_loaded(p)
    if not loaded:
        return False, detail

    try:
        http_get_json(p["base_url"] + "/models", headers)
    except (EgressDenied, AllowlistUnreadable) as exc:
        # Should not fire — profile() already vetted base_url — but a probe URL
        # that the allowlist rejects is a refusal, not an outage. Say which.
        return False, f"egress refused ({exc})"
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return False, f"auth rejected (HTTP {exc.code})"
        if exc.code in (402, 429):
            return False, f"quota/payment exhausted (HTTP {exc.code})"
        # Other codes (404/405 …): some compat layers don't expose /models —
        # reachable is good enough.
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"unreachable ({getattr(exc, 'reason', exc)})"

    if is_local(p):
        return True, "local endpoint (no credit check needed, nothing leaves the machine)"

    if "openrouter" in host:
        try:
            data = http_get_json(p["base_url"] + "/credits", headers).get("data", {})
            remaining = float(data.get("total_credits", 0)) - float(data.get("total_usage", 0))
            if remaining <= 0:
                return False, f"no credits left (remaining {remaining:.2f} USD)"
            return True, f"credits remaining: {remaining:.2f} USD"
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            return True, "reachable; credit lookup failed (proceeding, 402/429 on use is terminal)"

    return True, "reachable + auth ok (no balance API — exhaustion only shows on use)"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path):
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def strip_thinking(text):
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def count_findings(text):
    """Count numbered findings (lines starting '1.' / '2)' etc.).

    Every numbered line counts: multi-section reports restart numbering per
    section, and de-duplicating by number would under-count them. The value
    only feeds the rubber-stamp lower bound, so over-counting is harmless.
    """
    return len(re.findall(r"^\s*\d{1,2}[.)]\s+\S", text, flags=re.M))


class ProviderError(Exception):
    """Transport/HTTP failure. terminal=True means: don't retry THIS provider."""

    def __init__(self, message, terminal=False):
        super().__init__(message)
        self.terminal = terminal


def run_review(p, args, plan_hash, user_content):
    """One review call against one provider. Returns (exit_code, verdict_line).

    Raises ProviderError on transport/HTTP failure so a chain can move on.
    """
    system_prompt = read_text(args.system_file) if args.system_file else SYSTEM_PROMPT
    payload = json.dumps({
        "model": p["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": p["temperature"],
        "max_tokens": p["max_tokens"],
        "stream": False,
    }).encode("utf-8")

    chat_url = p["base_url"] + "/chat/completions"
    check_egress(chat_url)  # the request that actually carries the plan
    req = urllib.request.Request(chat_url, data=payload, headers=auth_headers(p))
    try:
        with urllib.request.urlopen(req, timeout=p["timeout"]) as resp:
            body = json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        # Quota/auth errors are terminal for this provider; 5xx may be transient.
        terminal = exc.code in (401, 402, 403, 404, 429)
        raise ProviderError(f"HTTP {exc.code} from {p['base_url']} — {detail}",
                            terminal=terminal) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ProviderError(f"endpoint unreachable or bad reply ({exc})",
                            terminal=False) from exc

    try:
        msg = body["choices"][0]["message"]
    except (KeyError, IndexError):
        raise ProviderError(f"unexpected response shape: {json.dumps(body)[:300]}",
                            terminal=True) from None
    critique = strip_thinking(msg.get("content") or "")
    if not critique and msg.get("reasoning_content"):
        critique = strip_thinking(msg["reasoning_content"])
    finish = body["choices"][0].get("finish_reason")
    if finish == "length":
        # Seen in practice: a dense local model re-listed the inlined diff with
        # line numbers and ran out of output budget before any verdict line.
        print(f"WARNING: {p['name']} hit max_tokens ({p['max_tokens']}) — the reply "
              "is truncated. Raise CLAUDEX_REVIEWER_<NAME>_MAX_TOKENS, shorten the "
              "input, or pick a model that doesn't echo the material; the verdict "
              "check below will (correctly) reject this round.")

    # Validate FIRST, write SECOND — the output file carries the verdict status
    # in its header, so a reader who ignores the exit code cannot mistake an
    # invalid review for a recorded round.
    code, status = validate(critique, args, p)
    header = (f"# Reviewer: {p['model']} via {p['name']} (fallback — not the primary reviewer)\n"
              f"# Round: {args.round_no} | Plan SHA256: {plan_hash}\n"
              f"# Status: {status}\n\n")
    output = header + critique + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(output)
        print(f"Review written: {args.out}")
    else:
        print(output)
    print(f"{status} | findings: {count_findings(critique)} | plan-sha256: {plan_hash} "
          f"| reviewer: {p['name']}")
    if args.append_log:
        label = "fallback" if code == 0 else "fallback — INVALID ATTEMPT, does not count as a round"
        entry = (f"\n## Round {args.round_no} — {p['model']} (via {p['name']}, {label})\n\n"
                 f"_Status: {status} · plan SHA256 {plan_hash}_\n\n{critique}\n")
        with open(args.append_log, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(entry)
        print(f"Round appended to {args.append_log}")
    return code


def validate(critique, args, p):
    """Apply the verdict grammar and the rubber-stamp gate.

    Returns (exit_code, status_line): 0 with the verdict summary, or 3 with an
    'INVALID: …' reason. Markdown decoration around a verdict line is
    tolerated (**VERDICT: X**, etc.); if a verdict appears several times, the
    LAST occurrence counts.
    """
    DECOR = r"[\s*_`>#-]*"

    def last_verdict(name, values):
        rx = rf"^{DECOR}{re.escape(name)}:\s*({'|'.join(map(re.escape, values))})[\s*_`.!]*$"
        found = re.findall(rx, critique, flags=re.MULTILINE | re.IGNORECASE)
        return found[-1].upper() if found else None

    findings = count_findings(critique)
    if args.require_verdicts:
        # Custom grammar: every named verdict must appear; first value = pass.
        results, missing, all_pass = [], [], True
        for entry in args.require_verdicts.split(","):
            name, _, vals = entry.strip().partition(":")
            values = [v.strip() for v in vals.split("|") if v.strip()]
            got = last_verdict(name.strip(), values)
            if got is None:
                missing.append(name.strip())
                continue
            results.append(f"{name.strip().upper()}: {got}")
            if got != values[0].upper():
                all_pass = False
        if missing:
            return 3, (f"INVALID: missing verdict line(s) {missing} — "
                       "do not record this as a round")
        if args.round_no == 1 and all_pass and findings < args.min_findings:
            return 3, (f"INVALID: rubber-stamp suspicion — all verdicts passing in "
                       f"round 1 with only {findings} finding(s) (< {args.min_findings})")
        return 0, " | ".join(results)

    verdict = last_verdict("VERDICT", ["APPROVED", "REVISE"])
    if verdict is None:
        return 3, ("INVALID: no VERDICT line at the end of the reply — "
                   "do not record this as a round")
    if args.round_no == 1 and verdict == "APPROVED" and findings < args.min_findings:
        return 3, (f"INVALID: rubber-stamp suspicion — APPROVED in round 1 with only "
                   f"{findings} finding(s) (< {args.min_findings}); check the "
                   "model/prompt, or skip the review and log the plan as not cross-reviewed")
    return 0, f"VERDICT: {verdict}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--plan", help="plan file (inlined into the prompt)")
    ap.add_argument("--log", help="review log so far (inlined; replaces the "
                                  "resumed-session memory the primary reviewer had)")
    ap.add_argument("--reviewer", help="profile name (default: first of CLAUDEX_REVIEWERS)")
    ap.add_argument("--chain", action="store_true",
                    help="walk CLAUDEX_REVIEWERS in order: preflight each, use the "
                         "first viable one, move on when a provider is out of "
                         "quota/credits — every skip is reported")
    ap.add_argument("--round", type=int, default=1, dest="round_no")
    ap.add_argument("--out", help="write the critique here (default: stdout)")
    ap.add_argument("--append-log",
                    help="append this round to the review log (e.g. PLAN-REVIEW-LOG.md) "
                         "as '## Round <n> — <model> (via <reviewer>, fallback)' with the "
                         "status line and the full critique — INVALID attempts are "
                         "appended too, labeled as not counting. Findings never live "
                         "only in a chat transcript.")
    ap.add_argument("--system-file",
                    help="file whose content replaces the built-in plan-review "
                         "system prompt — lets other gates (e.g. codex-verify) "
                         "reuse the transport/preflight/chain with their own prompt")
    ap.add_argument("--require-verdicts",
                    help="comma-list NAME:PASSVAL|OTHERVAL[|...] replacing the "
                         "default 'VERDICT: APPROVED|REVISE' grammar, e.g. "
                         "'DOD:COMPLETE|INCOMPLETE,QUALITY:ACCEPTABLE|REVISE,"
                         "SECURITY:PASS|FAIL'. Every named verdict line must "
                         "appear or the review is invalid (exit 3); the FIRST "
                         "value of each entry counts as its passing value for "
                         "the rubber-stamp gate")
    ap.add_argument("--min-findings", type=int,
                    default=int(os.environ.get("CLAUDEX_FALLBACK_MIN_FINDINGS", "3")),
                    help="round 1: an APPROVED with fewer numbered findings is "
                         "treated as a rubber stamp (exit 3)")
    ap.add_argument("--list", action="store_true", help="list configured reviewers and exit")
    ap.add_argument("--check", action="store_true",
                    help="preflight all configured reviewers (reachability/auth/"
                         "credits where the provider exposes them) and exit")
    args = ap.parse_args()

    load_dotenv()

    if args.list or args.check:
        names = reviewer_names()
        if not names:
            print("No reviewers configured (CLAUDEX_REVIEWERS / CLAUDEX_REVIEWER_*_BASE_URL).")
            return 2
        worst = 0
        for n in names:
            try:
                p = profile(n)
            except SystemExit as exc:
                print(f"{n}: INCOMPLETE — {exc}")
                worst = 2
                continue
            key = "key set" if p["api_key"] else "no key (local endpoint?)"
            line = f"{n}: {p['model']} @ {p['base_url']} [{key}]"
            if args.check:
                ok, detail = preflight(p)
                line += f" -> {'OK' if ok else 'UNAVAILABLE'}: {detail}"
                if not ok:
                    worst = max(worst, 1)
            print(line)
        return worst if args.check else 0

    if not args.plan:
        ap.error("--plan is required (unless --list/--check)")

    names = reviewer_names()
    if args.chain:
        candidates = names
    else:
        name = args.reviewer or (names[0] if names else None)
        candidates = [name] if name else []
    if not candidates:
        print("ERROR: No fallback reviewer configured. Set CLAUDEX_REVIEWERS and a "
              "CLAUDEX_REVIEWER_<NAME>_* profile (see .env.example).")
        return 2

    plan_hash = sha256_file(args.plan)
    user_parts = []
    if args.log:
        user_parts.append(
            "Review history so far (earlier findings and the planner's "
            "responses — check whether they are addressed, and find what is "
            "new):\n=== BEGIN LOG ===\n" + read_text(args.log) + "\n=== END LOG ===\n")
    user_parts.append(
        f"Review round {args.round_no}. The plan under review "
        f"(SHA256 {plan_hash[:16]}):\n=== BEGIN PLAN ===\n"
        + read_text(args.plan) + "\n=== END PLAN ===")
    user_content = "\n".join(user_parts)

    for name in candidates:
        try:
            p = profile(name)
        except SystemExit as exc:
            if not args.chain:
                print(f"ERROR: {exc}")
                return 2  # config error — keep the documented exit-code contract
            print(f"CHAIN: skipping '{name}' — {exc}")
            continue

        ok, detail = preflight(p)
        if not ok and args.chain and detail.startswith("unreachable"):
            # Transient network stumble gets one retry before the chain moves on.
            print(f"CHAIN: preflight {name}: {detail} — retrying once ...")
            ok, detail = preflight(p)
        print(f"{'CHAIN: ' if args.chain else ''}preflight {name}: "
              f"{'OK' if ok else 'UNAVAILABLE'} — {detail}")
        if not ok:
            if not args.chain:
                print("ERROR: reviewer unavailable — pick another (--reviewer/--chain) "
                      "or wait/skip per FALLBACK.md.")
                return 2
            continue

        attempts = 2  # one retry for transient failures on this provider
        while attempts:
            attempts -= 1
            try:
                return run_review(p, args, plan_hash, user_content)
            except ProviderError as exc:
                kind = "terminal" if exc.terminal else "transient"
                print(f"{'CHAIN: ' if args.chain else 'ERROR: '}{name}: {exc} [{kind}]")
                if exc.terminal:
                    break
                if attempts:
                    print(f"{'CHAIN: ' if args.chain else ''}retrying {name} once ...")
        if not args.chain:
            return 2
        print(f"CHAIN: '{name}' failed — moving to the next configured reviewer.")

    if args.chain:
        print("ERROR: every configured reviewer failed preflight or errored. "
              "Remaining options per FALLBACK.md: wait for the Codex reset, or "
              "skip the review with an explicit log entry.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
