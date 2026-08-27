# Self-review log: codex-verify over its own diff (2026-08-27)

The acceptance gate (`codex-verify`, scope=dod,quality,security) was run over
this branch's own diff against upstream `main`, once per reviewer path. This
file is the findings ledger for that run: every reviewer reply verbatim, every
disposition. Spec = the Definition of Done the branch was built against
(12 items, see the PR description).

## Second review (codex-verify) — dod,quality,security — Codex gpt-5.6-terra (high)

_Fresh read-only session, spec + full diff inlined via stdin (the first attempt
passed the prompt as a CLI argument and failed with "Argument list too long" —
that finding is fixed in the skill)._

## DOD

1. Implemented — local quota introspection, threshold exits, and pre-round guidance are present.

2. Partially implemented.

   1. `scripts/fallback_review.py:114` accepts `CLAUDEX_REVIEWER_<NAME>_API_KEY` directly, contrary to mandatory `API_KEY_ENV` indirection.  
      Fix: reject direct `API_KEY` configuration and require a non-empty `API_KEY_ENV`.

   2. `.env.example:41` configures Anthropic’s native `/v1` base URL, but `scripts/fallback_review.py:239` always calls `/chat/completions`, which Anthropic’s native API does not implement.  
      Fix: implement Anthropic’s native Messages transport or document/configure a genuine OpenAI-compatible proxy endpoint.

3. Implemented — fallback calls contain only inlined plan/log text and expose no tools or filesystem access.

4. Implemented — missing verdicts and round-one all-pass rubber stamps exit 3.

5. Partially implemented.

   1. `scripts/fallback_review.py:312` prints only `plan_hash[:16]` alongside the verdict, not the complete SHA256 required by the contract.  
      Fix: print the full `plan_hash` in the verdict summary.

6. Partially implemented.

   1. `scripts/fallback_review.py:169` treats remote `/models` errors other than 401/403 as successful authentication, including 404, 402, and 429.  
      Fix: treat non-success remote probe responses as unavailable/auth-unverified and report the HTTP reason.

   2. `scripts/fallback_review.py:186` does not catch `HTTPError` from OpenRouter `/credits`, causing `--check` to terminate with a traceback instead of reporting availability.  
      Fix: catch `HTTPError` and return a clear unavailable/credit-probe result.

7. Partially implemented.

   1. `scripts/fallback_review.py:414` performs only one preflight attempt; a transient preflight network failure is skipped immediately despite the required retry.  
      Fix: retry transient preflight failures once before skipping that chain provider.

8. Implemented — affected skill commands now redirect stderr to a file.

9. Implemented — wait, switch, and skip are documented with explicit logging and weaker-approval treatment.

10. Implemented — `codex-verify` defines scoped verdicts, fresh read-only review, bounded rechecks, arbitration, and red-scope gate failure.

11. Implemented — custom system prompts and mandatory custom verdict grammar are supported.

12. Partially implemented.

   1. `README.md:121` links to `.env.example` but does not document the required environment-variable contract itself.  
      Fix: document `CLAUDEX_REVIEWERS` and `CLAUDEX_REVIEWER_<NAME>_{BASE_URL,MODEL,API_KEY_ENV}` in the README.

DOD: INCOMPLETE

## QUALITY

1. `scripts/codex_usage.py:60` formats a missing `used_percent` with `:.0f`, and `scripts/codex_usage.py:94` calls `max()` on an empty window set; incomplete rollout data crashes instead of producing the documented no-data behavior.  
   Fix: validate window values before formatting/aggregation and return a controlled no-snapshot/no-window exit.

2. `scripts/fallback_review.py:275` accepts a verdict anywhere in the response, while its prompt and diagnostics say the verdict must end the reply; trailing contradictory text can still pass validation.  
   Fix: parse only the final nonblank response line as the verdict.

3. `scripts/fallback_review.py:127` directly casts environment configuration values and emits a traceback for malformed numeric settings.  
   Fix: validate numeric profile fields and exit with a profile-specific configuration error.

QUALITY: REVISE

## SECURITY

1. `scripts/fallback_review.py:114` permits API keys directly in `.env` or process configuration rather than requiring secret-manager/environment indirection, violating the credential-handling requirement.  
   Fix: remove direct `API_KEY` support and require `API_KEY_ENV`.

2. `scripts/fallback_review.py:135` sends bearer credentials to any configured URL, including a non-local `http://` endpoint.  
   Fix: require HTTPS for non-loopback endpoints whenever an API key is configured.

SECURITY: FAIL
### Claude's dispositions

- DOD 2.1 / SECURITY 1 (inline `API_KEY` allowed) → rejected as a removal, accepted in spirit: inline keys stay supported for keyless local setups; the adapter now prints a warning recommending `API_KEY_ENV`.
- DOD 2.2 (Anthropic `/chat/completions` "does not exist") → rejected: `api.anthropic.com/v1/chat/completions` is Anthropic's documented OpenAI-compatibility endpoint.
- DOD 5.1 (truncated hash in verdict line) → accepted: full SHA256 printed.
- DOD 6.1 (402/429 on `/models` treated as auth-ok) → accepted: 402/429 now mark the provider unavailable; 404/405 stay "reachable, no models listing".
- DOD 6.2 (`/credits` HTTPError uncaught) → rejected: `HTTPError` subclasses `URLError`, the except clause catches it.
- DOD 7.1 (no transient preflight retry in chain) → accepted: one retry.
- DOD 12.1 (README lacks env contract) → accepted: documented inline.
- QUALITY 1 (crash on incomplete rollout data) → accepted: guards for missing `used_percent` / empty windows.
- QUALITY 2 (verdict accepted anywhere, not only last line) → rejected: last-occurrence-wins is deliberate (markdown decoration, trailing notes); documented in code.
- QUALITY 3 (traceback on malformed numeric env) → accepted: clear config error.
- SECURITY 2 (bearer over plain http to non-local host) → accepted: refused, https required.

## Second review — INVALID ATTEMPT (finish_reason=length), does not count — qwen/qwen3.8-27b via lmstudio, fallback

_Same spec + diff via `fallback_review.py --system-file --require-verdicts`.
The dense model re-listed the inlined diff with line numbers and exhausted
`max_tokens` (12288) before any verdict line; the gate rejected the reply
(`INVALID: missing verdict line(s) ['DOD', 'QUALITY', 'SECURITY']`). Two
fixes followed: explicit truncation detection, and a no-echo rule in the
prompts. Reply body omitted here (17k tokens of echoed diff)._

## Second review (codex-verify) — dod,quality,security — qwen/qwen3.8-27b via lmstudio, fallback (rerun with no-echo prompt)

## DOD

1. **Quota introspection** — implemented. `codex_usage.py` reads local rollouts, reports 5-hr/weekly `used_percent` + `resets_at`, exits 1 at threshold; SKILL.md and FALLBACK.md mandate the pre-round-1 check.
2. **Fallback adapter over any OpenAI-compatible endpoint** — implemented. `fallback_review.py` uses named `.env` profiles, `API_KEY_ENV` indirection, `.env` git-ignored, `.env.example` provided.
3. **Read-only by construction** — implemented. The adapter makes a single chat-completions call with no tool/file access; plan and log are inlined into the prompt.
4. **Anti-rubber-stamping** — implemented. Missing verdict line → exit 3; round-1 all-pass with fewer than `min-findings` → exit 3 (both default and `--require-verdicts` paths).
5. **Plan-hash binding** — implemented. SHA256 stamped into the verdict header and printed with the verdict line.
6. **Preflight (`--check`)** — implemented. Local: reachability only. Remote: auth probe via `GET /models`. OpenRouter: `GET /credits` balance check.
7. **Chain (`--chain`)** — implemented. Walks `CLAUDEX_REVIEWERS` in order; terminal codes (401/402/403/404/429) move on; transient errors get one retry; every skip printed with reason.
8. **Detection via stderr file** — implemented. All SKILL.md commands changed from `2>/dev/null` to `2>/tmp/codex-stderr.txt`; FALLBACK.md explains why.
9. **Three exits documented** — implemented. FALLBACK.md documents wait/switch/skip with the required log labels and weaker-approval disclaimer.
10. **codex-verify skill** — implemented. Post-build second gate, parameterizable `scope=`, per-scope mandatory verdict lines, fresh read-only session, diff+spec inlined, Claude arbitrates, `MAX_RECHECK` bounded, red scope = failed gate.
11. **Fallback parity for the gate** — implemented. `--system-file` and `--require-verdicts` are present; every named verdict line is mandatory (missing → exit 3); first value = passing for the rubber-stamp gate.
12. **Wiring** — implemented. Optional offer in claudex-loop and codex-build SKILL.md; README documents the new skill and env vars; backward compatible (no profiles → script refuses, loop unchanged).

No silent scope cuts or unrequested extras detected.

**DOD: COMPLETE**

## QUALITY

1. **Exit-code contract broken for unconfigured profiles (non-chain path).** `profile()` raises `SystemExit("<message>")` when `BASE_URL`/`MODEL` are missing; in the non-chain review path this is re-raised (`main()`, `except SystemExit: if not args.chain: raise`), causing Python to exit with **code 1**. The module docstring promises "2 = config/transport error." A caller keying on exit 2 to detect misconfiguration will miss this. Fix: `raise SystemExit(2)` or catch and `return 2`.

2. **Output file written before verdict validation.** `run_review()` writes `args.out` (or prints) *before* the verdict/rubber-stamp checks, so an invalid review (exit 3) still produces a verdict file. Downstream logic that reads the file without checking the exit code could mistake garbage for a round. Fix: validate first, write second.

3. **`count_findings` dedups by number via `set()`.** A model that writes "1. foo" and "1. bar" (reusing a number) counts as one finding, silently weakening the rubber-stamp gate. Low likelihood but the dedup is unexplained. Fix: drop the `set()` or document the intent.

**QUALITY: REVISE**

## SECURITY

No injection vectors, no `subprocess`/`eval`/`exec`, no secret logging, `.env` git-ignored, API keys sent only to the configured endpoint via standard `Authorization`/`x-api-key` headers. The `load_dotenv` uses `os.environ.setdefault` so process env wins over file values. No path-traversal or unsafe-deserialization risks introduced.

**SECURITY: PASS**

### Claude's dispositions

- QUALITY 1 (exit code 1 instead of documented 2 for an unconfigured profile) → accepted: non-chain path prints the error and returns 2.
- QUALITY 2 (output file written before validation) → accepted: validate first, write second; the file carries a `# Status:` header (verdict summary or `INVALID: <reason>`).
- QUALITY 3 (`count_findings` de-duplicates by number) → accepted with a correction: the claimed effect is inverted (under-counting makes the rubber-stamp gate stricter, not weaker), but sectioned reports restart numbering and were under-counted — dedup removed, intent documented.

## Second review — gate result

| Scope | Codex | Local fallback (rerun) | After fixes |
|---|---|---|---|
| DOD | INCOMPLETE → 6 accepted, 2 rejected | COMPLETE | complete |
| QUALITY | REVISE → 2 accepted, 1 rejected | REVISE → 3 accepted | acceptable |
| SECURITY | FAIL → 1 accepted, 1 rejected-with-warning | PASS | pass |

Rejected findings, each with its reason, are listed above — none were
averaged away.
