# Changelog

## 2.8.1 — 2026-11-02

- Wrapper 2.7.1: a review round in which commands were attempted but none succeeded is
  blind (exit 3) when a command failed to start or was denied access (`exit_code -1`,
  `CreateProcessAsUserW failed`, `Access to the path … is denied`, …), when stderr carries a
  Codex router execution-error record, or when the evidence is incomplete. Rounds whose
  commands only failed in an ordinary way stay valid with a warning. Rounds without any
  command keep the 2.7.0 rule, plus one addition: a router record of a start failure or
  denial (`CreateProcessAsUserW`) in stderr now invalidates them too. Measured on a Windows VM: four plan reviews (Store alias of pwsh;
  repository on a network share) had ended with exit 0 and a verdict without reading a file.
- `scripts/review_mirror.py` (from the VM, merged): review from a local copy of the review
  scope when the repository sits on a network share; `docs/betrieb.md` section 2b.
- Fixtures of the three real runs under `tests/fixtures/codex-0.162/blind-failed-commands/`
  (a leaked local path anonymised); `tests/test_codex_ro_blind_denied.py` drives them through
  `blind_run` and `main()`, every new condition with a mutation witness.

## 2.8.0 — 2026-11-02

- Add the B2 container build runner, isolated network probe and per-run TLS token
  proxy. Real credentials stay outside the builder; only the fixed model endpoint
  receives injected credentials, with deadline, volume caps and response scanning.
- Keep generated changes in quarantine until paginated review and digest-bound
  publication. Detect conflicts, preserve permissions and report exact recovery
  commands after partial publication. Deleted entries use null content metadata;
  the publication limit agrees with the policy's 200 MiB cap.
- Run every fix round in fresh containers on the reviewed Git tree. Update the
  build skill, Windows/macOS/Linux contracts, mirrored READMEs and runbook.
- Pin the container test dependency cryptography to 50.0.2 and add the Codex build
  image. Retain the no-PyYAML test lane. Terminate Git for Windows child processes
  when the snapshot deadline expires.
- Documentation: both READMEs gain the table of what this fork adds to upstream and
  one flow diagram per part; a beginner guide in English and German
  (`docs/getting-started.md`, `docs/einstieg.md`) explains the plugin without prior
  knowledge, including how it differs from and works with ujc-security-checker.
  `tests/test_readme_sync.py` holds the guides to each other and to this repository's
  install command.

The package version identifies this release; the independently versioned copied
Codex review wrapper is unchanged by B2.
