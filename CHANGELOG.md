# Changelog

## 2.8.2 — 2026-11-02

- Wrapper 2.7.2: the diagnostic for an output another run holds no longer reads the lock with
  `read_text()` (followed symlinks, unbounded, blocked on a FIFO). POSIX: lstat, regular file with
  one link, `O_NOFOLLOW|O_NONBLOCK`, same (dev, ino) via fstat, at most 200 bytes; Windows never
  reads the holder. Lock acquisition, release, order and exit 2 are unchanged.
- `fallback_review.py` (T24): unique exclusive staging file instead of a fixed `.claudex-part`;
  locks `<out>.claudex-lock` and `<append-log>.claudex-lock` from the deletion of `--out` through
  publication and append (exit 2 when held, by another fallback or by the wrapper); refuses
  out == log, reserved suffixes, ambiguous Windows spellings, links, hard-linked outputs and
  unreadable metadata; appends through a handle validated after opening (an absent log is created
  only exclusively, a non-regular log is refused before opening); a failed write or fsync of `--out`
  is `ERROR:` + exit 2 instead of a traceback; same safe lock diagnostic.
- `review_mirror.py` (T26): immutable generations under `%LOCALAPPDATA%\codex-review\<repo>-<hash>`
  instead of `/MIR` into a shared target; one path rule for entries and `!` exclusions (`.git` in any
  spelling, `.env*`/`*.env` except listed templates, cache dirs, Windows aliases, wildcards, links);
  `!` wins over every entry; `?` optional entries; source and destination checked for reparse points;
  robocopy `/XJ` plus a full post-copy validation; receipt (schema 1: file manifest, `entry_types`,
  strictly increasing `created_ns`) written last; `MIRROR=`, `--verify`, `--prune` (keeps the newest
  verified generation by creation order); the repo root itself must not be a link; directory
  exclusions with or without a trailing slash; `--target` and the old source mark removed. Full copy
  per run. Linked generations and a linked `--check` probe are refused; an invalid or duplicate
  `created_ns` stops `--prune`; `--prune` never changes attributes of a hard-linked file; an
  unreadable scope file is exit 2, a missing robocopy or unwritable receipt exit 1, without traceback.
- Tests no longer assume a git checkout of this repo (sandbox runner, T25); `hunt_snapshot` treats a
  Linux zombie as gone and an unreadable `/proc` record as unknown. The full suite passes in the
  sandbox container for the first time.

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
