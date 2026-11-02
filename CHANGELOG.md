# Changelog

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

The package version identifies this release; the independently versioned copied
Codex review wrapper is unchanged by B2.
