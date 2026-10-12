# Codex 0.162.1 event streams (measured 2026-10-12)

Raw `codex exec --json` output and stderr from raising the wrapper to codex-cli 0.162.1 and the
default model to `gpt-6.1-sol` (wrapper 2.6.1, `docs/betrieb.md` section 8). User and repository
paths are replaced by `<USERPROFILE-PATH>` / `<REPO-PATH>`, command outputs are cut to their last
line; event types, fields, order, `status` and `exit_code` are unchanged.

| File | Run |
|---|---|
| `blind-run.*` | plain `codex exec`, `gpt-6.1-sol/medium`, own `CODEX_HOME` without `[windows]` (openai/codex#42172): the command is refused; the refusal (`rejected: blocked by policy`) is only in stderr, the stream has no `command_execution` |
| `normal-run.stream.json` | wrapper 2.6.0 + `gpt-6.1-sol/medium`: one read (`completed`, `exit_code` 0), one write attempt (`failed`, `exit_code` 1, access denied) |
