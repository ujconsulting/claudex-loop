# Codex 0.156.0 event streams (measured 2026-09-30)

Raw `codex exec --json` output and stderr from the J0 measurement of plan
`docs/plans/2026-09-23-codex-heben-wrapper-2.6.0` (git-ignored). User paths are replaced by
`<USERPROFILE-PATH>`, long PowerShell outputs are cut to their last line; event types, fields,
order, `status` and `exit_code` are unchanged.

| File | Run |
|---|---|
| `blind-run.*` | `CODEX_HOME` without `[windows]` (openai/codex#42172): every command refused; the refusal is only in stderr, the stream has no `command_execution` |
| `resume.stream.json` | `exec resume` on a thread that had a command before: no replay, exactly one `turn.started` |
| `normal-run.stream.json` | wrapper 2.5.0 + `gpt-6-sol/medium`: one write attempt (`failed`, `exit_code` 1), one read (`completed`, `exit_code` 0) |
