# Blind runs where commands ran but all failed (measured 2026-11-02)

Three real plan-review runs (codex-cli 0.162.1, `gpt-6.1-sol/medium`, wrapper 2.6.1, Hyper-V VM)
in which Codex did not read a single file and still answered with a verdict. The wrapper ended
with **exit 0**; 2.7.0 does not catch them either. Exit 3 requires a last turn without any
`command_execution`; here commands *did* execute and every one failed. See `docs/betrieb.md`
section 2b.

Paths are anonymised (`C:\Users\user`, `C:\scratch`, `repo`, `\\fileserver`) and thread IDs are
zeroed; event types, fields, order, `status` and `exit_code` are unchanged.

| Files | Cause | per command |
|---|---|---|
| `pwsh-alias-S.*` | Codex starts the Store alias `%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe`, which the restricted token cannot launch; repo on a network drive | `exit_code` -1, stderr `CreateProcessAsUserW failed: 5` |
| `pwsh-alias-C.*` | same alias, repo cloned to a local disk (rules out the drive as the cause) | `exit_code` -1, same stderr |
| `network-share.*` | pwsh 7 as MSI (starts fine), repo on the network drive `S:\` | `exit_code` 1, output "Zugriff verweigert" (access denied); stderr has no refusal line |

Each set: `*.answer.md` (the answer file; it states itself that the review was blocked and ends
with `VERDICT: CHANGES_REQUESTED`), `*.stream.json` (`codex exec --json`), `*.stderr.txt`.

Expected behaviour of a fix: all three end in exit 3 (no usable review); a run with at least one
`command_execution` of `exit_code` 0 (e.g. `../normal-run.stream.json`) does not.
