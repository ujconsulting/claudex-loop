# Codex 0.149.1 blind run (measured 2026-09-16)

The first real blind run: no `[windows] sandbox` in the config, every command refused
(openai/codex#42172). Command text and answer are removed; event types, order, and the
stderr refusal format are unchanged. The stream has no `command_execution` at all -- the
refusals exist only in stderr.
