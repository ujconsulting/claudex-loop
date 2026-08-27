# claudex-loop unter Windows — verifizierte Betriebsanleitung

Gilt für **alle** Projekte, die den claudex-loop nutzen. Der Original-README des Plugins ist
für Linux/macOS geschrieben und an mehreren Stellen für diese Umgebung schlicht falsch; was
hier steht, ist gegen `codex-cli 0.149.1` auf Windows **gemessen**, nicht vermutet.

Bis 27.08.2026 lag diese Datei in `s100-scripte/_todos/plaene/README.md`. Sie gehört nicht in
ein Fachprojekt — projektspezifisch bleiben dort nur Einsatzfälle, Tabu-Scope und Ablage.

> **Namen seit 27.08.2026:** `codex-review` → **`plan-review`** (prüft den Plan, vor dem
> Code), `codex-verify` → **`code-review`** (prüft den fertigen Diff gegen den Plan). Die
> alten Namen waren gegenüber dem Sprachgebrauch vertauscht. Ältere Protokolle und der
> Dogfood-Log unter `docs/self-review/` führen noch die alten Namen.
## ⛔ Abweichungen vom Original-Skill (Windows)

Der Skill ist für Linux/macOS geschrieben. Drei Stellen müssen hier anders laufen —
alle am 26.08.2026 gegen `codex-cli 0.149.1` verifiziert:

**1. Ausgabepfad über `cygpath -w`.** `codex.exe` ist ein Windows-Binary und versteht
Git-Bash-Pfade wie `/tmp/codex-verdict.txt` nicht — es schriebe ins Leere:

```bash
OUT="$(cygpath -w "$TEMP/codex-verdict.txt")"
codex exec -s read-only --json -o "$OUT" "$(cat PROMPT)" < /dev/null 2>"$TEMP/cx-err.txt"
```

**2. stderr in eine Datei, nicht nach `/dev/null`.** Das `2>/dev/null` des Originals
verschluckt Auth-Fehler. Ein abgelaufener Token liefert exit 0, eine gültige
`thread_id` — und eine **leere Verdict-Datei**. Ohne stderr rätselt man, warum Codex
schweigt. Der 401 stand nur in stderr.

**3. Timeout der Bash-Tool-Aufrufe auf 600000 ms.** Der 2-Minuten-Default reicht für
einen Review nicht. GNU `timeout` liegt in Git Bash unter `/usr/bin/timeout` (8.32),
funktioniert also zusätzlich wie im Skill beschrieben.

Unverändert gültig: `< /dev/null` ist Pflicht (sonst hängt `codex exec` ohne TTY),
`-s read-only` beim ersten Aufruf, `-c sandbox_mode="read-only"` beim `resume` (dort
wird `-s` abgewiesen), **kein** `-m`-Modellpin.

## Zwei Lehren aus dem ersten echten Lauf (26.08.2026)

**1. Codex sieht `PLAN.md` nicht zuverlässig — Plantext inline in den Prompt.** Im ersten
Lauf wurden *alle* Shell-Aufrufe von Codex (`pwsh`, `cmd`) mit `rejected: blocked by policy`
abgewiesen, und die frisch angelegte `PLAN.md` war noch untracked. Ergebnis: Codex hat den
Code-Kontext review't, aber **nicht den Plan** — und sagt das immerhin dazu. Eine ganze
Runde für halbe Arbeit. Deshalb ab sofort:

```bash
{ echo "…Anweisungen…"; echo "=== BEGIN PLAN ==="; cat "$PLAN_FILE"; echo "=== END PLAN ==="; } > prompt.txt
codex exec … "$(cat prompt.txt)"
```

Der Plan gehört **in** den Prompt, nicht als Pfadverweis. Repo-Dateien liest Codex weiterhin
selbst — nur auf die eigene, oft untrackte Plandatei ist kein Verlass.

**2. `sol` reisst das 10-Minuten-Ceiling — `terra` nehmen.** Die Empfehlung „`gpt-5.6-sol`
für die Angriffsrunde" weiter unten galt einem 8-Sekunden-Smoketest, nicht einem echten
Review. An einem 120-Zeilen-Plan mit Repo-Kontext lief `sol`/high in den Timeout (exit 143),
die Verdict-Datei kam erst auf der Ziellinie. `gpt-5.6-terra` mit
`model_reasoning_effort="high"` lieferte dieselbe Schärfe in **1–2 Minuten je Runde** —
Runden 2 bis 5 fanden 9, 5, 5 und 1 echte Fehler, keiner davon war falsch.

**Vorgabe: `-m gpt-5.6-terra -c model_reasoning_effort="high"`.** `sol` nur, wenn `terra`
an einer Frage erkennbar scheitert, und dann mit mehr Zeitbudget.

**Nebenbefund zur Erwartungshaltung:** `MAX_ROUNDS` zu erreichen ist kein Misserfolg. Der
erste Lauf endete formal ohne `APPROVED`, war aber konvergiert (11 → 9 → 5 → 5 → 1 Funde,
ab Runde 2 kein einziger abgelehnt). Aussagekräftiger als das Verdikt ist die **Fundkurve**
plus die Frage, wie viele Funde man begründet zurückweisen konnte.

## Modell und MCP-Server (verifiziert 26.08.2026)

**Modell für die Angriffsrunde pinnen.** Der Original-Skill rät vom `-m`-Pin ab — das
zielte auf die alten `*-codex`-Slugs. Ein Pin funktioniert unter ChatGPT-Auth einwandfrei,
kein HTTP 400.

⛔ **Nimm `terra`, nicht `sol`** — s. „Zwei Lehren" oben: `sol` lief an einem echten Plan in
den 10-Minuten-Timeout. Der 8-Sekunden-Test unten war ein Smoketest, kein Review.

```bash
codex exec -m gpt-5.6-terra -c model_reasoning_effort="high" -s read-only ...
```

Der Default aus `~/.codex/config.toml` ist `gpt-5.6-terra` (medium) — für den Alltag
richtig, aber in der Review-Runde zahlt Denktiefe sich aus. Verfügbar sind
`gpt-5.6-sol` / `-terra` / `-luna` mit Effort bis `ultra`.
⛔ `gpt-5.4` und `gpt-5.4-mini` verschwinden am **31.08.2026** aus Codex.

**MCP-Server pro Aufruf abschalten.** Sie bringen für einen Plan-Review nichts und
kosten Startzeit:

```bash
-c mcp_servers.n8n.enabled=false -c mcp_servers.MCP_DOCKER.enabled=false
```

⛔ `-c mcp_servers="{}"` wirkt **nicht** — getestet, die Server starten trotzdem.
Nur der dotted-path-Weg mit `.enabled=false` je Server greift (danach null
MCP-Fehler in stderr).

**Bekannter Defekt, unabhängig davon:** der n8n-Eintrag in `~/.codex/config.toml`
zeigt auf `http://127.0.0.1:3069/` und wirft bei jedem Lauf HTTP 404. Der richtige
Pfad ist `/mcp` (dort antwortet der Server), aber auch mit dem hinterlegten Token
kommt 401 zurück — Pfad **und** Anmeldung sind kaputt. Gehört zusammen mit dem
Klartext-Bearer-Token in derselben Datei repariert (`codex mcp add
--bearer-token-env-var`, Wert in den Vault).

## Sandbox: was gemessen ist (27.08.2026)

⛔ **Codex wird NICHT per Allowlist freigestellt** — höchstens `Bash(codex --version)`.
Jeder `exec`-Aufruf fragt einmal nach (Review-Loop: ~6 Rückfragen über 5 Runden). Das ist
der Preis dafür, dass sichtbar bleibt, in welcher Sandbox Codex startet.

Die verbreitete Begründung dafür — „ein nachgestelltes `-c sandbox_mode` reißt jede Regel
auf" — ist **nur zur Hälfte richtig**. Gemessen mit `codex-cli 0.149.1`, jeweils Schreibversuch
in ein leeres Verzeichnis, mit Positivkontrolle:

| Aufruf | schreibt? | heißt |
|---|---|---|
| `exec -s read-only` | nein | Basislinie |
| `exec -s read-only -c sandbox_mode="danger-full-access"` | **nein** | **`-s` gewinnt gegen nachgestelltes `-c`** |
| `exec -s danger-full-access` | ja | Positivkontrolle — die Probe erkennt eine offene Sandbox |
| `resume -c sandbox_mode="read-only" -c sandbox_mode="danger-full-access"` | **ja** | **späteres `-c` gewinnt** |

Daraus folgt genauer:

- **`codex exec`**: mit explizitem `-s read-only` ist der Modus nicht mehr aufreißbar. Eine
  Präfix-Regel wäre hier technisch dicht.
- **`codex exec resume`**: kennt kein `-s`. Der Modus hängt allein an `-c`, und das letzte
  gewinnt — hier ist **keine** Präfix-Regel dicht.

Die Regel „nichts freistellen" bleibt trotzdem stehen: sie deckt beide Fälle mit einer
Entscheidung ab, und der `resume`-Fall ist real aushebelbar. Wer die Rückfragen loswerden
will, braucht ein Wrapper-Skript, das `-s read-only` bzw. `-c sandbox_mode="read-only"` hart
setzt und jedes weitere `-c sandbox_mode` **verwirft** — nur das ließe sich sauber freigeben.

⚠️ **Eine breite `Bash(*)`-Freigabe hebelt das alles aus.** Sie erlaubt jeden
Codex-Aufruf samt beliebiger Sandbox — dann ist die Codex-Regel wirkungslos, egal wie eng
sie formuliert ist. Vor dem Berufen auf diese Regel prüfen:
`grep -n 'Bash(\*)' .claude/settings.local.json`.

## Voraussetzungen (Stand 26.08.2026 erfüllt)

| | |
|---|---|
| `codex --version` | 0.149.1 — Skill fordert ≥ 0.130 |
| `codex login status` | `Logged in using ChatGPT` (Abo, **kein** API-Key) |
| PATH | `C:\Users\ujoerk\AppData\Roaming\npm\codex` (npm global, nativ Windows — **kein WSL**) |
| Plugin | `claudex-loop@claudex-loop`, scope **user**, enabled |

Codex liest im Repo-Root automatisch die `AGENTS.md` — dort steht
unter „Rolle: Plan-Reviewer", worauf es prüfen soll. Deshalb **immer aus dem Repo-Root
starten**: nur dieser Pfad steht in `~/.codex/config.toml` als `trust_level = "trusted"`.

## Kontingent-Ausfall: Fallback oder Überspringen statt Dead-End (27.08.2026)

Upstream-Problem ([claudex-loop#7](https://github.com/chaseai-yt/claudex-loop/issues/7)):
läuft das Codex-Kontingent (5-h- oder Wochenfenster des ChatGPT-Abos) mitten im Loop
aus, endet der Skill im Nichts. Der dort vorgeschlagene Umbau (steckbare
Fallback-Reviewer via `REVIEWERS.md`) ist nicht gemergt. **Regel hier: erkennen,
Restkontingent + Reset-Zeit nennen, dann entscheidet der NUTZER** — warten, auf den
lokalen LM-Studio-Reviewer ausweichen, oder die Review-Phase geloggt überspringen.
Nie still, nie automatisch. Ein Same-Model-Review durch Claude selbst ist KEIN
Ersatz für den Cross-Model-Check und wird nicht als solcher verkauft.

### Restkontingent abfragen — lokal, ohne API-Call

Codex schreibt nach jedem Turn einen `rate_limits`-Snapshot in die Session-Rollouts
(`~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`): `primary` = 5-h-Fenster,
`secondary` = Wochenfenster, je `used_percent` + `resets_at` (Epoch), dazu
`credits.balance`. Verifiziert 27.08.2026 gegen codex-cli 0.149.1.

```bash
python scripts/codex_usage.py            # menschenlesbar, Exit 1 ab 95 % Verbrauch
python scripts/codex_usage.py --json     # Roh-Snapshot
```

Der Snapshot ist so alt wie der letzte codex-Lauf. Reicht das nicht (z. B. nach
Tagen Pause), frischt ein Ping ihn auf: `codex exec -s read-only "OK" < /dev/null`
(kostet ~20k Input-Tokens ≈ Rundungsfehler im Fenster).

### Protokoll im Loop

1. **Vor Runde 1:** `python scripts/codex_usage.py`. Exit 1 → gar nicht erst starten;
   dem Nutzer Verbrauch + Reset-Zeit nennen und entscheiden lassen.
2. **Erkennung im Lauf** (stderr-Datei lesen — deshalb NIE `2>/dev/null`):
   429 / „usage limit" / „quota" in stderr, `rate_limit_reached_type` ≠ null im
   Rollout, oder das bekannte Muster *exit 0 + gültige thread_id + leere
   Verdict-Datei* (dann steht die Ursache nur in stderr — auch ein 401 sieht so aus).
3. **Kein blinder Retry.** Loop sofort anhalten, Ursache + Reset-Zeitpunkt aus
   `codex_usage.py` nennen, Nutzer wählt:
   - **Warten** — Reset-Zeit steht fest. Danach `codex exec resume $THREAD_ID …`
     (Session-Kontext bleibt erhalten); ist der Thread weg, frische Session und den
     bisherigen `PLAN-REVIEW-LOG.md` inline in den Prompt geben.
   - **Fallback LM Studio (lokal)** — s. Abschnitt unten. Reviewer-Wechsel wird im
     Log ausgewiesen, das Verdict zählt als Cross-Model-Review zweiter Klasse.
   - **Review überspringen** — Phase 2 endet ohne Verdikt. In den Log gehört ein
     expliziter Eintrag: `## Review übersprungen — Codex-Kontingent erschöpft
     (<Fenster>, Reset <Zeit>), Entscheidung <User>, <Datum>`. Der Plan gilt als
     **nicht cross-reviewed** und geht direkt zum User-Sign-off. Analog zum
     `inspect=off`-Muster des Skills: überspringen ja, still überspringen nie.
   - **Abbrechen** — Stand ist im Log, Wiedereinstieg jederzeit.
4. Die Fundkurve-Regel von oben gilt sinngemäß: ein nach N Runden abgebrochener Lauf
   mit dokumentierten Runden ist mehr wert als ein erzwungenes „APPROVED" von einem
   Ersatz-Reviewer, der nur abnickt (Rubber-Stamping-Risiko aus issue #7).

### Fallback-Reviewer: Qwen3.8-27B über LM Studio (27.08.2026)

LM Studio läuft als Service auf `127.0.0.1:1234` (Budget: max. **32 GB** reserviert).
Modellwahl 27.08.2026 — Coding-Benchmarks der ≤32-GB-Klasse:

| Modell | Benchmarks | Q4_K_M | auf Strix Halo (256 GB/s) |
|---|---|---|---|
| **Qwen3.8-27B** (dense, 14.08.2026) | Terminal-Bench 2.1 **73,0** · SWE-bench Pro **61,7** | 16,8 GB | ~10–15 tok/s → ~4–5 min/Runde |
| Qwen3.6-35B-A3B (MoE, 04/2026) | SWE-bench Verified 73,4 · LCB v6 80,4 | 21,2 GB | schnell (~3B aktiv, ~1–1,5 min/Runde) |
| Qwen3.6-27B (dense) | SWE Verified 77,2 · TB 2.1 63,4 | ~17 GB | wie 3.8, aber überholt |
| gpt-oss-20b (vorhanden) | deutlich darunter (AA-Index ~15) | 12,1 GB | schnell |

**Gewählt: `Qwen3.8-27B` @ Q4_K_M** — der Qualitätssprung der 3.8er-Generation
(Terminal-Bench +9,6, SWE-Pro +8,2 ggü. 3.6-27B) schlägt beim Fallback-Reviewer das
Tempo-Argument: pro Ausfall laufen nur eine Handvoll Runden, und Schärfe ist genau
das, worum es beim Anti-Rubber-Stamping geht. Kleinster Download der Spitzengruppe,
viel KV-Headroom im 32-GB-Budget. Wer Tempo braucht, lädt zusätzlich den MoE
3.6-35B-A3B; `gpt-oss-20b` bleibt Null-Download-Notnagel (`--model openai/gpt-oss-20b`).
Installiert 27.08.2026, Modell-ID verifiziert: **`qwen/qwen3.8-27b`** (so auch als
`CLAUDEX_REVIEWER_LMSTUDIO_MODEL` eintragen). Modellordner ist `D:\AI\models`,
nicht `~\.lmstudio\models` — Side-Loads dorthin, sonst indexiert LM Studio nichts.

```bash
python tools/lms_review.py --plan PLAN.md --out /d/tmp/lms-verdict.txt          # Runde 1
python tools/lms_review.py --plan PLAN.md --log PLAN-REVIEW-LOG.md --round 2 …  # Folgerunden
```

Das Tool lädt das Modell bei Bedarf selbst (`lms load … --context-length 32768`).

**Weitere Provider über `.env`-Profile:** `scripts/fallback_review.py` (identisch zum
Upstream-PR-Skript, s. u.) spricht jeden OpenAI-kompatiblen Endpoint — LM Studio,
Ollama, OpenRouter, OpenAI, Gemini (`…/v1beta/openai`), Anthropic (`api.anthropic.com/v1`).
Profile in die (gitignorierte) `.env` im Repo-Root, Keys nach Vault-Regel nie inline:

```text
CLAUDEX_REVIEWERS=lmstudio,openrouter
CLAUDEX_REVIEWER_LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
CLAUDEX_REVIEWER_LMSTUDIO_MODEL=qwen/qwen3.6-35b-a3b
CLAUDEX_REVIEWER_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
CLAUDEX_REVIEWER_OPENROUTER_MODEL=deepseek/deepseek-r1
CLAUDEX_REVIEWER_OPENROUTER_API_KEY_ENV=OPENROUTER_API_KEY
```

⛔ **Findings-Ledger-Regel (alle Skills, alle Reviewer, alle Phasen):** jede
Reviewer-Ausgabe — Codex-Runde, Fallback-Runde (auch ein UNGÜLTIGER Versuch, so
gekennzeichnet), Cold-Read, Post-Build-Inspection, Recheck, code-review-Pass — wird
**sofort wörtlich** in den Review-Log geschrieben, gefolgt von Claudes Disposition je
Befund (akzeptiert → was geändert / abgelehnt → warum). Nichts lebt nur im Chat; was
nicht im Log steht, ist nicht passiert. Für Fallback-Runden macht das der Adapter
mechanisch: `--append-log <LOG_FILE>`.

`python scripts/fallback_review.py --list` zeigt, was konfiguriert ist; `--reviewer <name>`
wählt, **`--check` prefligtet alle Provider** (lokal: nur Erreichbarkeit; OpenRouter:
echtes Restguthaben via `/credits`; OpenAI/Gemini/Anthropic haben keine Guthaben-API —
dort zeigt sich Erschöpfung erst als 402/429 bei Nutzung) und **`--chain` arbeitet die
`CLAUDEX_REVIEWERS`-Reihenfolge als Fallback-Kette ab** — erster verfügbarer Provider
gewinnt, jeder Skip wird mit Grund ausgewiesen. Gates (Verdict-Pflicht, Rubber-Stamp,
Hash) identisch.

**Upstream-PR vorbereitet (27.08.2026):** der generische Fix liegt als Branch
`fix/7-fallback-reviewers` auf `ujconsulting/claudex-loop` (Fork-Klon:
`D:\Dokumente\Projekte\git\claudex-loop`), Commit `6f37a60` — FALLBACK.md,
`scripts/{fallback_review,codex_usage}.py`, `.env.example`, SKILL.md-stderr-Fix.
Als [PR #9](https://github.com/chaseai-yt/claudex-loop/pull/9) upstream eröffnet (27.08.2026).

### Zweites Abnahme-Gate nach dem Build: `/code-review`

Prozessablauf-Erweiterung (Fork-PR [ujconsulting/claudex-loop#1](https://github.com/ujconsulting/claudex-loop/pull/1),
lokal als User-Skill installiert): läuft NACH Build + Cross-Inspection als
parametrisierbarer Zweit-Review — `scope=dod,quality,security` (Teilmengen erlaubt),
je Dimension ein Pflicht-Verdict (`DOD: COMPLETE|INCOMPLETE`,
`QUALITY: ACCEPTABLE|REVISE`, `SECURITY: PASS|FAIL`), frische read-only
Codex-Session, Diff+Spec inline, 1 Recheck nach Fixes, Ergebnis in denselben
Review-Log. Rote Dimension = Gate gescheitert, wird nie weggemittelt.

```
/code-review scope=dod,security SPEC_FILE=_todos/plaene/<slug>/PLAN.md LOG_FILE=_todos/plaene/<slug>/PLAN-REVIEW-LOG.md
```

**Es gelten dieselben Fallback-Szenarien** wie oben: Preflight `codex_usage.py`,
bei Ausfall warten / Fallback / geloggt überspringen. Der Adapter kann dafür die
Gate-Grammatik fahren: `scripts/fallback_review.py --chain --system-file <prompt>
--require-verdicts "DOD:COMPLETE|INCOMPLETE,QUALITY:ACCEPTABLE|REVISE,SECURITY:PASS|FAIL"`
mit Spec+Diff in EINER Eingabedatei (Fallbacks sehen nur Inline-Text). E2E getestet
27.08.2026: dead-Provider übersprungen, gpt-oss-20b fand die gesäte SQL-Injection
und fehlende Plan-Schritte (`DOD: INCOMPLETE | SECURITY: FAIL`, 3 Befunde).
Eigenschaften, bewusst anders als der Codex-Pfad:

- **Read-only per Konstruktion:** das Modell bekommt keinerlei Datei-/Tool-Zugriff —
  Plan und bisheriger Log gehen inline in den Prompt. Kein „hoffentlich hält sich
  die CLI an read-only" (der zweite Befund aus issue #7).
- **Kein Session-Gedächtnis:** die API ist stateless — Folgerunden bekommen den
  bisherigen `PLAN-REVIEW-LOG.md` per `--log` inline (Ersatz für `codex resume`).
- **Anti-Rubber-Stamping** (der dritte Befund aus issue #7): `VERDICT:`-Zeile ist
  Pflicht; ein APPROVED in Runde 1 mit < 3 nummerierten Befunden gilt als
  **ungültiges Review** (Exit 3), nicht als Freigabe.
- **Plan-Hash-Bindung:** SHA256 des Plans steht im Verdict-Header — ein Verdict gilt
  nur für exakt diesen Planstand; nach jeder Revision zählt nur ein neues.
- **Datenschutz umgekehrt:** lokal verlässt nichts die Maschine — der
  Codex-Tabu-Scope (Begründung: Upload zu OpenAI) greift hier nicht. Für
  Kundendaten-lastige Pläne ist der lokale Reviewer damit sogar der *bessere* Kanal.
- **Log-Kennzeichnung Pflicht:** jede Runde mit diesem Reviewer heißt im Log
  `## Round <n> — Qwen3.6-35B-A3B (LM Studio, Fallback)`. Ein APPROVED von hier
  wiegt weniger als eines von Codex/terra — bei hochriskanten Plänen nach
  Kontingent-Reset eine Codex-Bestätigungsrunde nachziehen.