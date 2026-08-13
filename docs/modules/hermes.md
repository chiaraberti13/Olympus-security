# Hermes — Secret & config scanner (DevSecOps)

> **🇮🇹 Italiano** · [🇬🇧 English below](#-english)

## 🇮🇹 Italiano

### Cosa fa
Hermes è il modulo Blue di Olympus per lo **scanning di secret e configurazioni**: trova
credenziali esposte prima che diventino un incidente, sia nei file sul disco sia nella
history git (dove un secret "ruotato" resta comunque recuperabile finché la storia non
viene riscritta).

Combina due motori indipendenti:

- **Regex a prefisso noto** — AWS Access Key ID, token GitHub (classici e fine-grained),
  token Slack, JWT, blocchi di chiave privata PEM.
- **Entropia di Shannon** — cattura secret generici senza prefisso noto (password casuali,
  chiavi API arbitrarie), con **soglie separate per hex e base64** (un alfabeto esadecimale
  arriva al massimo a 4 bit/carattere, uno base64-like a 6: una soglia unica farebbe perdere
  i secret in hex o annegherebbe in falsi positivi su blob base64).

Ogni valore trovato viene **mascherato** (`AKIA************MPLE`) prima di finire in
qualunque output — mai un secret in chiaro su disco o su schermo.

### Comandi
```bash
# Scan di file/directory (usato anche come hook pre-commit: exit 1 se trova qualcosa)
olympus hermes scan path/to/file.env path/to/dir/ --sarif-output report.sarif.json

# Scan dell'intera history git (tutti i commit, tutti i ref)
olympus hermes git-history --repo . --sarif-output history.sarif.json

# Demo reale, offline, su dati sintetici "Olympus Demo Corp"
olympus hermes demo
```

### Output SARIF
`--sarif-output` scrive un report **SARIF 2.1.0** (deduplicazione delle regole, un
`result` per finding, secret sempre mascherato nello `snippet`). La forma del report è
validata strutturalmente da `validate_sarif_shape` (chiavi obbligatorie, un solo `run`,
ogni `result` riferisce una regola dichiarata) — non contro lo schema JSON ufficiale
completo (multi-megabyte), scelta pragmatica documentata nel modulo `hermes.sarif`.

### Hook pre-commit
Il repo definisce `.pre-commit-hooks.yaml` così che chiunque possa adottare Hermes:
```yaml
repos:
  - repo: https://github.com/chiaraberti13/olympus-security
    rev: <tag o commit>
    hooks:
      - id: hermes-secret-scan
```
Questo stesso repo usa Hermes su se stesso (`.pre-commit-config.yaml`, hook locale), con
`examples/`, `tests/` esclusi perché contengono secret finti usati come fixture/demo.

### Comportamento senza git
`hermes git-history` richiede una repo git valida; su un path che non lo è restituisce un
errore chiaro (`exit 2`) invece di un traceback. Il comando `demo` non dipende dalla rete e
non tocca mai la history reale di questo repo: costruisce una repo git usa-e-getta in una
directory temporanea.

### Esempi
`examples/input/hermes-samples/` contiene un file con secret sintetici (tutti
placeholder noti: la chiave d'esempio AWS della documentazione ufficiale, token con
caratteri ripetuti, ecc.) e uno pulito, usati sia dal comando `demo` sia come riferimento.
L'output reale del demo è in `examples/output/hermes-report.sarif.json`.

### Etica
Nessun dato reale: tutti i secret nei file di esempio e nei test sono placeholder pubblici
o valori palesemente finti, mai credenziali vere.

---

## 🇬🇧 English

### What it does
Hermes is Olympus's Blue module for **secret and config scanning**: it finds exposed
credentials before they become an incident, both in files on disk and in git history
(where a "rotated" secret is still recoverable as long as history isn't rewritten).

It combines two independent engines:

- **Known-prefix regex** — AWS Access Key ID, GitHub tokens (classic and fine-grained),
  Slack tokens, JWTs, PEM private key blocks.
- **Shannon entropy** — catches generic secrets with no known prefix (random passwords,
  arbitrary API keys), with **separate thresholds for hex and base64** (a hex alphabet
  tops out at 4 bits/char, a base64-like one at 6: a single threshold would either miss
  hex secrets or drown in base64 false positives).

Every matched value is **masked** (`AKIA************MPLE`) before it reaches any output —
never a secret in the clear on disk or on screen.

### Commands
```bash
# Scan files/directories (also usable as a pre-commit hook: exits 1 on any finding)
olympus hermes scan path/to/file.env path/to/dir/ --sarif-output report.sarif.json

# Scan the entire git history (every commit, every ref)
olympus hermes git-history --repo . --sarif-output history.sarif.json

# Real, offline demo on synthetic "Olympus Demo Corp" data
olympus hermes demo
```

### SARIF output
`--sarif-output` writes a **SARIF 2.1.0** report (deduplicated rules, one `result` per
finding, secret always masked in the `snippet`). The report's shape is structurally
validated by `validate_sarif_shape` (required keys, exactly one `run`, every `result`
references a declared rule) rather than against the full official JSON Schema
(multi-megabyte) — a pragmatic trade-off documented in the `hermes.sarif` module.

### Pre-commit hook
The repo ships `.pre-commit-hooks.yaml` so anyone can adopt Hermes:
```yaml
repos:
  - repo: https://github.com/chiaraberti13/olympus-security
    rev: <tag or commit>
    hooks:
      - id: hermes-secret-scan
```
This repo itself dogfoods Hermes on its own source (`.pre-commit-config.yaml`, local
hook), excluding `examples/` and `tests/` since they intentionally contain fake secrets as
fixtures/demo data.

### Behavior without git
`hermes git-history` requires a valid git repository; on a path that isn't one it returns
a clear error (`exit 2`) instead of a traceback. The `demo` command never depends on the
network and never touches this repo's real history: it builds a throwaway git repo in a
temporary directory.

### Examples
`examples/input/hermes-samples/` contains one file with synthetic secrets (all well-known
placeholders: AWS's own documentation example key, repeated-character tokens, etc.) and one
clean file, used both by `demo` and as a reference. The demo's real output lives at
`examples/output/hermes-report.sarif.json`.

### Ethics
No real data: every secret in the sample files and tests is a public placeholder or an
obviously fake value, never a real credential.
