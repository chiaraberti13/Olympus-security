# CLAUDE.md — Note operative per l'agente / Agent operating notes

## 🇮🇹 Push automatico
Nel loop Olympus (`PLAN → BUILD → VERIFY → TEST → CHECK → LOG → RESOLVE → GATE`), ogni volta
che un task viene chiuso con `make check` verde, **committa e pusha automaticamente** sul
branch di sviluppo (`claude/olympus-security-dev-sc1bdl`), senza chiedere conferma ad ogni
commit. La Pull Request di riferimento è:
https://github.com/chiaraberti13/olympus-security/pull/1
Pushare nuovi commit su questo branch **aggiorna la PR esistente** — non aprirne una nuova.

## 🇬🇧 Auto-push
In the Olympus loop (`PLAN → BUILD → VERIFY → TEST → CHECK → LOG → RESOLVE → GATE`), every
time a task closes with `make check` green, **commit and push automatically** to the
development branch (`claude/olympus-security-dev-sc1bdl`), without asking for confirmation on
each commit. Reference Pull Request:
https://github.com/chiaraberti13/olympus-security/pull/1
Pushing new commits to this branch **updates the existing PR** — do not open a new one.
