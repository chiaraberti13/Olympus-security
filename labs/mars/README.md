# Mars — Cyber Range & Purple Lab

🇮🇹 Ambiente bersaglio segmentato (Docker Compose) e scenari **purple** end-to-end che
attraversano l'intera suite Olympus. Solo dati sintetici, ambiente isolato, non distruttivo.

🇬🇧 Segmented target environment (Docker Compose) and end-to-end **purple** scenarios that
traverse the whole Olympus suite. Synthetic data only, isolated, non-destructive.

Stato / Status: **W4 completo / done** — vedi [`docs/modules/mars.md`](../../docs/modules/mars.md)
per la documentazione completa bilingue.

## Avvio rapido / Quick start
```bash
make mars-up       # avvia il range / starts the range (localhost:8080)
make mars-status    # verifica lo stato / check status
make mars-down      # ferma e rimuove il range / stops and removes the range

# poi, punta i moduli al range reale / then, point the modules at the real range:
olympus artemis scan --url http://localhost:8080 --scope labs/mars/scope-artemis.json
olympus helios scan --target 127.0.0.1 --scope labs/mars/scope-helios.json
```

## Scenario purple offline / Offline purple scenario
Lo scenario end-to-end che attraversa tutta la suite (senza bisogno del daemon Docker) è
in `tests/integration/test_purple_scenario.py`, eseguito da `make check`.
The end-to-end scenario across the whole suite (no Docker daemon needed) lives in
`tests/integration/test_purple_scenario.py`, run by `make check`.
