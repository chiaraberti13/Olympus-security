# Contributing Guide

Grazie per il tuo interesse! 🎉

## Setup locale

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Workflow consigliato

1. Crea un branch feature (`feat/<nome>`)
2. Aggiungi test dove necessario
3. Assicurati che lint e test passino
4. Apri una PR con descrizione dettagliata

## Convenzioni

- Python 3.10+.
- Usare tipizzazione dove possibile.
- Evitare regressioni in sicurezza.

## Report bug

Includi:
- Steps to reproduce
- Output log
- Versione OS e Python

## Riferimenti ufficiali

- FastAPI: https://fastapi.tiangolo.com/
- Pydantic: https://docs.pydantic.dev/
