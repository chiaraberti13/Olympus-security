# OpenAPI 3.0 & Swagger UI

## Generazione automatica della specifica OpenAPI

La piattaforma espone automaticamente la specifica **OpenAPI 3.0**. Puoi:

- **Servire la specifica live** da FastAPI: `GET /openapi.json`
- **Generare un file statico** con lo script di build:

```bash
python scripts/generate_openapi.py
```

Il file viene salvato in `docs/openapi/openapi.json`.

## Swagger UI

FastAPI offre la UI interattiva per provare le API:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

Se la sicurezza è attiva (API key o JWT), inserisci:

- `x-api-key` negli header
- `Authorization: Bearer <token>`

## Best practice

- Versiona la specifica `openapi.json` ad ogni release.
- Mantieni esempi di request/response aggiornati nelle route.
- Validare i payload con Pydantic (già in uso).
