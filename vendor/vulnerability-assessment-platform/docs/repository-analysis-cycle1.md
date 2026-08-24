## CICLO #1

### PROBLEMI TROVATI: 6

#### 🔴 CRITICI (0)
Nessuno.

#### 🟠 ALTA PRIORITÀ (2)
1. WebSocket `/ws` non applica l'enforcement JWT anche quando `VAP_JWT_REQUIRED=true`.
   - File: `app.py:1273-1281`
   - Impatto: un client con sola API key (o senza, se API key disattivata) può ottenere aggiornamenti in tempo reale di scansioni senza autenticazione bearer, bypassando il controllo usato sulle REST API.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    scan_id_param = websocket.query_params.get("scan_id")
    api_key = websocket.query_params.get("api_key")
    if (settings.api_key or settings.api_key_hash) and not verify_api_key(api_key or ""):
        await websocket.close(code=1008)
        return
```

```python
# NUOVO (proposto)
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    scan_id_param = websocket.query_params.get("scan_id")
    api_key = websocket.query_params.get("api_key")
    jwt_token = websocket.query_params.get("jwt")

    if (settings.api_key or settings.api_key_hash) and not verify_api_key(api_key or ""):
        await websocket.close(code=1008)
        return

    if settings.jwt_required:
        if not jwt_token:
            await websocket.close(code=1008)
            return
        try:
            verify_jwt_token(jwt_token)
        except ValueError:
            await websocket.close(code=1008)
            return
```

2. Content Security Policy permissiva con `unsafe-inline` su script e stili.
   - File: `config.py:76-79`
   - Impatto: aumenta in modo significativo la superficie XSS lato browser, perché consente esecuzione di JavaScript inline.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
csp_policy: str = os.getenv(
    "VAP_CSP_POLICY",
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
    "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; connect-src 'self'; frame-ancestors 'none'",
)
```

```python
# NUOVO (proposto)
csp_policy: str = os.getenv(
    "VAP_CSP_POLICY",
    "default-src 'self'; img-src 'self' data:; style-src 'self' https://cdn.tailwindcss.com; "
    "script-src 'self' https://cdn.tailwindcss.com; connect-src 'self'; frame-ancestors 'none'",
)
# + migrazione script inline verso file statici e, se necessario, nonce-based CSP.
```

#### 🟡 MEDIA PRIORITÀ (3)
1. Endpoint `/metrics` esposto senza autenticazione.
   - File: `app.py:367-369`
   - Impatto: disclosure di telemetria interna (path, volumi richieste, latenza) utile per reconnaissance.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

```python
# NUOVO (proposto)
@app.get("/metrics")
def metrics(
    request: Request,
    _: None = Depends(enforce_api_key),
    __: None = Depends(enforce_jwt),
) -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

2. Mancanza di pipeline CI/CD versionata nel repository.
   - File: root repository (`.github/workflows` assente)
   - Impatto: nessuna garanzia automatica su linting, test, security scan e compatibilità Linux/Windows/macOS ad ogni commit.
   - Soluzione (codice prima/dopo):

```yaml
# VECCHIO
# (assente)
```

```yaml
# NUOVO (proposto) - .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ["3.11", "3.12"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements.txt
      - run: pytest -q
```

3. Security dependency scanning non integrato nel progetto.
   - File: `requirements.txt` (presenza dipendenze, ma assenza tooling SCA nel repo)
   - Impatto: vulnerabilità note su dipendenze possono arrivare in produzione senza blocco preventivo.
   - Soluzione (codice prima/dopo):

```yaml
# VECCHIO
# Nessun job SCA automatizzato
```

```yaml
# NUOVO (proposto) - estratto workflow
- run: pip install pip-audit
- run: pip-audit --strict
```

#### 🟢 BASSA PRIORITÀ (1)
1. Default HTTPS non secure-by-default.
   - File: `config.py:40`
   - Impatto: in setup iniziali è facile esporre cookie senza flag `Secure`.
   - Soluzione (codice prima/dopo):

```python
# VECCHIO
require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "false").lower() == "true"
```

```python
# NUOVO (proposto)
require_https: bool = os.getenv("VAP_REQUIRE_HTTPS", "true").lower() == "true"
# Override a false solo in ambiente development locale.
```

### RACCOMANDAZIONI AGGIUNTIVE
- Introdurre policy di hardening fail-fast in produzione (es. bloccare startup se `VAP_ENV=production` con `VAP_REQUIRE_HTTPS=false`).
- Eseguire baseline OWASP ASVS L1/L2 su endpoint principali (`/auth/token`, `/api/v1/scans`, websocket).
- Aggiungere quality gates minimi in CI: coverage >= 80%, SCA severità high/critical = 0.

### PROSSIMI STEP
1. Conferma se procedo con il **CICLO #2** implementando direttamente le correzioni di priorità ALTA/MEDIA.
2. Dopo patch, rieseguo test e validazioni sicurezza per produrre delta report con evidenze.

---
STATO: IN CORSO
