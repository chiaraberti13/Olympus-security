# Troubleshooting & FAQ

## FAQ

### 1. La dashboard non carica le scansioni
**Possibili cause**:
- DB non inizializzato
- Errore di connessione DB

**Soluzione**:
- Avvia l'app e controlla i log.
- Verifica i permessi di scrittura su `scans/` e `reports/`.

### 2. API restituisce 401
**Possibili cause**:
- API key non inviata
- JWT mancante/invalidato

**Soluzione**:
- Invia `x-api-key` e `Authorization: Bearer <token>`

### 3. Report PDF non disponibile
**Possibili cause**:
- Scansione non completata
- Errore nella generazione report

**Soluzione**:
- Controlla lo stato della scansione.
- Riesegui la scansione e verifica i log.

### 4. Redis non disponibile
**Sintomo**: cache API disabilitata o rate limit non funzionante.

**Soluzione**:
- Avvia Redis
- Verifica `VAP_API_CACHE_REDIS_URL`

## Checklist rapida

- ✅ `python app.py` parte senza errori
- ✅ `GET /health` risponde `status: ok`
- ✅ `GET /ready` mostra checks positivi
