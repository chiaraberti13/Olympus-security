# Security Best Practices

## Autenticazione & autorizzazione

- **API key** per accesso alle API REST.
- **JWT** per sessioni temporanee (token bearer).
- **Rate limiting** attivo su endpoint sensibili.

## HTTPS

- Abilita `VAP_REQUIRE_HTTPS=true` in produzione.
- Configura certificati TLS (vedi `config.py`).

## OWASP Top 10 (mitigazioni)

- **Injection**: validazione input (Pydantic) e query parametrizzate.
- **Broken Auth**: JWT con secret e scadenza breve.
- **Sensitive Data Exposure**: HTTPS + HSTS.
- **Security Misconfiguration**: header di sicurezza e CSP.
- **Logging & Monitoring**: audit log e metriche.

## Hardening consigliato

- Ruota le API key periodicamente.
- Usa DB esterno con backup e cifratura.
- Segregazione dei secret (Vault, Secrets Manager).
- Esegui i tool esterni in ambienti isolati.

## Checklist minima produzione (operativa)

1. **Autenticazione obbligatoria**: abilita `VAP_JWT_REQUIRED=true` e imposta `VAP_API_KEY` oppure `VAP_API_KEY_HASH`.
2. **Secret forti**: configura `VAP_JWT_SECRET` e `VAP_CSRF_SECRET` con valori unici e ruotabili.
3. **HTTPS**: abilita `VAP_REQUIRE_HTTPS=true` e fornisci `VAP_TLS_CERTFILE`/`VAP_TLS_KEYFILE`.
4. **CORS restrittivo**: limita `VAP_CORS_ALLOWED_ORIGINS` ai domini effettivi.
5. **Rate limiting**: rivedi `VAP_RATE_LIMIT_*` per prevenire abuso.
6. **Security headers**: lascia `VAP_SECURITY_HEADERS=true` e valida `VAP_CSP_POLICY`.
7. **Audit & retention**: abilita `VAP_AUDIT_LOGGING` e definisci `VAP_AUDIT_RETENTION_DAYS`.

Per la lista completa delle variabili: `docs/configuration.md`.

## Riferimenti ufficiali

- OWASP Top 10: https://owasp.org/Top10/
- JWT: https://jwt.io/introduction
- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
