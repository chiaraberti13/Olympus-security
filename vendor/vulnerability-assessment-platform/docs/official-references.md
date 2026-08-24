# Riferimenti ufficiali framework e librerie

Questa pagina raccoglie la documentazione ufficiale delle tecnologie usate in VAP, utile per sviluppo, hardening, testing e troubleshooting.

## Backend e API

- [FastAPI](https://fastapi.tiangolo.com/) — framework web/API principale.
- [Starlette](https://www.starlette.io/) — componenti ASGI, middleware e request lifecycle.
- [Uvicorn](https://www.uvicorn.org/) — server ASGI per esecuzione locale/produzione.
- [Pydantic](https://docs.pydantic.dev/latest/) — validazione e serializzazione dati.
- [SQLAlchemy](https://docs.sqlalchemy.org/) — ORM e accesso al database.
- [Alembic](https://alembic.sqlalchemy.org/) — migrazioni database (consigliato per ambienti multi-stage).

## Sicurezza applicativa

- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — riferimento rischio applicativo.
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — checklist di verifica sicurezza.
- [JSON Web Token (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519) — standard token JWT.
- [Content Security Policy (MDN)](https://developer.mozilla.org/docs/Web/HTTP/Guides/CSP) — guida ufficiale CSP browser.
- [NIST Secure Software Development Framework (SSDF)](https://csrc.nist.gov/Projects/ssdf) — framework secure SDLC.

## Frontend e UX

- [Jinja](https://jinja.palletsprojects.com/) — templating engine lato server.
- [Tailwind CSS](https://tailwindcss.com/docs/installation) — utility CSS (in progetto via CDN, con roadmap verso build locale).
- [WCAG 2.2](https://www.w3.org/TR/WCAG22/) — standard accessibilità web.
- [WAI-ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/) — pattern accessibili per componenti interattivi.

## Job asincroni e orchestrazione

- [Celery](https://docs.celeryq.dev/) — orchestrazione job asincroni.
- [Redis](https://redis.io/docs/latest/) — broker/result backend Celery.

## Testing e qualità

- [Pytest](https://docs.pytest.org/) — test runner principale.
- [HTTPX](https://www.python-httpx.org/) — client HTTP asincrono/sincrono per test integrazione.
- [Lighthouse](https://developer.chrome.com/docs/lighthouse/overview) — auditing performance/a11y/best-practices.

## Scanner e strumenti sicurezza integrabili

Per gli scanner orchestration, fare sempre riferimento alla documentazione ufficiale dei vendor/progetti prima di tuning avanzato o uso in CI/CD:

- [Nmap](https://nmap.org/docs.html)
- [Nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [OWASP ZAP](https://www.zaproxy.org/docs/)
- [SQLMap](https://sqlmap.org/)
- [Nikto](https://cirt.net/Nikto2)
- [WPScan](https://wpscan.com/docs/)

> Nota operativa: applicare scanner solo su asset autorizzati e con consenso esplicito.
