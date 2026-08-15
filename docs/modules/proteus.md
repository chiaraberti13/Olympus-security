# Proteus — Simulazione phishing autorizzata / Authorized phishing simulation

## Italiano
Proteus esegue simulazioni di phishing **di sola formazione**: assegna a ogni destinatario
in-scope un token univoco, genera l'email-esca e la pagina che il "cliccatore" vede. Quella
pagina è per costruzione una **pagina di awareness** — nessun campo credenziali, non raccoglie
nulla. Proteus non cattura mai credenziali reali: misura il click-through e forma le persone.

```bash
# Costruisci la campagna (token univoco per target in-scope). Richiede autorizzazione.
olympus proteus campaign --engagement acme-2026 --targets destinatari.txt \
  --landing-url https://training.example/p --scope examples/input/proteus-scope.json \
  --i-am-authorized --output campagna.json

# Pagina di training (ciò che vede chi clicca): nessun form credenziali
olympus proteus page --engagement acme-2026 --output training.html

# Email-esca per un token, e report del click-through
olympus proteus email --campaign campagna.json --token <TOKEN>
olympus proteus report --campaign campagna.json --clicked <TOKEN>
```

Lo scope è una **allowlist di domini email** (`examples/input/proteus-scope.json`): i
destinatari fuori dai domini autorizzati vengono bloccati e registrati.

## English
Proteus runs **training-only** phishing simulations: each in-scope recipient gets a unique
token, a lure email and the page a "clicker" lands on. That page is, by construction, an
**awareness page** — no credential fields, it captures nothing. Proteus never collects real
credentials; it measures click-through and trains people. Targets outside the authorized email
-domain allowlist are blocked and logged, and building a campaign requires `--i-am-authorized`.
