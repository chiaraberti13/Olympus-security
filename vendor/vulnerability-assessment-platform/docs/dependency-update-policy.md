# Policy di aggiornamento dipendenze sicurezza

Questa policy formalizza il ciclo di aggiornamento delle dipendenze Python per VAP, con obiettivo di ridurre il rischio CVE e mantenere la compatibilità applicativa.

## Obiettivi

- Ridurre la finestra di esposizione a vulnerabilità note nelle librerie usate.
- Rendere ripetibile il processo di revisione e patching.
- Validare compatibilità funzionale prima di promuovere aggiornamenti in release.

## Frequenza e responsabilità

- **Cadenza standard:** revisione **trimestrale** (gennaio, aprile, luglio, ottobre).
- **Trigger straordinario:** CVE critico su dipendenza in uso, advisory vendor o finding `pip-audit` severo.
- **Owner:** maintainers della codebase (review + merge) con evidenza nei workflow CI.

## Processo operativo

1. Eseguire audit dipendenze (`pip-audit`) sulla baseline del branch.
2. Eseguire inventario aggiornamenti disponibili (`pip list --outdated`).
3. Aprire aggiornamenti su branch dedicato (`deps/security-YYYYQn`).
4. Rieseguire controlli minimi di compatibilità:
   - `pytest tests/test_security.py tests/test_security_headers.py tests/test_api_integration.py`
   - `pip check`
5. Se i test passano, creare PR con changelog dipendenze aggiornate.
6. In caso di breaking change, pianificare fix applicativo nello stesso ciclo trimestrale.

## Criteri di accettazione

Un ciclo è considerato chiuso quando:

- `pip-audit --requirement requirements.txt` non riporta vulnerabilità aperte non accettate.
- I test di compatibilità minimi passano.
- È disponibile evidenza CI del job schedulato e/o della PR di aggiornamento.

## CI automation

È presente il workflow GitHub Actions `dependency-security-review.yml` che:

- gira ogni trimestre in automatico;
- può essere lanciato manualmente (`workflow_dispatch`);
- esegue `pip-audit`, inventario aggiornamenti e test di compatibilità minimi.

Questo workflow non modifica automaticamente `requirements.txt`: produce evidenze e blocca in presenza di regressioni/finding, lasciando il controllo del cambiamento ai maintainer.
