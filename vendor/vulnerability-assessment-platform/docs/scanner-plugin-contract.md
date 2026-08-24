# Scanner Plugin Contract (versioned)

Questo documento formalizza il contratto di estensione scanner in VAP per mantenere compatibilità architetturale, UX coerente e sicurezza fail-closed.

## Versione contratto

- **Versione corrente:** `1.0.0`
- **Costante runtime:** `PLUGIN_CONTRACT_VERSION` in `scanner_engine.py`
- Un plugin con versione diversa viene rifiutato in registrazione.

## API di registrazione

Usare `register_scanner_plugin()` con una `ScannerPluginSpec`.

Campi richiesti:

- `scanner_name`: identificativo scanner (solo `[a-z0-9_]`, lowercase).
- `scanner_class`: classe scanner istanziabile.

Campi opzionali:

- `display_name`: nome leggibile in UI/report.
- `profile_assignments`: elenco profili supportati (`light`, `wordpress`, ...).
- `contract_version`: default `1.0.0`.

## Regole di sicurezza e robustezza

1. **Version gate obbligatorio**: mismatch di versione ⇒ `ScanValidationError`.
2. **Naming gate obbligatorio**: solo `[a-z0-9_]`; no collisione con scan type riservati (`full`, profili core).
3. **No override silenzioso**: se il nome è già presente in `SCANNERS_MAP`, registrazione bloccata.
4. **Profile allowlist**: è possibile assegnare plugin solo a profili esistenti.
5. **Aggiornamento atomico mappe**: validazioni fatte prima delle mutazioni runtime.

## Esempio di registrazione

```python
from scanner_engine import ScannerPluginSpec, register_scanner_plugin

register_scanner_plugin(
    ScannerPluginSpec(
        scanner_name="custom_plugin",
        scanner_class=CustomPluginScanner,
        display_name="Custom Plugin",
        profile_assignments=["light"],
        contract_version="1.0.0",
    )
)
```

## Test contract (obbligatori)

La suite `tests/test_scanner_engine_runtime.py` copre i casi minimi:

- registrazione valida e update runtime maps;
- rifiuto su versione contratto non supportata;
- rifiuto su profilo non valido senza mutazioni parziali.

