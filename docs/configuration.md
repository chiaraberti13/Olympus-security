# Configurazione Olympus

Olympus risolve ogni valore con questa precedenza, dalla più alta alla più bassa:

1. opzione passata esplicitamente dalla CLI o dal chiamante;
2. variabile `OLYMPUS_<SEZIONE>_<CHIAVE>`;
3. valore nel file TOML selezionato;
4. default integrato.

Per esempio, `[http].timeout` può essere sovrascritto da
`OLYMPUS_HTTP_TIMEOUT`. Un'opzione CLI specifica del comando prevale su entrambi.

Il file viene cercato in quest'ordine:

1. percorso indicato da `OLYMPUS_CONFIG`;
2. `./olympus.toml`;
3. `~/.olympus.toml`.

Se `OLYMPUS_CONFIG` indica un file assente o non valido, Olympus interrompe
l'operazione: non ripiega silenziosamente su un altro file o sui default.

## Validazione

```bash
olympus config validate
olympus config validate --file /percorso/olympus.toml
```

Il comando restituisce un documento JSON con sorgente, nomi degli override
environment attivi e configurazione effettiva. I valori associati a chiavi
sensibili (`token`, `password`, `secret`, `api_key` e simili) vengono sempre
sostituiti con `[REDACTED]`.

Gli override environment sono convertiti nel tipo del valore previsto e
validati con gli stessi limiti del TOML. Un valore non interpretabile o fuori
intervallo causa exit code `2`.

Le opzioni HTTP riconosciute sono `timeout`, `deadline`, `retries`, `backoff`,
`jitter`, `rate`, `max_response_bytes`, `max_response_headers`,
`max_response_header_bytes`, `max_redirects`, `max_decompressed_bytes` e
`max_expansion_ratio`.
