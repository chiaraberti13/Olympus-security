# Maturità delle integrazioni scanner

Il catalogo AEGIS elenca **24 scanner**. Elencarli non significa eseguirli. Questo
documento descrive la scala con cui Olympus dichiara *quanto* ogni integrazione è
stata davvero validata, e il meccanismo che impedisce a quella dichiarazione di
mentire.

Modulo di riferimento: `olympus.integrations.maturity`.
Comando: `olympus aegis capabilities`.

## Due assi, non uno

È la distinzione centrale, e confonderli è il modo più rapido per costruire un
catalogo disonesto.

| Asse | Domanda | Modulo | Dipende da |
| --- | --- | --- | --- |
| **Readiness** | "Questo motore può girare **qui e ora**?" | `integrations.capabilities` | la macchina corrente: binario nel PATH, API configurata |
| **Maturity** | "Quanto lontano ha portato questa integrazione **il progetto**?" | `integrations.maturity` | il repository: adapter, test, evidenze |

I due assi sono indipendenti e devono restarlo. Esempi concreti:

- `nmap` è `live-tested` dal progetto, ma su una macchina senza il binario resta
  `dependency-missing` e **non** eseguibile;
- `nuclei` può essere installato sulla tua macchina — quindi "disponibile" — e
  restare `catalog-only`, perché una `ScannerSpec` è una voce di catalogo, non
  un'implementazione.

Un comando che collassasse i due assi direbbe "nuclei disponibile" e lascerebbe
credere che Olympus sappia eseguirlo. Non lo sa.

## La scala

| Stadio | Significato |
| --- | --- |
| `catalog-only` | Esiste una `ScannerSpec`. Non esegue nulla. |
| `adapter-ready` | Adapter registrato in `olympus.aegis.registry`: Olympus sa costruire la command line e possiede codice di parsing. Nessuno dei due è dimostrato. |
| `offline-tested` | Il parser è esercitato contro output reale registrato: una regressione **fa fallire la build**. |
| `live-tested` | L'adapter è stato eseguito end-to-end contro un motore reale in un lab autorizzato, e l'evidenza è committata. |
| `production-ready` | `live-tested` **più** l'intera Definition of Done: evidence manifest con digest, SBOM, vulnerability scan, compatibilità di versione documentata. |

## Lo stato oggi

```text
catalog-only     18
adapter-ready     0
offline-tested    2   testssl, whatweb
live-tested       4   nmap, nikto, sqlmap, wafw00f
production-ready  0
```

**Nessun adapter è `production-ready`**, e dirlo è il punto di questo modulo. La
Definition of Done non è soddisfatta per nessun motore: mancano l'evidence
manifest per adapter, l'SBOM e la scansione vulnerabilità. Dichiarare
`production-ready` oggi sarebbe esattamente l'overpromise che la scala esiste per
impedire.

`whatweb` merita una nota: l'unica esecuzione live catturata è **fallita** su un
ambiente Ruby rotto (`docs/aegis-execution-evidence.md`), quindi l'adapter non ha
mai analizzato output reale del motore. Il parser è coperto da test offline, e lo
stadio si ferma lì.

## Perché la dichiarazione non può mentire

Un registro scritto a mano invecchia e diventa marketing. Per questo
`verify_declarations()` ri-deriva dal repository ciò che è dimostrabile e
segnala ogni affermazione che lo supera:

- una dichiarazione esiste solo per uno scanner effettivamente a catalogo;
- qualsiasi stadio sopra `catalog-only` ha davvero un adapter registrato;
- qualsiasi stadio sopra `catalog-only` cita un'evidenza, **e quel file esiste**;
- `offline-tested` e oltre richiedono una funzione `test_<scanner>_parser*` in
  `tests/unit/test_aegis_execution.py` — se il test non c'è, l'affermazione "una
  regressione fa fallire la build" è falsa;
- `production-ready` non convive con un blocker aperto;
- un adapter registrato ma **non** dichiarato è anch'esso una deriva: sottostimare
  il progetto non è un default sicuro, è comunque un'informazione sbagliata.

`test_declared_ledger_matches_the_repository` asserisce che l'elenco dei problemi
sia vuoto. Se quel test fallisce, si corregge la dichiarazione o si aggiunge
l'evidenza — **mai** l'asserzione.

## Uso in CI

```bash
# Ispezione: readiness + maturità per ogni motore
olympus aegis capabilities

# Gate: fallisce se meno di 4 integrazioni raggiungono live-tested
olympus aegis capabilities --min-maturity live-tested --count 4
```

Codici di uscita del gate:

| Codice | Causa |
| --- | --- |
| `0` | La soglia è raggiunta. |
| `2` | Stadio sconosciuto, **oppure** deriva nel registro: è un bug di reporting, non un risultato di readiness, e non deve travestirsi da tale. |
| `4` | Troppo poche integrazioni raggiungono lo stadio richiesto. |

## Aggiungere un'integrazione

Il meccanismo non cambia (vedi `ROADMAP_HARDENING.md` §3.0):

1. registrare la `ScannerSpec` in `olympus/integrations/scanners.py` → `catalog-only`;
2. scrivere l'adapter in `olympus/aegis/adapters/<nome>.py` e registrarlo in
   `olympus/aegis/registry.py` → `adapter-ready`;
3. aggiungere fixture di output reale e `test_<nome>_parser` → `offline-tested`;
4. eseguire contro un motore reale in lab autorizzato e committare l'evidenza in
   `docs/aegis-execution-evidence.md` → `live-tested`;
5. completare la Definition of Done → `production-ready`.

A ogni passo si aggiorna `DECLARED` in `olympus/integrations/maturity.py`. Se si
salta un passo, il verificatore se ne accorge.

## Riferimenti

- Catalogo e licenze: [`docs/scanner-matrix.md`](scanner-matrix.md)
- Evidenze di esecuzione reale: [`docs/aegis-execution-evidence.md`](aegis-execution-evidence.md)
- Definition of Done: [`ROADMAP_HARDENING.md`](../ROADMAP_HARDENING.md)
- Licenze di terze parti: [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)
