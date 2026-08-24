# Manuale Utente

## 1. Accesso alla dashboard

Apri il browser e vai su `http://localhost:8000/`. La dashboard mostra:

- scansioni attive
- tempo medio di completamento
- totale findings

## 2. Avviare una scansione

1. Inserisci **target** (URL o IP).
2. Seleziona **scan type** (es. `full`, `nmap`, `nuclei`).
3. Imposta **priorità** (0–9).
4. Clicca **Start Scan**.

### Validazione input

- URL devono essere complete (schema `http/https`).
- IP e domini devono essere validi.

## 3. Monitorare lo stato

Vai su **Scans** e apri il dettaglio:

- stato (queued/running/completed)
- percentuale avanzamento
- log ultimi eventi

## 4. Report PDF

Quando la scansione è completata, scarica il PDF:

- dalla pagina di dettaglio
- oppure via API: `GET /api/v1/scans/{scan_id}/report/download`

## 5. Sicurezza e autenticazione

Se attive, devi includere:

- API key (`x-api-key`)
- JWT Bearer (`Authorization`)

Vedi **Security** per dettagli.

## 6. KPI didattici

Per monitorare l'efficacia del percorso formativo sono disponibili endpoint dedicati (protetti da API key + ruolo viewer/operator/admin):

- `POST /api/v1/learning-quiz-attempts`  
  Registra un tentativo quiz per modulo (`module_id`, numero domande, risposte corrette, durata).
- `GET /api/v1/learning-kpis`  
  Restituisce KPI aggregati per soggetto:
  - accuratezza quiz;
  - trend di riduzione dei finding da validare (proxy false positive confermati);
  - tempo medio di remediation e miglioramento rispetto alla baseline storica.
