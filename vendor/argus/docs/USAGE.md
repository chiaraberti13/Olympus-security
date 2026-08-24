# 📖 Usage Guide / Guida all'uso

🇬🇧 English below · 🇮🇹 Italiano più sotto ([vai](#-italiano))

---

## 🇬🇧 English

### Two ways to use Argus

1. **Interactive menu** — just run `argus` with no arguments.
2. **Command line** — run a subcommand for scripting/automation.

### Global options
These work either before or after the subcommand:

| Option | Description | Default |
|--------|-------------|---------|
| `--export {json,csv,html}` | Save a report of the result | off |
| `--timeout SECONDS` | Per-request timeout | `8.0` |
| `--workers N` | Concurrent workers (username scan) | `20` |
| `--no-color` | Disable colored output | off |
| `--version` | Print version and exit | — |

### Commands

#### `ip` — IP geolocation
```bash
argus ip 8.8.8.8
argus ip 1.1.1.1 --export json
```
Returns country, region, city, coordinates, timezone, ISP/org, ASN and a
ready-to-open Google Maps link. Uses HTTPS with automatic failover to a second
provider. Private/reserved addresses are flagged.

#### `phone` — phone number intelligence
```bash
argus phone "+14155552671"
argus phone "02 1234 5678" --region IT      # help the parser with a region
```
Returns validity, line type (mobile/fixed/VoIP…), carrier, region, timezone(s)
and E.164 / international / national / RFC3966 formats. **Works fully offline.**

> Tip: always prefer international format (`+<country><number>`). Use `--region`
> (ISO code like `US`, `IT`, `GB`) only when passing a national number.

#### `username` — hunt a username across 50+ sites
```bash
argus username torvalds
argus username johndoe --workers 30 --timeout 6 --export html
```
Checks 50+ platforms **concurrently** and lists where the username exists.
Add sites by editing [`../data/sites.json`](../data/sites.json).

> Note: some platforms return HTTP 200 for any URL, which can cause false
> positives. For those, set `"method": "text"` with an `"absence"` string in
> `sites.json` so a profile is only counted when that string is absent.

#### `email` — passive email OSINT
```bash
argus email someone@example.com --export json
```
Validates syntax, checks whether the domain can receive mail (MX record),
derives the Gravatar URL and reports whether a Gravatar exists. It performs
**no** intrusive SMTP probing. Install `dnspython` for real MX checks.

#### `domain` — domain / WHOIS via RDAP
```bash
argus domain github.com --export json
```
Returns registrar, registration/expiry/last-changed dates, name servers, domain
status flags and DNSSEC state. Uses RDAP (the modern, structured WHOIS), so no
API key is needed. You can paste a full URL — Argus extracts the domain.

#### `dns` — DNS records via DNS-over-HTTPS
```bash
argus dns example.com
argus dns example.com --types A,MX,TXT      # only specific record types
```
Resolves A / AAAA / MX / TXT / NS / CNAME / SOA records over encrypted DoH
(Cloudflare, with a Google fallback) — works even where port 53 is blocked.

#### `web` — website / HTTP recon
```bash
argus web example.com
argus web https://example.com --export html
```
Shows the response status, redirect chain, resolved IP, `Server`/tech headers
and audits common **security headers** (HSTS, CSP, X-Frame-Options…), flagging
missing ones. A passive GET only — no crawling or scanning.

#### `mac` — MAC address vendor lookup
```bash
argus mac 3C:22:FB:11:22:33
argus mac 3c22fb112233                       # separators optional
```
Resolves the hardware **vendor** from the MAC's OUI and reports whether the
address is locally administered or multicast.

#### `myip` — your own public IP
```bash
argus myip
```
Discovers your public IP (with provider failover) and geolocates it.

#### `config` — configuration
```bash
argus config --show      # print current settings
argus config --init      # write ~/.config/argus/config.json
```

### Reports
Reports are saved to a `report/` folder inside the script's folder by default
(change with `ARGUS_OUTPUT_DIR`). The HTML report is a standalone dark-themed page with
clickable links — great for sharing findings.

### Automation example
```bash
for u in alice bob charlie; do
  argus username "$u" --export json
done
```

---

## 🇮🇹 Italiano

### Due modi per usare Argus

1. **Menu interattivo** — esegui `argus` senza argomenti.
2. **Riga di comando** — esegui un sottocomando per scripting/automazione.

### Opzioni globali
Funzionano sia prima sia dopo il sottocomando:

| Opzione | Descrizione | Default |
|---------|-------------|---------|
| `--export {json,csv,html}` | Salva un report del risultato | off |
| `--timeout SECONDI` | Timeout per richiesta | `8.0` |
| `--workers N` | Worker concorrenti (scansione username) | `20` |
| `--no-color` | Disattiva l'output colorato | off |
| `--version` | Mostra la versione ed esce | — |

### Comandi

#### `ip` — geolocalizzazione IP
```bash
argus ip 8.8.8.8
argus ip 1.1.1.1 --export json
```
Restituisce nazione, regione, città, coordinate, fuso orario, ISP/organizzazione,
ASN e un link a Google Maps pronto all'uso. Usa HTTPS con failover automatico su
un secondo provider. Gli indirizzi privati/riservati vengono segnalati.

#### `phone` — analisi numero di telefono
```bash
argus phone "+390212345678"
argus phone "02 1234 5678" --region IT      # aiuta il parser con la regione
```
Restituisce validità, tipo di linea (mobile/fisso/VoIP…), operatore, regione,
fusi orari e i formati E.164 / internazionale / nazionale / RFC3966.
**Funziona completamente offline.**

> Suggerimento: preferisci sempre il formato internazionale (`+<prefisso><numero>`).
> Usa `--region` (codice ISO come `US`, `IT`, `GB`) solo con un numero nazionale.

#### `username` — cerca uno username su 50+ siti
```bash
argus username torvalds
argus username mariorossi --workers 30 --timeout 6 --export html
```
Controlla 50+ piattaforme **in parallelo** ed elenca dove lo username esiste.
Aggiungi siti modificando [`../data/sites.json`](../data/sites.json).

> Nota: alcune piattaforme rispondono HTTP 200 a qualsiasi URL, causando falsi
> positivi. Per quelle, imposta `"method": "text"` con una stringa `"absence"`
> in `sites.json`, così un profilo viene contato solo se quella stringa è assente.

#### `email` — OSINT email passivo
```bash
argus email qualcuno@example.com --export json
```
Verifica la sintassi, controlla se il dominio può ricevere posta (record MX),
ricava l'URL Gravatar e indica se un Gravatar esiste. **Non** esegue sondaggi
SMTP intrusivi. Installa `dnspython` per controlli MX reali.

#### `domain` — dominio / WHOIS via RDAP
```bash
argus domain github.com --export json
```
Restituisce registrar, date di registrazione/scadenza/ultima modifica, name
server, flag di stato del dominio e stato DNSSEC. Usa RDAP (il WHOIS moderno e
strutturato), quindi nessuna API key. Puoi incollare un URL completo — Argus ne
estrae il dominio.

#### `dns` — record DNS via DNS-over-HTTPS
```bash
argus dns example.com
argus dns example.com --types A,MX,TXT      # solo determinati tipi di record
```
Risolve i record A / AAAA / MX / TXT / NS / CNAME / SOA tramite DoH cifrato
(Cloudflare, con fallback su Google) — funziona anche dove la porta 53 è bloccata.

#### `web` — ricognizione sito / HTTP
```bash
argus web example.com
argus web https://example.com --export html
```
Mostra status della risposta, catena di redirect, IP risolto, header
`Server`/tecnologici e verifica i principali **header di sicurezza** (HSTS, CSP,
X-Frame-Options…), segnalando quelli mancanti. Solo una GET passiva — nessun
crawling o scanning.

#### `mac` — lookup produttore da indirizzo MAC
```bash
argus mac 3C:22:FB:11:22:33
argus mac 3c22fb112233                       # separatori opzionali
```
Ricava il **produttore** hardware dall'OUI del MAC e indica se l'indirizzo è
localmente amministrato o multicast.

#### `myip` — il tuo IP pubblico
```bash
argus myip
```
Rileva il tuo IP pubblico (con failover tra provider) e lo geolocalizza.

#### `config` — configurazione
```bash
argus config --show      # mostra le impostazioni correnti
argus config --init      # crea ~/.config/argus/config.json
```

### Report
I report vengono salvati per default nella cartella `report/` all'interno della
cartella dello script (modificabile con `ARGUS_OUTPUT_DIR`). Il report HTML è una pagina autonoma con tema scuro e
link cliccabili — perfetta per condividere i risultati.

### Esempio di automazione
```bash
for u in alice bob charlie; do
  argus username "$u" --export json
done
```
