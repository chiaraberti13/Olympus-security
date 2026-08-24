<div align="center">

```
     _    ____   ____ _   _ ____
    / \  |  _ \ / ___| | | / ___|
   / _ \ | |_) | |  _| | | \___ \
  / ___ \|  _ <| |_| | |_| |___) |
 /_/   \_\_| \_\\____|\___/|____/
```

# 👁️ Argus

**Il toolkit OSINT & di ricognizione che vede tutto**
*IP · Dominio · DNS · Telefono · Username · Email · Web · MAC — un'unica CLI veloce e unificata*

<p align="center">
  <a href="README.md">🇬🇧 English</a> | <a href="README-IT.md">🇮🇹 Italiano</a>
</p>

<p align="center">
  <a href="https://github.com/chiaraberti13/ARGUS/actions"><img src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=for-the-badge" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/chiaraberti13/ARGUS?style=for-the-badge&color=green" alt="Licenza"></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/piattaforme-Windows%20%7C%20Ubuntu%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Piattaforme">
  <img src="https://img.shields.io/badge/moduli-9-blue?style=for-the-badge" alt="9 moduli">
</p>

</div>

> [!IMPORTANT]
> **Solo per attività di sicurezza autorizzate, training OSINT e scopi didattici.**
> Argus interroga esclusivamente informazioni **pubblicamente disponibili**. Sei
> l'unico responsabile di un uso **lecito ed etico** dello strumento — leggi il
> **[disclaimer](docs/DISCLAIMER.md)** completo prima dell'uso.

---

## Indice rapido

- **[Cos'è Argus?](#cosè-argus)** — cosa fa e a chi è rivolto.
- **[Moduli](#-moduli)** — ogni sottocomando, cosa fa e come resta onesto il
  rilevamento username.
- **[Installazione](#-installazione)** — installazione in un comando su
  Ubuntu, Debian, macOS, Windows o Docker.
- **[Utilizzo](#-utilizzo)** — il menu interattivo e i sottocomandi CLI.
- **[Configurazione](#-configurazione)** — flag, variabili d'ambiente e file
  di config, nell'ordine di risoluzione.
- **[Struttura del progetto](#-struttura-del-progetto)** — com'è organizzato
  il repository.
- **[Sviluppo](#-sviluppo)** — venv, test, lint.
- **[Licenza](#-licenza)** — MIT, per l'intero repository.
- **[Uso legale ed etico](#-uso-legale-ed-etico)** — cosa significano in
  pratica "pubblicamente disponibile" e "passivo".

> [!TIP]
> **Hai un'idea per un modulo o hai trovato un bug?** Apri una
> [issue](https://github.com/chiaraberti13/ARGUS/issues).

---

## Cos'è Argus?

**Argus è un toolkit da riga di comando per l'OSINT (Open Source Intelligence)** —
la raccolta di informazioni da fonti *pubbliche e liberamente accessibili*.
Riunisce in **un'unica interfaccia veloce e coerente** i passi di ricognizione
che un analista compie di solito su una dozzina di siti e strumenti diversi, ed
esegue ogni ricerca in modo **passivo**: legge soltanto dati pubblici, senza mai
attaccare, autenticarsi o sondare sistemi privati.

Fornisci ad Argus un identificatore — un IP, un dominio, un numero di telefono,
uno username, un'email, un URL o un indirizzo MAC — e lo arricchisce con tutto
ciò che le fonti pubbliche sanno a riguardo, presentando il risultato in tabelle
colorate ordinate e potendo salvare un report in JSON / CSV / HTML.

**A chi serve e a cosa serve:**
- 🛡️ **Professionisti della sicurezza** — la fase di ricognizione di un
  penetration test o red-team *autorizzato* (mappare l'infrastruttura di un
  obiettivo).
- 🔎 **Threat intelligence e incident response** — arricchire rapidamente un
  indicatore (IP, dominio, hash di un'email) visto nei log o in un alert.
- 🕵️ **Analisti OSINT e investigatori** — ricostruire l'impronta digitale
  pubblica di un soggetto a partire da dati che ha scelto di rendere pubblici.
- 🙋 **Persone attente alla privacy** — verificare la *propria* esposizione:
  su quali siti compare il tuo username, cosa rivela il tuo IP pubblico, cosa
  lascia trapelare un dominio.
- 🎓 **Studenti e docenti** — un modo pratico e documentato per capire come
  funzionano davvero OSINT, DNS, WHOIS, HTTP e geolocalizzazione.

## 🧰 Moduli

| Comando | Cosa fa |
|---------|---------|
| `ip` | Geolocalizza un indirizzo IPv4/IPv6 (nazione, città, coordinate, ISP, ASN, link mappa) — HTTPS con failover su due provider |
| `domain` | Dati dominio / WHOIS via **RDAP**: registrar, date di creazione/scadenza, name server, stato, DNSSEC |
| `dns` | Record A / AAAA / MX / TXT / NS / CNAME / SOA via **DNS-over-HTTPS** |
| `phone` | Analisi numero: validità, tipo linea, operatore, regione, fusi orari, 4 formati (**offline**) |
| `username` | Cerca uno username su **50+ siti in parallelo** con rilevamento per-sito (status / testo / redirect) e uno stato **blocked** onesto per i siti anti-bot |
| `email` | OSINT email passivo: sintassi, MX (dominio in grado di ricevere posta), Gravatar |
| `web` | Ricognizione sito / HTTP: status, redirect, server, **audit degli header di sicurezza**, IP risolto |
| `mac` | Indirizzo MAC → **produttore** hardware (OUI), flag local/multicast |
| `myip` | Rileva e geolocalizza il **tuo** IP pubblico |
| `update` | Aggiorna le dipendenze e la lista siti username (`--check` per una prova a vuoto) |

Ogni risultato è esportabile con `--export json|csv|html`.

### Rilevamento username affidabile

Il controllo ingenuo "HTTP 200 = il profilo esiste" è sbagliato per la maggior
parte delle grandi piattaforme, che rispondono `200` per qualsiasi URL,
reindirizzano gli utenti inesistenti o bloccano i bot. Argus usa un modello
per-sito (`errorType` in `data/sites.json`):

- **`status_code`** — esiste solo su un 2xx *non* reindirizzato altrove.
- **`message`** — la pagina è sempre 200, quindi decide una stringa nel corpo.
- **`response_url`** — un profilo assente si riconosce dalla destinazione del redirect.

Le risposte anti-bot / rate-limit (401/403/406/429/451) sono segnalate come
**`blocked`** — un "sconosciuto" esplicito — invece di essere contate come
trovate o assenti: così un risultato non pretende mai più certezza di quella che ha.

### Restare aggiornati

```bash
argus update            # aggiorna dipendenze + ricarica la lista siti
argus update --check    # segnala cosa è obsoleto, senza modificare nulla
argus update --sites    # ricarica solo il catalogo username
```

All'avvio, il menu interattivo mostra un avviso **non bloccante** di una riga
quando esiste una versione più recente di una dipendenza (in cache una volta al
giorno, disattivabile con `ARGUS_NO_UPDATE_CHECK=1`). Imposta `auto_update: true`
nel config per aggiornare le dipendenze automaticamente all'avvio (opt-in —
richiede la rete ed è più lento).

## 🚀 Installazione

L'installer rileva automaticamente il sistema operativo, installa Python se
necessario, crea un ambiente virtuale isolato, installa Argus e aggiunge il
comando `argus` al PATH. Guida completa passo-passo: **[docs/INSTALL.it.md](docs/INSTALL.it.md)**.

**Ubuntu / Debian / macOS**
```bash
git clone https://github.com/chiaraberti13/ARGUS.git argus
cd argus
./scripts/install.sh          # aggiungi --with-dns per controlli MX reali nel modulo email
argus                         # avvia il menu interattivo
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/chiaraberti13/ARGUS.git argus
cd argus
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
argus
```

**Docker (senza Python installato in locale)**
```bash
docker build -t argus .
docker run --rm -it argus                 # menu interattivo
docker run --rm argus ip 8.8.8.8          # comando singolo
```

## 🎯 Utilizzo

Esegui `argus` per il **menu interattivo**, oppure usa i **sottocomandi** per lo scripting:

```bash
argus ip 8.8.8.8
argus domain github.com
argus dns example.com --types A,MX,TXT
argus phone "+390212345678"
argus username torvalds --export html
argus email qualcuno@example.com
argus web example.com
argus mac 3C:22:FB:11:22:33
argus myip
```

Flag globali (prima o dopo il sottocomando): `--export {json,csv,html}`,
`--timeout SECONDI`, `--workers N`, `--no-color`.
Riferimento completo: **[docs/USAGE.md](docs/USAGE.md)**.

## ⚙️ Configurazione

Risolta in quest'ordine: **flag CLI → variabili d'ambiente → file di config → default**.

| Impostazione | Flag | Variabile d'ambiente | Default |
|--------------|------|----------------------|---------|
| Timeout richiesta (s) | `--timeout` | `ARGUS_TIMEOUT` | `8.0` |
| Worker concorrenti | `--workers` | `ARGUS_MAX_WORKERS` | `20` |
| Retry | — | `ARGUS_RETRIES` | `2` |
| Cartella di output | — | `ARGUS_OUTPUT_DIR` | `<cartella script>/report` |
| User-Agent | — | `ARGUS_USER_AGENT` | UA browser |
| Disattiva verifica SSL | — | `ARGUS_NO_VERIFY_SSL=1` | (verifica attiva) |
| Avviso aggiornamenti all'avvio | — | `ARGUS_NO_UPDATE_CHECK=1` | (attivo) |
| Auto-aggiornamento all'avvio | — | `ARGUS_AUTO_UPDATE=1` | (disattivo) |

```bash
argus config --init      # crea ~/.config/argus/config.json
argus config --show      # mostra le impostazioni correnti
```

## 🗂️ Struttura del progetto

```
argus/
├── argus/                    # il pacchetto Python
│   ├── cli.py                # menu + comandi CLI
│   ├── config.py             # configurazione a livelli
│   ├── ui.py                 # UI colorata con fallback testuale
│   ├── exporters.py          # report JSON / CSV / HTML
│   └── modules/               # ip · domain · dns · phone · username · email · web · mac · myip
├── data/sites.json           # 50+ siti per username (facile da estendere)
├── scripts/                  # install.sh · install.ps1 · run.sh · run.bat
├── docs/                     # INSTALL (EN/IT) · USAGE · DISCLAIMER
├── tests/                    # test unitari offline
├── Dockerfile · Makefile · pyproject.toml
└── .github/workflows/ci.yml  # CI su Ubuntu, macOS, Windows
```

Aggiungi un sito alla ricerca username modificando
[`data/sites.json`](data/sites.json) — nessuna modifica al codice.

## 🧪 Sviluppo

```bash
make venv     # crea .venv e installa con gli extra di sviluppo
make test     # esegue i test offline
make lint     # ruff
make run      # avvia il menu
```

## 📄 Licenza

Distribuito con **[Licenza MIT](LICENSE)**.

## ⚠️ Uso legale ed etico

Argus interroga esclusivamente informazioni **pubblicamente disponibili** ed
esegue solo ricerche **passive**. Usalo unicamente su obiettivi di cui sei
proprietario o per cui hai un'**autorizzazione esplicita**. Termini completi:
**[docs/DISCLAIMER.md](docs/DISCLAIMER.md)**.

---

<p align="center">
  <sub>Realizzato con 👁️ da <a href="https://github.com/chiaraberti13">chiaraberti13</a></sub>
</p>
