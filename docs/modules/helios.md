# Helios — superficie autorizzata / Authorized surface

## Italiano
Helios verifica obbligatoriamente un file di scope CIDR prima di tentare handshake TCP
limitati, con timeout e massimo 128 porte. Non invia payload applicativi; i target fuori scope
sono bloccati e registrati. L'output usa `olympus.core.Finding`.

```bash
olympus helios scan 192.0.2.10 --ports 80,443 --scope examples/input/helios-scope.json
olympus helios demo
```

## English
Helios requires a CIDR scope file before attempting bounded TCP handshakes with a timeout and
a maximum of 128 ports. It sends no application payload; out-of-scope targets are blocked and
audited. Output uses `olympus.core.Finding`. The offline demo uses only documentation addresses.
