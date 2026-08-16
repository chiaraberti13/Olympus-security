# Helios — superficie autorizzata / Authorized surface

## Italiano
Helios verifica obbligatoriamente un file di scope CIDR prima di tentare handshake TCP
limitati, con timeout e massimo 128 porte. Non invia payload applicativi; i target fuori scope
sono bloccati e registrati. Identifica passivamente il servizio più probabile per porta e alza
la severità (con remediation) per i servizi rischiosi esposti. L'output usa
`olympus.core.Finding`, con `--asset-id` per collegare i finding a un asset.

```bash
olympus helios scan 192.0.2.10 --ports 80,443 --scope examples/input/helios-scope.json \
  --asset-id AST-HELIOS-00001
```

## English
Helios requires a CIDR scope file before attempting bounded TCP handshakes with a timeout and
a maximum of 128 ports. It sends no application payload; out-of-scope targets are blocked and
audited. It passively labels the most likely service per port and raises severity (with
remediation) for exposed risky services. Output uses `olympus.core.Finding`; `--asset-id`
attaches the findings to a specific asset.
