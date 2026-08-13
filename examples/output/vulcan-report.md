# Pentest Report — olympus-demo-corp-2026

_Generated 2026-08-13T12:49:46.087170+00:00_

## Summary

- Assets: 8
- Findings: 7
- Alerts: 3

## Findings (ranked by risk)

### Exposed path: /.env

- Severity: **critical** · CVSS: n/a · Source: artemis
- Asset: `AST-2026-00001`

An exposed .env file commonly contains secrets/credentials.

### CORS wildcard origin with credentials allowed

- Severity: **high** · CVSS: n/a · Source: artemis
- Asset: `AST-2026-00001`

Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is invalid per spec but indicates a misconfigured CORS policy.

### Recipient clicked simulated phishing link (Olympus Demo Corp Q3 Awareness Campaign)

- Severity: **low** · CVSS: n/a · Source: proteus
- Asset: `AST-2026-00002`

bob@olympusdemocorp.example clicked the simulated phishing link in campaign 'Olympus Demo Corp Q3 Awareness Campaign'. No real credentials were requested or collected; a training-disclosure page was shown instead.

### Recipient clicked simulated phishing link (Olympus Demo Corp Q3 Awareness Campaign)

- Severity: **low** · CVSS: n/a · Source: proteus
- Asset: `AST-2026-00003`

carol@olympusdemocorp.example clicked the simulated phishing link in campaign 'Olympus Demo Corp Q3 Awareness Campaign'. No real credentials were requested or collected; a training-disclosure page was shown instead.

### Recipient clicked simulated phishing link (Olympus Demo Corp Q3 Awareness Campaign)

- Severity: **low** · CVSS: n/a · Source: proteus
- Asset: `AST-2026-00004`

dave@olympusdemocorp.example clicked the simulated phishing link in campaign 'Olympus Demo Corp Q3 Awareness Campaign'. No real credentials were requested or collected; a training-disclosure page was shown instead.

### Missing security header: x-content-type-options

- Severity: **low** · CVSS: n/a · Source: artemis
- Asset: `AST-2026-00001`

X-Content-Type-Options: nosniff prevents MIME-sniffing attacks.

### Missing security header: referrer-policy

- Severity: **low** · CVSS: n/a · Source: artemis
- Asset: `AST-2026-00001`

Referrer-Policy controls how much referrer information leaks cross-origin.

## Alerts

- `ALT-2026-00001` **Repeated authentication failure** (MITRE T1110) — severity high
- `ALT-2026-00002` **Repeated authentication failure** (MITRE T1110) — severity high
- `ALT-2026-00003` **Repeated authentication failure** (MITRE T1110) — severity high
