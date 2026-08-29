# Security Policy

## Supported versions

Security fixes are applied to the latest version on the default branch. Older
commits, forks and unofficial builds are not supported unless explicitly
documented.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/chiaraberti13/Olympus-security/security/advisories/new).

Do not open a public issue for an unpatched vulnerability. Include, when
possible:

- the affected version or commit;
- a clear description of the impact;
- reproducible steps or a minimal proof of concept;
- suggested mitigations, if known;
- any relevant logs with credentials and personal data removed.

Please allow reasonable time for investigation and remediation before public
disclosure.

## Scope

This policy covers vulnerabilities in Olympus Security. Vulnerabilities in external
dependencies or third-party services should also be reported to their
maintainers. A dependency report may still be submitted here when it directly
affects this project.

Testing must be performed only on systems and data you own or are explicitly
authorized to test. Do not perform denial-of-service testing, access third-party
data, degrade services, or use social engineering.

## Secret scanning

Every push and pull request runs gitleaks as a blocking CI check:

- the checked-out working tree is scanned on every run;
- the complete Git history is scanned on pushes to `main` and on manual runs;
- a **canary step runs first** and plants a synthetic credential outside the
  repository. If gitleaks fails to flag it the job fails immediately, because a
  scanner that cannot find a known secret proves nothing when it later reports a
  clean tree.

Both scans run with `--redact`, so the SARIF reports carry rule names and file
locations but never secret values. They are published on every run — including
failed ones — to GitHub code scanning and as the `gitleaks-sarif` build
artifact.

If a real secret is ever committed, rotate it first: removing it from history
does not undo the disclosure.

## Responsible use

This policy does not grant authorization to test third-party infrastructure.
Users remain responsible for complying with applicable laws, licences and
written scopes of authorization.
