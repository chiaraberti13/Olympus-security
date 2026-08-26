# Third-party notices and licence scope

This repository is a multi-licence source distribution.

| Component | Location | Licence | Source revision |
| --- | --- | --- | --- |
| Olympus native code | `src/olympus/` | MIT, root `LICENSE` | this repository |
| ARGUS | `vendor/argus/` | MIT, component `LICENSE` | `1c7a8310ee64e005878dfa183ca8a384760706c6` |
| Vulnerability Assessment Platform / AEGIS | `vendor/vulnerability-assessment-platform/` | GPL-3.0-only, component `LICENSE` | `6c6b395d79f358372e028fe7094cc673374dd88f` |

Each vendored component retains its complete licence file. The root MIT
licence applies only to Olympus-owned material and does not relicense vendored
code. Distribution or modification of the GPL component must comply with GNU
GPL version 3, including corresponding-source and notice obligations.

The projects listed in `docs/reference-implementations.md` were reviewed for
functional ideas only. Their source code is not vendored or imported into the
native implementation described there.
