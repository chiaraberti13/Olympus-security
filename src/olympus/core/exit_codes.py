"""Canonical process exit codes shared across every Olympus command.

A single, documented convention so scripts and CI can branch on *why* a
command stopped, not just whether it failed:

===  ==========================================================================
0    success
1    a finding/condition the caller may want to act on (e.g. secrets found)
2    usage or input error (bad flag, unreadable/invalid file, malformed scope)
3    blocked: the target is out of the authorized scope (and was logged)
4    refused: an authorization/consent flag was required but not given
===  ==========================================================================
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Canonical Olympus CLI exit codes (see module docstring)."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    OUT_OF_SCOPE = 3
    NOT_AUTHORIZED = 4
