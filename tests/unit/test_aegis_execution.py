"""Tests for the AEGIS native scanner execution layer.

Adapter parsers are tested against REAL captured native output (fixtures below
were produced by running the tools against a local lab target). Orchestration,
scope/SSRF, the runner, config, and the registry are tested directly. No mock
is used as evidence of end-to-end functionality — that lives in
``docs/aegis-execution-evidence.md``.
"""

from __future__ import annotations

import pytest

from olympus.aegis.adapters.nikto import NiktoAdapter
from olympus.aegis.adapters.nmap import NmapAdapter
from olympus.aegis.adapters.sqlmap import SqlmapAdapter
from olympus.aegis.adapters.testssl import TestsslAdapter
from olympus.aegis.adapters.wafw00f import Wafw00fAdapter
from olympus.aegis.base import NotAuthorizedError, ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandError, CommandOutput, CommandTimeout, run_command
from olympus.aegis.scope import (
    OutOfScopeError,
    SsrfBlockedError,
    TargetValidationError,
    ensure_allowed,
    host_of,
)
from olympus.aegis.states import ExecutionState
from olympus.core.enums import Severity

# --- real captured fixtures (trimmed) ------------------------------------- #
NMAP_XML = (
    '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
    '<address addr="127.0.0.1" addrtype="ipv4"/>'
    '<ports><port protocol="tcp" portid="8000"><state state="open"/>'
    '<service name="http" product="Apache httpd" version="2.4.29"/></port>'
    '<port protocol="tcp" portid="23"><state state="open"/>'
    '<service name="telnet"/></port></ports></host></nmaprun>'
)
NIKTO_TXT = (
    "+ Target IP:          127.0.0.1\n"
    "+ Server: Apache/2.4.29 (Ubuntu)\n"
    "+ The anti-clickjacking X-Frame-Options header is not present.\n"
    "+ OSVDB-1201: /cgi/cgiproc?: It may be possible to crash ...\n"
    "+ 6544 items checked: 0 error(s) and 2 item(s) reported on remote host\n"
)
WAFW00F_JSON = '[{"detected": true, "firewall": "Cloudflare", "url": "http://x"}]'
WAFW00F_NONE = '[{"detected": false, "firewall": "None", "url": "http://x"}]'
SQLMAP_VULN = "[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing?"
SQLMAP_SAFE = "[WARNING] GET parameter 'id' does not seem to be injectable"
TESTSSL_JSON = '[{"id":"BEAST","severity":"LOW","finding":"VULNERABLE (CVE-2011-3389)"}]'


def _out(stdout: str = "", stderr: str = "", code: int = 0) -> CommandOutput:
    return CommandOutput(exit_code=code, stdout=stdout, stderr=stderr)


def _req(**kw: object) -> ScanRequest:
    base: dict[str, object] = {"scanner": "x", "target": "127.0.0.1", "allowed": ("127.0.0.1",)}
    base.update(kw)
    return ScanRequest(**base)  # type: ignore[arg-type]


# --- scope / SSRF ---------------------------------------------------------- #
def test_host_of_variants() -> None:
    assert host_of("url", "https://example.com/a") == "example.com"
    assert host_of("host", "Example.COM") == "example.com"
    with pytest.raises(TargetValidationError):
        host_of("host", "bad/host")


def test_scope_in_and_out() -> None:
    assert ensure_allowed("domain", "api.example.com", ("example.com",)) == "api.example.com"
    with pytest.raises(OutOfScopeError):
        ensure_allowed("domain", "evil.test", ("example.com",))


def test_scope_ssrf_guard_and_authorized_lab() -> None:
    with pytest.raises(SsrfBlockedError):
        ensure_allowed("host", "127.0.0.1", ("example.com",))
    # Explicitly authorized loopback lab target is intentional and allowed.
    assert ensure_allowed("host", "127.0.0.1", ("127.0.0.1",)) == "127.0.0.1"


# --- runner ---------------------------------------------------------------- #
def test_runner_executes_real_process() -> None:
    out = run_command(["printf", "hello"], timeout=10)
    assert out.exit_code == 0
    assert "hello" in out.stdout


def test_runner_timeout() -> None:
    with pytest.raises(CommandTimeout):
        run_command(["sleep", "5"], timeout=1)


def test_runner_missing_binary() -> None:
    with pytest.raises(CommandError):
        run_command(["definitely-not-a-real-binary-xyz"], timeout=5)


# --- adapter parsers against real fixtures --------------------------------- #
def test_nmap_parser() -> None:
    findings = NmapAdapter().parse(_out(NMAP_XML), "127.0.0.1", _req())
    titles = [f.title for f in findings]
    assert any("8000" in t for t in titles)
    # Telnet (high-risk port) is elevated above INFO.
    telnet = next(f for f in findings if "23/tcp" in f.title)
    assert telnet.severity == Severity.MEDIUM


def test_nmap_parser_rejects_garbage() -> None:
    with pytest.raises(ParseError):
        NmapAdapter().parse(_out("not xml"), "127.0.0.1", _req())


def test_nikto_parser_skips_metadata() -> None:
    findings = NiktoAdapter().parse(_out(NIKTO_TXT), "127.0.0.1", _req())
    titles = " ".join(f.title for f in findings)
    assert "X-Frame-Options" in titles
    assert "OSVDB-1201" in titles
    assert "Target IP" not in titles and "items checked" not in titles


def test_wafw00f_parser_detected_and_none() -> None:
    assert Wafw00fAdapter().parse(_out(WAFW00F_JSON), "x", _req())
    assert Wafw00fAdapter().parse(_out(WAFW00F_NONE), "x", _req()) == []


def test_sqlmap_parser_vuln_vs_safe() -> None:
    vuln = SqlmapAdapter().parse(_out(SQLMAP_VULN), "x", _req())
    assert vuln and vuln[0].severity == Severity.CRITICAL
    assert SqlmapAdapter().parse(_out(SQLMAP_SAFE), "x", _req()) == []


def test_testssl_parser() -> None:
    findings = TestsslAdapter().parse(_out(TESTSSL_JSON), "x", _req())
    assert findings and findings[0].severity == Severity.LOW


# --- base orchestration (explicit states) ---------------------------------- #
class _FakeAdapter(ScannerAdapter):
    name = "fake"
    binary = "true"  # exists on PATH, exits 0
    install = "n/a"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        return ["true"]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list:  # type: ignore[type-arg]
        from olympus.core.enums import Source
        from olympus.core.models import Finding

        return [Finding(asset_id=self.asset_id(host), source=Source.AEGIS, title="live finding")]


def test_state_simulation_is_opt_in_only() -> None:
    result = _FakeAdapter().run(_req(scanner="fake", simulate=True))
    assert result.state is ExecutionState.SIMULATION
    assert "[SIMULATION]" in result.findings[0].title


def test_state_disabled_when_live_off() -> None:
    result = _FakeAdapter().run(_req(scanner="fake", authorized=True, live_enabled=False))
    assert result.state is ExecutionState.DISABLED
    assert result.findings == []


def test_state_unavailable_when_binary_missing() -> None:
    class _Missing(_FakeAdapter):
        binary = "definitely-not-a-real-binary-xyz"

    result = _Missing().run(_req(scanner="fake", authorized=True, live_enabled=True))
    assert result.state is ExecutionState.UNAVAILABLE
    assert result.dependency is not None
    assert result.findings == []


def test_state_live_runs_real_process() -> None:
    result = _FakeAdapter().run(_req(scanner="fake", authorized=True, live_enabled=True))
    assert result.state is ExecutionState.LIVE
    assert result.findings and result.findings[0].title == "live finding"


def test_state_failed_on_parse_error() -> None:
    class _Bad(_FakeAdapter):
        def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list:  # type: ignore[type-arg]
            raise ParseError("boom")

    result = _Bad().run(_req(scanner="fake", authorized=True, live_enabled=True))
    assert result.state is ExecutionState.FAILED
    assert "boom" in (result.error or "")


def test_not_authorized_raises() -> None:
    with pytest.raises(NotAuthorizedError):
        _FakeAdapter().run(_req(scanner="fake", authorized=False, live_enabled=True))


def test_out_of_scope_raises() -> None:
    with pytest.raises(OutOfScopeError):
        _FakeAdapter().run(_req(scanner="fake", target="evil.test", allowed=("example.com",),
                                authorized=True, live_enabled=True))


# --- registry / config ----------------------------------------------------- #
def test_registry() -> None:
    from olympus.aegis.registry import UnknownScannerError, get_adapter, implemented

    assert set(implemented()) == {"nmap", "nikto", "wafw00f", "sqlmap", "whatweb", "testssl"}
    assert get_adapter("nmap").name == "nmap"
    with pytest.raises(UnknownScannerError):
        get_adapter("subfinder")


def test_config_aegis_and_vap_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    from olympus.aegis import config

    monkeypatch.delenv("AEGIS_ENABLE_LIVE_SCANS", raising=False)
    monkeypatch.setenv("VAP_ENABLE_LIVE_SCANS", "true")
    assert config.live_enabled() is True  # legacy fallback honored
    monkeypatch.setenv("AEGIS_ENABLE_LIVE_SCANS", "false")
    assert config.live_enabled() is False  # AEGIS_* takes precedence
