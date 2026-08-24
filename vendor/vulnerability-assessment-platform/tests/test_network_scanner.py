"""Test dello scanner di rete (Nmap potenziato) e della categoria 'Rete'."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanners.nmap_scanner import NmapScanner
from scanner_engine import (
    NetworkNmapScanner,
    SCANNERS_MAP,
    SCAN_TYPE_PROFILES,
    get_scanner_classes,
)
from scan_catalog import SCAN_CATALOG, get_scan_catalog, get_tool_descriptions


NMAP_XML_WITH_CVE = """
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34"/>
    <hostnames><hostname name="example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
        <script id="vulners" output="cpe:/a:nginx:nginx:1.18.0:&#10;  CVE-2021-23017  7.5  https://vulners.com/cve/CVE-2021-23017"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_parser_extracts_cves_from_nse_scripts():
    findings = NmapScanner()._parse_nmap_xml(NMAP_XML_WITH_CVE)
    script_findings = [f for f in findings if f.get("cve")]
    assert script_findings, "Nessun finding con CVE estratte dagli script NSE"
    assert "CVE-2021-23017" in script_findings[0]["cve"]
    # Le CVE rilevate dagli script vuln/vulners alzano la severità.
    assert script_findings[0]["severity"] == "high"


def test_network_nmap_scanner_uses_service_profile_and_vuln_scripts():
    command = NetworkNmapScanner()._build_command("example.com", "service")
    assert "--script" in command
    script_index = command.index("--script")
    assert command[script_index + 1] == "vulners,vuln"
    assert "-sV" in command  # rilevamento servizio/versione richiesto da vulners
    assert command[-1] == "example.com"


def test_network_profile_resolves_to_network_scanners():
    assert "network" in SCAN_TYPE_PROFILES
    classes = get_scanner_classes("network")
    assert NetworkNmapScanner in classes
    assert SCANNERS_MAP["testssl"] in classes


def test_simulated_nmap_finding_carries_cve_for_enrichment():
    result = NmapScanner(enable_live_scans=False).run("https://demo.local")
    assert result["status"] == "simulated"
    cves = [cve for f in result["findings"] for cve in f.get("cve", [])]
    assert "CVE-2021-23017" in cves


def test_scan_catalog_uses_three_macro_categories():
    categories = {entry["category"] for entry in get_scan_catalog()}
    assert categories <= {"Web", "Web App", "Rete"}, f"Categorie inattese: {categories}"
    # Devono esistere tutte e tre le macro-categorie.
    assert {"Web", "Web App", "Rete"} <= categories


def test_network_scan_present_in_catalog_and_modules_have_descriptions():
    assert "network" in SCAN_CATALOG
    assert SCAN_CATALOG["network"].category == "Rete"
    descriptions = get_tool_descriptions()
    assert descriptions.get("nmap_network", "").strip()
