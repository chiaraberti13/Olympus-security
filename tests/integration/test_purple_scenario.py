"""End-to-end purple-team scenario: one synthetic target through the whole suite.

Exercises Argus -> Helios -> Artemis -> Apollo -> Minerva -> Vulcan against
the same "Olympus Demo Corp" target identities each module already uses
for its own `demo` command, using each module's real production code path
and its existing offline double (DemoResolver, DemoScanner, DemoClient...)
-- no real network, no Docker daemon required.

This is the capstone proof that the shared `olympus.core` contract
actually lets one investigation flow through every module while keeping
traceable ids: the same Finding/Alert objects Helios and Artemis and
Apollo produce are the ones Vulcan aggregates, ranks and reports on, and
the ones Minerva opens an incident from.
"""

from __future__ import annotations

from pathlib import Path

from olympus.apollo.alerting import generate_alerts as apollo_generate_alerts
from olympus.apollo.demo_data import demo_events
from olympus.apollo.rules import load_rules
from olympus.argus.assets import build_assets as argus_build_assets
from olympus.argus.ct import enumerate_subdomains
from olympus.argus.demo_data import DEMO_DOMAIN, DemoCtClient, DemoResolver
from olympus.argus.recon import scan_domain
from olympus.artemis.cors import analyze_cors
from olympus.artemis.demo_data import DEMO_URL
from olympus.artemis.demo_data import DemoClient as ArtemisDemoClient
from olympus.artemis.discovery import discover_content
from olympus.artemis.headers import analyze_headers
from olympus.core.enums import AssetType, IncidentStatus, Severity, Source
from olympus.core.models import Asset
from olympus.helios.alerts import build_alerts as helios_build_alerts
from olympus.helios.demo_data import DEMO_HOSTS, DemoScanner
from olympus.helios.findings import build_findings as helios_build_findings
from olympus.helios.recon import scan_host
from olympus.minerva.custody import ChainOfCustody
from olympus.minerva.incident import open_incident
from olympus.minerva.lifecycle import transition
from olympus.vulcan.pentest_report import render_report
from olympus.vulcan.risk import rank_findings

APOLLO_RULES_DIR = Path("examples/input/apollo-rules")
PROBE_ORIGIN = "https://attacker.example"


def test_purple_scenario_end_to_end() -> None:
    # --- Argus: passive recon on the demo domain -----------------------
    dns_result = scan_domain(DEMO_DOMAIN, DemoResolver())
    ct_result = enumerate_subdomains(DEMO_DOMAIN, DemoCtClient())
    argus_assets = argus_build_assets(dns_result, ct_result)
    domain_asset = next(asset for asset in argus_assets if asset.hostname == DEMO_DOMAIN)
    assert domain_asset.source == Source.ARGUS

    # --- Helios: port scan on the demo host -----------------------------
    high_risk_host = DEMO_HOSTS[1]  # deliberately exposes telnet/RDP/FTP
    host_recon = scan_host(high_risk_host, DemoScanner())
    helios_assets, helios_findings = helios_build_findings([host_recon])
    helios_alerts = helios_build_alerts(helios_findings)
    assert helios_alerts, "the demo host's high-risk ports must raise at least one alert"

    # --- Artemis: web recon on the demo site ----------------------------
    artemis_client = ArtemisDemoClient()
    web_asset = Asset(
        asset_type=AssetType.WEB_SERVER, hostname=DEMO_DOMAIN, source=Source.ARTEMIS
    )
    response = artemis_client.get(DEMO_URL, headers={"Origin": PROBE_ORIGIN})
    artemis_findings = [
        *analyze_headers(web_asset.asset_id, response),
        *analyze_cors(web_asset.asset_id, response, request_origin=PROBE_ORIGIN),
        *discover_content(web_asset.asset_id, DEMO_URL, artemis_client),
    ]
    assert artemis_findings, "the deliberately misconfigured demo site must yield findings"
    assert all(finding.asset_id == web_asset.asset_id for finding in artemis_findings)

    # --- Apollo: detection over a synthetic authentication log ----------
    rules = load_rules(APOLLO_RULES_DIR)
    events = demo_events()
    apollo_alerts = [
        alert for rule in rules for alert in apollo_generate_alerts(rule, events)
    ]
    assert apollo_alerts, "the brute-force events must trigger the demo rule"
    assert any(alert.mitre_technique_id == "T1110" for alert in apollo_alerts)

    # --- Vulcan: aggregate, dedupe (no id collisions expected), rank ----
    all_assets = [*argus_assets, *helios_assets, web_asset]
    all_findings = [*helios_findings, *artemis_findings]
    all_alerts = [*helios_alerts, *apollo_alerts]

    asset_ids = [asset.asset_id for asset in all_assets]
    assert len(asset_ids) == len(set(asset_ids)), "every module must mint distinct asset ids"

    ranked = rank_findings(all_findings)
    assert ranked[0].severity in (Severity.CRITICAL, Severity.HIGH)

    report = render_report("olympus-demo-corp-2026", all_assets, ranked, all_alerts)
    assert f"- Assets: {len(all_assets)}" in report
    assert f"- Findings: {len(ranked)}" in report
    assert f"- Alerts: {len(all_alerts)}" in report

    # --- Minerva: open the incident from the worst finding, close it ----
    worst_finding = ranked[0]
    incident = open_incident(
        "Purple scenario capstone incident",
        alerts=all_alerts,
        findings=[worst_finding],
        description="Cross-module purple exercise against the Olympus Demo Corp range.",
    )
    assert incident.finding_ids == [worst_finding.finding_id]
    assert incident.severity == worst_finding.severity

    chain = ChainOfCustody()
    chain.append(
        "Incident opened from cross-module purple scenario", reference=incident.incident_id
    )
    for status in (
        IncidentStatus.TRIAGED,
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    ):
        incident = transition(incident, status)
        chain.append(f"Incident moved to {status.value}", reference=incident.incident_id)

    assert incident.status == IncidentStatus.CLOSED
    assert incident.closed_at is not None
    assert chain.verify() is True
