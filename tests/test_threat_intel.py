"""Unit tests for Threat Intel Agent and STIX2 export."""

from core.schema import NormalizedAlert, IncidentCluster, AlertSource, AlertSeverity
from core.state import SOCInvestigationState
from agents.threat_intel_agent import ThreatIntelAgent


def test_threat_intel_enrichment():
    agent = ThreatIntelAgent()
    cluster = IncidentCluster(
        cluster_id="c-test",
        title="APT29 Test Cluster",
        primary_host="HOST-1",
        related_ips=["185.220.101.5"],
        related_hashes=["4a7d1ed414474e4033ac29ccb8653d9b4b60fd33ac79d3434685ff86a59963be"],
        mitre_attack_chain=["Initial Access", "Command and Control"],
        alert_count=2
    )

    state = SOCInvestigationState(
        investigation_id="TEST-INTEL",
        incident_clusters=[cluster]
    )

    state = agent.run(state)
    assert "global" in state.threat_intel_reports
    report = state.threat_intel_reports["global"]
    assert "185.220.101.5" in report.queried_indicators
    assert report.stix_bundle_json is not None
    assert "bundle" in report.stix_bundle_json
