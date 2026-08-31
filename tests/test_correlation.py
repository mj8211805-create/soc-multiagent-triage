"""Unit tests for Correlation and Clustering Agent."""

from datetime import datetime, timedelta
from core.schema import RawAlert
from core.state import SOCInvestigationState
from agents.ingestion_agent import IngestionAgent
from agents.correlation_agent import CorrelationAgent
from datasets.generator import AlertDatasetGenerator


def test_apt29_correlation_clustering():
    raw_alerts = AlertDatasetGenerator.generate_apt29_scenario()
    
    state = SOCInvestigationState(investigation_id="TEST-CORR-01", raw_alerts=raw_alerts)
    ingestion = IngestionAgent()
    correlation = CorrelationAgent()

    state = ingestion.run(state)
    state = correlation.run(state)

    assert len(state.incident_clusters) >= 1
    cluster = state.incident_clusters[0]
    assert cluster.primary_host == "FIN-WORKSTATION-04"
    assert cluster.alert_count == len(raw_alerts)
    assert "Execution" in cluster.mitre_attack_chain
    assert "185.220.101.5" in cluster.related_ips


def test_alert_burst_deduplication():
    base_time = datetime.utcnow()
    # Create 5 identical alerts within 10 seconds
    burst_raw = [
        RawAlert(
            source_type="sysmon",
            data={
                "alert_id": f"BURST-{i}",
                "event_type": "ProcessCreate",
                "timestamp": (base_time + timedelta(seconds=i*2)).isoformat(),
                "host_name": "CORP-HOST",
                "process_name": "scanner.exe",
                "dst_ip": "10.0.0.1"
            }
        )
        for i in range(5)
    ]

    state = SOCInvestigationState(investigation_id="TEST-DEDUP", raw_alerts=burst_raw)
    ingestion = IngestionAgent()
    correlation = CorrelationAgent()

    state = ingestion.run(state)
    state = correlation.run(state)

    # 5 burst duplicate alerts should be compressed to 1 unique alert
    assert state.incident_clusters[0].alert_count == 1
