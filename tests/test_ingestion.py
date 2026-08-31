"""Unit tests for alert ingestion and normalization agent."""

from datetime import datetime
from core.schema import RawAlert, AlertSource, AlertSeverity
from core.state import SOCInvestigationState
from agents.ingestion_agent import IngestionAgent


def test_sysmon_alert_normalization():
    agent = IngestionAgent()
    state = SOCInvestigationState(
        investigation_id="TEST-01",
        raw_alerts=[
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "SYS-101",
                    "EventID": 1,
                    "event_type": "ProcessCreate",
                    "timestamp": "2026-08-31T12:00:00Z",
                    "host_name": "WIN-SRV-01",
                    "user_name": "CORP\\admin",
                    "process_name": "powershell.exe",
                    "process_command_line": "powershell.exe -enc SQBFAFgA",
                    "file_hash_sha256": "4a7d1ed414474e4033ac29ccb8653d9b4b60fd33ac79d3434685ff86a59963be",
                    "severity": "High",
                    "mitre_tactics": ["Execution"],
                    "mitre_techniques": ["T1059.001"]
                }
            )
        ]
    )

    state = agent.run(state)

    assert len(state.normalized_alerts) == 1
    norm = state.normalized_alerts[0]
    assert norm.source == AlertSource.SYSMON
    assert norm.severity == AlertSeverity.HIGH
    assert norm.host_name == "WIN-SRV-01"
    assert norm.process_name == "powershell.exe"
    assert norm.mitre_tactics == ["Execution"]
    assert norm.mitre_techniques == ["T1059.001"]


def test_suricata_alert_normalization():
    agent = IngestionAgent()
    state = SOCInvestigationState(
        investigation_id="TEST-02",
        raw_alerts=[
            RawAlert(
                source_type="suricata",
                data={
                    "alert_id": "SURI-201",
                    "signature": "ET TROJAN Cobalt Strike Beacon Observed",
                    "src_ip": "10.0.1.5",
                    "dst_ip": "185.220.101.5",
                    "src_port": 49152,
                    "dst_port": 443,
                    "severity": "Critical"
                }
            )
        ]
    )

    state = agent.run(state)
    assert len(state.normalized_alerts) == 1
    norm = state.normalized_alerts[0]
    assert norm.source == AlertSource.SURICATA
    assert norm.severity == AlertSeverity.CRITICAL
    assert norm.dst_ip == "185.220.101.5"
