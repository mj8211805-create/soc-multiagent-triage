"""Integration tests for MultiAgentSOCEngine pipeline orchestration."""

from core.engine import MultiAgentSOCEngine
from datasets.generator import AlertDatasetGenerator
from core.schema import Verdict, AlertSeverity


def test_full_pipeline_apt29_scenario():
    engine = MultiAgentSOCEngine()
    alerts = AlertDatasetGenerator.generate_apt29_scenario()

    state = engine.run_pipeline(alerts)

    assert state.is_completed is True
    assert state.current_stage == "INVESTIGATION_COMPLETE"
    assert len(state.normalized_alerts) == len(alerts)
    assert len(state.incident_clusters) >= 1
    assert len(state.incident_reports) >= 1

    report = state.incident_reports[0]
    assert report.verdict == Verdict.TRUE_POSITIVE
    assert report.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    assert len(report.containment_actions) >= 1
    assert len(state.agent_messages) >= 3


def test_full_pipeline_lockbit_scenario():
    engine = MultiAgentSOCEngine()
    alerts = AlertDatasetGenerator.generate_lockbit_scenario()

    state = engine.run_pipeline(alerts)

    assert state.is_completed is True
    assert len(state.incident_reports) >= 1
    report = state.incident_reports[0]
    assert report.verdict == Verdict.TRUE_POSITIVE
    assert report.severity == AlertSeverity.CRITICAL
    assert any("isolation" in a.action_type.value.lower() for a in report.containment_actions)
