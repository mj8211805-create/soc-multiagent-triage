"""Reasoning and Incident Report Synthesis Agent (LLM-Backed Lead Investigator)."""

from typing import List
from agents.base import BaseAgent
from core.schema import IncidentReport
from core.state import SOCInvestigationState
from llm.client import get_llm_client


class ReasoningAgent(BaseAgent):
    """Lead SOC Investigator synthesizing multi-modal forensic findings into human-readable incident reports."""

    def __init__(self):
        super().__init__(
            name="ReasoningAgent",
            role="Lead SOC Incident Investigator & Response Synthesizer"
        )
        self.llm_client = get_llm_client()

    def process(self, state: SOCInvestigationState) -> SOCInvestigationState:
        reports: List[IncidentReport] = []

        threat_intel = state.threat_intel_reports.get("global")

        for cluster in state.incident_clusters:
            # Filter malware reports relevant to this cluster
            relevant_malware = {
                h: r for h, r in state.malware_reports.items()
                if h in cluster.related_hashes or any(p.lower() in r.file_name.lower() for p in cluster.related_processes)
            }
            if not relevant_malware and state.malware_reports:
                relevant_malware = state.malware_reports

            # Synthesize report via LLM Reasoning
            inc_report = self.llm_client.synthesize_incident(
                cluster=cluster,
                malware_reports=relevant_malware,
                threat_intel=threat_intel,
                scratchpad=state.scratchpad
            )
            reports.append(inc_report)

        state.incident_reports = reports
        state.is_completed = True
        state.current_stage = "INVESTIGATION_COMPLETE"

        # Final broadcast message
        self.send_message(
            state=state,
            recipient="SOC_Incident_Manager",
            content=f"Investigation concluded. Generated {len(reports)} comprehensive incident triage reports with containment playbooks.",
            payload={"reports_count": len(reports)}
        )

        return state

    def get_execution_summary(self, state: SOCInvestigationState) -> str:
        rep_count = len(state.incident_reports)
        severities = [r.severity.value for r in state.incident_reports]
        return f"Synthesized {rep_count} final incident reports (Severities: {', '.join(severities) if severities else 'None'})."
