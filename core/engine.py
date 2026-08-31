"""Multi-Agent StateGraph Orchestrator Engine for SOC Incident Triage."""

import uuid
import time
import asyncio
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from core.schema import RawAlert
from core.state import SOCInvestigationState
from agents.ingestion_agent import IngestionAgent
from agents.correlation_agent import CorrelationAgent
from agents.malware_agent import MalwareAnalysisAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.reasoning_agent import ReasoningAgent


class MultiAgentSOCEngine:
    """Coordinates agent execution, state transitions, message passing, and event streaming."""

    def __init__(self):
        self.ingestion_agent = IngestionAgent()
        self.correlation_agent = CorrelationAgent()
        self.malware_agent = MalwareAnalysisAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.reasoning_agent = ReasoningAgent()

    def run_pipeline(
        self,
        raw_alerts: List[RawAlert],
        binary_payloads: Optional[Dict[str, bytes]] = None,
        on_step_callback: Optional[Callable[[str, SOCInvestigationState], None]] = None
    ) -> SOCInvestigationState:
        """Synchronously executes the full multi-agent triage DAG."""
        state = SOCInvestigationState(
            investigation_id=f"INV-{uuid.uuid4().hex[:8].upper()}",
            raw_alerts=raw_alerts,
            scratchpad={"binary_payloads": binary_payloads or {}}
        )

        pipeline_agents = [
            self.ingestion_agent,
            self.correlation_agent,
            self.malware_agent,
            self.threat_intel_agent,
            self.reasoning_agent
        ]

        for agent in pipeline_agents:
            if on_step_callback:
                on_step_callback(f"START_{agent.name}", state)
            
            state = agent.run(state)
            
            if on_step_callback:
                on_step_callback(f"FINISH_{agent.name}", state)

        return state

    async def run_pipeline_async(
        self,
        raw_alerts: List[RawAlert],
        binary_payloads: Optional[Dict[str, bytes]] = None,
        on_step_callback: Optional[Callable[[str, SOCInvestigationState], None]] = None
    ) -> SOCInvestigationState:
        """Asynchronously executes the multi-agent triage pipeline."""
        state = SOCInvestigationState(
            investigation_id=f"INV-{uuid.uuid4().hex[:8].upper()}",
            raw_alerts=raw_alerts,
            scratchpad={"binary_payloads": binary_payloads or {}}
        )

        # Stage 1: Ingestion
        if on_step_callback: on_step_callback("START_IngestionAgent", state)
        state = self.ingestion_agent.run(state)
        if on_step_callback: on_step_callback("FINISH_IngestionAgent", state)

        # Stage 2: Correlation
        if on_step_callback: on_step_callback("START_CorrelationAgent", state)
        state = self.correlation_agent.run(state)
        if on_step_callback: on_step_callback("FINISH_CorrelationAgent", state)

        # Stage 3: Parallel Forensics & Threat Intel
        if on_step_callback: on_step_callback("START_Forensics_Layer", state)
        state = self.malware_agent.run(state)
        state = self.threat_intel_agent.run(state)
        if on_step_callback: on_step_callback("FINISH_Forensics_Layer", state)

        # Stage 4: Synthesis Reasoning
        if on_step_callback: on_step_callback("START_ReasoningAgent", state)
        state = self.reasoning_agent.run(state)
        if on_step_callback: on_step_callback("FINISH_ReasoningAgent", state)

        return state
