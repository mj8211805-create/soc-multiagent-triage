"""Shared state and message passing models for the Multi-Agent SOC Investigation Graph."""

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from core.schema import (
    RawAlert,
    NormalizedAlert,
    IncidentCluster,
    MalwareAnalysisReport,
    ThreatIntelReport,
    IncidentReport
)


class AgentMessage(BaseModel):
    """Inter-agent message container."""
    message_id: str = Field(default_factory=lambda: f"msg-{int(datetime.utcnow().timestamp()*1000)}")
    sender_agent: str
    recipient_agent: str
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    payload: Dict[str, Any] = Field(default_factory=dict)


class ExecutionTraceStep(BaseModel):
    """Audit log step of agent execution in the StateGraph."""
    step_index: int
    agent_name: str
    action_name: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0
    status: str = "COMPLETED"  # RUNNING, COMPLETED, FAILED, SKIPPED
    summary: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class SOCInvestigationState(BaseModel):
    """Shared immutable state passed between all agents in the StateGraph."""
    investigation_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    current_stage: str = "INITIALIZED"
    is_completed: bool = False
    
    # 1. Ingestion Phase Artifacts
    raw_alerts: List[RawAlert] = Field(default_factory=list)
    normalized_alerts: List[NormalizedAlert] = Field(default_factory=list)
    
    # 2. Correlation Phase Artifacts
    incident_clusters: List[IncidentCluster] = Field(default_factory=list)
    
    # 3. Forensics & Threat Intel Artifacts
    malware_reports: Dict[str, MalwareAnalysisReport] = Field(default_factory=dict)
    threat_intel_reports: Dict[str, ThreatIntelReport] = Field(default_factory=dict)
    
    # 4. Incident Synthesis & Reporting
    incident_reports: List[IncidentReport] = Field(default_factory=list)
    
    # 5. Agent Communication & Audit Trail
    agent_messages: List[AgentMessage] = Field(default_factory=list)
    execution_trace: List[ExecutionTraceStep] = Field(default_factory=list)
    scratchpad: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

    def log_trace(self, agent_name: str, action: str, duration_ms: float, summary: str, details: Optional[Dict[str, Any]] = None, status: str = "COMPLETED") -> None:
        """Appends an execution trace entry."""
        step = ExecutionTraceStep(
            step_index=len(self.execution_trace) + 1,
            agent_name=agent_name,
            action_name=action,
            duration_ms=duration_ms,
            status=status,
            summary=summary,
            details=details or {}
        )
        self.execution_trace.append(step)

    def send_message(self, sender: str, recipient: str, content: str, payload: Optional[Dict[str, Any]] = None) -> AgentMessage:
        """Sends and registers a message in the shared communication trace."""
        msg = AgentMessage(
            sender_agent=sender,
            recipient_agent=recipient,
            content=content,
            payload=payload or {}
        )
        self.agent_messages.append(msg)
        return msg
