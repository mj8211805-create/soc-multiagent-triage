"""SOC Multi-Agent System Agent implementations."""

from agents.base import BaseAgent
from agents.ingestion_agent import IngestionAgent
from agents.correlation_agent import CorrelationAgent
from agents.malware_agent import MalwareAnalysisAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.reasoning_agent import ReasoningAgent

__all__ = [
    "BaseAgent",
    "IngestionAgent",
    "CorrelationAgent",
    "MalwareAnalysisAgent",
    "ThreatIntelAgent",
    "ReasoningAgent"
]
