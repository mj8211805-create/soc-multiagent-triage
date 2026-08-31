"""Abstract Base Class for all autonomous SOC agents."""

import time
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from core.state import SOCInvestigationState

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class providing lifecycle management, tracing, and inter-agent communication."""

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role

    def run(self, state: SOCInvestigationState) -> SOCInvestigationState:
        """Executes the agent logic with timing, trace recording, and exception handling."""
        start_time = time.perf_counter()
        logger.info(f"[{self.name}] Beginning stage processing (Role: {self.role})...")
        
        try:
            state = self.process(state)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            summary = self.get_execution_summary(state)
            state.log_trace(
                agent_name=self.name,
                action=f"{self.name}.process",
                duration_ms=round(duration_ms, 2),
                summary=summary,
                status="COMPLETED"
            )
            logger.info(f"[{self.name}] Completed in {duration_ms:.2f}ms: {summary}")
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            err_msg = f"Error in {self.name}: {str(e)}"
            logger.error(err_msg, exc_info=True)
            state.errors.append(err_msg)
            state.log_trace(
                agent_name=self.name,
                action=f"{self.name}.process",
                duration_ms=round(duration_ms, 2),
                summary=err_msg,
                status="FAILED"
            )
            raise e

        return state

    @abstractmethod
    def process(self, state: SOCInvestigationState) -> SOCInvestigationState:
        """Core logic to be implemented by child agent."""
        pass

    def get_execution_summary(self, state: SOCInvestigationState) -> str:
        """Returns brief summary of what this agent accomplished in the state."""
        return f"{self.name} finished processing."

    def send_message(
        self,
        state: SOCInvestigationState,
        recipient: str,
        content: str,
        payload: Optional[Dict[str, Any]] = None
    ) -> None:
        """Utility to post an inter-agent message to the state graph."""
        state.send_message(
            sender=self.name,
            recipient=recipient,
            content=content,
            payload=payload
        )
