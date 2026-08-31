"""LLM integration and prompt layer for SOC Multi-Agent System."""

from llm.client import LLMClient, get_llm_client
from llm.prompts import SOCPrompts
from llm.mock_provider import MockCyberLLMProvider

__all__ = ["LLMClient", "get_llm_client", "SOCPrompts", "MockCyberLLMProvider"]
