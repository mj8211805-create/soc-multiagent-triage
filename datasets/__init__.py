"""Dataset generation and benchmark scenarios for SOC multi-agent system."""

from datasets.generator import AlertDatasetGenerator
from datasets.malware_samples import create_test_pe_binary, create_test_ransomware_payload

__all__ = ["AlertDatasetGenerator", "create_test_pe_binary", "create_test_ransomware_payload"]
