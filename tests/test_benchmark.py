"""Unit tests for Benchmark Suite and comparative metrics."""

from benchmark.evaluator import SOCBenchmarkEvaluator
from datasets.generator import AlertDatasetGenerator


def test_benchmark_evaluator_execution():
    evaluator = SOCBenchmarkEvaluator()
    alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(total_alerts=30, noise_ratio=0.5)

    results = evaluator.evaluate(alerts, dataset_name="Test_Stream")

    assert results.total_raw_alerts == len(alerts)
    assert results.multi_agent_system.f1_score >= 0.8
    assert results.multi_agent_system.alert_compression_ratio > 0.0
    assert results.single_llm_baseline is not None
    assert results.rule_based_baseline is not None

    md_report = evaluator.generate_markdown_report(results)
    assert "# SOC Multi-Agent Triage Evaluation Report" in md_report
