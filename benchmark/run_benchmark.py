"""CLI runner for automated benchmark evaluations."""

import sys
from pathlib import Path

# Configure utf-8 encoding for Windows console if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datasets.generator import AlertDatasetGenerator
from benchmark.evaluator import SOCBenchmarkEvaluator

console = Console()


def run_benchmark_cli(dataset_type: str = "mixed", output_file: str = None):
    console.print(Panel.fit("[bold cyan]AegisSOC Multi-Agent Benchmark Suite[/bold cyan]\n[dim]Evaluating Multi-Agent vs Single-LLM vs Rule-Based SIEM[/dim]"))

    # Load / Generate Alerts
    if dataset_type == "apt29":
        alerts = AlertDatasetGenerator.generate_apt29_scenario()
        name = "APT29_Spearphishing_C2"
    elif dataset_type == "lockbit":
        alerts = AlertDatasetGenerator.generate_lockbit_scenario()
        name = "LockBit3_Ransomware_Outbreak"
    elif dataset_type == "benign":
        alerts = AlertDatasetGenerator.generate_benign_noise(30)
        name = "Enterprise_Admin_Benign_Stream"
    else:
        alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(total_alerts=50, noise_ratio=0.6)
        name = "Mixed_Enterprise_SOC_Stream"

    console.print(f"[green][+][/green] Loaded scenario [bold]{name}[/bold] with [bold]{len(alerts)}[/bold] raw alerts.")

    evaluator = SOCBenchmarkEvaluator()
    console.print("[yellow][*][/yellow] Running comparative baseline evaluations...")
    results = evaluator.evaluate(alerts, dataset_name=name)

    # Render Table
    table = Table(title="Comparative Benchmark Performance Matrix", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim", width=25)
    table.add_column("Multi-Agent System", style="green", justify="right")
    table.add_column("Single-LLM Direct", style="yellow", justify="right")
    table.add_column("Rule-Based SIEM", style="cyan", justify="right")

    ma = results.multi_agent_system
    sl = results.single_llm_baseline
    rb = results.rule_based_baseline

    table.add_row("Precision", f"{ma.precision:.4f}", f"{sl.precision:.4f}", f"{rb.precision:.4f}")
    table.add_row("Recall", f"{ma.recall:.4f}", f"{sl.recall:.4f}", f"{rb.recall:.4f}")
    table.add_row("F1-Score", f"[bold]{ma.f1_score:.4f}[/bold]", f"{sl.f1_score:.4f}", f"{rb.f1_score:.4f}")
    table.add_row("Accuracy", f"{ma.accuracy:.4f}", f"{sl.accuracy:.4f}", f"{rb.accuracy:.4f}")
    table.add_row("Alert Compression", f"[bold]{ma.alert_compression_ratio:.1f}%[/bold]", f"{sl.alert_compression_ratio:.1f}%", f"{rb.alert_compression_ratio:.1f}%")
    table.add_row("FP Reduction Rate", f"[bold]{ma.false_positive_reduction_rate:.1f}%[/bold]", f"{sl.false_positive_reduction_rate:.1f}%", f"{rb.false_positive_reduction_rate:.1f}%")
    table.add_row("Latency (ms)", f"{ma.avg_latency_ms:.1f} ms", f"{sl.avg_latency_ms:.1f} ms", f"{rb.avg_latency_ms:.1f} ms")
    table.add_row("Tokens Used", f"{ma.total_tokens_used:,}", f"{sl.total_tokens_used:,}", f"{rb.total_tokens_used}")

    console.print(table)
    console.print(f"\n[bold green][+][/bold green] {results.summary_analysis}")

    if output_file:
        out_p = Path(output_file)
        if out_p.suffix == ".md":
            out_p.write_text(evaluator.generate_markdown_report(results), encoding="utf-8")
        else:
            out_p.write_text(json.dumps(results.model_dump(mode="json"), indent=2), encoding="utf-8")
        console.print(f"[cyan]Results saved to {output_file}[/cyan]")


if __name__ == "__main__":
    run_benchmark_cli()
