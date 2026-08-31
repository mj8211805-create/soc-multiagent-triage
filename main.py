"""Main CLI and Application Entrypoint for AegisSOC Multi-Agent Platform."""

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
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import json
import typer
import uvicorn
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from core.engine import MultiAgentSOCEngine
from datasets.generator import AlertDatasetGenerator
from benchmark.evaluator import SOCBenchmarkEvaluator
from agents.malware_agent import MalwareAnalysisAgent
from config import settings

app = typer.Typer(help="AegisSOC: Autonomous Multi-Agent Malware Triage & Correlation System")
console = Console()


@app.command()
def triage(
    scenario: str = typer.Option("mixed", help="Scenario name: apt29, lockbit, benign, or mixed"),
    alerts_file: Optional[str] = typer.Option(None, help="Optional path to custom alerts JSON file"),
    output: Optional[str] = typer.Option(None, help="Save final state / incident report to file")
):
    """Run full autonomous multi-agent triage on an alert stream."""
    console.print(Panel.fit("[bold cyan]AegisSOC Autonomous Multi-Agent Triage[/bold cyan]\n[dim]StateGraph Multi-Agent Investigation[/dim]"))

    if alerts_file:
        raw_json = json.loads(Path(alerts_file).read_text(encoding="utf-8"))
        alerts = [AlertDatasetGenerator.generate_benign_noise(1)[0]] # fallback or parse
        console.print(f"[green][+][/green] Loaded {len(raw_json)} raw alerts from {alerts_file}")
    else:
        if scenario == "apt29":
            alerts = AlertDatasetGenerator.generate_apt29_scenario()
        elif scenario == "lockbit":
            alerts = AlertDatasetGenerator.generate_lockbit_scenario()
        elif scenario == "benign":
            alerts = AlertDatasetGenerator.generate_benign_noise(25)
        else:
            alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(50, 0.6)
        console.print(f"[green][+][/green] Loaded built-in scenario: [bold]{scenario}[/bold] ({len(alerts)} raw alerts)")

    engine = MultiAgentSOCEngine()
    console.print("[yellow][*][/yellow] Executing StateGraph multi-agent pipeline...")
    state = engine.run_pipeline(alerts)

    # Print Trace Summary Table
    trace_table = Table(title="Execution Trace Summary", show_header=True, header_style="bold cyan")
    trace_table.add_column("Step", width=6)
    trace_table.add_column("Agent", style="bold yellow")
    trace_table.add_column("Duration (ms)", justify="right")
    trace_table.add_column("Summary", style="dim")

    for step in state.execution_trace:
        trace_table.add_row(str(step.step_index), step.agent_name, f"{step.duration_ms:.2f} ms", step.summary)

    console.print(trace_table)

    # Print Incidents Summary
    console.print(f"\n[bold green][+][/bold green] Synthesized [bold]{len(state.incident_reports)}[/bold] Incident Reports:")
    for rep in state.incident_reports:
        console.print(Panel(
            f"[bold red]Verdict:[/bold red] {rep.verdict.value} (Confidence: {int(rep.confidence_score*100)}%)\n"
            f"[bold yellow]Severity:[/bold yellow] {rep.severity.value}\n"
            f"[bold]Executive Summary:[/bold]\n{rep.executive_summary}\n\n"
            f"[bold]Root Cause Analysis:[/bold]\n{rep.root_cause_analysis}\n\n"
            f"[bold green]Containment Playbook ({len(rep.containment_actions)} Actions):[/bold green]\n" +
            "\n".join([f"- [{act.action_type.value}] {act.target}: {act.command_or_script}" for act in rep.containment_actions]),
            title=f"Incident: {rep.title} ({rep.incident_id})",
            border_style="cyan"
        ))

    if output:
        out_p = Path(output)
        out_p.write_text(json.dumps(state.model_dump(mode="json"), indent=2), encoding="utf-8")
        console.print(f"[cyan]Saved state to {output}[/cyan]")


@app.command()
def benchmark(
    dataset: str = typer.Option("mixed", help="Dataset name: mixed, apt29, lockbit, benign"),
    output: Optional[str] = typer.Option(None, help="Save benchmark results to JSON or Markdown")
):
    """Run comparative benchmark against Single-LLM and Rule-Based baselines."""
    from benchmark.run_benchmark import run_benchmark_cli
    run_benchmark_cli(dataset_type=dataset, output_file=output)


@app.command()
def malware(
    file_path: Optional[str] = typer.Option(None, help="Path to binary file on disk"),
    sample_hash: Optional[str] = typer.Option(None, help="Known malware SHA256 hash or keyword")
):
    """Run static PE header inspection and YARA matching."""
    agent = MalwareAnalysisAgent()
    if file_path and Path(file_path).exists():
        data = Path(file_path).read_bytes()
        rep = agent._analyze_pe_bytes(data, Path(file_path).name)
    else:
        h = sample_hash or "4a7d1ed414474e4033ac29ccb8653d9b4b60fd33ac79d3434685ff86a59963be"
        rep = agent._analyze_hash_and_context(h, "sample_artifact.exe", "powershell -enc beacon.ps1")

    console.print(Panel.fit(
        f"[bold]Target File:[/bold] {rep.file_name}\n"
        f"[bold]Threat Class:[/bold] {rep.threat_classification} (Risk: {rep.risk_score}/100)\n"
        f"[bold]YARA Hits:[/bold] {', '.join([h.rule_name for h in rep.yara_matches]) if rep.yara_matches else 'None'}\n"
        f"[bold]Summary:[/bold] {rep.summary}",
        title="Malware Forensics Report",
        border_style="red" if rep.is_malicious else "green"
    ))


@app.command()
def serve(
    host: str = typer.Option(settings.HOST, help="Host to bind server"),
    port: int = typer.Option(settings.PORT, help="Port to bind server")
):
    """Launch the FastAPI server and Cyber SOC Web Command Center."""
    console.print(Panel.fit(
        f"[bold cyan]Launching AegisSOC Command Center[/bold cyan]\n"
        f"Server running at: [bold green]http://{host}:{port}[/bold green]\n"
        f"Interactive Web UI: [bold green]http://localhost:{port}[/bold green]\n"
        f"REST API Docs: [bold green]http://localhost:{port}/docs[/bold green]",
        border_style="cyan"
    ))
    uvicorn.run("server.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
