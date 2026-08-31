"""API routes for SOC alert ingestion, multi-agent triage, malware analysis, and benchmarking."""

import json
import base64
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from core.schema import (
    RawAlert,
    IncidentReport,
    MalwareAnalysisReport,
    BenchmarkMetrics
)
from core.state import SOCInvestigationState
from core.engine import MultiAgentSOCEngine
from datasets.generator import AlertDatasetGenerator
from benchmark.evaluator import SOCBenchmarkEvaluator
from agents.malware_agent import MalwareAnalysisAgent

router = APIRouter(prefix="/api")
engine = MultiAgentSOCEngine()
evaluator = SOCBenchmarkEvaluator()
malware_agent = MalwareAnalysisAgent()


class PipelineRunRequest(BaseModel):
    scenario_name: Optional[str] = None
    alerts: Optional[List[Dict[str, Any]]] = None
    total_noise_alerts: Optional[int] = 20


class MalwareAnalyzeRequest(BaseModel):
    file_name: str = "suspicious_sample.exe"
    base64_data: Optional[str] = None
    command_line: Optional[str] = None
    file_hash_sha256: Optional[str] = None


class BenchmarkRunRequest(BaseModel):
    dataset_name: str = "mixed"
    total_alerts: int = 50
    noise_ratio: float = 0.6


@router.get("/health")
async def health_check():
    return {
        "status": "online",
        "service": "AegisSOC Multi-Agent Platform",
        "version": "1.0.0",
        "agents": [
            "IngestionAgent",
            "CorrelationAgent",
            "MalwareAnalysisAgent",
            "ThreatIntelAgent",
            "ReasoningAgent"
        ]
    }


@router.get("/scenarios")
async def list_scenarios():
    return {
        "scenarios": [
            {
                "id": "apt29",
                "name": "APT29 (Cozy Bear) Cyber Espionage",
                "description": "Multi-stage intrusion: Spearphishing -> PowerShell Cradle -> Process Injection -> C2 Beaconing.",
                "threat_actor": "APT29 / Cozy Bear",
                "expected_severity": "High"
            },
            {
                "id": "lockbit",
                "name": "LockBit 3.0 Ransomware Outbreak",
                "description": "Shadow copy destruction, boot recovery disablement, file encryption, and ransom note drop.",
                "threat_actor": "LockBit Syndicate",
                "expected_severity": "Critical"
            },
            {
                "id": "benign",
                "name": "Enterprise IT Background Noise",
                "description": "Authorized administrative scripts, backup tasks, Windows Defender scans, and vulnerability probes.",
                "threat_actor": "Authorized Sysadmin / Benign",
                "expected_severity": "Low"
            },
            {
                "id": "mixed",
                "name": "Mixed Real-World Enterprise Stream",
                "description": "Realistic noisy SOC alert feed containing active APT & Ransomware attacks interspersed with high-volume benign noise.",
                "threat_actor": "Multiple Actors + Benign Noise",
                "expected_severity": "Critical"
            }
        ]
    }


@router.get("/scenarios/{scenario_id}")
async def get_scenario_alerts(scenario_id: str):
    if scenario_id == "apt29":
        alerts = AlertDatasetGenerator.generate_apt29_scenario()
    elif scenario_id == "lockbit":
        alerts = AlertDatasetGenerator.generate_lockbit_scenario()
    elif scenario_id == "benign":
        alerts = AlertDatasetGenerator.generate_benign_noise(20)
    elif scenario_id == "mixed":
        alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(50, 0.6)
    else:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    return {"scenario_id": scenario_id, "total_alerts": len(alerts), "alerts": [a.model_dump(mode="json") for a in alerts]}


@router.post("/pipeline/run")
async def run_triage_pipeline(req: PipelineRunRequest):
    raw_alerts: List[RawAlert] = []

    if req.alerts:
        for item in req.alerts:
            raw_alerts.append(RawAlert(source_type=item.get("source_type", "generic"), data=item))
    elif req.scenario_name:
        s_id = req.scenario_name.lower()
        if s_id == "apt29":
            raw_alerts = AlertDatasetGenerator.generate_apt29_scenario()
        elif s_id == "lockbit":
            raw_alerts = AlertDatasetGenerator.generate_lockbit_scenario()
        elif s_id == "benign":
            raw_alerts = AlertDatasetGenerator.generate_benign_noise(req.total_noise_alerts or 20)
        else:
            raw_alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(req.total_noise_alerts or 50)
    else:
        raw_alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(40)

    # Execute Multi-Agent StateGraph
    state = engine.run_pipeline(raw_alerts)
    return state.model_dump(mode="json")


@router.post("/malware/analyze")
async def analyze_malware_sample(req: MalwareAnalyzeRequest):
    if req.base64_data:
        try:
            raw_bytes = base64.b64decode(req.base64_data)
            report = malware_agent._analyze_pe_bytes(raw_bytes, req.file_name)
            return report.model_dump(mode="json")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse binary data: {str(e)}")
    elif req.file_hash_sha256 or req.command_line:
        sha256 = req.file_hash_sha256 or "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        report = malware_agent._analyze_hash_and_context(sha256, req.file_name, req.command_line)
        return report.model_dump(mode="json")
    else:
        raise HTTPException(status_code=400, detail="Must provide base64_data, file_hash_sha256, or command_line")


@router.post("/benchmark/run")
async def run_benchmark(req: BenchmarkRunRequest):
    if req.dataset_name == "apt29":
        alerts = AlertDatasetGenerator.generate_apt29_scenario()
        name = "APT29_Campaign"
    elif req.dataset_name == "lockbit":
        alerts = AlertDatasetGenerator.generate_lockbit_scenario()
        name = "LockBit3_Outbreak"
    elif req.dataset_name == "benign":
        alerts = AlertDatasetGenerator.generate_benign_noise(req.total_alerts)
        name = "Benign_Admin_Stream"
    else:
        alerts, _ = AlertDatasetGenerator.generate_mixed_dataset(req.total_alerts, req.noise_ratio)
        name = f"Mixed_Enterprise_Stream_{req.total_alerts}_Alerts"

    metrics = evaluator.evaluate(alerts, dataset_name=name)
    return metrics.model_dump(mode="json")
