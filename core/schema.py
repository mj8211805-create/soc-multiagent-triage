"""Standard schema definitions for SOC Multi-Agent Triage and Alert Correlation System."""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class AlertSource(str, Enum):
    SYSMON = "Sysmon"
    SURICATA = "Suricata"
    WINDOWS_DEFENDER = "WindowsDefender"
    CROWDSTRIKE = "CrowdStrike"
    ZEEK = "Zeek"
    LINUX_AUDIT = "LinuxAudit"
    FIREWALL = "Firewall"
    CUSTOM = "Custom"


class AlertSeverity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Verdict(str, Enum):
    TRUE_POSITIVE = "TruePositive"
    FALSE_POSITIVE = "FalsePositive"
    BENIGN_TRUE_ALARM = "BenignTrueAlarm"
    SUSPICIOUS = "Suspicious"
    INCONCLUSIVE = "Inconclusive"


class ActionType(str, Enum):
    HOST_ISOLATION = "HostIsolation"
    PROCESS_TERMINATION = "ProcessTermination"
    IP_BLOCK = "IPBlock"
    DOMAIN_BLOCK = "DomainBlock"
    ACCOUNT_DISABLE = "AccountDisable"
    YARA_DEPLOYMENT = "YaraDeployment"
    PATCH_VULNERABILITY = "PatchVulnerability"
    MONITOR_ONLY = "MonitorOnly"


class RawAlert(BaseModel):
    """Raw unprocessed alert from any telemetry source."""
    raw_id: Optional[str] = None
    source_type: str = "generic"
    data: Dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)


class NormalizedAlert(BaseModel):
    """Standardized alert following ECS/OCSF schema."""
    alert_id: str
    timestamp: datetime
    source: AlertSource
    event_type: str
    severity: AlertSeverity
    description: str
    
    # Host & Identity
    host_id: Optional[str] = None
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    
    # Process Telemetry
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_command_line: Optional[str] = None
    parent_process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_command_line: Optional[str] = None
    
    # File & Hash Telemetry
    file_path: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_hash_md5: Optional[str] = None
    
    # Network Telemetry
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    network_protocol: Optional[str] = None
    dns_query: Optional[str] = None
    http_uri: Optional[str] = None
    
    # MITRE ATT&CK
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    
    # Additional Metadata
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    """Chronological event representation in an attack timeline."""
    timestamp: datetime
    event_type: str
    description: str
    entities: List[str] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    alert_ref: Optional[str] = None


class IncidentCluster(BaseModel):
    """Correlated cluster of alerts forming a single incident."""
    cluster_id: str
    title: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    alert_ids: List[str] = Field(default_factory=list)
    alert_count: int = 0
    primary_host: Optional[str] = None
    primary_user: Optional[str] = None
    related_ips: List[str] = Field(default_factory=list)
    related_hashes: List[str] = Field(default_factory=list)
    related_processes: List[str] = Field(default_factory=list)
    mitre_attack_chain: List[str] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    cluster_severity: AlertSeverity = AlertSeverity.MEDIUM
    correlation_score: float = Field(default=0.8, ge=0.0, le=1.0)
    initial_access_vector: Optional[str] = None


class PESectionInfo(BaseModel):
    """PE binary section metadata and entropy metrics."""
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: List[str] = Field(default_factory=list)
    is_suspicious: bool = False


class PEAnalysisResult(BaseModel):
    """Static PE header and disassembly inspection details."""
    file_name: str
    file_size_bytes: int
    sha256: str
    md5: str
    imphash: Optional[str] = None
    compile_timestamp: Optional[str] = None
    architecture: str = "x86_64"
    entry_point: Optional[str] = None
    is_dll: bool = False
    is_packed: bool = False
    max_entropy: float = 0.0
    sections: List[PESectionInfo] = Field(default_factory=list)
    suspicious_imports: List[str] = Field(default_factory=list)
    detected_capabilities: List[str] = Field(default_factory=list)


class YARAHit(BaseModel):
    """YARA signature match result."""
    rule_name: str
    category: str
    description: str
    severity: AlertSeverity
    matched_strings: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class BehavioralObservation(BaseModel):
    """Observed runtime or sandbox behavior."""
    category: str
    description: str
    severity: AlertSeverity
    mitre_technique: Optional[str] = None


class MalwareAnalysisReport(BaseModel):
    """Comprehensive malware analysis synthesis."""
    sha256: str
    file_name: str
    file_type: str = "PE32/PE32+"
    is_malicious: bool
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    threat_classification: str = "Benign"
    static_analysis: Optional[PEAnalysisResult] = None
    yara_matches: List[YARAHit] = Field(default_factory=list)
    behavioral_observations: List[BehavioralObservation] = Field(default_factory=list)
    extracted_iocs: List[str] = Field(default_factory=list)
    summary: str = ""


class ThreatIntelReport(BaseModel):
    """Enriched threat intelligence context."""
    queried_indicators: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    matched_threat_actors: List[str] = Field(default_factory=list)
    associated_cves: List[str] = Field(default_factory=list)
    threat_feed_matches: List[Dict[str, Any]] = Field(default_factory=list)
    stix_bundle_json: Optional[str] = None
    summary: str = ""


class ContainmentAction(BaseModel):
    """Actionable remediation or containment step for SOC analysts."""
    action_id: str
    action_type: ActionType
    target: str
    command_or_script: str
    priority: int = 1
    description: str
    rollback_command: Optional[str] = None


class IncidentReport(BaseModel):
    """Final synthesized SOC incident investigation report."""
    incident_id: str
    title: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "TriageComplete"
    severity: AlertSeverity
    confidence_score: float = Field(default=0.9, ge=0.0, le=1.0)
    verdict: Verdict
    
    # Executive & Root Cause
    executive_summary: str
    root_cause_analysis: str
    blast_radius: str
    
    # Technical Evidence
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    identified_iocs: List[str] = Field(default_factory=list)
    mitre_kill_chain: List[str] = Field(default_factory=list)
    attack_timeline: List[TimelineEvent] = Field(default_factory=list)
    
    # Forensics & Threat Intel
    malware_findings: List[MalwareAnalysisReport] = Field(default_factory=list)
    threat_intel: Optional[ThreatIntelReport] = None
    
    # Response Playbook
    containment_actions: List[ContainmentAction] = Field(default_factory=list)
    stix_bundle: Optional[Dict[str, Any]] = None
    analyst_notes: Optional[str] = None


class BaselineMetrics(BaseModel):
    """Performance metrics for an individual triage method."""
    method_name: str
    total_alerts_processed: int = 0
    incidents_generated: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    alert_compression_ratio: float = 0.0
    false_positive_reduction_rate: float = 0.0
    avg_latency_ms: float = 0.0
    total_tokens_used: int = 0
    cost_usd: float = 0.0


class BenchmarkMetrics(BaseModel):
    """Comparative benchmark results across all triage baselines."""
    dataset_name: str
    total_raw_alerts: int
    benchmark_timestamp: datetime = Field(default_factory=datetime.utcnow)
    multi_agent_system: BaselineMetrics
    single_llm_baseline: BaselineMetrics
    rule_based_baseline: BaselineMetrics
    summary_analysis: str
