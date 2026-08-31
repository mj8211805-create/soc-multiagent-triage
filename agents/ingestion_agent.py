"""Alert Ingestion and Normalization Agent."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from agents.base import BaseAgent
from core.schema import AlertSource, AlertSeverity, NormalizedAlert, RawAlert
from core.state import SOCInvestigationState


class IngestionAgent(BaseAgent):
    """Ingests multi-format telemetry and normalizes it into ECS/OCSF standard schemas."""

    def __init__(self):
        super().__init__(
            name="IngestionAgent",
            role="Telemetry Parser & Schema Normalization Specialist"
        )

    def process(self, state: SOCInvestigationState) -> SOCInvestigationState:
        normalized_list: List[NormalizedAlert] = []

        for raw in state.raw_alerts:
            norm = self._normalize_single_alert(raw)
            if norm:
                normalized_list.append(norm)

        state.normalized_alerts = normalized_list
        state.current_stage = "NORMALIZATION_COMPLETE"

        # Notify Correlation Agent
        self.send_message(
            state=state,
            recipient="CorrelationAgent",
            content=f"Normalized {len(normalized_list)} alerts across {len({a.source for a in normalized_list})} telemetry sources.",
            payload={"normalized_count": len(normalized_list)}
        )

        return state

    def _normalize_single_alert(self, raw: RawAlert) -> Optional[NormalizedAlert]:
        data = raw.data
        source_type = raw.source_type.lower()
        
        # Determine source enum
        source = AlertSource.CUSTOM
        if "sysmon" in source_type:
            source = AlertSource.SYSMON
        elif "suricata" in source_type:
            source = AlertSource.SURICATA
        elif "defender" in source_type or "windows" in source_type:
            source = AlertSource.WINDOWS_DEFENDER
        elif "crowdstrike" in source_type:
            source = AlertSource.CROWDSTRIKE
        elif "zeek" in source_type:
            source = AlertSource.ZEEK
        elif "firewall" in source_type:
            source = AlertSource.FIREWALL

        # Timestamp parsing
        ts_val = data.get("timestamp") or data.get("EventTime") or data.get("@timestamp") or raw.ingested_at
        if isinstance(ts_val, str):
            try:
                timestamp = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            except Exception:
                timestamp = datetime.utcnow()
        elif isinstance(ts_val, datetime):
            timestamp = ts_val
        else:
            timestamp = datetime.utcnow()

        # Severity parsing
        sev_raw = str(data.get("severity") or data.get("Severity") or data.get("level") or "Medium").upper()
        if any(s in sev_raw for s in ["CRIT", "5", "EMERGENCY"]):
            severity = AlertSeverity.CRITICAL
        elif any(s in sev_raw for s in ["HIGH", "4"]):
            severity = AlertSeverity.HIGH
        elif any(s in sev_raw for s in ["MED", "3"]):
            severity = AlertSeverity.MEDIUM
        elif any(s in sev_raw for s in ["LOW", "2"]):
            severity = AlertSeverity.LOW
        else:
            severity = AlertSeverity.INFORMATIONAL

        alert_id = str(data.get("alert_id") or data.get("id") or raw.raw_id or f"ALT-{uuid.uuid4().hex[:8].upper()}")
        event_type = str(data.get("event_type") or data.get("EventID") or data.get("signature") or "SecurityEvent")
        description = str(data.get("description") or data.get("message") or data.get("alert_name") or f"{event_type} on {data.get('host_name', 'host')}")

        # Host & User identification
        host_id = data.get("host_id") or data.get("Computer") or data.get("host") or data.get("agent_id")
        host_name = data.get("host_name") or data.get("Hostname") or data.get("ComputerName") or host_id
        user_name = data.get("user_name") or data.get("User") or data.get("AccountName") or data.get("username")

        # Process telemetry
        process_id = data.get("process_id") or data.get("ProcessId")
        if isinstance(process_id, str) and process_id.isdigit():
            process_id = int(process_id)
        elif not isinstance(process_id, int):
            process_id = None

        process_name = data.get("process_name") or data.get("Image") or data.get("process")
        if process_name and ("\\" in str(process_name) or "/" in str(process_name)):
            process_name = str(process_name).replace("\\", "/").split("/")[-1]

        process_path = data.get("process_path") or data.get("Image") or data.get("path")
        process_command_line = data.get("process_command_line") or data.get("CommandLine") or data.get("cmd")
        parent_process_name = data.get("parent_process_name") or data.get("ParentImage")
        if parent_process_name and ("\\" in str(parent_process_name) or "/" in str(parent_process_name)):
            parent_process_name = str(parent_process_name).replace("\\", "/").split("/")[-1]

        # File & Hashes
        file_path = data.get("file_path") or data.get("TargetFilename") or data.get("file")
        file_hash_sha256 = data.get("file_hash_sha256") or data.get("Hashes", {}).get("SHA256") if isinstance(data.get("Hashes"), dict) else data.get("sha256")
        if not file_hash_sha256 and isinstance(data.get("Hashes"), str):
            # Parse Hashes: "SHA256=xxx,MD5=yyy"
            for h in data["Hashes"].split(","):
                if "sha256=" in h.lower():
                    file_hash_sha256 = h.split("=")[1].strip()

        file_hash_md5 = data.get("file_hash_md5") or data.get("md5")

        # Network telemetry
        src_ip = data.get("src_ip") or data.get("SourceIp") or data.get("src")
        dst_ip = data.get("dst_ip") or data.get("DestinationIp") or data.get("dest_ip") or data.get("dst")
        src_port = data.get("src_port") or data.get("SourcePort")
        dst_port = data.get("dst_port") or data.get("DestinationPort")
        network_protocol = data.get("network_protocol") or data.get("proto") or data.get("Protocol")

        # MITRE ATT&CK extraction
        mitre_tactics = data.get("mitre_tactics") or []
        mitre_techniques = data.get("mitre_techniques") or []
        if isinstance(mitre_tactics, str):
            mitre_tactics = [mitre_tactics]
        if isinstance(mitre_techniques, str):
            mitre_techniques = [mitre_techniques]

        return NormalizedAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            description=description,
            host_id=str(host_id) if host_id else None,
            host_name=str(host_name) if host_name else None,
            user_name=str(user_name) if user_name else None,
            process_id=process_id,
            process_name=str(process_name) if process_name else None,
            process_path=str(process_path) if process_path else None,
            process_command_line=str(process_command_line) if process_command_line else None,
            parent_process_name=str(parent_process_name) if parent_process_name else None,
            file_path=str(file_path) if file_path else None,
            file_hash_sha256=str(file_hash_sha256) if file_hash_sha256 else None,
            file_hash_md5=str(file_hash_md5) if file_hash_md5 else None,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            src_port=int(src_port) if src_port and str(src_port).isdigit() else None,
            dst_port=int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            network_protocol=str(network_protocol) if network_protocol else None,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            confidence=float(data.get("confidence", 0.7)),
            raw_payload=data
        )

    def get_execution_summary(self, state: SOCInvestigationState) -> str:
        return f"Ingested and normalized {len(state.normalized_alerts)} alerts across telemetry sources."
