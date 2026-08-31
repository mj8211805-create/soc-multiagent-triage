"""Alert Correlation and Incident Graph Clustering Agent."""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Set
from collections import defaultdict
from agents.base import BaseAgent
from core.schema import (
    NormalizedAlert,
    IncidentCluster,
    TimelineEvent,
    AlertSeverity
)
from core.state import SOCInvestigationState
from config import settings


class CorrelationAgent(BaseAgent):
    """Correlates individual normalized alerts into unified incident clusters using temporal graph linkage."""

    def __init__(self):
        super().__init__(
            name="CorrelationAgent",
            role="Temporal & Entity Graph Correlation Specialist"
        )
        self.time_window = timedelta(minutes=settings.CORRELATION_TIME_WINDOW_MINUTES)

    def process(self, state: SOCInvestigationState) -> SOCInvestigationState:
        alerts = state.normalized_alerts
        if not alerts:
            state.incident_clusters = []
            return state

        # Step 1: Deduplicate redundant alert bursts
        deduped_alerts = self._deduplicate_alerts(alerts)
        
        # Step 2: Sort chronologically
        sorted_alerts = sorted(deduped_alerts, key=lambda a: a.timestamp)

        # Step 3: Cluster alerts by entity linkages & temporal proximity
        clusters = self._cluster_alerts(sorted_alerts)

        state.incident_clusters = clusters
        state.current_stage = "CORRELATION_COMPLETE"

        # Notify downstream agents
        total_clusters = len(clusters)
        self.send_message(
            state=state,
            recipient="MalwareAnalysisAgent",
            content=f"Formed {total_clusters} correlated incident clusters from {len(alerts)} alerts.",
            payload={"cluster_count": total_clusters}
        )
        self.send_message(
            state=state,
            recipient="ThreatIntelAgent",
            content=f"Formed {total_clusters} correlated incident clusters for threat enrichment.",
            payload={"cluster_count": total_clusters}
        )

        return state

    def _deduplicate_alerts(self, alerts: List[NormalizedAlert]) -> List[NormalizedAlert]:
        """Filters out high-frequency identical alerts occurring within 30 seconds."""
        unique_alerts: List[NormalizedAlert] = []
        seen_signatures: Dict[str, datetime] = {}

        for a in alerts:
            # Create a signature key from core event attributes
            sig = f"{a.source.value}:{a.event_type}:{a.host_name}:{a.process_name}:{a.dst_ip}:{a.file_hash_sha256}"
            if sig in seen_signatures:
                delta = abs((a.timestamp - seen_signatures[sig]).total_seconds())
                if delta < 30.0:
                    continue  # Drop burst duplicate
            
            seen_signatures[sig] = a.timestamp
            unique_alerts.append(a)

        return unique_alerts

    def _cluster_alerts(self, alerts: List[NormalizedAlert]) -> List[IncidentCluster]:
        """Partitions alerts into incident clusters based on shared hosts, IPs, hashes, or users."""
        assigned_cluster: Dict[str, str] = {}
        cluster_groups: Dict[str, List[NormalizedAlert]] = defaultdict(list)

        for alert in alerts:
            matched_cluster_id = None
            
            # Check if this alert shares entities with any existing cluster
            for c_id, c_alerts in cluster_groups.items():
                if self._alerts_are_linked(alert, c_alerts):
                    matched_cluster_id = c_id
                    break

            if matched_cluster_id:
                cluster_groups[matched_cluster_id].append(alert)
                assigned_cluster[alert.alert_id] = matched_cluster_id
            else:
                new_id = f"clus-{uuid.uuid4().hex[:6]}"
                cluster_groups[new_id].append(alert)
                assigned_cluster[alert.alert_id] = new_id

        # Build IncidentCluster objects
        result_clusters: List[IncidentCluster] = []
        for c_id, c_alerts in cluster_groups.items():
            cluster_obj = self._build_cluster_object(c_id, c_alerts)
            result_clusters.append(cluster_obj)

        return result_clusters

    def _alerts_are_linked(self, alert: NormalizedAlert, cluster_alerts: List[NormalizedAlert]) -> bool:
        """Determines if an alert belongs to an existing cluster group."""
        latest_time = max(a.timestamp for a in cluster_alerts)
        if abs(alert.timestamp - latest_time) > self.time_window:
            return False

        for ca in cluster_alerts:
            # Host match
            if alert.host_name and ca.host_name and alert.host_name.lower() == ca.host_name.lower():
                return True
            if alert.host_id and ca.host_id and alert.host_id == ca.host_id:
                return True
            # User match
            if alert.user_name and ca.user_name and alert.user_name.lower() == ca.user_name.lower() and alert.user_name.lower() not in ["system", "local service", "network service"]:
                return True
            # Hash match
            if alert.file_hash_sha256 and ca.file_hash_sha256 and alert.file_hash_sha256 == ca.file_hash_sha256:
                return True
            # External C2 IP match
            if alert.dst_ip and ca.dst_ip and alert.dst_ip == ca.dst_ip and not alert.dst_ip.startswith("127."):
                return True

        return False

    def _build_cluster_object(self, cluster_id: str, alerts: List[NormalizedAlert]) -> IncidentCluster:
        """Synthesizes high-level metadata and attack chain for an alert group."""
        hosts: Set[str] = {a.host_name for a in alerts if a.host_name}
        users: Set[str] = {a.user_name for a in alerts if a.user_name}
        ips: Set[str] = {a.dst_ip for a in alerts if a.dst_ip and not a.dst_ip.startswith("127.")}
        hashes: Set[str] = {a.file_hash_sha256 for a in alerts if a.file_hash_sha256}
        processes: Set[str] = {a.process_name for a in alerts if a.process_name}
        
        # MITRE ATT&CK progression
        mitre_tactics: List[str] = []
        for a in alerts:
            for t in a.mitre_tactics:
                if t not in mitre_tactics:
                    mitre_tactics.append(t)

        # Build timeline
        timeline: List[TimelineEvent] = []
        for a in alerts:
            mitre_tech = a.mitre_techniques[0] if a.mitre_techniques else None
            entities = []
            if a.host_name: entities.append(a.host_name)
            if a.process_name: entities.append(a.process_name)
            if a.dst_ip: entities.append(a.dst_ip)
            
            timeline.append(
                TimelineEvent(
                    timestamp=a.timestamp,
                    event_type=a.event_type,
                    description=a.description,
                    entities=entities,
                    mitre_technique=mitre_tech,
                    severity=a.severity,
                    alert_ref=a.alert_id
                )
            )

        # Max severity
        severities = [a.severity for a in alerts]
        if AlertSeverity.CRITICAL in severities:
            cluster_sev = AlertSeverity.CRITICAL
        elif AlertSeverity.HIGH in severities:
            cluster_sev = AlertSeverity.HIGH
        elif AlertSeverity.MEDIUM in severities:
            cluster_sev = AlertSeverity.MEDIUM
        else:
            cluster_sev = AlertSeverity.LOW

        primary_host = next(iter(hosts)) if hosts else "UnknownHost"
        primary_user = next(iter(users)) if users else "System"

        # Generate descriptive title
        if any("ransomware" in a.description.lower() or "lockbit" in a.description.lower() for a in alerts):
            title = f"Ransomware Deployment & Shadow Copy Deletion on {primary_host}"
        elif any("beacon" in a.description.lower() or "cobalt" in a.description.lower() for a in alerts):
            title = f"C2 Beaconing & Memory Injection on {primary_host}"
        elif any("powershell" in str(a.process_command_line).lower() and "admin" in primary_user.lower() for a in alerts):
            title = f"Administrative PowerShell Script Execution on {primary_host}"
        else:
            title = f"Multi-Stage Suspicious Activity Cluster on {primary_host}"

        return IncidentCluster(
            cluster_id=cluster_id,
            title=title,
            alert_ids=[a.alert_id for a in alerts],
            alert_count=len(alerts),
            primary_host=primary_host,
            primary_user=primary_user,
            related_ips=list(ips),
            related_hashes=list(hashes),
            related_processes=list(processes),
            mitre_attack_chain=mitre_tactics if mitre_tactics else ["Execution"],
            timeline=timeline,
            cluster_severity=cluster_sev,
            correlation_score=round(min(0.99, 0.65 + len(alerts) * 0.05), 2),
            initial_access_vector="Phishing / Execution" if mitre_tactics else "Process Execution"
        )

    def get_execution_summary(self, state: SOCInvestigationState) -> str:
        orig_count = len(state.normalized_alerts)
        clus_count = len(state.incident_clusters)
        reduction = ((orig_count - clus_count) / orig_count * 100.0) if orig_count > 0 else 0.0
        return f"Clustered {orig_count} alerts into {clus_count} incidents ({reduction:.1f}% alert reduction)."
