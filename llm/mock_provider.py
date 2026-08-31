"""Deterministic cybersecurity domain reasoning provider for offline execution and reproducible benchmarks."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from core.schema import (
    IncidentCluster,
    MalwareAnalysisReport,
    ThreatIntelReport,
    IncidentReport,
    AlertSeverity,
    Verdict,
    ContainmentAction,
    ActionType,
    TimelineEvent
)


class MockCyberLLMProvider:
    """Simulates high-capability LLM cybersecurity reasoning deterministically."""

    def synthesize_incident_report(
        self,
        cluster: IncidentCluster,
        malware_reports: Dict[str, MalwareAnalysisReport],
        threat_intel: Optional[ThreatIntelReport],
        scratchpad: Optional[Dict[str, Any]] = None
    ) -> IncidentReport:
        """Synthesizes an in-depth SOC Incident Report from correlated cluster artifacts."""
        
        # Analyze indicators across cluster and malware
        has_ransomware = any(
            "ransomware" in str(r.yara_matches).lower() or "lockbit" in str(r.threat_classification).lower()
            for r in malware_reports.values()
        ) or any("ransomware" in str(e).lower() or "vssadmin" in str(e).lower() for e in cluster.related_processes)
        
        has_c2_beacon = any(
            "beacon" in str(r.yara_matches).lower() or "cobalt" in str(r.threat_classification).lower()
            for r in malware_reports.values()
        ) or any("cobalt" in str(t).lower() or "c2" in str(t).lower() for t in cluster.mitre_attack_chain)
        
        has_webshell = any("webshell" in str(t).lower() for t in cluster.mitre_attack_chain) or any("eval(" in str(p) for p in cluster.related_processes)
        
        is_benign = "benign" in cluster.title.lower() or ("powershell" in cluster.title.lower() and "admin" in cluster.title.lower() and not has_ransomware and not has_c2_beacon)
        
        # Determine Verdict & Severity
        if is_benign:
            verdict = Verdict.BENIGN_TRUE_ALARM
            severity = AlertSeverity.LOW
            confidence = 0.92
            exec_summary = (
                f"Investigation of incident cluster '{cluster.title}' confirms authorized administrative activity. "
                f"Routine system management commands were executed by {cluster.primary_user or 'Administrator'} "
                f"on host {cluster.primary_host or 'WORKSTATION-01'} with no indicators of compromise or malicious persistence."
            )
            root_cause = "Scheduled IT administrative task / maintenance script execution."
            blast_radius = "Zero impact. No unauthorized lateral movement or data exfiltration detected."
            actions = [
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-1",
                    action_type=ActionType.MONITOR_ONLY,
                    target=cluster.primary_host or "System",
                    command_or_script="# No isolation required. Logging baseline updated.",
                    priority=3,
                    description="Update SIEM alert rule whitelist for legitimate maintenance scripts."
                )
            ]
        elif has_ransomware:
            verdict = Verdict.TRUE_POSITIVE
            severity = AlertSeverity.CRITICAL
            confidence = 0.98
            exec_summary = (
                f"CRITICAL INCIDENT: Confirmed Ransomware outbreak on host {cluster.primary_host or 'ENDPOINT-01'}. "
                f"Malicious payload executed shadow copy deletion, attempted file encryption, and connected to external C2. "
                f"Immediate host isolation and credential revocation required."
            )
            root_cause = "Execution of suspicious payload via phishing attachment or compromised service leading to Volume Shadow Copy deletion."
            blast_radius = f"Host {cluster.primary_host or 'ENDPOINT-01'}, User {cluster.primary_user or 'User'}, Network shares attached to subnet."
            actions = [
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-1",
                    action_type=ActionType.HOST_ISOLATION,
                    target=cluster.primary_host or "ENDPOINT-01",
                    command_or_script=f"Set-NetIPInterface -InterfaceAlias 'Ethernet0' -Dhcp Disabled; Disable-NetAdapter -Name 'Ethernet0' -Confirm:$false",
                    priority=1,
                    description="Isolate infected endpoint from the corporate LAN to prevent lateral worm propagation."
                ),
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-2",
                    action_type=ActionType.PROCESS_TERMINATION,
                    target=cluster.related_processes[0] if cluster.related_processes else "lockbit.exe",
                    command_or_script=f"Stop-Process -Name '{cluster.related_processes[0] if cluster.related_processes else 'ransomware'}' -Force",
                    priority=1,
                    description="Immediately terminate ransomware worker process."
                ),
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-3",
                    action_type=ActionType.IP_BLOCK,
                    target=cluster.related_ips[0] if cluster.related_ips else "185.220.101.5",
                    command_or_script=f"New-NetFirewallRule -DisplayName 'Block C2 Outbound' -Direction Outbound -RemoteAddress {cluster.related_ips[0] if cluster.related_ips else '185.220.101.5'} -Action Block",
                    priority=2,
                    description="Block external C2 communication at perimeter firewall."
                )
            ]
        elif has_c2_beacon:
            verdict = Verdict.TRUE_POSITIVE
            severity = AlertSeverity.HIGH
            confidence = 0.95
            exec_summary = (
                f"HIGH SEVERITY: Advanced Persistent Threat (APT) activity detected on {cluster.primary_host or 'HOST-01'}. "
                f"Cobalt Strike / C2 beaconing behavior observed following memory injection and remote thread creation."
            )
            root_cause = "Process injection (T1055) into legitimate Windows processes (rundll32/svchost) establishing persistent HTTPS C2."
            blast_radius = f"Endpoint {cluster.primary_host or 'HOST-01'}, User session {cluster.primary_user or 'CORP_USER'}."
            actions = [
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-1",
                    action_type=ActionType.HOST_ISOLATION,
                    target=cluster.primary_host or "HOST-01",
                    command_or_script="Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; New-NetFirewallRule -DisplayName 'Quarantine' -Direction Inbound,Outbound -Action Block",
                    priority=1,
                    description="Quarantine compromised host to enable live memory forensics."
                ),
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-2",
                    action_type=ActionType.ACCOUNT_DISABLE,
                    target=cluster.primary_user or "compromised_user",
                    command_or_script=f"Disable-ADAccount -Identity '{cluster.primary_user or 'compromised_user'}'",
                    priority=2,
                    description="Revoke Active Directory account privileges and invalidate active Kerberos tickets."
                )
            ]
        else:
            verdict = Verdict.TRUE_POSITIVE if cluster.cluster_severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL] else Verdict.SUSPICIOUS
            severity = cluster.cluster_severity
            confidence = 0.88
            exec_summary = (
                f"Security Incident Triage completed for cluster '{cluster.title}'. "
                f"Detected multi-stage suspicious activity across {cluster.alert_count} correlated alerts on {cluster.primary_host or 'monitored assets'}."
            )
            root_cause = f"Correlated sequence matching MITRE tactics: {', '.join(cluster.mitre_attack_chain) if cluster.mitre_attack_chain else 'Initial Access -> Execution'}."
            blast_radius = f"Host: {cluster.primary_host or 'Local Host'}, IPs: {', '.join(cluster.related_ips[:3]) if cluster.related_ips else 'Internal Subnet'}."
            actions = [
                ContainmentAction(
                    action_id=f"act-{int(datetime.utcnow().timestamp())}-1",
                    action_type=ActionType.PROCESS_TERMINATION if cluster.related_processes else ActionType.IP_BLOCK,
                    target=cluster.related_processes[0] if cluster.related_processes else (cluster.related_ips[0] if cluster.related_ips else "10.0.0.1"),
                    command_or_script="Stop-Process -Name 'powershell' -Force" if cluster.related_processes else "iptables -A INPUT -s $TARGET -j DROP",
                    priority=1,
                    description="Mitigate active execution vector."
                )
            ]

        # Assemble STIX 2.1 Bundle representation
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{cluster.cluster_id}",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "incident",
                    "id": f"incident--{cluster.cluster_id}",
                    "name": cluster.title,
                    "severity": severity.value,
                    "confidence": int(confidence * 100),
                    "labels": ["soc-triage", verdict.value.lower()]
                }
            ]
        }

        # Build timeline from cluster
        timeline = cluster.timeline if cluster.timeline else [
            TimelineEvent(
                timestamp=cluster.created_at,
                event_type="CorrelatedIncident",
                description=f"Aggregated {cluster.alert_count} alerts into unified incident graph",
                entities=[cluster.primary_host or "host", cluster.primary_user or "user"],
                severity=severity
            )
        ]

        return IncidentReport(
            incident_id=f"INC-{cluster.cluster_id.upper()}",
            title=f"[{severity.value.upper()}] {cluster.title}",
            status="TriageComplete",
            severity=severity,
            confidence_score=confidence,
            verdict=verdict,
            executive_summary=exec_summary,
            root_cause_analysis=root_cause,
            blast_radius=blast_radius,
            affected_hosts=[cluster.primary_host] if cluster.primary_host else ["Unknown"],
            affected_users=[cluster.primary_user] if cluster.primary_user else ["Unknown"],
            identified_iocs=cluster.related_hashes + cluster.related_ips,
            mitre_kill_chain=cluster.mitre_attack_chain if cluster.mitre_attack_chain else ["Execution", "Defense Evasion"],
            attack_timeline=timeline,
            malware_findings=list(malware_reports.values()),
            threat_intel=threat_intel,
            containment_actions=actions,
            stix_bundle=stix_bundle,
            analyst_notes="Automated multi-agent synthesis completed with high confidence."
        )
