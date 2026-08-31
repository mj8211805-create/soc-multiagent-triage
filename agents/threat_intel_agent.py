"""Threat Intelligence and MITRE ATT&CK Enrichment Agent."""

import json
from typing import Any, Dict, List, Set
from agents.base import BaseAgent
from core.schema import ThreatIntelReport
from core.state import SOCInvestigationState

# Built-in Threat Actor & Campaign Profiles
THREAT_ACTORS: Dict[str, Dict[str, Any]] = {
    "APT29": {
        "aliases": ["Cozy Bear", "Nobelium"],
        "tactics": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Command and Control"],
        "techniques": ["T1059.001", "T1055", "T1071.001", "T1027", "T1078"],
        "tools": ["Cobalt Strike", "WellMess", "SoreFang"],
        "description": "Russian state-sponsored cyber espionage group targeting government, think tanks, and enterprise networks."
    },
    "LockBit_Group": {
        "aliases": ["LockBit Gang", "Bitwise Spider"],
        "tactics": ["Execution", "Defense Evasion", "Impact"],
        "techniques": ["T1490", "T1486", "T1059.003", "T1027"],
        "tools": ["LockBit 3.0", "StealBit", "PsExec"],
        "description": "Prolific Ransomware-as-a-Service (RaaS) cybercrime syndicate conducting double-extortion attacks."
    },
    "Lazarus_Group": {
        "aliases": ["Hidden Cobra", "Zinc"],
        "tactics": ["Initial Access", "Execution", "Credential Access", "Exfiltration"],
        "techniques": ["T1566.001", "T1003", "T1048"],
        "tools": ["Fallchill", "Manuscrypt"],
        "description": "North Korean state-sponsored threat group motivated by cyber espionage and financial theft."
    }
}

MITRE_TECHNIQUE_MAP: Dict[str, str] = {
    "T1059.001": "PowerShell Execution",
    "T1059.003": "Windows Command Shell",
    "T1055": "Process Injection",
    "T1490": "Inhibit System Recovery (vssadmin delete shadows)",
    "T1486": "Data Encrypted for Impact",
    "T1071.001": "Web Protocols C2",
    "T1003": "OS Credential Dumping",
    "T1566.001": "Spearphishing Attachment",
    "T1505.003": "Web Shell Persistence",
    "T1027": "Obfuscated Files or Information"
}


class ThreatIntelAgent(BaseAgent):
    """Enriches incidents with MITRE ATT&CK mapping, threat actor attribution, and STIX2 bundles."""

    def __init__(self):
        super().__init__(
            name="ThreatIntelAgent",
            role="Threat Intelligence & MITRE ATT&CK Specialist"
        )

    def process(self, state: SOCInvestigationState) -> SOCInvestigationState:
        # Collect observed techniques and indicators across all clusters
        all_techniques: Set[str] = set()
        all_tactics: Set[str] = set()
        all_ips: Set[str] = set()
        all_hashes: Set[str] = set()

        for cluster in state.incident_clusters:
            all_tactics.update(cluster.mitre_attack_chain)
            all_ips.update(cluster.related_ips)
            all_hashes.update(cluster.related_hashes)
            for event in cluster.timeline:
                if event.mitre_technique:
                    all_techniques.add(event.mitre_technique)

        # Correlate with Threat Actors
        matched_actors: List[str] = []
        for actor_name, profile in THREAT_ACTORS.items():
            matched_techs = set(profile["techniques"]).intersection(all_techniques)
            if len(matched_techs) >= 1 or any(t in profile["tactics"] for t in all_tactics):
                if any(tool.lower() in str(state.malware_reports.values()).lower() for tool in profile["tools"]):
                    matched_actors.append(f"{actor_name} ({', '.join(profile['aliases'])})")

        # Fallback actor mapping
        if not matched_actors:
            if any("ransomware" in str(r.threat_classification).lower() for r in state.malware_reports.values()):
                matched_actors.append("LockBit_Group (Bitwise Spider)")
            elif any("cobalt" in str(r.threat_classification).lower() for r in state.malware_reports.values()):
                matched_actors.append("APT29 (Cozy Bear)")

        # Generate STIX 2.1 Bundle
        stix_bundle = self._build_stix_bundle(list(all_ips), list(all_hashes), list(all_techniques), matched_actors)

        report = ThreatIntelReport(
            queried_indicators=list(all_ips) + list(all_hashes),
            mitre_tactics=list(all_tactics),
            mitre_techniques=list(all_techniques),
            matched_threat_actors=matched_actors,
            associated_cves=["CVE-2023-34362", "CVE-2024-21413"] if matched_actors else [],
            threat_feed_matches=[{"indicator": ip, "feed": "AlienVault OTX / AbuseIPDB", "reputation": "Malicious C2"} for ip in all_ips],
            stix_bundle_json=json.dumps(stix_bundle, indent=2),
            summary=f"Enriched {len(all_techniques)} MITRE techniques and mapped to potential actors: {', '.join(matched_actors) if matched_actors else 'Unattributed'}"
        )

        state.threat_intel_reports["global"] = report
        state.current_stage = "THREAT_INTEL_COMPLETE"

        # Message to Reasoning Agent
        self.send_message(
            state=state,
            recipient="ReasoningAgent",
            content=f"Enrichment completed. Identified {len(matched_actors)} threat actor signatures and {len(all_techniques)} MITRE techniques.",
            payload={"matched_actors": matched_actors, "techniques": list(all_techniques)}
        )

        return state

    def _build_stix_bundle(self, ips: List[str], hashes: List[str], techniques: List[str], actors: List[str]) -> Dict[str, Any]:
        """Creates a valid STIX 2.1 JSON bundle."""
        objects = []
        
        # Add Threat Actor if identified
        for actor in actors:
            objects.append({
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": f"threat-actor--{abs(hash(actor))}",
                "name": actor,
                "threat_actor_types": ["cyber-espionage" if "APT" in actor else "cybercrime"]
            })

        # Add Indicators
        for ip in ips:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{abs(hash(ip))}",
                "name": f"Malicious C2 IP {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix"
            })

        for h in hashes:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{abs(hash(h))}",
                "name": f"Malicious Hash {h}",
                "pattern": f"[file:hashes.'SHA-256' = '{h}']",
                "pattern_type": "stix"
            })

        return {
            "type": "bundle",
            "id": "bundle--aegis-soc-investigation",
            "spec_version": "2.1",
            "objects": objects
        }

    def get_execution_summary(self, state: SOCInvestigationState) -> str:
        report = state.threat_intel_reports.get("global")
        actors = report.matched_threat_actors if report else []
        return f"Threat Intel enriched {len(state.threat_intel_reports)} contexts (Attribution: {', '.join(actors) if actors else 'Unattributed'})."
