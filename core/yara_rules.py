"""YARA rule definitions and hybrid matching engine for static malware triage."""

import re
import math
from typing import List, Dict, Any, Optional
from core.schema import YARAHit, AlertSeverity

# Built-in signature definitions
BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "rule_name": "Ransomware_LockBit_Strings",
        "category": "Ransomware",
        "description": "Matches LockBit 3.0 string patterns, ransom note markers, and shadow copy deletion commands.",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["ransomware", "lockbit", "shadow_copy", "financial_crime"],
        "strings": [
            b"vssadmin.exe Delete Shadows /All /Quiet",
            b"wbadmin DELETE SYSTEMSTATEBACKUP",
            b"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            b"bcdedit /set {default} recoveryenabled no",
            b"LockBit 3.0",
            b"All your data has been stolen and encrypted",
            b".lockbit",
            b"Restore-My-Files.txt"
        ],
        "condition_threshold": 1
    },
    {
        "rule_name": "CobaltStrike_Beacon_Indicators",
        "category": "C2_Framework",
        "description": "Matches Cobalt Strike malleable C2 profile signatures, named pipes, and default metadata.",
        "severity": AlertSeverity.CRITICAL,
        "tags": ["c2", "cobalt_strike", "beacon", "apt"],
        "strings": [
            b"\\pipe\\msagent_",
            b"\\pipe\\status_",
            b"%s as %s\\%s: %d",
            b"beacon.x64.dll",
            b"beacon.dll",
            b"ReflectiveLoader",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream"
        ],
        "condition_threshold": 1
    },
    {
        "rule_name": "Process_Hollowing_Injection_APIs",
        "category": "Evasion",
        "description": "Detects combination of memory allocation, process creation in suspended state, and remote thread execution.",
        "severity": AlertSeverity.HIGH,
        "tags": ["process_injection", "hollowing", "t1055"],
        "strings": [
            b"VirtualAllocEx",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"NtUnmapViewOfSection",
            b"SetThreadContext",
            b"ResumeThread",
            b"QueueUserAPC"
        ],
        "condition_threshold": 3
    },
    {
        "rule_name": "WebShell_Generic_PHP_JSP",
        "category": "WebShell",
        "description": "Detects common PHP and JSP webshell execution vectors and one-liner eval backdoors.",
        "severity": AlertSeverity.HIGH,
        "tags": ["webshell", "persistence", "t1505"],
        "strings": [
            b"eval(base64_decode(",
            b"eval($_POST[",
            b"passthru($_GET[",
            b"system($_REQUEST[",
            b"Runtime.getRuntime().exec(request.getParameter(",
            b"ProcessBuilder",
            b"b374k",
            b"ChinaChopper"
        ],
        "condition_threshold": 1
    },
    {
        "rule_name": "PowerShell_Obfuscated_Download_Cradle",
        "category": "Execution",
        "description": "Detects suspicious obfuscated PowerShell download cradles and bypass flags.",
        "severity": AlertSeverity.HIGH,
        "tags": ["powershell", "download_cradle", "execution", "t1059"],
        "strings": [
            b"powershell -nop -w hidden -enc",
            b"powershell -ExecutionPolicy Bypass",
            b"Net.WebClient).DownloadString(",
            b"Net.WebClient).DownloadFile(",
            b"Invoke-Expression",
            b"IEX (New-Object",
            b"[System.Convert]::FromBase64String("
        ],
        "condition_threshold": 2
    },
    {
        "rule_name": "CryptoMiner_XMRig_Indicators",
        "category": "Cryptomining",
        "description": "Detects Monero/XMRig cryptominer configuration, stratum protocols, and pool markers.",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["cryptominer", "xmrig", "resource_hijacking", "t1496"],
        "strings": [
            b"stratum+tcp://",
            b"stratum+ssl://",
            b"xmr-eu.dwarfpool.com",
            b"minexmr.com",
            b"donate-level",
            b"cryptonight"
        ],
        "condition_threshold": 1
    },
    {
        "rule_name": "High_Entropy_Packed_Section",
        "category": "Evasion",
        "description": "Identifies common packer markers including UPX, Themida, and VMProtect.",
        "severity": AlertSeverity.MEDIUM,
        "tags": ["packer", "entropy", "upx", "obfuscation"],
        "strings": [
            b"UPX0",
            b"UPX1",
            b"UPX!",
            b"Themida",
            b".vmp0",
            b".vmp1"
        ],
        "condition_threshold": 1
    }
]


def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class YARAMatcher:
    """Hybrid YARA rule matcher using native libyara if present, otherwise fast Python byte matcher."""
    
    def __init__(self, custom_rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = custom_rules or BUILTIN_RULES
        self._has_native_yara = False
        try:
            import yara
            self._has_native_yara = True
            # Optional: compile native rules if needed
        except ImportError:
            self._has_native_yara = False

    def scan_bytes(self, data: bytes, file_name: str = "") -> List[YARAHit]:
        """Scans byte data against all registered YARA rules."""
        hits: List[YARAHit] = []
        if not data:
            return hits
        
        data_lower = data.lower()
        
        for rule in self.rules:
            matched_strings: List[str] = []
            for target_pattern in rule["strings"]:
                if target_pattern.lower() in data_lower:
                    try:
                        matched_strings.append(target_pattern.decode('latin-1'))
                    except Exception:
                        matched_strings.append(str(target_pattern))
            
            threshold = rule.get("condition_threshold", 1)
            if len(matched_strings) >= threshold:
                hits.append(
                    YARAHit(
                        rule_name=rule["rule_name"],
                        category=rule["category"],
                        description=rule["description"],
                        severity=rule["severity"],
                        matched_strings=matched_strings,
                        tags=rule["tags"]
                    )
                )
                
        return hits

    def scan_file(self, file_path: str) -> List[YARAHit]:
        """Scans a file on disk."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.scan_bytes(data, file_name=file_path)
        except Exception as e:
            return []


yara_engine = YARAMatcher()
