"""Técnicas MITRE ATT&CK usadas por las reglas (embebidas: funciona sin conexión)."""

from __future__ import annotations

TECHNIQUES: dict[str, str] = {
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Software Packing",
    "T1036": "Masquerading",
    "T1036.005": "Match Legitimate Name or Location",
    "T1036.007": "Double File Extension",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1059.007": "JavaScript",
    "T1070": "Indicator Removal",
    "T1070.004": "File Deletion",
    "T1070.006": "Timestomp",
    "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1137": "Office Application Startup",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1204.002": "User Execution: Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1543.003": "Windows Service",
    "T1546.003": "WMI Event Subscription",
    "T1546.008": "Accessibility Features",
    "T1546.010": "AppInit DLLs",
    "T1546.012": "Image File Execution Options Injection",
    "T1546.015": "Component Object Model Hijacking",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.002": "Authentication Package",
    "T1547.004": "Winlogon Helper DLL",
    "T1547.009": "Shortcut Modification",
    "T1547.010": "Port Monitors",
    "T1556.008": "Network Provider DLL",
    "T1564.003": "Hidden Window",
}

# Categoría de autorunsc → (técnica, peso base). Lo infrecuente en un PC pesa más.
PERSISTENCE: dict[str, tuple[str, int]] = {
    "logon": ("T1547.001", 5),
    "tasks": ("T1053.005", 10),
    "scheduled tasks": ("T1053.005", 10),
    "services": ("T1543.003", 10),
    "drivers": ("T1543.003", 15),
    "wmi": ("T1546.003", 40),
    "image hijacks": ("T1546.012", 40),
    "winlogon": ("T1547.004", 30),
    "appinit": ("T1546.010", 35),
    "explorer": ("T1546.015", 10),
    "lsa providers": ("T1547.002", 40),
    "print monitors": ("T1547.010", 35),
    "boot execute": ("T1547.001", 35),
    "office": ("T1137", 25),
    "network providers": ("T1556.008", 35),
}


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, TECHNIQUES.get(tid.split(".")[0], ""))


def attack_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
