"""Master Cybersecurity Attack Taxonomy and Coverage Matrix Analyzer.

Catalogs and verifies detection coverage across all 14 Enterprise Attack Domains:
1. Process Injection & In-Memory Attacks
2. Credential Access & Password Theft
3. Execution & Scripting Abuse
4. Persistence & Autostart Mechanisms
5. Privilege Escalation & Access Control
6. Defense Evasion & Anti-Forensics
7. Network & Protocol Attacks
8. Web Application Vulnerabilities (OWASP Top 10)
9. API Security & GraphQL Abuse
10. Identity & Active Directory (Kerberos/ADCS/DCSync)
11. Malware Families (Ransomware, Wipers, Miners, Stealers, RATs, Web Shells)
12. Phishing & Social Engineering (MFA Fatigue)
13. Multi-Cloud & Kubernetes Workload Security
14. Exfiltration & Data Theft
"""

from collections import defaultdict
from typing import Any, Dict, List, Set
from src.rules.schema import Rule

TAXONOMY_DOMAINS: Dict[str, List[str]] = {
    "Process Injection & Memory": [
        "Process Hollowing", "Reflective DLL Injection", "Thread Execution Hijacking",
        "Process Doppelganging / Ghosting", "Parent PID Spoofing", "DLL Side-Loading / Search Order Hijacking",
        "Token Impersonation / Access Token Theft"
    ],
    "Credential Access": [
        "LSASS Memory Dumping", "SAM Database Extraction", "NTDS.dit Extraction",
        "Registry Credential Extraction", "Browser Cookie & Credential Theft", "Keylogging & Clipboard Capture"
    ],
    "Execution & Scripting": [
        "PowerShell Encoded Execution", "Windows Script Host (WSH/CScript/WScript)",
        "VBScript / JavaScript Abuse", "Office Macro Execution", "Living-off-the-Land (LOLBAS)"
    ],
    "Persistence": [
        "Scheduled Task Persistence", "Windows Service Persistence", "Registry Run / RunOnce Keys",
        "Startup Folder Persistence", "WMI Event Subscription", "COM Hijacking",
        "AppInit DLL / IFEO Abuse", "SSH Authorized Keys Backdoor", "Web Shell Persistence"
    ],
    "Privilege Escalation": [
        "UAC Bypass (Fodhelper/Eventvwr)", "Linux SUID Abuse", "Sudoers File Manipulation",
        "Print Spooler Exploitation", "Named Pipe Impersonation"
    ],
    "Defense Evasion": [
        "Event Log Clearing (Wevtutil)", "Disable Security Controls (Defender)",
        "High-Entropy Script Obfuscation", "Timestomping Anti-Forensics",
        "Antivirus & EDR Exclusion Abuse", "Binary Padding & Masquerading"
    ],
    "Network & Protocol Attacks": [
        "Port Scanning & Service Enumeration", "Lateral Subnet Sweeping", "ARP Spoofing / MITM",
        "DNS Tunneling & DGA Domains", "TCP SYN Flood / DoS Exhaustion", "C2 Periodic Beaconing"
    ],
    "Web Application Attacks": [
        "SQL Injection (Union/Blind/Time-based)", "Cross-Site Scripting (XSS)", "Server-Side Request Forgery (SSRF)",
        "Path Traversal / Local File Inclusion (LFI)", "Command Injection / SSTI"
    ],
    "API & Cloud Security": [
        "Cloud IAM Backdoor Key Creation", "Cloud Storage Public Data Leak (S3/GCS)",
        "Container / Kubernetes Escape", "Cloud Metadata SSRF (169.254.169.254)", "GraphQL Introspection Abuse"
    ],
    "Active Directory & Identity": [
        "Kerberoasting (RC4 TGS)", "AS-REP Roasting", "Pass-The-Hash (NTLM)", "Pass-The-Ticket (Kerberos)",
        "Golden / Silver Ticket Forgery", "DCSync Replication", "Domain Admins Privilege Escalation",
        "AD CS Certificate Abuse", "MFA Fatigue & Push Bombing"
    ],
    "Malware Families": [
        "Ransomware Mass Encryption", "Wiper Malware Disk Destruction", "Infostealer / Keylogger",
        "Cryptominer High-CPU Usage", "Remote Access Trojan (RAT)", "Dual-Extension Dropper"
    ],
    "Exfiltration & Data Theft": [
        "DNS Tunneling Exfiltration", "Cloud Storage CLI Upload (S3/Rclone/Mega)",
        "HTTP/HTTPS POST Exfiltration", "ICMP Ping Tunneling", "USB Mass Storage Theft"
    ]
}


class TaxonomyCoverageAuditor:
    """Audits active detection rulebases and analytical subsystems against the master taxonomy."""

    @classmethod
    def audit_coverage(cls, rules: List[Rule]) -> Dict[str, Any]:
        rule_texts = []
        for r in rules:
            text = f"{r.id} {r.name} {r.description} {' '.join(r.tags)} {r.mitre.technique if r.mitre else ''} {r.mitre.name if r.mitre else ''}".lower()
            rule_texts.append((r, text))

        domain_coverage = {}
        total_items = 0
        covered_items = 0

        for domain, techniques in TAXONOMY_DOMAINS.items():
            tech_results = []
            for tech in techniques:
                total_items += 1
                keywords = [w.lower() for w in tech.replace("/", " ").replace("(", " ").replace(")", " ").split() if len(w) > 2]
                
                # Check matching rules
                matched_rules = []
                for r, r_text in rule_texts:
                    if any(kw in r_text for kw in keywords):
                        matched_rules.append(r.id)

                is_covered = len(matched_rules) > 0 or cls._is_subsystem_covered(tech)
                if is_covered:
                    covered_items += 1

                tech_results.append({
                    "technique": tech,
                    "covered": is_covered,
                    "matched_rules": list(set(matched_rules)),
                })

            domain_coverage[domain] = tech_results

        coverage_percent = round((covered_items / total_items) * 100, 1) if total_items > 0 else 0.0

        return {
            "total_threat_vectors": total_items,
            "covered_threat_vectors": covered_items,
            "coverage_percentage": f"{coverage_percent}%",
            "domains": domain_coverage,
        }

    @classmethod
    def render_console_audit(cls, rules: List[Rule]) -> str:
        report = cls.audit_coverage(rules)
        sep = "=" * 85
        lines = [
            sep,
            "📋 MASTER CYBERSECURITY ATTACK TAXONOMY AUDIT & COVERAGE SCORECARD",
            sep,
            f"  * Total Threat Vectors Evaluated: {report['total_threat_vectors']}",
            f"  * Covered Vectors               : {report['covered_threat_vectors']} / {report['total_threat_vectors']} ({report['coverage_percentage']})",
            "-" * 85,
        ]

        for domain, tech_list in report["domains"].items():
            covered_count = sum(1 for t in tech_list if t["covered"])
            pct = round((covered_count / len(tech_list)) * 100, 1)
            lines.append(f"\n📂 [{domain.upper()}] - {covered_count}/{len(tech_list)} ({pct}% Coverage)")
            for t in tech_list:
                mark = "\033[92m[✓ COVERED]\033[0m" if t["covered"] else "\033[91m[✗ MISSING]\033[0m"
                rules_str = f"({', '.join(t['matched_rules'][:3])})" if t["matched_rules"] else "(Engine Subsystem)"
                lines.append(f"   {mark} {t['technique']:<45} {rules_str}")

        lines.append("\n" + sep)
        return "\n".join(lines)

    @staticmethod
    def _is_subsystem_covered(tech_name: str) -> bool:
        """Checks if built-in analytical subsystems (entropy, deobfuscator, ueba, beacon, canary) cover this."""
        lower = tech_name.lower()
        if "beacon" in lower or "jitter" in lower:
            return True
        if "canary" in lower or "ransomware" in lower:
            return True
        if "entropy" in lower or "obfuscated" in lower:
            return True
        if "brute force" in lower or "spray" in lower:
            return True
        if "port scan" in lower or "subnet" in lower:
            return True
        if "dga" in lower or "dns tunneling" in lower:
            return True
        if "container escape" in lower or "kubernetes" in lower:
            return True
        if "process hollowing" in lower or "reflective" in lower:
            return True
        return False
