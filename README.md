# 👁️ eyedetect — Enterprise Cyber Threat Detection & Automated Response Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://www.python.org/)
[![Tests: 40 Passed](https://img.shields.io/badge/Tests-40%20Passed%20(100%25)-success.svg)](tests/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-12%2F12%20Tactics%20Covered-orange.svg)](rules/)
[![Project Status](https://img.shields.io/badge/Status-Active%20Capstone%20Development-yellow.svg)](#-project-status--research-disclaimer)

A cross-domain Endpoint, Identity, Network, and Cloud Threat Detection & Automated Remediation Engine (EDR / XDR) designed in Python.

---

## ⚠️ Project Status & Research Disclaimer

> **📌 PLEASE NOTE: ACTIVE CAPSTONE RESEARCH & DEVELOPMENT PROTOTYPE**
> 
> * This project is an **academic capstone engineering prototype** currently undergoing active, continuous development and evaluation.
> * While the core detection engine, unit test suite (40/40 tests), and rulebase are validated, **it is not a finalized commercial build**.
> * Ongoing research updates, experimental detection modules, and performance refactors are pushed frequently. Minor environment-specific quirks or edge-case variations may occur during testing across different operating systems.
> * Feedback, bug reports, and research discussions are welcomed via GitHub Issues.

---

## 🧪 How to Test & Verify (Step-by-Step Guide)

Follow these steps to set up, test, and evaluate `eyedetect` on any Windows, macOS, or Linux environment:

### 📋 Prerequisites
* Python 3.9, 3.10, 3.11, or newer installed.
* Git installed.

---

### Step 1: Clone the Repository
Open PowerShell or your system terminal and clone the repository:
```bash
git clone https://github.com/Adityasingh230058/eyedetect.git
cd eyedetect
```

---

### Step 2: Install Dependencies
Install the required lightweight packages:
```bash
pip install -r requirements.txt
```
*(Dependencies: `pydantic`, `pyyaml`, `pytest`)*

> 💡 **Windows Tip**: If `python` opens the Microsoft Store or shows an alias error, run using your direct Python path (e.g., `py -m pip install -r requirements.txt` or `& "C:\Users\<user>\anaconda3\python.exe"`).

---

### Step 3: Run the Automated Engine Test Suite
Run the automated test suite to verify math algorithms, deobfuscators, process trees, and detection logic:
```bash
pytest -v tests/
```
* **Expected Result**: `40 passed in ~4s` (100% pass rate across all 8 test modules).

---

### Step 4: Run the Master Cyber Attack Simulation
Run the full-spectrum enterprise threat simulation to observe detection cards and automated auto-remediation playbooks in real time:
```bash
python src/main.py --rules rules --telemetry samples/master_full_spectrum_simulation.ndjson
```
* **What You Will See**:
  * 🔴 **Threat Detection Cards**: Clearly explains what the attacker attempted in human-readable terms.
  * 🛡️ **Automated Defense**: Real-time process termination, file quarantine to encrypted vaults, account lockouts, and cloud access key revocations.
  * 📊 **Executive Summary**: Final tally of intercepted attacks and containment actions.

---

### Step 5: Audit MITRE ATT&CK & Taxonomy Compliance
Generate full terminal heatmaps and audit scorecards verifying coverage across all 12 MITRE Enterprise tactics and 14 cybersecurity threat domains:
```bash
python src/main.py --mitre-matrix --audit-taxonomy
```

---

## 🎯 Additional Dedicated Test Scenarios

### 👤 Identity & Active Directory UEBA Simulation
Simulate and detect account brute-force attacks, distributed password spraying, and Kerberoasting:
```bash
python src/main.py --rules rules --telemetry samples/identity_threat_simulation.ndjson
```

### 🌐 Enterprise Multi-Hop Cross-Domain Lateral Movement
Simulate and track an attacker moving laterally from a phished laptop across servers to a Domain Controller and Cloud:
```bash
python src/main.py --rules rules --telemetry samples/enterprise_cloud_attack_simulation.ndjson
```

---

## 🛡️ Core Capabilities & Architecture

| Subsystem | Threat Vectors Detected | Automated Defense Action |
| :--- | :--- | :--- |
| **Endpoint / EDR** | Process Injection, BYOVD Drivers, LSASS Dumps, SAM Dumps, Wipers, LOLBAS | `KILL_PROCESS_TREE`, `QUARANTINE_FILE` |
| **Ransomware Shield** | Decoy Canary file tripwires, Mass extension changes | `ISOLATE_HOST`, `TERMINATE_PROCESS` |
| **Identity / ITDR** | Brute Force, Password Spraying, DCSync, Kerberoasting, Golden Ticket | `LOCK_USER_ACCOUNT`, `REVOKE_SESSIONS` |
| **Network / NDR** | C2 Periodic Beaconing (Jitter CV ≤ 0.22), DNS Tunneling, DGA, Port Scans | `BLOCK_FIREWALL_IP`, `ISOLATE_HOST` |
| **Cloud & Workload** | AWS IAM Backdoor Keys, S3 Public Leaks, Kubernetes Container Escape | `REVOKE_ACCESS_KEY`, `RESTRICT_BUCKET` |
| **Enterprise Graph** | Multi-hop lateral pivot chains across endpoints and cloud | `ENTERPRISE_ISOLATE_PIVOT_PATH` |

---

## 📂 Repository Structure
```text
eyedetect/
├── rules/                    # 84 YAML-based Sigma/Wazuh detection rules
│   ├── cloud/                # AWS, GCP, and Kubernetes rules
│   ├── identity/             # Active Directory & authentication rules
│   ├── network/              # DNS, C2, and port scanning rules
│   ├── persistence/          # Registry, services, and scheduled tasks
│   ├── privilege_escalation/ # UAC bypass, BYOVD, token abuse
│   ├── process/              # Injection, hollowing, LOLBAS
│   └── web_api/              # SQLi, SSRF, XSS, and GraphQL rules
├── samples/                  # Pre-recorded realistic test telemetry (NDJSON)
│   ├── master_full_spectrum_simulation.ndjson
│   ├── enterprise_cloud_attack_simulation.ndjson
│   └── identity_threat_simulation.ndjson
├── src/                      # Core detection and remediation engine
│   ├── alerting/             # Clean human-readable alert formatters
│   ├── cloud/                # Cloud and container security analyzer
│   ├── correlation/          # Process tree, attack graph, and risk scorer
│   ├── evaluator/            # Sigma operators and condition evaluator
│   ├── identity/             # UEBA identity analytics
│   ├── ingestion/            # High-throughput NDJSON event reader
│   ├── mitre/                # MITRE ATT&CK matrix generator
│   ├── network/              # C2 beaconing and port scan detectors
│   ├── remediation/          # Auto-remediation playbooks & canary shield
│   ├── rules/                # Rule loaders and taxonomy auditors
│   ├── threat_intel/         # IOC hash and reputation engine
│   └── main.py               # Central engine orchestrator
└── tests/                    # 40 automated pytest unit tests
```

---

## 📜 License
MIT License. Developed as a University Capstone Project.
