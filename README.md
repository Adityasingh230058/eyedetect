# 👁️ eyedetect — Enterprise Cyber Threat Detection & Automated Response Engine

A high-performance, cross-domain Endpoint, Identity, Network, and Cloud Threat Detection & Automated Remediation Engine (EDR / XDR) built in Python.

---

## 🚀 How to Test This Project (Step-by-Step)

Anyone visiting this repository can clone, run, and verify the entire detection system in under 2 minutes.

### Step 1: Clone the Repository
Open PowerShell or your terminal and run:
```bash
git clone https://github.com/Adityasingh230058/eyedetect.git
cd eyedetect
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```
*(Requires Python 3.9 or newer. Uses `pydantic`, `pyyaml`, and `pytest`)*

---

### Step 3: Run the Automated Unit Test Suite
Verify that all detection math, algorithms, deobfuscators, and threat engines pass with 100% integrity:
```bash
pytest -v tests/
```
> **Expected Result**: `40 passed in ~4s` (100% pass rate across all 8 test modules).

---

### Step 4: Run the Full Attack Simulation (Live Detection & Auto-Fix)
Simulate a realistic enterprise attack stream (phishing droppers, password dumps, ransomware canary breach, cloud backdoors, web shells, and wipers):
```bash
python src/main.py --rules rules --telemetry samples/master_full_spectrum_simulation.ndjson
```
> **What You Will See**: Clean, human-readable detection cards showing:
> - 🔴 **What Happened**: Plain-English explanation of the attack.
> - 🛡️ **Auto-Defense Applied**: Process termination, encrypted vault quarantine, or account lockout.
> - 📊 **Severity & Confidence**: Threat classification score.

---

### Step 5: View MITRE ATT&CK Matrix & Taxonomy Scorecard
Verify 100% framework coverage across all 12 MITRE enterprise tactics and 14 attack domains:
```bash
# View MITRE ATT&CK Matrix & 14-Domain Taxonomy Scorecard
python src/main.py --mitre-matrix --audit-taxonomy
```

---

## 🎯 Additional Test Scenarios

### 👤 Identity & Active Directory UEBA Test
Simulate brute-force attacks, password spraying, and Kerberoasting:
```bash
python src/main.py --rules rules --telemetry samples/identity_threat_simulation.ndjson
```

### 🌐 Enterprise Multi-Hop Lateral Movement Test
Simulate an attacker pivoting across multiple endpoints into a Domain Controller and Cloud:
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
│   ├── alerting/             # Clean alert formatters
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
MIT License. Developed for University Capstone Project.
