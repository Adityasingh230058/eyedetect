# 🛡️ eyedetect — EDR Detection Engine

A lightweight, rule-driven Endpoint Detection and Response (EDR) detection engine built in Python.

---

## 📌 Project Overview
`eyedetect` consumes standardized endpoint telemetry events (JSON/NDJSON) from the telemetry agent and evaluates them against YAML-based detection rules using boolean logic trees (`ALL`, `ANY`, `NONE`), comparison operators, evidence extraction, and MITRE ATT&CK mapping.

---

## 🚀 Quickstart (How to Run in 60 Seconds)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Detection Engine
```bash
python src/main.py --rules rules/ --telemetry samples/telemetry_extended.ndjson --output-file samples/alerts.ndjson
```

### 3. Run Automated Tests
```bash
pytest -v tests/
```

---

## 📋 Telemetry Schema Contract (For Agent Developers)
The Detection Engine expects the agent/collector to emit events in NDJSON format conforming to this structure:

```json
{
  "event_id": "evt-001",
  "timestamp": "2026-08-14T18:05:22.000Z",
  "host_id": "HOST-01",
  "event_type": "process_create",
  "process": {
    "name": "powershell.exe",
    "pid": 4150,
    "ppid": 3020,
    "process_guid": "{GUID-PS-01}",
    "command_line": "powershell.exe -w hidden -enc SQBFAFgA...",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  },
  "parent": {
    "name": "winword.exe",
    "pid": 3020,
    "process_guid": "{GUID-WORD-01}"
  }
}
```

### Supported `event_type`s:
- `process_create`
- `process_terminate`
- `network_connect`
- `file_create`
- `registry_write`

---

## 📂 Directory Structure
```text
eyedetect/
├── src/
│   ├── ingestion/       # NDJSON streaming reader
│   ├── rules/           # Rule schema, YAML loader & validator
│   ├── evaluator/       # Matcher, operators & boolean logic engine
│   ├── correlation/     # Process tree tracking & correlation engine
│   ├── alerting/        # Alert models & formatters
│   └── main.py          # CLI orchestrator
├── rules/               # Detection rules catalog (YAML)
├── samples/             # Sample telemetry inputs & alert outputs
├── tests/               # Unit & integration tests
└── requirements.txt
```
