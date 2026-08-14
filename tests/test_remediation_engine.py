"""Unit tests for Endpoint Threat Remediation, Auto-Fixing, and Ransomware Shield."""

import pytest
from src.remediation.engine import EndpointRemediationEngine
from src.remediation.ransomware_shield import RansomwareShield


def test_endpoint_remediation_playbook():
    engine = EndpointRemediationEngine(dry_run=False)

    event = {
        "host_id": "SRV-PROD-01",
        "process": {
            "name": "malware.exe",
            "pid": 5544,
            "executable_path": "C:\\Temp\\malware.exe",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "command_line": "malware.exe",
        },
        "registry": {
            "key_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
        },
    }

    report = engine.remediate_threat(
        rule_id="DET-MALW-001",
        threat_name="Malware Persistence & Dropper",
        event=event,
        custom_action="ISOLATE_HOST",
    )

    assert report.containment_status == "FULLY_CONTAINED"
    assert len(report.actions_executed) == 4

    action_types = [a.action_type for a in report.actions_executed]
    assert "KILL_PROCESS_TREE" in action_types
    assert "QUARANTINE_FILE" in action_types
    assert "REVERT_PERSISTENCE" in action_types
    assert "ISOLATE_HOST" in action_types

    assert "C:\\Temp\\malware.exe" in engine.quarantine_vault


def test_ransomware_canary_tripwire_trigger():
    shield = RansomwareShield()

    canary_event = {
        "event_type": "file_modify",
        "host_id": "LAPTOP-EXEC-01",
        "process": {"name": "wannacry.exe", "pid": 6620, "command_line": "wannacry.exe"},
        "file": {"path": "C:\\Users\\User\\Documents\\quarterly_taxes.canary.docx"},
    }

    match = shield.inspect_file_event(canary_event)
    assert match is not None
    assert "Canary Tripwire" in match.threat_type
    assert match.pid == 6620
    assert match.confidence >= 0.95


def test_ransomware_extension_detection():
    shield = RansomwareShield()

    ransom_event = {
        "event_type": "file_rename",
        "host_id": "LAPTOP-EXEC-01",
        "process": {"name": "lockbit.exe", "pid": 7710},
        "file": {"path": "C:\\Users\\User\\Documents\\database.locked"},
    }

    match = shield.inspect_file_event(ransom_event)
    assert match is not None
    assert "Known Ransomware Extension" in match.threat_type
    assert match.pid == 7710
