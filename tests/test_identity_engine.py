"""Unit tests for ITDR Identity Threat Detection and UEBA Subsystems."""

import pytest
from src.identity.ueba import IdentityAnalyticsEngine
from src.remediation.engine import EndpointRemediationEngine


def test_brute_force_account_lockout_detection():
    engine = IdentityAnalyticsEngine(brute_force_threshold=5, window_seconds=60)

    matches = []
    for i in range(5):
        evt = {
            "event_type": "user_login",
            "host_id": "DC-01",
            "timestamp": 1000.0 + i,
            "user": {"name": "target_admin"},
            "auth": {"status": "failure", "source_ip": "192.168.1.100"},
        }
        res = engine.ingest_identity_event(evt)
        matches.extend(res)

    assert len(matches) == 1
    match = matches[0]
    assert "Brute Force" in match.threat_type
    assert match.username == "target_admin"
    assert match.remediation_required == "LOCK_USER_ACCOUNT"


def test_password_spraying_detection():
    engine = IdentityAnalyticsEngine(spray_account_threshold=4, window_seconds=60)

    users = ["user1", "user2", "user3", "user4"]
    matches = []
    for idx, u in enumerate(users):
        evt = {
            "event_type": "user_login",
            "host_id": "DC-01",
            "timestamp": 1000.0 + idx,
            "user": {"name": u},
            "auth": {"status": "failure", "source_ip": "185.220.101.5"},
        }
        res = engine.ingest_identity_event(evt)
        matches.extend(res)

    assert len(matches) == 1
    assert "Password Spray" in matches[0].threat_type
    assert matches[0].source_ip == "185.220.101.5"


def test_privileged_group_escalation():
    engine = IdentityAnalyticsEngine()

    evt = {
        "event_type": "group_change",
        "host_id": "DC-01",
        "timestamp": 1000.0,
        "action": "member_added",
        "user": {"name": "compromised_user"},
        "group": {"name": "Domain Admins"},
    }

    matches = engine.ingest_identity_event(evt)
    assert len(matches) == 1
    assert "Privilege Escalation" in matches[0].threat_type
    assert matches[0].username == "compromised_user"
    assert matches[0].remediation_required == "REVOKE_USER_SESSIONS"


def test_kerberoasting_rc4_detection():
    engine = IdentityAnalyticsEngine()

    evt = {
        "event_type": "kerberos_ticket",
        "host_id": "DC-01",
        "timestamp": 1000.0,
        "user": {"name": "attacker"},
        "kerberos": {"service_name": "MSSQLSvc/sql01", "encryption_type": "0x17 (RC4_HMAC)"},
    }

    matches = engine.ingest_identity_event(evt)
    assert len(matches) == 1
    assert "Kerberoasting" in matches[0].threat_type
    assert matches[0].remediation_required == "FORCE_PASSWORD_RESET"
