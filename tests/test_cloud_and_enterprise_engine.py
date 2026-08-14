"""Unit tests for Cloud Threat Engine, Kubernetes Workload Protection, and Enterprise Attack Graph."""

import pytest
from src.cloud.cloud_engine import CloudThreatEngine
from src.correlation.enterprise_graph import EnterpriseAttackGraph
from src.remediation.engine import EndpointRemediationEngine


def test_cloud_iam_backdoor_key_creation():
    engine = CloudThreatEngine()

    evt = {
        "event_type": "cloud_audit",
        "cloud": {"provider": "AWS", "account_id": "123456789012"},
        "action": "CreateAccessKey",
        "user": {"name": "compromised_admin"},
        "api_call": {"name": "CreateAccessKey", "target_user": "backdoor_user"},
        "network": {"source_ip": "198.51.100.55"},
    }

    matches = engine.inspect_cloud_event(evt)
    assert len(matches) == 1
    match = matches[0]
    assert "Backdoor Access Key" in match.threat_type
    assert match.cloud_provider == "AWS"
    assert match.remediation_required == "REVOKE_CLOUD_ACCESS_KEY"


def test_s3_storage_public_exposure():
    engine = CloudThreatEngine()

    evt = {
        "event_type": "cloud_storage",
        "cloud": {"provider": "AWS", "account_id": "123456789012"},
        "action": "PutBucketAcl",
        "user": {"name": "admin_svc"},
        "storage": {"bucket_name": "confidential-hr-data", "permissions": "public-read"},
    }

    matches = engine.inspect_cloud_event(evt)
    assert len(matches) == 1
    assert "Storage Bucket Exfiltration" in matches[0].threat_type
    assert matches[0].remediation_required == "RESTRICT_BUCKET_PERMISSIONS"


def test_kubernetes_container_escape():
    engine = CloudThreatEngine()

    evt = {
        "event_type": "k8s_container",
        "cloud": {"provider": "KUBERNETES", "account_id": "K8S-CLUSTER-PROD"},
        "container": {
            "pod_name": "crypto-miner-pod",
            "privileged": True,
            "host_mount": "/var/run/docker.sock",
        },
    }

    matches = engine.inspect_cloud_event(evt)
    assert len(matches) == 1
    assert "Container Workload Escape" in matches[0].threat_type
    assert matches[0].remediation_required == "TERMINATE_POD_WORKLOAD"


def test_enterprise_multi_hop_lateral_attack_graph():
    graph = EnterpriseAttackGraph()

    # Hop 1: Laptop -> Jumpbox
    c1 = graph.record_attack_step(
        source_id="LAPTOP-SALES-01",
        source_type="ENDPOINT",
        target_id="SRV-JUMP-01",
        target_type="ENDPOINT",
        pivot_mechanism="WMI_REMOTE_EXEC",
        rule_id="DET-LAT-001",
        timestamp="2026-08-14T22:00:00Z",
    )
    assert c1 is None  # Hop 1 (2 nodes, threshold is 3)

    # Hop 2: Jumpbox -> Domain Controller
    c2 = graph.record_attack_step(
        source_id="SRV-JUMP-01",
        source_type="ENDPOINT",
        target_id="DC-PRIMARY-01",
        target_type="ENDPOINT",
        pivot_mechanism="PASS_THE_HASH",
        rule_id="DET-IDENT-004",
        timestamp="2026-08-14T22:01:00Z",
    )
    assert c2 is not None  # Hop 2 (3 nodes in chain: LAPTOP -> JUMP -> DC)
    assert c2.lateral_pivot_path == ["LAPTOP-SALES-01", "SRV-JUMP-01", "DC-PRIMARY-01"]
    assert c2.root_cause_asset == "LAPTOP-SALES-01"
