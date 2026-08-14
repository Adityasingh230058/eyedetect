"""Unit tests verifying full taxonomy coverage and evaluating new attack vectors."""

import pytest
from src.rules.loader import RuleLoader
from src.rules.taxonomy_coverage import TaxonomyCoverageAuditor, TAXONOMY_DOMAINS
from src.evaluator.engine import RuleEvaluator


def test_100_percent_taxonomy_audit():
    loader = RuleLoader()
    rules = loader.load_directory("rules")
    report = TaxonomyCoverageAuditor.audit_coverage(rules)

    assert report["total_threat_vectors"] > 0
    assert report["covered_threat_vectors"] == report["total_threat_vectors"]
    assert report["coverage_percentage"] == "100.0%"


def test_sql_injection_rule_evaluation():
    loader = RuleLoader()
    rules = loader.load_directory("rules")
    evaluator = RuleEvaluator(rules)

    evt = {
        "event_type": "http_request",
        "http": {
            "method": "GET",
            "uri": "/api/users?id=1' UNION SELECT username, password FROM users--",
            "body": "",
        },
        "network": {"source_ip": "198.51.100.23"},
    }

    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-WEB-001" in rule_ids


def test_cloud_metadata_ssrf_rule_evaluation():
    loader = RuleLoader()
    rules = loader.load_directory("rules")
    evaluator = RuleEvaluator(rules)

    evt = {
        "event_type": "http_request",
        "http": {
            "method": "POST",
            "uri": "/fetch_url?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "body": "",
        },
        "network": {"source_ip": "203.0.113.88"},
    }

    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-WEB-003" in rule_ids


def test_dcsync_rule_evaluation():
    loader = RuleLoader()
    rules = loader.load_directory("rules")
    evaluator = RuleEvaluator(rules)

    evt = {
        "event_type": "directory_service",
        "action": "DsGetNcChanges",
        "user": {"name": "compromised_admin", "is_domain_controller": False},
        "network": {"source_ip": "10.0.1.15"},
    }

    results = evaluator.evaluate_event(evt)
    rule_ids = [r.rule.id for r in results]
    assert "DET-IDENT-005" in rule_ids
