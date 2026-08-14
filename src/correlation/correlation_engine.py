"""Multi-Event Correlation Engine.

Correlates individual, multi-stage telemetry events across sliding time windows
and process hierarchies to detect complex attack chains (e.g. Office -> PowerShell -> Network Outbound).
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from src.alerting.alert import Alert
from src.evaluator.engine import DetectionResult


@dataclass
class CorrelationRule:
    """Defines a multi-stage correlation sequence."""
    id: str
    name: str
    description: str
    stages: List[str]  # List of matching Rule IDs in expected sequence e.g. ["DET-PROC-001", "DET-NET-001"]
    time_window_seconds: int = 60
    severity: str = "critical"
    confidence: float = 0.95
    mitre_tactic: str = "Execution"
    mitre_technique: str = "T1059"


@dataclass
class CorrelatedIncident:
    """Represents a composite multi-stage attack detection."""
    incident_id: str
    correlation_rule_id: str
    title: str
    severity: str
    confidence: float
    host_id: str
    timestamp: str
    stages_matched: List[str]
    composite_evidence: List[Dict[str, Any]]
    mitre_technique: str
    mitre_tactic: str

    def to_alert(self) -> Alert:
        evidence_summary: Dict[str, Any] = {
            "attack_chain_stages": " -> ".join(self.stages_matched),
            "stage_count": len(self.stages_matched),
        }
        for i, ev in enumerate(self.composite_evidence, start=1):
            evidence_summary[f"stage_{i}_rule"] = ev.get("rule_id")
            for k, v in ev.get("evidence", {}).items():
                evidence_summary[f"stage_{i}_{k}"] = v

        return Alert(
            alert_id=self.incident_id,
            rule_id=self.correlation_rule_id,
            title=f"[CORRELATED INCIDENT] {self.title}",
            description=f"Multi-stage attack chain detected ({len(self.stages_matched)} correlated stages).",
            severity=self.severity,
            confidence=self.confidence,
            host_id=self.host_id,
            timestamp=self.timestamp,
            event_id=None,
            evidence=evidence_summary,
            mitre_tactic=self.mitre_tactic,
            mitre_technique=self.mitre_technique,
            tags=["attack.correlation", "multi-stage-killchain"],
        )


class CorrelationEngine:
    """Maintains active sliding-window state buffers and checks correlation rules."""

    def __init__(self, correlation_rules: Optional[List[CorrelationRule]] = None):
        self.correlation_rules = correlation_rules or self._default_correlation_rules()
        # Key: (host_id, process_guid or lineage) -> List[Dict] with timestamp and rule_id
        self.alert_history: Dict[str, List[Dict[str, Any]]] = {}

    def ingest_detection(self, detection: DetectionResult) -> List[CorrelatedIncident]:
        """Ingests an atomic detection result and checks for multi-stage correlation matches."""
        rule_id = detection.rule.id
        event = detection.event
        host_id = event.get("host_id", "UNKNOWN")
        guid = event.get("process", {}).get("process_guid") or event.get("host_id", "HOST")
        
        # Track by host + process_guid or host-level key
        key = f"{host_id}:{guid}"
        
        # Parse timestamp or fallback
        ts_str = event.get("timestamp", datetime.utcnow().isoformat())
        
        record = {
            "rule_id": rule_id,
            "timestamp_str": ts_str,
            "evidence": detection.matched_evidence,
            "event": event,
        }
        
        self.alert_history.setdefault(key, []).append(record)
        
        # Check all correlation rules
        incidents: List[CorrelatedIncident] = []
        for corr_rule in self.correlation_rules:
            incident = self._evaluate_correlation_rule(corr_rule, key, host_id)
            if incident:
                incidents.append(incident)

        return incidents

    def _evaluate_correlation_rule(
        self, corr_rule: CorrelationRule, key: str, host_id: str
    ) -> Optional[CorrelatedIncident]:
        history = self.alert_history.get(key, [])
        if len(history) < len(corr_rule.stages):
            return None

        # Check if the sequence of rule_ids occurred
        history_rule_ids = [h["rule_id"] for h in history]
        
        # Look for contiguous or ordered subsequence matching stages
        stage_idx = 0
        matched_records = []
        for rec in history:
            if rec["rule_id"] == corr_rule.stages[stage_idx]:
                matched_records.append(rec)
                stage_idx += 1
                if stage_idx == len(corr_rule.stages):
                    break

        if stage_idx == len(corr_rule.stages):
            # All stages found in sequence!
            incident = CorrelatedIncident(
                incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
                correlation_rule_id=corr_rule.id,
                title=corr_rule.name,
                severity=corr_rule.severity,
                confidence=corr_rule.confidence,
                host_id=host_id,
                timestamp=matched_records[-1]["timestamp_str"],
                stages_matched=corr_rule.stages,
                composite_evidence=matched_records,
                mitre_tactic=corr_rule.mitre_tactic,
                mitre_technique=corr_rule.mitre_technique,
            )
            # Clear or prune matched history so it doesn't trigger repeatedly
            self.alert_history[key] = [r for r in history if r not in matched_records]
            return incident

        return None

    @staticmethod
    def _default_correlation_rules() -> List[CorrelationRule]:
        return [
            CorrelationRule(
                id="CORR-001",
                name="Office Document Spawned PowerShell Establishing External Network Connection",
                description="Detects Office spawning PowerShell followed immediately by an outbound network connection.",
                stages=["DET-PROC-001", "DET-NET-001"],
                time_window_seconds=60,
                severity="critical",
                confidence=0.98,
                mitre_tactic="Execution",
                mitre_technique="T1059.001",
            ),
            CorrelationRule(
                id="CORR-002",
                name="Reconnaissance Followed by Ransomware Shadow Copy Deletion",
                description="Detects initial system reconnaissance discovery followed by shadow copy wiping.",
                stages=["DET-PROC-008", "DET-PROC-006"],
                time_window_seconds=60,
                severity="critical",
                confidence=0.95,
                mitre_tactic="Impact",
                mitre_technique="T1490",
            ),
        ]
