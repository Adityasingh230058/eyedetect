"""Extracts fields from events and matches atomic rule conditions with process tree and threat intel awareness."""

from typing import Any, Dict, List, Optional
from src.rules.schema import Condition
from src.evaluator.operators import OPERATOR_MAP
from src.correlation.process_tree import ProcessTree
from src.threat_intel.ioc_lookup import ThreatIntelEngine


def extract_field(
    event: Dict[str, Any],
    field_path: str,
    process_tree: Optional[ProcessTree] = None,
    threat_intel: Optional[ThreatIntelEngine] = None,
) -> Any:
    """Extracts a nested field value from a dictionary using dot notation or dynamic state."""
    # Special dynamic fields supported by ProcessTree
    if field_path in ("process.lineage", "process.ancestry") and process_tree:
        guid = event.get("process", {}).get("process_guid")
        if guid:
            return process_tree.get_lineage_string(guid)

    if field_path == "process.ancestor_names" and process_tree:
        guid = event.get("process", {}).get("process_guid")
        if guid:
            return [a.name for a in process_tree.get_ancestors(guid)]

    # Special dynamic fields supported by ThreatIntelEngine
    if field_path == "threat_intel.hash_match" and threat_intel:
        file_hash = event.get("process", {}).get("file_hash") or event.get("file", {}).get("hash")
        return threat_intel.check_hash(file_hash)

    if field_path == "threat_intel.ip_match" and threat_intel:
        dest_ip = event.get("network", {}).get("destination_ip")
        return threat_intel.check_ip(dest_ip)

    parts = field_path.split(".")
    current = event
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


class ConditionMatcher:
    """Evaluates a single rule Condition against an event."""

    @staticmethod
    def evaluate(
        condition: Condition,
        event: Dict[str, Any],
        process_tree: Optional[ProcessTree] = None,
        threat_intel: Optional[ThreatIntelEngine] = None,
    ) -> bool:
        # 1. Special operator: has_ancestor
        if condition.operator == "has_ancestor" and process_tree:
            guid = event.get("process", {}).get("process_guid")
            if not guid:
                return False
            targets = condition.value if isinstance(condition.value, list) else [condition.value]
            return process_tree.has_ancestor(guid, targets)

        # 2. Special operator: in_threat_intel (IOC Blacklist Check)
        if condition.operator == "in_threat_intel" and threat_intel:
            actual_val = extract_field(event, condition.field, process_tree=process_tree, threat_intel=threat_intel)
            target_type = str(condition.value).lower()
            if target_type in ("hash", "file_hash", "sha256", "md5"):
                return threat_intel.check_hash(actual_val) is not None
            elif target_type in ("ip", "ip_address", "c2"):
                return threat_intel.check_ip(actual_val) is not None

        actual_val = extract_field(event, condition.field, process_tree=process_tree, threat_intel=threat_intel)
        op_func = OPERATOR_MAP.get(condition.operator)

        if not op_func:
            return False

        return op_func(actual_val, condition.value, case_sensitive=condition.case_sensitive)
