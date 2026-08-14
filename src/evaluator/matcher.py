"""Extracts fields from events and matches atomic rule conditions with process tree awareness."""

from typing import Any, Dict, List, Optional
from src.rules.schema import Condition
from src.evaluator.operators import OPERATOR_MAP
from src.correlation.process_tree import ProcessTree


def extract_field(
    event: Dict[str, Any],
    field_path: str,
    process_tree: Optional[ProcessTree] = None,
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
    ) -> bool:
        # Special operator: has_ancestor
        if condition.operator == "has_ancestor" and process_tree:
            guid = event.get("process", {}).get("process_guid")
            if not guid:
                return False
            targets = condition.value if isinstance(condition.value, list) else [condition.value]
            return process_tree.has_ancestor(guid, targets)

        actual_val = extract_field(event, condition.field, process_tree=process_tree)
        op_func = OPERATOR_MAP.get(condition.operator)

        if not op_func:
            return False

        return op_func(actual_val, condition.value, case_sensitive=condition.case_sensitive)
