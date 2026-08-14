"""Extracts fields from events and matches atomic rule conditions."""

from typing import Any, Dict, Optional
from src.rules.schema import Condition
from src.evaluator.operators import OPERATOR_MAP


def extract_field(event: Dict[str, Any], field_path: str) -> Any:
    """Extracts a nested field value from a dictionary using dot notation (e.g. 'process.name')."""
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
    def evaluate(condition: Condition, event: Dict[str, Any]) -> bool:
        actual_val = extract_field(event, condition.field)
        op_func = OPERATOR_MAP.get(condition.operator)

        if not op_func:
            return False

        return op_func(actual_val, condition.value, case_sensitive=condition.case_sensitive)
