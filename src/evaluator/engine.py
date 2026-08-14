"""Evaluation engine orchestrating rule logic matching and evidence generation."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from src.rules.schema import Condition, LogicNode, Rule
from src.evaluator.matcher import ConditionMatcher, extract_field
from src.correlation.process_tree import ProcessTree


@dataclass
class DetectionResult:
    """Represents a successful atomic rule match with extracted evidence."""
    rule: Rule
    event: Dict[str, Any]
    matched_evidence: Dict[str, Any] = field(default_factory=dict)


class RuleEvaluator:
    """Evaluates telemetry events against active detection rules."""

    def __init__(self, rules: List[Rule] = None, process_tree: Optional[ProcessTree] = None):
        self.rules = rules or []
        self.process_tree = process_tree
        self._rules_by_type: Dict[str, List[Rule]] = {}
        self.set_rules(self.rules)

    def set_rules(self, rules: List[Rule]) -> None:
        self.rules = rules
        self._rules_by_type.clear()
        for r in self.rules:
            self._rules_by_type.setdefault(r.event_type, []).append(r)

    def evaluate_event(self, event: Dict[str, Any]) -> List[DetectionResult]:
        """Evaluates a single telemetry event against all candidate rules for its event_type."""
        # Update process tree state if tracking is active
        if self.process_tree:
            self.process_tree.handle_event(event)

        event_type = event.get("event_type")
        if not event_type:
            return []

        candidate_rules = self._rules_by_type.get(event_type, [])
        matches: List[DetectionResult] = []

        for rule in candidate_rules:
            if self._evaluate_logic_node(rule.logic, event):
                evidence = self._extract_evidence(rule, event)
                matches.append(DetectionResult(rule=rule, event=event, matched_evidence=evidence))

        return matches

    def _evaluate_logic_node(self, node: LogicNode, event: Dict[str, Any]) -> bool:
        """Recursively evaluates boolean logic tree with short-circuiting."""
        # 1. Evaluate 'all' (AND)
        if node.all is not None:
            for item in node.all:
                if isinstance(item, Condition):
                    if not ConditionMatcher.evaluate(item, event, process_tree=self.process_tree):
                        return False
                elif isinstance(item, LogicNode):
                    if not self._evaluate_logic_node(item, event):
                        return False

        # 2. Evaluate 'any' (OR)
        if node.any is not None:
            any_matched = False
            for item in node.any:
                if isinstance(item, Condition):
                    if ConditionMatcher.evaluate(item, event, process_tree=self.process_tree):
                        any_matched = True
                        break
                elif isinstance(item, LogicNode):
                    if self._evaluate_logic_node(item, event):
                        any_matched = True
                        break
            if not any_matched:
                return False

        # 3. Evaluate 'none' (NOT)
        if node.none is not None:
            for item in node.none:
                if isinstance(item, Condition):
                    if ConditionMatcher.evaluate(item, event, process_tree=self.process_tree):
                        return False
                elif isinstance(item, LogicNode):
                    if self._evaluate_logic_node(item, event):
                        return False

        return True

    def _extract_evidence(self, rule: Rule, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts specified evidence fields from the event or dynamic process tree."""
        evidence_dict: Dict[str, Any] = {}
        for field_path in rule.evidence:
            val = extract_field(event, field_path, process_tree=self.process_tree)
            if val is not None:
                evidence_dict[field_path] = val
        return evidence_dict
