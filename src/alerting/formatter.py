"""Alert formatters for console and file output."""

import json
from typing import List
from src.alerting.alert import Alert

SEVERITY_COLORS = {
    "low": "\033[94m",       # Blue
    "medium": "\033[93m",    # Yellow
    "high": "\033[91m",      # Red
    "critical": "\033[95m",  # Magenta
}
RESET_COLOR = "\033[0m"


class AlertFormatter:
    """Formats alerts for display or persistent storage."""

    @staticmethod
    def to_console(alert: Alert) -> str:
        color = SEVERITY_COLORS.get(alert.severity.lower(), "")
        sep = "=" * 70
        
        lines = [
            sep,
            f"{color}[ALERT: {alert.severity.upper()}] {alert.title}{RESET_COLOR}",
            sep,
            f"  • Alert ID    : {alert.alert_id}",
            f"  • Rule ID     : {alert.rule_id}",
            f"  • Timestamp   : {alert.timestamp}",
            f"  • Host ID     : {alert.host_id}",
            f"  • Event ID    : {alert.event_id}",
            f"  • Confidence  : {alert.confidence * 100:.0f}%",
        ]

        if alert.mitre_technique or alert.mitre_tactic:
            lines.append(f"  • MITRE ATT&CK: {alert.mitre_tactic} -> {alert.mitre_technique}")

        lines.append("  • Evidence Extracted:")
        for k, v in alert.evidence.items():
            lines.append(f"      - {k}: {v}")

        if alert.tags:
            lines.append(f"  • Tags        : {', '.join(alert.tags)}")

        lines.append(sep)
        return "\n".join(lines)

    @staticmethod
    def to_json(alert: Alert) -> str:
        return json.dumps(alert.to_dict(), indent=2)

    @staticmethod
    def to_ndjson(alert: Alert) -> str:
        return json.dumps(alert.to_dict())
