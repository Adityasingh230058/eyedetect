"""Active Response and Automated Incident Containment Engine.

Inspired by Wazuh Active Response (<active-response>).
Generates structured remediation actions for high-severity alerts (Level 12+).
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class ActiveResponseAction:
    """Action payload for automated endpoint containment."""
    action: str  # e.g., "TERMINATE_PROCESS", "ISOLATE_HOST", "BLOCK_FIREWALL_IP", "QUARANTINE_FILE"
    host_id: str
    target_pid: Optional[int] = None
    target_guid: Optional[str] = None
    target_ip: Optional[str] = None
    target_file: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class ActiveResponseEngine:
    """Evaluates alerts and attaches automated mitigation instructions."""

    @staticmethod
    def resolve_action(
        level: int,
        event: Dict[str, Any],
        custom_action: Optional[str] = None,
        reason: str = "",
    ) -> Optional[ActiveResponseAction]:
        host_id = event.get("host_id", "UNKNOWN_HOST")
        proc = event.get("process", {})
        net = event.get("network", {})
        file_info = event.get("file", {})

        pid = proc.get("pid")
        guid = proc.get("process_guid")
        dest_ip = net.get("destination_ip")
        file_path = file_info.get("path")

        # 1. Custom rule-specified action takes first precedence
        if custom_action == "TERMINATE_PROCESS" or (custom_action is None and pid and level in (12, 13)):
            return ActiveResponseAction(
                action="TERMINATE_PROCESS",
                host_id=host_id,
                target_pid=pid,
                target_guid=guid,
                reason=reason or f"Automated malicious process termination for Level {level} threat",
            )
        elif custom_action == "BLOCK_FIREWALL_IP" or (custom_action is None and dest_ip and level >= 12):
            return ActiveResponseAction(
                action="BLOCK_FIREWALL_IP",
                host_id=host_id,
                target_ip=dest_ip,
                target_pid=pid,
                reason=reason or f"Automated C2 egress block for Level {level} threat",
            )
        elif custom_action == "ISOLATE_HOST" or level >= 14:
            return ActiveResponseAction(
                action="ISOLATE_HOST",
                host_id=host_id,
                target_pid=pid,
                target_guid=guid,
                reason=reason or f"Emergency containment triggered for critical Level {level} event",
            )

        return None
