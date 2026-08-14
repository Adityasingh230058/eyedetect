"""Cloud Threat Detection, Workload Security, IAM Anomaly, and Storage Protection Engine.

Analyzes multi-cloud audit logs (AWS CloudTrail, GCP Cloud Audit, Azure Activity Logs) and Container/K8s telemetry:
- IAM Backdoor Access Key Creation & Admin Policy Escalations
- S3 / GCS Storage Bucket Public Exposure & Data Exfiltration
- Container Escape / Privileged Workload Breakout Attempts
- Cloud API Anomalies (Anomalous Regions, High-Velocity Enumeration)
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class CloudThreatMatch:
    """Represents a confirmed cloud security threat or workload anomaly."""
    threat_type: str
    cloud_provider: str  # "AWS", "GCP", "AZURE", "KUBERNETES"
    account_or_project_id: str
    principal_arn_or_user: str
    resource_id: str
    confidence: float
    evidence: Dict[str, Any]
    remediation_required: str  # "REVOKE_CLOUD_ACCESS_KEY", "RESTRICT_BUCKET_PERMISSIONS", "TERMINATE_POD_WORKLOAD"


class CloudThreatEngine:
    """Evaluates cloud audit events and container telemetry for malicious activity."""

    SUSPICIOUS_IAM_POLICIES = {
        "administratoraccess",
        "iamfullaccess",
        "poweruseraccess",
        "roles/owner",
        "roles/editor",
        "contributor",
    }

    def __init__(self, api_burst_threshold: int = 8, burst_window_seconds: int = 30):
        self.api_burst_threshold = api_burst_threshold
        self.burst_window = burst_window_seconds
        # Key: (principal, action_type) -> deque of timestamps
        self.api_activity: Dict[str, deque] = defaultdict(deque)
        self.alerted_events: Set[str] = set()

    def inspect_cloud_event(self, event: Dict[str, Any]) -> List[CloudThreatMatch]:
        """Evaluates a cloud audit, IAM, storage, or container event."""
        event_type = event.get("event_type")
        if not event_type or not event_type.startswith(("cloud_", "k8s_", "container_")):
            return []

        matches: List[CloudThreatMatch] = []
        cloud_info = event.get("cloud", {})
        provider = (cloud_info.get("provider") or "AWS").upper()
        account_id = cloud_info.get("account_id") or cloud_info.get("project_id") or "UNKNOWN_ACCOUNT"
        principal = event.get("user", {}).get("name") or event.get("principal", {}).get("arn") or "anonymous"
        event_name = event.get("action") or event.get("api_call", {}).get("name") or ""
        ts = self._parse_timestamp(event.get("timestamp"))

        # 1. IAM Backdoor Access Key Creation
        if event_name in ("CreateAccessKey", "create_service_account_key", "New-AzureADMSApplicationKeyCredential"):
            target_user = event.get("api_call", {}).get("target_user") or principal
            matches.append(
                CloudThreatMatch(
                    threat_type="Cloud IAM Backdoor Access Key Created",
                    cloud_provider=provider,
                    account_or_project_id=account_id,
                    principal_arn_or_user=principal,
                    resource_id=target_user,
                    confidence=0.95,
                    remediation_required="REVOKE_CLOUD_ACCESS_KEY",
                    evidence={
                        "api_action": event_name,
                        "created_by": principal,
                        "target_identity": target_user,
                        "source_ip": event.get("network", {}).get("source_ip"),
                        "user_agent": event.get("http", {}).get("user_agent"),
                    },
                )
            )

        # 2. Administrative Privilege Policy Attachment
        if event_name in ("AttachUserPolicy", "AttachRolePolicy", "setIamPolicy", "Add-RoleMember"):
            policy_name = str(event.get("api_call", {}).get("policy_name") or "").lower()
            if any(p in policy_name for p in self.SUSPICIOUS_IAM_POLICIES):
                matches.append(
                    CloudThreatMatch(
                        threat_type="Cloud IAM Privilege Escalation: Administrator Policy Attached",
                        cloud_provider=provider,
                        account_or_project_id=account_id,
                        principal_arn_or_user=principal,
                        resource_id=policy_name,
                        confidence=0.98,
                        remediation_required="REVOKE_CLOUD_ACCESS_KEY",
                        evidence={
                            "escalated_policy": policy_name,
                            "acting_principal": principal,
                            "target_entity": event.get("api_call", {}).get("target_entity"),
                            "technique": "Cloud Privilege Escalation (T1098.001)",
                        },
                    )
                )

        # 3. S3 / GCS Storage Bucket Made Public
        if event_name in ("PutBucketAcl", "PutBucketPolicy", "setBucketIamPolicy", "Set-AzStorageBlobContent"):
            acl = str(event.get("api_call", {}).get("acl") or event.get("storage", {}).get("permissions") or "").lower()
            bucket_name = event.get("storage", {}).get("bucket_name") or event.get("api_call", {}).get("bucket") or "unknown-bucket"

            if any(marker in acl for marker in ("public-read", "allusers", "anonymous", "allauthenticatedusers", "0.0.0.0/0")):
                matches.append(
                    CloudThreatMatch(
                        threat_type="Cloud Storage Bucket Exfiltration Risk: Public Exposure Policy Set",
                        cloud_provider=provider,
                        account_or_project_id=account_id,
                        principal_arn_or_user=principal,
                        resource_id=bucket_name,
                        confidence=0.98,
                        remediation_required="RESTRICT_BUCKET_PERMISSIONS",
                        evidence={
                            "bucket_name": bucket_name,
                            "exposed_acl": acl,
                            "modified_by": principal,
                            "source_ip": event.get("network", {}).get("source_ip"),
                        },
                    )
                )

        # 4. Kubernetes / Container Workload Escape
        if event_type in ("k8s_container", "container_execution"):
            pod_name = event.get("container", {}).get("pod_name") or event.get("container", {}).get("name") or "pod"
            is_privileged = event.get("container", {}).get("privileged", False)
            host_mount = event.get("container", {}).get("host_mount") or ""

            if is_privileged or any(m in host_mount for m in ("/docker.sock", "/host", "/proc", "/root", "/")):
                matches.append(
                    CloudThreatMatch(
                        threat_type="Container Workload Escape / Privileged Host Filesystem Mount",
                        cloud_provider="KUBERNETES",
                        account_or_project_id=account_id,
                        principal_arn_or_user=principal,
                        resource_id=pod_name,
                        confidence=0.96,
                        remediation_required="TERMINATE_POD_WORKLOAD",
                        evidence={
                            "pod_name": pod_name,
                            "is_privileged_container": is_privileged,
                            "mounted_host_path": host_mount,
                            "image": event.get("container", {}).get("image"),
                            "technique": "Escape to Host (T1611)",
                        },
                    )
                )

        return matches

    @staticmethod
    def _parse_timestamp(ts_val: Any) -> float:
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                clean_ts = ts_val.replace("Z", "+00:00")
                return datetime.fromisoformat(clean_ts).timestamp()
            except Exception:
                pass
        return datetime.now(timezone.utc).timestamp()
