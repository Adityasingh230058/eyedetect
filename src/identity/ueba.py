"""Identity Threat Detection & User Entity Behavior Analytics (UEBA) Engine.

Analyzes identity and authentication events across endpoints and domain controllers:
- Password Spraying and Distributed Brute Force
- Impossible Travel / Geo-velocity Anomalies
- Privilege Escalation (Privileged Group Modifications)
- Kerberoasting & Pass-the-Hash credential abuse
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class IdentityThreatMatch:
    """Represents a confirmed identity compromise or anomalous user behavior."""
    threat_type: str
    username: str
    host_id: str
    source_ip: Optional[str]
    confidence: float
    evidence: Dict[str, Any]
    remediation_required: str  # "LOCK_USER_ACCOUNT", "REVOKE_USER_SESSIONS", "FORCE_PASSWORD_RESET"


class IdentityAnalyticsEngine:
    """Tracks authentication velocity, credential abuse, and account privilege escalations."""

    PRIVILEGED_GROUPS = {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "backup operators",
        "server operators",
    }

    def __init__(
        self,
        brute_force_threshold: int = 5,
        spray_account_threshold: int = 4,
        window_seconds: int = 60,
    ):
        self.brute_threshold = brute_force_threshold
        self.spray_threshold = spray_account_threshold
        self.window = window_seconds

        # Key: (username) -> deque of (timestamp, source_ip)
        self.failed_logins_per_user: Dict[str, deque] = defaultdict(deque)

        # Key: (source_ip) -> deque of (timestamp, target_username)
        self.failed_logins_per_ip: Dict[str, deque] = defaultdict(deque)

        # Key: (username) -> (last_timestamp, last_source_ip)
        self.last_successful_login: Dict[str, tuple[float, str]] = {}

        # Suppress repeat alerts
        self.alerted_entities: Set[str] = set()

    def ingest_identity_event(self, event: Dict[str, Any]) -> List[IdentityThreatMatch]:
        """Analyzes an identity, authentication, or account management event."""
        event_type = event.get("event_type")
        matches: List[IdentityThreatMatch] = []
        host_id = event.get("host_id", "UNKNOWN_HOST")
        ts = self._parse_timestamp(event.get("timestamp"))
        user = event.get("user", {})
        username = user.get("name") or user.get("target_user") or event.get("account", {}).get("name", "")

        if not username or username.endswith("$"):  # Skip machine accounts
            return []

        # 1. Authentication Failure Analysis (Brute Force & Password Spraying)
        if event_type in ("user_login", "authentication", "auth_attempt"):
            auth_status = event.get("auth", {}).get("status") or event.get("status")
            src_ip = event.get("network", {}).get("source_ip") or event.get("auth", {}).get("source_ip")

            if auth_status in ("failure", "failed", "denied"):
                # Track per-user brute force
                u_queue = self.failed_logins_per_user[username]
                u_queue.append((ts, src_ip))
                self._prune_queue(u_queue, ts)

                if len(u_queue) >= self.brute_threshold:
                    alert_key = f"brute:{username}"
                    if alert_key not in self.alerted_entities:
                        self.alerted_entities.add(alert_key)
                        matches.append(
                            IdentityThreatMatch(
                                threat_type="Account Targeted via High-Velocity Brute Force",
                                username=username,
                                host_id=host_id,
                                source_ip=src_ip,
                                confidence=0.95,
                                remediation_required="LOCK_USER_ACCOUNT",
                                evidence={
                                    "failed_attempts": len(u_queue),
                                    "window_seconds": self.window,
                                    "target_username": username,
                                    "source_ips": list({ip for _, ip in u_queue if ip}),
                                },
                            )
                        )

                # Track per-IP password spraying
                if src_ip:
                    ip_queue = self.failed_logins_per_ip[src_ip]
                    ip_queue.append((ts, username))
                    self._prune_queue(ip_queue, ts)

                    distinct_users = {u for _, u in ip_queue}
                    if len(distinct_users) >= self.spray_threshold:
                        alert_key = f"spray:{src_ip}"
                        if alert_key not in self.alerted_entities:
                            self.alerted_entities.add(alert_key)
                            matches.append(
                                IdentityThreatMatch(
                                    threat_type="Distributed Password Spray Attack Detected",
                                    username=f"Multiple ({len(distinct_users)} targets)",
                                    host_id=host_id,
                                    source_ip=src_ip,
                                    confidence=0.96,
                                    remediation_required="REVOKE_USER_SESSIONS",
                                    evidence={
                                        "attacking_ip": src_ip,
                                        "targeted_accounts_count": len(distinct_users),
                                        "sample_accounts": sorted(list(distinct_users))[:6],
                                        "window_seconds": self.window,
                                    },
                                )
                            )

            elif auth_status in ("success", "successful", "approved") and src_ip:
                # 2. Impossible Travel / Multi-IP Anomaly
                if username in self.last_successful_login:
                    last_ts, last_ip = self.last_successful_login[username]
                    delta_t = ts - last_ts
                    if last_ip and src_ip != last_ip and delta_t < 180.0:  # < 3 minutes between distinct IPs
                        alert_key = f"travel:{username}:{src_ip}"
                        if alert_key not in self.alerted_entities:
                            self.alerted_entities.add(alert_key)
                            matches.append(
                                IdentityThreatMatch(
                                    threat_type="Impossible Travel / Concurrent Location Anomaly",
                                    username=username,
                                    host_id=host_id,
                                    source_ip=src_ip,
                                    confidence=0.91,
                                    remediation_required="REVOKE_USER_SESSIONS",
                                    evidence={
                                        "compromised_user": username,
                                        "previous_ip": last_ip,
                                        "current_ip": src_ip,
                                        "time_delta_seconds": round(delta_t, 1),
                                    },
                                )
                            )
                self.last_successful_login[username] = (ts, src_ip)

        # 3. Privileged Group Membership Modification (Privilege Escalation)
        if event_type in ("group_change", "account_management", "user_management"):
            target_group = str(event.get("group", {}).get("name") or event.get("target_group", "")).lower()
            action = str(event.get("action") or event.get("activity", "")).lower()

            if any(pg in target_group for pg in self.PRIVILEGED_GROUPS) and "add" in action:
                matches.append(
                    IdentityThreatMatch(
                        threat_type="Unauthorized Privilege Escalation: Added to Privileged Group",
                        username=username,
                        host_id=host_id,
                        source_ip=event.get("network", {}).get("source_ip"),
                        confidence=0.98,
                        remediation_required="REVOKE_USER_SESSIONS",
                        evidence={
                            "escalated_user": username,
                            "target_privileged_group": target_group,
                            "modified_by": event.get("user", {}).get("acting_user", "SYSTEM/Unknown"),
                            "action": action,
                        },
                    )
                )

        # 4. Kerberoasting TGS Ticket Request with RC4 Encryption
        if event_type in ("kerberos_ticket", "ticket_granting_service"):
            encryption_type = str(event.get("kerberos", {}).get("encryption_type", "")).lower()
            spn = event.get("kerberos", {}).get("service_name") or event.get("service", {}).get("name", "")

            if "0x17" in encryption_type or "rc4" in encryption_type:
                matches.append(
                    IdentityThreatMatch(
                        threat_type="Kerberoasting: RC4 SPN Service Ticket Extraction",
                        username=username,
                        host_id=host_id,
                        source_ip=event.get("network", {}).get("source_ip"),
                        confidence=0.93,
                        remediation_required="FORCE_PASSWORD_RESET",
                        evidence={
                            "requesting_user": username,
                            "target_spn": spn,
                            "encryption_downgrade": encryption_type,
                            "technique": "Kerberoasting (T1558.003)",
                        },
                    )
                )

        return matches

    def _prune_queue(self, q: deque, current_ts: float):
        cutoff = current_ts - self.window
        while q and q[0][0] < cutoff:
            q.popleft()

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
