"""Enterprise-Wide Multi-Hop Incident Graph & Lateral Pivot Tracker.

Constructs unified attack progression graphs across multiple endpoints, user accounts,
internal network segments, and cloud workloads to reconstruct the full Cyber Kill Chain.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class AttackGraphNode:
    """Represents an asset (Host, User, Cloud Account, IP) in the Enterprise Attack Graph."""
    entity_id: str
    entity_type: str  # "ENDPOINT", "USER", "CLOUD_ACCOUNT", "C2_SERVER", "STORAGE_BUCKET"
    first_seen: str
    risk_score: int = 0
    tags: Set[str] = field(default_factory=set)


@dataclass
class AttackGraphEdge:
    """Represents a threat movement or lateral pivot step."""
    source_entity: str
    target_entity: str
    pivot_mechanism: str  # "PHISHING_DROPPER", "LATERAL_WMI", "PASS_THE_HASH", "CLOUD_IAM_ABUSE", "EXFILTRATION"
    rule_id: str
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnterpriseKillChainIncident:
    """Represents a full multi-hop, cross-domain attack across the enterprise."""
    incident_id: str
    title: str
    root_cause_asset: str
    lateral_pivot_path: List[str]  # e.g. ["LAPTOP-01", "SRV-PIVOT-02", "DC-WIN-01", "AWS:Production"]
    compromised_identities: List[str]
    total_stages: int
    severity: str
    confidence: float
    graph_edges: List[AttackGraphEdge]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EnterpriseAttackGraph:
    """Tracks global entity connections and identifies enterprise-wide lateral attack campaigns."""

    def __init__(self):
        self.nodes: Dict[str, AttackGraphNode] = {}
        self.edges: List[AttackGraphEdge] = []
        # Key: source_host -> list of target_hosts
        self.lateral_hops: Dict[str, Set[str]] = defaultdict(set)
        # Active campaigns
        self.campaigns: List[EnterpriseKillChainIncident] = []

    def record_attack_step(
        self,
        source_id: str,
        source_type: str,
        target_id: str,
        target_type: str,
        pivot_mechanism: str,
        rule_id: str,
        timestamp: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[EnterpriseKillChainIncident]:
        """Ingests an attack step and updates the enterprise graph."""
        # 1. Update Nodes
        if source_id not in self.nodes:
            self.nodes[source_id] = AttackGraphNode(entity_id=source_id, entity_type=source_type, first_seen=timestamp)
        if target_id not in self.nodes:
            self.nodes[target_id] = AttackGraphNode(entity_id=target_id, entity_type=target_type, first_seen=timestamp)

        # 2. Add Edge
        edge = AttackGraphEdge(
            source_entity=source_id,
            target_entity=target_id,
            pivot_mechanism=pivot_mechanism,
            rule_id=rule_id,
            timestamp=timestamp,
            details=details or {},
        )
        self.edges.append(edge)

        if source_type == "ENDPOINT" and target_type in ("ENDPOINT", "CLOUD_ACCOUNT"):
            self.lateral_hops[source_id].add(target_id)

        # 3. Detect Multi-Hop Lateral Propagation (Path length >= 3 assets)
        path = self._find_longest_pivot_chain(source_id)
        if len(path) >= 3:
            incident_id = f"ENT-CAMPAIGN-{len(self.campaigns) + 1:03d}"
            # Check if this campaign path is already reported
            for c in self.campaigns:
                if c.lateral_pivot_path == path:
                    return None

            campaign = EnterpriseKillChainIncident(
                incident_id=incident_id,
                title=f"Multi-Hop Lateral Campaign Pivoting across {len(path)} Enterprise Assets",
                root_cause_asset=path[0],
                lateral_pivot_path=path,
                compromised_identities=[details.get("user") for edge in self.edges if details and "user" in details and details["user"]],
                total_stages=len(path) - 1,
                severity="critical",
                confidence=0.98,
                graph_edges=self.edges[-len(path):],
                timestamp=timestamp,
            )
            self.campaigns.append(campaign)
            return campaign

        return None

    def _find_longest_pivot_chain(self, start_node: str) -> List[str]:
        """Traverses the lateral hop graph to reconstruct the full pivot path."""
        # Trace backwards to find the true root cause
        parents = {target: source for source, targets in self.lateral_hops.items() for target in targets}
        current = start_node
        visited = set()
        while current in parents and current not in visited:
            visited.add(current)
            current = parents[current]
        root = current

        # Now traverse forward from root
        chain = [root]
        curr = root
        visited_forward = {root}
        while curr in self.lateral_hops and self.lateral_hops[curr]:
            next_hop = list(self.lateral_hops[curr])[0]
            if next_hop in visited_forward:
                break
            visited_forward.add(next_hop)
            chain.append(next_hop)
            curr = next_hop

        return chain
