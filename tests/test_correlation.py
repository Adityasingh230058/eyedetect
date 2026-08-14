"""Unit tests for ProcessTree ancestry and Multi-Event Correlation Engine."""

from src.correlation.process_tree import ProcessTree
from src.correlation.correlation_engine import CorrelationEngine, CorrelationRule
from src.rules.schema import Rule, LogicNode, Condition
from src.evaluator.engine import DetectionResult


def test_process_tree_ancestry_and_pid_reuse():
    tree = ProcessTree()

    # 1. explorer.exe starts
    tree.handle_event({
        "event_type": "process_create",
        "host_id": "HOST-01",
        "timestamp": "2026-08-14T10:00:00Z",
        "process": {"name": "explorer.exe", "pid": 1000, "process_guid": "{GUID-EXP}"},
        "parent": {"pid": 500},
    })

    # 2. explorer launches winword.exe
    tree.handle_event({
        "event_type": "process_create",
        "host_id": "HOST-01",
        "timestamp": "2026-08-14T10:01:00Z",
        "process": {"name": "winword.exe", "pid": 2000, "process_guid": "{GUID-WORD}"},
        "parent": {"process_guid": "{GUID-EXP}", "pid": 1000},
    })

    # 3. winword launches cmd.exe
    tree.handle_event({
        "event_type": "process_create",
        "host_id": "HOST-01",
        "timestamp": "2026-08-14T10:01:05Z",
        "process": {"name": "cmd.exe", "pid": 3000, "process_guid": "{GUID-CMD}"},
        "parent": {"process_guid": "{GUID-WORD}", "pid": 2000},
    })

    # 4. cmd launches powershell.exe
    tree.handle_event({
        "event_type": "process_create",
        "host_id": "HOST-01",
        "timestamp": "2026-08-14T10:01:10Z",
        "process": {"name": "powershell.exe", "pid": 4000, "process_guid": "{GUID-PS}"},
        "parent": {"process_guid": "{GUID-CMD}", "pid": 3000},
    })

    # Check ancestry traversal
    ancestors = tree.get_ancestors("{GUID-PS}")
    ancestor_names = [a.name for a in ancestors]
    assert ancestor_names == ["cmd.exe", "winword.exe", "explorer.exe"]

    assert tree.has_ancestor("{GUID-PS}", ["winword.exe"])
    assert tree.has_ancestor("{GUID-PS}", ["explorer.exe"])
    assert not tree.has_ancestor("{GUID-PS}", ["notepad.exe"])

    lineage = tree.get_lineage_string("{GUID-PS}")
    assert lineage == "explorer.exe -> winword.exe -> cmd.exe -> powershell.exe"


def test_multi_event_correlation():
    corr_engine = CorrelationEngine()

    rule_proc = Rule(
        id="DET-PROC-001",
        name="Office spawns PowerShell",
        event_type="process_create",
        logic=LogicNode(all=[Condition(field="process.name", operator="equals", value="powershell.exe")]),
    )

    rule_net = Rule(
        id="DET-NET-001",
        name="PowerShell outbound network",
        event_type="network_connect",
        logic=LogicNode(all=[Condition(field="process.name", operator="equals", value="powershell.exe")]),
    )

    event_stage1 = {
        "event_id": "evt-1",
        "host_id": "HOST-01",
        "timestamp": "2026-08-14T12:00:00Z",
        "process": {"name": "powershell.exe", "process_guid": "{GUID-ATTACK-01}"},
    }

    event_stage2 = {
        "event_id": "evt-2",
        "host_id": "HOST-01",
        "timestamp": "2026-08-14T12:00:08Z",
        "process": {"name": "powershell.exe", "process_guid": "{GUID-ATTACK-01}"},
    }

    # Ingest Stage 1 (Atomic match, no correlation yet)
    incidents_1 = corr_engine.ingest_detection(DetectionResult(rule=rule_proc, event=event_stage1))
    assert len(incidents_1) == 0

    # Ingest Stage 2 (Triggers CORR-001!)
    incidents_2 = corr_engine.ingest_detection(DetectionResult(rule=rule_net, event=event_stage2))
    assert len(incidents_2) == 1
    assert incidents_2[0].correlation_rule_id == "CORR-001"
    assert incidents_2[0].severity == "critical"
