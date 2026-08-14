"""Main CLI entrypoint for eyedetect Detection Engine.

Orchestrates Wazuh-grade detection rules (Levels 0-16), Threat Intelligence IOC matching,
stateful process tree tracking, frequency threshold analysis, multi-event correlation,
and Active Response automated containment.
"""

import argparse
import sys
from pathlib import Path

# Fix Windows console encoding for UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.alerting.active_response import ActiveResponseEngine
from src.alerting.alert import Alert
from src.alerting.formatter import AlertFormatter
from src.correlation.correlation_engine import CorrelationEngine
from src.correlation.process_tree import ProcessTree
from src.evaluator.engine import RuleEvaluator
from src.evaluator.threshold import ThresholdEngine
from src.ingestion.event_reader import EventReader
from src.rules.loader import RuleLoader
from src.threat_intel.ioc_lookup import ThreatIntelEngine


def main():
    parser = argparse.ArgumentParser(
        description="eyedetect - Wazuh-Grade EDR Detection, Threat Intel & Active Response Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--rules",
        type=str,
        default="rules",
        help="Path to detection rules directory",
    )
    parser.add_argument(
        "--telemetry",
        type=str,
        default="samples/attack_simulation.ndjson",
        help="Path to telemetry NDJSON file",
    )
    parser.add_argument(
        "--output-format",
        choices=["console", "json", "ndjson"],
        default="console",
        help="Alert display format",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Optional path to save generated alerts (NDJSON format)",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("[*] eyedetect - Wazuh-Grade EDR Detection & Correlation Engine")
    print("=" * 70)

    # 1. Load Rules
    rules_path = Path(args.rules)
    loader = RuleLoader()

    try:
        if rules_path.is_file():
            rules = [loader.load_file(rules_path)]
        elif rules_path.is_dir():
            rules = loader.load_directory(rules_path)
        else:
            print(f"[ERROR] Rules path does not exist: {rules_path}")
            sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to load rules: {e}")
        sys.exit(1)

    print(f"[*] Loaded and validated {len(rules)} active detection rule(s):")
    for r in sorted(rules, key=lambda x: -x.level):
        print(f"    - [{r.id}] (Lvl {r.level:2d} | {r.severity.upper():8s}) {r.name}")

    # 2. Initialize Subsystems
    threat_intel = ThreatIntelEngine()
    process_tree = ProcessTree()
    evaluator = RuleEvaluator(rules, process_tree=process_tree, threat_intel=threat_intel)
    threshold_engine = ThresholdEngine()
    correlation_engine = CorrelationEngine()

    print(f"\n[*] Loaded Threat Intelligence Engine with high-confidence IOC hash/IP feeds.")
    print(f"[*] Initialized Process Tree & Stateful Ancestry Engine.")
    print(f"[*] Initialized Threshold & Frequency Engine ({len(threshold_engine.rules)} active rules).")
    print(f"[*] Initialized Multi-Event Correlation Engine ({len(correlation_engine.correlation_rules)} attack chains).")

    # 3. Ingest and Evaluate Telemetry
    telemetry_path = Path(args.telemetry)
    if not telemetry_path.exists():
        print(f"[ERROR] Telemetry file not found: {telemetry_path}")
        sys.exit(1)

    print(f"[*] Ingesting and evaluating telemetry from: {telemetry_path}\n")

    events_count = 0
    atomic_alerts_count = 0
    threshold_alerts_count = 0
    incident_alerts_count = 0
    active_responses_count = 0
    all_generated_alerts = []

    for event in EventReader.read_ndjson(telemetry_path):
        events_count += 1

        # A. Evaluate Atomic & Threat Intel Rules
        results = evaluator.evaluate_event(event)
        for res in results:
            atomic_alerts_count += 1
            alert = Alert.from_detection_result(res)
            all_generated_alerts.append(alert)

            if alert.active_response:
                active_responses_count += 1

            _print_alert(alert, args.output_format)

            # B. Ingest into Multi-Event Correlation Engine
            incidents = correlation_engine.ingest_detection(res)
            for inc in incidents:
                incident_alerts_count += 1
                inc_alert = inc.to_alert()
                inc_alert.level = 16  # Correlated incidents are emergency level 16
                all_generated_alerts.append(inc_alert)
                _print_alert(inc_alert, args.output_format)

        # C. Evaluate Frequency & Threshold Rules (e.g. Mass Ransomware Encryption)
        thresh_matches = threshold_engine.ingest_event(event)
        for tm in thresh_matches:
            threshold_alerts_count += 1
            ar_action = ActiveResponseEngine.resolve_action(
                level=tm.rule.level,
                event=event,
                custom_action=tm.rule.active_response,
                reason=f"Threshold rule [{tm.rule.id}] triggered: {tm.event_count} events in {tm.timeframe_seconds}s",
            )
            if ar_action:
                active_responses_count += 1

            thresh_alert = Alert(
                alert_id=f"ALT-TH-{tm.rule.id}",
                rule_id=tm.rule.id,
                title=f"[FREQUENCY THRESHOLD] {tm.rule.name}",
                description=tm.rule.description,
                level=tm.rule.level,
                severity=tm.rule.severity,
                confidence=tm.rule.confidence,
                host_id=tm.host_id,
                timestamp=event.get("timestamp", ""),
                event_id=event.get("event_id"),
                evidence=tm.evidence,
                active_response=ar_action.to_dict() if ar_action else None,
                mitre_tactic=tm.rule.mitre_tactic,
                mitre_technique=tm.rule.mitre_technique,
                tags=["attack.impact", "ransomware", "threshold_trigger"],
            )
            all_generated_alerts.append(thresh_alert)
            _print_alert(thresh_alert, args.output_format)

    # Save to output file if specified
    if args.output_file:
        out_path = Path(args.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for alt in all_generated_alerts:
                f.write(AlertFormatter.to_ndjson(alt) + "\n")
        print(f"\n[+] Saved {len(all_generated_alerts)} alert log(s) to: {out_path.resolve()}")

    print("\n" + "=" * 70)
    print("[+] Wazuh-Grade Evaluation & Incident Summary:")
    print(f"   • Total Telemetry Events Processed : {events_count}")
    print(f"   • Atomic Threat Detections         : {atomic_alerts_count}")
    print(f"   • Frequency Threshold Detections   : {threshold_alerts_count}")
    print(f"   • Correlated Multi-Stage Incidents : {incident_alerts_count}")
    print(f"   • Automated Active Responses Fired : {active_responses_count}")
    print("=" * 70)


def _print_alert(alert: Alert, fmt: str):
    if fmt == "console":
        print(AlertFormatter.to_console(alert))
    elif fmt == "json":
        print(AlertFormatter.to_json(alert))
    elif fmt == "ndjson":
        print(AlertFormatter.to_ndjson(alert))


if __name__ == "__main__":
    main()
