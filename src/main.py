"""Main CLI entrypoint for eyedetect Detection Engine.

Orchestrates Wazuh-grade detection rules (Levels 0-16), Threat Intelligence IOC matching,
MITRE ATT&CK Matrix Navigator, stateful process tree tracking, inline payload deobfuscation,
Shannon Entropy analysis, frequency thresholding, multi-event correlation,
Entity Risk Scoring (0-100), and Active Response automated containment.
"""

import argparse
import json
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
from src.correlation.risk_scorer import EntityRiskScorer
from src.evaluator.engine import RuleEvaluator
from src.evaluator.threshold import ThresholdEngine
from src.ingestion.event_reader import EventReader
from src.mitre.attack import MitreMatrixNavigator
from src.rules.loader import RuleLoader
from src.threat_intel.ioc_lookup import ThreatIntelEngine


def main():
    parser = argparse.ArgumentParser(
        description="eyedetect - Elite EDR Detection, MITRE Navigator, Deobfuscation & Risk Scoring Engine",
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
    parser.add_argument(
        "--mitre-matrix",
        action="store_true",
        help="Display full MITRE ATT&CK Matrix Coverage Heatmap across loaded rules",
    )
    parser.add_argument(
        "--export-navigator",
        type=str,
        default=None,
        help="Export official MITRE ATT&CK Navigator v4 JSON Layer file",
    )

    args = parser.parse_args()

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

    # MITRE ATT&CK Matrix Heatmap Request
    if args.mitre_matrix:
        print(MitreMatrixNavigator.render_console_heatmap(rules))
        if not args.telemetry:
            return

    # Export Navigator Layer Request
    if args.export_navigator:
        nav_layer = MitreMatrixNavigator.export_navigator_layer(rules)
        out_layer_path = Path(args.export_navigator)
        out_layer_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_layer_path, "w", encoding="utf-8") as f:
            json.dump(nav_layer, f, indent=2)
        print(f"[+] Exported MITRE ATT&CK Navigator Layer to: {out_layer_path.resolve()}")

    print("=" * 70)
    print("[*] eyedetect - Elite EDR Detection, MITRE Navigator & Risk Engine")
    print("=" * 70)

    print(f"[*] Loaded and validated {len(rules)} active detection rule(s):")
    for r in sorted(rules, key=lambda x: -x.level):
        print(f"    - [{r.id}] (Lvl {r.level:2d} | {r.severity.upper():8s}) {r.name}")

    # 2. Initialize Subsystems
    threat_intel = ThreatIntelEngine()
    process_tree = ProcessTree()
    evaluator = RuleEvaluator(rules, process_tree=process_tree, threat_intel=threat_intel)
    threshold_engine = ThresholdEngine()
    correlation_engine = CorrelationEngine()
    risk_scorer = EntityRiskScorer(breach_threshold=75)

    print(f"\n[*] Loaded Threat Intelligence Engine with high-confidence IOC hash/IP feeds.")
    print(f"[*] Initialized Inline Command-Line Deobfuscator & Shannon Entropy Analyzer.")
    print(f"[*] Initialized Process Tree & Stateful Ancestry Engine.")
    print(f"[*] Initialized Threshold & Frequency Engine ({len(threshold_engine.rules)} active rules).")
    print(f"[*] Initialized Multi-Event Correlation Engine ({len(correlation_engine.correlation_rules)} attack chains).")
    print(f"[*] Initialized Entity Risk Scorer & Host Threat Meter (Breach Threshold: 75/100).")

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
    risk_breach_alerts_count = 0
    active_responses_count = 0
    all_generated_alerts = []

    for event in EventReader.read_ndjson(telemetry_path):
        events_count += 1
        host_id = event.get("host_id", "UNKNOWN_HOST")
        ts = event.get("timestamp", "")

        # A. Evaluate Atomic & Threat Intel Rules
        results = evaluator.evaluate_event(event)
        for res in results:
            atomic_alerts_count += 1
            alert = Alert.from_detection_result(res)
            all_generated_alerts.append(alert)

            if alert.active_response:
                active_responses_count += 1

            _print_alert(alert, args.output_format)

            # Update Host Threat Meter
            risk_incident = risk_scorer.record_detection(
                host_id=host_id,
                rule_id=res.rule.id,
                rule_name=res.rule.name,
                level=res.rule.level,
                timestamp=ts,
                summary=res.rule.description,
            )
            if risk_incident:
                risk_breach_alerts_count += 1
                all_generated_alerts.append(risk_incident)
                _print_alert(risk_incident, args.output_format)

            # Ingest into Multi-Event Correlation Engine
            incidents = correlation_engine.ingest_detection(res)
            for inc in incidents:
                incident_alerts_count += 1
                inc_alert = inc.to_alert()
                inc_alert.level = 16
                all_generated_alerts.append(inc_alert)
                _print_alert(inc_alert, args.output_format)

        # B. Evaluate Frequency & Threshold Rules
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
                timestamp=ts,
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
    print("[+] Elite Evaluation & Incident Summary:")
    print(f"   • Total Telemetry Events Processed : {events_count}")
    print(f"   • Atomic Threat Detections         : {atomic_alerts_count}")
    print(f"   • Frequency Threshold Detections   : {threshold_alerts_count}")
    print(f"   • Correlated Multi-Stage Incidents : {incident_alerts_count}")
    print(f"   • Host Threat Meter Breaches (>75) : {risk_breach_alerts_count}")
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
