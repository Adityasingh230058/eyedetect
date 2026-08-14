"""Main CLI entrypoint for eyedetect Detection Engine.

Orchestrates rule loading, stateful process tree tracking, streaming telemetry evaluation,
multi-event temporal correlation, and alert generation.
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

from src.alerting.alert import Alert
from src.alerting.formatter import AlertFormatter
from src.correlation.correlation_engine import CorrelationEngine
from src.correlation.process_tree import ProcessTree
from src.evaluator.engine import RuleEvaluator
from src.ingestion.event_reader import EventReader
from src.rules.loader import RuleLoader


def main():
    parser = argparse.ArgumentParser(
        description="eyedetect - Advanced EDR Detection & Correlation Engine",
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
        default="samples/telemetry_extended.ndjson",
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
    print("[*] eyedetect - Advanced EDR Detection & Correlation Engine")
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
    for r in sorted(rules, key=lambda x: x.id):
        print(f"    - [{r.id}] ({r.severity.upper():8s}) {r.name}")

    # 2. Initialize State Trackers & Engines
    process_tree = ProcessTree()
    evaluator = RuleEvaluator(rules, process_tree=process_tree)
    correlation_engine = CorrelationEngine()

    print(f"\n[*] Initialized Process Tree & Stateful Ancestry Engine.")
    print(f"[*] Initialized Multi-Event Correlation Engine with {len(correlation_engine.correlation_rules)} attack chains.")

    # 3. Ingest and Evaluate Telemetry
    telemetry_path = Path(args.telemetry)
    if not telemetry_path.exists():
        print(f"[ERROR] Telemetry file not found: {telemetry_path}")
        sys.exit(1)

    print(f"[*] Ingesting and evaluating telemetry from: {telemetry_path}\n")

    events_count = 0
    atomic_alerts_count = 0
    incident_alerts_count = 0
    all_generated_alerts = []

    for event in EventReader.read_ndjson(telemetry_path):
        events_count += 1
        results = evaluator.evaluate_event(event)

        for res in results:
            atomic_alerts_count += 1
            alert = Alert.from_detection_result(res)
            all_generated_alerts.append(alert)

            if args.output_format == "console":
                print(AlertFormatter.to_console(alert))
            elif args.output_format == "json":
                print(AlertFormatter.to_json(alert))
            elif args.output_format == "ndjson":
                print(AlertFormatter.to_ndjson(alert))

            # 4. Ingest into Correlation Engine
            incidents = correlation_engine.ingest_detection(res)
            for inc in incidents:
                incident_alerts_count += 1
                inc_alert = inc.to_alert()
                all_generated_alerts.append(inc_alert)

                if args.output_format == "console":
                    print(AlertFormatter.to_console(inc_alert))
                elif args.output_format == "json":
                    print(AlertFormatter.to_json(inc_alert))
                elif args.output_format == "ndjson":
                    print(AlertFormatter.to_ndjson(inc_alert))

    # Save to output file if specified
    if args.output_file:
        out_path = Path(args.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for alt in all_generated_alerts:
                f.write(AlertFormatter.to_ndjson(alt) + "\n")
        print(f"\n[+] Saved {len(all_generated_alerts)} alert log(s) to: {out_path.resolve()}")

    print("\n" + "=" * 70)
    print("[+] Evaluation & Correlation Summary:")
    print(f"   • Total Telemetry Events Processed : {events_count}")
    print(f"   • Atomic Threat Detections Triggered: {atomic_alerts_count}")
    print(f"   • Correlated Multi-Stage Incidents  : {incident_alerts_count}")
    print("=" * 70)


if __name__ == "__main__":
    main()
