"""Main CLI entrypoint for eyedetect Detection Engine."""

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
from src.evaluator.engine import RuleEvaluator
from src.ingestion.event_reader import EventReader
from src.rules.loader import RuleLoader


def main():
    parser = argparse.ArgumentParser(
        description="eyedetect - EDR Detection Engine MVP",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--rules",
        type=str,
        default="rules",
        help="Path to detection rules directory or single YAML rule",
    )
    parser.add_argument(
        "--telemetry",
        type=str,
        default="samples/telemetry.ndjson",
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
        help="Optional path to save generated alerts (NDJSON or JSON format)",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("[*] eyedetect - EDR Detection Engine MVP")
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

    print(f"[*] Loaded and validated {len(rules)} active detection rule(s).")
    for r in rules:
        print(f"    - [{r.id}] ({r.severity.upper()}) {r.name}")

    print("\n[*] Initializing Evaluation Engine...")
    evaluator = RuleEvaluator(rules)

    # 2. Ingest and Evaluate Telemetry
    telemetry_path = Path(args.telemetry)
    if not telemetry_path.exists():
        print(f"[ERROR] Telemetry file not found: {telemetry_path}")
        sys.exit(1)

    print(f"[*] Ingesting and evaluating telemetry from: {telemetry_path}\n")

    events_count = 0
    alerts_count = 0
    generated_alerts = []

    for event in EventReader.read_ndjson(telemetry_path):
        events_count += 1
        results = evaluator.evaluate_event(event)

        for res in results:
            alerts_count += 1
            alert = Alert.from_detection_result(res)
            generated_alerts.append(alert)

            if args.output_format == "console":
                print(AlertFormatter.to_console(alert))
            elif args.output_format == "json":
                print(AlertFormatter.to_json(alert))
            elif args.output_format == "ndjson":
                print(AlertFormatter.to_ndjson(alert))

    # Save to output file if specified
    if args.output_file:
        out_path = Path(args.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for alt in generated_alerts:
                f.write(AlertFormatter.to_ndjson(alt) + "\n")
        print(f"\n[+] Saved {len(generated_alerts)} alert log(s) to: {out_path.resolve()}")

    print("\n" + "=" * 70)
    print("[+] Evaluation Summary:")
    print(f"   • Total Events Processed : {events_count}")
    print(f"   • Total Alerts Triggered  : {alerts_count}")
    print("=" * 70)


if __name__ == "__main__":
    main()
