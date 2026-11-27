
import csv
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_ROOT / "data" / "sample_audit_logs.csv"
OUTPUT_FILE = PROJECT_ROOT / "data" / "event_behavior_features.csv"

SENSITIVE_ACTIONS = {
    "delete_logs",
    "export_keys",
    "download_bulk",
    "assume_role",
    "modify_security_group",
    "spawn_vm",
}

SENSITIVE_RESOURCES = {
    "customer_pii_vault",
    "financial_records_db",
    "kms_keystone",
    "role_cloud_admin",
    "cloud_audit_trail",
}


def extract_features(events):
    user_events = defaultdict(list)

    for event in events:
        user_events[event["user_id"]].append(event)

    feature_rows = []

    for user_id, records in user_events.items():
        records.sort(
            key=lambda row: datetime.strptime(
                row["timestamp"], "%Y-%m-%d %H:%M:%S"
            )
        )

        previous_time = None
        previous_ip = None

        for index, event in enumerate(records, start=1):
            event_time = datetime.strptime(
                event["timestamp"], "%Y-%m-%d %H:%M:%S"
            )

            action = event["action"].strip().lower()
            resource = event["resource"].strip().lower()
            source_ip = event["source_ip"].strip()

            hour = event_time.hour

            time_gap = ""
            if previous_time is not None:
                time_gap = round(
                    (event_time - previous_time).total_seconds() / 60, 2
                )

            feature_rows.append({
                "timestamp": event["timestamp"],
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "source_ip": source_ip,
                "status": event["status"].strip().lower(),
                "event_sequence": index,
                "failed_event_flag": int(
                    event["status"].strip().lower() in {"failure", "failed", "denied"}
                ),
                "sensitive_action_flag": int(
                    action in SENSITIVE_ACTIONS
                ),
                "sensitive_resource_flag": int(
                    resource in SENSITIVE_RESOURCES
                ),
                "off_hours_flag": int(hour < 6 or hour >= 22),
                "ip_change_flag": int(
                    previous_ip is not None and source_ip != previous_ip
                ),
                "time_gap_minutes": time_gap,
            })

            previous_time = event_time
            previous_ip = source_ip

    return feature_rows


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input dataset not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "timestamp", "user_id", "action",
            "resource", "source_ip", "status"
        }

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError("Required CSV columns are missing.")

        events = list(reader)

    features = extract_features(events)

    if not features:
        raise ValueError("No events found in the input dataset.")

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=features[0].keys()
        )
        writer.writeheader()
        writer.writerows(features)

    print("Feature extraction completed successfully.")
    print(f"Input events: {len(events)}")
    print(f"Output feature rows: {len(features)}")
    print(f"Unique users: {len(set(row['user_id'] for row in features))}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
