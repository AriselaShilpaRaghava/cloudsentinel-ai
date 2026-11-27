
import json
import csv
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

INPUT_FILE = DATA_DIR / "normalized_events.json"
OUTPUT_FILE = DATA_DIR / "normalized_event_features.csv"

SENSITIVE_ACTIONS = {
    "assume_role",
    "export_keys",
    "download_bulk",
    "delete_logs",
    "modify_security_group",
    "spawn_vm"
}

SENSITIVE_RESOURCES = {
    "customer_pii_vault",
    "financial_records_db",
    "kms_keystone",
    "role_cloud_admin",
    "cloud_audit_trail"
}


def parse_timestamp(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def main():
    events = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

    events.sort(
        key=lambda event: (
            event["user_id"],
            parse_timestamp(event["timestamp"]) or datetime.max
        )
    )

    previous_event = {}
    rows = []

    for event in events:
        user_id = event["user_id"]
        action = event["action"].lower()
        resource = event["resource"].lower()
        status = event["status"].lower()
        source_ip = event["source_ip"]

        timestamp = parse_timestamp(event["timestamp"])

        previous = previous_event.get(user_id)

        if previous and timestamp and previous["timestamp"]:
            time_gap = (
                timestamp - previous["timestamp"]
            ).total_seconds() / 60
        else:
            time_gap = ""

        if timestamp:
            hour = timestamp.hour
            off_hours = int(hour < 6 or hour >= 22)
        else:
            off_hours = 0

        ip_change = int(
            previous is not None
            and source_ip != previous["source_ip"]
        )

        row = {
            "event_id": event["event_id"],
            "user_id": user_id,
            "event_source": event["event_source"],
            "is_faas": int(event["is_faas"]),
            "failed_event_flag": int(
                status in {"failed", "failure", "denied", "error"}
            ),
            "sensitive_action_flag": int(action in SENSITIVE_ACTIONS),
            "sensitive_resource_flag": int(resource in SENSITIVE_RESOURCES),
            "off_hours_flag": off_hours,
            "ip_change_flag": ip_change,
            "time_gap_minutes": round(time_gap, 2) if time_gap != "" else ""
        }

        rows.append(row)

        if timestamp:
            previous_event[user_id] = {
                "timestamp": timestamp,
                "source_ip": source_ip
            }

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print("Normalized feature extraction completed.")
    print("Input events:", len(events))
    print("Output feature rows:", len(rows))
    print("Unique users:", len(set(row["user_id"] for row in rows)))
    print("FaaS feature rows:", sum(row["is_faas"] for row in rows))
    print("Output file:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
