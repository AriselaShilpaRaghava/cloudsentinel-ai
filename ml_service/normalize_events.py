
import csv
import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

AUDIT_FILE = DATA_DIR / "sample_audit_logs.csv"
STORE_FILE = DATA_DIR / "store.json"
OUTPUT_FILE = DATA_DIR / "normalized_events.json"


def get_value(record, *keys, default=""):
    """Return the first available value from possible field names."""
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return default


def normalize_audit_event(event, index):
    timestamp = get_value(event, "timestamp", "event_time")

    return {
        "event_id": f"AUDIT-{index:03d}",
        "timestamp": str(timestamp),
        "user_id": str(get_value(event, "user_id", "cloud_user_id", default="unknown")),
        "provider": "cloud_audit",
        "event_source": "audit_log",
        "action": str(get_value(event, "action", "event_name", default="unknown")),
        "resource": str(get_value(event, "resource", "resource_name", default="unknown")),
        "source_ip": str(get_value(event, "source_ip", "ip_address", default="unknown")),
        "status": str(get_value(event, "status", "result", default="unknown")).lower(),
        "is_faas": False,
        "is_simulated": True
    }


def normalize_faas_event(event, index):
    return {
        "event_id": f"FAAS-{index:03d}",
        "timestamp": str(get_value(
            event, "timestamp", "event_time", "execution_time", default="unknown"
        )),
        "user_id": str(get_value(
            event, "user_id", "cloud_user_id", "principal_id", default="unknown"
        )),
        "provider": str(get_value(event, "provider", default="faas_simulated")),
        "event_source": "faas",
        "action": str(get_value(
            event, "action", "event_name", "function_name", default="function_invocation"
        )),
        "resource": str(get_value(
            event, "resource", "function_name", "function", default="unknown"
        )),
        "source_ip": str(get_value(event, "source_ip", "ip_address", default="unknown")),
        "status": str(get_value(event, "status", "result", default="unknown")).lower(),
        "is_faas": True,
        "is_simulated": bool(event.get("is_simulated", True))
    }


def main():
    normalized_events = []

    if not AUDIT_FILE.exists():
        raise FileNotFoundError(f"Audit CSV not found: {AUDIT_FILE}")

    # Read the original audit CSV.
    with AUDIT_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        for index, event in enumerate(reader, start=1):
            normalized_events.append(
                normalize_audit_event(event, index)
            )

    # Read only FaaS events from store.json.
    if STORE_FILE.exists():
        with STORE_FILE.open("r", encoding="utf-8") as file:
            store = json.load(file)

        faas_events = store.get("faas_events", [])

        for index, event in enumerate(faas_events, start=1):
            normalized_events.append(
                normalize_faas_event(event, index)
            )

    OUTPUT_FILE.write_text(
        json.dumps(normalized_events, indent=4),
        encoding="utf-8"
    )

    print("Event normalization completed successfully.")
    print(f"Audit events: {sum(e['event_source'] == 'audit_log' for e in normalized_events)}")
    print(f"FaaS events: {sum(e['event_source'] == 'faas' for e in normalized_events)}")
    print(f"Total normalized events: {len(normalized_events)}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
