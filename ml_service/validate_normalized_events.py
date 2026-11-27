
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "data" / "normalized_events.json"

events = json.loads(FILE.read_text(encoding="utf-8"))

required_fields = [
    "event_id",
    "timestamp",
    "user_id",
    "provider",
    "event_source",
    "action",
    "resource",
    "source_ip",
    "status",
    "is_faas",
    "is_simulated"
]

missing_fields = []
event_ids = [event["event_id"] for event in events]

for index, event in enumerate(events, start=1):
    for field in required_fields:
        if field not in event or event[field] is None:
            missing_fields.append((index, field))

print("Total events:", len(events))
print("Audit events:", sum(e["event_source"] == "audit_log" for e in events))
print("FaaS events:", sum(e["event_source"] == "faas" for e in events))
print("Duplicate event IDs:", len(event_ids) - len(set(event_ids)))
print("Missing required fields:", len(missing_fields))

if missing_fields:
    print("Missing field details:", missing_fields)

if len(event_ids) != len(set(event_ids)):
    print("Duplicate IDs found.")

if not missing_fields and len(event_ids) == len(set(event_ids)):
    print("Validation completed successfully.")
