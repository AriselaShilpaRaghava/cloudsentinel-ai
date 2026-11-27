
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "data" / "normalized_event_features.csv"

with FILE.open("r", encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f))

binary_fields = [
    "is_faas",
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag"
]

invalid_values = []

for row in rows:
    for field in binary_fields:
        if row[field] not in {"0", "1"}:
            invalid_values.append((row["event_id"], field, row[field]))

event_ids = [row["event_id"] for row in rows]

missing_fields = [
    (row["event_id"], field)
    for row in rows
    for field, value in row.items()
    if value is None
]

print("Total feature rows:", len(rows))
print("Unique event IDs:", len(set(event_ids)))
print("FaaS rows:", sum(int(row["is_faas"]) for row in rows))
print("Invalid binary values:", len(invalid_values))
print("Missing values:", len(missing_fields))

if invalid_values:
    print("Invalid details:", invalid_values)

if len(event_ids) == len(set(event_ids)) and not invalid_values and not missing_fields:
    print("Feature validation completed successfully.")
