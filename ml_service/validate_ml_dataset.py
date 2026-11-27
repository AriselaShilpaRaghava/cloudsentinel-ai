
import csv
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "data" / "ml_model_input.csv"

FEATURES = [
    "is_faas",
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag",
    "time_gap_minutes",
    "time_gap_missing_flag"
]

with FILE.open("r", encoding="utf-8", newline="") as file:
    rows = list(csv.DictReader(file))

invalid_values = []

for row in rows:
    for feature in FEATURES:
        try:
            value = float(row[feature])
            if not math.isfinite(value):
                invalid_values.append((row["event_id"], feature, value))
        except (ValueError, TypeError):
            invalid_values.append((row["event_id"], feature, row[feature]))

event_ids = [row["event_id"] for row in rows]

print("Total rows:", len(rows))
print("Numerical features:", len(FEATURES))
print("Unique event IDs:", len(set(event_ids)))
print("Invalid numerical values:", len(invalid_values))
print("FaaS rows:", sum(float(row["is_faas"]) for row in rows))
print(
    "Missing time-gap indicators:",
    sum(float(row["time_gap_missing_flag"]) for row in rows)
)

if invalid_values:
    print("Invalid details:", invalid_values)

if (
    len(event_ids) == len(set(event_ids))
    and not invalid_values
):
    print("ML dataset validation completed successfully.")
