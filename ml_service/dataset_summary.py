
import csv
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "data" / "ml_model_input.csv"

with FILE.open("r", encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f))

print("========== CLOUDSENTINEL DATASET SUMMARY ==========")
print("Total events:", len(rows))
print("Unique users:", len(set(r["user_id"] for r in rows)))

print("\nEvent source distribution:")
for source, count in Counter(r["event_source"] for r in rows).items():
    print(source, ":", count)

print("\nFeature flag counts:")
for feature in [
    "is_faas",
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag"
]:
    count = sum(float(r[feature]) for r in rows)
    print(feature, ":", int(count))

print("\nDataset summary completed.")
