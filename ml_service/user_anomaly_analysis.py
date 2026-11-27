
import csv
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT / "data" / "isolation_forest_predictions.csv"
OUTPUT_FILE = ROOT / "data" / "user_anomaly_summary.csv"

summary = defaultdict(lambda: {"normal": 0, "anomaly": 0})

with INPUT_FILE.open("r", encoding="utf-8", newline="") as file:
    for row in csv.DictReader(file):
        summary[row["user_id"]][row["anomaly_prediction"]] += 1

rows = []

for user, counts in sorted(summary.items()):
    total = counts["normal"] + counts["anomaly"]

    rows.append({
        "user_id": user,
        "total_events": total,
        "normal_predictions": counts["normal"],
        "anomaly_predictions": counts["anomaly"],
        "anomaly_percentage": round(
            counts["anomaly"] / total * 100, 2
        )
    })

with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print("User-wise anomaly analysis completed.")
print("Users analyzed:", len(rows))
print("Output file:", OUTPUT_FILE)

for row in rows:
    print(
        row["user_id"],
        "| Anomalies:", row["anomaly_predictions"],
        "| Percentage:", row["anomaly_percentage"], "%"
    )
