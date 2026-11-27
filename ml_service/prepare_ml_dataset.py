
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

INPUT_FILE = DATA_DIR / "normalized_event_features.csv"
OUTPUT_FILE = DATA_DIR / "ml_model_input.csv"

FEATURE_COLUMNS = [
    "is_faas",
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag",
    "time_gap_minutes"
]

METADATA_COLUMNS = [
    "event_id",
    "user_id",
    "event_source"
]


def main():
    with INPUT_FILE.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))

    prepared_rows = []

    for row in rows:
        prepared = {
            "event_id": row["event_id"],
            "user_id": row["user_id"],
            "event_source": row["event_source"]
        }

        for feature in FEATURE_COLUMNS:
            value = row[feature]

            # First event for each user has no previous time gap.
            # Represent it as 0 and preserve a missing-value indicator.
            if feature == "time_gap_minutes" and value == "":
                prepared["time_gap_missing_flag"] = 1
                prepared[feature] = 0.0
            else:
                if feature == "time_gap_minutes":
                    prepared["time_gap_missing_flag"] = 0
                prepared[feature] = float(value)

        prepared_rows.append(prepared)

    output_columns = (
        METADATA_COLUMNS
        + FEATURE_COLUMNS
        + ["time_gap_missing_flag"]
    )

    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=output_columns)
        writer.writeheader()
        writer.writerows(prepared_rows)

    print("ML input dataset prepared successfully.")
    print("Total rows:", len(prepared_rows))
    print("Numerical features:", len(FEATURE_COLUMNS) + 1)
    print("Metadata columns:", len(METADATA_COLUMNS))
    print("Output:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
