
import csv
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_ROOT / "data" / "event_behavior_features.csv"

BINARY_COLUMNS = [
    "failed_event_flag",
    "sensitive_action_flag",
    "sensitive_resource_flag",
    "off_hours_flag",
    "ip_change_flag",
]


def main():
    with INPUT_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    print("Total event rows:", len(rows))
    print("Unique users:", len(set(row["user_id"] for row in rows)))

    print("\nFeature flag counts:")
    for column in BINARY_COLUMNS:
        counts = Counter(row[column] for row in rows)
        print(f"{column}: {dict(counts)}")

    print("\nMissing time gaps:", sum(
        row["time_gap_minutes"] == "" for row in rows
    ))

    invalid_flags = [
        (column, row["user_id"], row[column])
        for column in BINARY_COLUMNS
        for row in rows
        if row[column] not in {"0", "1"}
    ]

    print("Invalid binary flags:", len(invalid_flags))

    negative_gaps = [
        row for row in rows
        if row["time_gap_minutes"] != ""
        and float(row["time_gap_minutes"]) < 0
    ]

    print("Negative time gaps:", len(negative_gaps))

    print("\nUser event counts:")
    for user, count in Counter(row["user_id"] for row in rows).items():
        print(f"{user}: {count}")

    if len(rows) == 51 and not invalid_flags and not negative_gaps:
        print("\nValidation completed successfully.")
    else:
        print("\nValidation needs attention.")


if __name__ == "__main__":
    main()
