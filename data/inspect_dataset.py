
import json
from pathlib import Path
from collections import defaultdict

# Dataset location
dataset_path = Path("data/security_events.jsonl")

if not dataset_path.exists():
    print("Dataset file not found:", dataset_path)
    raise SystemExit

field_types = defaultdict(set)
field_count = defaultdict(int)
total_records = 0
first_record = None

with dataset_path.open("r", encoding="utf-8") as file:
    for line in file:
        if not line.strip():
            continue

        record = json.loads(line)
        total_records += 1

        if first_record is None:
            first_record = record

        for field, value in record.items():
            field_count[field] += 1
            field_types[field].add(type(value).__name__)

print("\nTOTAL RECORDS:", total_records)

print("\nEXACT INPUT FIELDS:")
for field in sorted(field_count):
    print(
        f"{field:25} "
        f"Types: {', '.join(sorted(field_types[field])):20} "
        f"Present: {field_count[field]}/{total_records}"
    )

print("\nFIRST DATASET RECORD:")
print(json.dumps(first_record, indent=4))
