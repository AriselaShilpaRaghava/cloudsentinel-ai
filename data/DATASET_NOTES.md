
# CloudSentinel AI - Dataset Notes

## Dataset Overview
- Dataset file: sample_audit_logs.csv
- Total events: 51
- Unique users: 6
- Date coverage: 10 March 2026 to 11 March 2026
- Total columns: 6

## Available Fields
- timestamp
- user_id
- action
- resource
- source_ip
- status

## Data Quality
- Missing values: 0
- Duplicate events: 0 (based on checked fields)
- Failed events: 4
- Successful events: 47

## Limitations
- No ground-truth label column is available.
- Events are not confirmed as malicious or normal.
- Dataset has limited event volume and time coverage.
- It should not be treated as verified live AWS CloudTrail or OpenStack data.

## Research Usage
This dataset is used for initial feature extraction,
data validation, and exploratory anomaly detection.

Reliable supervised model evaluation requires
appropriately labelled data.

## Additional Store JSON Inspection

- Contains 51 audit log records.
- Contains 51 existing detection records.
- Contains 3 FaaS event records.
- All 3 FaaS records are marked as simulated.
- Contains policy recommendations and incident information.
- Existing anomaly scores are application-generated outputs,
  not ground-truth labels.
- Model status metadata alone does not prove actual model training.


## Normalized Event Feature Dataset

- Original audit events: 51
- Simulated FaaS events: 3
- Total normalized events: 54
- Unique users: 6
- Normalized output: normalized_events.json
- Feature output: normalized_event_features.csv
- Feature rows: 54
- Duplicate event IDs: 0
- Missing required fields: 0
- Invalid binary feature values: 0

### Extracted Features

- FaaS event indicator
- Failed event indicator
- Sensitive action indicator
- Sensitive resource indicator
- Off-hours activity indicator
- IP change indicator
- Time gap between consecutive user events

### Research Limitations

- The FaaS records are simulated.
- The audit dataset has no ground-truth anomaly labels.
- Off-hours detection uses a preliminary time-based heuristic.
- The current dataset is suitable for pipeline testing, not for claiming reliable model performance.
