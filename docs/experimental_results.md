# CloudSentinel AI — Verified Experimental Results and Configurations

This document records the exact, unmodified experimental outputs, hardware/software specifications, dataset statistics, and saved model metadata observed directly from the CloudSentinel AI codebase (`ml_service/`, `server.ts`, `data/`).

---

## 1. Execution Environment & Runtime Specification

- **Host Operating System:** Windows 11 (`Windows-11-10.0.26300-SP0`, `AMD64`)
- **CPU / Memory:** 12 logical cores; 15.65 GB physical RAM
- **Python Runtime:** Python `3.14.0` (`torch 2.14.0+cpu`, `cuda=False`; `scikit-learn 1.9.0`, `numpy 2.5.2`, `scipy 1.18.1`, `joblib 1.5.3`, `fastapi 0.165.0`, `uvicorn 0.52.4`)
- **Application Runtime:** Node.js / Express (`4.21.2`), `tsx 4.21.0`, React (`19.0.1`), TypeScript (`7.0.2`), Vite (`8.3.0`)
- **Virtualization Constraints:** Docker and WSL2 are not installed on the verification host; OpenStack Keystone/Nova connectors and cost-aware optimization remain unvalidated against a live private cloud testbed.

---

## 2. Dataset Summary (`data/`)

| Dataset File | Registered ID | Raw Records | Deduplicated in Express | Benign Events (`should_sample=false`) | Attack Events (`should_sample=true`) | Positive Class Share | Unique Identities | Time Span (UTC) |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `data/cloudtrail_training.json` | `ds-cloudtrail-train` | 4,216 | 4,216 | 3,675 | 541 | 12.83% | 65 | `2026-04-27T23:52:48Z` – `2026-04-28T06:04:37Z` |
| `data/cloudtrail_testing.json` | `ds-cloudtrail-test` | 24,087 | 24,079 *(8 duplicate `eventID`s removed)* | 21,502 raw | 2,585 raw | 10.73% | 87 | `2026-02-17T22:50:27Z` – `2026-04-04T23:52:53Z` |

### `userIdentity.type` Breakdown
- **Training (`4,216`):** `IAMUser`: 1,705 | `AWSService`: 1,560 | `AssumedRole`: 900 | `AWSAccount`: 48 | Missing `userIdentity.type`: 3
- **Testing (`24,087` raw):** `AssumedRole`: 16,415 | `IAMUser`: 6,016 | `AWSService`: 1,506 | `AWSAccount`: 144 | Missing `userIdentity.type`: 6

### Ground-Truth Attack Categories (`attack_name`, Evaluation-Only — Never Used as Features)
- **Training (`541` total):** `MassGetMultipleBuckets` (519), `AnonymousS3Calls` (18), `MassGetSingleBucket` (4)
- **Testing (`2,585` total):** `MassPutMultipleBuckets` (542), `MassGetMultipleBuckets` (535), `MassPutSingleBucket` (520), `MassDeleteMultipleBuckets` (510), `MassDeleteSingleBucket` (302), `MassGetSingleBucket` (123), `AnonymousS3PentestWeirdAPIs` (25), `AnonymousS3Calls` (17), `FullPersistenceCreationChain` (10), `RootFederationTokenGeneration` (1)

---

## 3. Baseline Model: Isolation Forest (`isolation-forest-cloudtrail-v2`)

- **Artifact:** `data/isolation_forest_cloudtrail.joblib`
- **Pipeline:** `ml_service/cloudtrail_pipeline.py` (`ml_service/train_cloudtrail_model.py`)
- **Hyperparameters:** `IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)`, `StandardScaler` fit on benign training subset (`n=3,675`), calibrated threshold `0.012074`.
- **8 Input Features:** `is_faas`, `failed_event_flag`, `is_iam_user`, `is_anonymous_or_account`, `recon_action_flag`, `sensitive_action_flag`, `log_s3_burst_1m`, `log_unique_buckets_5m`.

### Full Held-Out Evaluation (`24,079` Deduplicated Test Records via Express -> `/evaluate`)
| Metric | Value |
|---|---:|
| Accuracy | 80.02% |
| Precision | 34.31% |
| Recall | 94.08% |
| F1-Score | 50.28% |
| False Positive Rate (FPR) | 21.67% |
| ROC-AUC | 84.50% |
| Confusion Matrix (`TP / FP / TN / FN`) | `2432 / 4657 / 16837 / 153` |

*(Note: Direct offline evaluation over all `24,087` raw records in `data/cloudtrail_model_info.json` prior to `eventID` deduplication gives `TP=2432, FP=4659, TN=16843, FN=153`, Accuracy `80.02%`, Precision `34.30%`, F1 `50.27%`, Recall `94.08%`, FPR `21.67%`, ROC-AUC `84.50%`.)*

---

## 4. PyTorch LSTM Autoencoder vs. Saved Isolation Forest (Cross-Dataset Side-by-Side)

- **Pipeline:** `ml_service/lstm_pipeline.py` (`POST /lstm/train-evaluate` via `POST /api/ml/train`)
- **10 Sequential Step Features:** 8 Isolation Forest features + `log_time_delta_sec` + `action_novelty_flag`
- **Architecture:** Single-layer LSTM encoder (`hidden_dim=32`) -> bottleneck repetition -> single-layer LSTM decoder (`output_dim=10`), trained with `Adam(lr=0.002)`, `MSELoss`, `batch_size=128`, `epochs=15`, deterministic seed `42`.
- **Chronological Zero-Leakage Protocol:** Training dataset sorted by timestamp -> earliest `70%` slice (pure benign sliding windows only for training + `StandardScaler`), latest `30%` slice for validation threshold calibration (`empirical quantile F1 maximization`), evaluated on `cloudtrail_testing.json` sliding windows (`eligible test events`). Both models are scored on the exact same eligible test event indices.

### Table A: Sliding Window Sequence Counts
| Window Size (`W`) | Benign Train Windows | Validation Windows (Attacks) | Eligible Test Events | Excluded Test Events (`W-1` Warmup + Short Tails) | Checkpoint Artifact (`data/`) | Calibrated Threshold |
|---:|---:|---:|---:|---:|---|---:|
| `W = 5` | 2,790 | 1,210 (523) | 23,889 | 190 | `lstm_cloudtrail_w5.pt` (34,663 B) | `0.337648` |
| `W = 10` | 2,687 | 1,169 (518) | 23,754 | 325 | `lstm_cloudtrail_w10.pt` (34,677 B) | `0.330225` |
| `W = 16` | 2,583 | 1,139 (503) | 23,611 | 468 | `lstm_cloudtrail_w16.pt` (34,677 B) | `0.311792` |

### Table B: Side-by-Side Model Metrics on Identical Eligible Test Events
| Window (`W`) | Eligible Test Events | Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | `TP / FP / FN / TN` | Train Time (ms) | Infer Latency (ms) |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| `W = 5` | 23,889 | **LSTM Autoencoder** (`EXP-MWZ5JVGB`) | 77.5% | 32.0% | 97.2% | 48.2% | 24.9% | 83.6% | 26.9% | `2505 / 5311 / 72 / 16001` | 1297.32 | 123.9 |
| `W = 5` | 23,889 | **Isolation Forest** (same events) | 80.2% | 34.6% | 94.2% | 50.7% | 21.5% | 84.7% | 27.4% | `2427 / 4578 / 150 / 16734` | saved | 483.93 |
| `W = 10` | 23,754 | **LSTM Autoencoder** (`EXP-MWZ5J1Z1`) | 47.6% | 16.8% | 97.4% | 28.7% | 58.5% | 81.4% | 25.1% | `2501 / 12389 / 66 / 8798` | 3480.57 | 164.43 |
| `W = 10` | 23,754 | **Isolation Forest** (same events) | 80.4% | 35.0% | 94.4% | 51.0% | 21.3% | 84.9% | 27.7% | `2422 / 4508 / 145 / 16679` | saved | 586.0 |
| `W = 16` | 23,611 | **LSTM Autoencoder** (`EXP-MWZ5J6C2`) | 41.8% | 15.6% | 99.3% | 26.9% | 65.2% | 80.2% | 23.4% | `2533 / 13727 / 18 / 7333` | 1681.17 | 245.91 |
| `W = 16` | 23,611 | **Isolation Forest** (same events) | 80.6% | 35.3% | 94.6% | 51.4% | 21.0% | 85.1% | 27.9% | `2412 / 4431 / 139 / 16629` | saved | 571.59 |

---

## 5. Phase R1: AWS CloudTrail Serverless FaaS Telemetry (`POST /faas/telemetry`)

| Scope / Dataset | Scanned Events | Detected FaaS Events | `lambda:Invoke` | `sts:AssumeRole` (`invokedBy=lambda`) | `inScopeOf` (`AWS::Lambda::Function`) | Control-Plane Events | Unique Function / Role Identities | `AccessDenied` / Errors | Unavailable Runtime Fields |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Training (`ds-cloudtrail-train`) | 4,216 | 51 | 0 | 50 | 0 | 1 | 3 | 0 | `avg_duration_ms`, `memory_mb`, `cold_start_rate` |
| Testing (`ds-cloudtrail-test`) | 24,079 | 2,994 | 567 | 130 | 2,294 | 3 | 6 | 3 (`60.0%` on S3 auto-delete Lambda) | `avg_duration_ms`, `memory_mb`, `cold_start_rate` |
| Combined (`cloudtrail_all`) | 28,295 | 3,045 | 567 | 180 | 2,294 | 4 | 7 | 3 | `avg_duration_ms`, `memory_mb`, `cold_start_rate` |

- **Ground-Truth Label Note:** All 51 training and 2,994 deduplicated testing FaaS records carry `should_sample = false` (benign). Accordingly, FaaS attack accuracy or recall cannot be reported from this dataset.
- **KMS Identity Limitation:** 13 `kms.amazonaws.com` `Decrypt` events in raw `cloudtrail_testing.json` execute under the Lambda execution role session ARN without populating `userIdentity.inScopeOf` and are excluded from strict schema-based matching.

---

## 6. Phase R3: Cost-Aware Adaptive Policy Optimizer (`src/server/policyOptimizer.ts`) — Estimated Cost Scenarios

- **Cost & Impact Nature:** Configurable model estimates (`$18`–`$260` per enforcement window, `5`–`88` operational impact, `1.5s`–`12.0s` latency); **not** live AWS billing charges. Zero automatic cloud execution (`auto_executed = false`); Admin approval required via `/api/policies/:id/approve`.
- **Verified Deterministic Selections Across Risk Tiers:**
  - Low Risk (`risk_score=18`, `conf=0.65`, `maxCost=$180`, `maxImpact=70`) $\rightarrow$ **Monitor and alert** (`$18`, `5/100` impact)
  - Medium Risk (`risk_score=48`, `conf=0.75`, `maxCost=$180`, `maxImpact=70`) $\rightarrow$ **Require additional MFA** (`$45`, `22/100` impact)
  - High Risk (`risk_score=76`, `conf=0.85`, `maxCost=$180`, `maxImpact=70`) $\rightarrow$ **Revoke suspicious session** (`$140`, `64/100` impact; static baseline: `Temporarily restrict permissions`)
  - Critical Risk (`risk_score=95`, `conf=0.94`, `Asset=Critical`, `maxCost=$180`, `maxImpact=70`) $\rightarrow$ **Revoke suspicious session** (`100 -> 15.76` residual risk, est. `$140`, `64/100` impact, utility `0.6212`) while static baseline `Isolate account and escalate to administrator` (`$260`, `88/100` impact) is flagged as **Infeasible** (`-$120` cost delta).

---

## 7. Phase R4: OpenStack Private Cloud Adapter (`src/server/openstackAdapter.ts`) — Synthetic Fixture Validation

- **Live Connectivity on Host:** **`Not Connected`** (`OPENSTACK_AUTH_URL` and read-only tokens absent; DevStack not installed).
- **Synthetic Fixture Validation (`tests/fixtures/openstack/openstack_audit_sample.json`):** 9 multi-service synthetic events ingested cleanly (`Keystone`, `Nova`, `Neutron`, `Glance`, `Cinder`) with `[REDACTED]` secret scrubbing verified across HTTP responses, distinguishing baseline daytime operations (`Normal Baseline`) from external-IP auth failure, role escalation, `0.0.0.0/0` ingress rules, and off-hours resource deletion. Live private-cloud cluster evaluation remains future work.
