# AI-Based Insider Threat Detection in Cloud Environments Using Cloud Audit Log Analysis: An Isolation Forest and LSTM-Based Approach

**Authors:** [Author Names Placeholder — CloudSentinel AI Research Team]  
**Affiliation:** [Department / Institution Placeholder]  
**Correspondence:** [Corresponding Author Email Placeholder]

---

## 1. Abstract

Cloud infrastructure telemetry captures high-volume API control-plane and data-plane activity across heterogeneous identities, including IAM users, temporary assumed roles, cross-account callers, and AWS services. Detecting malicious insider and credential-abuse activity within these audit streams requires behavioral modeling without leaking future knowledge or ground-truth labels. This paper presents **CloudSentinel AI**, a full-stack audit-log analysis system pairing a React/TypeScript security console and Express gateway with a Python FastAPI machine learning microservice. We evaluate an unsupervised eight-feature **Isolation Forest** baseline alongside a ten-feature chronological **PyTorch Long Short-Term Memory (LSTM) Autoencoder** using identity-grouped sliding windows ($W \in \{5, 10, 16\}$) on two separate offline AWS CloudTrail datasets: a 4,216-record training log (541 attacks) and a 24,087-record held-out testing log (24,079 deduplicated records; 2,585 raw attacks). Strictly separating feature engineering from `should_sample` and `attack_name` ground-truth labels, fitting the scaler and LSTM purely on earliest benign sequences, and calibrating anomaly thresholds solely on chronological validation splits, the Isolation Forest baseline achieves **80.02% accuracy**, **34.31% precision**, **94.08% recall**, **50.28% F1-score**, **21.67% false positive rate (FPR)**, and **84.50% ROC-AUC**. In side-by-side comparison across identical eligible sliding-window test events, the PyTorch LSTM Autoencoder improves attack recall—reaching **97.2% recall** at $W = 5$ (**48.2% F1**, **24.9% FPR**, **83.6% ROC-AUC**, **26.9% PR-AUC**, **123.9 ms** inference) and **99.3% recall** at $W = 16$—but suffers progressively higher false-positive rates (**58.5%** at $W = 10$ and **65.2%** at $W = 16$) due to sequence reconstruction drift across benign test environments, meaning Isolation Forest retains superior overall precision, F1, and ROC-AUC. Additionally, an additive schema-driven Function-as-a-Service (FaaS) telemetry extractor identifies **3,045 Lambda-related audit events** across **28,295 combined deduplicated events** while transparently reporting missing CloudWatch runtime attributes (duration, memory, cold-start rate) and the absence of labeled FaaS attacks. Live AWS integration, OpenStack private-cloud validation, and cost-aware adaptive policy optimization remain explicitly scoped as future work.

---

## 2. Keywords

Insider Threat Detection, Cloud Audit Logs, AWS CloudTrail, Isolation Forest, LSTM Autoencoder, Sliding Window Sequence Modeling, Serverless FaaS Telemetry, Threshold Calibration, Anomaly Detection

---

## 3. Introduction

Modern cloud platforms centralize administrative control and data access behind fine-grained API gateways where legitimate users, automation roles, and managed services generate thousands of audit events per hour [3, 6]. Malicious insiders and compromised credential holders rarely trigger simple signature rules because their API calls—such as enumerating S3 buckets (`ListBuckets`), reading or deleting objects (`GetObject`, `DeleteObject`), assuming roles (`AssumeRole`), or generating root federation tokens—mimic syntactically valid administrative workflows [3]. Detecting suspicious activity therefore depends on behavioral anomaly detection capable of identifying anomalous volume bursts, unfamiliar resource breadth, elevated error rates, and abnormal identity posture across heterogeneous `userIdentity` structures.

Practical deployment of anomaly detectors in multi-tier security platforms poses three recurring engineering and methodological challenges:

1. **Leakage-Free Data Engineering:** Audit datasets annotated for research evaluation (such as AWS CloudTrail logs carrying `should_sample` and `attack_name` fields) must never expose ground-truth indicators to feature extractors, scalers, or HTTP inference payloads. Furthermore, real-world multi-megabyte log ingestion must preserve incomplete or non-IAM identities (`AssumedRole`, `AWSService`, `AWSAccount`, missing identity fields) rather than silently dropping records.
2. **Temporal Ordering and Threshold Calibration:** Splitting audit logs randomly mixes future benign or attack patterns into earlier training windows. Conversely, calibrating detection thresholds on held-out test scores yields overly optimistic performance estimates that collapse under deployment shift.
3. **Point-Wise vs. Sequential Modeling Tradeoffs:** Tree-based isolation methods such as Isolation Forest [1] evaluate each behavioral feature vector independently at low variance, whereas recurrent neural models such as LSTM Autoencoders [2, 4, 7] encode temporal transition context over sliding event windows. Comparing both paradigms on the **exact same eligible test events** is essential to measure whether higher sequential recall justifies potential false-positive inflation.

This work documents the architecture, leak-free ingestion pipeline, machine learning microservice, and controlled comparative evaluation implemented in **CloudSentinel AI**, an end-to-end insider threat detection platform combining a React/TypeScript analytical interface, an Express orchestration gateway, and a FastAPI machine learning backend.

---

## 4. Problem Statement

Given an offline collection of cloud audit logs containing raw AWS CloudTrail JSON records $\mathcal{E} = \{e_1, e_2, \dots, e_N\}$ spanning heterogeneous identities (`IAMUser`, `AssumedRole`, `AWSService`, `AWSAccount`, and missing identity types), we seek to:

1. Normalize all incoming audit records without discarding identity variants or leaking annotation fields (`should_sample`, `attack_name`) into feature construction.
2. Detect anomalous insider or credential-abuse events using (a) a point-wise unsupervised **Isolation Forest** model trained exclusively on benign baseline behavior, and (b) a chronological **PyTorch LSTM Autoencoder** operating on user/session sliding windows of length $W \in \{5, 10, 16\}$.
3. Calibrate decision thresholds strictly from chronological training/validation partitions prior to evaluating held-out testing logs.
4. Quantify detection effectiveness (`Accuracy`, `Precision`, `Recall`, `F1-Score`, `FPR`, `ROC-AUC`, `PR-AUC`, confusion matrix), computational latency, and serverless FaaS observability gaps without fabricating unmeasured metrics.

---

## 5. Research Objectives

The primary objectives realized and empirically evaluated in the CloudSentinel AI codebase are:

1. **Leak-Free CloudTrail Normalization and Safe Ingestion:** Parse large multi-identity CloudTrail JSON arrays cleanly on the server, deduplicate repeated `eventID` entries transparently, preserve `should_sample` and `attack_name` exclusively as post-hoc evaluation metadata, and separate dataset provenance via persistent dataset IDs (`ds-cloudtrail-train`, `ds-cloudtrail-test`).
2. **Unsupervised Isolation Forest Baseline:** Implement an 8-feature CloudTrail behavioral vector and persist an `IsolationForest` baseline (`isolation_forest_cloudtrail.joblib`) calibrated on training data for live event scoring and held-out cross-dataset evaluation.
3. **Chronological LSTM Sequence Modeling:** Construct an identity-grouped sliding-window sequence dataset builder ($W \in \{5, 10, 16\}$) with strict chronological train/validation/test separation, train a real PyTorch LSTM Autoencoder on benign sequences only, calibrate reconstruction thresholds strictly on validation windows, and persist model checkpoints (`lstm_cloudtrail_w5.pt`, `lstm_cloudtrail_w10.pt`, `lstm_cloudtrail_w16.pt`).
4. **Controlled Side-by-Side Comparison:** Compare the PyTorch LSTM Autoencoder against the saved Isolation Forest baseline over the identical set of eligible sliding-window test events.
5. **Schema-Driven Serverless FaaS Telemetry Extraction:** Detect AWS Lambda invocation, STS role assumption (`invokedBy`), Lambda control-plane activity, and downstream `userIdentity.inScopeOf` calls via FastAPI while explicitly marking missing CloudWatch metrics (`avg_duration_ms`, `memory_mb`, `cold_start_rate`) as unavailable.

---

## 6. Related Work

Tree-based and deep sequential anomaly detection constitute two complementary paradigms for log security analytics. Liu, Ting, and Zhou [1] introduced **Isolation Forest**, establishing that anomalous observations—being few and distinct in feature space—require shorter expected binary partition paths across random sub-sampled trees than dense normal clusters, achieving linear time complexity without parametric density assumptions.

To capture long-range temporal dependencies across ordered event streams, Hochreiter and Schmidhuber [2] formulated **Long Short-Term Memory (LSTM)** recurrent cells equipped with gated Constant Error Carousels to prevent vanishing gradients over extended sequences. Applying this capability specifically to security logs, Villarreal-Vasquez et al. [3] proposed an LSTM-based anomaly detection framework for hunting insider threats where malicious actions are interleaved within long legitimate user event sequences.

In the unsupervised reconstruction paradigm, Maleki, Maleki, and Jennings [4] combined Central Limit Theorem statistical filtering with LSTM Autoencoders, flagging sequential anomalies whenever reconstruction error exceeds an empirically filtered baseline threshold. Extending LSTM log analysis toward multi-dimensional temporal dynamics, Wang, Zhang, and Yu [5] modeled time-domain log structures for large-scale operational log streams. Focusing explicitly on cloud insider threats, Shanmugapriya et al. [6] evaluated CNN and LSTM deep learning classifiers paired with SMOTE oversampling on imbalanced user behavioral datasets, demonstrating the sensitivity of recurrent models to severe class imbalance. Most recently, Huang et al. [7] integrated an LSTM module and Kullback–Leibler (KL) divergence regularization into deep autoencoders (`IAE-LSTM-KL`) to curb feature collapse and over-reconstruction of outlier patterns.

CloudSentinel AI builds directly on these foundations by empirically contrasting an unsupervised benign-fitted Isolation Forest [1] against an unsupervised benign-trained LSTM Autoencoder [2, 3, 4] on held-out AWS CloudTrail datasets under strict zero-future-leakage chronological evaluation, without synthetic oversampling of test distributions.

---

## 7. Proposed System Architecture

CloudSentinel AI employs a decoupled three-tier architecture designed to keep browser presentation lightweight, API orchestration centralized in Node.js/TypeScript, and numerical/deep-learning computation isolated in Python:

1. **Presentation Layer (React 19, TypeScript, Vite):** Single-page analytical console (`src/App.tsx`) featuring dedicated views including *Audit Log Monitoring* (`AuditLogsPage.tsx`), *Cloud Environments & Serverless FaaS Monitoring* (`CloudEnvironmentsPage.tsx`), *AI Threat Detection* (`ThreatDetectionPage.tsx`), *Model Evaluation* (`ModelEvaluationPage.tsx`), and *Reports & Analytics* (`ReportsPage.tsx`), communicating exclusively via REST API helpers (`src/services/api.ts`).
2. **Application & Normalization Gateway (Node.js, Express 4):** `server.ts` handles server-side CloudTrail JSON normalization (`src/server/eventNormalizer.ts`), role-based state management (`cloudsentinel_state_v1.json`), request sanitization (`sanitizeEventForMl`), prediction/telemetry response caching (30-second TTL invalidated upon state mutation), PDF security report export (`src/services/reportGenerator.ts`), and fallback labeling whenever the Python ML microservice is unreachable.
3. **Python Machine Learning Microservice (FastAPI, scikit-learn, PyTorch CPU):** Hosted independently on port `8001` (`ml_service/main.py`), loading the persisted Isolation Forest artifact (`data/isolation_forest_cloudtrail.joblib`) and exposing additive endpoints for tabular anomaly scoring (`/predict`, `/train`, `/evaluate`), serverless FaaS telemetry aggregation (`/faas/telemetry` via `ml_service/faas_extractor.py`), and PyTorch LSTM training/evaluation (`/lstm/train-evaluate`, `/lstm/evaluate`, `/lstm/status` via `ml_service/lstm_pipeline.py`).

> **[Figure 1 Placeholder: CloudSentinel AI Three-Tier System Architecture]**  
> *Caption:* End-to-end dataflow between the React/TypeScript frontend (port 3000 UI), Express normalization and sanitization gateway (`server.ts`, `sanitizeEventForMl`), and Python FastAPI ML microservice (`ml_service/main.py` on port 8001) serving Isolation Forest, PyTorch LSTM Autoencoder, and FaaS telemetry endpoints.

---

## 8. Dataset Description and Preprocessing

The experimental study uses two separate AWS CloudTrail JSON datasets stored locally under `data/`:

- **Training Dataset (`data/cloudtrail_training.json`, `ds-cloudtrail-train`):** Contains **4,216** audit events spanning `2026-04-27T23:52:48Z` to `2026-04-28T06:04:37Z` across **65 unique identities**, comprising **3,675 benign records** (`should_sample = false`, 87.17%) and **541 attack records** (`should_sample = true`, 12.83%). Observed attack classes are `MassGetMultipleBuckets` (519), `AnonymousS3Calls` (18), and `MassGetSingleBucket` (4).
- **Held-Out Testing Dataset (`data/cloudtrail_testing.json`, `ds-cloudtrail-test`):** Contains **24,087 raw records** (**24,079 deduplicated events** in Express state after removing 8 duplicate `eventID` entries) spanning `2026-02-17T22:50:27Z` to `2026-04-04T23:52:53Z` across **87 unique identities**. Raw records include **21,502 benign** (89.27%) and **2,585 attack** records (10.73%) spanning 10 distinct attack classes, notably introducing attack types absent from training such as `MassPutMultipleBuckets` (542), `MassDeleteMultipleBuckets` (510), `MassPutSingleBucket` (520), `MassDeleteSingleBucket` (302), `AnonymousS3PentestWeirdAPIs` (25), `FullPersistenceCreationChain` (10), and `RootFederationTokenGeneration` (1).

| Property | Training Dataset (`cloudtrail_training.json`) | Testing Dataset (`cloudtrail_testing.json`) |
|---|---:|---:|
| Raw CloudTrail Records | 4,216 | 24,087 |
| Deduplicated Express Records | 4,216 | 24,079 *(8 duplicate `eventID`s)* |
| Benign Records (`should_sample=false`) | 3,675 (87.17%) | 21,502 raw (89.27%) |
| Attack Records (`should_sample=true`) | 541 (12.83%) | 2,585 raw (10.73%) |
| Unique Resolved Identities | 65 | 87 |
| `IAMUser` Events | 1,705 | 6,016 |
| `AWSService` Events | 1,560 | 1,506 |
| `AssumedRole` Events | 900 | 16,415 |
| `AWSAccount` Events | 48 | 144 |
| Missing `userIdentity.type` Events | 3 | 6 |

*Table I: Composition and `userIdentity` distribution across the offline AWS CloudTrail training and held-out testing datasets.*

In addition, the application retains a small 36-row legacy reference fixture (`CERT-r4.2-Cloud-FaaS-Hybrid-v1`, `ds-cert-cloud-01`) alongside seeded UI demonstration rows (`SEEDED_LAMBDA_METRICS` and `SEEDED_INCIDENTS`); these small/seeded fixtures are kept explicitly separate from all real CloudTrail experimental results reported in this study.

---

## 9. Methodology

### 9.1 CloudTrail Event Normalization
Incoming CloudTrail files (parsed either server-side via workspace registration or binary streaming upload without loading 50 MB JSON files into browser textareas) are normalized by `validateAndNormalizeUpload()` in `src/server/eventNormalizer.ts`:
- **Identity Resolution:** Handles `IAMUser` (`userName`), `AssumedRole` (ARN / `sessionContext.sessionIssuer`), `AWSService` (`invokedBy`), `AWSAccount` (`aws-account:<accountId>`), and missing `userIdentity` fields (`anonymous-caller`) so no authentic CloudTrail record is silently dropped.
- **Ground-Truth Mapping:** Maps `should_sample === true` to `ground_truth_label = 1` (attack) and `should_sample === false` to `ground_truth_label = 0` (benign), preserving `attack_name` only as dataset metadata.
- **Strict Sanitization Gateway:** `sanitizeEventForMl(event, includeLabel)` strips ground-truth labels on all inference (`/predict`) and FaaS extraction (`/faas/telemetry`) requests (`includeLabel = false`), forwarding only structural non-label metadata (`eventSource`, `awsRegion`, `errorCode`, `errorMessage`, `bytesTransferredMB`, `resources`, and selective `requestParameters` / `userIdentity.inScopeOf` keys).

### 9.2 Eight-Feature Isolation Forest Baseline
Implemented in `ml_service/cloudtrail_pipeline.py` and trained via `ml_service/train_cloudtrail_model.py`, the baseline extracts an 8-dimensional behavioral vector per event after sorting records chronologically per identity without inspecting any label column:

1. `is_faas`: Binary indicator for Lambda/FaaS providers, sources, `invokefunction` actions, or `fn_`/`fn-` resource prefixes.
2. `failed_event_flag`: Binary indicator for `Failed`/`Denied`/`Error` statuses or CloudTrail `errorCode`/`errorMessage`.
3. `is_iam_user`: Binary indicator for `userIdentity.type == "iamuser"`.
4. `is_anonymous_or_account`: Binary indicator for `awsaccount`, `anonymous`, or `missing` identities lacking `invokedBy`.
5. `recon_action_flag`: Binary indicator for discovery calls (e.g., `ListBuckets`, `ListObjects`, `ListObjectsV2`, `GetBucketPolicy`, `ListUsers`, `ListRoles`, `ListAccessKeys`).
6. `sensitive_action_flag`: Binary indicator for privilege, key, destructive, or high-transfer actions (`AttachUserPolicy`, `CreateAccessKey`, `DeleteBucket`, `AssumeRole`, `bytesTransferredMB >= 500`, etc.).
7. `log_s3_burst_1m`: $\ln(1 + c_{1\text{m}})$ where $c_{1\text{m}}$ counts rolling 60-second object/bucket actions per identity.
8. `log_unique_buckets_5m`: $\ln(1 + b_{5\text{m}})$ where $b_{5\text{m}}$ counts distinct accessed buckets within a rolling 300-second window per identity.

During training on `data/cloudtrail_training.json`, benign records ($n = 3,675$) are standardized using scikit-learn `StandardScaler` and fit with `IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)`. Decision scores are inverted (`raw_score = -model.decision_function(X_scaled)`), and threshold $\tau_{\text{IF}} = 0.012074$ is calibrated strictly on training data. The bundle is serialized to `data/isolation_forest_cloudtrail.joblib` (`isolation-forest-cloudtrail-v2`) and remains strictly unmodified during Phase R1 and Phase R2.

### 9.3 Ten-Feature Chronological LSTM Sequence Pipeline
Implemented in `ml_service/lstm_pipeline.py`, each audit event is represented by the 8 CloudTrail behavioral features above augmented with two strictly causal per-identity temporal features (`LSTM_FEATURES`, 10 dimensions):
- `log_time_delta_sec`: $\ln(1 + \max(0, t_i - t_{i-1}))$ in seconds between consecutive actions by the same user/session identity ($0.0$ for an identity's initial event).
- `action_novelty_flag`: $1.0$ if `action_i != action_{i-1}` within the identity's chronological trace, and $0.0$ otherwise.

This deliberate omission of dataset-specific domain flags (such as test-only `inScopeOf` indicators) avoids zero-variance training features that would deterministically inflate test false positives under distribution shift.

### 9.4 Identity-Based Sliding Windows ($W = 5, 10, 16$)
In `build_identity_sliding_windows()`, events are grouped by resolved user/session identity (`_extract_user_id`), sorted ascending by `(event_time, original_index)`, and segmented into overlapping sliding windows $[i - W + 1, \dots, i]$ of configurable window length $W \in \{5, 10, 16\}$. Each window tensor $\mathbf{X}^{(k)} \in \mathbb{R}^{W \times 10}$ predicts anomaly status for its final target step $i$. Identities with fewer than $W$ events and the initial $W - 1$ warmup steps of each sequence cannot form a full $W$-event context and are reported explicitly as `excluded_test_events`.

### 9.5 Benign-Only LSTM Training
To prevent future-data leakage, `train_and_evaluate_lstm()` sorts primary training records globally by timestamp. In cross-dataset evaluation (`ds-cloudtrail-train` $\rightarrow$ `ds-cloudtrail-test`), the earliest **70%** chronological slice forms the training partition and the latest **30%** slice forms the validation partition. Both `StandardScaler` fitting (on benign events) and PyTorch model optimization are confined strictly to the earliest 70% slice:
- Only **pure benign sliding windows**—where every event step across all $W$ positions satisfies `ground_truth_label == 0`—are retained for training (`2,790` windows at $W=5$; `2,687` at $W=10$; `2,583` at $W=16$).
- The `LSTMAutoencoder` architecture comprises a single-layer LSTM encoder (`input_dim=10`, `hidden_dim=32`), final hidden-state bottleneck repetition across $W$ timesteps, and a single-layer LSTM decoder (`hidden_dim=32`, `output_dim=10`).
- Training uses `Adam(lr=0.002)`, `MSELoss`, `batch_size=128`, `epochs=15`, and fixed seed `42` on CPU PyTorch.

> **[Figure 2 Placeholder: Chronological Zero-Leakage Data Splitting & PyTorch LSTM Autoencoder Architecture]**  
> *Caption:* Temporal partitioning of `cloudtrail_training.json` into earliest 70% benign-only sequences for scaler/LSTM optimization and latest 30% validation sequences for threshold calibration prior to held-out sliding-window inference on `cloudtrail_testing.json`.

### 9.6 Validation-Only Threshold Calibration
Reconstruction anomaly error combines global sequence fidelity and final target-step deviation:
$$e(\mathbf{X}, \hat{\mathbf{X}}) = 0.5 \cdot \frac{1}{WD}\sum_{t=1}^{W}\sum_{d=1}^{D}(\hat{x}_{t,d} - x_{t,d})^2 + 0.5 \cdot \frac{1}{D}\sum_{d=1}^{D}(\hat{x}_{W,d} - x_{W,d})^2$$
Because heavy-tailed outlier errors skew uniform linear threshold grids, `_calibrate_validation_threshold()` searches 150 empirical quantiles ($[0.05, 0.99]$) strictly over the chronological validation slice (`n=1,210` at $W=5$; `1,169` at $W=10$; `1,139` at $W=16$) to maximize validation F1 without inspecting `cloudtrail_testing.json`.

*(Empirical note on split sensitivity: When an earlier experiment accidentally normalized a `0.6 / 0.2 / 0.2` UI ratio into `75% train / 25% val`, attacks exceeded 51% of the shortened validation tail [e.g., 519/1,007 at $W=5$], causing threshold calibration to degenerate to $\sim 0.15$ and ~85% FPR. Preserving an explicit `70% / 30%` chronological split in cross-dataset mode keeps validation majority-benign and eliminates that pathology.)*

### 9.7 Held-Out Testing and Evaluation Metrics
Held-out test windows are evaluated strictly once using the frozen scaler, LSTM weights, and validation threshold, recording: **Accuracy**, **Precision**, **Recall**, **F1-Score**, **False Positive Rate (FPR)**, **ROC-AUC**, **PR-AUC** (`average_precision_score`), **Confusion Matrix** (`TP`, `FP`, `FN`, `TN`), **Training Time** (`ms`), and **Inference Latency** (`ms`). For rigorous side-by-side comparison, `_evaluate_saved_isolation_forest_on_indices()` scores the untouched saved Isolation Forest over the exact same `target_indices` representing the eligible sliding-window test events. Datasets failing chronological sequence eligibility (e.g., `ds-cert-cloud-01` with 36 rows) return HTTP `422` cleanly rather than fabricating synthetic scores.

### 9.8 FaaS / Lambda Telemetry Extraction
Implemented in `ml_service/faas_extractor.py` and exposed at `POST /faas/telemetry`, FaaS telemetry analysis operates additively without altering the 8-feature Isolation Forest vector. `classify_faas_event()` matches non-label CloudTrail fields across four categories:
1. **Direct Lambda Invocation (`invoke`):** `eventSource == "lambda.amazonaws.com"` with `Invoke` / `InvokeFunction`.
2. **Lambda Control-Plane (`control_plane`):** Non-invoke `lambda.amazonaws.com` calls (e.g., `ListLayers20181031`, `ListTags20170331`).
3. **Lambda STS Role Assumption (`assume_role`):** `sts.amazonaws.com` `AssumeRole` calls with `userIdentity.invokedBy == "lambda.amazonaws.com"` or `roleSessionName` prefixed `awslambda_`.
4. **Downstream In-Scope Execution (`in_scope_downstream`):** Downstream SDK calls across S3, DynamoDB, Rekognition, and CloudWatch Logs where `userIdentity.inScopeOf.issuerType == "AWS::Lambda::Function"`.

Canonical function/role identities are aggregated with 1-minute/5-minute rolling burst peaks, `AccessDenied`/error rates, unique downstream service breadth, and sensitive action counts, while `avg_duration_ms`, `memory_mb`, and `cold_start_rate` remain explicitly `null` (`Unavailable in CloudTrail`).

---

## 10. Implementation and System Architecture

| Component / Endpoint | Technology / Artifact | Primary Responsibility |
|---|---|---|
| `src/server/eventNormalizer.ts` | TypeScript | Multi-identity CloudTrail JSON/CSV parser and normalization summary reporter |
| `src/server/policyOptimizer.ts` | TypeScript | Phase R3 cost-aware multi-objective response optimizer (5 candidate controls, hard cost/impact/latency constraints, static baseline comparison, proposal-only workflow) |
| `src/server/openstackAdapter.ts` | TypeScript | Phase R4 OpenStack audit ingestion adapter (Keystone, Nova, Neutron, Glance, Cinder, recursive secret redaction, honest connectivity probe) |
| `server.ts` | Node.js / Express (`4.21.2`) | API gateway, dataset registry, label-stripping sanitization (`sanitizeEventForMl`), `/api/ml/train`, `/api/faas/telemetry`, `/api/policies/optimizer`, `/api/policies/optimize`, `/api/openstack/*`, `/api/reports/pdf` |
| `ml_service/cloudtrail_pipeline.py` | Python / scikit-learn (`1.9.0`) | 8-feature Isolation Forest baseline extractor, scaler, and curve evaluator (`data/isolation_forest_cloudtrail.joblib`) |
| `ml_service/lstm_pipeline.py` | Python / PyTorch CPU (`2.14.0+cpu`) | 10-feature chronological sliding-window builder ($W=5,10,16$), LSTM Autoencoder training/calibration/evaluation, IF side-by-side evaluator, `.pt` persistence |
| `ml_service/faas_extractor.py` | Python (`3.14.0`) | Schema-based AWS Lambda `Invoke` / `AssumeRole` / `inScopeOf` classifier and per-function aggregator |
| `ml_service/main.py` | FastAPI (`0.165.0`) / Uvicorn (`0.52.4`) | Microservice exposing `/health`, `/predict`, `/train`, `/evaluate`, `/faas/telemetry`, `/lstm/train-evaluate`, `/lstm/evaluate`, `/lstm/status` |
| `src/pages/ModelEvaluationPage.tsx` | React (`19.0.1`) / TypeScript | Cross-dataset runner, window-size selector, 7 metric cards (incl. PR-AUC), Side-by-Side Comparison table, ROC/PR curves, `Real ML` vs `Simulated` badges |
| `src/pages/CostOptimizationPage.tsx` | React (`19.0.1`) / TypeScript | Interactive Cost-Aware Policy Optimizer console with estimated cost disclosure, static baseline comparison, and Admin approval proposal submission |
| `src/pages/CloudEnvironmentsPage.tsx` | React (`19.0.1`) / TypeScript | Displays real CloudTrail FaaS telemetry (`Unavailable` runtime markers) separate from `SIMULATED SEEDED DATA`, plus OpenStack telemetry (`Not Connected` / `Fixture Mode`) |

*Table II: Implemented modules across CloudSentinel AI and their separation of concerns.*

---

## 11. Experimental Setup

All verified experiments executed offline on a single Windows 11 (`AMD64`) workstation equipped with a **12-core CPU** and **15.65 GB RAM**, running **Python 3.14.0**, **PyTorch 2.14.0+cpu** (`cuda=False`), **scikit-learn 1.9.0**, **FastAPI 0.165.0**, and **Node.js / Express 4.21.2**. No GPU acceleration, cloud API polling, or synthetic oversampling (such as SMOTE) was used. TypeScript static analysis (`tsc --noEmit`) and Vite production builds (`vite build`) passed cleanly, and live dashboard workflows were verified in Chromium against the local Express and FastAPI daemons with zero console or HTTP errors.

---

## 12. Results and Comparative Analysis

### 12.1 Full-Dataset Isolation Forest Baseline
Evaluated across all **24,079 deduplicated held-out events** via the Express/FastAPI pipeline using `isolation-forest-cloudtrail-v2` (`threshold = 0.012074`):

| Metric | Isolation Forest Baseline (`n = 24,079`) |
|---|---:|
| Accuracy | 80.02% |
| Precision | 34.31% |
| Recall | 94.08% |
| F1-Score | 50.28% |
| False Positive Rate (FPR) | 21.67% |
| ROC-AUC | 84.50% |
| True Positives (`TP`) | 2,432 |
| False Positives (`FP`) | 4,657 |
| True Negatives (`TN`) | 16,837 |
| False Negatives (`FN`) | 153 |

*Table III: Held-out evaluation of the saved CloudTrail Isolation Forest model (`24,079` deduplicated test events; raw `24,087`-event pre-deduplication offline check in `data/cloudtrail_model_info.json` reports `TP=2432, FP=4659, TN=16843, FN=153`).*

### 12.2 Side-by-Side Comparison: PyTorch LSTM Autoencoder vs. Isolation Forest ($W = 5, 10, 16$)
Table IV reports cross-dataset evaluation comparing the trained PyTorch LSTM Autoencoder against the untouched saved Isolation Forest over the exact same eligible target events (`23,889` for $W=5$; `23,754` for $W=10$; `23,611` for $W=16$).

| Window (`W`) | Eligible Test Events (`Excluded`) | Model | Threshold | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC | Confusion (`TP/FP/FN/TN`) | Train / Infer (ms) |
|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|
| **5** | 23,889 (190) | **LSTM Autoencoder** | `0.337648` | 77.5% | 32.0% | **97.2%** | 48.2% | 24.9% | 83.6% | 26.9% | `2505/5311/72/16001` | 1297.32 / **123.9** |
| **5** | 23,889 (190) | **Isolation Forest** | `0.012074` | **80.2%** | **34.6%** | 94.2% | **50.7%** | **21.5%** | **84.7%** | **27.4%** | `2427/4578/150/16734` | saved / 483.93 |
| **10** | 23,754 (325) | **LSTM Autoencoder** | `0.330225` | 47.6% | 16.8% | **97.4%** | 28.7% | 58.5% | 81.4% | 25.1% | `2501/12389/66/8798` | 3480.57 / **164.43** |
| **10** | 23,754 (325) | **Isolation Forest** | `0.012074` | **80.4%** | **35.0%** | 94.4% | **51.0%** | **21.3%** | **84.9%** | **27.7%** | `2422/4508/145/16679` | saved / 586.0 |
| **16** | 23,611 (468) | **LSTM Autoencoder** | `0.311792` | 41.8% | 15.6% | **99.3%** | 26.9% | 65.2% | 80.2% | 23.4% | `2533/13727/18/7333` | 1681.17 / **245.91** |
| **16** | 23,611 (468) | **Isolation Forest** | `0.012074` | **80.6%** | **35.3%** | 94.6% | **51.4%** | **21.0%** | **85.1%** | **27.9%** | `2412/4431/139/16629` | saved / 571.59 |

*Table IV: Controlled cross-dataset comparison of PyTorch LSTM Autoencoder and Isolation Forest across window sizes $W \in \{5, 10, 16\}$ on identical eligible test events (`cloudtrail_training.json` $\rightarrow$ `cloudtrail_testing.json`).*

> **[Figure 3 Placeholder: ROC Curves, Precision-Recall Curves, and Window-Length FPR/Recall Tradeoff]**  
> *Caption:* Comparative Model Evaluation view (`EXP-MWZ5JVGB` at $W=5$) illustrating ROC/PR curves, confusion matrix, and false-positive rate escalation across $W \in \{5, 10, 16\}$ vs. Isolation Forest.

### 12.3 Serverless FaaS Telemetry Extraction Results
Executing `GET /api/faas/telemetry` (`POST /faas/telemetry` on Python ML service) yielded the observed CloudTrail serverless telemetry summarized in Table V:

| Dataset Scope | Scanned Events | Total FaaS Events | `Invoke` | `AssumeRole` (`invokedBy`) | `inScopeOf` (`AWS::Lambda::Function`) | Control-Plane | Unique Identities | `AccessDenied` / Errors | Runtime Metrics (`duration`, `memory`, `cold_start`) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Training (`ds-cloudtrail-train`) | 4,216 | 51 | 0 | 50 | 0 | 1 | 3 | 0 | Unavailable |
| Testing (`ds-cloudtrail-test`) | 24,079 | 2,994 | 567 | 130 | 2,294 | 3 | 6 | 3 | Unavailable |
| Combined (`cloudtrail_all`) | 28,295 | 3,045 | 567 | 180 | 2,294 | 4 | 7 | 3 | Unavailable |

*Table V: Observed AWS Lambda/FaaS telemetry across ingested CloudTrail datasets. All FaaS records carry benign (`should_sample=false`) ground-truth labels.*

In `ds-cloudtrail-test`, `CloudEnvironmentStack-ProcessingLambda0A3B4A63-ZnqwasP5052O` accounts for `567` `Invoke` (`RequestResponse`) events and `2,290+` `inScopeOf` downstream calls across DynamoDB (`TransactWriteItems`), Rekognition (`DetectLabels`), S3 (`GetObject`, `HeadObject`), and CloudWatch Logs, with peak bursts reaching 35 events/min and 115 events/5min (`0` errors). Conversely, `CloudEnvironmentStack-CustomS3AutoDeleteObjectsCus-baVbRU4OCRnu` exhibits 3 `AccessDenied` S3 errors out of 5 FaaS events (60.0% error rate), cleanly separated in the UI from the 5 `SIMULATED SEEDED DATA` fixtures.

> **[Figure 4 Placeholder: Serverless FaaS Telemetry UI Separating CloudTrail Metrics from Seeded Reference Data]**  
> *Caption:* *Cloud Environments $\rightarrow$ Serverless FaaS Telemetry* console presenting real CloudTrail Lambda identities, downstream service badges (`dynamodb`, `logs`, `rekognition`, `s3`), explicit `Unavailable (CloudTrail)` cells, and the isolated `SIMULATED SEEDED DATA` table below.

---

## 13. Discussion

Three central findings emerge from the controlled cross-dataset evaluation:

1. **Sequential Recall Gain vs. Overall F1/Precision Superiority:** Across every tested window size, the PyTorch LSTM Autoencoder captures more attack events than Isolation Forest—improving recall from **94.2% to 97.2%** at $W=5$ (`FN` reduced from 150 to 72) and reaching **99.3% recall** at $W=16$ (`FN = 18`). However, **Isolation Forest outperforms the LSTM Autoencoder overall** on accuracy, precision, F1-score (**50.7%–51.4%** vs. **26.9%–48.2%**), false positive rate (**21.0%–21.5%** vs. **24.9%–65.2%**), ROC-AUC (**84.7%–85.1%** vs. **80.2%–83.6%**), and PR-AUC (**27.4%–27.9%** vs. **23.4%–26.9%**).
2. **Effect of Longer Sliding Windows Under Domain Shift:** As $W$ grows from 5 to 16, LSTM accuracy drops from **77.5% to 41.8%** and FPR rises from **24.9% to 65.2%**. Because `cloudtrail_training.json` spans ~6 hours of activity across 65 identities whereas `cloudtrail_testing.json` spans 46 days across 87 identities introducing new benign serverless/service workloads (e.g., Lambda `ProcessingLambda` bursts, DynamoDB writes, Rekognition calls), any sequence containing unfamiliar multi-step benign transitions accumulates reconstruction error across $W$ timesteps, whereas Isolation Forest evaluates each step individually without accumulating sequence drift.
3. **Inference Speed vs. Alert Volume:** CPU batch scoring via `LSTMAutoencoder` achieves lower batch latency (**123.9–245.91 ms**) than scikit-learn tree path traversal (**483.93–586.0 ms** on CPU), making $W=5$ LSTM a viable high-recall screening signal—though operational SOC triage without human alert fatigue currently favors Isolation Forest's much lower false-positive load (`4,578` vs. `5,311` FPs at $W=5$, and `4,508` vs. `12,389` at $W=10$).

---

## 14. Limitations

Strict scientific reporting requires highlighting the verified boundaries and limitations of the current system:

1. **Elevated False-Positive Rates:** Even the strongest configuration (`Isolation Forest` at `80.02%` accuracy / `21.67%` FPR; `LSTM W=5` at `24.9%` FPR) produces over 4,600 false positives on 21,502 benign held-out events (`Precision ~32%–35%`, `PR-AUC ~27%`), reflecting extreme cross-environment workload shift between the short 6-hour training log and the 46-day testing log.
2. **Offline Evaluation Only (No Live AWS Polling):** CloudTrail JSON files are ingested offline; AWS STS credential connectors report validation failure without backend secrets, and no live production AWS stream is claimed.
3. **Absence of Labeled FaaS Attacks & Missing Lambda Runtime Metrics:** All 51 training and 2,994 deduplicated testing FaaS records carry `should_sample = false`, preventing measurement of FaaS-specific attack precision or recall. CloudTrail also omits execution duration, memory usage, and cold-start metrics (`Unavailable`), and `13` raw `kms:Decrypt` events invoke under Lambda role ARNs without populating `inScopeOf`.
4. **Validation Sensitivity & Window Warmup Exclusions:** Chronological threshold calibration degrades if validation splits drop below majority-benign (`75/25` collapse noted in Section 9.6), and sequence windows exclude initial $W-1$ warmup events plus short user sequences (`190–468` excluded test events). Small fixtures such as the 36-row CERT sample cannot support windowing and are explicitly rejected (`HTTP 422`).
5. **Estimated Optimization Costs, Synthetic OpenStack Fixtures & Future Extensions:** The implemented **Cost-Aware Adaptive Security Policy Optimizer** (`src/server/policyOptimizer.ts`) uses explicitly labeled configurable model estimates (`$18`–`$260` per enforcement action, `5`–`88` disruption index, `1.5s`–`12.0s` latency) rather than live AWS billing telemetry, and produces non-binding `Pending Approval` proposals rather than executing automated cloud remediations. Similarly, the **OpenStack audit integration** (`src/server/openstackAdapter.ts`) was verified against multi-service synthetic fixtures (`Keystone`, `Nova`, `Neutron`, `Glance`, `Cinder`) and remains honestly `Not Connected` on the host because Docker, WSL2, and live Keystone credentials are absent. **Transformer sequence detectors** and seeded demonstration rows (`SEEDED_LAMBDA_METRICS`, `SEEDED_INCIDENTS`, `SEEDED_POLICIES`) remain explicitly separated from measured ML outputs.

---

## 15. Conclusion and Future Work

This work presented **CloudSentinel AI**, an integrated cloud audit-log insider threat analysis system implementing leak-free AWS CloudTrail normalization, an 8-feature unsupervised Isolation Forest baseline, a chronological 10-feature PyTorch LSTM Autoencoder evaluated across sliding windows $W \in \{5, 10, 16\}$, a schema-driven AWS Lambda/FaaS telemetry extractor, a constraint-bounded cost-aware adaptive policy optimizer, and a multi-service OpenStack CADF/audit ingestion adapter. Controlled held-out evaluation over 24,079 CloudTrail records confirms that while PyTorch LSTM achieves superior sensitivity (**97.2% recall** at $W=5$, **99.3% recall** at $W=16$) and fast batch inference (**123.9 ms**), the **Isolation Forest baseline achieves stronger overall detection balance** (**80.02% accuracy**, **50.28% F1**, **84.50% ROC-AUC**, **21.67% FPR** across all 24,079 events; **50.7%–51.4% F1** on eligible sequential subsets), avoiding the sharp false-positive escalation seen in longer LSTM windows ($W=10, 16$).

Future research directions directly following these verified findings include:
1. **Labeled Serverless FaaS Attack Datasets & CloudWatch Fusion:** Combining CloudTrail audit trails with CloudWatch Logs runtime metrics (`REPORT RequestId`, duration, billed memory, cold-start init time) and curated labeled FaaS insider/abuse scenarios.
2. **Domain-Adaptive & Calibrated Sequence Models:** Investigating KL-regularized autoencoders [7] or attention-based Transformer architectures with false-positive-constrained validation objectives to suppress benign distribution-shift alerts.
3. **Live OpenStack Private-Cloud Validation:** Connecting the implemented OpenStack adapter to a live containerized DevStack/Kollla-Ansible cluster (`Keystone` v3 reader credentials, `Nova`, `Neutron`, `Glance`, `Cinder`) to benchmark trained detectors on live private-cloud attack traces.
4. **Billing-Calibrated & Automated Remediation Studies:** Grounding enforcement cost parameters in empirical AWS CloudWatch / Cost Explorer telemetry and SOC triage measurements prior to evaluating closed-loop policy execution under human oversight.

---

## 16. References

[1] F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation Forest," in *Proc. Eighth IEEE International Conference on Data Mining (ICDM)*, Pisa, Italy, Dec. 2008, pp. 413–422. DOI: `10.1109/ICDM.2008.17`.

[2] S. Hochreiter and J. Schmidhuber, "Long Short-Term Memory," *Neural Computation*, vol. 9, no. 8, pp. 1735–1780, Nov. 1997. DOI: `10.1162/neco.1997.9.8.1735`.

[3] M. Villarreal-Vasquez, G. Modelo-Howard, S. Dube, and B. K. Bhargava, "Hunting for Insider Threats Using LSTM-Based Anomaly Detection," *IEEE Transactions on Dependable and Secure Computing*, vol. 20, no. 1, pp. 451–462, Jan.–Feb. 2023 (Early Access 2021). Official IEEE DOI: `10.1109/TDSC.2021.3135639` *(Verified via IEEE bibliography; corrects draft identifier `10.1109/TDSC.2021.3130377`)*.

[4] S. Maleki, S. Maleki, and N. R. Jennings, "Unsupervised anomaly detection with LSTM autoencoders using statistical data-filtering," *Applied Soft Computing*, vol. 108, Art. no. 107443, Sep. 2021. DOI: `10.1016/j.asoc.2021.107443`.

[5] Y. Wang, C. Zhang, and J. Yu, "Towards Massive Log Anomaly Detection Based on an Enhanced Multi-dimensional Time-domain LSTM," in *Proc. IEEE Ninth International Conference on Big Data Computing Service and Applications (BigDataService)*, 2023. DOI: `10.1109/BigDataService58306.2023.00042` *(Page numbers: [Author verification needed before final camera-ready submission])*.

[6] D. Shanmugapriya, C. Dhanya, S. Asha, G. Padmavathi, and D. N. P. Suthisini, "Cloud Insider Threat Detection using Deep Learning Models," in *Proc. 11th International Conference on Computing for Sustainable Global Development (INDIACom)*, New Delhi, India, Feb. 2024, pp. 434–438. DOI: `10.23919/INDIACom61295.2024.10498767`.

[7] W. Huang, B. Zhang, K. Zhang, H. Gao, and R. Wan, "Improved AutoEncoder With LSTM Module and KL Divergence for Anomaly Detection," *IEEE Transactions on Instrumentation and Measurement*, vol. 73, pp. 1–11, 2024. DOI: `10.1109/TIM.2024.3460931`.
