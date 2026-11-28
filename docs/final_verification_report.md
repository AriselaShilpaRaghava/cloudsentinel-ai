# CloudSentinel AI — Final Verification & Submission Readiness Report (Phase R5)

**Verification Date:** `2026-11-27`  
**Host Environment:** Windows 11 (`AMD64`, 12 logical cores, 15.65 GB RAM), Python `3.14.0` (`torch 2.14.0+cpu`, `scikit-learn 1.9.0`, `fastapi 0.165.0`), Node.js / Express (`4.21.2`), React (`19.0.1`), TypeScript (`7.0.2`), Vite (`8.3.0`).

---

## 1. Verified Feature Checklist

| Component / Capability | Status | Evidence & Scope |
|---|---|---|
| React Dashboard (`DashboardPage.tsx`) | **PASS** | Displayed `28,341` total events, ML connected badge, resource counts, threat timeline, cost posture, recent events; `0` console/HTTP errors |
| Express Backend (`server.ts`, port `3000`) | **PASS** | Served all `/api/*` endpoints cleanly, enforced RBAC (`Admin`, `Security Analyst`, `Viewer`), persisted state in `STATE_FILE` |
| Python FastAPI ML Service (`ml_service/main.py`, port `8001`) | **PASS** | `/health`, `/predict`, `/train`, `/evaluate`, `/faas/telemetry`, `/lstm/status`, `/lstm/train-evaluate`, `/lstm/evaluate` all operational |
| CloudTrail CSV/JSON Upload & Dataset Registry | **PASS** | `ds-cloudtrail-train` (`4,216`), `ds-cloudtrail-test` (`24,079` deduplicated), OpenStack & CERT datasets cleanly registered; empty/invalid payload returns `HTTP 400` |
| Isolation Forest Prediction & Contract | **PASS** | Saved `data/isolation_forest_cloudtrail.joblib` (`isolation-forest-cloudtrail-v2`) preserved intact with `feature_count = 8`, `threshold = 0.012074` |
| LSTM Sequence Evaluation (`W = 5, 10, 16`) | **PASS** | Saved checkpoints `lstm_cloudtrail_w5.pt`, `lstm_cloudtrail_w10.pt`, `lstm_cloudtrail_w16.pt` verified via `GET /lstm/status` and `POST /lstm/evaluate` |
| Side-by-Side Model Comparison (`ModelEvaluationPage.tsx`) | **PASS** | Evaluated PyTorch LSTM vs. saved Isolation Forest over identical eligible test events (`23,889` / `23,754` / `23,611`) with `Real ML` badges and ROC/PR curves |
| Phase R1 FaaS Telemetry (`ml_service/faas_extractor.py`) | **PASS** | Extracted `3,045` combined FaaS events (`51` train, `2,994` test) across `7` functions/roles; separated from `SIMULATED SEEDED DATA`; missing runtime fields marked `Unavailable` |
| Phase R3 Cost-Aware Policy Optimizer (`src/server/policyOptimizer.ts`) | **PASS** | Evaluated 5 controls under cost/impact/latency constraints, compared against static severity baseline, tagged estimated costs, `auto_executed = false` |
| Pending Approval & Admin Approval Workflow | **PASS** | `Security Analyst` created `Pending Approval` proposals (`HTTP 201`), denied approval (`HTTP 403`), `Admin` approved (`HTTP 200`); `Viewer` denied mutations (`HTTP 403`) |
| Phase R4 OpenStack Adapter (`src/server/openstackAdapter.ts`) | **PASS** | Normalized all 5 services (`Keystone`, `Nova`, `Neutron`, `Glance`, `Cinder`) + unknown service, redacted secrets/tokens (`[REDACTED]`), labeled `Real OpenStack` vs `Synthetic Fixture`, reported `Not Connected` honestly |
| Risk Scoring, UBA & Incident Management | **PASS** | `GET /api/uba/users` (`154` profiles), `GET /api/detection/predictions` (`28,341`), and `GET /api/incidents` (`4` incidents) rendered and triaged cleanly |
| CSV & PDF Report Exports (`ReportsPage.tsx`) | **PASS** | `GET /api/reports/pdf` returned `HTTP 200` (`Content-Type: application/pdf`, `attachment; filename="cloudsentinel-report.pdf"`, `16,633` bytes, `%PDF-1.3`); CSV download exported without `file://` errors |

---

## 2. Actual Test & Quality Check Outcomes

| Check / Command | Outcome | Observed Summary |
|---|---|---|
| `npx.cmd tsx tests/openstackAdapter.test.ts` (unit + `RUN_LIVE_API_TESTS=1`) | **PASS** | Unit tests (5 services, redaction, missing/malformed, dedup, baseline vs suspicious) and live API/RBAC/regression suite exited `0` *(made live connectivity assertion idempotent across repeated fixture/real ingest runs)* |
| `npx.cmd tsx tests/policyOptimizer.test.ts` (unit + `RUN_LIVE_API_TESTS=1`) | **PASS** | 9 deterministic unit test groups (Low/Med/High/Critical, constraints, missing/invalid, determinism) and live API/RBAC/approval/IF+FaaS regression exited `0` |
| `npm.cmd run lint` (`tsc --noEmit`) | **PASS** | Exited `0` with zero TypeScript errors |
| `npm.cmd run build` (`vite build`) | **PASS** | Exited `0` (`dist/` bundled in `1.48 s`) |
| `GET http://127.0.0.1:8001/health` & `/lstm/status` | **PASS** | `200 OK`; `isolation_forest_cloudtrail.joblib` (`feature_count=8`); 3 `.pt` LSTM checkpoints (`exists: true`) |
| `POST http://127.0.0.1:8001/lstm/evaluate` (`W=5, 10, 16`) | **PASS** | All three checkpoints returned `200 OK`, `suitable=True`, with synchronized IF baseline counts (`78`, `58`, `34` test windows on sample batch) |
| Live Browser Sweep across 10 major pages + exports (`http://localhost:3000/`) | **PASS** | `0` console errors, `0` HTTP `>= 400` failures across 50 requests; verified all pages + PDF & CSV downloads |

---

## 3. Data, Model Artifact & External Backup Integrity

### External Backup Check (`C:\Users\A Shilpa Raghava\Downloads\cloudsentinel-ai-backup-2026-11-27`)
- Backup exists with `264` files; SHA-256 comparison confirmed **exact bit-for-bit equality** (`identical=True`) with workspace sources/models for:
  - `data/cloudtrail_training.json` (`7e133640cd9ff5d2`, `7,108,889` bytes)
  - `data/cloudtrail_testing.json` (`42cbfdd55ca7ca69`, `49,833,156` bytes)
  - `data/isolation_forest_cloudtrail.joblib` (`cfbe7d6752c0394c`, `1,589,279` bytes)
  - `ml_service/cloudtrail_pipeline.py` (`c371c621e20b7bd8`, `17,319` bytes)

### Dataset & Model Inventory
- `data/cloudtrail_training.json` (`ds-cloudtrail-train`): `4,216` raw / `4,216` unique `eventID` records (`541` attacks, `3,675` benign; `51` FaaS events).
- `data/cloudtrail_testing.json` (`ds-cloudtrail-test`): `24,087` raw / `24,079` unique `eventID` records (`2,585` raw attacks, `21,502` raw benign; `2,994` deduplicated FaaS events).
- Isolation Forest: `data/isolation_forest_cloudtrail.joblib` (`isolation-forest-cloudtrail-v2`, 8 features, calibrated threshold `0.012074`).
- PyTorch LSTM Checkpoints:
  - `data/lstm_cloudtrail_w5.pt` (`34,663` B, `pytorch-lstm-ae-w5-h32-v1`, threshold `0.337648`)
  - `data/lstm_cloudtrail_w10.pt` (`34,677` B, `pytorch-lstm-ae-w10-h32-v1`, threshold `0.330225`)
  - `data/lstm_cloudtrail_w16.pt` (`34,677` B, `pytorch-lstm-ae-w16-h32-v1`, threshold `0.311792`)

---

## 4. Known Limitations

1. **False-Positive Tradeoff:** Isolation Forest (`80.02%` accuracy, `21.67%` FPR, `50.28%` F1) outperforms the chronological LSTM Autoencoder overall; LSTM raises recall (`97.2%`–`99.3%`) at higher FPR (`24.9%` at `W=5`, `58.5%` at `W=10`, `65.2%` at `W=16`) due to benign distribution shift between the 6-hour training log and 46-day testing log.
2. **Offline Evaluation Only / No Live Cloud Deployments:** AWS CloudTrail files are processed offline and OpenStack live connectivity reports `Not Connected` on this host (`OPENSTACK_AUTH_URL` and credentials absent; Docker/WSL2 absent).
3. **FaaS Observability Constraints:** Zero FaaS attack labels exist in the CloudTrail datasets (`should_sample=false` on all FaaS events); runtime duration, memory, and cold-start metrics are `Unavailable in CloudTrail`; and `13` raw `kms:Decrypt` Lambda role calls omit `userIdentity.inScopeOf`.
4. **Estimated Optimization Costs & Seeded Demo Fixtures:** Optimizer dollar costs/latencies/impacts are configurable estimates rather than AWS Billing data; optimizer approvals generate human-approved proposals rather than automated API mutations; seeded UI fixtures (`SEEDED_LAMBDA_METRICS`, `SEEDED_INCIDENTS`, `SEEDED_POLICIES`) remain separated and labeled.

---

## 5. Deployment Prerequisites & Remaining Submission Tasks

### Deployment Prerequisites (When Moving Beyond Local Evaluation)
- Configure backend `.env` secrets (`ML_SERVICE_URL`, read-only `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` if integrating live STS/CloudTrail, and `OPENSTACK_AUTH_URL` + `OPENSTACK_APPLICATION_CREDENTIAL_ID`/`SECRET` or `OPENSTACK_TOKEN` for live OpenStack Keystone).
- Provision persistent state storage (`STATE_FILE` or PostgreSQL backing store) and run `ml_service` (`uvicorn main:app`) alongside Express (`server.ts`).

### Remaining Submission Tasks (Author Actions)
1. Fill `[Author Names Placeholder]`, `[Department / Institution Placeholder]`, and `[Corresponding Author Email Placeholder]` in [docs/research_paper.md](docs/research_paper.md) / [docs/research_paper.docx](docs/research_paper.docx).
2. Confirm Ref `[5]` pagination (`BigDataService 2023`, DOI `10.1109/BigDataService58306.2023.00042`) marked `[Author verification needed before final camera-ready submission]`.
3. Capture and insert final PNG figures from the running UI into Figure Placeholders 1–4 of `docs/research_paper.docx` prior to final journal/conference upload.
