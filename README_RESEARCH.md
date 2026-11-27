# CloudSentinel AI — Setup, Architecture & Research Execution Guide

## 1. Live Full-Stack Applet (Node.js + Express + React/TypeScript)
Run directly on port `3000`:
```bash
npm install
npm run dev
```
Build for production:
```bash
npm run build
npm start
```

## 2. Full Multi-Service Research Stack (FastAPI + PyTorch LSTM + Scikit-learn + PostgreSQL)
To run the standalone Python FastAPI control plane, Python ML microservice (`ml_service/`), and PostgreSQL 16 database (`database/schema.sql`):
```bash
docker compose up --build
```
Set `ML_SERVICE_URL=http://localhost:8001` in your environment to route anomaly detection requests from the Node/Express API gateway to the Python ML service. When `ML_SERVICE_URL` is unset, the UI transparently labels all detection scores as **Simulated Baseline Scorer (Python FastAPI ML Service Disconnected)**.

## 3. Role-Based Access Control (RBAC)
- **Admin**: Full access including policy approval/rejection, risk/cost weight configuration, cloud integration testing, and user provisioning.
- **Security Analyst**: Can upload audit logs/datasets, run anomaly detection, create/investigate incidents, and execute ML evaluation experiments.
- **Viewer**: Read-only access across dashboards, UBA, reports, and architecture views.

## 4. Acceptance & Verification Checklist
- Normalized canonical schema: `event_id, provider, event_time, cloud_user_id, action, resource, source_ip, status, raw_event`.
- Confidence-aware detection keeps **Anomaly Score**, **Prediction Confidence**, and **Risk Score** separate, routing low-confidence or sparse-evidence events to **Requires Additional Investigation**.
- Model Evaluation Lab computes real Confusion Matrices, Accuracy, Precision, Recall, F1, FPR, ROC curves, and PR curves over strict train/validation/test splits.
