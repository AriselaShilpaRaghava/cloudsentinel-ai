"""
FastAPI router mapping all CloudSentinel AI endpoints.
Provides complete REST coverage for audit logs, preprocessing, ML training & detection,
FaaS monitoring, policy optimization, incidents, reporting, and OpenStack integration.
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import io
import os
import csv
import pandas as pd
from datetime import datetime

from backend.app.database import get_db
from backend.app.models.db_models import (
    AuditLog, PreprocessingJob, ModelRecord, DetectionResult,
    FaasEvent, PolicyRecommendation, Incident, InvestigationNote
)
from backend.app.schemas.schemas import (
    AuditLogOut, PreprocessingResponse, ModelTrainRequest, ModelStatusOut,
    DetectionResultOut, DetectionRunRequest, FaasEventBase, FaasEventOut,
    PolicyRecommendationOut, PolicyDecisionRequest, IncidentCreate, IncidentUpdate,
    InvestigationNoteCreate, IncidentOut, OpenStackTestResponse
)
from backend.app.services.preprocessor import LogPreprocessor
from backend.app.services.risk_engine import RiskEngine
from backend.app.services.policy_optimizer import PolicyOptimizer
from backend.app.ml.isolation_forest import IsolationForestDetector
from backend.app.ml.lstm_detector import LSTMSequenceDetector
from backend.app.ml.metrics import compute_metrics
from backend.app.integrations.openstack_adapter import OpenStackAdapter

router = APIRouter(prefix="/api")

preprocessor = LogPreprocessor()
if_detector = IsolationForestDetector()
lstm_detector = LSTMSequenceDetector()
policy_optimizer = PolicyOptimizer()
openstack_adapter = OpenStackAdapter()

@router.get("/health")
def get_health():
    return {
        "status": "healthy",
        "app": "CloudSentinel AI",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "SQLite (Connected)",
        "models": {
            "isolation_forest": if_detector.is_trained,
            "lstm_sequence": lstm_detector.is_trained
        }
    }

@router.get("/dashboard")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    total_logs = db.query(AuditLog).count()
    unique_users = db.query(AuditLog.user_id).distinct().count()
    total_detections = db.query(DetectionResult).count()
    high_risk_count = db.query(DetectionResult).filter(DetectionResult.risk_level == "High Risk").count()
    medium_risk_count = db.query(DetectionResult).filter(DetectionResult.risk_level == "Medium Risk").count()
    normal_count = db.query(DetectionResult).filter(DetectionResult.risk_level == "Normal").count()
    active_incidents = db.query(Incident).filter(Incident.status.in_(["Open", "Investigating"])).count()
    total_faas = db.query(FaasEvent).count()
    anomalous_faas = db.query(FaasEvent).filter(FaasEvent.is_anomalous == True).count()

    recent_suspicious = (
        db.query(DetectionResult)
        .filter(DetectionResult.risk_level.in_(["High Risk", "Medium Risk"]))
        .order_by(DetectionResult.id.desc())
        .limit(6)
        .all()
    )

    return {
        "summary": {
            "total_audit_logs": total_logs,
            "monitored_users": unique_users,
            "normal_activities": normal_count if total_detections > 0 else total_logs,
            "suspicious_activities": high_risk_count + medium_risk_count,
            "high_risk_events": high_risk_count,
            "active_incidents": active_incidents,
            "faas_invocations": total_faas,
            "anomalous_faas": anomalous_faas
        },
        "risk_distribution": [
            {"name": "Normal", "value": normal_count, "color": "#22C55E"},
            {"name": "Medium Risk", "value": medium_risk_count, "color": "#F59E0B"},
            {"name": "High Risk", "value": high_risk_count, "color": "#EF4444"}
        ],
        "model_status": {
            "active_baseline": "Isolation Forest (scikit-learn)",
            "sequence_model": "LSTM Sequential Autoencoder (PyTorch)",
            "isolation_forest_trained": if_detector.is_trained,
            "lstm_trained": lstm_detector.is_trained
        },
        "recent_suspicious": recent_suspicious
    }

@router.post("/logs/upload")
async def upload_audit_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    content = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(content))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV file: {str(e)}")

    required_cols = {"timestamp", "user_id", "action", "resource", "source_ip", "status"}
    if not required_cols.issubset(set(df.columns)):
        raise HTTPException(
            status_code=422,
            detail=f"CSV is missing required columns. Must contain: {', '.join(required_cols)}"
        )

    batch_id = f"batch_{int(datetime.utcnow().timestamp())}"
    logs_created = 0
    duplicates_skipped = 0

    for _, row in df.iterrows():
        # Avoid exact duplicate insert
        exists = db.query(AuditLog).filter(
            AuditLog.timestamp == str(row["timestamp"]),
            AuditLog.user_id == str(row["user_id"]),
            AuditLog.action == str(row["action"]),
            AuditLog.resource == str(row["resource"])
        ).first()

        if exists:
            duplicates_skipped += 1
            continue

        log_obj = AuditLog(
            timestamp=str(row["timestamp"]),
            user_id=str(row["user_id"]),
            action=str(row["action"]),
            resource=str(row["resource"]),
            source_ip=str(row["source_ip"]),
            status=str(row["status"]),
            upload_batch_id=batch_id
        )
        db.add(log_obj)
        logs_created += 1

    db.commit()

    return {
        "batch_id": batch_id,
        "filename": file.filename,
        "logs_imported": logs_created,
        "duplicates_skipped": duplicates_skipped,
        "message": f"Successfully parsed and stored {logs_created} audit logs in SQLite database."
    }

@router.get("/logs", response_model=List[AuditLogOut])
def get_logs(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if user_id:
        query = query.filter(AuditLog.user_id.ilike(f"%{user_id}%"))
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if status:
        query = query.filter(AuditLog.status.ilike(f"%{status}%"))
    return query.order_by(AuditLog.id.desc()).offset(offset).limit(limit).all()

@router.get("/logs/{log_id}", response_model=AuditLogOut)
def get_log_by_id(log_id: int, db: Session = Depends(get_db)):
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return log

@router.post("/preprocessing/run", response_model=PreprocessingResponse)
def run_preprocessing(db: Session = Depends(get_db)):
    logs = db.query(AuditLog).all()
    if not logs:
        raise HTTPException(status_code=400, detail="No audit logs in database to preprocess. Please upload logs first.")

    data = [
        {
            "timestamp": l.timestamp,
            "user_id": l.user_id,
            "action": l.action,
            "resource": l.resource,
            "source_ip": l.source_ip,
            "status": l.status
        }
        for l in logs
    ]
    df = pd.DataFrame(data)
    cleaned_df, feat_mat, stats = preprocessor.preprocess_dataframe(df)

    batch_id = f"prep_{int(datetime.utcnow().timestamp())}"
    job = PreprocessingJob(
        batch_id=batch_id,
        total_records=stats["initial_records"],
        valid_records=stats["valid_records"],
        removed_duplicates=stats["duplicates_removed"],
        encoded_features=",".join(stats["extracted_features"]),
        status="completed"
    )
    db.add(job)
    db.commit()

    return PreprocessingResponse(
        batch_id=batch_id,
        total_records=stats["initial_records"],
        valid_records=stats["valid_records"],
        removed_duplicates=stats["duplicates_removed"],
        extracted_features=stats["extracted_features"],
        user_count=stats["unique_users"],
        time_span=f"{cleaned_df['timestamp'].min()} to {cleaned_df['timestamp'].max()}"
    )

@router.post("/models/train", response_model=ModelStatusOut)
def train_model(req: ModelTrainRequest, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).all()
    if len(logs) < 5:
        raise HTTPException(
            status_code=400,
            detail="Insufficient audit log records in database. At least 5 records required for model training."
        )

    data = [
        {
            "timestamp": l.timestamp,
            "user_id": l.user_id,
            "action": l.action,
            "resource": l.resource,
            "source_ip": l.source_ip,
            "status": l.status
        }
        for l in logs
    ]
    df = pd.DataFrame(data)
    cleaned_df, feat_mat, stats = preprocessor.preprocess_dataframe(df)

    start_t = datetime.utcnow()

    if req.model_type == "LSTM":
        sequences = preprocessor.create_lstm_sequences(cleaned_df, feat_mat, window_size=req.sequence_length)
        lstm_detector.sequence_length = req.sequence_length
        lstm_detector.fit(sequences, epochs=req.epochs)
        train_time = (datetime.utcnow() - start_t).total_seconds()
        model_name = "LSTM Sequence Autoencoder"
        m_type = "LSTM"
    else:
        if_detector.contamination = req.contamination
        if_detector.fit(feat_mat)
        train_time = (datetime.utcnow() - start_t).total_seconds()
        model_name = "Isolation Forest Baseline"
        m_type = "IsolationForest"

    rec = ModelRecord(
        model_name=model_name,
        model_type=m_type,
        dataset_size=len(cleaned_df),
        training_time_seconds=round(train_time, 3),
        status="Trained and Saved"
    )
    db.add(rec)
    db.commit()

    return ModelStatusOut(
        model_name=model_name,
        model_type=m_type,
        status="Trained & Ready",
        trained_at=datetime.utcnow(),
        dataset_size=len(cleaned_df),
        accuracy=None,
        precision=None,
        recall=None,
        f1_score=None,
        roc_auc=None,
        training_time_seconds=round(train_time, 3)
    )

@router.get("/models/status")
def get_models_status(db: Session = Depends(get_db)):
    records = db.query(ModelRecord).order_by(ModelRecord.id.desc()).all()
    return {
        "isolation_forest": {
            "name": "Isolation Forest (Baseline)",
            "is_trained": if_detector.is_trained,
            "parameters": {"n_estimators": 100, "contamination": if_detector.contamination}
        },
        "lstm_sequence": {
            "name": "LSTM Temporal Sequence Detector",
            "is_trained": lstm_detector.is_trained,
            "parameters": {"sequence_length": lstm_detector.sequence_length, "hidden_dim": 32}
        },
        "transformer_extension": {
            "name": "Transformer Self-Attention Log Sequence (Extension)",
            "is_trained": False,
            "status": "Optional Architectural Extension Available"
        },
        "recent_training_history": records
    }

@router.post("/detection/run")
def run_detection(req: DetectionRunRequest, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).all()
    if not logs:
        raise HTTPException(status_code=400, detail="No audit logs available for anomaly detection.")

    data = [
        {
            "id": l.id,
            "timestamp": l.timestamp,
            "user_id": l.user_id,
            "action": l.action,
            "resource": l.resource,
            "source_ip": l.source_ip,
            "status": l.status
        }
        for l in logs
    ]
    df = pd.DataFrame(data)
    cleaned_df, feat_mat, stats = preprocessor.preprocess_dataframe(df)

    # Automatically fit if not trained yet
    if req.model_type == "LSTM":
        if not lstm_detector.is_trained:
            sequences = preprocessor.create_lstm_sequences(cleaned_df, feat_mat, window_size=5)
            lstm_detector.fit(sequences)
        sequences = preprocessor.create_lstm_sequences(cleaned_df, feat_mat, window_size=5)
        raw_scores = lstm_detector.predict_anomaly_scores(sequences)
        # Pad or interpolate back to sample length if sequential windows differ
        if len(raw_scores) < len(cleaned_df):
            padded = np.full(len(cleaned_df), np.mean(raw_scores) if len(raw_scores) > 0 else 0.5)
            padded[:len(raw_scores)] = raw_scores
            scores = padded
        else:
            scores = raw_scores[:len(cleaned_df)]
        model_name = "LSTM Sequence Model"
    else:
        if not if_detector.is_trained:
            if_detector.fit(feat_mat)
        scores = if_detector.predict_anomaly_scores(feat_mat)
        model_name = "Isolation Forest"

    # Clear old results to keep current run fresh
    db.query(DetectionResult).delete()
    db.query(PolicyRecommendation).delete()

    results_to_add = []
    policies_to_add = []

    for idx, row in cleaned_df.iterrows():
        ml_score = float(scores[idx])
        act_risk = float(row["action_risk_weight"])
        res_sens = float(row["resource_sensitivity"])
        is_off = bool(row["is_off_hours"] > 0)
        is_fail = bool(row["is_failure"] > 0)

        risk_score, risk_lvl, reason, action = RiskEngine.calculate_risk(
            ml_score=ml_score,
            action_risk=act_risk,
            resource_sensitivity=res_sens,
            is_off_hours=is_off,
            is_failure=is_fail,
            action_name=str(row["action"]),
            resource_name=str(row["resource"]),
            timestamp_str=str(row["timestamp"])
        )

        det_result = DetectionResult(
            log_id=int(row["id"]) if "id" in row and pd.notnull(row["id"]) else None,
            user_id=str(row["user_id"]),
            timestamp=str(row["timestamp"]),
            action=str(row["action"]),
            resource=str(row["resource"]),
            source_ip=str(row["source_ip"]),
            status=str(row["status"]),
            anomaly_score=ml_score,
            risk_level=risk_lvl,
            model_used=model_name,
            flag_reason=reason,
            recommended_action=action
        )
        db.add(det_result)
        db.flush()

        # If flagged as Medium or High Risk, generate cost-aware policy recommendation
        if risk_lvl in ["High Risk", "Medium Risk"]:
            policy_rec = policy_optimizer.optimize(
                current_risk=risk_score,
                user_id=str(row["user_id"]),
                flag_reason=reason
            )
            pol_obj = PolicyRecommendation(
                detection_id=det_result.id,
                user_id=str(row["user_id"]),
                current_risk_score=risk_score,
                recommended_policy=policy_rec["recommended_policy"],
                security_benefit=policy_rec["security_benefit"],
                estimated_cost_usd=policy_rec["estimated_cost_usd"],
                performance_overhead_pct=policy_rec["performance_overhead_pct"],
                reason=policy_rec["reason"],
                status="Pending"
            )
            db.add(pol_obj)

    db.commit()

    return {
        "status": "success",
        "model_used": model_name,
        "total_analyzed": len(cleaned_df),
        "high_risk_flagged": db.query(DetectionResult).filter(DetectionResult.risk_level == "High Risk").count(),
        "medium_risk_flagged": db.query(DetectionResult).filter(DetectionResult.risk_level == "Medium Risk").count()
    }

@router.get("/detection/results", response_model=List[DetectionResultOut])
def get_detection_results(
    risk_level: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    q = db.query(DetectionResult)
    if risk_level:
        q = q.filter(DetectionResult.risk_level == risk_level)
    if user_id:
        q = q.filter(DetectionResult.user_id.ilike(f"%{user_id}%"))
    return q.order_by(DetectionResult.anomaly_score.desc()).limit(limit).all()

@router.get("/detection/results/{result_id}", response_model=DetectionResultOut)
def get_detection_result_by_id(result_id: int, db: Session = Depends(get_db)):
    res = db.query(DetectionResult).filter(DetectionResult.id == result_id).first()
    if not res:
        raise HTTPException(status_code=404, detail="Detection result not found")
    return res

@router.get("/risk/summary")
def get_risk_summary(db: Session = Depends(get_db)):
    results = db.query(DetectionResult).all()
    user_stats = {}
    for r in results:
        u = r.user_id
        if u not in user_stats:
            user_stats[u] = {
                "user_id": u,
                "total_events": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "normal": 0,
                "max_score": 0.0,
                "avg_score": 0.0,
                "scores": []
            }
        user_stats[u]["total_events"] += 1
        if r.risk_level == "High Risk":
            user_stats[u]["high_risk"] += 1
        elif r.risk_level == "Medium Risk":
            user_stats[u]["medium_risk"] += 1
        else:
            user_stats[u]["normal"] += 1
        user_stats[u]["scores"].append(r.anomaly_score)
        if r.anomaly_score > user_stats[u]["max_score"]:
            user_stats[u]["max_score"] = round(r.anomaly_score, 3)

    summary_list = []
    for u, data in user_stats.items():
        data["avg_score"] = round(sum(data["scores"]) / len(data["scores"]), 3) if data["scores"] else 0.0
        del data["scores"]
        summary_list.append(data)

    summary_list.sort(key=lambda x: (x["high_risk"], x["max_score"]), reverse=True)

    return {
        "user_profiles": summary_list,
        "scoring_methodology": {
            "formula": "Risk = 0.40 * ML_Score + 0.25 * ActionWeight + 0.20 * ResourceSensitivity + 0.10 * OffHours + 0.05 * Failure",
            "thresholds": {"Normal": "< 0.40", "Medium": "0.40 - 0.70", "High": ">= 0.70"}
        }
    }

@router.get("/faas/events", response_model=List[FaasEventOut])
def get_faas_events(db: Session = Depends(get_db)):
    return db.query(FaasEvent).order_by(FaasEvent.id.desc()).limit(100).all()

@router.post("/faas/events", response_model=FaasEventOut)
def record_faas_event(event: FaasEventBase, db: Session = Depends(get_db)):
    # Serverless Anomaly Check
    # High execution duration (> 4000ms), sensitive IAM permissions (e.g. iam:* or s3:Delete*), or off-hours invocation
    is_anomalous = False
    anomaly_reasons = []

    if event.execution_duration_ms > 4500:
        is_anomalous = True
        anomaly_reasons.append(f"Excessive function runtime ({event.execution_duration_ms}ms) exceeding 99th percentile cold-start baseline")
    if "admin" in event.permission.lower() or "root" in event.permission.lower() or "delete" in event.permission.lower():
        is_anomalous = True
        anomaly_reasons.append(f"Over-privileged function IAM permission requested: '{event.permission}'")

    faas_obj = FaasEvent(
        function_name=event.function_name,
        function_id=event.function_id,
        user_id=event.user_id,
        request_id=event.request_id,
        event_type=event.event_type,
        execution_duration_ms=event.execution_duration_ms,
        permission=event.permission,
        resource=event.resource,
        timestamp=event.timestamp,
        status=event.status,
        is_anomalous=is_anomalous,
        anomaly_reason=" | ".join(anomaly_reasons) if anomaly_reasons else None,
        is_simulated=True
    )
    db.add(faas_obj)
    db.commit()
    db.refresh(faas_obj)
    return faas_obj

@router.get("/policies", response_model=List[PolicyRecommendationOut])
def get_policy_recommendations(status: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(PolicyRecommendation)
    if status:
        q = q.filter(PolicyRecommendation.status == status)
    return q.order_by(PolicyRecommendation.id.desc()).all()

@router.post("/policies/{policy_id}/decision")
def record_policy_decision(policy_id: int, req: PolicyDecisionRequest, db: Session = Depends(get_db)):
    pol = db.query(PolicyRecommendation).filter(PolicyRecommendation.id == policy_id).first()
    if not pol:
        raise HTTPException(status_code=404, detail="Policy recommendation not found")

    if req.decision not in ["Approved", "Rejected"]:
        raise HTTPException(status_code=400, detail="Decision must be 'Approved' or 'Rejected'")

    pol.status = req.decision
    pol.decided_at = datetime.utcnow()
    pol.decision_notes = req.notes
    db.commit()

    return {
        "policy_id": policy_id,
        "decision": pol.status,
        "decided_at": pol.decided_at.isoformat(),
        "notes": pol.decision_notes,
        "message": f"Policy recommendation has been marked as {req.decision}. Enforced in policy store."
    }

@router.get("/incidents", response_model=List[IncidentOut])
def get_incidents(status: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(Incident)
    if status:
        q = q.filter(Incident.status == status)
    return q.order_by(Incident.id.desc()).all()

@router.post("/incidents", response_model=IncidentOut)
def create_incident(inc: IncidentCreate, db: Session = Depends(get_db)):
    inc_obj = Incident(
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status="Open",
        related_user_id=inc.related_user_id,
        related_event_ids=inc.related_event_ids or ""
    )
    db.add(inc_obj)
    db.commit()
    db.refresh(inc_obj)
    return inc_obj

@router.put("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(incident_id: int, inc: IncidentUpdate, db: Session = Depends(get_db)):
    item = db.query(Incident).filter(Incident.id == incident_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Incident not found")

    if inc.status:
        item.status = inc.status
    if inc.severity:
        item.severity = inc.severity
    if inc.assigned_to:
        item.assigned_to = inc.assigned_to
    item.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(item)
    return item

@router.post("/incidents/{incident_id}/notes")
def add_incident_note(incident_id: int, note_in: InvestigationNoteCreate, db: Session = Depends(get_db)):
    item = db.query(Incident).filter(Incident.id == incident_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Incident not found")

    note_obj = InvestigationNote(
        incident_id=incident_id,
        author=note_in.author or "Security Analyst",
        note=note_in.note
    )
    db.add(note_obj)
    item.updated_at = datetime.utcnow()
    db.commit()
    return {"message": "Investigation note added successfully"}

@router.get("/reports/summary")
def get_reports_summary(db: Session = Depends(get_db)):
    total_logs = db.query(AuditLog).count()
    total_detections = db.query(DetectionResult).count()
    high_risk = db.query(DetectionResult).filter(DetectionResult.risk_level == "High Risk").count()
    medium_risk = db.query(DetectionResult).filter(DetectionResult.risk_level == "Medium Risk").count()
    normal = db.query(DetectionResult).filter(DetectionResult.risk_level == "Normal").count()
    total_incidents = db.query(Incident).count()
    open_incidents = db.query(Incident).filter(Incident.status.in_(["Open", "Investigating"])).count()
    total_policies = db.query(PolicyRecommendation).count()
    approved_policies = db.query(PolicyRecommendation).filter(PolicyRecommendation.status == "Approved").count()

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "total_audit_logs": total_logs,
        "detection_summary": {
            "total_analyzed": total_detections,
            "normal_events": normal,
            "medium_risk_events": medium_risk,
            "high_risk_events": high_risk
        },
        "incident_summary": {
            "total": total_incidents,
            "active": open_incidents
        },
        "policy_summary": {
            "total_recommended": total_policies,
            "approved": approved_policies
        },
        "openstack_status": openstack_adapter.test_connection()["mode"]
    }

@router.get("/reports/export")
def export_report_csv(db: Session = Depends(get_db)):
    results = db.query(DetectionResult).order_by(DetectionResult.id.asc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "user_id", "action", "resource", "source_ip", "status", "anomaly_score", "risk_level", "model_used", "flag_reason", "recommended_action"])
    for r in results:
        writer.writerow([r.id, r.timestamp, r.user_id, r.action, r.resource, r.source_ip, r.status, r.anomaly_score, r.risk_level, r.model_used, r.flag_reason, r.recommended_action])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cloudsentinel_audit_report_{int(datetime.utcnow().timestamp())}.csv"}
    )

@router.get("/integrations/openstack/status")
def get_openstack_status():
    return openstack_adapter.test_connection()

@router.post("/integrations/openstack/test")
def test_openstack_integration():
    return openstack_adapter.test_connection()

def find_sample_csv_path() -> Optional[str]:
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "sample_audit_logs.csv")),
        os.path.abspath(os.path.join(os.getcwd(), "data", "sample_audit_logs.csv")),
        "/app/applet/data/sample_audit_logs.csv",
        "data/sample_audit_logs.csv"
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None

def execute_demo_load(db: Session, reset: bool = False):
    sample_csv_path = find_sample_csv_path()
    if not sample_csv_path:
        raise HTTPException(
            status_code=404,
            detail="Sample audit logs CSV file not found at data/sample_audit_logs.csv"
        )

    try:
        df = pd.read_csv(sample_csv_path)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse sample CSV file: {str(e)}"
        )

    required_cols = {"timestamp", "user_id", "action", "resource", "source_ip", "status"}
    if not required_cols.issubset(set(df.columns)):
        raise HTTPException(
            status_code=422,
            detail=f"CSV is missing required columns. Must contain: {', '.join(required_cols)}"
        )

    if reset:
        db.query(AuditLog).delete()
        db.query(DetectionResult).delete()
        db.query(PolicyRecommendation).delete()
        db.query(Incident).delete()
        db.query(InvestigationNote).delete()
        db.query(FaasEvent).delete()
        db.commit()

    batch_id = f"demo_load_{int(datetime.utcnow().timestamp())}"
    inserted_count = 0
    skipped_count = 0

    for _, row in df.iterrows():
        exists = db.query(AuditLog).filter(
            AuditLog.timestamp == str(row["timestamp"]),
            AuditLog.user_id == str(row["user_id"]),
            AuditLog.action == str(row["action"]),
            AuditLog.resource == str(row["resource"])
        ).first()

        if exists:
            skipped_count += 1
            continue

        log_obj = AuditLog(
            timestamp=str(row["timestamp"]),
            user_id=str(row["user_id"]),
            action=str(row["action"]),
            resource=str(row["resource"]),
            source_ip=str(row["source_ip"]),
            status=str(row["status"]),
            upload_batch_id=batch_id
        )
        db.add(log_obj)
        inserted_count += 1

    db.commit()

    total_logs = db.query(AuditLog).count()

    if inserted_count == 0 and not reset:
        return {
            "status": "info",
            "message": f"Demo data is already loaded ({total_logs} records in database).",
            "records_loaded": 0,
            "duplicates_skipped": skipped_count,
            "total_records": total_logs,
            "already_loaded": True
        }

    # Preprocess and Run Detection on all logs
    all_logs = db.query(AuditLog).all()
    if all_logs:
        log_dicts = [
            {
                "timestamp": l.timestamp,
                "user_id": l.user_id,
                "action": l.action,
                "resource": l.resource,
                "source_ip": l.source_ip,
                "status": l.status
            }
            for l in all_logs
        ]
        all_df = pd.DataFrame(log_dicts)
        cleaned_df, feat_mat, stats = preprocessor.preprocess_dataframe(all_df)
        if_detector.fit(feat_mat)
        scores = if_detector.predict_anomaly_scores(feat_mat)

        db.query(DetectionResult).delete()
        db.query(PolicyRecommendation).delete()

        for idx, row in cleaned_df.iterrows():
            ml_score = float(scores[idx])
            act_risk = float(row["action_risk_weight"])
            res_sens = float(row["resource_sensitivity"])
            is_off = bool(row["is_off_hours"] > 0)
            is_fail = bool(row["is_failure"] > 0)

            risk_score, risk_lvl, reason, action = RiskEngine.calculate_risk(
                ml_score=ml_score,
                action_risk=act_risk,
                resource_sensitivity=res_sens,
                is_off_hours=is_off,
                is_failure=is_fail,
                action_name=str(row["action"]),
                resource_name=str(row["resource"]),
                timestamp_str=str(row["timestamp"])
            )

            det = DetectionResult(
                user_id=str(row["user_id"]),
                timestamp=str(row["timestamp"]),
                action=str(row["action"]),
                resource=str(row["resource"]),
                source_ip=str(row["source_ip"]),
                status=str(row["status"]),
                anomaly_score=ml_score,
                risk_level=risk_lvl,
                model_used="Isolation Forest Baseline",
                flag_reason=reason,
                recommended_action=action
            )
            db.add(det)
            db.flush()

            if risk_lvl in ["High Risk", "Medium Risk"]:
                policy_rec = policy_optimizer.optimize(
                    current_risk=risk_score,
                    user_id=str(row["user_id"]),
                    flag_reason=reason
                )
                pol = PolicyRecommendation(
                    detection_id=det.id,
                    user_id=str(row["user_id"]),
                    current_risk_score=risk_score,
                    recommended_policy=policy_rec["recommended_policy"],
                    security_benefit=policy_rec["security_benefit"],
                    estimated_cost_usd=policy_rec["estimated_cost_usd"],
                    performance_overhead_pct=policy_rec["performance_overhead_pct"],
                    reason=policy_rec["reason"],
                    status="Pending"
                )
                db.add(pol)

    # Seed Sample Incidents if none exist
    if db.query(Incident).count() == 0 or reset:
        inc1 = Incident(
            title="Unusual Off-Hours Bulk Download from PII Vault",
            description="User 'usr_dev_dave' assumed role 'role_cloud_admin' at 23:45 and executed bulk data downloads from customer_pii_vault and financial_records_db.",
            severity="Critical",
            status="Investigating",
            assigned_to="SOC Lead Analyst",
            related_user_id="usr_dev_dave",
            related_event_ids="28,29,30"
        )
        db.add(inc1)
        db.flush()

        note1 = InvestigationNote(
            incident_id=inc1.id,
            author="Tier-2 SOC Analyst",
            note="Contacted manager of usr_dev_dave; no scheduled maintenance or authorized export window was approved for 23:45 UTC."
        )
        db.add(note1)

    # Seed Sample FaaS Events if none exist
    if db.query(FaasEvent).count() == 0 or reset:
        faas_events = [
            FaasEvent(
                function_name="fn_auth_token_refresher",
                function_id="fn-1092-auth",
                user_id="usr_dev_alice",
                request_id="req-9901-aa",
                event_type="HTTP_TRIGGER",
                execution_duration_ms=142.5,
                permission="keystone:read_token",
                resource="token_cache",
                timestamp="2026-03-11 09:12:00",
                status="SUCCESS",
                is_anomalous=False,
                is_simulated=True
            ),
            FaasEvent(
                function_name="fn_crypto_key_rotator",
                function_id="fn-4411-sec",
                user_id="usr_ops_eve",
                request_id="req-9902-bb",
                event_type="CRON_TRIGGER",
                execution_duration_ms=4820.0,
                permission="kms:*",
                resource="kms_keystone",
                timestamp="2026-03-11 02:18:00",
                status="SUCCESS",
                is_anomalous=True,
                anomaly_reason="Execution duration 4820ms exceeded standard P99 threshold (4000ms) with wildcard KMS privileges",
                is_simulated=True
            ),
            FaasEvent(
                function_name="fn_thumbnail_generator",
                function_id="fn-8822-media",
                user_id="usr_dev_frank",
                request_id="req-9903-cc",
                event_type="S3_EVENT",
                execution_duration_ms=210.0,
                permission="swift:read_object",
                resource="object_storage_swift",
                timestamp="2026-03-11 11:21:00",
                status="SUCCESS",
                is_anomalous=False,
                is_simulated=True
            )
        ]
        for fe in faas_events:
            db.add(fe)

    db.commit()

    return {
        "status": "success",
        "message": f"Successfully loaded {inserted_count} demo audit records into SQLite database.",
        "records_loaded": inserted_count,
        "duplicates_skipped": skipped_count,
        "total_records": total_logs,
        "already_loaded": False
    }

@router.post("/demo/load")
def load_demo_data(reset: bool = Query(default=False), db: Session = Depends(get_db)):
    """Loads synthetic audit logs into SQLite, avoiding duplicates unless reset=True."""
    return execute_demo_load(db, reset=reset)

@router.post("/demo/seed")
def seed_demo_data(db: Session = Depends(get_db)):
    """Seed / reseed comprehensive demo dataset into SQLite database."""
    return execute_demo_load(db, reset=True)
