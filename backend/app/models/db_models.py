from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(String(50), index=True)
    user_id = Column(String(100), index=True)
    action = Column(String(100), index=True)
    resource = Column(String(150), index=True)
    source_ip = Column(String(50))
    status = Column(String(30))
    upload_batch_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class PreprocessingJob(Base):
    __tablename__ = "preprocessing_jobs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    batch_id = Column(String(100), unique=True, index=True)
    total_records = Column(Integer, default=0)
    valid_records = Column(Integer, default=0)
    removed_duplicates = Column(Integer, default=0)
    encoded_features = Column(Text, default="")
    status = Column(String(50), default="completed")
    created_at = Column(DateTime, default=datetime.utcnow)

class ModelRecord(Base):
    __tablename__ = "model_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    model_name = Column(String(100), index=True)
    model_type = Column(String(50))  # IsolationForest, LSTM, Transformer
    trained_at = Column(DateTime, default=datetime.utcnow)
    dataset_size = Column(Integer, default=0)
    accuracy = Column(Float, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    roc_auc = Column(Float, nullable=True)
    training_time_seconds = Column(Float, default=0.0)
    status = Column(String(50), default="ready")

class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    log_id = Column(Integer, ForeignKey("audit_logs.id"), nullable=True)
    user_id = Column(String(100), index=True)
    timestamp = Column(String(50))
    action = Column(String(100))
    resource = Column(String(150))
    source_ip = Column(String(50))
    status = Column(String(30))
    anomaly_score = Column(Float)
    risk_level = Column(String(30))  # Normal, Medium Risk, High Risk
    model_used = Column(String(50))  # Isolation Forest, LSTM Sequence Detector
    flag_reason = Column(Text)
    recommended_action = Column(String(200))
    created_at = Column(DateTime, default=datetime.utcnow)

class FaasEvent(Base):
    __tablename__ = "faas_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    function_name = Column(String(120), index=True)
    function_id = Column(String(100))
    user_id = Column(String(100), index=True)
    request_id = Column(String(100), unique=True)
    event_type = Column(String(50))
    execution_duration_ms = Column(Float)
    permission = Column(String(100))
    resource = Column(String(150))
    timestamp = Column(String(50))
    status = Column(String(30))
    is_anomalous = Column(Boolean, default=False)
    anomaly_reason = Column(String(250), nullable=True)
    is_simulated = Column(Boolean, default=True)

class PolicyRecommendation(Base):
    __tablename__ = "policy_recommendations"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    detection_id = Column(Integer, ForeignKey("detection_results.id"), nullable=True)
    user_id = Column(String(100), index=True)
    current_risk_score = Column(Float)
    recommended_policy = Column(String(100))
    security_benefit = Column(String(200))
    estimated_cost_usd = Column(Float)
    performance_overhead_pct = Column(Float)
    reason = Column(Text)
    status = Column(String(30), default="Pending")  # Pending, Approved, Rejected
    decided_at = Column(DateTime, nullable=True)
    decision_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    title = Column(String(200))
    description = Column(Text)
    severity = Column(String(30))  # Low, Medium, High, Critical
    status = Column(String(30), default="Open")  # Open, Investigating, Resolved, Closed
    assigned_to = Column(String(100), default="SOC Analyst")
    related_user_id = Column(String(100))
    related_event_ids = Column(String(250), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    notes = relationship("InvestigationNote", back_populates="incident", cascade="all, delete-orphan")

class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    author = Column(String(100), default="Security Analyst")
    note = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="notes")
