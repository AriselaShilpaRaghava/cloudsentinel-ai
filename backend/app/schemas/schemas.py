from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class AuditLogBase(BaseModel):
    timestamp: str
    user_id: str
    action: str
    resource: str
    source_ip: str
    status: str

class AuditLogCreate(AuditLogBase):
    pass

class AuditLogOut(AuditLogBase):
    id: int
    upload_batch_id: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class PreprocessingResponse(BaseModel):
    batch_id: str
    total_records: int
    valid_records: int
    removed_duplicates: int
    extracted_features: List[str]
    user_count: int
    time_span: str

class ModelTrainRequest(BaseModel):
    model_type: str = Field(default="IsolationForest", description="'IsolationForest' or 'LSTM'")
    contamination: float = Field(default=0.1, description="Expected proportion of outliers")
    sequence_length: int = Field(default=5, description="Sequence window size for LSTM")
    epochs: int = Field(default=10, description="Training epochs for LSTM")

class ModelStatusOut(BaseModel):
    model_name: str
    model_type: str
    status: str
    trained_at: Optional[datetime] = None
    dataset_size: int
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    roc_auc: Optional[float] = None
    training_time_seconds: float

class DetectionResultOut(BaseModel):
    id: int
    log_id: Optional[int] = None
    user_id: str
    timestamp: str
    action: str
    resource: str
    source_ip: str
    status: str
    anomaly_score: float
    risk_level: str
    model_used: str
    flag_reason: str
    recommended_action: str

    class Config:
        from_attributes = True

class DetectionRunRequest(BaseModel):
    model_type: str = "IsolationForest"
    threshold: float = 0.65

class FaasEventBase(BaseModel):
    function_name: str
    function_id: str
    user_id: str
    request_id: str
    event_type: str
    execution_duration_ms: float
    permission: str
    resource: str
    timestamp: str
    status: str

class FaasEventOut(FaasEventBase):
    id: int
    is_anomalous: bool
    anomaly_reason: Optional[str] = None
    is_simulated: bool

    class Config:
        from_attributes = True

class PolicyOption(BaseModel):
    policy_name: str
    security_benefit: str
    estimated_cost_usd: float
    performance_overhead_pct: float
    score: float

class PolicyRecommendationOut(BaseModel):
    id: int
    detection_id: Optional[int] = None
    user_id: str
    current_risk_score: float
    recommended_policy: str
    security_benefit: str
    estimated_cost_usd: float
    performance_overhead_pct: float
    reason: str
    status: str
    decided_at: Optional[datetime] = None
    candidate_options: Optional[List[PolicyOption]] = None

    class Config:
        from_attributes = True

class PolicyDecisionRequest(BaseModel):
    decision: str = Field(..., description="'Approved' or 'Rejected'")
    notes: Optional[str] = None

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str
    related_user_id: str
    related_event_ids: Optional[str] = ""

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    assigned_to: Optional[str] = None

class InvestigationNoteCreate(BaseModel):
    note: str
    author: Optional[str] = "SOC Analyst"

class InvestigationNoteOut(BaseModel):
    id: int
    author: str
    note: str
    created_at: datetime

    class Config:
        from_attributes = True

class IncidentOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    assigned_to: str
    related_user_id: str
    related_event_ids: str
    created_at: datetime
    updated_at: datetime
    notes: List[InvestigationNoteOut] = []

    class Config:
        from_attributes = True

class OpenStackConfig(BaseModel):
    auth_url: str = "http://openstack.testbed.local:5000/v3"
    username: str = "admin"
    password: str = "********"
    project_name: str = "demo"
    user_domain_name: str = "Default"
    project_domain_name: str = "Default"

class OpenStackTestResponse(BaseModel):
    connected: bool
    mode: str
    status_message: str
    discovered_endpoints: List[str]
    latency_ms: float
