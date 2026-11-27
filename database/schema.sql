-- CloudSentinel AI PostgreSQL Schema (v1)
-- Covers RBAC users, datasets, normalized multi-cloud audit events, UBA profiles,
-- threat predictions, incidents, adaptive policies, ML experiments, and audit trail.

CREATE TABLE IF NOT EXISTS users (
  user_id VARCHAR(64) PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  full_name VARCHAR(128) NOT NULL,
  email VARCHAR(160) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(32) NOT NULL CHECK (role IN ('Admin', 'Security Analyst', 'Viewer')),
  department VARCHAR(128) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS datasets (
  dataset_id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(160) NOT NULL,
  source_type VARCHAR(16) NOT NULL CHECK (source_type IN ('CSV', 'JSON')),
  provenance TEXT NOT NULL,
  is_cert_mapped BOOLEAN NOT NULL DEFAULT FALSE,
  total_rows INTEGER NOT NULL,
  valid_rows INTEGER NOT NULL,
  missing_value_count INTEGER NOT NULL DEFAULT 0,
  duplicate_count INTEGER NOT NULL DEFAULT 0,
  original_records_count INTEGER NOT NULL DEFAULT 0,
  adapted_faas_count INTEGER NOT NULL DEFAULT 0,
  split_ratio JSONB NOT NULL,
  preprocessed BOOLEAN NOT NULL DEFAULT FALSE,
  features_extracted JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
  event_id VARCHAR(96) PRIMARY KEY,
  dataset_id VARCHAR(64) REFERENCES datasets(dataset_id) ON DELETE SET NULL,
  provider VARCHAR(48) NOT NULL,
  event_time TIMESTAMPTZ NOT NULL,
  cloud_user_id VARCHAR(128) NOT NULL,
  action VARCHAR(128) NOT NULL,
  resource TEXT NOT NULL,
  source_ip INET NOT NULL,
  status VARCHAR(24) NOT NULL CHECK (status IN ('Success', 'Failed', 'Denied')),
  raw_event JSONB NOT NULL,
  is_simulated BOOLEAN NOT NULL DEFAULT FALSE,
  ground_truth_label SMALLINT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_user_time ON audit_events (cloud_user_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_provider ON audit_events (provider);

CREATE TABLE IF NOT EXISTS threat_predictions (
  prediction_id VARCHAR(96) PRIMARY KEY,
  event_id VARCHAR(96) NOT NULL REFERENCES audit_events(event_id) ON DELETE CASCADE,
  cloud_user_id VARCHAR(128) NOT NULL,
  scenario VARCHAR(160) NOT NULL,
  anomaly_score NUMERIC(5, 4) NOT NULL,
  prediction_confidence NUMERIC(5, 4) NOT NULL,
  risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  risk_level VARCHAR(16) NOT NULL CHECK (risk_level IN ('Low', 'Medium', 'High', 'Critical')),
  investigation_status VARCHAR(48) NOT NULL,
  data_quality_score NUMERIC(5, 4) NOT NULL,
  model_version VARCHAR(64) NOT NULL,
  explanation TEXT NOT NULL,
  factor_contributions JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id VARCHAR(64) PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(16) NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
  status VARCHAR(24) NOT NULL CHECK (status IN ('Open', 'Investigating', 'Resolved')),
  affected_user VARCHAR(128) NOT NULL,
  provider VARCHAR(48) NOT NULL,
  prediction_id VARCHAR(96) REFERENCES threat_predictions(prediction_id),
  summary TEXT NOT NULL,
  recommended_actions JSONB NOT NULL,
  assigned_to VARCHAR(128),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_recommendations (
  policy_id VARCHAR(64) PRIMARY KEY,
  target_user_id VARCHAR(128) NOT NULL,
  target_resource TEXT NOT NULL,
  category VARCHAR(48) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  supporting_evidence JSONB NOT NULL,
  security_improvement_pct NUMERIC(6, 2) NOT NULL,
  residual_risk_before INTEGER NOT NULL,
  residual_risk_after INTEGER NOT NULL,
  operational_cost_before_usd NUMERIC(10, 2) NOT NULL,
  operational_cost_after_usd NUMERIC(10, 2) NOT NULL,
  performance_overhead_pct NUMERIC(5, 2) NOT NULL,
  monitoring_overhead_pct NUMERIC(5, 2) NOT NULL,
  optimizer_score NUMERIC(5, 4) NOT NULL,
  approval_status VARCHAR(32) NOT NULL DEFAULT 'Pending Approval',
  approved_by VARCHAR(64) REFERENCES users(user_id),
  approved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ml_experiments (
  experiment_id VARCHAR(64) PRIMARY KEY,
  dataset_id VARCHAR(64) NOT NULL REFERENCES datasets(dataset_id),
  model_type VARCHAR(48) NOT NULL,
  model_version VARCHAR(64) NOT NULL,
  execution_mode TEXT NOT NULL,
  train_size INTEGER NOT NULL,
  val_size INTEGER NOT NULL,
  test_size INTEGER NOT NULL,
  features_used JSONB NOT NULL,
  metrics JSONB NOT NULL,
  confusion_matrix JSONB NOT NULL,
  system_metrics JSONB NOT NULL,
  trained_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_trail (
  trail_id VARCHAR(64) PRIMARY KEY,
  actor_id VARCHAR(64) REFERENCES users(user_id),
  actor_role VARCHAR(32) NOT NULL,
  action_type VARCHAR(64) NOT NULL,
  target VARCHAR(128) NOT NULL,
  details TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
