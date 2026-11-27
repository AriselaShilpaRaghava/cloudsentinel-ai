export type UserRole = 'Admin' | 'Security Analyst' | 'Viewer';

export type CloudProvider =
  | 'AWS CloudTrail'
  | 'AWS Lambda'
  | 'AWS IAM'
  | 'OpenStack Keystone'
  | 'OpenStack Nova'
  | 'CERT Mapped';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export type IncidentStatus = 'Open' | 'Investigating' | 'Resolved';

export type ApprovalStatus = 'Pending Approval' | 'Approved' | 'Rejected';

export interface AuthUser {
  user_id: string;
  username: string;
  full_name: string;
  email: string;
  role: UserRole;
  department: string;
  last_login: string;
  is_active: boolean;
}

export interface NormalizedAuditEvent {
  event_id: string;
  provider: CloudProvider;
  event_time: string;
  cloud_user_id: string;
  action: string;
  resource: string;
  source_ip: string;
  status: 'Success' | 'Failed' | 'Denied';
  raw_event: Record<string, unknown>;
  is_simulated: boolean;
  dataset_source: string;
  ground_truth_label?: 0 | 1;
}

export interface RiskFactorBreakdown {
  anomaly_contribution: number;
  privilege_contribution: number;
  resource_contribution: number;
  action_contribution: number;
  frequency_contribution: number;
  evidence_contribution: number;
}

export interface UserBehaviorProfile {
  user_id: string;
  display_name: string;
  department: string;
  privilege_level: 'Standard' | 'Elevated' | 'Admin' | 'Service Account';
  normal_hours: string;
  baseline_login_freq: number;
  observed_login_freq: number;
  avg_daily_api_calls: number;
  observed_api_calls: number;
  known_ips: string[];
  observed_ips: string[];
  active_status: 'Active' | 'Dormant-Reactivated';
  current_risk_score: number;
  risk_level: RiskLevel;
  anomaly_count: number;
  factor_breakdown: RiskFactorBreakdown;
  hourly_activity: number[];
  recent_actions: Array<{
    event_id: string;
    event_time: string;
    action: string;
    resource: string;
    source_ip: string;
    status: string;
    is_anomalous: boolean;
  }>;
}

export interface ThreatPrediction {
  prediction_id: string;
  event_id: string;
  cloud_user_id: string;
  provider: CloudProvider;
  scenario: string;
  timestamp: string;
  anomaly_score: number; // 0..1
  prediction_confidence: number; // 0..1
  risk_score: number; // 0..100
  risk_level: RiskLevel;
  investigation_status: 'High-Confidence Alert' | 'Requires Additional Investigation' | 'Normal Baseline';
  data_quality_score: number; // 0..1
  model_version: string;
  execution_mode: string;
  explanation: string;
  evidence_events: string[];
  recommended_steps: string[];
  factor_contributions: RiskFactorBreakdown;
}

export interface SecurityIncident {
  incident_id: string;
  title: string;
  severity: RiskLevel;
  status: IncidentStatus;
  affected_user: string;
  provider: CloudProvider;
  prediction_id: string;
  scenario: string;
  anomaly_score: number;
  risk_score: number;
  created_at: string;
  updated_at: string;
  summary: string;
  evidence_events: NormalizedAuditEvent[];
  recommended_actions: string[];
  analyst_notes: Array<{
    note_id: string;
    author: string;
    timestamp: string;
    content: string;
  }>;
  assigned_to: string;
}

export interface PolicyRecommendation {
  policy_id: string;
  target_user_id: string;
  target_resource: string;
  category: 'Least Privilege' | 'MFA Enforcement' | 'Temporary Restriction' | 'FaaS Rate Limit' | 'Session Hardening';
  title: string;
  description: string;
  supporting_evidence: string[];
  security_improvement_pct: number;
  residual_risk_before: number;
  residual_risk_after: number;
  operational_cost_before_usd: number;
  operational_cost_after_usd: number;
  performance_overhead_pct: number;
  monitoring_overhead_pct: number;
  optimizer_score: number;
  approval_status: ApprovalStatus;
  approved_by?: string;
  approved_at?: string;
  requires_admin_approval: boolean;
}

export interface RiskEngineWeights {
  w_anomaly: number;
  w_privilege: number;
  w_resource: number;
  w_action: number;
  w_frequency: number;
  w_evidence: number;
  confidence_threshold: number;
}

export interface CostOptimizerWeights {
  w_security_gain: number;
  w_operational_cost: number;
  w_performance_overhead: number;
  w_monitoring_overhead: number;
  max_budget_usd: number;
  max_latency_overhead_pct: number;
}

export interface DatasetRecord {
  dataset_id: string;
  name: string;
  source_type: 'CSV' | 'JSON';
  provenance: string;
  is_cert_mapped: boolean;
  total_rows: number;
  valid_rows: number;
  missing_value_count: number;
  duplicate_count: number;
  original_records_count: number;
  adapted_faas_count: number;
  split_ratio: { train: number; val: number; test: number };
  preprocessed: boolean;
  features_extracted: string[];
  created_at: string;
  sample_preview: NormalizedAuditEvent[];
}

export interface MLExperimentResult {
  experiment_id: string;
  model_type: 'Isolation Forest' | 'LSTM Sequence' | 'Transformer (Planned)';
  model_version: string;
  dataset_id: string;
  dataset_name: string;
  execution_mode: string;
  trained_at: string;
  train_size: number;
  val_size: number;
  test_size: number;
  features_used: string[];
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    false_positive_rate: number;
    roc_auc: number;
  };
  confusion_matrix: {
    tp: number;
    fp: number;
    tn: number;
    fn: number;
  };
  roc_curve: Array<{ fpr: number; tpr: number; threshold: number }>;
  pr_curve: Array<{ recall: number; precision: number; threshold: number }>;
  system_metrics: {
    latency_ms: number;
    cpu_pct: number;
    memory_mb: number;
    estimated_monthly_cost_usd: number;
  };
}

export interface CloudIntegrationConfig {
  integration_id: string;
  provider: 'AWS' | 'OpenStack';
  service_name: string;
  status: 'Not Configured' | 'Validation Failed' | 'Read-Only Verified';
  auth_mode: string;
  permissions_scope: 'Read-Only';
  endpoint_or_region: string;
  role_or_project: string;
  last_tested: string | null;
  validation_message: string;
  events_ingested: number;
}

export interface LambdaFunctionMetric {
  function_name: string;
  runtime: string;
  region: string;
  invocations_24h: number;
  baseline_invocations: number;
  error_rate_pct: number;
  avg_duration_ms: number;
  memory_mb: number;
  last_caller: string;
  anomaly_flag: boolean;
  last_invoked: string;
}

export interface AuditTrailEntry {
  trail_id: string;
  timestamp: string;
  actor: string;
  actor_role: UserRole;
  action_type: string;
  target: string;
  details: string;
}

export interface DashboardSummary {
  total_cloud_events: number;
  suspicious_activities: number;
  critical_security_alerts: number;
  high_risk_users: number;
  active_incidents: number;
  pending_policy_approvals: number;
  ml_service_connected: boolean;
  ml_service_label: string;
  cloud_resource_overview: {
    aws_cloudtrail_events: number;
    aws_lambda_functions: number;
    aws_iam_identities: number;
    openstack_keystone_tokens: number;
    openstack_nova_instances: number;
  };
  threat_timeline: Array<{
    bucket: string;
    total_events: number;
    suspicious_events: number;
    critical_alerts: number;
  }>;
  risk_distribution: Array<{
    level: RiskLevel;
    count: number;
  }>;
  cost_overview: {
    current_monthly_cost_usd: number;
    recommended_monthly_cost_usd: number;
    current_residual_risk: number;
    recommended_residual_risk: number;
    avg_performance_overhead_pct: number;
  };
  recent_events: NormalizedAuditEvent[];
}
