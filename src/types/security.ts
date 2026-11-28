export type UserRole = 'Admin' | 'Security Analyst' | 'Viewer';

export type CloudProvider =
  | 'AWS CloudTrail'
  | 'AWS Lambda'
  | 'AWS IAM'
  | 'OpenStack Keystone'
  | 'OpenStack Nova'
  | 'OpenStack Neutron'
  | 'OpenStack Glance'
  | 'OpenStack Cinder'
  | 'OpenStack Audit'
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
  dataset_id?: string;
  provider: CloudProvider;
  event_time: string;
  cloud_user_id: string;
  identity_type?: string;
  action: string;
  resource: string;
  source_ip: string;
  status: 'Success' | 'Failed' | 'Denied';
  raw_event: Record<string, unknown>;
  is_simulated: boolean;
  dataset_source: string;
  source_origin?: 'real_openstack' | 'synthetic_fixture' | 'workspace_dataset';
  security_category?: string;
  ground_truth_label?: 0 | 1;
  attack_name?: string;
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

export type PolicyActionId =
  | 'monitor_and_alert'
  | 'require_additional_mfa'
  | 'temporarily_restrict_permissions'
  | 'revoke_suspicious_session'
  | 'isolate_account_and_escalate';

export interface OptimizerCandidateActionConfig {
  action_id: PolicyActionId;
  action_label: string;
  category:
    | 'Monitoring & Alerting'
    | 'MFA Enforcement'
    | 'Temporary Restriction'
    | 'Session Hardening'
    | 'Least Privilege';
  base_effectiveness: number;
  estimated_enforcement_cost_usd: number;
  base_operational_impact: number;
  estimated_response_latency_sec: number;
  fp_friction_factor: number;
  description: string;
}

export interface OptimizerConstraints {
  max_enforcement_cost_usd: number;
  max_operational_impact: number;
  max_response_latency_sec: number;
}

export interface OptimizerObjectiveWeights {
  w_risk_reduction: number;
  w_enforcement_cost: number;
  w_operational_impact: number;
  w_response_latency: number;
  w_fp_friction: number;
}

export interface OptimizerScenarioInput {
  risk_score: number;
  confidence?: number;
  false_positive_likelihood?: number;
  identity_type?: 'IAMUser' | 'AssumedRole' | 'AWSService' | 'AWSAccount' | 'ServicePrincipal' | 'Unknown';
  asset_criticality?: 'Low' | 'Medium' | 'High' | 'Critical';
  target_user_id?: string;
  target_resource?: string;
  scenario_name?: string;
  scenario_source?: 'application_prediction' | 'incident' | 'manual_simulation';
  prediction_id?: string;
  incident_id?: string;
  constraints?: Partial<OptimizerConstraints>;
  weights?: Partial<OptimizerObjectiveWeights>;
}

export interface OptimizerInputValidationResult {
  valid: boolean;
  errors: string[];
  normalized?: OptimizerScenarioInput;
}

export interface OptimizerActionEvaluation {
  action_id: PolicyActionId;
  action_label: string;
  category: OptimizerCandidateActionConfig['category'];
  description: string;
  expected_residual_risk: number;
  risk_reduction: number;
  risk_reduction_pct: number;
  estimated_enforcement_cost_usd: number;
  operational_impact: number;
  response_latency_sec: number;
  false_positive_friction: number;
  utility_score: number;
  feasible: boolean;
  constraint_violations: string[];
}

export interface CostAwareOptimizationResult {
  optimization_id: string;
  evaluated_at: string;
  data_origin: 'application_data' | 'simulated_scenario';
  data_origin_label: string;
  is_estimated_cost: boolean;
  auto_executed: boolean;
  execution_notice: string;
  cost_assumptions: string;
  input: OptimizerScenarioInput;
  effective_risk_score: number;
  feasible_action_found: boolean;
  constraint_status: string;
  recommended_action: OptimizerActionEvaluation;
  static_baseline: OptimizerActionEvaluation;
  comparison_summary: {
    same_as_static_baseline: boolean;
    cost_delta_vs_static_usd: number;
    impact_delta_vs_static: number;
    utility_delta_vs_static: number;
    static_baseline_feasible: boolean;
  };
  explanation: string;
  approval_status: ApprovalStatus | 'Proposal Only (Not Submitted)';
  linked_policy_id?: string;
  candidates: OptimizerActionEvaluation[];
}

export interface PolicyOptimizerOverviewResponse {
  methodology_summary: string;
  cost_assumptions: string;
  candidate_catalog: OptimizerCandidateActionConfig[];
  default_constraints: OptimizerConstraints;
  default_weights: OptimizerObjectiveWeights;
  application_evaluations: CostAwareOptimizationResult[];
  history: CostAwareOptimizationResult[];
}

export type OpenStackServiceName =
  | 'keystone'
  | 'nova'
  | 'neutron'
  | 'glance'
  | 'cinder'
  | 'unknown';

export type OpenStackSecurityCategory =
  | 'Authentication Failures'
  | 'Privilege and Role Changes'
  | 'Instance Creation/Deletion'
  | 'Security Group and Network Changes'
  | 'Image and Volume Access'
  | 'Unusual Administrative Operations'
  | 'Routine Operational Activity';

export type OpenStackConnectivityStatus = 'Connected' | 'Not Connected' | 'Fixture Mode';

export interface OpenStackIngestResult {
  dataset_id: string;
  source_mode: 'real' | 'fixture';
  source_name: string;
  total_received: number;
  imported_count: number;
  normalized_count: number;
  rejected_count: number;
  skipped_count: number;
  duplicate_count: number;
  missing_field_count: number;
  services_detected: OpenStackServiceName[];
  rejection_reasons: string[];
  skip_reasons: string[];
  errors: string[];
}

export interface OpenStackTelemetryOverviewResponse {
  connectivity_status: OpenStackConnectivityStatus;
  status_reason: string;
  env_status: {
    auth_url_configured: boolean;
    credentials_configured: boolean;
    endpoint_hint: string | null;
    auth_mode: string;
  };
  event_counts: {
    total_events: number;
    real_events: number;
    fixture_events: number;
    failed_or_denied_events: number;
    suspicious_events: number;
  };
  services_detected: Array<{
    service: OpenStackServiceName;
    provider: CloudProvider;
    event_count: number;
    real_count: number;
    fixture_count: number;
  }>;
  category_breakdown: Array<{
    category: string;
    count: number;
  }>;
  user_project_activity: Array<{
    cloud_user_id: string;
    project_id: string;
    event_count: number;
    failed_or_denied: number;
    max_risk_score: number;
    source_origins: string[];
  }>;
  suspicious_events: Array<{
    event_id: string;
    event_time: string;
    provider: CloudProvider;
    cloud_user_id: string;
    project_id: string;
    action: string;
    resource: string;
    status: string;
    risk_score: number;
    risk_level: RiskLevel;
    scenario: string;
    explanation: string;
    source_origin: string;
    is_simulated: boolean;
  }>;
  latest_events: Array<{
    event_id: string;
    event_time: string;
    provider: CloudProvider;
    service: string;
    cloud_user_id: string;
    project_id: string;
    action: string;
    resource: string;
    source_ip: string;
    region: string;
    request_id: string;
    status: string;
    security_category: string;
    source_origin: string;
    is_simulated: boolean;
  }>;
  prerequisites: string[];
}

export interface DatasetRecord {
  dataset_id: string;
  name: string;
  source_type: 'CSV' | 'JSON';
  provenance: string;
  dataset_role?: 'training' | 'testing' | 'evaluation' | 'audit';
  file_path?: string;
  is_cert_mapped: boolean;
  total_rows: number;
  valid_rows: number;
  normalized_rows?: number;
  imported_rows?: number;
  rejected_rows?: number;
  skipped_rows?: number;
  missing_value_count: number;
  duplicate_count: number;
  benign_count?: number;
  attack_count?: number;
  unlabeled_count?: number;
  rejection_reasons?: string[];
  skip_reasons?: string[];
  original_records_count: number;
  adapted_faas_count: number;
  split_ratio: { train: number; val: number; test: number };
  preprocessed: boolean;
  features_extracted: string[];
  created_at: string;
  sample_preview: NormalizedAuditEvent[];
}

export interface IngestionSummary {
  total_rows: number;
  valid_rows: number;
  normalized_rows: number;
  imported_rows: number;
  rejected_rows: number;
  skipped_rows: number;
  missing_value_count: number;
  duplicate_count: number;
  already_exists_count: number;
  adapted_faas_count: number;
  original_records_count: number;
  benign_count: number;
  attack_count: number;
  unlabeled_count: number;
  raw_benign_count: number;
  raw_attack_count: number;
  raw_unlabeled_count: number;
  rejection_reasons: string[];
  skip_reasons: string[];
  errors: string[];
}

export interface LocalDatasetFileInfo {
  filename: string;
  size_bytes: number;
  format: 'CSV' | 'JSON';
  suggested_role: 'training' | 'testing' | 'audit';
  already_registered: boolean;
}

export interface MLExperimentMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  roc_auc: number;
  pr_auc?: number;
}

export interface MLConfusionMatrix {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export interface MLExperimentResult {
  experiment_id: string;
  model_type: 'Isolation Forest' | 'LSTM Sequence' | 'Transformer (Planned)';
  model_version: string;
  model_artifact?: string | null;
  threshold?: number;
  dataset_id: string;
  dataset_name: string;
  execution_mode: string;
  is_simulated?: boolean;
  has_ground_truth?: boolean;
  trained_at: string;
  train_size: number;
  val_size: number;
  test_size: number;
  training_time_ms?: number | null;
  inference_latency_ms?: number;
  features_used: string[];
  metrics: MLExperimentMetrics;
  confusion_matrix: MLConfusionMatrix;
  sequence_config?: {
    window_size: 5 | 10 | 16;
    identity_grouping: string;
    train_windows: number;
    benign_train_windows: number;
    val_windows: number;
    test_windows: number;
    eligible_test_events: number;
    excluded_test_events: number;
    validation_calibration_note?: string;
    epochs?: number;
    hidden_dim?: number;
    final_train_loss?: number | null;
  };
  baseline_comparison?: {
    model_type: string;
    model_version: string;
    model_file?: string;
    threshold: number;
    has_ground_truth: boolean;
    eligible_test_events: number;
    inference_latency_ms: number;
    metrics: MLExperimentMetrics;
    confusion_matrix: MLConfusionMatrix;
  } | null;
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

export interface CloudTrailFaasFunctionTelemetry {
  function_name: string;
  function_arn: string | null;
  region: string;
  telemetry_source: 'cloudtrail';
  invoke_count: number;
  assume_role_count: number;
  in_scope_downstream_count: number;
  control_plane_count: number;
  total_events: number;
  peak_burst_1m: number;
  peak_burst_5m: number;
  error_count: number;
  access_denied_count: number;
  error_rate_pct: number;
  downstream_services: string[];
  downstream_service_breadth: number;
  sensitive_action_count: number;
  sensitive_actions: string[];
  invocation_types: string[];
  last_caller: string;
  first_seen: string;
  last_invoked: string;
  anomaly_flag: boolean;
  avg_duration_ms: null;
  memory_mb: null;
  cold_start_rate: null;
  missing_telemetry_fields: string[];
  telemetry_note: string;
}

export interface CloudTrailFaasSummary {
  total_events_scanned: number;
  faas_events_detected: number;
  invoke_events: number;
  assume_role_events: number;
  in_scope_downstream_events: number;
  control_plane_events: number;
  unique_functions: number;
  total_errors: number;
  total_access_denied: number;
  processing_ms: number;
}

export interface CloudTrailFaasTelemetryResponse {
  telemetry_available: boolean;
  ml_service_connected: boolean;
  telemetry_source: 'cloudtrail' | 'unavailable';
  dataset_id: string;
  dataset_name: string;
  available_datasets: Array<{
    dataset_id: string;
    name: string;
    total_events: number;
    faas_related_hint: number;
  }>;
  features_extracted: string[];
  summary: CloudTrailFaasSummary | null;
  functions: CloudTrailFaasFunctionTelemetry[];
  unavailable_reason?: string;
  missing_telemetry_notice: string;
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
