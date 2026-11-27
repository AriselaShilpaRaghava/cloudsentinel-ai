export interface AuditLog {
  id: number;
  timestamp: string;
  user_id: string;
  action: string;
  resource: string;
  source_ip: string;
  status: string;
  upload_batch_id?: string;
  created_at?: string;
}

export interface DetectionResult {
  id: number;
  log_id?: number;
  user_id: string;
  timestamp: string;
  action: string;
  resource: string;
  source_ip: string;
  status: string;
  anomaly_score: number;
  risk_level: 'Normal' | 'Medium Risk' | 'High Risk';
  model_used: string;
  flag_reason: string;
  recommended_action: string;
  created_at?: string;
}

export interface FaasEvent {
  id: number;
  function_name: string;
  function_id: string;
  user_id: string;
  request_id: string;
  event_type: string;
  execution_duration_ms: number;
  permission: string;
  resource: string;
  timestamp: string;
  status: string;
  is_anomalous: boolean;
  anomaly_reason?: string;
  is_simulated: boolean;
}

export interface CandidatePolicy {
  policy_name: string;
  security_benefit: string;
  security_benefit_score: number;
  estimated_cost_usd: number;
  performance_overhead_pct: number;
  score: number;
}

export interface PolicyRecommendation {
  id: number;
  detection_id?: number;
  user_id: string;
  current_risk_score: number;
  recommended_policy: string;
  security_benefit: string;
  estimated_cost_usd: number;
  performance_overhead_pct: number;
  reason: string;
  status: 'Pending' | 'Approved' | 'Rejected';
  decided_at?: string;
  decision_notes?: string;
  candidate_options?: CandidatePolicy[];
}

export interface InvestigationNote {
  id: number;
  author: string;
  note: string;
  created_at: string;
}

export interface Incident {
  id: number;
  title: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Open' | 'Investigating' | 'Resolved' | 'Closed';
  assigned_to: string;
  related_user_id: string;
  related_event_ids: string;
  created_at: string;
  updated_at: string;
  notes: InvestigationNote[];
}

export interface DashboardSummary {
  total_audit_logs: number;
  monitored_users: number;
  normal_activities: number;
  suspicious_activities: number;
  high_risk_events: number;
  active_incidents: number;
  faas_invocations: number;
  anomalous_faas: number;
}

export interface DashboardData {
  summary: DashboardSummary;
  risk_distribution: Array<{ name: string; value: number; color: string }>;
  model_status: {
    active_baseline: string;
    sequence_model: string;
    isolation_forest_trained: boolean;
    lstm_trained: boolean;
  };
  recent_suspicious: DetectionResult[];
}

export interface PreprocessingStatus {
  batch_id: string;
  total_records: number;
  valid_records: number;
  removed_duplicates: number;
  extracted_features: string[];
  user_count: number;
  time_span: string;
}

export interface UserRiskProfile {
  user_id: string;
  total_events: number;
  high_risk: number;
  medium_risk: number;
  normal: number;
  max_score: number;
  avg_score: number;
}

export interface OpenStackStatus {
  connected: boolean;
  mode: string;
  status_message: string;
  discovered_endpoints: string[];
  latency_ms: number;
}
