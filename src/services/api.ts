import type {
  AuditTrailEntry,
  AuthUser,
  CloudIntegrationConfig,
  CostOptimizerWeights,
  DashboardSummary,
  DatasetRecord,
  IncidentStatus,
  LambdaFunctionMetric,
  MLExperimentResult,
  NormalizedAuditEvent,
  PolicyRecommendation,
  RiskEngineWeights,
  SecurityIncident,
  ThreatPrediction,
  UserBehaviorProfile,
  UserRole,
} from '../types/security';

let currentSessionUser: AuthUser | null = null;

export function setApiSessionUser(user: AuthUser | null): void {
  currentSessionUser = user;
}

async function apiFetch<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (!headers.has('Content-Type') && options.body) {
    headers.set('Content-Type', 'application/json');
  }
  if (currentSessionUser) {
    headers.set('X-CloudSentinel-UserId', currentSessionUser.user_id);
    headers.set('X-CloudSentinel-Role', currentSessionUser.role);
  }

  const res = await fetch(url, { ...options, headers });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!res.ok) {
    throw new Error(String(data.error || `Request failed with status ${res.status}`));
  }
  return data as T;
}

export const api = {
  getUsersDirectory: () => apiFetch<{ users: AuthUser[] }>('/api/auth/users-directory'),

  login: (payload: { email?: string; user_id?: string }) =>
    apiFetch<{ user: AuthUser; token: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getDashboardSummary: () => apiFetch<DashboardSummary>('/api/dashboard/summary'),

  getEvents: (params: {
    provider?: string;
    status?: string;
    search?: string;
    page?: number;
    pageSize?: number;
  }) => {
    const qs = new URLSearchParams();
    if (params.provider) qs.set('provider', params.provider);
    if (params.status) qs.set('status', params.status);
    if (params.search) qs.set('search', params.search);
    if (params.page) qs.set('page', String(params.page));
    if (params.pageSize) qs.set('pageSize', String(params.pageSize));
    return apiFetch<{
      items: NormalizedAuditEvent[];
      total: number;
      page: number;
      pageSize: number;
      totalPages: number;
    }>(`/api/events?${qs.toString()}`);
  },

  uploadAuditLogs: (payload: { content: string; format: 'CSV' | 'JSON'; source_name: string }) =>
    apiFetch<{
      message: string;
      summary: {
        total_rows: number;
        valid_rows: number;
        missing_value_count: number;
        duplicate_count: number;
        adapted_faas_count: number;
        original_records_count: number;
        errors: string[];
      };
    }>('/api/events/upload', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getDatasets: () => apiFetch<{ datasets: DatasetRecord[] }>('/api/datasets'),

  uploadDataset: (payload: {
    name: string;
    content: string;
    format: 'CSV' | 'JSON';
    provenance: string;
    is_cert_mapped: boolean;
    split_ratio: { train: number; val: number; test: number };
  }) =>
    apiFetch<{ dataset: DatasetRecord; merged_events_count: number }>('/api/datasets/upload', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getUbaProfiles: () => apiFetch<{ profiles: UserBehaviorProfile[] }>('/api/uba/users'),

  getPredictions: () =>
    apiFetch<{
      ml_service_connected: boolean;
      ml_service_label: string;
      predictions: ThreatPrediction[];
    }>('/api/detection/predictions'),

  runDetection: (event_ids?: string[]) =>
    apiFetch<{
      ml_service_connected: boolean;
      ml_service_label: string;
      predictions: ThreatPrediction[];
    }>('/api/detection/run', {
      method: 'POST',
      body: JSON.stringify({ event_ids }),
    }),

  getIncidents: () => apiFetch<{ incidents: SecurityIncident[] }>('/api/incidents'),

  createIncidentFromPrediction: (prediction_id: string) =>
    apiFetch<{ incident: SecurityIncident; already_exists?: boolean }>(
      '/api/incidents/from-prediction',
      {
        method: 'POST',
        body: JSON.stringify({ prediction_id }),
      },
    ),

  updateIncident: (id: string, payload: { status?: IncidentStatus; note?: string; assigned_to?: string }) =>
    apiFetch<{ incident: SecurityIncident }>(`/api/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  getPolicies: () =>
    apiFetch<{
      policies: PolicyRecommendation[];
      costWeights: CostOptimizerWeights;
      riskWeights: RiskEngineWeights;
    }>('/api/policies'),

  approvePolicy: (id: string) =>
    apiFetch<{ policy: PolicyRecommendation }>(`/api/policies/${id}/approve`, {
      method: 'POST',
    }),

  rejectPolicy: (id: string) =>
    apiFetch<{ policy: PolicyRecommendation }>(`/api/policies/${id}/reject`, {
      method: 'POST',
    }),

  updateWeights: (payload: {
    riskWeights?: Partial<RiskEngineWeights>;
    costWeights?: Partial<CostOptimizerWeights>;
  }) =>
    apiFetch<{
      riskWeights: RiskEngineWeights;
      costWeights: CostOptimizerWeights;
      policies: PolicyRecommendation[];
    }>('/api/settings/weights', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  getIntegrations: () =>
    apiFetch<{
      integrations: CloudIntegrationConfig[];
      lambdaMetrics: LambdaFunctionMetric[];
    }>('/api/integrations'),

  testIntegration: (
    id: string,
    payload: { endpoint_or_region: string; role_or_project: string; credential_provided: boolean },
  ) =>
    apiFetch<{ integration: CloudIntegrationConfig }>(`/api/integrations/${id}/test`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getMlExperiments: () =>
    apiFetch<{
      ml_service_connected: boolean;
      ml_service_label: string;
      experiments: MLExperimentResult[];
    }>('/api/ml/experiments'),

  trainExperiment: (payload: {
    dataset_id: string;
    model_type: MLExperimentResult['model_type'];
    features_used: string[];
    split_ratio: { train: number; val: number; test: number };
  }) =>
    apiFetch<{ experiment: MLExperimentResult }>('/api/ml/train', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getUsersAndTrail: () =>
    apiFetch<{ users: AuthUser[]; auditTrail: AuditTrailEntry[] }>('/api/users'),

  createUser: (payload: { full_name: string; email: string; role: UserRole; department: string }) =>
    apiFetch<{ user: AuthUser }>('/api/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  updateUser: (id: string, payload: { role?: UserRole; is_active?: boolean }) =>
    apiFetch<{ user: AuthUser }>(`/api/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),
};
