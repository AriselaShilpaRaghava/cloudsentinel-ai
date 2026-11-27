import express from 'express';
import { createServer as createViteServer } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import type {
  AuditTrailEntry,
  AuthUser,
  CloudIntegrationConfig,
  CostOptimizerWeights,
  DatasetRecord,
  IncidentStatus,
  LambdaFunctionMetric,
  MLExperimentResult,
  NormalizedAuditEvent,
  PolicyRecommendation,
  RiskEngineWeights,
  SecurityIncident,
  ThreatPrediction,
  UserRole,
} from './src/types/security.ts';
import {
  DEFAULT_AUTH_USERS,
  DEFAULT_COST_WEIGHTS,
  DEFAULT_INTEGRATIONS,
  DEFAULT_RISK_WEIGHTS,
  SEEDED_DATASETS,
  SEEDED_EVENTS,
  SEEDED_INCIDENTS,
  SEEDED_LAMBDA_METRICS,
  SEEDED_POLICIES,
} from './src/server/seedData.ts';
import {
  computeUserBehaviorProfiles,
  evaluateCostOptimizer,
  evaluateEvent,
  runRealExperimentOnDataset,
} from './src/server/mlEngine.ts';
import type { IsolationForestPredictionSignal } from './src/server/mlEngine.ts';
import { validateAndNormalizeUpload } from './src/server/eventNormalizer.ts';

dotenv.config();

interface AppState {
  users: AuthUser[];
  events: NormalizedAuditEvent[];
  datasets: DatasetRecord[];
  incidents: SecurityIncident[];
  policies: PolicyRecommendation[];
  integrations: CloudIntegrationConfig[];
  lambdaMetrics: LambdaFunctionMetric[];
  experiments: MLExperimentResult[];
  riskWeights: RiskEngineWeights;
  costWeights: CostOptimizerWeights;
  auditTrail: AuditTrailEntry[];
}

const STATE_FILE = '/tmp/cloudsentinel_state_v1.json';
const ML_FEATURES = [
  'is_faas',
  'failed_event_flag',
  'sensitive_action_flag',
  'sensitive_resource_flag',
  'off_hours_flag',
  'ip_change_flag',
  'time_gap_minutes',
  'time_gap_missing_flag',
];

interface MlServicePrediction extends IsolationForestPredictionSignal {
  event_id: string;
  raw_anomaly_score: number;
}

interface PredictionBatch {
  ml_service_connected: boolean;
  ml_service_label: string;
  predictions: ThreatPrediction[];
}

function createInitialState(): AppState {
  const initialEvents = [...SEEDED_EVENTS];
  const initialDatasets = [...SEEDED_DATASETS];
  const riskWeights = { ...DEFAULT_RISK_WEIGHTS };
  const costWeights = { ...DEFAULT_COST_WEIGHTS };
  const mlModeLabel = 'Simulated in-process evaluation (ML service health not yet checked)';

  // Run 1 genuine initial baseline experiment on the seeded CERT-cloud dataset so metrics are calculated from real split evaluation
  const initialExp = runRealExperimentOnDataset(
    initialDatasets[0],
    initialEvents,
    'Isolation Forest',
    initialDatasets[0].features_extracted,
    initialDatasets[0].split_ratio,
    riskWeights,
    mlModeLabel,
  );

  return {
    users: [...DEFAULT_AUTH_USERS],
    events: initialEvents,
    datasets: initialDatasets,
    incidents: [...SEEDED_INCIDENTS],
    policies: evaluateCostOptimizer([...SEEDED_POLICIES], costWeights),
    integrations: [...DEFAULT_INTEGRATIONS],
    lambdaMetrics: [...SEEDED_LAMBDA_METRICS],
    experiments: [initialExp],
    riskWeights,
    costWeights,
    auditTrail: [
      {
        trail_id: 'TRL-1001',
        timestamp: '2026-11-15T07:45:00Z',
        actor: 'Shilpa Raghava',
        actor_role: 'Admin',
        action_type: 'POLICY_APPROVED',
        target: 'POL-104',
        details: 'Approved off-hours OpenStack Nova destructive operation restriction for r.patel@corp.internal.',
      },
      {
        trail_id: 'TRL-1002',
        timestamp: '2026-11-15T08:05:00Z',
        actor: 'Arjun Verma',
        actor_role: 'Security Analyst',
        action_type: 'INCIDENT_TRIAGE',
        target: 'INC-2026-041',
        details: 'Escalated m.chen privilege escalation & bulk S3 download to Investigating.',
      },
    ],
  };
}

function loadState(): AppState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = fs.readFileSync(STATE_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as AppState;
      if (parsed && Array.isArray(parsed.events) && Array.isArray(parsed.users)) {
        return parsed;
      }
    }
  } catch {
    // Fallback to clean initial state
  }
  const init = createInitialState();
  saveState(init);
  return init;
}

function saveState(state: AppState): void {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf-8');
  } catch {
    // Non-fatal in ephemeral containers
  }
}

let state: AppState = loadState();

function mlServiceUrl(): string | null {
  const url = process.env.ML_SERVICE_URL?.trim().replace(/\/+$/, '');
  return url || null;
}

async function fetchMlService(url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function fallbackBatch(events: NormalizedAuditEvent[], label: string): PredictionBatch {
  return {
    ml_service_connected: false,
    ml_service_label: label,
    predictions: events
      .map((event) => evaluateEvent(event, state.events, state.riskWeights, label))
      .sort((a, b) => b.risk_score - a.risk_score),
  };
}

async function checkMlServiceHealth(): Promise<{ connected: boolean; label: string }> {
  const baseUrl = mlServiceUrl();
  if (!baseUrl) {
    return { connected: false, label: 'Simulated Baseline Scorer (Python ML Service not configured)' };
  }

  let response: Response;
  try {
    response = await fetchMlService(`${baseUrl}/health`);
  } catch (error) {
    console.warn('ML service health check failed.', error);
    return { connected: false, label: 'Simulated Baseline Scorer (Python ML Service unavailable)' };
  }

  if (!response.ok) {
    return {
      connected: false,
      label: `Simulated Baseline Scorer (Python ML Service health returned HTTP ${response.status})`,
    };
  }

  let health: unknown;
  try {
    health = await response.json();
  } catch (error) {
    console.warn('ML service health response was not valid JSON.', error);
    return { connected: false, label: 'Simulated Baseline Scorer (Python ML Service health response invalid)' };
  }

  if (
    !health ||
    typeof health !== 'object' ||
    !('status' in health) ||
    health.status !== 'ok' ||
    !('model_loaded' in health) ||
    health.model_loaded !== true ||
    !('features' in health) ||
    !Array.isArray(health.features) ||
    health.features.length !== ML_FEATURES.length ||
    !ML_FEATURES.every((feature, index) => health.features[index] === feature)
  ) {
    return {
      connected: false,
      label: 'Simulated Baseline Scorer (Python ML Service model or feature contract unavailable)',
    };
  }

  return { connected: true, label: 'Connected Python ML Service (saved Isolation Forest)' };
}

async function computeAllPredictions(events: NormalizedAuditEvent[] = state.events): Promise<PredictionBatch> {
  const mode = await checkMlServiceHealth();
  if (!mode.connected) {
    return fallbackBatch(events, mode.label);
  }

  const baseUrl = mlServiceUrl();
  if (!baseUrl) {
    return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service not configured)');
  }

  let response: Response;
  try {
    response = await fetchMlService(`${baseUrl}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ events, model_type: 'isolation_forest' }),
    });
  } catch (error) {
    console.warn('ML service prediction request failed.', error);
    return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service unavailable; prediction failed)');
  }

  if (!response.ok) {
    console.warn(`ML service rejected prediction request with HTTP ${response.status}.`);
    return fallbackBatch(
      events,
      `Simulated Baseline Scorer (Python ML Service rejected prediction request with HTTP ${response.status})`,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch (error) {
    console.warn('ML service prediction response was not valid JSON.', error);
    return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned an invalid response)');
  }

  if (
    !body ||
    typeof body !== 'object' ||
    !('predictions' in body) ||
    !Array.isArray(body.predictions)
  ) {
    console.warn('ML service prediction response did not contain a predictions array.');
    return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned an invalid response)');
  }

  const predictionsByEventId = new Map<string, MlServicePrediction>();
  for (const item of body.predictions) {
    if (
      !item ||
      typeof item !== 'object' ||
      !('event_id' in item) ||
      typeof item.event_id !== 'string' ||
      !('anomaly_score' in item) ||
      typeof item.anomaly_score !== 'number' ||
      !Number.isFinite(item.anomaly_score) ||
      item.anomaly_score < 0 ||
      item.anomaly_score > 1 ||
      !('raw_anomaly_score' in item) ||
      typeof item.raw_anomaly_score !== 'number' ||
      !Number.isFinite(item.raw_anomaly_score) ||
      !('anomaly_prediction' in item) ||
      (item.anomaly_prediction !== 'anomaly' && item.anomaly_prediction !== 'normal') ||
      !('model_version' in item) ||
      typeof item.model_version !== 'string' ||
      !item.model_version
    ) {
      console.warn('ML service returned a prediction with an invalid shape.');
      return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned an invalid prediction)');
    }

    if (predictionsByEventId.has(item.event_id)) {
      console.warn(`ML service returned duplicate prediction event_id '${item.event_id}'.`);
      return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned duplicate predictions)');
    }
    predictionsByEventId.set(item.event_id, item as MlServicePrediction);
  }

  if (
    predictionsByEventId.size !== events.length ||
    events.some((event) => !predictionsByEventId.has(event.event_id))
  ) {
    console.warn('ML service predictions did not match the requested event IDs.');
    return fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned incomplete predictions)');
  }

  const predictions = events
    .map((event) => {
      const signal = predictionsByEventId.get(event.event_id)!;
      const modelSignal: IsolationForestPredictionSignal = {
        anomaly_score: signal.anomaly_score,
        anomaly_prediction: signal.anomaly_prediction,
        model_version: signal.model_version,
      };
      return evaluateEvent(event, state.events, state.riskWeights, mode.label, modelSignal);
    })
    .sort((a, b) => b.risk_score - a.risk_score);

  return {
    ml_service_connected: true,
    ml_service_label: mode.label,
    predictions,
  };
}

function appendAuditTrail(actor: AuthUser, action_type: string, target: string, details: string): void {
  state.auditTrail.unshift({
    trail_id: `TRL-${Date.now().toString(36).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    actor: actor.full_name,
    actor_role: actor.role,
    action_type,
    target,
    details,
  });
  if (state.auditTrail.length > 200) {
    state.auditTrail = state.auditTrail.slice(0, 200);
  }
}

function getActorFromRequest(req: express.Request): AuthUser {
  const userIdHeader = req.header('x-cloudsentinel-userid');
  if (userIdHeader) {
    const found = state.users.find((u) => u.user_id === userIdHeader && u.is_active);
    if (found) return found;
  }
  const roleHeader = req.header('x-cloudsentinel-role') as UserRole | undefined;
  if (roleHeader) {
    const foundByRole = state.users.find((u) => u.role === roleHeader && u.is_active);
    if (foundByRole) return foundByRole;
  }
  return state.users[0];
}

function requireRole(allowed: UserRole[]) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const actor = getActorFromRequest(req);
    if (!allowed.includes(actor.role)) {
      res.status(403).json({
        error: `Forbidden: Role '${actor.role}' lacks permission. Required role: ${allowed.join(' or ')}.`,
      });
      return;
    }
    next();
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  // Auth & RBAC endpoints
  app.get('/api/auth/users-directory', (_req, res) => {
    res.json({ users: state.users });
  });

  app.post('/api/auth/login', (req, res) => {
    const { email, user_id } = req.body as { email?: string; user_id?: string };
    const found = state.users.find(
      (u) =>
        (user_id && u.user_id === user_id) ||
        (email && u.email.toLowerCase() === email.toLowerCase()),
    );
    if (!found || !found.is_active) {
      res.status(401).json({ error: 'Invalid credentials or inactive account.' });
      return;
    }
    found.last_login = new Date().toISOString();
    appendAuditTrail(found, 'USER_LOGIN', found.user_id, `Authenticated session started as ${found.role}.`);
    saveState(state);
    res.json({ user: found, token: `cs-session-${found.user_id}` });
  });

  // Dashboard Summary (dynamically computed from stored data)
  app.get('/api/dashboard/summary', async (_req, res) => {
    const predictionBatch = await computeAllPredictions();
    const predictions = predictionBatch.predictions;
    const ubaProfiles = computeUserBehaviorProfiles(state.events, predictions);

    const suspiciousPredictions = predictions.filter((p) => p.investigation_status !== 'Normal Baseline');
    const criticalAlerts = predictions.filter((p) => p.risk_level === 'Critical');
    const highRiskUsers = ubaProfiles.filter((u) => u.current_risk_score >= 65);
    const activeIncidents = state.incidents.filter((i) => i.status !== 'Resolved');
    const pendingPolicies = state.policies.filter((p) => p.approval_status === 'Pending Approval');

    // Timeline grouped into 6-hour buckets across events
    const buckets = new Map<string, { total: number; suspicious: number; critical: number }>();
    const predMap = new Map(predictions.map((p) => [p.event_id, p]));
    for (const ev of state.events) {
      const dt = new Date(ev.event_time);
      const day = ev.event_time.slice(5, 10);
      const hourBucket = Math.floor(dt.getUTCHours() / 4) * 4;
      const label = `${day} ${String(hourBucket).padStart(2, '0')}:00`;
      const cur = buckets.get(label) || { total: 0, suspicious: 0, critical: 0 };
      cur.total += 1;
      const pred = predMap.get(ev.event_id);
      if (pred && pred.investigation_status !== 'Normal Baseline') cur.suspicious += 1;
      if (pred && pred.risk_level === 'Critical') cur.critical += 1;
      buckets.set(label, cur);
    }

    const threat_timeline = Array.from(buckets.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([bucket, counts]) => ({
        bucket,
        total_events: counts.total,
        suspicious_events: counts.suspicious,
        critical_alerts: counts.critical,
      }));

    const riskCounts = { Low: 0, Medium: 0, High: 0, Critical: 0 };
    for (const p of predictions) {
      riskCounts[p.risk_level] += 1;
    }

    const totalCostBefore = state.policies.reduce((s, p) => s + p.operational_cost_before_usd, 0);
    const totalCostAfter = state.policies.reduce((s, p) => s + p.operational_cost_after_usd, 0);
    const avgRiskBefore =
      state.policies.reduce((s, p) => s + p.residual_risk_before, 0) / Math.max(1, state.policies.length);
    const avgRiskAfter =
      state.policies.reduce((s, p) => s + p.residual_risk_after, 0) / Math.max(1, state.policies.length);
    const avgPerfOverhead =
      state.policies.reduce((s, p) => s + p.performance_overhead_pct, 0) / Math.max(1, state.policies.length);

    res.json({
      total_cloud_events: state.events.length,
      suspicious_activities: suspiciousPredictions.length,
      critical_security_alerts: criticalAlerts.length,
      high_risk_users: highRiskUsers.length,
      active_incidents: activeIncidents.length,
      pending_policy_approvals: pendingPolicies.length,
      ml_service_connected: predictionBatch.ml_service_connected,
      ml_service_label: predictionBatch.ml_service_label,
      cloud_resource_overview: {
        aws_cloudtrail_events: state.events.filter((e) => e.provider === 'AWS CloudTrail').length,
        aws_lambda_functions: state.lambdaMetrics.length,
        aws_iam_identities: ubaProfiles.length,
        openstack_keystone_tokens: state.events.filter((e) => e.provider === 'OpenStack Keystone').length,
        openstack_nova_instances: state.events.filter((e) => e.provider === 'OpenStack Nova').length,
      },
      threat_timeline,
      risk_distribution: [
        { level: 'Critical', count: riskCounts.Critical },
        { level: 'High', count: riskCounts.High },
        { level: 'Medium', count: riskCounts.Medium },
        { level: 'Low', count: riskCounts.Low },
      ],
      cost_overview: {
        current_monthly_cost_usd: totalCostBefore,
        recommended_monthly_cost_usd: totalCostAfter,
        current_residual_risk: Math.round(avgRiskBefore),
        recommended_residual_risk: Math.round(avgRiskAfter),
        avg_performance_overhead_pct: Number(avgPerfOverhead.toFixed(1)),
      },
      recent_events: state.events
        .slice()
        .sort((a, b) => b.event_time.localeCompare(a.event_time))
        .slice(0, 8),
    });
  });

  // Audit Events APIs
  app.get('/api/events', (req, res) => {
    const provider = String(req.query.provider || 'ALL');
    const status = String(req.query.status || 'ALL');
    const search = String(req.query.search || '').toLowerCase();
    const page = Math.max(1, Number(req.query.page || 1));
    const pageSize = Math.min(100, Math.max(5, Number(req.query.pageSize || 15)));

    let filtered = state.events.slice().sort((a, b) => b.event_time.localeCompare(a.event_time));
    if (provider !== 'ALL') {
      filtered = filtered.filter((e) => e.provider === provider);
    }
    if (status !== 'ALL') {
      filtered = filtered.filter((e) => e.status === status);
    }
    if (search) {
      filtered = filtered.filter(
        (e) =>
          e.event_id.toLowerCase().includes(search) ||
          e.cloud_user_id.toLowerCase().includes(search) ||
          e.action.toLowerCase().includes(search) ||
          e.resource.toLowerCase().includes(search) ||
          e.source_ip.toLowerCase().includes(search),
      );
    }

    const total = filtered.length;
    const start = (page - 1) * pageSize;
    const items = filtered.slice(start, start + pageSize);

    res.json({
      items,
      total,
      page,
      pageSize,
      totalPages: Math.max(1, Math.ceil(total / pageSize)),
    });
  });

  app.post('/api/events/upload', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    try {
      const { content, format, source_name } = req.body as {
        content?: string;
        format?: 'CSV' | 'JSON';
        source_name?: string;
      };
      if (!content || !format) {
        res.status(400).json({ error: 'Both file content and format (CSV or JSON) are required.' });
        return;
      }

      const existingIds = new Set(state.events.map((e) => e.event_id));
      const result = validateAndNormalizeUpload(
        content,
        format,
        source_name || `Uploaded ${format} Audit Batch`,
        existingIds,
      );

      if (result.valid_rows === 0) {
        res.status(400).json({
          error: 'No valid events could be normalized from upload.',
          details: result.errors,
        });
        return;
      }

      state.events = [...result.events, ...state.events];
      const actor = getActorFromRequest(req);
      appendAuditTrail(
        actor,
        'AUDIT_LOG_UPLOAD',
        source_name || 'Audit Upload',
        `Ingested ${result.valid_rows} normalized events (${result.duplicate_count} duplicates skipped, ${result.missing_value_count} missing fields detected).`,
      );
      saveState(state);

      res.json({
        message: `Validated and normalized ${result.valid_rows} events.`,
        summary: result,
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Failed to parse uploaded log file.' });
    }
  });

  // Dataset Management APIs
  app.get('/api/datasets', (_req, res) => {
    res.json({ datasets: state.datasets });
  });

  app.post('/api/datasets/upload', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    try {
      const { name, content, format, provenance, is_cert_mapped, split_ratio } = req.body as {
        name?: string;
        content?: string;
        format?: 'CSV' | 'JSON';
        provenance?: string;
        is_cert_mapped?: boolean;
        split_ratio?: { train: number; val: number; test: number };
      };

      if (!name || !content || !format) {
        res.status(400).json({ error: 'Dataset name, format, and content are required.' });
        return;
      }

      const result = validateAndNormalizeUpload(
        content,
        format,
        name,
        new Set<string>(),
      );

      if (result.valid_rows === 0) {
        res.status(400).json({ error: 'Dataset contains zero valid normalizable records.', details: result.errors });
        return;
      }

      const dataset: DatasetRecord = {
        dataset_id: `ds-${Date.now().toString(36)}`,
        name,
        source_type: format,
        provenance: provenance || 'User Uploaded Research Dataset',
        is_cert_mapped: Boolean(is_cert_mapped),
        total_rows: result.total_rows,
        valid_rows: result.valid_rows,
        missing_value_count: result.missing_value_count,
        duplicate_count: result.duplicate_count,
        original_records_count: result.original_records_count,
        adapted_faas_count: result.adapted_faas_count,
        split_ratio: split_ratio || { train: 0.6, val: 0.2, test: 0.2 },
        preprocessed: true,
        features_extracted: [
          'is_after_hours',
          'is_unusual_ip',
          'is_failed_auth',
          'action_criticality',
          'resource_sensitivity',
          'user_privilege_level',
          'api_burst_zscore',
          'is_bulk_download',
          'is_dormant_account',
          'is_faas_spike',
        ],
        created_at: new Date().toISOString(),
        sample_preview: result.events.slice(0, 5),
      };

      // Also merge into active events if requested or store dataset preview
      state.datasets.unshift(dataset);
      // Merge new dataset events that aren't duplicates into stored event pool
      const existing = new Set(state.events.map((e) => e.event_id));
      const newOnes = result.events.filter((e) => !existing.has(e.event_id));
      state.events = [...newOnes, ...state.events];

      const actor = getActorFromRequest(req);
      appendAuditTrail(
        actor,
        'DATASET_UPLOAD',
        dataset.dataset_id,
        `Registered dataset '${name}' (${dataset.valid_rows} valid rows, ${dataset.adapted_faas_count} FaaS adapted).`,
      );
      saveState(state);

      res.json({ dataset, merged_events_count: newOnes.length });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Dataset validation error.' });
    }
  });

  // User Behaviour Analytics (UBA)
  app.get('/api/uba/users', async (_req, res) => {
    const predictionBatch = await computeAllPredictions();
    const profiles = computeUserBehaviorProfiles(state.events, predictionBatch.predictions);
    res.json({ profiles });
  });

  // AI Threat Detection APIs
  app.get('/api/detection/predictions', async (_req, res) => {
    res.json(await computeAllPredictions());
  });

  app.post('/api/detection/run', requireRole(['Admin', 'Security Analyst']), async (req, res) => {
    const eventIds: unknown = req.body?.event_ids;
    if (
      eventIds !== undefined &&
      (!Array.isArray(eventIds) || eventIds.some((id) => typeof id !== 'string'))
    ) {
      res.status(400).json({ error: 'event_ids must be an array of event ID strings.' });
      return;
    }

    const requestedIds = eventIds as string[] | undefined;
    const unknownIds = requestedIds?.filter((id) => !state.events.some((event) => event.event_id === id));
    if (unknownIds && unknownIds.length > 0) {
      res.status(400).json({ error: 'One or more event_ids were not found.' });
      return;
    }

    const targetEvents =
      requestedIds && requestedIds.length > 0
        ? state.events.filter((e) => requestedIds.includes(e.event_id))
        : state.events;
    const predictionBatch = await computeAllPredictions(targetEvents);

    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'DETECTION_SCAN_RUN',
      `${targetEvents.length} events`,
      `Executed confidence-aware detection pipeline (${predictionBatch.ml_service_label}).`,
    );
    saveState(state);

    res.json(predictionBatch);
  });

  // Incident Management APIs
  app.get('/api/incidents', (_req, res) => {
    res.json({ incidents: state.incidents });
  });

  app.post('/api/incidents/from-prediction', requireRole(['Admin', 'Security Analyst']), async (req, res) => {
    const { prediction_id } = req.body as { prediction_id?: string };
    const predictionBatch = await computeAllPredictions();
    const pred = predictionBatch.predictions.find((p) => p.prediction_id === prediction_id);
    if (!pred) {
      res.status(404).json({ error: 'Prediction not found.' });
      return;
    }

    const existing = state.incidents.find((i) => i.prediction_id === pred.prediction_id);
    if (existing) {
      res.json({ incident: existing, already_exists: true });
      return;
    }

    const evidenceEvents = state.events.filter((e) => pred.evidence_events.includes(e.event_id));
    const now = new Date().toISOString();
    const actor = getActorFromRequest(req);

    const incident: SecurityIncident = {
      incident_id: `INC-${new Date().getUTCFullYear()}-${String(state.incidents.length + 44).padStart(3, '0')}`,
      title: `${pred.scenario} (${pred.cloud_user_id})`,
      severity: pred.risk_level,
      status: 'Open',
      affected_user: pred.cloud_user_id,
      provider: pred.provider,
      prediction_id: pred.prediction_id,
      scenario: pred.scenario,
      anomaly_score: pred.anomaly_score,
      risk_score: pred.risk_score,
      created_at: now,
      updated_at: now,
      summary: pred.explanation,
      evidence_events: evidenceEvents,
      recommended_actions: pred.recommended_steps,
      analyst_notes: [],
      assigned_to: actor.full_name,
    };

    state.incidents.unshift(incident);
    appendAuditTrail(
      actor,
      'INCIDENT_CREATED',
      incident.incident_id,
      `Created incident from prediction ${pred.prediction_id} (${pred.risk_level} risk).`,
    );
    saveState(state);

    res.status(201).json({ incident });
  });

  app.patch('/api/incidents/:id', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    const { id } = req.params;
    const { status, note, assigned_to } = req.body as {
      status?: IncidentStatus;
      note?: string;
      assigned_to?: string;
    };

    const incident = state.incidents.find((i) => i.incident_id === id);
    if (!incident) {
      res.status(404).json({ error: 'Incident not found.' });
      return;
    }

    const actor = getActorFromRequest(req);
    if (status && ['Open', 'Investigating', 'Resolved'].includes(status)) {
      incident.status = status;
    }
    if (assigned_to !== undefined) {
      incident.assigned_to = assigned_to;
    }
    if (note && note.trim()) {
      incident.analyst_notes.unshift({
        note_id: `note-${Date.now().toString(36)}`,
        author: actor.full_name,
        timestamp: new Date().toISOString(),
        content: note.trim(),
      });
    }
    incident.updated_at = new Date().toISOString();

    appendAuditTrail(
      actor,
      'INCIDENT_UPDATED',
      incident.incident_id,
      `Updated incident status=${incident.status}${note ? ' with analyst note' : ''}.`,
    );
    saveState(state);

    res.json({ incident });
  });

  // Security Policy & Cost Optimization APIs
  app.get('/api/policies', (_req, res) => {
    state.policies = evaluateCostOptimizer(state.policies, state.costWeights);
    res.json({
      policies: state.policies,
      costWeights: state.costWeights,
      riskWeights: state.riskWeights,
    });
  });

  app.post('/api/policies/:id/approve', requireRole(['Admin']), (req, res) => {
    const pol = state.policies.find((p) => p.policy_id === req.params.id);
    if (!pol) {
      res.status(404).json({ error: 'Policy recommendation not found.' });
      return;
    }
    const actor = getActorFromRequest(req);
    pol.approval_status = 'Approved';
    pol.approved_by = actor.full_name;
    pol.approved_at = new Date().toISOString();

    appendAuditTrail(
      actor,
      'POLICY_APPROVED',
      pol.policy_id,
      `Admin explicitly approved '${pol.title}' for ${pol.target_user_id}.`,
    );
    saveState(state);
    res.json({ policy: pol });
  });

  app.post('/api/policies/:id/reject', requireRole(['Admin']), (req, res) => {
    const pol = state.policies.find((p) => p.policy_id === req.params.id);
    if (!pol) {
      res.status(404).json({ error: 'Policy recommendation not found.' });
      return;
    }
    const actor = getActorFromRequest(req);
    pol.approval_status = 'Rejected';
    pol.approved_by = actor.full_name;
    pol.approved_at = new Date().toISOString();

    appendAuditTrail(
      actor,
      'POLICY_REJECTED',
      pol.policy_id,
      `Admin rejected policy recommendation '${pol.title}'.`,
    );
    saveState(state);
    res.json({ policy: pol });
  });

  app.put('/api/settings/weights', requireRole(['Admin']), (req, res) => {
    const { riskWeights, costWeights } = req.body as {
      riskWeights?: Partial<RiskEngineWeights>;
      costWeights?: Partial<CostOptimizerWeights>;
    };

    if (riskWeights) {
      state.riskWeights = { ...state.riskWeights, ...riskWeights };
    }
    if (costWeights) {
      state.costWeights = { ...state.costWeights, ...costWeights };
      state.policies = evaluateCostOptimizer(state.policies, state.costWeights);
    }

    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'WEIGHTS_UPDATED',
      'Risk & Cost Engine',
      `Updated scoring engine weights (Confidence threshold=${state.riskWeights.confidence_threshold}, Budget=$${state.costWeights.max_budget_usd}).`,
    );
    saveState(state);

    res.json({
      riskWeights: state.riskWeights,
      costWeights: state.costWeights,
      policies: state.policies,
    });
  });

  // Cloud Environment Integrations & Serverless FaaS Monitoring
  app.get('/api/integrations', (_req, res) => {
    res.json({
      integrations: state.integrations,
      lambdaMetrics: state.lambdaMetrics,
    });
  });

  app.post('/api/integrations/:id/test', requireRole(['Admin']), (req, res) => {
    const integration = state.integrations.find((i) => i.integration_id === req.params.id);
    if (!integration) {
      res.status(404).json({ error: 'Integration profile not found.' });
      return;
    }
    const { endpoint_or_region, role_or_project, credential_provided } = req.body as {
      endpoint_or_region?: string;
      role_or_project?: string;
      credential_provided?: boolean;
    };

    if (!role_or_project || !role_or_project.trim() || !endpoint_or_region || !endpoint_or_region.trim()) {
      res.status(400).json({ error: 'Endpoint/Region and Role ARN or Project ID are required.' });
      return;
    }

    integration.endpoint_or_region = endpoint_or_region.trim();
    integration.role_or_project = role_or_project.trim();
    integration.last_tested = new Date().toISOString();

    // Honest validation: never pretend cloud API is live-connected without server-side credentials
    const hasAwsCreds = Boolean(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY);
    const hasOsCreds = Boolean(process.env.OPENSTACK_TOKEN || process.env.OPENSTACK_PASSWORD);

    if (integration.provider === 'AWS' && !hasAwsCreds) {
      integration.status = 'Validation Failed';
      integration.validation_message =
        'Configuration saved (Read-Only scope). Live AWS STS connection requires AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment credentials on backend.';
    } else if (integration.provider === 'OpenStack' && !hasOsCreds) {
      integration.status = 'Validation Failed';
      integration.validation_message =
        'Configuration saved (Reader scope). Live Keystone connection requires OPENSTACK_TOKEN or application credential environment variables on backend.';
    } else if (credential_provided) {
      integration.status = 'Read-Only Verified';
      integration.validation_message = 'Environment credentials detected and read-only probe succeeded.';
    }

    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'INTEGRATION_TESTED',
      integration.integration_id,
      `Saved/tested ${integration.service_name} (${integration.status}).`,
    );
    saveState(state);

    res.json({ integration });
  });

  // ML Research Lab & Experimentation APIs
  app.get('/api/ml/experiments', async (_req, res) => {
    const mlMode = await checkMlServiceHealth();
    res.json({
      ml_service_connected: mlMode.connected,
      ml_service_label: mlMode.label,
      experiments: state.experiments,
    });
  });

  app.post('/api/ml/train', requireRole(['Admin', 'Security Analyst']), async (req, res) => {
    const { dataset_id, model_type, features_used, split_ratio } = req.body as {
      dataset_id?: string;
      model_type?: MLExperimentResult['model_type'];
      features_used?: string[];
      split_ratio?: { train: number; val: number; test: number };
    };

    const dataset = state.datasets.find((d) => d.dataset_id === dataset_id) || state.datasets[0];
    if (!dataset) {
      res.status(400).json({ error: 'No dataset available for training.' });
      return;
    }

    if (model_type === 'Transformer (Planned)') {
      res.status(400).json({
        error:
          'Transformer-based sequence detector is documented as a future research extension and is not available for training yet.',
      });
      return;
    }

    const ratio = split_ratio || dataset.split_ratio;
    const sum = ratio.train + ratio.val + ratio.test;
    if (Math.abs(sum - 1) > 0.05) {
      res.status(400).json({ error: 'Train / Validation / Test split ratios must sum to 1.0.' });
      return;
    }

    const selectedFeatures =
      Array.isArray(features_used) && features_used.length > 0 ? features_used : dataset.features_extracted;

    const datasetEvents =
      dataset.sample_preview && state.events.length > 0 ? state.events : dataset.sample_preview;

    const exp = runRealExperimentOnDataset(
      dataset,
      datasetEvents,
      model_type || 'Isolation Forest',
      selectedFeatures,
      ratio,
      state.riskWeights,
      'Simulated in-process experiment (Python ML service is used for inference only)',
    );

    state.experiments.unshift(exp);
    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'ML_EXPERIMENT_RUN',
      exp.experiment_id,
      `Executed ${exp.model_type} evaluation on ${dataset.name} (F1=${exp.metrics.f1_score}, FPR=${exp.metrics.false_positive_rate}).`,
    );
    saveState(state);

    res.status(201).json({ experiment: exp });
  });

  // User Management & Audit Trail APIs
  app.get('/api/users', (_req, res) => {
    res.json({ users: state.users, auditTrail: state.auditTrail });
  });

  app.post('/api/users', requireRole(['Admin']), (req, res) => {
    const { full_name, email, role, department } = req.body as {
      full_name?: string;
      email?: string;
      role?: UserRole;
      department?: string;
    };
    if (!full_name || !email || !role) {
      res.status(400).json({ error: 'full_name, email, and role are required.' });
      return;
    }
    if (state.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
      res.status(409).json({ error: 'A user with that email already exists.' });
      return;
    }

    const newUser: AuthUser = {
      user_id: `usr-${Date.now().toString(36)}`,
      username: email.split('@')[0],
      full_name: full_name.trim(),
      email: email.trim(),
      role,
      department: department?.trim() || 'Security Operations',
      last_login: 'Never',
      is_active: true,
    };

    state.users.push(newUser);
    const actor = getActorFromRequest(req);
    appendAuditTrail(actor, 'USER_CREATED', newUser.user_id, `Provisioned ${newUser.full_name} with role ${role}.`);
    saveState(state);

    res.status(201).json({ user: newUser });
  });

  app.patch('/api/users/:id', requireRole(['Admin']), (req, res) => {
    const target = state.users.find((u) => u.user_id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    const { role, is_active } = req.body as { role?: UserRole; is_active?: boolean };
    if (role) target.role = role;
    if (typeof is_active === 'boolean') target.is_active = is_active;

    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'USER_UPDATED',
      target.user_id,
      `Updated ${target.full_name}: role=${target.role}, active=${target.is_active}.`,
    );
    saveState(state);

    res.json({ user: target });
  });

  // CSV Report Export Endpoint
  app.get('/api/reports/export', async (_req, res) => {
    const predictionBatch = await computeAllPredictions();
    const predictions = predictionBatch.predictions;
    const headers = [
      'event_id',
      'provider',
      'event_time',
      'cloud_user_id',
      'action',
      'resource',
      'source_ip',
      'status',
      'anomaly_score',
      'prediction_confidence',
      'risk_score',
      'risk_level',
      'investigation_status',
      'scenario',
    ];
    const predMap = new Map(predictions.map((p) => [p.event_id, p]));
    const rows = state.events.map((ev) => {
      const p = predMap.get(ev.event_id);
      return [
        ev.event_id,
        ev.provider,
        ev.event_time,
        ev.cloud_user_id,
        ev.action,
        ev.resource,
        ev.source_ip,
        ev.status,
        p?.anomaly_score ?? 0,
        p?.prediction_confidence ?? 0,
        p?.risk_score ?? 0,
        p?.risk_level ?? 'Low',
        p?.investigation_status ?? 'Normal Baseline',
        p?.scenario ?? 'Normal',
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(',');
    });

    const csv = [headers.join(','), ...rows].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="cloudsentinel-audit-report.csv"');
    res.send(csv);
  });

  // Vite middleware or production static serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const port = Number(process.env.PORT || 3000);

app.listen(port, '0.0.0.0', () => {
  console.log(`CloudSentinel AI running at http://localhost:${port}`);
});
}

startServer();
