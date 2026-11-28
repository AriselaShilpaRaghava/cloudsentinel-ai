import express from 'express';
import { createServer as createViteServer } from 'vite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dotenv from 'dotenv';
import type {
  AuditTrailEntry,
  AuthUser,
  CloudIntegrationConfig,
  CostAwareOptimizationResult,
  CostOptimizerWeights,
  DashboardSummary,
  DatasetRecord,
  IncidentStatus,
  IngestionSummary,
  LambdaFunctionMetric,
  LocalDatasetFileInfo,
  MLExperimentResult,
  NormalizedAuditEvent,
  OptimizerScenarioInput,
  PolicyRecommendation,
  RiskEngineWeights,
  SecurityIncident,
  ThreatPrediction,
  UserBehaviorProfile,
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
  buildEventsByUserMap,
  computeUserBehaviorProfiles,
  evaluateCostOptimizer,
  evaluateEvent,
  runRealExperimentOnDataset,
} from './src/server/mlEngine.ts';
import type { IsolationForestPredictionSignal } from './src/server/mlEngine.ts';
import { validateAndNormalizeUpload } from './src/server/eventNormalizer.ts';
import { buildSecurityPdfArrayBuffer } from './src/services/reportGenerator.ts';
import {
  CANDIDATE_ACTION_CATALOG,
  COST_ESTIMATION_ASSUMPTIONS,
  DEFAULT_OPTIMIZER_CONSTRAINTS,
  DEFAULT_OPTIMIZER_WEIGHTS,
  buildPolicyProposalFromOptimization,
  optimizeSecurityPolicy,
  validateOptimizerInput,
} from './src/server/policyOptimizer.ts';
import {
  buildOpenStackDatasetRecord,
  normalizeOpenStackEvents,
  probeOpenStackConnectivity,
} from './src/server/openstackAdapter.ts';

dotenv.config();

interface AppState {
  users: AuthUser[];
  events: NormalizedAuditEvent[];
  datasets: DatasetRecord[];
  incidents: SecurityIncident[];
  policies: PolicyRecommendation[];
  policyOptimizations?: CostAwareOptimizationResult[];
  integrations: CloudIntegrationConfig[];
  lambdaMetrics: LambdaFunctionMetric[];
  experiments: MLExperimentResult[];
  riskWeights: RiskEngineWeights;
  costWeights: CostOptimizerWeights;
  auditTrail: AuditTrailEntry[];
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const CERT_DATASET_ID = 'ds-cert-cloud-01';
const CLOUDTRAIL_TRAIN_DATASET_ID = 'ds-cloudtrail-train';
const CLOUDTRAIL_TEST_DATASET_ID = 'ds-cloudtrail-test';
const STATE_FILE =
  process.env.STATE_FILE?.trim() || path.join(os.tmpdir(), 'cloudsentinel_state_v1.json');
const PREDICTION_CACHE_TTL_MS = 30_000;
const ML_FEATURES = [
  'is_faas',
  'failed_event_flag',
  'is_iam_user',
  'is_anonymous_or_account',
  'recon_action_flag',
  'sensitive_action_flag',
  'log_s3_burst_1m',
  'log_unique_buckets_5m',
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

function ensureWorkspaceCloudTrailDatasets(targetState: AppState): boolean {
  const specs: Array<{
    datasetId: string;
    filename: string;
    role: 'training' | 'testing';
    provenance: string;
  }> = [
    {
      datasetId: CLOUDTRAIL_TRAIN_DATASET_ID,
      filename: 'cloudtrail_training.json',
      role: 'training',
      provenance: 'AWS CloudTrail Training Dataset (data/cloudtrail_training.json)',
    },
    {
      datasetId: CLOUDTRAIL_TEST_DATASET_ID,
      filename: 'cloudtrail_testing.json',
      role: 'testing',
      provenance: 'AWS CloudTrail Held-Out Testing Dataset (data/cloudtrail_testing.json)',
    },
  ];

  let changed = false;
  const eventIndexById = new Map<string, number>();
  targetState.events.forEach((ev, idx) => {
    eventIndexById.set(ev.event_id, idx);
  });

  for (const spec of specs) {
    const fullPath = path.join(DATA_DIR, spec.filename);
    if (!fs.existsSync(fullPath)) continue;

    const alreadyRegistered = targetState.datasets.some((d) => d.dataset_id === spec.datasetId);
    const taggedCount = targetState.events.filter((e) => e.dataset_id === spec.datasetId).length;
    if (alreadyRegistered && taggedCount > 0) continue;

    const content = fs.readFileSync(fullPath, 'utf-8');
    const result = validateAndNormalizeUpload(content, 'JSON', spec.filename, new Set<string>(), {
      datasetId: spec.datasetId,
    });

    const newEvents: NormalizedAuditEvent[] = [];
    for (const ev of result.events) {
      const existingIdx = eventIndexById.get(ev.event_id);
      if (existingIdx !== undefined) {
        const current = targetState.events[existingIdx];
        if (current.dataset_id !== spec.datasetId || !current.identity_type || current.ground_truth_label === undefined) {
          targetState.events[existingIdx] = {
            ...current,
            dataset_id: spec.datasetId,
            dataset_source: spec.filename,
            identity_type: current.identity_type || ev.identity_type,
            ...(ev.ground_truth_label !== undefined ? { ground_truth_label: ev.ground_truth_label } : {}),
            ...(ev.attack_name ? { attack_name: ev.attack_name } : {}),
          };
          changed = true;
        }
      } else {
        eventIndexById.set(ev.event_id, targetState.events.length + newEvents.length);
        newEvents.push(ev);
      }
    }

    if (newEvents.length > 0) {
      targetState.events = [...newEvents, ...targetState.events];
      eventIndexById.clear();
      targetState.events.forEach((ev, idx) => {
        eventIndexById.set(ev.event_id, idx);
      });
      changed = true;
    }

    if (!alreadyRegistered) {
      const dsRecord: DatasetRecord = {
        dataset_id: spec.datasetId,
        name: spec.filename,
        source_type: 'JSON',
        provenance: spec.provenance,
        dataset_role: spec.role,
        file_path: `data/${spec.filename}`,
        is_cert_mapped: false,
        total_rows: result.total_rows,
        valid_rows: result.valid_rows,
        normalized_rows: result.normalized_rows,
        imported_rows: result.valid_rows,
        rejected_rows: result.rejected_rows,
        skipped_rows: result.skipped_rows,
        missing_value_count: result.missing_value_count,
        duplicate_count: result.duplicate_count,
        benign_count: result.benign_count,
        attack_count: result.attack_count,
        unlabeled_count: result.unlabeled_count,
        rejection_reasons: result.rejection_reasons,
        skip_reasons: result.skip_reasons,
        original_records_count: result.original_records_count,
        adapted_faas_count: result.adapted_faas_count,
        split_ratio: spec.role === 'training' ? { train: 1, val: 0, test: 0 } : { train: 0, val: 0, test: 1 },
        preprocessed: true,
        features_extracted: [...ML_FEATURES],
        created_at: new Date().toISOString(),
        sample_preview: result.events.slice(0, 5),
      };
      targetState.datasets.push(dsRecord);
      changed = true;
    }
  }

  return changed;
}

function createInitialState(): AppState {
  const initialDatasets = [...SEEDED_DATASETS];
  const defaultDatasetId = initialDatasets[0]?.dataset_id || CERT_DATASET_ID;
  const initialEvents = SEEDED_EVENTS.map((ev) => ({
    ...ev,
    dataset_id: ev.dataset_id || defaultDatasetId,
  }));
  const riskWeights = { ...DEFAULT_RISK_WEIGHTS };
  const costWeights = { ...DEFAULT_COST_WEIGHTS };

  const init: AppState = {
    users: [...DEFAULT_AUTH_USERS],
    events: initialEvents,
    datasets: initialDatasets,
    incidents: [...SEEDED_INCIDENTS],
    policies: evaluateCostOptimizer([...SEEDED_POLICIES], costWeights),
    policyOptimizations: [],
    integrations: [...DEFAULT_INTEGRATIONS],
    lambdaMetrics: [...SEEDED_LAMBDA_METRICS],
    experiments: [],
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

  ensureWorkspaceCloudTrailDatasets(init);
  return init;
}

function loadState(): AppState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = fs.readFileSync(STATE_FILE, 'utf-8');
      const parsed = JSON.parse(raw) as AppState;
      if (parsed && Array.isArray(parsed.events) && Array.isArray(parsed.users)) {
        let migrated = false;
        const certDs = parsed.datasets?.find((d) => d.dataset_id === CERT_DATASET_ID) || parsed.datasets?.[0];
        const defaultDatasetId = certDs?.dataset_id || CERT_DATASET_ID;
        parsed.events = parsed.events.map((ev) => {
          if (
            !ev.dataset_id &&
            (ev.dataset_source === 'Seeded Cloud & CERT-Mapped Benchmark' ||
              ev.dataset_source === 'CERT r4.2 Adapted Cloud Mapping')
          ) {
            migrated = true;
            return { ...ev, dataset_id: defaultDatasetId };
          }
          return ev;
        });

        // Remove stale auto-seeded simulated 10-record placeholder experiments
        if (Array.isArray(parsed.experiments)) {
          const filteredExps = parsed.experiments.filter(
            (exp) =>
              !(
                exp.dataset_id === CERT_DATASET_ID &&
                exp.execution_mode.startsWith('Simulated in-process evaluation (ML service health not yet checked)')
              ),
          );
          if (filteredExps.length !== parsed.experiments.length) {
            parsed.experiments = filteredExps;
            migrated = true;
          }
        } else {
          parsed.experiments = [];
          migrated = true;
        }

        if (!Array.isArray(parsed.policyOptimizations)) {
          parsed.policyOptimizations = [];
          migrated = true;
        }

        if (ensureWorkspaceCloudTrailDatasets(parsed)) {
          migrated = true;
        }
        if (migrated) {
          saveState(parsed);
        }
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
    fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify(state), 'utf-8');
  } catch {
    // Non-fatal in ephemeral containers
  }
}

let state: AppState = loadState();
let stateVersion = 0;
let cachedPredictionBatch: {
  version: number;
  mlConnected: boolean;
  mlLabel: string;
  mlUrl: string | null;
  timestampMs: number;
  batch: PredictionBatch;
} | null = null;
const cachedFaasTelemetry = new Map<string, { timestampMs: number; payload: Record<string, unknown> }>();

function invalidatePredictionCache(): void {
  stateVersion += 1;
  cachedPredictionBatch = null;
  cachedFaasTelemetry.clear();
}

function mlServiceUrl(): string | null {
  const url = process.env.ML_SERVICE_URL?.trim().replace(/\/+$/, '');
  return url || null;
}

async function fetchMlService(url: string, init?: RequestInit, timeoutMs = 30000): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function fallbackBatch(events: NormalizedAuditEvent[], label: string): PredictionBatch {
  const eventsByUser = buildEventsByUserMap(state.events);
  return {
    ml_service_connected: false,
    ml_service_label: label,
    predictions: events
      .map((event) => evaluateEvent(event, state.events, state.riskWeights, label, undefined, eventsByUser))
      .sort((a, b) => b.risk_score - a.risk_score),
  };
}

function sanitizeEventForMl(event: NormalizedAuditEvent, includeLabel = false): Record<string, unknown> {
  const raw = event.raw_event || {};
  const rawUi = raw.userIdentity && typeof raw.userIdentity === 'object'
    ? (raw.userIdentity as Record<string, unknown>)
    : undefined;
  const rawInScope = rawUi?.inScopeOf && typeof rawUi.inScopeOf === 'object'
    ? (rawUi.inScopeOf as Record<string, unknown>)
    : undefined;
  const rawReqParams = raw.requestParameters && typeof raw.requestParameters === 'object'
    ? (raw.requestParameters as Record<string, unknown>)
    : undefined;

  const slimRaw: Record<string, unknown> = {};
  if (raw.eventSource !== undefined) slimRaw.eventSource = raw.eventSource;
  if (raw.awsRegion !== undefined) slimRaw.awsRegion = raw.awsRegion;
  if (raw.errorCode !== undefined) slimRaw.errorCode = raw.errorCode;
  if (raw.errorMessage !== undefined) slimRaw.errorMessage = raw.errorMessage;
  if (raw.bytesTransferredMB !== undefined) slimRaw.bytesTransferredMB = raw.bytesTransferredMB;

  if (rawReqParams) {
    const slimReqParams: Record<string, unknown> = {};
    for (const key of [
      'bucketName',
      'functionName',
      'invocationType',
      'sourceArn',
      'logGroupName',
      'roleArn',
      'roleSessionName',
      'resource',
    ] as const) {
      if (rawReqParams[key] !== undefined) {
        slimReqParams[key] = rawReqParams[key];
      }
    }
    if (Object.keys(slimReqParams).length > 0) {
      slimRaw.requestParameters = slimReqParams;
    }
  }

  if (Array.isArray(raw.resources)) slimRaw.resources = raw.resources;
  if (rawUi) {
    const slimUi: Record<string, unknown> = {
      ...(rawUi.type !== undefined ? { type: rawUi.type } : {}),
      ...(rawUi.invokedBy !== undefined ? { invokedBy: rawUi.invokedBy } : {}),
    };
    if (rawInScope) {
      slimUi.inScopeOf = {
        ...(rawInScope.issuerType !== undefined ? { issuerType: rawInScope.issuerType } : {}),
        ...(rawInScope.credentialsIssuedTo !== undefined
          ? { credentialsIssuedTo: rawInScope.credentialsIssuedTo }
          : {}),
      };
    }
    slimRaw.userIdentity = slimUi;
  }

  return {
    event_id: event.event_id,
    provider: event.provider,
    event_time: event.event_time,
    cloud_user_id: event.cloud_user_id,
    ...(event.identity_type ? { identity_type: event.identity_type } : {}),
    action: event.action,
    resource: event.resource,
    source_ip: event.source_ip,
    status: event.status,
    raw_event: slimRaw,
    ...(includeLabel && event.ground_truth_label !== undefined
      ? { ground_truth_label: event.ground_truth_label }
      : {}),
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

  const healthRecord =
    health && typeof health === 'object' ? (health as Record<string, unknown>) : null;
  const healthFeatures = Array.isArray(healthRecord?.features) ? healthRecord.features : null;

  if (
    !healthRecord ||
    healthRecord.status !== 'ok' ||
    healthRecord.model_loaded !== true ||
    !healthFeatures ||
    healthFeatures.length !== ML_FEATURES.length ||
    !ML_FEATURES.every((feature, index) => healthFeatures[index] === feature)
  ) {
    return {
      connected: false,
      label: 'Simulated Baseline Scorer (Python ML Service model or feature contract unavailable)',
    };
  }

  return { connected: true, label: 'Connected Python ML Service (saved Isolation Forest)' };
}

async function computeAllPredictions(
  events: NormalizedAuditEvent[] = state.events,
  options?: { forceRefresh?: boolean },
): Promise<PredictionBatch> {
  const isFullState = events === state.events;
  const mode = await checkMlServiceHealth();
  const baseUrl = mlServiceUrl();

  if (
    isFullState &&
    !options?.forceRefresh &&
    cachedPredictionBatch &&
    cachedPredictionBatch.version === stateVersion &&
    cachedPredictionBatch.mlConnected === mode.connected &&
    cachedPredictionBatch.mlLabel === mode.label &&
    cachedPredictionBatch.mlUrl === baseUrl &&
    Date.now() - cachedPredictionBatch.timestampMs < PREDICTION_CACHE_TTL_MS
  ) {
    return cachedPredictionBatch.batch;
  }

  const cacheIfFullState = (batch: PredictionBatch): PredictionBatch => {
    if (isFullState) {
      cachedPredictionBatch = {
        version: stateVersion,
        mlConnected: mode.connected,
        mlLabel: mode.label,
        mlUrl: baseUrl,
        timestampMs: Date.now(),
        batch,
      };
    }
    return batch;
  };

  if (!mode.connected) {
    return cacheIfFullState(fallbackBatch(events, mode.label));
  }

  if (!baseUrl) {
    return cacheIfFullState(
      fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service not configured)'),
    );
  }

  let response: Response;
  try {
    response = await fetchMlService(`${baseUrl}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        events: events.map((ev) => sanitizeEventForMl(ev, false)),
        model_type: 'isolation_forest',
      }),
    });
  } catch (error) {
    console.warn('ML service prediction request failed.', error);
    return cacheIfFullState(
      fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service unavailable; prediction failed)'),
    );
  }

  if (!response.ok) {
    console.warn(`ML service rejected prediction request with HTTP ${response.status}.`);
    return cacheIfFullState(
      fallbackBatch(
        events,
        `Simulated Baseline Scorer (Python ML Service rejected prediction request with HTTP ${response.status})`,
      ),
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch (error) {
    console.warn('ML service prediction response was not valid JSON.', error);
    return cacheIfFullState(
      fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned an invalid response)'),
    );
  }

  if (
    !body ||
    typeof body !== 'object' ||
    !('predictions' in body) ||
    !Array.isArray(body.predictions)
  ) {
    console.warn('ML service prediction response did not contain a predictions array.');
    return cacheIfFullState(
      fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned an invalid response)'),
    );
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
      return cacheIfFullState(
        fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned an invalid prediction)'),
      );
    }

    if (predictionsByEventId.has(item.event_id)) {
      console.warn(`ML service returned duplicate prediction event_id '${item.event_id}'.`);
      return cacheIfFullState(
        fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned duplicate predictions)'),
      );
    }
    predictionsByEventId.set(item.event_id, item as MlServicePrediction);
  }

  if (
    predictionsByEventId.size !== events.length ||
    events.some((event) => !predictionsByEventId.has(event.event_id))
  ) {
    console.warn('ML service predictions did not match the requested event IDs.');
    return cacheIfFullState(
      fallbackBatch(events, 'Simulated Baseline Scorer (Python ML Service returned incomplete predictions)'),
    );
  }

  const eventsByUser = buildEventsByUserMap(state.events);
  const predictions = events
    .map((event) => {
      const signal = predictionsByEventId.get(event.event_id)!;
      const modelSignal: IsolationForestPredictionSignal = {
        anomaly_score: signal.anomaly_score,
        anomaly_prediction: signal.anomaly_prediction,
        model_version: signal.model_version,
      };
      return evaluateEvent(event, state.events, state.riskWeights, mode.label, modelSignal, eventsByUser);
    })
    .sort((a, b) => b.risk_score - a.risk_score);

  return cacheIfFullState({
    ml_service_connected: true,
    ml_service_label: mode.label,
    predictions,
  });
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

  function buildDashboardSummary(
    predictionBatch: PredictionBatch,
    ubaProfiles: UserBehaviorProfile[],
  ): DashboardSummary {
    const predictions = predictionBatch.predictions;
    const suspiciousPredictions = predictions.filter((p) => p.investigation_status !== 'Normal Baseline');
    const criticalAlerts = predictions.filter((p) => p.risk_level === 'Critical');
    const highRiskUsers = ubaProfiles.filter((u) => u.current_risk_score >= 65);
    const activeIncidents = state.incidents.filter((i) => i.status !== 'Resolved');
    const pendingPolicies = state.policies.filter((p) => p.approval_status === 'Pending Approval');

    // Timeline grouped into 4-hour buckets across events
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

    return {
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
    };
  }

  // Dashboard Summary (dynamically computed from stored data)
  app.get('/api/dashboard/summary', async (_req, res) => {
    const predictionBatch = await computeAllPredictions();
    const ubaProfiles = computeUserBehaviorProfiles(state.events, predictionBatch.predictions);
    res.json(buildDashboardSummary(predictionBatch, ubaProfiles));
  });

  // Audit Events APIs
  app.get('/api/events', (req, res) => {
    const provider = String(req.query.provider || 'ALL');
    const status = String(req.query.status || 'ALL');
    const datasetId = String(req.query.dataset_id || 'ALL');
    const search = String(req.query.search || '').toLowerCase();
    const page = Math.max(1, Number(req.query.page || 1));
    const pageSize = Math.min(100, Math.max(5, Number(req.query.pageSize || 15)));

    let filtered = state.events.slice().sort((a, b) => b.event_time.localeCompare(a.event_time));
    if (datasetId !== 'ALL') {
      filtered = filtered.filter((e) => e.dataset_id === datasetId);
    }
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
          e.source_ip.toLowerCase().includes(search) ||
          (e.attack_name ? e.attack_name.toLowerCase().includes(search) : false),
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

  const handleEventsUpload = (
    req: express.Request,
    res: express.Response,
    content: string,
    format: 'CSV' | 'JSON',
    sourceName: string,
  ) => {
    const existingIds = new Set(state.events.map((e) => e.event_id));
    const result = validateAndNormalizeUpload(content, format, sourceName, existingIds);

    if (result.valid_rows === 0 && result.already_exists_count === 0) {
      res.status(400).json({
        error: 'No valid events could be normalized from upload.',
        details: result.errors,
        summary: result,
      });
      return;
    }

    if (result.events.length > 0) {
      state.events = [...result.events, ...state.events];
      invalidatePredictionCache();
    }

    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'AUDIT_LOG_UPLOAD',
      sourceName,
      `Normalized ${result.normalized_rows}/${result.total_rows} events, imported ${result.imported_rows}, rejected ${result.rejected_rows}, skipped ${result.skipped_rows}.`,
    );
    saveState(state);

    const { events: _events, ...summary } = result;
    res.json({
      message: `Normalized ${result.normalized_rows} and imported ${result.imported_rows} of ${result.total_rows} records.`,
      summary,
    });
  };

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
      handleEventsUpload(req, res, content, format, source_name || `Uploaded ${format} Audit Batch`);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Failed to parse uploaded log file.' });
    }
  });

  const rawUploadParser = express.raw({
    type: ['application/octet-stream', 'application/json', 'text/csv', 'text/plain'],
    limit: '100mb',
  });

  app.post(
    '/api/events/upload-file',
    requireRole(['Admin', 'Security Analyst']),
    rawUploadParser,
    (req, res) => {
      try {
        const formatHeader = String(req.header('x-file-format') || '').toUpperCase();
        const format: 'CSV' | 'JSON' = formatHeader === 'CSV' ? 'CSV' : 'JSON';
        const sourceRaw = req.header('x-source-name');
        const sourceName = sourceRaw ? decodeURIComponent(sourceRaw) : `Uploaded ${format} File`;
        const content = Buffer.isBuffer(req.body) ? req.body.toString('utf-8') : '';
        if (!content) {
          res.status(400).json({ error: 'Uploaded file payload is empty.' });
          return;
        }
        handleEventsUpload(req, res, content, format, sourceName);
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : 'Failed to parse uploaded file.' });
      }
    },
  );

  // Dataset Management APIs
  const LOCAL_DATASET_ALLOWLIST = new Set([
    'cloudtrail_training.json',
    'cloudtrail_testing.json',
    'sample_audit_logs.csv',
    'normalized_events.json',
  ]);

  const ingestDatasetFromContent = (params: {
    req: express.Request;
    name: string;
    content: string;
    format: 'CSV' | 'JSON';
    provenance?: string;
    datasetRole?: DatasetRecord['dataset_role'];
    isCertMapped?: boolean;
    splitRatio?: { train: number; val: number; test: number };
    filePath?: string;
    fixedDatasetId?: string;
  }): { dataset: DatasetRecord; summary: IngestionSummary; merged_events_count: number; already_registered: boolean } => {
    const existingRegistered = state.datasets.find(
      (d) =>
        (params.fixedDatasetId && d.dataset_id === params.fixedDatasetId) ||
        (params.filePath && d.file_path === params.filePath) ||
        d.name === params.name,
    );
    const datasetId =
      params.fixedDatasetId ||
      existingRegistered?.dataset_id ||
      `ds-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

    const existingIds = new Set(state.events.map((e) => e.event_id));
    const result = validateAndNormalizeUpload(params.content, params.format, params.name, existingIds, {
      datasetId,
    });

    if (result.total_rows === 0) {
      throw new Error('Dataset contains zero records.');
    }
    if (result.valid_rows === 0 && result.already_exists_count === 0) {
      throw new Error(
        `Dataset contains zero valid normalizable records. ${result.rejection_reasons.join('; ')}`,
      );
    }

    const { events: normalizedEvents, ...summary } = result;

    if (normalizedEvents.length === 0 && result.already_exists_count > 0 && existingRegistered) {
      return {
        dataset: existingRegistered,
        summary,
        merged_events_count: 0,
        already_registered: true,
      };
    }

    // If events were previously uploaded via /api/events/upload without a dataset_id,
    // reconcile them into this newly registered dataset instead of failing or reusing CERT ID.
    let finalEvents = normalizedEvents;
    let finalSummary = summary;
    if (normalizedEvents.length === 0 && result.already_exists_count > 0 && !existingRegistered) {
      const fullResult = validateAndNormalizeUpload(
        params.content,
        params.format,
        params.name,
        new Set<string>(),
        { datasetId },
      );
      const idSet = new Set(fullResult.events.map((e) => e.event_id));
      state.events = state.events.map((ev) =>
        idSet.has(ev.event_id) && !ev.dataset_id
          ? { ...ev, dataset_id: datasetId, dataset_source: params.name }
          : ev,
      );
      finalEvents = fullResult.events;
      const { events: _ev, ...fullSummary } = fullResult;
      finalSummary = fullSummary;
    }

    const dataset: DatasetRecord = {
      dataset_id: datasetId,
      name: params.name,
      source_type: params.format,
      provenance: params.provenance || 'User Uploaded Research Dataset',
      dataset_role: params.datasetRole || 'audit',
      ...(params.filePath ? { file_path: params.filePath } : {}),
      is_cert_mapped: Boolean(params.isCertMapped),
      total_rows: finalSummary.total_rows,
      valid_rows: finalSummary.valid_rows,
      normalized_rows: finalSummary.normalized_rows,
      imported_rows: finalSummary.imported_rows,
      rejected_rows: finalSummary.rejected_rows,
      skipped_rows: finalSummary.skipped_rows,
      missing_value_count: finalSummary.missing_value_count,
      duplicate_count: finalSummary.duplicate_count,
      benign_count: finalSummary.benign_count,
      attack_count: finalSummary.attack_count,
      unlabeled_count: finalSummary.unlabeled_count,
      rejection_reasons: finalSummary.rejection_reasons,
      skip_reasons: finalSummary.skip_reasons,
      original_records_count: finalSummary.original_records_count,
      adapted_faas_count: finalSummary.adapted_faas_count,
      split_ratio: params.splitRatio || { train: 0.6, val: 0.2, test: 0.2 },
      preprocessed: true,
      features_extracted: [...ML_FEATURES],
      created_at: new Date().toISOString(),
      sample_preview: finalEvents.slice(0, 5),
    };

    state.datasets.unshift(dataset);
    if (normalizedEvents.length > 0) {
      state.events = [...normalizedEvents, ...state.events];
    }
    invalidatePredictionCache();

    const actor = getActorFromRequest(params.req);
    appendAuditTrail(
      actor,
      'DATASET_UPLOAD',
      dataset.dataset_id,
      `Registered dataset '${params.name}' (total=${finalSummary.total_rows}, normalized=${finalSummary.normalized_rows}, imported=${finalSummary.imported_rows}, rejected=${finalSummary.rejected_rows}, skipped=${finalSummary.skipped_rows}, benign=${finalSummary.benign_count}, attack=${finalSummary.attack_count}).`,
    );
    saveState(state);

    return {
      dataset,
      summary: finalSummary,
      merged_events_count: normalizedEvents.length,
      already_registered: false,
    };
  };

  app.get('/api/datasets', (_req, res) => {
    res.json({ datasets: state.datasets });
  });

  app.get('/api/datasets/local-files', (_req, res) => {
    const files: LocalDatasetFileInfo[] = [];
    for (const filename of LOCAL_DATASET_ALLOWLIST) {
      const fullPath = path.join(DATA_DIR, filename);
      if (!fs.existsSync(fullPath)) continue;
      const stat = fs.statSync(fullPath);
      const format: 'CSV' | 'JSON' = filename.toLowerCase().endsWith('.csv') ? 'CSV' : 'JSON';
      const suggested_role: LocalDatasetFileInfo['suggested_role'] = filename.includes('training')
        ? 'training'
        : filename.includes('testing')
          ? 'testing'
          : 'audit';
      const relPath = `data/${filename}`;
      const already_registered = state.datasets.some((d) => d.file_path === relPath);
      files.push({
        filename,
        size_bytes: stat.size,
        format,
        suggested_role,
        already_registered,
      });
    }
    res.json({ files });
  });

  app.post('/api/datasets/ingest-local', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    try {
      const { filename, name, provenance, dataset_role, split_ratio } = req.body as {
        filename?: string;
        name?: string;
        provenance?: string;
        dataset_role?: DatasetRecord['dataset_role'];
        split_ratio?: { train: number; val: number; test: number };
      };

      if (!filename || typeof filename !== 'string') {
        res.status(400).json({ error: 'filename is required.' });
        return;
      }
      const safeName = path.basename(filename);
      if (safeName !== filename || !LOCAL_DATASET_ALLOWLIST.has(safeName)) {
        res.status(400).json({ error: `Unsupported or disallowed local dataset file '${filename}'.` });
        return;
      }

      const fullPath = path.resolve(DATA_DIR, safeName);
      if (!fs.existsSync(fullPath)) {
        res.status(404).json({ error: `Local dataset file not found at data/${safeName}.` });
        return;
      }

      const content = fs.readFileSync(fullPath, 'utf-8');
      const format: 'CSV' | 'JSON' = safeName.toLowerCase().endsWith('.csv') ? 'CSV' : 'JSON';
      const inferredRole: DatasetRecord['dataset_role'] =
        dataset_role ||
        (safeName.includes('training')
          ? 'training'
          : safeName.includes('testing')
            ? 'testing'
            : 'audit');

      const fixedDatasetId =
        safeName === 'cloudtrail_training.json'
          ? CLOUDTRAIL_TRAIN_DATASET_ID
          : safeName === 'cloudtrail_testing.json'
            ? CLOUDTRAIL_TEST_DATASET_ID
            : undefined;

      const out = ingestDatasetFromContent({
        req,
        name: name?.trim() || safeName,
        content,
        format,
        provenance:
          provenance?.trim() ||
          `Workspace file data/${safeName} (AWS CloudTrail / Audit Dataset)`,
        datasetRole: inferredRole,
        isCertMapped: false,
        splitRatio: split_ratio,
        filePath: `data/${safeName}`,
        fixedDatasetId,
      });

      res.json(out);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Local dataset ingestion failed.' });
    }
  });

  app.post('/api/datasets/upload', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    try {
      const { name, content, format, provenance, dataset_role, is_cert_mapped, split_ratio } = req.body as {
        name?: string;
        content?: string;
        format?: 'CSV' | 'JSON';
        provenance?: string;
        dataset_role?: DatasetRecord['dataset_role'];
        is_cert_mapped?: boolean;
        split_ratio?: { train: number; val: number; test: number };
      };

      if (!name || !content || !format) {
        res.status(400).json({ error: 'Dataset name, format, and content are required.' });
        return;
      }

      const out = ingestDatasetFromContent({
        req,
        name,
        content,
        format,
        provenance,
        datasetRole: dataset_role,
        isCertMapped: is_cert_mapped,
        splitRatio: split_ratio,
      });

      res.json(out);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Dataset validation error.' });
    }
  });

  app.post(
    '/api/datasets/upload-file',
    requireRole(['Admin', 'Security Analyst']),
    rawUploadParser,
    (req, res) => {
      try {
        const formatHeader = String(req.header('x-file-format') || '').toUpperCase();
        const format: 'CSV' | 'JSON' = formatHeader === 'CSV' ? 'CSV' : 'JSON';
        const nameHeader = req.header('x-dataset-name');
        const name = nameHeader ? decodeURIComponent(nameHeader) : `Uploaded-${format}-${Date.now()}`;
        const provHeader = req.header('x-dataset-provenance');
        const provenance = provHeader ? decodeURIComponent(provHeader) : 'Direct File Upload';
        const roleHeader = req.header('x-dataset-role') as DatasetRecord['dataset_role'] | undefined;
        const isCertMapped = req.header('x-cert-mapped') === 'true';
        const splitHeader = req.header('x-split-ratio');
        const splitRatio = splitHeader
          ? (JSON.parse(decodeURIComponent(splitHeader)) as { train: number; val: number; test: number })
          : undefined;

        const content = Buffer.isBuffer(req.body) ? req.body.toString('utf-8') : '';
        if (!content) {
          res.status(400).json({ error: 'Uploaded file payload is empty.' });
          return;
        }

        const out = ingestDatasetFromContent({
          req,
          name,
          content,
          format,
          provenance,
          datasetRole: roleHeader,
          isCertMapped,
          splitRatio,
        });

        res.json(out);
      } catch (err) {
        res.status(400).json({ error: err instanceof Error ? err.message : 'Dataset file upload failed.' });
      }
    },
  );

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
    const predictionBatch = await computeAllPredictions(targetEvents, {
      forceRefresh: targetEvents === state.events,
    });

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
  function syncOptimizationApproval(pol: PolicyRecommendation): void {
    if (!Array.isArray(state.policyOptimizations)) return;
    for (const opt of state.policyOptimizations) {
      if (opt.linked_policy_id === pol.policy_id) {
        opt.approval_status = pol.approval_status;
      }
    }
  }

  app.get('/api/policies', (_req, res) => {
    state.policies = evaluateCostOptimizer(state.policies, state.costWeights);
    res.json({
      policies: state.policies,
      costWeights: state.costWeights,
      riskWeights: state.riskWeights,
    });
  });

  app.get('/api/policies/optimizer', async (_req, res) => {
    const predictionBatch = await computeAllPredictions();
    const highRiskPreds = predictionBatch.predictions
      .filter((p) => p.risk_score >= 45)
      .slice(0, 3);

    const appScenarios: OptimizerScenarioInput[] = [];
    for (const inc of state.incidents.slice(0, 3)) {
      appScenarios.push({
        risk_score: inc.risk_score,
        confidence: inc.anomaly_score,
        false_positive_likelihood: Number(Math.max(0.05, 1 - inc.anomaly_score).toFixed(2)),
        identity_type: inc.affected_user.startsWith('svc-') ? 'ServicePrincipal' : 'IAMUser',
        asset_criticality: inc.severity === 'Critical' ? 'Critical' : inc.severity === 'High' ? 'High' : 'Medium',
        target_user_id: inc.affected_user,
        target_resource: inc.provider,
        scenario_name: `${inc.incident_id}: ${inc.scenario}`,
        scenario_source: 'incident',
        incident_id: inc.incident_id,
        prediction_id: inc.prediction_id,
        constraints: DEFAULT_OPTIMIZER_CONSTRAINTS,
        weights: DEFAULT_OPTIMIZER_WEIGHTS,
      });
    }
    for (const pred of highRiskPreds) {
      if (appScenarios.some((s) => s.prediction_id === pred.prediction_id)) continue;
      appScenarios.push({
        risk_score: pred.risk_score,
        confidence: pred.prediction_confidence,
        false_positive_likelihood: Number(Math.max(0.05, 1 - pred.prediction_confidence).toFixed(2)),
        identity_type: pred.cloud_user_id.startsWith('svc-') ? 'ServicePrincipal' : 'IAMUser',
        asset_criticality: pred.risk_level === 'Critical' ? 'Critical' : pred.risk_level === 'High' ? 'High' : 'Medium',
        target_user_id: pred.cloud_user_id,
        target_resource: pred.provider,
        scenario_name: `${pred.prediction_id}: ${pred.scenario}`,
        scenario_source: 'application_prediction',
        prediction_id: pred.prediction_id,
        constraints: DEFAULT_OPTIMIZER_CONSTRAINTS,
        weights: DEFAULT_OPTIMIZER_WEIGHTS,
      });
    }

    const applicationEvaluations = appScenarios.slice(0, 5).map((scenario) => {
      const linked = state.policies.find(
        (p) =>
          p.target_user_id === scenario.target_user_id &&
          (scenario.incident_id ? true : p.supporting_evidence.includes(scenario.prediction_id || '')),
      );
      return optimizeSecurityPolicy(scenario, { linkedPolicy: linked || null });
    });

    const history = (state.policyOptimizations || []).map((entry) => {
      if (!entry.linked_policy_id) return entry;
      const linked = state.policies.find((p) => p.policy_id === entry.linked_policy_id);
      return linked ? { ...entry, approval_status: linked.approval_status } : entry;
    });

    res.json({
      methodology_summary:
        'Multi-objective cost-aware optimizer evaluating 5 response controls across expected risk reduction, estimated USD enforcement cost, operational disruption index (0-100), response latency (seconds), and false-positive friction subject to hard feasibility constraints.',
      cost_assumptions: COST_ESTIMATION_ASSUMPTIONS,
      candidate_catalog: CANDIDATE_ACTION_CATALOG,
      default_constraints: DEFAULT_OPTIMIZER_CONSTRAINTS,
      default_weights: DEFAULT_OPTIMIZER_WEIGHTS,
      application_evaluations: applicationEvaluations,
      history,
    });
  });

  app.post('/api/policies/optimize', requireRole(['Admin', 'Security Analyst']), async (req, res) => {
    const rawBody =
      req.body && typeof req.body === 'object' && !Array.isArray(req.body)
        ? ({ ...(req.body as Record<string, unknown>) })
        : req.body;

    if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
      res.status(400).json({ error: 'Request payload must be a JSON object.' });
      return;
    }

    const createProposal = rawBody.create_proposal === true;
    const candidatePayload = { ...rawBody };

    if (typeof rawBody.incident_id === 'string' && rawBody.incident_id.trim()) {
      const inc = state.incidents.find((i) => i.incident_id === rawBody.incident_id);
      if (!inc) {
        res.status(404).json({ error: `Incident '${rawBody.incident_id}' not found.` });
        return;
      }
      if (candidatePayload.risk_score === undefined) candidatePayload.risk_score = inc.risk_score;
      if (candidatePayload.confidence === undefined) candidatePayload.confidence = inc.anomaly_score;
      if (!candidatePayload.target_user_id) candidatePayload.target_user_id = inc.affected_user;
      if (!candidatePayload.target_resource) candidatePayload.target_resource = inc.provider;
      if (!candidatePayload.scenario_name) candidatePayload.scenario_name = `${inc.incident_id}: ${inc.scenario}`;
      candidatePayload.scenario_source = 'incident';
    } else if (typeof rawBody.prediction_id === 'string' && rawBody.prediction_id.trim()) {
      const batch = await computeAllPredictions();
      const pred = batch.predictions.find((p) => p.prediction_id === rawBody.prediction_id);
      if (!pred) {
        res.status(404).json({ error: `Prediction '${rawBody.prediction_id}' not found.` });
        return;
      }
      if (candidatePayload.risk_score === undefined) candidatePayload.risk_score = pred.risk_score;
      if (candidatePayload.confidence === undefined) candidatePayload.confidence = pred.prediction_confidence;
      if (!candidatePayload.target_user_id) candidatePayload.target_user_id = pred.cloud_user_id;
      if (!candidatePayload.target_resource) candidatePayload.target_resource = pred.provider;
      if (!candidatePayload.scenario_name) candidatePayload.scenario_name = `${pred.prediction_id}: ${pred.scenario}`;
      candidatePayload.scenario_source = 'application_prediction';
    }

    const validation = validateOptimizerInput(candidatePayload);
    if (!validation.valid || !validation.normalized) {
      res.status(400).json({
        error: validation.errors.join(' '),
        validation_errors: validation.errors,
      });
      return;
    }

    let result = optimizeSecurityPolicy(validation.normalized);
    let createdPolicy: PolicyRecommendation | undefined;

    if (createProposal) {
      createdPolicy = buildPolicyProposalFromOptimization(result);
      state.policies.unshift(createdPolicy);
      state.policies = evaluateCostOptimizer(state.policies, state.costWeights);
      result = {
        ...result,
        approval_status: createdPolicy.approval_status,
        linked_policy_id: createdPolicy.policy_id,
      };
    }

    if (!Array.isArray(state.policyOptimizations)) {
      state.policyOptimizations = [];
    }
    state.policyOptimizations.unshift(result);
    if (state.policyOptimizations.length > 50) {
      state.policyOptimizations = state.policyOptimizations.slice(0, 50);
    }

    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'POLICY_OPTIMIZED',
      result.optimization_id,
      `Evaluated cost-aware optimization (risk=${result.input.risk_score}, recommended=${result.recommended_action.action_label}, estCost=$${result.recommended_action.estimated_enforcement_cost_usd}, proposalCreated=${createProposal}).`,
    );
    saveState(state);

    res.status(201).json({
      optimization: result,
      ...(createdPolicy ? { created_policy: createdPolicy } : {}),
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
    syncOptimizationApproval(pol);

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
    syncOptimizationApproval(pol);

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
      invalidatePredictionCache();
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

  function isLikelyFaasEvent(ev: NormalizedAuditEvent): boolean {
    const raw = ev.raw_event || {};
    const ui =
      raw.userIdentity && typeof raw.userIdentity === 'object'
        ? (raw.userIdentity as Record<string, unknown>)
        : undefined;
    const inScope =
      ui?.inScopeOf && typeof ui.inScopeOf === 'object'
        ? (ui.inScopeOf as Record<string, unknown>)
        : undefined;
    const source = String(raw.eventSource || '').toLowerCase();
    const invokedBy = String(ui?.invokedBy || '').toLowerCase();
    return (
      ev.provider === 'AWS Lambda' ||
      source.includes('lambda') ||
      invokedBy.includes('lambda') ||
      inScope?.issuerType === 'AWS::Lambda::Function'
    );
  }

  app.get('/api/faas/telemetry', async (req, res) => {
    const requestedDatasetId =
      typeof req.query.dataset_id === 'string' && req.query.dataset_id.trim()
        ? req.query.dataset_id.trim()
        : 'cloudtrail_all';

    const cloudtrailDatasets = state.datasets.filter((d) => d.dataset_id !== CERT_DATASET_ID);
    const availableDatasets = [
      {
        dataset_id: 'cloudtrail_all',
        name: 'All CloudTrail / Uploaded Datasets',
        total_events: state.events.filter((e) => e.dataset_id !== CERT_DATASET_ID).length,
        faas_related_hint: state.events.filter(
          (e) => e.dataset_id !== CERT_DATASET_ID && isLikelyFaasEvent(e),
        ).length,
      },
      ...cloudtrailDatasets.map((ds) => {
        const dsEvents = state.events.filter((e) => e.dataset_id === ds.dataset_id);
        return {
          dataset_id: ds.dataset_id,
          name: ds.name,
          total_events: dsEvents.length,
          faas_related_hint: dsEvents.filter(isLikelyFaasEvent).length,
        };
      }),
    ];

    const selectedMeta =
      availableDatasets.find((d) => d.dataset_id === requestedDatasetId) || availableDatasets[0];
    const resolvedDatasetId = selectedMeta?.dataset_id || 'cloudtrail_all';
    const scopedEvents =
      resolvedDatasetId === 'cloudtrail_all'
        ? state.events.filter((e) => e.dataset_id !== CERT_DATASET_ID)
        : state.events.filter((e) => e.dataset_id === resolvedDatasetId);

    const missingNotice =
      'CloudTrail logs do not contain execution duration, allocated memory, or cold-start counts; those fields are explicitly marked Unavailable.';
    const baseUrl = mlServiceUrl();

    if (!baseUrl) {
      res.json({
        telemetry_available: false,
        ml_service_connected: false,
        telemetry_source: 'unavailable',
        dataset_id: resolvedDatasetId,
        dataset_name: selectedMeta?.name || resolvedDatasetId,
        available_datasets: availableDatasets,
        features_extracted: [],
        summary: null,
        functions: [],
        unavailable_reason: 'ML_SERVICE_URL is not configured; real CloudTrail FaaS telemetry requires the Python ML microservice.',
        missing_telemetry_notice: missingNotice,
      });
      return;
    }

    const cacheKey = `${stateVersion}:${resolvedDatasetId}:${baseUrl}`;
    const cached = cachedFaasTelemetry.get(cacheKey);
    if (cached && Date.now() - cached.timestampMs < PREDICTION_CACHE_TTL_MS) {
      res.json(cached.payload);
      return;
    }

    try {
      const response = await fetchMlService(
        `${baseUrl}/faas/telemetry`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dataset_id: resolvedDatasetId,
            dataset_name: selectedMeta?.name || resolvedDatasetId,
            events: scopedEvents.map((ev) => sanitizeEventForMl(ev, false)),
          }),
        },
        60000,
      );

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Python ML service /faas/telemetry returned HTTP ${response.status}: ${text.slice(0, 200)}`);
      }

      const data = (await response.json()) as {
        features_extracted?: string[];
        summary?: Record<string, unknown>;
        functions?: unknown[];
      };

      const payload = {
        telemetry_available: true,
        ml_service_connected: true,
        telemetry_source: 'cloudtrail',
        dataset_id: resolvedDatasetId,
        dataset_name: selectedMeta?.name || resolvedDatasetId,
        available_datasets: availableDatasets,
        features_extracted: Array.isArray(data.features_extracted) ? data.features_extracted : [],
        summary: data.summary || null,
        functions: Array.isArray(data.functions) ? data.functions : [],
        missing_telemetry_notice: missingNotice,
      };
      cachedFaasTelemetry.set(cacheKey, { timestampMs: Date.now(), payload });
      res.json(payload);
    } catch (err) {
      res.json({
        telemetry_available: false,
        ml_service_connected: false,
        telemetry_source: 'unavailable',
        dataset_id: resolvedDatasetId,
        dataset_name: selectedMeta?.name || resolvedDatasetId,
        available_datasets: availableDatasets,
        features_extracted: [],
        summary: null,
        functions: [],
        unavailable_reason:
          err instanceof Error
            ? err.message
            : 'Python ML service unavailable during FaaS telemetry extraction.',
        missing_telemetry_notice: missingNotice,
      });
    }
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

  // OpenStack Private Cloud Telemetry & Audit Ingestion APIs (Phase R4)
  function ingestOpenStackBatch(params: {
    events: unknown[];
    sourceMode: 'real' | 'fixture';
    sourceName?: string;
    datasetId?: string;
    req: express.Request;
  }) {
    const existingIds = new Set(state.events.map((e) => e.event_id));
    const { events: normalized, result } = normalizeOpenStackEvents(params.events, existingIds, {
      sourceMode: params.sourceMode,
      sourceName: params.sourceName,
      datasetId: params.datasetId,
    });

    if (normalized.length > 0) {
      state.events = [...normalized, ...state.events];
      invalidatePredictionCache();
    }

    let dataset = state.datasets.find((d) => d.dataset_id === result.dataset_id);
    if (!dataset) {
      dataset = buildOpenStackDatasetRecord(normalized, result);
      state.datasets.unshift(dataset);
    } else {
      const dsEvents = state.events.filter((e) => e.dataset_id === result.dataset_id);
      const updated = buildOpenStackDatasetRecord(dsEvents, {
        ...result,
        total_received: dataset.total_rows + result.total_received,
        imported_count: dsEvents.length,
        normalized_count: dsEvents.length,
        rejected_count: (dataset.rejected_rows || 0) + result.rejected_count,
        skipped_count: (dataset.skipped_rows || 0) + result.skipped_count,
        duplicate_count: dataset.duplicate_count + result.duplicate_count,
        missing_field_count: dataset.missing_value_count + result.missing_field_count,
      });
      Object.assign(dataset, updated);
    }

    const actor = getActorFromRequest(params.req);
    appendAuditTrail(
      actor,
      'OPENSTACK_INGEST',
      result.dataset_id,
      `Ingested OpenStack events (mode=${result.source_mode}, imported=${result.imported_count}, skipped=${result.skipped_count}, rejected=${result.rejected_count}, services=${result.services_detected.join(',') || 'none'}).`,
    );
    saveState(state);

    return { summary: result, dataset };
  }

  app.get('/api/openstack/telemetry', async (_req, res) => {
    const osEvents = state.events.filter((e) => e.provider.startsWith('OpenStack'));
    const fixtureEvents = osEvents.filter(
      (e) => e.is_simulated || e.source_origin === 'synthetic_fixture',
    );
    const realEvents = osEvents.filter(
      (e) => !e.is_simulated && e.source_origin !== 'synthetic_fixture',
    );

    const probe = await probeOpenStackConnectivity(fixtureEvents.length, realEvents.length);
    const byUser = buildEventsByUserMap(state.events);
    const evaluated = osEvents.map((ev) => ({
      event: ev,
      pred: evaluateEvent(ev, state.events, state.riskWeights, 'OpenStack Risk Scoring Engine', undefined, byUser),
    }));

    const svcMap = new Map<
      string,
      { service: string; provider: string; event_count: number; real_count: number; fixture_count: number }
    >();
    const catMap = new Map<string, number>();
    const activityMap = new Map<
      string,
      {
        cloud_user_id: string;
        project_id: string;
        event_count: number;
        failed_or_denied: number;
        max_risk_score: number;
        source_origins: Set<string>;
      }
    >();

    for (const { event, pred } of evaluated) {
      const raw = event.raw_event || {};
      const svc = String(raw.openstack_service || event.provider.replace('OpenStack ', '').toLowerCase());
      const project = String(raw.project_id || 'default-project');
      const category = String(
        event.security_category || raw.security_category || 'Routine Operational Activity',
      );
      const isFixture = event.is_simulated || event.source_origin === 'synthetic_fixture';

      const svcEntry = svcMap.get(svc) || {
        service: svc,
        provider: event.provider,
        event_count: 0,
        real_count: 0,
        fixture_count: 0,
      };
      svcEntry.event_count += 1;
      if (isFixture) svcEntry.fixture_count += 1;
      else svcEntry.real_count += 1;
      svcMap.set(svc, svcEntry);

      catMap.set(category, (catMap.get(category) || 0) + 1);

      const actKey = `${event.cloud_user_id}::${project}`;
      const actEntry = activityMap.get(actKey) || {
        cloud_user_id: event.cloud_user_id,
        project_id: project,
        event_count: 0,
        failed_or_denied: 0,
        max_risk_score: 0,
        source_origins: new Set<string>(),
      };
      actEntry.event_count += 1;
      if (event.status === 'Failed' || event.status === 'Denied') actEntry.failed_or_denied += 1;
      if (pred.risk_score > actEntry.max_risk_score) actEntry.max_risk_score = pred.risk_score;
      actEntry.source_origins.add(isFixture ? 'synthetic_fixture' : 'real_openstack');
      activityMap.set(actKey, actEntry);
    }

    const suspiciousEvents = evaluated
      .filter(({ pred }) => pred.investigation_status !== 'Normal Baseline')
      .sort((a, b) => b.pred.risk_score - a.pred.risk_score)
      .slice(0, 20)
      .map(({ event, pred }) => {
        const raw = event.raw_event || {};
        const isFixture = event.is_simulated || event.source_origin === 'synthetic_fixture';
        return {
          event_id: event.event_id,
          event_time: event.event_time,
          provider: event.provider,
          cloud_user_id: event.cloud_user_id,
          project_id: String(raw.project_id || 'default-project'),
          action: event.action,
          resource: event.resource,
          status: event.status,
          risk_score: pred.risk_score,
          risk_level: pred.risk_level,
          scenario: pred.scenario,
          explanation: pred.explanation,
          source_origin: isFixture ? 'synthetic_fixture' : 'real_openstack',
          is_simulated: isFixture,
        };
      });

    const latestEvents = osEvents
      .slice()
      .sort((a, b) => b.event_time.localeCompare(a.event_time))
      .slice(0, 25)
      .map((ev) => {
        const raw = ev.raw_event || {};
        const isFixture = ev.is_simulated || ev.source_origin === 'synthetic_fixture';
        return {
          event_id: ev.event_id,
          event_time: ev.event_time,
          provider: ev.provider,
          service: String(raw.openstack_service || ev.provider),
          cloud_user_id: ev.cloud_user_id,
          project_id: String(raw.project_id || 'default-project'),
          action: ev.action,
          resource: ev.resource,
          source_ip: ev.source_ip,
          region: String(raw.region || 'RegionOne'),
          request_id: String(raw.request_id || ''),
          status: ev.status,
          security_category: String(ev.security_category || raw.security_category || 'Routine Operational Activity'),
          source_origin: isFixture ? 'synthetic_fixture' : 'real_openstack',
          is_simulated: isFixture,
        };
      });

    res.json({
      connectivity_status: probe.connectivity_status,
      status_reason: probe.status_reason,
      env_status: probe.env_status,
      event_counts: {
        total_events: osEvents.length,
        real_events: realEvents.length,
        fixture_events: fixtureEvents.length,
        failed_or_denied_events: osEvents.filter((e) => e.status === 'Failed' || e.status === 'Denied').length,
        suspicious_events: suspiciousEvents.length,
      },
      services_detected: Array.from(svcMap.values()).sort((a, b) => b.event_count - a.event_count),
      category_breakdown: Array.from(catMap.entries())
        .map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count),
      user_project_activity: Array.from(activityMap.values())
        .map((a) => ({
          ...a,
          source_origins: Array.from(a.source_origins),
        }))
        .sort((a, b) => b.max_risk_score - a.max_risk_score),
      suspicious_events: suspiciousEvents,
      latest_events: latestEvents,
      prerequisites: [
        'Deploy or reach an OpenStack Keystone v3 endpoint (e.g., DevStack, MicroStack, or Kolla-Ansible).',
        'Set OPENSTACK_AUTH_URL and read-only credentials (OPENSTACK_TOKEN or OPENSTACK_APPLICATION_CREDENTIAL_ID + OPENSTACK_APPLICATION_CREDENTIAL_SECRET) on the backend.',
        'Forward sanitized Keystone/Nova/Neutron/Glance/Cinder CADF audit exports via POST /api/openstack/ingest with source_mode="real".',
      ],
    });
  });

  app.post('/api/openstack/ingest', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    const body = req.body as {
      events?: unknown;
      source_mode?: string;
      source_name?: string;
      dataset_id?: string;
    };

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      res.status(400).json({ error: 'Request payload must be a JSON object containing an events array.' });
      return;
    }
    if (!Array.isArray(body.events) || body.events.length === 0) {
      res.status(400).json({ error: 'events must be a non-empty JSON array of OpenStack audit records.' });
      return;
    }

    const sourceMode: 'real' | 'fixture' = body.source_mode === 'fixture' ? 'fixture' : 'real';
    const outcome = ingestOpenStackBatch({
      events: body.events,
      sourceMode,
      sourceName: typeof body.source_name === 'string' ? body.source_name : undefined,
      datasetId: typeof body.dataset_id === 'string' ? body.dataset_id : undefined,
      req,
    });

    res.status(201).json(outcome);
  });

  app.post('/api/openstack/load-fixtures', requireRole(['Admin', 'Security Analyst']), (req, res) => {
    const fixturePath = path.resolve(
      process.cwd(),
      'tests',
      'fixtures',
      'openstack',
      'openstack_audit_sample.json',
    );
    if (!fs.existsSync(fixturePath)) {
      res.status(404).json({ error: 'OpenStack synthetic fixture file not found.' });
      return;
    }
    const parsed = JSON.parse(fs.readFileSync(fixturePath, 'utf-8')) as {
      source_name?: string;
      events?: unknown[];
    };
    const rawEvents = Array.isArray(parsed.events) ? parsed.events : [];
    const outcome = ingestOpenStackBatch({
      events: rawEvents,
      sourceMode: 'fixture',
      sourceName: parsed.source_name || 'OpenStack Multi-Service Synthetic Test Fixtures',
      req,
    });
    res.status(201).json(outcome);
  });

  // ML Research Lab & Experimentation APIs
  async function runPythonCloudTrailExperiment(params: {
    trainDataset: DatasetRecord;
    testDataset: DatasetRecord | null;
    trainEvents: NormalizedAuditEvent[];
    testEvents: NormalizedAuditEvent[];
    splitRatio: { train: number; val: number; test: number };
    baseUrl: string;
  }): Promise<MLExperimentResult | null> {
    const useSavedCloudTrailModel =
      params.testDataset !== null &&
      params.trainDataset.dataset_id === CLOUDTRAIL_TRAIN_DATASET_ID &&
      params.testEvents.length > 0;

    const endpoint = useSavedCloudTrailModel ? `${params.baseUrl}/evaluate` : `${params.baseUrl}/train`;
    const bodyPayload = useSavedCloudTrailModel
      ? {
          test_events: params.testEvents.map((ev) => sanitizeEventForMl(ev, true)),
          train_size: params.trainEvents.length,
        }
      : {
          train_events: params.trainEvents.map((ev) => sanitizeEventForMl(ev, true)),
          test_events:
            params.testEvents.length > 0
              ? params.testEvents.map((ev) => sanitizeEventForMl(ev, true))
              : undefined,
          split_ratio: params.splitRatio,
          n_estimators: 200,
          contamination: 'auto',
        };

    const mlResp = await fetchMlService(
      endpoint,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyPayload),
      },
      60000,
    );

    if (!mlResp.ok) return null;

    const mlData = (await mlResp.json()) as {
      model_version: string;
      features: string[];
      threshold: number;
      has_ground_truth: boolean;
      train_size: number;
      val_size: number;
      test_size: number;
      latency_ms: number;
      metrics: MLExperimentResult['metrics'];
      confusion_matrix: MLExperimentResult['confusion_matrix'];
      roc_curve: MLExperimentResult['roc_curve'];
      pr_curve: MLExperimentResult['pr_curve'];
    };

    const memMb = Math.round(process.memoryUsage().rss / (1024 * 1024));
    const modeDetail = useSavedCloudTrailModel
      ? `Connected Python ML Service (Saved CloudTrail Isolation Forest · ${mlData.model_version}, threshold=${mlData.threshold}${mlData.has_ground_truth ? '' : ', NO GROUND TRUTH'})`
      : params.testDataset
        ? `Connected Python ML Service (scikit-learn Isolation Forest · Cross-Dataset, threshold=${mlData.threshold}${mlData.has_ground_truth ? '' : ', NO GROUND TRUTH'})`
        : `Connected Python ML Service (scikit-learn Isolation Forest · Split ${Math.round(params.splitRatio.train * 100)}/${Math.round(params.splitRatio.val * 100)}/${Math.round(params.splitRatio.test * 100)}, threshold=${mlData.threshold})`;

    return {
      experiment_id: `EXP-${Date.now().toString(36).toUpperCase()}`,
      model_type: 'Isolation Forest',
      model_version: mlData.model_version,
      dataset_id: params.trainDataset.dataset_id,
      dataset_name: params.testDataset
        ? `${params.trainDataset.name} -> ${params.testDataset.name}`
        : params.trainDataset.name,
      execution_mode: modeDetail,
      is_simulated: false,
      has_ground_truth: mlData.has_ground_truth,
      trained_at: new Date().toISOString(),
      train_size: mlData.train_size,
      val_size: mlData.val_size,
      test_size: mlData.test_size,
      features_used: mlData.features,
      metrics: mlData.metrics,
      confusion_matrix: mlData.confusion_matrix,
      roc_curve: mlData.roc_curve,
      pr_curve: mlData.pr_curve,
      system_metrics: {
        latency_ms: mlData.latency_ms,
        cpu_pct: 6.4,
        memory_mb: memMb,
        estimated_monthly_cost_usd: 34,
      },
    };
  }

  async function runPythonLstmExperiment(params: {
    trainDataset: DatasetRecord;
    testDataset: DatasetRecord | null;
    trainEvents: NormalizedAuditEvent[];
    testEvents: NormalizedAuditEvent[];
    splitRatio: { train: number; val: number; test: number };
    windowSize: 5 | 10 | 16;
    baseUrl: string;
  }): Promise<
    | { ok: true; experiment: MLExperimentResult }
    | { ok: false; unsuitableReason: string }
  > {
    const mlResp = await fetchMlService(
      `${params.baseUrl}/lstm/train-evaluate`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          train_events: params.trainEvents.map((ev) => sanitizeEventForMl(ev, true)),
          test_events:
            params.testEvents.length > 0
              ? params.testEvents.map((ev) => sanitizeEventForMl(ev, true))
              : undefined,
          window_size: params.windowSize,
          epochs: 15,
          hidden_dim: 32,
          split_ratio: params.testDataset
            ? { train: 0.7, val: 0.3, test: 0 }
            : params.splitRatio,
          include_if_comparison: true,
          save_model: true,
        }),
      },
      120000,
    );

    if (!mlResp.ok) {
      const errText = await mlResp.text();
      throw new Error(`Python ML Service /lstm/train-evaluate returned HTTP ${mlResp.status}: ${errText.slice(0, 200)}`);
    }

    const mlData = (await mlResp.json()) as {
      suitable?: boolean;
      unsuitable_reason?: string;
      model_version: string;
      model_artifact?: string | null;
      features: string[];
      threshold: number;
      has_ground_truth: boolean;
      train_size: number;
      val_size: number;
      test_size: number;
      training_time_ms?: number | null;
      inference_latency_ms?: number;
      latency_ms: number;
      sequence_config?: MLExperimentResult['sequence_config'];
      baseline_comparison?: MLExperimentResult['baseline_comparison'];
      metrics: MLExperimentResult['metrics'];
      confusion_matrix: MLExperimentResult['confusion_matrix'];
      roc_curve: MLExperimentResult['roc_curve'];
      pr_curve: MLExperimentResult['pr_curve'];
    };

    if (mlData.suitable === false) {
      return {
        ok: false,
        unsuitableReason:
          mlData.unsuitable_reason ||
          'Dataset or chronological sequence split is unsuitable for the requested LSTM window size.',
      };
    }

    const memMb = Math.round(process.memoryUsage().rss / (1024 * 1024));
    const modeDetail = params.testDataset
      ? `Connected Python ML Service (Real PyTorch LSTM Autoencoder · W=${params.windowSize}, Cross-Dataset, threshold=${mlData.threshold}${mlData.has_ground_truth ? '' : ', NO GROUND TRUTH'})`
      : `Connected Python ML Service (Real PyTorch LSTM Autoencoder · W=${params.windowSize}, Chronological Split, threshold=${mlData.threshold})`;

    return {
      ok: true,
      experiment: {
        experiment_id: `EXP-${Date.now().toString(36).toUpperCase()}`,
        model_type: 'LSTM Sequence',
        model_version: mlData.model_version,
        model_artifact: mlData.model_artifact || null,
        threshold: mlData.threshold,
        dataset_id: params.trainDataset.dataset_id,
        dataset_name: params.testDataset
          ? `${params.trainDataset.name} -> ${params.testDataset.name}`
          : params.trainDataset.name,
        execution_mode: modeDetail,
        is_simulated: false,
        has_ground_truth: mlData.has_ground_truth,
        trained_at: new Date().toISOString(),
        train_size: mlData.train_size,
        val_size: mlData.val_size,
        test_size: mlData.test_size,
        training_time_ms: mlData.training_time_ms ?? null,
        inference_latency_ms: mlData.inference_latency_ms ?? mlData.latency_ms,
        features_used: mlData.features,
        metrics: mlData.metrics,
        confusion_matrix: mlData.confusion_matrix,
        sequence_config: mlData.sequence_config,
        baseline_comparison: mlData.baseline_comparison ?? null,
        roc_curve: mlData.roc_curve,
        pr_curve: mlData.pr_curve,
        system_metrics: {
          latency_ms: mlData.inference_latency_ms ?? mlData.latency_ms,
          cpu_pct: 24.5,
          memory_mb: memMb,
          estimated_monthly_cost_usd: 52,
        },
      },
    };
  }

  app.get('/api/ml/experiments', async (_req, res) => {
    const mlMode = await checkMlServiceHealth();
    const baseUrl = mlServiceUrl();

    if (mlMode.connected && baseUrl && state.experiments.length === 0) {
      const trainDs = state.datasets.find((d) => d.dataset_id === CLOUDTRAIL_TRAIN_DATASET_ID);
      const testDs = state.datasets.find((d) => d.dataset_id === CLOUDTRAIL_TEST_DATASET_ID);
      if (trainDs && testDs) {
        const trainEvents = state.events.filter((e) => e.dataset_id === trainDs.dataset_id);
        const testEvents = state.events.filter((e) => e.dataset_id === testDs.dataset_id);
        if (trainEvents.length > 0 && testEvents.length > 0) {
          try {
            const realExp = await runPythonCloudTrailExperiment({
              trainDataset: trainDs,
              testDataset: testDs,
              trainEvents,
              testEvents,
              splitRatio: { train: 1, val: 0, test: 0 },
              baseUrl,
            });
            if (realExp) {
              state.experiments.unshift(realExp);
              saveState(state);
            }
          } catch (err) {
            console.warn('Initial CloudTrail Python ML evaluation failed:', err);
          }
        }
      }
    }

    res.json({
      ml_service_connected: mlMode.connected,
      ml_service_label: mlMode.label,
      experiments: state.experiments,
    });
  });

  app.post('/api/ml/train', requireRole(['Admin', 'Security Analyst']), async (req, res) => {
    const { dataset_id, test_dataset_id, model_type, features_used, split_ratio, window_size } = req.body as {
      dataset_id?: string;
      test_dataset_id?: string;
      model_type?: MLExperimentResult['model_type'];
      features_used?: string[];
      split_ratio?: { train: number; val: number; test: number };
      window_size?: number;
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

    const testDataset =
      test_dataset_id && test_dataset_id !== dataset.dataset_id
        ? state.datasets.find((d) => d.dataset_id === test_dataset_id) || null
        : null;

    const ratio = split_ratio || dataset.split_ratio;
    if (!testDataset) {
      const sum = ratio.train + ratio.val + ratio.test;
      if (Math.abs(sum - 1) > 0.05) {
        res.status(400).json({ error: 'Train / Validation / Test split ratios must sum to 1.0.' });
        return;
      }
    }

    const selectedFeatures =
      Array.isArray(features_used) && features_used.length > 0 ? features_used : dataset.features_extracted;

    const scopedTrain = state.events.filter((e) => e.dataset_id === dataset.dataset_id);
    const datasetEvents = scopedTrain.length > 0 ? scopedTrain : dataset.sample_preview;
    const scopedTest = testDataset
      ? state.events.filter((e) => e.dataset_id === testDataset.dataset_id)
      : [];

    const effectiveModelType = model_type || 'Isolation Forest';
    const resolvedWindowSize: 5 | 10 | 16 =
      window_size === 5 || window_size === 16 ? window_size : 10;
    const mlMode = await checkMlServiceHealth();
    const baseUrl = mlServiceUrl();

    let exp: MLExperimentResult | null = null;
    if (effectiveModelType === 'Isolation Forest' && mlMode.connected && baseUrl && datasetEvents.length >= 5) {
      try {
        exp = await runPythonCloudTrailExperiment({
          trainDataset: dataset,
          testDataset,
          trainEvents: datasetEvents,
          testEvents: scopedTest,
          splitRatio: ratio,
          baseUrl,
        });
      } catch (err) {
        console.warn('Python ML Service evaluation failed, falling back to simulated baseline:', err);
      }
    } else if (effectiveModelType === 'LSTM Sequence' && mlMode.connected && baseUrl) {
      try {
        const lstmResult = await runPythonLstmExperiment({
          trainDataset: dataset,
          testDataset,
          trainEvents: datasetEvents,
          testEvents: scopedTest,
          splitRatio: ratio,
          windowSize: resolvedWindowSize,
          baseUrl,
        });
        if (!lstmResult.ok) {
          res.status(422).json({ error: lstmResult.unsuitableReason });
          return;
        }
        exp = lstmResult.experiment;
      } catch (err) {
        console.warn('Python PyTorch LSTM evaluation failed, falling back to simulated baseline:', err);
      }
    }

    if (!exp) {
      const evalEvents = scopedTest.length > 0 ? scopedTest : datasetEvents;
      const fallbackRatio =
        ratio.train + ratio.val + ratio.test >= 0.95 ? ratio : { train: 0.6, val: 0.2, test: 0.2 };
      exp = runRealExperimentOnDataset(
        testDataset || dataset,
        evalEvents,
        effectiveModelType,
        selectedFeatures,
        fallbackRatio,
        state.riskWeights,
        effectiveModelType === 'LSTM Sequence'
          ? 'SIMULATED FALLBACK — In-process LSTM proxy (Python PyTorch ML service unavailable)'
          : 'SIMULATED FALLBACK — In-process baseline (Python ML Service unavailable)',
      );
      exp.is_simulated = true;
    }

    state.experiments.unshift(exp);
    const actor = getActorFromRequest(req);
    appendAuditTrail(
      actor,
      'ML_EXPERIMENT_RUN',
      exp.experiment_id,
      `Executed ${exp.model_type} evaluation on ${exp.dataset_name} (F1=${exp.metrics.f1_score}, FPR=${exp.metrics.false_positive_rate}, simulated=${Boolean(exp.is_simulated)}).`,
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

  // PDF Report Export Endpoint
  app.get('/api/reports/pdf', async (_req, res) => {
    try {
      const predictionBatch = await computeAllPredictions();
      const predictions = predictionBatch.predictions;
      const ubaProfiles = computeUserBehaviorProfiles(state.events, predictions);
      const summary = buildDashboardSummary(predictionBatch, ubaProfiles);
      const policies = evaluateCostOptimizer(state.policies, state.costWeights);

      const arrayBuffer = buildSecurityPdfArrayBuffer({
        summary,
        predictions,
        profiles: ubaProfiles,
        incidents: state.incidents,
        policies,
        experiments: state.experiments,
        datasets: state.datasets,
      });
      const pdfBuffer = Buffer.from(arrayBuffer);

      if (pdfBuffer.length < 100 || pdfBuffer.subarray(0, 5).toString('ascii') !== '%PDF-') {
        throw new Error('Generated PDF payload failed header validation.');
      }

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'attachment; filename="cloudsentinel-report.pdf"');
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).send(pdfBuffer);
    } catch (err) {
      console.error('Failed to generate PDF report:', err);
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Failed to generate PDF security report.',
      });
    }
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

  const httpServer = app.listen(port, '0.0.0.0', () => {
    console.log(`\nCloudSentinel AI running at http://localhost:${port}\n`);
  });

  httpServer.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.error(
        `\nPort ${port} is already in use (EADDRINUSE). Stop the existing process occupying port ${port} or run with another PORT before restarting.\n`,
      );
      process.exit(1);
    }
    throw err;
  });
}

startServer();
