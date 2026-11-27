import React, { useState } from 'react';
import { ArrowRight } from 'lucide-react';

export interface PipelineStage {
  id: string;
  step: string;
  title: string;
  targetPage: string;
  inputContract: string;
  outputContract: string;
  mechanism: string;
}

const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: 'logs',
    step: '01',
    title: 'Cloud Audit Logs',
    targetPage: 'cloud-environments',
    inputContract: 'AWS CloudTrail, Lambda, IAM, OpenStack Keystone/Nova',
    outputContract: 'Raw JSON/CSV event streams',
    mechanism: 'Read-only event ingestion across public cloud, private OpenStack, and serverless FaaS.',
  },
  {
    id: 'collect',
    step: '02',
    title: 'Log Collection',
    targetPage: 'audit-logs',
    inputContract: 'Raw multi-cloud exports & uploads',
    outputContract: 'Buffered event batches',
    mechanism: 'Ingests JSON/CSV batches and validates upload size, encoding, and schema presence.',
  },
  {
    id: 'normalize',
    step: '03',
    title: 'Event Normalization',
    targetPage: 'audit-logs',
    inputContract: 'Heterogeneous provider schemas',
    outputContract: 'event_id, provider, event_time, cloud_user_id, action, resource, source_ip, status, raw_event',
    mechanism: 'Maps AWS eventSource/userIdentity and OpenStack Nova/Keystone fields into a unified schema.',
  },
  {
    id: 'validate',
    step: '04',
    title: 'Data Validation',
    targetPage: 'audit-logs',
    inputContract: 'Normalized candidate records',
    outputContract: 'Deduplicated, quality-scored events',
    mechanism: 'Detects missing values, duplicate event_ids, and records data completeness score.',
  },
  {
    id: 'features',
    step: '05',
    title: 'Feature Extraction',
    targetPage: 'model-evaluation',
    inputContract: 'Validated normalized events',
    outputContract: '10-dimensional numerical feature vectors',
    mechanism: 'Extracts off-hours indicator, unusual IP, action criticality, resource sensitivity, FaaS burst, and dormancy.',
  },
  {
    id: 'uba',
    step: '06',
    title: 'User Behaviour Profiling',
    targetPage: 'user-behavior',
    inputContract: 'Historical per-identity event windows',
    outputContract: 'Normal baseline & deviation vector',
    mechanism: 'Computes baseline login frequency, working hours, known IP ranges, and API call norms.',
  },
  {
    id: 'anomaly',
    step: '07',
    title: 'Anomaly Detection',
    targetPage: 'threat-detection',
    inputContract: 'Feature vectors & behavior sequences',
    outputContract: 'Anomaly Score (0.00 - 1.00)',
    mechanism: 'Isolation Forest baseline & LSTM sequential behavior model (or Node baseline proxy when Python service is offline).',
  },
  {
    id: 'confidence',
    step: '08',
    title: 'Confidence Assessment',
    targetPage: 'threat-detection',
    inputContract: 'Anomaly Score + data quality + corroborating events',
    outputContract: 'Prediction Confidence & Investigation Gate',
    mechanism: 'Flags low-confidence or sparse-telemetry events as "Requires Additional Investigation".',
  },
  {
    id: 'risk',
    step: '09',
    title: 'Risk Scoring',
    targetPage: 'security-policies',
    inputContract: 'Anomaly + privilege + resource + action + frequency + evidence',
    outputContract: 'Transparent Risk Score (0-100) & Severity',
    mechanism: 'Weighted linear risk decomposition with configurable administrator weights.',
  },
  {
    id: 'incident',
    step: '10',
    title: 'Incident Generation',
    targetPage: 'incidents',
    inputContract: 'High-confidence / elevated risk predictions',
    outputContract: 'Open SOC Incident with evidence',
    mechanism: 'Creates trackable Open / Investigating / Resolved incidents linked to supporting audit events.',
  },
  {
    id: 'recommend',
    step: '11',
    title: 'Adaptive Policy Recommendation',
    targetPage: 'security-policies',
    inputContract: 'Incident & UBA evidence',
    outputContract: 'Least-privilege / MFA / FaaS cap proposals',
    mechanism: 'Generates least-privilege, MFA, and rate-limiting recommendations tied to specific evidence.',
  },
  {
    id: 'cost',
    step: '12',
    title: 'Cost & Security Evaluation',
    targetPage: 'cost-optimization',
    inputContract: 'Candidate policy + operational/latency costs',
    outputContract: 'Weighted optimizer score & trade-off matrix',
    mechanism: 'Evaluates residual risk reduction against monthly cost, performance impact, and monitoring overhead.',
  },
  {
    id: 'approve',
    step: '13',
    title: 'Administrator Approval',
    targetPage: 'security-policies',
    inputContract: 'Ranked policy recommendation',
    outputContract: 'Audited human approval decision',
    mechanism: 'Strict RBAC human-in-the-loop gate: Admin approval required before any policy state change.',
  },
];

export function InteractiveResearchPipeline({
  onNavigate,
}: {
  onNavigate?: (pageId: string) => void;
}) {
  const [selectedId, setSelectedId] = useState<string>('anomaly');
  const activeStage = PIPELINE_STAGES.find((s) => s.id === selectedId) || PIPELINE_STAGES[0];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-1.5">
        {PIPELINE_STAGES.map((stage, idx) => {
          const isActive = stage.id === selectedId;
          return (
            <React.Fragment key={stage.id}>
              <button
                type="button"
                onClick={() => setSelectedId(stage.id)}
                className={`px-2.5 py-1.5 rounded text-xs font-medium transition-colors text-left whitespace-nowrap ${
                  isActive
                    ? 'bg-indigo-600 text-white'
                    : 'bg-slate-900 text-slate-300 border border-slate-800 hover:border-slate-700 hover:text-white'
                }`}
              >
                <span className="font-mono text-[10px] opacity-75 mr-1.5">{stage.step}</span>
                {stage.title}
              </button>
              {idx < PIPELINE_STAGES.length - 1 && (
                <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" aria-hidden="true" />
              )}
            </React.Fragment>
          );
        })}
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div>
          <div className="text-slate-400 mb-1">Stage {activeStage.step} · Mechanism</div>
          <div className="font-medium text-slate-100 mb-1">{activeStage.title}</div>
          <p className="text-slate-300 leading-relaxed">{activeStage.mechanism}</p>
        </div>
        <div>
          <div className="text-slate-400 mb-1">Input Contract</div>
          <p className="font-mono text-[11px] text-indigo-300 leading-relaxed">{activeStage.inputContract}</p>
        </div>
        <div className="flex flex-col justify-between gap-3">
          <div>
            <div className="text-slate-400 mb-1">Output Artifact</div>
            <p className="font-mono text-[11px] text-emerald-300 leading-relaxed">{activeStage.outputContract}</p>
          </div>
          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate(activeStage.targetPage)}
              className="self-start px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-100 font-medium transition-colors"
            >
              Open Module
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function ArchitectureBlueprintsPanel() {
  const [activeDiagram, setActiveDiagram] = useState<'system' | 'er' | 'ml' | 'api'>('system');

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg w-fit">
        {[
          { id: 'system', label: 'System & Cloud Architecture' },
          { id: 'ml', label: 'ML Detection Workflow' },
          { id: 'er', label: 'PostgreSQL ER Schema' },
          { id: 'api', label: 'FastAPI & Docker Topology' },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveDiagram(tab.id as typeof activeDiagram)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              activeDiagram === tab.id
                ? 'bg-indigo-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {activeDiagram === 'system' && (
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-5 overflow-x-auto">
          <svg viewBox="0 0 880 260" className="w-full min-w-[680px] h-64">
            {/* Cloud Sources */}
            <rect x="16" y="24" width="175" height="210" rx="6" fill="#0F172A" stroke="#334155" />
            <text x="103" y="46" textAnchor="middle" className="fill-slate-200 text-xs font-semibold">Cloud & FaaS Sources</text>
            {['AWS CloudTrail', 'AWS Lambda (FaaS)', 'AWS IAM Policies', 'OpenStack Keystone', 'OpenStack Nova'].map((lbl, i) => (
              <g key={lbl}>
                <rect x="28" y={62 + i * 32} width="151" height="24" rx="4" fill="#1E293B" stroke="#475569" />
                <text x="103" y={78 + i * 32} textAnchor="middle" className="fill-slate-300 text-[10px] font-mono">{lbl}</text>
              </g>
            ))}

            <line x1="191" y1="128" x2="232" y2="128" stroke="#818CF8" strokeWidth="2" />

            {/* FastAPI Ingestion & Normalization */}
            <rect x="232" y="24" width="190" height="210" rx="6" fill="#0F172A" stroke="#4F46E5" />
            <text x="327" y="46" textAnchor="middle" className="fill-indigo-300 text-xs font-semibold">FastAPI Control Plane</text>
            {['Event Normalizer', 'Schema & Quality Check', 'UBA Baseline Builder', 'Risk & Cost Optimizer', 'RBAC & Audit Trail'].map((lbl, i) => (
              <g key={lbl}>
                <rect x="244" y={62 + i * 32} width="166" height="24" rx="4" fill="#1E1B4B" stroke="#4338CA" />
                <text x="327" y={78 + i * 32} textAnchor="middle" className="fill-indigo-100 text-[10px] font-mono">{lbl}</text>
              </g>
            ))}

            <line x1="422" y1="90" x2="465" y2="90" stroke="#38BDF8" strokeWidth="2" />
            <line x1="422" y1="175" x2="465" y2="175" stroke="#10B981" strokeWidth="2" />

            {/* Python ML Service */}
            <rect x="465" y="24" width="185" height="115" rx="6" fill="#0F172A" stroke="#0284C7" />
            <text x="557" y="46" textAnchor="middle" className="fill-sky-300 text-xs font-semibold">Python ML Microservice</text>
            <rect x="478" y="58" width="159" height="28" rx="4" fill="#0C4A6E" stroke="#0369A1" />
            <text x="557" y="76" textAnchor="middle" className="fill-sky-100 text-[10px] font-mono">Scikit-learn Isolation Forest</text>
            <rect x="478" y="96" width="159" height="28" rx="4" fill="#0C4A6E" stroke="#0369A1" />
            <text x="557" y="114" textAnchor="middle" className="fill-sky-100 text-[10px] font-mono">PyTorch LSTM Sequence Net</text>

            {/* PostgreSQL */}
            <rect x="465" y="152" width="185" height="82" rx="6" fill="#0F172A" stroke="#059669" />
            <text x="557" y="174" textAnchor="middle" className="fill-emerald-300 text-xs font-semibold">PostgreSQL 16 Store</text>
            <text x="557" y="194" textAnchor="middle" className="fill-slate-300 text-[10px] font-mono">audit_events · uba_profiles</text>
            <text x="557" y="212" textAnchor="middle" className="fill-slate-300 text-[10px] font-mono">incidents · policies · ml_runs</text>

            <line x1="650" y1="128" x2="690" y2="128" stroke="#A78BFA" strokeWidth="2" />

            {/* SOC Frontend */}
            <rect x="690" y="48" width="174" height="160" rx="6" fill="#0F172A" stroke="#7C3AED" />
            <text x="777" y="72" textAnchor="middle" className="fill-violet-300 text-xs font-semibold">React SOC Console</text>
            <text x="777" y="98" textAnchor="middle" className="fill-slate-300 text-[10px]">Threat & Incident Triage</text>
            <text x="777" y="118" textAnchor="middle" className="fill-slate-300 text-[10px]">Cost vs Risk Trade-off</text>
            <text x="777" y="138" textAnchor="middle" className="fill-slate-300 text-[10px]">ML Research Lab</text>
            <text x="777" y="158" textAnchor="middle" className="fill-slate-300 text-[10px]">Admin Approval Gate</text>
            <text x="777" y="182" textAnchor="middle" className="fill-amber-300 text-[10px] font-mono">PDF / CSV Reporting</text>
          </svg>
        </div>
      )}

      {activeDiagram === 'ml' && (
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-5 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="border border-slate-800 rounded p-4 space-y-2">
            <div className="font-semibold text-indigo-300">Track A: Isolation Forest (Point Anomaly Baseline)</div>
            <p className="text-slate-300 leading-relaxed">
              Operates on 10 extracted tabular features per normalized event (`is_after_hours`, `is_unusual_ip`,
              `action_criticality`, `resource_sensitivity`, `is_faas_spike`, `is_bulk_download`, etc.). Computes
              path-depth isolation scores without requiring labeled attack signatures.
            </p>
          </div>
          <div className="border border-slate-800 rounded p-4 space-y-2">
            <div className="font-semibold text-sky-300">Track B: PyTorch LSTM (Sequential Behaviour Detector)</div>
            <p className="text-slate-300 leading-relaxed">
              Processes sliding sequences of W=12 chronological actions per `cloud_user_id` to detect multi-step
              attack chains (e.g., Failed Login → ConsoleLogin → AttachUserPolicy → GetSecretValue → BulkGetObject).
              Runs in standalone Python ML container (`ml_service/`).
            </p>
          </div>
          <div className="border border-slate-800 rounded p-4 space-y-2 md:col-span-2">
            <div className="font-semibold text-emerald-300">Confidence-Aware Gating & Transparent Risk Decomposition</div>
            <p className="text-slate-300 leading-relaxed">
              Anomaly Score (model output), Prediction Confidence (evidence count & data quality score), and Risk Score
              (weighted combination of anomaly, user privilege, resource sensitivity, action criticality, frequency, and
              evidence) are kept mathematically distinct. Low-confidence outputs are gated to "Requires Additional
              Investigation".
            </p>
          </div>
        </div>
      )}

      {activeDiagram === 'er' && (
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-5 overflow-x-auto">
          <pre className="text-[11px] font-mono text-slate-300 leading-relaxed">
{`users (user_id PK, email UNIQUE, full_name, role [Admin|Security Analyst|Viewer], is_active)
  ├──< audit_trail (trail_id PK, actor_id FK->users, action_type, target, details, created_at)
  └──< incidents (incident_id PK, assigned_to FK->users, status, severity, affected_user, prediction_id FK)

datasets (dataset_id PK, name, source_type, provenance, is_cert_mapped, total_rows, missing_count, duplicate_count)
  ├──< audit_events (event_id PK, dataset_id FK->datasets, provider, event_time, cloud_user_id, action, resource, source_ip, status, raw_event JSONB)
  └──< ml_experiments (experiment_id PK, dataset_id FK->datasets, model_type, accuracy, precision, recall, f1, fpr, confusion_matrix JSONB)

audit_events ──< threat_predictions (prediction_id PK, event_id FK, anomaly_score, prediction_confidence, risk_score, investigation_status)
threat_predictions ──< policy_recommendations (policy_id PK, target_user_id, category, security_gain, cost_before, cost_after, approval_status, approved_by FK->users)`}
          </pre>
        </div>
      )}

      {activeDiagram === 'api' && (
        <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-5 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="space-y-1.5 font-mono text-[11px] text-slate-300">
            <div className="text-indigo-300 font-sans font-semibold text-xs mb-2">FastAPI & Express Endpoint Map</div>
            <div>POST /api/auth/login · GET /api/users</div>
            <div>GET/POST /api/events · /api/events/upload</div>
            <div>GET/POST /api/datasets · /api/datasets/upload</div>
            <div>GET /api/uba/users · POST /api/detection/run</div>
            <div>GET/POST/PATCH /api/incidents</div>
            <div>GET/POST /api/policies/:id/approve | reject</div>
            <div>PUT /api/settings/weights · GET/POST /api/ml/train</div>
            <div>GET /api/reports/export?format=csv</div>
          </div>
          <div className="space-y-1.5 font-mono text-[11px] text-slate-300">
            <div className="text-emerald-300 font-sans font-semibold text-xs mb-2">Docker Compose Services (Repo Blueprint)</div>
            <div>1. frontend (React + Vite SPA · Port 3000)</div>
            <div>2. backend_api (FastAPI Uvicorn · Port 8000)</div>
            <div>3. ml_service (PyTorch LSTM + Scikit-learn · Port 8001)</div>
            <div>4. postgres (PostgreSQL 16-alpine · Port 5432)</div>
            <div className="text-slate-400 font-sans pt-2">
              Full Python FastAPI, ML service, PostgreSQL SQL migrations, and Docker configuration are included under
              /backend, /ml_service, and /database.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
