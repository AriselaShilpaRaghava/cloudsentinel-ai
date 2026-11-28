import React, { useEffect, useState } from 'react';
import { Database, FileUp, Play, Server, Upload, X } from 'lucide-react';
import { api } from '../services/api';
import type { AuthUser, DatasetRecord, LocalDatasetFileInfo, MLExperimentResult } from '../types/security';
import { DataStateWrapper, SectionHeader, SimulationNotice, SurfacePanel } from '../components/ui/SocPrimitives';
import { CurveChart } from '../components/charts/SocCharts';

const ALL_FEATURES = [
  'is_faas',
  'failed_event_flag',
  'is_iam_user',
  'is_anonymous_or_account',
  'recon_action_flag',
  'sensitive_action_flag',
  'log_s3_burst_1m',
  'log_unique_buckets_5m',
];

const SAMPLE_CERT_DATASET_CSV = `event_id,provider,event_time,cloud_user_id,action,resource,source_ip,status,ground_truth_label
cert-901,CERT Mapped,2026-11-14T10:15:00Z,k.sato@corp.internal,GetObject,s3://corp-compliance-archive/audit.pdf,10.24.12.19,Success,0
cert-902,CERT Mapped,2026-11-14T11:20:00Z,l.vance@corp.internal,PutObject,s3://corp-eng-docs/design.md,10.24.15.88,Success,0
cert-903,AWS Lambda,2026-11-15T02:11:00Z,d.kline@corp.internal,InvokeFunction,arn:aws:lambda:us-east-1:904812:function:fn-payroll-disbursement,185.220.101.42,Success,1
cert-904,CERT Mapped,2026-11-15T01:40:00Z,m.chen@corp.internal,BulkGetObject,s3://prod-finance-ledger-vault/dump.tar.gz,185.220.101.42,Success,1
cert-905,AWS IAM,2026-11-15T01:42:00Z,m.chen@corp.internal,AttachUserPolicy,arn:aws:iam::aws:policy/AdministratorAccess,185.220.101.42,Success,1
cert-906,OpenStack Nova,2026-11-14T14:10:00Z,r.patel@corp.internal,NovaListServers,nova:regionOne/eng-sandbox/servers,10.24.19.45,Success,0`;

export function ModelEvaluationPage({ currentUser }: { currentUser: AuthUser }) {
  const [experiments, setExperiments] = useState<MLExperimentResult[]>([]);
  const [datasets, setDatasets] = useState<DatasetRecord[]>([]);
  const [mlConnected, setMlConnected] = useState(false);
  const [mlLabel, setMlLabel] = useState('');
  const [selectedExp, setSelectedExp] = useState<MLExperimentResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Training Lab Config
  const [selectedDatasetId, setSelectedDatasetId] = useState('');
  const [testDatasetId, setTestDatasetId] = useState('');
  const [modelType, setModelType] = useState<MLExperimentResult['model_type']>('Isolation Forest');
  const [windowSize, setWindowSize] = useState<5 | 10 | 16>(10);
  const [selectedFeatures, setSelectedFeatures] = useState<string[]>(ALL_FEATURES);
  const [trainSplit, setTrainSplit] = useState(0.6);
  const [valSplit, setValSplit] = useState(0.2);
  const [running, setRunning] = useState(false);
  const [expFeedback, setExpFeedback] = useState<string | null>(null);

  // Dataset upload form
  const [showDsForm, setShowDsForm] = useState(false);
  const [localFiles, setLocalFiles] = useState<LocalDatasetFileInfo[]>([]);
  const [dsName, setDsName] = useState('CERT-r4.2-Custom-Cloud-Slice');
  const [dsFormat, setDsFormat] = useState<'CSV' | 'JSON'>('CSV');
  const [dsRole, setDsRole] = useState<DatasetRecord['dataset_role']>('evaluation');
  const [dsProvenance, setDsProvenance] = useState('CERT r4.2 adapted cloud actions + simulated FaaS invocations');
  const [dsContent, setDsContent] = useState(SAMPLE_CERT_DATASET_CSV);
  const [dsFile, setDsFile] = useState<File | null>(null);
  const [dsSubmitting, setDsSubmitting] = useState(false);
  const [ingestingLocal, setIngestingLocal] = useState<string | null>(null);
  const [dsErr, setDsErr] = useState<string | null>(null);

  const testSplit = Math.max(0.1, Number((1 - trainSplit - valSplit).toFixed(2)));

  const loadLab = async () => {
    setLoading(true);
    setError(null);
    try {
      const [mlRes, dsRes, localRes] = await Promise.all([
        api.getMlExperiments(),
        api.getDatasets(),
        api.getLocalDatasets(),
      ]);
      setExperiments(mlRes.experiments);
      setMlConnected(mlRes.ml_service_connected);
      setMlLabel(mlRes.ml_service_label);
      setDatasets(dsRes.datasets);
      setLocalFiles(localRes.files);
      if (dsRes.datasets.length > 0 && !selectedDatasetId) {
        const trainDs =
          dsRes.datasets.find((d) => d.dataset_id === 'ds-cloudtrail-train' || d.dataset_role === 'training') ||
          dsRes.datasets[0];
        setSelectedDatasetId(trainDs.dataset_id);
        const testDs = dsRes.datasets.find(
          (d) =>
            (d.dataset_id === 'ds-cloudtrail-test' || d.dataset_role === 'testing') &&
            d.dataset_id !== trainDs.dataset_id,
        );
        if (testDs && !testDatasetId) {
          setTestDatasetId(testDs.dataset_id);
        }
      }
      if (mlRes.experiments.length > 0) {
        setSelectedExp((prev) =>
          prev
            ? mlRes.experiments.find((e) => e.experiment_id === prev.experiment_id) || mlRes.experiments[0]
            : mlRes.experiments[0],
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load ML Research Lab.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLab();
  }, []);

  const toggleFeature = (feat: string) => {
    setSelectedFeatures((prev) =>
      prev.includes(feat) ? prev.filter((f) => f !== feat) : [...prev, feat],
    );
  };

  const handleRunExperiment = async (e: React.FormEvent) => {
    e.preventDefault();
    setRunning(true);
    setExpFeedback(null);
    try {
      const res = await api.trainExperiment({
        dataset_id: selectedDatasetId,
        ...(testDatasetId ? { test_dataset_id: testDatasetId } : {}),
        model_type: modelType,
        ...(modelType === 'LSTM Sequence' ? { window_size: windowSize } : {}),
        features_used: selectedFeatures,
        split_ratio: { train: trainSplit, val: valSplit, test: testSplit },
      });
      setExperiments((prev) => [res.experiment, ...prev]);
      setSelectedExp(res.experiment);
      setExpFeedback(
        `Completed experiment ${res.experiment.experiment_id} on ${res.experiment.test_size} held-out test events in ${res.experiment.system_metrics.latency_ms} ms.`,
      );
    } catch (err) {
      setExpFeedback(err instanceof Error ? err.message : 'Experiment failed.');
    } finally {
      setRunning(false);
    }
  };

  const handleDatasetFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.name.toLowerCase().endsWith('.json')) {
      setDsFormat('JSON');
      setDsProvenance(`Uploaded AWS CloudTrail / JSON dataset (${file.name})`);
    } else if (file.name.toLowerCase().endsWith('.csv')) {
      setDsFormat('CSV');
    }
    setDsName(file.name.replace(/\.(json|csv)$/i, ''));
    setDsErr(null);

    if (file.size > 1_000_000) {
      setDsFile(file);
      return;
    }

    setDsFile(null);
    const reader = new FileReader();
    reader.onload = () => {
      setDsContent(String(reader.result || ''));
    };
    reader.readAsText(file);
  };

  const handleUploadDataset = async (e: React.FormEvent) => {
    e.preventDefault();
    setDsErr(null);
    setDsSubmitting(true);
    try {
      const res = dsFile
        ? await api.uploadDatasetFile(dsFile, {
            name: dsName,
            format: dsFormat,
            provenance: dsProvenance,
            dataset_role: dsRole,
            is_cert_mapped: dsFormat === 'CSV',
            split_ratio: { train: trainSplit, val: valSplit, test: testSplit },
          })
        : await api.uploadDataset({
            name: dsName,
            content: dsContent,
            format: dsFormat,
            provenance: dsProvenance,
            dataset_role: dsRole,
            is_cert_mapped: dsFormat === 'CSV',
            split_ratio: { train: trainSplit, val: valSplit, test: testSplit },
          });
      if (!res.already_registered) {
        setDatasets((prev) => [res.dataset, ...prev]);
      }
      setSelectedDatasetId(res.dataset.dataset_id);
      setShowDsForm(false);
      setDsFile(null);
      setExpFeedback(
        `Dataset '${res.dataset.name}' (${res.dataset.dataset_id}): total=${res.summary.total_rows}, normalized=${res.summary.normalized_rows}, imported=${res.summary.imported_rows}, rejected=${res.summary.rejected_rows}, skipped=${res.summary.skipped_rows} (benign=${res.summary.benign_count}, attack=${res.summary.attack_count}).`,
      );
    } catch (err) {
      setDsErr(err instanceof Error ? err.message : 'Dataset upload failed.');
    } finally {
      setDsSubmitting(false);
    }
  };

  const handleIngestLocalDataset = async (file: LocalDatasetFileInfo) => {
    setIngestingLocal(file.filename);
    setDsErr(null);
    try {
      const res = await api.ingestLocalDataset({
        filename: file.filename,
        dataset_role: file.suggested_role,
        split_ratio: { train: trainSplit, val: valSplit, test: testSplit },
      });
      await loadLab();
      setSelectedDatasetId(res.dataset.dataset_id);
      setExpFeedback(
        `${res.already_registered ? 'Already registered' : 'Ingested'} '${res.dataset.name}' (${res.dataset.dataset_id}): total=${res.summary.total_rows}, normalized=${res.summary.normalized_rows}, imported=${res.summary.imported_rows}, rejected=${res.summary.rejected_rows}, skipped=${res.summary.skipped_rows}, benign=${res.summary.benign_count}, attack=${res.summary.attack_count}.`,
      );
    } catch (err) {
      setDsErr(err instanceof Error ? err.message : 'Failed to ingest local dataset.');
    } finally {
      setIngestingLocal(null);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Machine Learning Research Lab & Model Evaluation"
        description="Run real train/validation/test split evaluations across Isolation Forest and sequential baselines, inspect confusion matrices, ROC/PR curves, and measure latency/memory/cost."
        actions={
          <button
            type="button"
            disabled={currentUser.role === 'Viewer'}
            onClick={() => setShowDsForm((v) => !v)}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 rounded-md border border-slate-700 whitespace-nowrap"
          >
            <Upload className="w-3.5 h-3.5" />
            {showDsForm ? 'Close Dataset Upload' : 'Register CERT / Cloud Dataset'}
          </button>
        }
      />

      <SimulationNotice connected={mlConnected} label={mlLabel} />

      {expFeedback && (
        <div className="px-4 py-2.5 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200">
          {expFeedback}
        </div>
      )}

      {showDsForm && (
        <SurfacePanel
          title="Register & Preprocess Research Dataset (JSON or CSV)"
          subtitle="Supports AWS CloudTrail JSON (should_sample ground truth), CERT CSV, or server-side workspace datasets"
        >
          {localFiles.length > 0 && (
            <div className="mb-4 pb-4 border-b border-slate-800 space-y-2 text-xs">
              <div className="text-slate-300 font-medium">Server-Side Workspace Datasets (No Browser Upload Overhead)</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {localFiles.map((lf) => (
                  <div
                    key={lf.filename}
                    className="p-3 bg-slate-950/70 border border-slate-800 rounded flex items-center justify-between gap-2"
                  >
                    <div className="min-w-0">
                      <div className="font-mono text-slate-100 truncate flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        <span>{lf.filename}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        {(lf.size_bytes / (1024 * 1024)).toFixed(2)} MB · {lf.format} · {lf.suggested_role}
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={ingestingLocal !== null || lf.already_registered}
                      onClick={() => handleIngestLocalDataset(lf)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded whitespace-nowrap shrink-0"
                    >
                      <Database className="w-3.5 h-3.5" />
                      {lf.already_registered
                        ? 'Registered'
                        : ingestingLocal === lf.filename
                          ? 'Ingesting...'
                          : 'Ingest on Server'}
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <form onSubmit={handleUploadDataset} className="space-y-3 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <div>
                <label className="block text-slate-300 mb-1">Dataset File (.json or .csv)</label>
                <label className="flex items-center justify-center gap-2 px-3 py-2 bg-slate-950 border border-dashed border-slate-700 hover:border-indigo-500 rounded cursor-pointer text-slate-300">
                  <FileUp className="w-4 h-4 text-indigo-400" />
                  <span>Choose JSON / CSV</span>
                  <input
                    type="file"
                    accept=".csv,.json,text/csv,application/json"
                    onChange={handleDatasetFileChange}
                    className="hidden"
                  />
                </label>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Dataset Name</label>
                <input
                  type="text"
                  required
                  value={dsName}
                  onChange={(e) => setDsName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Format</label>
                <select
                  value={dsFormat}
                  onChange={(e) => setDsFormat(e.target.value as 'CSV' | 'JSON')}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="JSON">JSON (AWS CloudTrail / Normalized)</option>
                  <option value="CSV">CSV (CERT / OpenStack)</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Dataset Role</label>
                <select
                  value={dsRole || 'evaluation'}
                  onChange={(e) => setDsRole(e.target.value as DatasetRecord['dataset_role'])}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="training">Training</option>
                  <option value="testing">Testing</option>
                  <option value="evaluation">Evaluation</option>
                  <option value="audit">Audit</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-slate-300 mb-1">Provenance & Source Citation</label>
              <input
                type="text"
                required
                value={dsProvenance}
                onChange={(e) => setDsProvenance(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
              />
            </div>
            <div>
              <label className="block text-slate-300 mb-1">
                {dsFile ? 'Large File Selected (Direct Binary Stream Upload)' : 'Dataset Content (CloudTrail JSON or CSV)'}
              </label>
              {dsFile ? (
                <div className="p-3 bg-slate-950 border border-indigo-500/40 rounded flex items-center justify-between">
                  <span className="font-mono text-slate-200">
                    {dsFile.name} ({(dsFile.size / (1024 * 1024)).toFixed(2)} MB)
                  </span>
                  <button
                    type="button"
                    onClick={() => setDsFile(null)}
                    className="inline-flex items-center gap-1 px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
                  >
                    <X className="w-3.5 h-3.5" /> Clear
                  </button>
                </div>
              ) : (
                <textarea
                  rows={5}
                  required
                  value={dsContent}
                  onChange={(e) => setDsContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2.5 font-mono text-[11px] text-slate-200"
                />
              )}
            </div>
            {dsErr && <p className="text-rose-400">{dsErr}</p>}
            <button
              type="submit"
              disabled={dsSubmitting}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded"
            >
              {dsSubmitting ? 'Normalizing & Registering...' : 'Validate, Extract Features & Register'}
            </button>
          </form>
        </SurfacePanel>
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadLab}>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          {/* Experiment Configuration Runner */}
          <SurfacePanel title="Experiment Configuration" subtitle="Strict train / val / test separation on selected features">
            <form onSubmit={handleRunExperiment} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Training / Primary Dataset</label>
                <select
                  value={selectedDatasetId}
                  onChange={(e) => {
                    const nextId = e.target.value;
                    setSelectedDatasetId(nextId);
                    if (testDatasetId === nextId) {
                      setTestDatasetId('');
                    }
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  {datasets.map((d) => (
                    <option key={d.dataset_id} value={d.dataset_id}>
                      {d.name} ({(d.imported_rows ?? d.valid_rows).toLocaleString()} rows{d.dataset_role ? ` · ${d.dataset_role}` : ''})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Held-Out Test Dataset (Optional Cross-Dataset Eval)</label>
                <select
                  value={testDatasetId}
                  onChange={(e) => setTestDatasetId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="">None — Stratified Split on Primary Dataset</option>
                  {datasets
                    .filter((d) => d.dataset_id !== selectedDatasetId)
                    .map((d) => (
                      <option key={d.dataset_id} value={d.dataset_id}>
                        {d.name} ({(d.imported_rows ?? d.valid_rows).toLocaleString()} rows{d.dataset_role ? ` · ${d.dataset_role}` : ''})
                      </option>
                    ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Model Architecture</label>
                <select
                  aria-label="Model Architecture"
                  value={modelType}
                  onChange={(e) => setModelType(e.target.value as MLExperimentResult['model_type'])}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="Isolation Forest">Isolation Forest (Saved scikit-learn Baseline)</option>
                  <option value="LSTM Sequence">LSTM Sequence Detector (Real PyTorch Autoencoder)</option>
                  <option value="Transformer (Planned)">Transformer Sequence (Future Extension — Unavailable)</option>
                </select>
              </div>

              {modelType === 'LSTM Sequence' && (
                <div className="p-3 bg-indigo-950/25 border border-indigo-500/30 rounded space-y-2">
                  <label className="block text-indigo-200 font-medium">
                    Sliding Window Size (User / Session Sequence)
                  </label>
                  <select
                    aria-label="LSTM Sliding Window Size"
                    value={windowSize}
                    onChange={(e) => setWindowSize(Number(e.target.value) as 5 | 10 | 16)}
                    className="w-full bg-slate-950 border border-indigo-500/40 rounded px-3 py-1.5 font-mono text-slate-100"
                  >
                    <option value={5}>W = 5 events (Short-horizon burst sensitivity)</option>
                    <option value={10}>W = 10 events (Default session context)</option>
                    <option value={16}>W = 16 events (Extended sequence context)</option>
                  </select>
                  <p className="text-[11px] text-slate-400">
                    Trains PyTorch LSTM Autoencoder on chronological benign sequences only, calibrates threshold on chronological validation sequences only, and compares side-by-side against Isolation Forest on identical eligible test events.
                  </p>
                </div>
              )}

              <div className="grid grid-cols-3 gap-2">
                <div>
                  <label className="block text-slate-400 mb-1">Train Split</label>
                  <input
                    type="number"
                    step={0.05}
                    min={0.4}
                    max={0.8}
                    value={trainSplit}
                    onChange={(e) => setTrainSplit(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Val Split</label>
                  <input
                    type="number"
                    step={0.05}
                    min={0.1}
                    max={0.3}
                    value={valSplit}
                    onChange={(e) => setValSplit(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Test Split</label>
                  <div className="bg-slate-900 border border-slate-800 rounded px-2 py-1.5 font-mono text-indigo-300">
                    {testSplit.toFixed(2)}
                  </div>
                </div>
              </div>

              <div>
                <div className="text-slate-300 mb-1.5">Feature Selection ({selectedFeatures.length}/{ALL_FEATURES.length})</div>
                <div className="grid grid-cols-2 gap-1.5">
                  {ALL_FEATURES.map((feat) => (
                    <label key={feat} className="flex items-center gap-1.5 text-[11px] font-mono text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedFeatures.includes(feat)}
                        onChange={() => toggleFeature(feat)}
                        className="accent-indigo-500"
                      />
                      <span className="truncate">{feat}</span>
                    </label>
                  ))}
                </div>
              </div>

              <button
                type="submit"
                disabled={running || currentUser.role === 'Viewer' || selectedFeatures.length === 0}
                className="w-full inline-flex items-center justify-center gap-2 py-2 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                {running ? 'Training & Evaluating...' : 'Execute Evaluation Experiment'}
              </button>
            </form>
          </SurfacePanel>

          {/* Active Experiment Evaluation Results */}
          {selectedExp ? (
            <div className="xl:col-span-2 space-y-5">
              {(selectedExp.is_simulated || selectedExp.execution_mode.toLowerCase().includes('simulated')) ? (
                <div className="px-4 py-3 bg-amber-950/30 border border-amber-500/40 rounded-lg text-xs text-amber-200">
                  <strong>Simulated Fallback Results (Not Real ML):</strong> Python FastAPI ML Service was unavailable or a proxy model was selected. Connect the Python ML Service and run Isolation Forest or PyTorch LSTM evaluation for real ML metrics.
                </div>
              ) : (
                <div className="px-4 py-2.5 bg-emerald-950/25 border border-emerald-500/30 rounded-lg text-xs text-emerald-200 flex flex-wrap items-center justify-between gap-2">
                  <span>
                    <strong>Real Trained ML Output:</strong> {selectedExp.model_type} ({selectedExp.model_version})
                    {selectedExp.model_artifact ? ` · Checkpoint: ${selectedExp.model_artifact}` : ''}
                  </span>
                  {selectedExp.sequence_config && (
                    <span className="font-mono text-[11px] text-emerald-300">
                      W={selectedExp.sequence_config.window_size} · Eligible={selectedExp.sequence_config.eligible_test_events.toLocaleString()} (Excluded={selectedExp.sequence_config.excluded_test_events.toLocaleString()})
                    </span>
                  )}
                </div>
              )}
              <SurfacePanel
                title={`${selectedExp.model_type} · ${selectedExp.experiment_id}`}
                subtitle={`${selectedExp.execution_mode} · Trained ${selectedExp.trained_at.replace('T', ' ').slice(0, 19)} UTC`}
              >
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 pb-4 border-b border-slate-800 text-xs">
                  {[
                    { label: 'Accuracy', val: selectedExp.metrics.accuracy, supervised: true },
                    { label: 'Precision', val: selectedExp.metrics.precision, supervised: true },
                    { label: 'Recall', val: selectedExp.metrics.recall, supervised: true },
                    { label: 'F1-Score', val: selectedExp.metrics.f1_score, supervised: true },
                    { label: 'ROC AUC', val: selectedExp.metrics.roc_auc, supervised: true },
                    { label: 'PR AUC', val: selectedExp.metrics.pr_auc, supervised: true },
                    { label: 'False Pos Rate', val: selectedExp.metrics.false_positive_rate, supervised: false },
                  ].map((m) => (
                    <div key={m.label} className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                      <div className="text-slate-400 text-[11px]">{m.label}</div>
                      <div className="text-base font-mono tabular-nums font-semibold text-slate-100 mt-0.5">
                        {m.val === undefined || (selectedExp.has_ground_truth === false && m.supervised)
                          ? 'N/A'
                          : `${(m.val * 100).toFixed(1)}%`}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Confusion Matrix + System Resource Metrics */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 py-4 border-b border-slate-800 text-xs">
                  <div>
                    <div className="font-medium text-slate-200 mb-2">
                      Test Split Confusion Matrix (n = {selectedExp.test_size.toLocaleString()})
                    </div>
                    <div className="grid grid-cols-2 gap-2 font-mono tabular-nums text-center">
                      <div className="p-2.5 bg-emerald-950/30 border border-emerald-500/30 rounded">
                        <div className="text-[10px] text-emerald-300">True Positive (TP)</div>
                        <div className="text-lg font-semibold text-emerald-200">{selectedExp.confusion_matrix.tp}</div>
                      </div>
                      <div className="p-2.5 bg-rose-950/30 border border-rose-500/30 rounded">
                        <div className="text-[10px] text-rose-300">False Positive (FP)</div>
                        <div className="text-lg font-semibold text-rose-200">{selectedExp.confusion_matrix.fp}</div>
                      </div>
                      <div className="p-2.5 bg-amber-950/30 border border-amber-500/30 rounded">
                        <div className="text-[10px] text-amber-300">False Negative (FN)</div>
                        <div className="text-lg font-semibold text-amber-200">{selectedExp.confusion_matrix.fn}</div>
                      </div>
                      <div className="p-2.5 bg-slate-900 border border-slate-700 rounded">
                        <div className="text-[10px] text-slate-400">True Negative (TN)</div>
                        <div className="text-lg font-semibold text-slate-100">{selectedExp.confusion_matrix.tn}</div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <div className="font-medium text-slate-200 mb-2">Operational &amp; Compute Footprint</div>
                    <div className="divide-y divide-slate-800 border border-slate-800 rounded px-3">
                      {selectedExp.training_time_ms !== undefined && selectedExp.training_time_ms !== null && (
                        <div className="py-2 flex justify-between">
                          <span className="text-slate-400">Training Time</span>
                          <span className="font-mono tabular-nums text-indigo-300">
                            {selectedExp.training_time_ms} ms
                          </span>
                        </div>
                      )}
                      <div className="py-2 flex justify-between">
                        <span className="text-slate-400">Inference Latency</span>
                        <span className="font-mono tabular-nums text-slate-100">
                          {(selectedExp.inference_latency_ms ?? selectedExp.system_metrics.latency_ms)} ms
                        </span>
                      </div>
                      {selectedExp.sequence_config && (
                        <div className="py-2 flex justify-between">
                          <span className="text-slate-400">Sequence Windows (Benign Train / Val / Test)</span>
                          <span className="font-mono tabular-nums text-slate-200">
                            {selectedExp.sequence_config.benign_train_windows.toLocaleString()} / {selectedExp.sequence_config.val_windows.toLocaleString()} / {selectedExp.sequence_config.test_windows.toLocaleString()}
                          </span>
                        </div>
                      )}
                      <div className="py-2 flex justify-between">
                        <span className="text-slate-400">Memory Footprint (RSS)</span>
                        <span className="font-mono tabular-nums text-slate-100">{selectedExp.system_metrics.memory_mb} MB</span>
                      </div>
                      <div className="py-2 flex justify-between">
                        <span className="text-slate-400">Estimated Inference Cost</span>
                        <span className="font-mono tabular-nums text-indigo-300">
                          ${selectedExp.system_metrics.estimated_monthly_cost_usd}/mo
                        </span>
                      </div>
                    </div>
                    {selectedExp.sequence_config?.validation_calibration_note && (
                      <p className="text-[11px] text-slate-400 mt-2">
                        {selectedExp.sequence_config.validation_calibration_note}
                      </p>
                    )}
                  </div>
                </div>

                {selectedExp.baseline_comparison && (
                  <div className="py-4 border-b border-slate-800 text-xs space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="font-medium text-slate-100">
                        Side-by-Side Comparison on Identical Eligible Test Events (n ={' '}
                        {selectedExp.baseline_comparison.eligible_test_events.toLocaleString()})
                      </div>
                      <span className="text-[11px] font-mono text-indigo-300">
                        PyTorch LSTM (W={selectedExp.sequence_config?.window_size}) vs. Saved {selectedExp.baseline_comparison.model_type}
                      </span>
                    </div>
                    <div className="overflow-x-auto border border-slate-800 rounded">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                            <th className="py-2 px-3 font-medium">Model (Real ML)</th>
                            <th className="py-2 px-3 font-medium text-right">Accuracy</th>
                            <th className="py-2 px-3 font-medium text-right">Precision</th>
                            <th className="py-2 px-3 font-medium text-right">Recall</th>
                            <th className="py-2 px-3 font-medium text-right">F1</th>
                            <th className="py-2 px-3 font-medium text-right">FPR</th>
                            <th className="py-2 px-3 font-medium text-right">ROC-AUC</th>
                            <th className="py-2 px-3 font-medium text-right">PR-AUC</th>
                            <th className="py-2 px-3 font-medium text-right">TP / FP / FN / TN</th>
                            <th className="py-2 px-3 font-medium text-right">Infer (ms)</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                          <tr className="bg-indigo-950/20">
                            <td className="py-2 px-3 font-sans font-medium text-indigo-200">
                              LSTM Autoencoder (W={selectedExp.sequence_config?.window_size})
                            </td>
                            <td className="py-2 px-3 text-right">{(selectedExp.metrics.accuracy * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.metrics.precision * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right text-emerald-300">{(selectedExp.metrics.recall * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.metrics.f1_score * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.metrics.false_positive_rate * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.metrics.roc_auc * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">
                              {selectedExp.metrics.pr_auc !== undefined ? `${(selectedExp.metrics.pr_auc * 100).toFixed(1)}%` : 'N/A'}
                            </td>
                            <td className="py-2 px-3 text-right text-[11px]">
                              {selectedExp.confusion_matrix.tp}/{selectedExp.confusion_matrix.fp}/{selectedExp.confusion_matrix.fn}/{selectedExp.confusion_matrix.tn}
                            </td>
                            <td className="py-2 px-3 text-right">{selectedExp.inference_latency_ms ?? selectedExp.system_metrics.latency_ms}</td>
                          </tr>
                          <tr>
                            <td className="py-2 px-3 font-sans font-medium text-slate-200">
                              Isolation Forest ({selectedExp.baseline_comparison.model_version})
                            </td>
                            <td className="py-2 px-3 text-right">{(selectedExp.baseline_comparison.metrics.accuracy * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.baseline_comparison.metrics.precision * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right text-emerald-300">{(selectedExp.baseline_comparison.metrics.recall * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.baseline_comparison.metrics.f1_score * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.baseline_comparison.metrics.false_positive_rate * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">{(selectedExp.baseline_comparison.metrics.roc_auc * 100).toFixed(1)}%</td>
                            <td className="py-2 px-3 text-right">
                              {selectedExp.baseline_comparison.metrics.pr_auc !== undefined
                                ? `${(selectedExp.baseline_comparison.metrics.pr_auc * 100).toFixed(1)}%`
                                : 'N/A'}
                            </td>
                            <td className="py-2 px-3 text-right text-[11px]">
                              {selectedExp.baseline_comparison.confusion_matrix.tp}/{selectedExp.baseline_comparison.confusion_matrix.fp}/{selectedExp.baseline_comparison.confusion_matrix.fn}/{selectedExp.baseline_comparison.confusion_matrix.tn}
                            </td>
                            <td className="py-2 px-3 text-right">{selectedExp.baseline_comparison.inference_latency_ms}</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* ROC & Precision-Recall Curves */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                  <CurveChart
                    title="ROC Curve (TPR vs FPR)"
                    xLabel="False Positive Rate"
                    yLabel="True Positive Rate"
                    color="#818CF8"
                    diagonalBaseline
                    points={selectedExp.roc_curve.map((pt) => ({ x: pt.fpr, y: pt.tpr }))}
                  />
                  <CurveChart
                    title="Precision-Recall Curve"
                    xLabel="Recall"
                    yLabel="Precision"
                    color="#38BDF8"
                    points={selectedExp.pr_curve.map((pt) => ({ x: pt.recall, y: pt.precision }))}
                  />
                </div>
              </SurfacePanel>

              {/* Experiment History Table */}
              <SurfacePanel title="Executed Experiment Registry" subtitle="Select any run to inspect its curves and confusion matrix">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-3 font-medium">Run ID</th>
                        <th className="py-2 pr-3 font-medium">Model</th>
                        <th className="py-2 pr-3 font-medium">Dataset</th>
                        <th className="py-2 pr-3 font-medium text-right">F1</th>
                        <th className="py-2 pr-3 font-medium text-right">FPR</th>
                        <th className="py-2 font-medium text-right">Latency</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {experiments.map((exp) => (
                        <tr
                          key={exp.experiment_id}
                          onClick={() => setSelectedExp(exp)}
                          className={`cursor-pointer transition-colors ${
                            selectedExp?.experiment_id === exp.experiment_id ? 'bg-indigo-950/35' : 'hover:bg-slate-800/40'
                          }`}
                        >
                          <td className="py-2 pr-3 font-mono text-indigo-300">{exp.experiment_id}</td>
                          <td className="py-2 pr-3 text-slate-100">
                            <span>{exp.model_type}</span>
                            {exp.sequence_config ? ` (W=${exp.sequence_config.window_size})` : ''}
                            <span
                              className={`ml-2 inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                exp.is_simulated
                                  ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                                  : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                              }`}
                            >
                              {exp.is_simulated ? 'Simulated' : 'Real ML'}
                            </span>
                          </td>
                          <td className="py-2 pr-3 text-slate-400">{exp.dataset_name}</td>
                          <td className="py-2 pr-3 text-right font-mono tabular-nums text-emerald-400">
                            {(exp.metrics.f1_score * 100).toFixed(1)}%
                          </td>
                          <td className="py-2 pr-3 text-right font-mono tabular-nums text-slate-300">
                            {(exp.metrics.false_positive_rate * 100).toFixed(1)}%
                          </td>
                          <td className="py-2 text-right font-mono tabular-nums text-slate-400">
                            {exp.system_metrics.latency_ms} ms
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </SurfacePanel>
            </div>
          ) : (
            <div className="xl:col-span-2">
              <SurfacePanel
                title="No Evaluation Experiments Recorded Yet"
                subtitle={
                  mlConnected
                    ? 'Select a training and held-out test dataset on the left and click Execute Evaluation Experiment.'
                    : 'Python FastAPI ML Service is currently disconnected. Start ml_service on port 8001 to run real CloudTrail Isolation Forest evaluations.'
                }
              >
                <p className="text-xs text-slate-400">
                  Simulated metrics are not pre-seeded. All displayed metrics come from executed evaluations, with simulated fallbacks explicitly labeled when the Python ML service is unavailable.
                </p>
              </SurfacePanel>
            </div>
          )}
        </div>
      </DataStateWrapper>
    </div>
  );
}
