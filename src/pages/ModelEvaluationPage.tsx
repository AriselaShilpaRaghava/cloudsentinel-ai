import React, { useEffect, useState } from 'react';
import { Play, Upload } from 'lucide-react';
import { api } from '../services/api';
import type { AuthUser, DatasetRecord, MLExperimentResult } from '../types/security';
import { DataStateWrapper, SectionHeader, SimulationNotice, SurfacePanel } from '../components/ui/SocPrimitives';
import { CurveChart } from '../components/charts/SocCharts';

const ALL_FEATURES = [
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
  const [modelType, setModelType] = useState<MLExperimentResult['model_type']>('Isolation Forest');
  const [selectedFeatures, setSelectedFeatures] = useState<string[]>(ALL_FEATURES);
  const [trainSplit, setTrainSplit] = useState(0.6);
  const [valSplit, setValSplit] = useState(0.2);
  const [running, setRunning] = useState(false);
  const [expFeedback, setExpFeedback] = useState<string | null>(null);

  // Dataset upload form
  const [showDsForm, setShowDsForm] = useState(false);
  const [dsName, setDsName] = useState('CERT-r4.2-Custom-Cloud-Slice');
  const [dsProvenance, setDsProvenance] = useState('CERT r4.2 adapted cloud actions + simulated FaaS invocations');
  const [dsContent, setDsContent] = useState(SAMPLE_CERT_DATASET_CSV);
  const [dsErr, setDsErr] = useState<string | null>(null);

  const testSplit = Math.max(0.1, Number((1 - trainSplit - valSplit).toFixed(2)));

  const loadLab = async () => {
    setLoading(true);
    setError(null);
    try {
      const [mlRes, dsRes] = await Promise.all([api.getMlExperiments(), api.getDatasets()]);
      setExperiments(mlRes.experiments);
      setMlConnected(mlRes.ml_service_connected);
      setMlLabel(mlRes.ml_service_label);
      setDatasets(dsRes.datasets);
      if (dsRes.datasets.length > 0 && !selectedDatasetId) {
        setSelectedDatasetId(dsRes.datasets[0].dataset_id);
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
        model_type: modelType,
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

  const handleUploadDataset = async (e: React.FormEvent) => {
    e.preventDefault();
    setDsErr(null);
    try {
      const res = await api.uploadDataset({
        name: dsName,
        content: dsContent,
        format: 'CSV',
        provenance: dsProvenance,
        is_cert_mapped: true,
        split_ratio: { train: trainSplit, val: valSplit, test: testSplit },
      });
      setDatasets((prev) => [res.dataset, ...prev]);
      setSelectedDatasetId(res.dataset.dataset_id);
      setShowDsForm(false);
      setExpFeedback(`Uploaded and preprocessed dataset '${res.dataset.name}' (${res.dataset.valid_rows} valid rows).`);
    } catch (err) {
      setDsErr(err instanceof Error ? err.message : 'Dataset upload failed.');
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
        <SurfacePanel title="Register & Preprocess Research Dataset (CSV)" subtitle="Validates missing values, duplicates, and CERT-to-cloud/FaaS provenance">
          <form onSubmit={handleUploadDataset} className="space-y-3 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
                <label className="block text-slate-300 mb-1">Provenance & Source Citation</label>
                <input
                  type="text"
                  required
                  value={dsProvenance}
                  onChange={(e) => setDsProvenance(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>
            </div>
            <div>
              <label className="block text-slate-300 mb-1">CSV Content (with ground_truth_label 0/1)</label>
              <textarea
                rows={5}
                required
                value={dsContent}
                onChange={(e) => setDsContent(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded p-2.5 font-mono text-[11px] text-slate-200"
              />
            </div>
            {dsErr && <p className="text-rose-400">{dsErr}</p>}
            <button type="submit" className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded">
              Validate, Extract Features & Register
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
                <label className="block text-slate-300 mb-1">Dataset</label>
                <select
                  value={selectedDatasetId}
                  onChange={(e) => setSelectedDatasetId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  {datasets.map((d) => (
                    <option key={d.dataset_id} value={d.dataset_id}>
                      {d.name} ({d.valid_rows} rows)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Model Architecture</label>
                <select
                  value={modelType}
                  onChange={(e) => setModelType(e.target.value as MLExperimentResult['model_type'])}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="Isolation Forest">Isolation Forest (Baseline)</option>
                  <option value="LSTM Sequence">LSTM Sequence Detector (Proxy unless Python ML connected)</option>
                  <option value="Transformer (Planned)">Transformer Sequence (Future Extension — Unavailable)</option>
                </select>
              </div>

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
          {selectedExp && (
            <div className="xl:col-span-2 space-y-5">
              <SurfacePanel
                title={`${selectedExp.model_type} · ${selectedExp.experiment_id}`}
                subtitle={`${selectedExp.execution_mode} · Trained ${selectedExp.trained_at.replace('T', ' ').slice(0, 19)} UTC`}
              >
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 pb-4 border-b border-slate-800 text-xs">
                  {[
                    { label: 'Accuracy', val: selectedExp.metrics.accuracy },
                    { label: 'Precision', val: selectedExp.metrics.precision },
                    { label: 'Recall', val: selectedExp.metrics.recall },
                    { label: 'F1-Score', val: selectedExp.metrics.f1_score },
                    { label: 'False Pos Rate', val: selectedExp.metrics.false_positive_rate },
                    { label: 'ROC AUC', val: selectedExp.metrics.roc_auc },
                  ].map((m) => (
                    <div key={m.label} className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                      <div className="text-slate-400 text-[11px]">{m.label}</div>
                      <div className="text-base font-mono tabular-nums font-semibold text-slate-100 mt-0.5">
                        {(m.val * 100).toFixed(1)}%
                      </div>
                    </div>
                  ))}
                </div>

                {/* Confusion Matrix + System Resource Metrics */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 py-4 border-b border-slate-800 text-xs">
                  <div>
                    <div className="font-medium text-slate-200 mb-2">
                      Test Split Confusion Matrix (n = {selectedExp.test_size})
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
                    <div className="font-medium text-slate-200 mb-2">Operational & Compute Footprint</div>
                    <div className="divide-y divide-slate-800 border border-slate-800 rounded px-3">
                      <div className="py-2 flex justify-between">
                        <span className="text-slate-400">Inference Latency</span>
                        <span className="font-mono tabular-nums text-slate-100">{selectedExp.system_metrics.latency_ms} ms</span>
                      </div>
                      <div className="py-2 flex justify-between">
                        <span className="text-slate-400">CPU Utilization</span>
                        <span className="font-mono tabular-nums text-slate-100">{selectedExp.system_metrics.cpu_pct}%</span>
                      </div>
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
                  </div>
                </div>

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
                          <td className="py-2 pr-3 text-slate-100">{exp.model_type}</td>
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
          )}
        </div>
      </DataStateWrapper>
    </div>
  );
}
