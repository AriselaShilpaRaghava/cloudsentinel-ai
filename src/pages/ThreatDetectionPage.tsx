import React, { useEffect, useState } from 'react';
import { Play, PlusCircle } from 'lucide-react';
import { api } from '../services/api';
import type { AuthUser, ThreatPrediction } from '../types/security';
import {
  DataStateWrapper,
  SectionHeader,
  SeverityText,
  SimulationNotice,
  StatusText,
  SurfacePanel,
} from '../components/ui/SocPrimitives';

export function ThreatDetectionPage({
  currentUser,
  onNavigate,
}: {
  currentUser: AuthUser;
  onNavigate: (page: string) => void;
}) {
  const [predictions, setPredictions] = useState<ThreatPrediction[]>([]);
  const [mlConnected, setMlConnected] = useState(false);
  const [mlLabel, setMlLabel] = useState('');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<'ALL' | 'High-Confidence Alert' | 'Requires Additional Investigation'>('ALL');
  const [selectedPred, setSelectedPred] = useState<ThreatPrediction | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const loadPredictions = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getPredictions();
      setPredictions(res.predictions);
      setMlConnected(res.ml_service_connected);
      setMlLabel(res.ml_service_label);
      setSelectedPred((prev) =>
        prev ? res.predictions.find((p) => p.prediction_id === prev.prediction_id) || res.predictions[0] || null : res.predictions[0] || null,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load threat detections.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPredictions();
  }, []);

  const handleRunScan = async () => {
    setRunning(true);
    setActionMsg(null);
    try {
      const res = await api.runDetection();
      setPredictions(res.predictions);
      setMlConnected(res.ml_service_connected);
      setMlLabel(res.ml_service_label);
      setActionMsg(`Executed confidence-aware detection pipeline across ${res.predictions.length} stored events.`);
    } catch (err) {
      setActionMsg(err instanceof Error ? err.message : 'Detection scan failed.');
    } finally {
      setRunning(false);
    }
  };

  const handleCreateIncident = async (pred: ThreatPrediction) => {
    setActionMsg(null);
    try {
      const res = await api.createIncidentFromPrediction(pred.prediction_id);
      setActionMsg(
        res.already_exists
          ? `Incident ${res.incident.incident_id} already exists for this detection.`
          : `Created incident ${res.incident.incident_id} from detection ${pred.prediction_id}.`,
      );
    } catch (err) {
      setActionMsg(err instanceof Error ? err.message : 'Failed to create incident.');
    }
  };

  const visible = predictions.filter((p) => {
    if (filterMode === 'ALL') return p.investigation_status !== 'Normal Baseline';
    return p.investigation_status === filterMode;
  });

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Confidence-Aware AI Threat Detection"
        description="Separates Anomaly Score, Prediction Confidence, and Weighted Risk Score. Uncertain or sparse-evidence detections are gated to 'Requires Additional Investigation' rather than presented as confirmed malicious activity."
        actions={
          <button
            type="button"
            disabled={running || currentUser.role === 'Viewer'}
            onClick={handleRunScan}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            <Play className="w-3.5 h-3.5" aria-hidden="true" />
            {running ? 'Running Pipeline...' : 'Run Detection Scan'}
          </button>
        }
      />

      <SimulationNotice connected={mlConnected} label={mlLabel} />

      {actionMsg && (
        <div className="px-4 py-2.5 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200 flex items-center justify-between">
          <span>{actionMsg}</span>
          <button type="button" onClick={() => onNavigate('incidents')} className="text-indigo-400 hover:underline font-medium">
            Open Incidents
          </button>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg w-fit">
        {[
          { id: 'ALL', label: 'All Flagged Scenarios' },
          { id: 'High-Confidence Alert', label: 'High-Confidence Alerts' },
          { id: 'Requires Additional Investigation', label: 'Requires Additional Investigation' },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setFilterMode(tab.id as typeof filterMode)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              filterMode === tab.id ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <DataStateWrapper
        loading={loading}
        error={error}
        isEmpty={visible.length === 0}
        emptyTitle="No anomalies match the selected investigation filter"
        onRetry={loadPredictions}
      >
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <SurfacePanel title="Insider Threat Scenario Detections" className="xl:col-span-2">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 pr-3 font-medium">Scenario & Identity</th>
                    <th className="py-2.5 pr-3 font-medium text-right">Anomaly</th>
                    <th className="py-2.5 pr-3 font-medium text-right">Confidence</th>
                    <th className="py-2.5 pr-3 font-medium text-right">Risk</th>
                    <th className="py-2.5 pr-3 font-medium">Severity</th>
                    <th className="py-2.5 font-medium">Investigation Gate</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {visible.map((pred) => (
                    <tr
                      key={pred.prediction_id}
                      onClick={() => setSelectedPred(pred)}
                      className={`cursor-pointer transition-colors ${
                        selectedPred?.prediction_id === pred.prediction_id ? 'bg-indigo-950/35' : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-2.5 pr-3">
                        <div className="font-medium text-slate-100">{pred.scenario}</div>
                        <div className="font-mono text-[11px] text-slate-400">
                          {pred.cloud_user_id} · {pred.provider} · {pred.event_id}
                        </div>
                      </td>
                      <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-sky-300">
                        {pred.anomaly_score.toFixed(2)}
                      </td>
                      <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-indigo-300">
                        {pred.prediction_confidence.toFixed(2)}
                      </td>
                      <td className="py-2.5 pr-3 text-right font-mono tabular-nums font-semibold text-slate-100">
                        {pred.risk_score}
                      </td>
                      <td className="py-2.5 pr-3">
                        <SeverityText level={pred.risk_level} />
                      </td>
                      <td className="py-2.5">
                        <StatusText status={pred.investigation_status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SurfacePanel>

          {selectedPred && (
            <SurfacePanel
              title="Confidence & Evidence Assessment"
              subtitle={`Model: ${selectedPred.model_version}`}
            >
              <div className="space-y-4 text-xs">
                <div className="grid grid-cols-3 gap-2 p-3 bg-slate-950/70 border border-slate-800 rounded text-center">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Anomaly Score</span>
                    <span className="text-base font-mono tabular-nums font-semibold text-sky-300">
                      {selectedPred.anomaly_score.toFixed(2)}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Confidence</span>
                    <span className="text-base font-mono tabular-nums font-semibold text-indigo-300">
                      {selectedPred.prediction_confidence.toFixed(2)}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Risk Score</span>
                    <span className="text-base font-mono tabular-nums font-semibold text-rose-300">
                      {selectedPred.risk_score}/100
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                  <span className="text-slate-400">Data Quality Score</span>
                  <span className="font-mono tabular-nums text-slate-200">
                    {Math.round(selectedPred.data_quality_score * 100)}% complete
                  </span>
                </div>

                <div>
                  <div className="text-slate-400 mb-1">Threat Explanation</div>
                  <p className="text-slate-200 leading-relaxed">{selectedPred.explanation}</p>
                </div>

                <div>
                  <div className="text-slate-400 mb-1">Supporting Audit Events</div>
                  <div className="font-mono text-[11px] text-indigo-300">
                    {selectedPred.evidence_events.join(' · ')}
                  </div>
                </div>

                <div>
                  <div className="text-slate-400 mb-1">Recommended Investigation Steps</div>
                  <ul className="space-y-1.5 text-slate-300 list-disc list-inside">
                    {selectedPred.recommended_steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ul>
                </div>

                <button
                  type="button"
                  disabled={currentUser.role === 'Viewer'}
                  onClick={() => handleCreateIncident(selectedPred)}
                  className="w-full inline-flex items-center justify-center gap-2 py-2 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  Create Security Incident from Detection
                </button>
              </div>
            </SurfacePanel>
          )}
        </div>
      </DataStateWrapper>
    </div>
  );
}
