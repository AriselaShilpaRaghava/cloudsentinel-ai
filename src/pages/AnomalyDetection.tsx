import React, { useState, useEffect } from 'react';
import { DetectionResult } from '../types';
import { api } from '../services/api';
import {
  BrainCircuit,
  Play,
  CheckCircle2,
  AlertTriangle,
  Sliders,
  Filter,
  Eye,
  X,
  Shield,
  Layers
} from 'lucide-react';

interface AnomalyDetectionProps {
  onSelectResult: (result: DetectionResult) => void;
  onNavigateToThreats: () => void;
}

export const AnomalyDetection: React.FC<AnomalyDetectionProps> = ({
  onSelectResult,
  onNavigateToThreats,
}) => {
  const [modelType, setModelType] = useState<'Isolation Forest' | 'LSTM'>('Isolation Forest');
  const [threshold, setThreshold] = useState<number>(0.65);
  const [running, setRunning] = useState(false);
  const [training, setTraining] = useState(false);
  const [trainStatus, setTrainStatus] = useState<string | null>(null);
  const [results, setResults] = useState<DetectionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedResult, setSelectedResult] = useState<DetectionResult | null>(null);
  const [filterRisk, setFilterRisk] = useState<string>('all');

  const fetchResults = async () => {
    try {
      setLoading(true);
      const data = await api.getDetectionResults({ limit: 200 });
      setResults(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResults();
  }, []);

  const handleTrainModel = async () => {
    try {
      setTraining(true);
      setTrainStatus(null);
      const res = await api.trainModel(modelType === 'LSTM' ? 'LSTM' : 'IsolationForest');
      setTrainStatus(`Model '${res.model_name}' trained successfully in ${res.training_time_seconds}s.`);
    } catch (err: any) {
      setTrainStatus(`Training failed: ${err.message}`);
    } finally {
      setTraining(false);
    }
  };

  const handleRunDetection = async () => {
    try {
      setRunning(true);
      await api.runDetection(modelType, threshold);
      await fetchResults();
    } catch (err: any) {
      console.error(err);
    } finally {
      setRunning(false);
    }
  };

  const filteredResults = results.filter((r) => {
    if (filterRisk === 'all') return true;
    return r.risk_level === filterRisk;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Configuration & Trigger Panel */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-3 border-b border-[#1E2D4A]">
          <div>
            <h3 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2">
              <BrainCircuit className="w-4 h-4 text-[#22D3EE]" />
              <span>Machine Learning Anomaly Detection Engine</span>
            </h3>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Select model architecture, tune contamination threshold, train weights, and run real-time inference.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTrainModel}
              disabled={training}
              className="px-3.5 py-2 text-xs font-medium text-[#22D3EE] bg-[#111C2E] hover:bg-[#1E2F4C] border border-[#1E2D4A] rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>{training ? 'Training Model...' : `Train ${modelType}`}</span>
            </button>

            <button
              onClick={handleRunDetection}
              disabled={running}
              className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2 shadow-sm shadow-[#2563EB]/40 disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
              <span>{running ? 'Running Inference...' : 'Execute Anomaly Detection'}</span>
            </button>
          </div>
        </div>

        {trainStatus && (
          <div className="p-2.5 bg-[#111C2E] border border-[#2563EB]/40 rounded-lg text-xs text-[#22D3EE] flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#22C55E]" />
            <span>{trainStatus}</span>
          </div>
        )}

        {/* Hyperparameter Controls */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1 text-xs">
          {/* Model Selector */}
          <div className="space-y-1.5">
            <label className="text-[#94A3B8] font-medium">Model Architecture</label>
            <div className="flex items-center gap-2 p-1 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
              <button
                onClick={() => setModelType('Isolation Forest')}
                className={`flex-1 py-1.5 px-3 rounded text-center transition-colors font-medium ${
                  modelType === 'Isolation Forest'
                    ? 'bg-[#2563EB] text-white'
                    : 'text-[#94A3B8] hover:text-[#F8FAFC]'
                }`}
              >
                Isolation Forest
              </button>
              <button
                onClick={() => setModelType('LSTM')}
                className={`flex-1 py-1.5 px-3 rounded text-center transition-colors font-medium ${
                  modelType === 'LSTM'
                    ? 'bg-[#2563EB] text-white'
                    : 'text-[#94A3B8] hover:text-[#F8FAFC]'
                }`}
              >
                LSTM Sequence
              </button>
            </div>
          </div>

          {/* Threshold Slider */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-[#94A3B8]">
              <label className="font-medium">Anomaly Threshold</label>
              <span className="font-mono text-[#F8FAFC]">{threshold.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.30"
              max="0.90"
              step="0.05"
              value={threshold}
              onChange={(e) => setThreshold(parseFloat(e.target.value))}
              className="w-full accent-[#2563EB] bg-[#111C2E] rounded h-2 mt-2"
            />
          </div>

          {/* Active Model Description */}
          <div className="p-2.5 bg-[#111C2E] border border-[#1E2D4A] rounded-lg text-[11px] text-[#94A3B8] flex flex-col justify-center">
            <span className="font-medium text-[#F8FAFC]">
              {modelType === 'LSTM' ? 'PyTorch LSTM Sequential' : 'Scikit-learn Isolation Forest'}
            </span>
            <span>
              {modelType === 'LSTM'
                ? 'Analyzes sliding sequence of 5 chronological user actions for behavioral drift.'
                : 'Isolates outliers across 7 multi-dimensional temporal and privilege features.'}
            </span>
          </div>
        </div>
      </div>

      {/* Detection Results Filter & Table */}
      <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 bg-[#111C2E] border-b border-[#1E2D4A] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-3">
            <h4 className="font-semibold text-[#F8FAFC]">
              Model Prediction Results
            </h4>
            <span className="text-[#94A3B8] font-mono">
              ({filteredResults.length} scored activities)
            </span>
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-[#94A3B8]" />
            <select
              value={filterRisk}
              onChange={(e) => setFilterRisk(e.target.value)}
              className="bg-[#17243A] text-[#F8FAFC] border border-[#1E2D4A] rounded-lg px-2.5 py-1 text-xs focus:outline-none"
            >
              <option value="all">All Risk Levels</option>
              <option value="High Risk">High Risk Only</option>
              <option value="Medium Risk">Medium Risk Only</option>
              <option value="Normal">Normal Baseline</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#111C2E]/60 border-b border-[#1E2D4A] text-[#94A3B8]">
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium">User</th>
                <th className="py-2.5 px-4 font-medium">Action</th>
                <th className="py-2.5 px-4 font-medium">Resource</th>
                <th className="py-2.5 px-4 font-medium">Model Used</th>
                <th className="py-2.5 px-4 font-medium text-right">Anomaly Score</th>
                <th className="py-2.5 px-4 font-medium text-right">Risk Level</th>
                <th className="py-2.5 px-4 font-medium text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#94A3B8]">
                    Loading detection outputs...
                  </td>
                </tr>
              ) : filteredResults.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#94A3B8]">
                    No detection results found. Click "Execute Anomaly Detection" to run predictions.
                  </td>
                </tr>
              ) : (
                filteredResults.map((r) => (
                  <tr key={r.id} className="hover:bg-[#1E2F4C] transition-colors">
                    <td className="py-2.5 px-4 font-mono text-[#94A3B8] whitespace-nowrap">
                      {r.timestamp}
                    </td>
                    <td className="py-2.5 px-4 font-medium text-[#F8FAFC]">
                      {r.user_id}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[#22D3EE]">
                      {r.action}
                    </td>
                    <td className="py-2.5 px-4 text-[#94A3B8] truncate max-w-[150px]">
                      {r.resource}
                    </td>
                    <td className="py-2.5 px-4 text-[#94A3B8] font-mono text-[11px]">
                      {r.model_used}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-16 bg-[#111C2E] h-1.5 rounded-full overflow-hidden hidden sm:block">
                          <div
                            className={`h-full ${
                              r.anomaly_score > 0.7
                                ? 'bg-[#EF4444]'
                                : r.anomaly_score > 0.4
                                ? 'bg-[#F59E0B]'
                                : 'bg-[#22C55E]'
                            }`}
                            style={{ width: `${Math.min(r.anomaly_score * 100, 100)}%` }}
                          />
                        </div>
                        <span className="font-mono tabular-nums font-semibold text-[#F8FAFC]">
                          {r.anomaly_score.toFixed(2)}
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <span
                        className={`font-semibold ${
                          r.risk_level === 'High Risk'
                            ? 'text-[#EF4444]'
                            : r.risk_level === 'Medium Risk'
                            ? 'text-[#F59E0B]'
                            : 'text-[#22C55E]'
                        }`}
                      >
                        {r.risk_level}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedResult(r)}
                        className="px-2 py-1 text-[11px] text-[#22D3EE] bg-[#111C2E] hover:bg-[#2563EB] hover:text-white rounded transition-colors"
                      >
                        Explain
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Explanation Modal */}
      {selectedResult && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-lg w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-[#EF4444]" />
                <h3 className="text-sm font-semibold text-[#F8FAFC]">
                  Anomaly Diagnostic Explanation
                </h3>
              </div>
              <button
                onClick={() => setSelectedResult(null)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                <div className="text-[#94A3B8]">Target User & Action</div>
                <div className="font-semibold text-[#F8FAFC] mt-0.5">
                  {selectedResult.user_id} · <span className="font-mono text-[#22D3EE]">{selectedResult.action}</span> on {selectedResult.resource}
                </div>
              </div>

              <div>
                <span className="text-[#94A3B8] font-medium">Diagnostic Reason</span>
                <p className="mt-1 p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg text-[#F8FAFC] leading-relaxed">
                  {selectedResult.flag_reason}
                </p>
              </div>

              <div>
                <span className="text-[#94A3B8] font-medium">Recommended Immediate Action</span>
                <p className="mt-1 p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg text-[#38BDF8] leading-relaxed">
                  {selectedResult.recommended_action}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-[#94A3B8]">
                <div>Model: <span className="text-[#F8FAFC]">{selectedResult.model_used}</span></div>
                <div>Score: <span className="text-[#F8FAFC]">{selectedResult.anomaly_score.toFixed(3)}</span></div>
              </div>
            </div>

            <div className="pt-2 flex justify-end gap-2">
              <button
                onClick={() => setSelectedResult(null)}
                className="px-3 py-1.5 bg-[#111C2E] hover:bg-[#1E2F4C] text-xs font-medium text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
              >
                Close
              </button>
              <button
                onClick={() => {
                  onSelectResult(selectedResult);
                  setSelectedResult(null);
                  onNavigateToThreats();
                }}
                className="px-3.5 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-xs font-medium text-white rounded-lg transition-colors"
              >
                Investigate in Threat Center
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
