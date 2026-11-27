import React, { useState } from 'react';
import { api } from '../services/api';
import { PreprocessingStatus } from '../types';
import {
  Cpu,
  Play,
  CheckCircle2,
  Clock,
  Layers,
  Database,
  Calendar,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';

interface PreprocessingProps {
  onNavigateToDetection: () => void;
}

export const Preprocessing: React.FC<PreprocessingProps> = ({ onNavigateToDetection }) => {
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState<PreprocessingStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRunPreprocessing = async () => {
    try {
      setRunning(true);
      setError(null);
      const res = await api.runPreprocessing();
      setStatus(res);
    } catch (err: any) {
      setError(err.message || 'Preprocessing failed.');
    } finally {
      setRunning(false);
    }
  };

  const featureList = [
    { name: 'hour_of_day', type: 'Integer [0 - 23]', desc: 'Extracted hour of day for diurnal activity baseline.' },
    { name: 'is_off_hours', type: 'Binary [0.0 / 1.0]', desc: '1.0 if access occurs outside designated shift (before 07:00 or after 20:00).' },
    { name: 'is_weekend', type: 'Binary [0.0 / 1.0]', desc: '1.0 if access occurs on Saturday or Sunday.' },
    { name: 'action_risk_weight', type: 'Float [0.05 - 1.0]', desc: 'Normalized risk weight per administrative privilege level (e.g. delete_logs=1.0).' },
    { name: 'resource_sensitivity', type: 'Float [0.20 - 1.0]', desc: 'Criticality tier of target resource (e.g. customer_pii_vault=0.95).' },
    { name: 'is_failure', type: 'Binary [0.0 / 1.0]', desc: 'Indicates authorization rejection, token expiration or API error.' },
    { name: 'user_activity_frequency', type: 'Normalized [0.0 - 1.0]', desc: 'Relative operational frequency to detect sudden volumetric bursts.' },
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Action Header */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-[#F8FAFC]">
            Data Preprocessing & Feature Extraction Engine
          </h3>
          <p className="text-xs text-[#94A3B8] mt-0.5">
            Parses raw cloud logs into normalized numerical tensors and sequential LSTM sliding-window matrices.
          </p>
        </div>

        <button
          onClick={handleRunPreprocessing}
          disabled={running}
          className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap disabled:opacity-50"
        >
          <Play className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
          <span>{running ? 'Executing Pipeline...' : 'Run Preprocessing Pipeline'}</span>
        </button>
      </div>

      {error && (
        <div className="p-3 bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg text-xs text-[#EF4444] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Preprocessing Summary Stats */}
      {status ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
            <span className="text-xs text-[#94A3B8]">Total Logs Processed</span>
            <div className="mt-1 text-2xl font-bold font-mono text-[#F8FAFC]">
              {status.total_records}
            </div>
            <span className="text-[11px] text-[#22C55E] flex items-center gap-1 mt-1">
              <CheckCircle2 className="w-3 h-3" /> Validated
            </span>
          </div>

          <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
            <span className="text-xs text-[#94A3B8]">Duplicates Removed</span>
            <div className="mt-1 text-2xl font-bold font-mono text-[#F8FAFC]">
              {status.removed_duplicates}
            </div>
            <span className="text-[11px] text-[#94A3B8] mt-1">
              Exact matches filtered
            </span>
          </div>

          <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
            <span className="text-xs text-[#94A3B8]">Unique Identities</span>
            <div className="mt-1 text-2xl font-bold font-mono text-[#38BDF8]">
              {status.user_count}
            </div>
            <span className="text-[11px] text-[#94A3B8] mt-1">
              Users profiled
            </span>
          </div>

          <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
            <span className="text-xs text-[#94A3B8]">Features Extracted</span>
            <div className="mt-1 text-2xl font-bold font-mono text-[#22D3EE]">
              {status.extracted_features.length}
            </div>
            <span className="text-[11px] text-[#94A3B8] mt-1">
              Numerical dimensions
            </span>
          </div>
        </div>
      ) : (
        <div className="p-6 bg-[#17243A]/50 border border-[#1E2D4A] border-dashed rounded-xl text-center text-xs text-[#94A3B8]">
          Click "Run Preprocessing Pipeline" above to execute feature engineering on the stored audit logs.
        </div>
      )}

      {/* Feature Engineering Breakdown Table */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
          <div>
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              Feature Engineering Schema (7 Dimensions)
            </h3>
            <p className="text-[11px] text-[#94A3B8]">
              Trained representation fed into Isolation Forest and LSTM sequence autoencoder
            </p>
          </div>
          <span className="text-xs font-mono text-[#22D3EE]">Tensor Shape: (N, 7)</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#1E2D4A] text-[#94A3B8]">
                <th className="py-2 px-3 font-medium">Feature Name</th>
                <th className="py-2 px-3 font-medium">Data Type</th>
                <th className="py-2 px-3 font-medium">Cybersecurity Significance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]">
              {featureList.map((f) => (
                <tr key={f.name} className="hover:bg-[#1E2F4C] transition-colors">
                  <td className="py-2.5 px-3 font-mono font-medium text-[#22D3EE]">{f.name}</td>
                  <td className="py-2.5 px-3 font-mono text-[#94A3B8]">{f.type}</td>
                  <td className="py-2.5 px-3 text-[#F8FAFC]">{f.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Sequential Window Structure for LSTM */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#38BDF8]" />
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              LSTM Sliding Window Architecture
            </h3>
          </div>
          <span className="text-xs font-mono text-[#94A3B8]">Sequence Length: W = 5</span>
        </div>

        <p className="text-xs text-[#94A3B8]">
          Logs are grouped per user and sorted chronologically. A sliding window of length 5 creates sequence tensors
          of shape <span className="font-mono text-[#F8FAFC]">(Batch, 5, 7)</span>. This captures behavioral state transitions
          such as out-of-order execution, privilege escalation after authentication, or abnormal data queries following role assumption.
        </p>

        <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg font-mono text-[11px] text-[#94A3B8] space-y-1">
          <div>[Sequence Window 0]: [login (t=0) -&gt; describe_instances (t=1) -&gt; scale_cluster (t=2) -&gt; read (t=3) -&gt; logout (t=4)] -&gt; Expected Transition</div>
          <div className="text-[#EF4444]">[Sequence Window 1]: [login (t=23:42) -&gt; assume_role_failed -&gt; assume_role_success -&gt; list_buckets -&gt; download_bulk] -&gt; High Deviation Anomaly</div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            onClick={onNavigateToDetection}
            className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2"
          >
            <span>Proceed to Anomaly Detection</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
