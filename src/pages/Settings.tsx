import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  Database,
  Server,
  BrainCircuit,
  ShieldAlert,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';

interface SettingsProps {
  onResetDemo: () => void;
  isResetting: boolean;
  health: any;
}

export const Settings: React.FC<SettingsProps> = ({
  onResetDemo,
  isResetting,
  health,
}) => {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [resetSuccess, setResetSuccess] = useState(false);

  const handleConfirmReset = () => {
    onResetDemo();
    setConfirmOpen(false);
    setResetSuccess(true);
    setTimeout(() => setResetSuccess(false), 3000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Title */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-[#F8FAFC] flex items-center gap-2">
            <SettingsIcon className="w-4 h-4 text-[#22D3EE]" />
            <span>System Settings & Architecture Diagnostics</span>
          </h3>
          <p className="text-xs text-[#94A3B8] mt-0.5">
            CloudSentinel AI deployment parameters, database integrity, and operational runtime state.
          </p>
        </div>
      </div>

      {resetSuccess && (
        <div className="p-3 bg-[#22C55E]/10 border border-[#22C55E]/30 rounded-lg text-xs text-[#22C55E] flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4" />
          <span>Demo dataset and model parameters reset successfully to default baseline.</span>
        </div>
      )}

      {/* Grid of Diagnostics */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Project Info */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3 text-xs">
          <h4 className="font-semibold text-[#F8FAFC] pb-2 border-b border-[#1E2D4A] flex items-center gap-2">
            <Server className="w-4 h-4 text-[#38BDF8]" />
            <span>Project Specification</span>
          </h4>

          <div className="space-y-2">
            <div>
              <span className="text-[#94A3B8]">Official Project Title:</span>
              <p className="text-[#F8FAFC] font-medium mt-0.5">
                Insider Threat Detection in Cloud Environments via Anomaly Detection using Cloud Audit Log Analysis (e.g., LSTM/Transformer-based), Applied to Serverless (FaaS) Application Environments.
              </p>
            </div>
            <div>
              <span className="text-[#94A3B8]">Additional Enhancement:</span>
              <p className="text-[#22D3EE] font-medium mt-0.5">
                Cost-aware Adaptive Security Policy Optimization.
              </p>
            </div>
            <div>
              <span className="text-[#94A3B8]">Target Testbed:</span>
              <p className="text-[#F8FAFC] font-mono mt-0.5">
                OpenStack Private Cloud Testbed (CADF · Keystone · Nova · Swift · Neutron)
              </p>
            </div>
          </div>
        </div>

        {/* Database & Runtime Health */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3 text-xs">
          <h4 className="font-semibold text-[#F8FAFC] pb-2 border-b border-[#1E2D4A] flex items-center gap-2">
            <Database className="w-4 h-4 text-[#22C55E]" />
            <span>Database & API Status</span>
          </h4>

          <div className="space-y-2 font-mono">
            <div className="flex justify-between py-1 border-b border-[#1E2D4A]">
              <span className="text-[#94A3B8]">API Service:</span>
              <span className="text-[#22C55E]">Healthy (FastAPI / Express Engine)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#1E2D4A]">
              <span className="text-[#94A3B8]">Database Engine:</span>
              <span className="text-[#F8FAFC]">SQLite with SQLAlchemy ORM</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#1E2D4A]">
              <span className="text-[#94A3B8]">Active Port:</span>
              <span className="text-[#F8FAFC]">3000 (Development & Dev Server)</span>
            </div>
            <div className="flex justify-between py-1 border-b border-[#1E2D4A]">
              <span className="text-[#94A3B8]">Isolation Forest:</span>
              <span className="text-[#22C55E]">Loaded & Calibrated</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-[#94A3B8]">LSTM Engine:</span>
              <span className="text-[#38BDF8]">Sequence Ready (W=5)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Danger Zone: Demo Data Reset */}
      <div className="p-5 bg-[#17243A] border border-[#EF4444]/30 rounded-xl space-y-3">
        <div className="flex items-center gap-2 text-[#EF4444]">
          <AlertTriangle className="w-4 h-4" />
          <h4 className="text-xs font-semibold">Demo Data Management</h4>
        </div>
        <p className="text-xs text-[#94A3B8]">
          Resetting will flush custom uploads and reseed the SQLite database with the standard benchmark sample dataset
          (120+ cloud audit events, synthetic insider attacks on PII vault, FaaS events, and policy recommendations).
        </p>

        <button
          onClick={() => setConfirmOpen(true)}
          className="px-4 py-2 bg-[#EF4444]/15 hover:bg-[#EF4444] text-[#EF4444] hover:text-white border border-[#EF4444]/40 rounded-lg text-xs font-medium transition-colors flex items-center gap-2"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset All Data to Demo Baseline</span>
        </button>
      </div>

      {/* Confirmation Modal */}
      {confirmOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-sm w-full p-5 space-y-4 shadow-xl">
            <h4 className="text-sm font-semibold text-[#F8FAFC]">
              Confirm Database Reset
            </h4>
            <p className="text-xs text-[#94A3B8]">
              Are you sure you want to reset all audit logs, detection results, and incidents back to the default benchmark dataset?
            </p>
            <div className="flex justify-end gap-2 text-xs">
              <button
                onClick={() => setConfirmOpen(false)}
                className="px-3 py-1.5 bg-[#111C2E] text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmReset}
                disabled={isResetting}
                className="px-4 py-1.5 bg-[#EF4444] hover:bg-[#DC2626] text-white font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {isResetting ? 'Resetting...' : 'Yes, Reset Data'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
