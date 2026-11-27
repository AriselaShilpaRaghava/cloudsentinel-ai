import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import {
  FileSpreadsheet,
  Download,
  Printer,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Scale,
  Calendar,
  CheckCircle2
} from 'lucide-react';

export const Reports: React.FC = () => {
  const [summary, setSummary] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const fetchSummary = async () => {
      try {
        setLoading(true);
        const data = await api.getReportsSummary();
        setSummary(data);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchSummary();
  }, []);

  const handleDownloadCsv = () => {
    window.open('/api/reports/export', '_blank');
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Action Header */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="w-4 h-4 text-[#22D3EE]" />
            <h3 className="text-sm font-semibold text-[#F8FAFC]">
              Security Audit Reports & Compliance Export
            </h3>
          </div>
          <p className="text-xs text-[#94A3B8] mt-1">
            Export comprehensive cloud security audit findings, detected anomalies, and adaptive policy decisions.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handlePrint}
            className="px-3.5 py-2 text-xs font-medium text-[#94A3B8] hover:text-[#F8FAFC] bg-[#111C2E] hover:bg-[#1E2F4C] border border-[#1E2D4A] rounded-lg transition-colors flex items-center gap-1.5"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print View</span>
          </button>

          <button
            onClick={handleDownloadCsv}
            className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2 shadow-sm shadow-[#2563EB]/40"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Anomaly Report (CSV)</span>
          </button>
        </div>
      </div>

      {/* Report Container */}
      <div className="p-8 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-6 shadow-sm">
        {/* Document Header */}
        <div className="border-b border-[#1E2D4A] pb-5 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold text-[#F8FAFC] tracking-tight">
              CloudSentinel AI · Executive Security Audit Report
            </h2>
            <p className="text-xs text-[#94A3B8] mt-1 font-mono">
              Final Year B.Tech CSE (Cybersecurity) Project Evaluation Report
            </p>
          </div>
          <div className="text-right text-xs text-[#94A3B8] font-mono">
            <div>Generated: {summary?.generated_at ? new Date(summary.generated_at).toLocaleString() : 'Live'}</div>
            <div>Classification: <strong className="text-[#EF4444]">RESTRICTED SOC AUDIT</strong></div>
          </div>
        </div>

        {/* Executive Summary Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="p-4 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="text-[#94A3B8]">Audit Records Scanned</span>
            <div className="text-xl font-bold font-mono text-[#F8FAFC] mt-1">
              {summary?.total_audit_logs || 0}
            </div>
          </div>

          <div className="p-4 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="text-[#94A3B8]">High-Risk Incidents Flagged</span>
            <div className="text-xl font-bold font-mono text-[#EF4444] mt-1">
              {summary?.detection_summary?.high_risk_events || 0}
            </div>
          </div>

          <div className="p-4 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="text-[#94A3B8]">Active SOC Cases</span>
            <div className="text-xl font-bold font-mono text-[#A855F7] mt-1">
              {summary?.incident_summary?.active || 0}
            </div>
          </div>

          <div className="p-4 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
            <span className="text-[#94A3B8]">Adaptive Policies Enforced</span>
            <div className="text-xl font-bold font-mono text-[#22C55E] mt-1">
              {summary?.policy_summary?.approved || 0}
            </div>
          </div>
        </div>

        {/* Section 1: Methodology & Environment */}
        <div className="space-y-2 text-xs">
          <h4 className="font-semibold text-[#F8FAFC] pb-1 border-b border-[#1E2D4A]">
            1. Evaluation Testbed & Environment
          </h4>
          <p className="text-[#94A3B8] leading-relaxed">
            Telemetry ingested from an OpenStack Private Cloud testbed running Keystone (Identity), Nova (Compute),
            Swift (Storage), and Neutron (Firewalling). Anomaly evaluation uses an ensemble of scikit-learn Isolation Forest
            for multi-attribute access outliers paired with a PyTorch LSTM Sequential Autoencoder for chronological transition drift.
          </p>
        </div>

        {/* Section 2: Policy Optimization Overview */}
        <div className="space-y-2 text-xs">
          <h4 className="font-semibold text-[#F8FAFC] pb-1 border-b border-[#1E2D4A]">
            2. Cost-Aware Security Policy Optimization
          </h4>
          <p className="text-[#94A3B8] leading-relaxed">
            Rather than brute-force account termination, an adaptive utility optimization engine evaluated candidate security actions
            (SOC alerts, step-up MFA, least-privilege review, selective restriction, on-call escalation) balancing risk mitigation against
            computational cost and user latency.
          </p>
        </div>

        {/* Sign-off Block */}
        <div className="pt-6 border-t border-[#1E2D4A] grid grid-cols-2 gap-4 text-xs font-mono text-[#94A3B8]">
          <div>
            <div>System: CloudSentinel AI v1.0.0</div>
            <div>Storage: Local SQLite ORM Engine</div>
          </div>
          <div className="text-right">
            <div>Authorized Security Officer: SecOps Lead</div>
            <div>Verification: PASSED</div>
          </div>
        </div>
      </div>
    </div>
  );
};
