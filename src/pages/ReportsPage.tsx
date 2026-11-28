import React, { useEffect, useState } from 'react';
import { Download, FileText } from 'lucide-react';
import { api } from '../services/api';
import {
  downloadFullCsvSummary,
  type ReportPayload,
} from '../services/reportGenerator';
import { DataStateWrapper, SectionHeader, SurfacePanel } from '../components/ui/SocPrimitives';
import { ArchitectureBlueprintsPanel } from '../components/diagrams/ResearchDiagrams';

export function ReportsPage() {
  const [payload, setPayload] = useState<ReportPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const loadReportData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [summary, predRes, ubaRes, incRes, polRes, mlRes] = await Promise.all([
        api.getDashboardSummary(),
        api.getPredictions(),
        api.getUbaProfiles(),
        api.getIncidents(),
        api.getPolicies(),
        api.getMlExperiments(),
      ]);
      setPayload({
        summary,
        predictions: predRes.predictions,
        profiles: ubaRes.profiles,
        incidents: incRes.incidents,
        policies: polRes.policies,
        experiments: mlRes.experiments,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to compile report data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReportData();
  }, []);

  const handleDownloadPdf = async () => {
    setDownloadingPdf(true);
    setStatusMsg(null);
    setPdfError(null);
    try {
      const res = await fetch('/api/reports/pdf', { method: 'GET' });
      if (!res.ok) {
        let errMessage = `PDF download failed with HTTP ${res.status}.`;
        try {
          const errJson = (await res.json()) as { error?: string };
          if (errJson?.error) errMessage = errJson.error;
        } catch {
          // Ignore non-JSON error body
        }
        throw new Error(errMessage);
      }

      const contentType = res.headers.get('Content-Type') || '';
      if (!contentType.includes('application/pdf')) {
        throw new Error(`Unexpected response Content-Type: ${contentType || 'unknown'}`);
      }

      const blob = await res.blob();
      if (blob.size === 0) {
        throw new Error('Server returned an empty PDF document.');
      }

      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = 'cloudsentinel-report.pdf';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);

      setStatusMsg('Downloaded PDF security & cost optimization report from /api/reports/pdf.');
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : 'Failed to download PDF report.');
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handleDownloadCsv = () => {
    if (!payload) return;
    setPdfError(null);
    downloadFullCsvSummary(payload);
    setStatusMsg('Exported comprehensive CSV summary covering anomalies, incidents, ML evaluations, and policies.');
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Reports, Analytics & Research Architecture"
        description="Export executive PDF and comprehensive CSV reports from live stored telemetry, and inspect system architecture, PostgreSQL schema, and research methodology."
        actions={
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              disabled={!payload}
              onClick={handleDownloadCsv}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 rounded-md border border-slate-700 whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              Download CSV Report
            </button>
            <button
              type="button"
              disabled={!payload || downloadingPdf}
              onClick={handleDownloadPdf}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-md whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" />
              {downloadingPdf ? 'Generating PDF...' : 'Download PDF Report'}
            </button>
          </div>
        }
      />

      {statusMsg && (
        <div className="px-4 py-2 bg-emerald-950/30 border border-emerald-500/30 rounded text-xs text-emerald-200">
          {statusMsg}
        </div>
      )}

      {pdfError && (
        <div className="px-4 py-2 bg-rose-950/30 border border-rose-500/30 rounded text-xs text-rose-200">
          {pdfError}
        </div>
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadReportData}>
        {payload && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <SurfacePanel title="Audit & Threat Coverage">
                <div className="space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span>Normalized Events</span>
                    <span className="font-mono tabular-nums text-slate-100">{payload.summary.total_cloud_events}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Flagged Anomalies</span>
                    <span className="font-mono tabular-nums text-amber-300">{payload.summary.suspicious_activities}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Tracked Identities</span>
                    <span className="font-mono tabular-nums text-slate-100">{payload.profiles.length}</span>
                  </div>
                </div>
              </SurfacePanel>

              <SurfacePanel title="Incident & Policy Summary">
                <div className="space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span>Total Incidents</span>
                    <span className="font-mono tabular-nums text-slate-100">{payload.incidents.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Policy Recommendations</span>
                    <span className="font-mono tabular-nums text-slate-100">{payload.policies.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Projected Risk Reduction</span>
                    <span className="font-mono tabular-nums text-emerald-400">
                      {payload.summary.cost_overview.current_residual_risk} → {payload.summary.cost_overview.recommended_residual_risk}
                    </span>
                  </div>
                </div>
              </SurfacePanel>

              <SurfacePanel title="ML Evaluation & Export Endpoints">
                <div className="space-y-1.5 text-slate-300">
                  <div className="flex justify-between">
                    <span>Executed Experiments</span>
                    <span className="font-mono tabular-nums text-slate-100">{payload.experiments.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Latest F1-Score</span>
                    <span className="font-mono tabular-nums text-indigo-300">
                      {payload.experiments[0] ? `${(payload.experiments[0].metrics.f1_score * 100).toFixed(1)}%` : 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>PDF Report Endpoint</span>
                    <a
                      href="/api/reports/pdf"
                      download="cloudsentinel-report.pdf"
                      className="text-indigo-400 hover:underline font-mono"
                    >
                      /api/reports/pdf
                    </a>
                  </div>
                  <div className="flex justify-between">
                    <span>Raw Event CSV Endpoint</span>
                    <a href="/api/reports/export" className="text-indigo-400 hover:underline font-mono">
                      /api/reports/export
                    </a>
                  </div>
                </div>
              </SurfacePanel>
            </div>

            <SurfacePanel
              title="System Architecture, Data Flow, Database ER & FastAPI Blueprints"
              subtitle="Full multi-service deployment design across React SPA, FastAPI Control Plane, Python ML Service, and PostgreSQL"
            >
              <ArchitectureBlueprintsPanel />
            </SurfacePanel>

            <SurfacePanel
              title="Research Methodology, Limitations & Reproducibility"
              subtitle="Scientific documentation of module contributions, assumptions, and deployment boundaries"
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs text-slate-300 leading-relaxed">
                <div className="space-y-2">
                  <h4 className="font-semibold text-slate-100">Research Methodology & Module Contributions</h4>
                  <p>
                    CloudSentinel AI unifies heterogeneous AWS CloudTrail, AWS Lambda, AWS IAM, OpenStack Keystone, and
                    OpenStack Nova logs into a single 9-field canonical schema before extracting 10 behavioral and
                    resource-sensitivity features.
                  </p>
                  <p>
                    Point anomalies (Isolation Forest) and sequential action chains (PyTorch LSTM) are separated from
                    prediction confidence and weighted risk decomposition so analysts can audit why each alert fired.
                  </p>
                </div>
                <div className="space-y-2">
                  <h4 className="font-semibold text-slate-100">Known Limitations & Reproducibility</h4>
                  <p>
                    When the external Python ML microservice (<span className="font-mono text-indigo-300">ML_SERVICE_URL</span>)
                    is disconnected, the Node runtime executes a deterministic statistical baseline scorer and labels all
                    outputs as simulated/proxy results. CERT r4.2 insider records are explicitly distinguished from
                    adapted serverless FaaS events.
                  </p>
                  <p>
                    To reproduce full PyTorch LSTM & Scikit-learn Isolation Forest training with PostgreSQL persistence,
                    launch the included <span className="font-mono text-indigo-300">docker-compose.yml</span> stack
                    connecting <span className="font-mono">/backend</span>, <span className="font-mono">/ml_service</span>,
                    and <span className="font-mono">/database</span>.
                  </p>
                </div>
              </div>
            </SurfacePanel>
          </>
        )}
      </DataStateWrapper>
    </div>
  );
}
