import React, { useEffect, useState } from 'react';
import { ArrowUpRight, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import type { DashboardSummary, NormalizedAuditEvent } from '../types/security';
import {
  DataStateWrapper,
  SectionHeader,
  SimulationNotice,
  StatusText,
  SurfacePanel,
} from '../components/ui/SocPrimitives';
import { RiskDistributionBars, ThreatTimelineChart } from '../components/charts/SocCharts';
import { InteractiveResearchPipeline } from '../components/diagrams/ResearchDiagrams';

export function DashboardPage({ onNavigate }: { onNavigate: (page: string) => void }) {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<NormalizedAuditEvent | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDashboardSummary();
      setSummary(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard summary.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Security Operations Center Overview"
        description="Real-time telemetry, ML-assisted insider threat detection, and cost-aware adaptive policy posture across AWS, OpenStack, and serverless FaaS."
        actions={
          <button
            type="button"
            onClick={loadData}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded-md border border-slate-700 transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            Refresh Telemetry
          </button>
        }
      />

      {summary && (
        <SimulationNotice connected={summary.ml_service_connected} label={summary.ml_service_label} />
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadData}>
        {summary && (
          <>
            {/* Primary KPI Strip */}
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
              {[
                {
                  label: 'Total Cloud Events',
                  value: summary.total_cloud_events,
                  sub: 'Normalized schema',
                  target: 'audit-logs',
                },
                {
                  label: 'Suspicious Activities',
                  value: summary.suspicious_activities,
                  sub: 'Flagged by detector',
                  target: 'threat-detection',
                  accent: 'text-amber-400',
                },
                {
                  label: 'Critical Alerts',
                  value: summary.critical_security_alerts,
                  sub: 'Risk score >= 85',
                  target: 'threat-detection',
                  accent: 'text-rose-400',
                },
                {
                  label: 'High-Risk Users',
                  value: summary.high_risk_users,
                  sub: 'UBA score >= 65',
                  target: 'user-behavior',
                  accent: 'text-amber-300',
                },
                {
                  label: 'Active Incidents',
                  value: summary.active_incidents,
                  sub: 'Open or Investigating',
                  target: 'incidents',
                  accent: 'text-indigo-400',
                },
                {
                  label: 'Pending Approvals',
                  value: summary.pending_policy_approvals,
                  sub: 'Requires Admin review',
                  target: 'security-policies',
                  accent: 'text-sky-400',
                },
              ].map((kpi) => (
                <button
                  key={kpi.label}
                  type="button"
                  onClick={() => onNavigate(kpi.target)}
                  className="text-left bg-[#0F172A] border border-slate-800/90 hover:border-slate-700 rounded-lg p-4 transition-colors group"
                >
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>{kpi.label}</span>
                    <ArrowUpRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-300 transition-colors" />
                  </div>
                  <div className={`mt-2 text-2xl font-semibold font-mono tabular-nums ${kpi.accent || 'text-slate-100'}`}>
                    {kpi.value}
                  </div>
                  <div className="mt-1 text-[11px] text-slate-500">{kpi.sub}</div>
                </button>
              ))}
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              <SurfacePanel
                title="Threat Detection Timeline"
                subtitle="Event volume vs suspicious & critical alerts across UTC time windows"
                className="lg:col-span-2"
              >
                <ThreatTimelineChart data={summary.threat_timeline} />
              </SurfacePanel>

              <SurfacePanel
                title="Risk Distribution"
                subtitle="Classified prediction severity across stored events"
              >
                <RiskDistributionBars data={summary.risk_distribution} />
                <div className="mt-5 pt-4 border-t border-slate-800/80 grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <div className="text-slate-400">Avg Residual Risk</div>
                    <div className="font-mono tabular-nums text-slate-100 text-sm font-semibold mt-0.5">
                      {summary.cost_overview.current_residual_risk} → {summary.cost_overview.recommended_residual_risk}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400">Policy Cost Posture</div>
                    <div className="font-mono tabular-nums text-emerald-400 text-sm font-semibold mt-0.5">
                      ${summary.cost_overview.current_monthly_cost_usd} → ${summary.cost_overview.recommended_monthly_cost_usd}/mo
                    </div>
                  </div>
                </div>
              </SurfacePanel>
            </div>

            {/* Cloud Resource Overview & Security/Cost Summary */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              <SurfacePanel
                title="Cloud & Serverless Footprint"
                subtitle="Monitored telemetry sources across public, private, and FaaS"
              >
                <div className="divide-y divide-slate-800/80 text-xs">
                  {[
                    { name: 'AWS CloudTrail Events', value: summary.cloud_resource_overview.aws_cloudtrail_events },
                    { name: 'AWS Lambda Functions (FaaS)', value: summary.cloud_resource_overview.aws_lambda_functions },
                    { name: 'Tracked Cloud Identities', value: summary.cloud_resource_overview.aws_iam_identities },
                    { name: 'OpenStack Keystone Events', value: summary.cloud_resource_overview.openstack_keystone_tokens },
                    { name: 'OpenStack Nova Compute Events', value: summary.cloud_resource_overview.openstack_nova_instances },
                  ].map((row) => (
                    <div key={row.name} className="py-2.5 flex items-center justify-between">
                      <span className="text-slate-300">{row.name}</span>
                      <span className="font-mono tabular-nums font-medium text-slate-100">{row.value}</span>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  onClick={() => onNavigate('cloud-environments')}
                  className="mt-3 w-full py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors"
                >
                  Inspect Cloud & FaaS Integrations
                </button>
              </SurfacePanel>

              <SurfacePanel
                title="Recent Normalized Audit Events"
                subtitle="Latest ingested records across AWS, OpenStack, and CERT benchmarks"
                className="lg:col-span-2"
                rightSlot={
                  <button
                    type="button"
                    onClick={() => onNavigate('audit-logs')}
                    className="text-xs font-medium text-indigo-400 hover:text-indigo-300"
                  >
                    View All Events
                  </button>
                }
              >
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-3 font-medium">Timestamp (UTC)</th>
                        <th className="py-2 pr-3 font-medium">Provider</th>
                        <th className="py-2 pr-3 font-medium">Identity</th>
                        <th className="py-2 pr-3 font-medium">Action</th>
                        <th className="py-2 pr-3 font-medium">Source IP</th>
                        <th className="py-2 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {summary.recent_events.map((ev) => (
                        <tr
                          key={ev.event_id}
                          onClick={() => setSelectedEvent(ev)}
                          className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                        >
                          <td className="py-2.5 pr-3 font-mono tabular-nums text-slate-300 whitespace-nowrap">
                            {ev.event_time.replace('T', ' ').slice(0, 19)}
                          </td>
                          <td className="py-2.5 pr-3 text-slate-300 whitespace-nowrap">{ev.provider}</td>
                          <td className="py-2.5 pr-3 font-mono text-slate-200 whitespace-nowrap">{ev.cloud_user_id}</td>
                          <td className="py-2.5 pr-3 font-mono text-indigo-300 whitespace-nowrap">{ev.action}</td>
                          <td className="py-2.5 pr-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">{ev.source_ip}</td>
                          <td className="py-2.5">
                            <StatusText status={ev.status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {selectedEvent && (
                  <div className="mt-4 p-3.5 bg-slate-950/80 border border-slate-800 rounded text-xs">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-slate-200">
                        Normalized Event Detail · {selectedEvent.event_id}
                      </span>
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(null)}
                        className="text-slate-400 hover:text-slate-200"
                      >
                        Close
                      </button>
                    </div>
                    <pre className="font-mono text-[11px] text-slate-300 overflow-x-auto">
                      {JSON.stringify(selectedEvent, null, 2)}
                    </pre>
                  </div>
                )}
              </SurfacePanel>
            </div>

            {/* Interactive 13-stage Research Pipeline */}
            <SurfacePanel
              title="End-to-End Research Detection & Adaptive Policy Pipeline"
              subtitle="Click any stage to inspect input/output contracts and jump directly to its active module"
            >
              <InteractiveResearchPipeline onNavigate={onNavigate} />
            </SurfacePanel>
          </>
        )}
      </DataStateWrapper>
    </div>
  );
}
