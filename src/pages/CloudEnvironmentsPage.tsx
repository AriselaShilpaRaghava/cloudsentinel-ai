import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Cloud, Server, Shield } from 'lucide-react';
import { api } from '../services/api';
import type { AuthUser, CloudIntegrationConfig, LambdaFunctionMetric } from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';

export function CloudEnvironmentsPage({ currentUser }: { currentUser: AuthUser }) {
  const [integrations, setIntegrations] = useState<CloudIntegrationConfig[]>([]);
  const [lambdaMetrics, setLambdaMetrics] = useState<LambdaFunctionMetric[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'integrations' | 'serverless'>('integrations');

  const [editingId, setEditingId] = useState<string | null>(null);
  const [endpointInput, setEndpointInput] = useState('');
  const [roleInput, setRoleInput] = useState('');
  const [testMsg, setTestMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getIntegrations();
      setIntegrations(res.integrations);
      setLambdaMetrics(res.lambdaMetrics);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cloud environment integrations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const openConfig = (item: CloudIntegrationConfig) => {
    setEditingId(item.integration_id);
    setEndpointInput(item.endpoint_or_region);
    setRoleInput(item.role_or_project);
    setTestMsg(null);
  };

  const handleValidate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingId) return;
    setSubmitting(true);
    setTestMsg(null);
    try {
      const res = await api.testIntegration(editingId, {
        endpoint_or_region: endpointInput,
        role_or_project: roleInput,
        credential_provided: false,
      });
      setIntegrations((prev) => prev.map((i) => (i.integration_id === editingId ? res.integration : i)));
      setTestMsg(res.integration.validation_message);
    } catch (err) {
      setTestMsg(err instanceof Error ? err.message : 'Validation request failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Cloud Environment & Serverless FaaS Monitoring"
        description="Configure read-only AWS and OpenStack audit telemetry connectors and inspect AWS Lambda serverless execution patterns."
        actions={
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            <button
              type="button"
              onClick={() => setActiveTab('integrations')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                activeTab === 'integrations' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Cloud Connectors (5)
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('serverless')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                activeTab === 'serverless' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Serverless FaaS Telemetry ({lambdaMetrics.length})
            </button>
          </div>
        }
      />

      <div className="border border-slate-800 bg-slate-900/50 rounded-lg px-4 py-3 text-xs text-slate-300 flex items-center justify-between gap-4">
        <span>
          Security Policy: All cloud integrations enforce <strong className="text-slate-100">Read-Only</strong> permissions by default. Connectors never report as live without verified environment credentials.
        </span>
        <span className="font-mono text-slate-400 whitespace-nowrap">Actor: {currentUser.role}</span>
      </div>

      <DataStateWrapper loading={loading} error={error} onRetry={loadData}>
        {activeTab === 'integrations' ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2 space-y-4">
              {integrations.map((item) => (
                <SurfacePanel key={item.integration_id}>
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-2.5">
                        {item.provider === 'AWS' ? (
                          <Cloud className="w-4 h-4 text-sky-400 shrink-0" />
                        ) : (
                          <Server className="w-4 h-4 text-indigo-400 shrink-0" />
                        )}
                        <h3 className="text-sm font-semibold text-slate-100">{item.service_name}</h3>
                      </div>
                      <div className="text-xs text-slate-400 flex flex-wrap items-center gap-2">
                        <span>{item.provider}</span>
                        <span aria-hidden="true">·</span>
                        <span>{item.auth_mode}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-emerald-400 font-medium">{item.permissions_scope} Scope</span>
                      </div>
                      <p className="text-xs text-slate-300 pt-1">{item.validation_message}</p>
                      {item.role_or_project && (
                        <div className="text-[11px] font-mono text-slate-400 pt-1">
                          Endpoint/Region: {item.endpoint_or_region} · Target: {item.role_or_project}
                        </div>
                      )}
                    </div>
                    <div className="flex flex-col items-end gap-2 shrink-0">
                      <StatusText status={item.status} />
                      <button
                        type="button"
                        onClick={() => openConfig(item)}
                        className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-100 rounded border border-slate-700 transition-colors whitespace-nowrap"
                      >
                        Configure & Test
                      </button>
                    </div>
                  </div>
                </SurfacePanel>
              ))}
            </div>

            <div>
              <SurfacePanel
                title="Integration Endpoint Configuration"
                subtitle="Credentials must be injected via backend environment variables"
              >
                {editingId ? (
                  <form onSubmit={handleValidate} className="space-y-4 text-xs">
                    <div>
                      <label className="block text-slate-400 mb-1">Integration ID</label>
                      <div className="font-mono text-slate-200 bg-slate-900 px-3 py-2 rounded border border-slate-800">
                        {editingId}
                      </div>
                    </div>
                    <div>
                      <label htmlFor="int-endpoint" className="block text-slate-300 mb-1">
                        Region or Keystone Auth URL
                      </label>
                      <input
                        id="int-endpoint"
                        type="text"
                        required
                        value={endpointInput}
                        onChange={(e) => setEndpointInput(e.target.value)}
                        placeholder="us-east-1 or https://keystone.internal:5000/v3"
                        className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label htmlFor="int-role" className="block text-slate-300 mb-1">
                        Read-Only IAM Role ARN or OpenStack Project ID
                      </label>
                      <input
                        id="int-role"
                        type="text"
                        required
                        value={roleInput}
                        onChange={(e) => setRoleInput(e.target.value)}
                        placeholder="arn:aws:iam::123456789012:role/CloudSentinelReadOnly"
                        className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100 font-mono focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div className="p-3 bg-slate-900/70 border border-slate-800 rounded text-[11px] text-slate-400 space-y-1">
                      <div className="flex items-center gap-1.5 text-slate-200 font-medium">
                        <Shield className="w-3.5 h-3.5 text-indigo-400" />
                        No Secret Storage in Browser
                      </div>
                      <p>
                        Secret keys are never stored in browser state. Backend validates against{' '}
                        <span className="font-mono text-slate-300">AWS_ACCESS_KEY_ID</span> or{' '}
                        <span className="font-mono text-slate-300">OPENSTACK_TOKEN</span>.
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="submit"
                        disabled={submitting || currentUser.role !== 'Admin'}
                        className="flex-1 py-2 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
                      >
                        {submitting ? 'Testing Connection...' : 'Validate Read-Only Access'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingId(null)}
                        className="py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
                      >
                        Cancel
                      </button>
                    </div>
                    {currentUser.role !== 'Admin' && (
                      <p className="text-amber-400 text-[11px]">
                        Admin role required to save or probe cloud connector endpoints.
                      </p>
                    )}
                    {testMsg && (
                      <div className="p-3 rounded border border-slate-700 bg-slate-900 text-slate-200 text-xs">
                        {testMsg}
                      </div>
                    )}
                  </form>
                ) : (
                  <p className="text-xs text-slate-400 py-6">
                    Select any AWS or OpenStack connector on the left to configure its read-only role or Keystone endpoint and run a credential probe.
                  </p>
                )}
              </SurfacePanel>
            </div>
          </div>
        ) : (
          <SurfacePanel
            title="Serverless Function-as-a-Service (AWS Lambda) Security Telemetry"
            subtitle="Monitoring invocation bursts, execution duration anomalies, error spikes, and unusual callers (Simulated FaaS Telemetry)"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 pr-4 font-medium">Function Name</th>
                    <th className="py-2.5 pr-4 font-medium">Runtime / Region</th>
                    <th className="py-2.5 pr-4 font-medium text-right">24h Invocations</th>
                    <th className="py-2.5 pr-4 font-medium text-right">Baseline</th>
                    <th className="py-2.5 pr-4 font-medium text-right">Ratio</th>
                    <th className="py-2.5 pr-4 font-medium text-right">Error %</th>
                    <th className="py-2.5 pr-4 font-medium text-right">Avg Duration</th>
                    <th className="py-2.5 pr-4 font-medium">Last Caller</th>
                    <th className="py-2.5 font-medium">FaaS Posture</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {lambdaMetrics.map((fn) => {
                    const ratio = (fn.invocations_24h / Math.max(1, fn.baseline_invocations)).toFixed(1);
                    return (
                      <tr key={fn.function_name} className="hover:bg-slate-800/40">
                        <td className="py-3 pr-4 font-mono text-indigo-300 font-medium whitespace-nowrap">
                          {fn.function_name}
                        </td>
                        <td className="py-3 pr-4 text-slate-300 whitespace-nowrap">
                          {fn.runtime} · {fn.region}
                        </td>
                        <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-100">
                          {fn.invocations_24h.toLocaleString()}
                        </td>
                        <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-400">
                          {fn.baseline_invocations.toLocaleString()}
                        </td>
                        <td
                          className={`py-3 pr-4 text-right font-mono tabular-nums font-medium ${
                            Number(ratio) >= 5 ? 'text-rose-400' : 'text-slate-300'
                          }`}
                        >
                          {ratio}x
                        </td>
                        <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-300">
                          {fn.error_rate_pct.toFixed(1)}%
                        </td>
                        <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-300">
                          {fn.avg_duration_ms} ms
                        </td>
                        <td className="py-3 pr-4 font-mono text-slate-200 whitespace-nowrap">{fn.last_caller}</td>
                        <td className="py-3 whitespace-nowrap">
                          {fn.anomaly_flag ? (
                            <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                              <AlertTriangle className="w-3.5 h-3.5" /> Invocation Anomaly
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Within Baseline
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </SurfacePanel>
        )}
      </DataStateWrapper>
    </div>
  );
}
