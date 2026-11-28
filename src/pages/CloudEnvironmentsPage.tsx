import React, { useEffect, useState } from 'react';
import { Activity, AlertTriangle, CheckCircle2, Cloud, Database, Info, Server, Shield, Upload } from 'lucide-react';
import { api } from '../services/api';
import type {
  AuthUser,
  CloudIntegrationConfig,
  CloudTrailFaasTelemetryResponse,
  LambdaFunctionMetric,
  OpenStackTelemetryOverviewResponse,
} from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';

export function CloudEnvironmentsPage({ currentUser }: { currentUser: AuthUser }) {
  const [integrations, setIntegrations] = useState<CloudIntegrationConfig[]>([]);
  const [lambdaMetrics, setLambdaMetrics] = useState<LambdaFunctionMetric[]>([]);
  const [faasTelemetry, setFaasTelemetry] = useState<CloudTrailFaasTelemetryResponse | null>(null);
  const [osTelemetry, setOsTelemetry] = useState<OpenStackTelemetryOverviewResponse | null>(null);
  const [selectedFaasDatasetId, setSelectedFaasDatasetId] = useState<string>('cloudtrail_all');
  const [faasLoading, setFaasLoading] = useState(false);
  const [faasError, setFaasError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'integrations' | 'serverless' | 'openstack'>('integrations');

  const [osLoading, setOsLoading] = useState(false);
  const [osMsg, setOsMsg] = useState<string | null>(null);
  const [osSourceMode, setOsSourceMode] = useState<'fixture' | 'real'>('fixture');
  const [osJsonInput, setOsJsonInput] = useState('');

  const [editingId, setEditingId] = useState<string | null>(null);
  const [endpointInput, setEndpointInput] = useState('');
  const [roleInput, setRoleInput] = useState('');
  const [testMsg, setTestMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const loadFaasTelemetry = async (datasetId: string) => {
    setFaasLoading(true);
    setFaasError(null);
    try {
      const telemetryRes = await api.getFaasTelemetry(datasetId);
      setFaasTelemetry(telemetryRes);
    } catch (err) {
      setFaasError(err instanceof Error ? err.message : 'Failed to extract CloudTrail FaaS telemetry.');
    } finally {
      setFaasLoading(false);
    }
  };

  const refreshOpenStackTelemetry = async () => {
    const osRes = await api.getOpenStackTelemetry();
    setOsTelemetry(osRes);
  };

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [intRes, telemetryRes, osRes] = await Promise.all([
        api.getIntegrations(),
        api.getFaasTelemetry(selectedFaasDatasetId),
        api.getOpenStackTelemetry(),
      ]);
      setIntegrations(intRes.integrations);
      setLambdaMetrics(intRes.lambdaMetrics);
      setFaasTelemetry(telemetryRes);
      setOsTelemetry(osRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cloud environment integrations.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadOsFixtures = async () => {
    setOsLoading(true);
    setOsMsg(null);
    try {
      const res = await api.loadOpenStackFixtures();
      await refreshOpenStackTelemetry();
      setOsMsg(
        `Loaded synthetic OpenStack fixtures (${res.summary.imported_count} imported, ${res.summary.skipped_count} skipped/duplicates across ${res.summary.services_detected.join(', ') || 'stored'}).`,
      );
    } catch (err) {
      setOsMsg(err instanceof Error ? err.message : 'Failed to load OpenStack fixtures.');
    } finally {
      setOsLoading(false);
    }
  };

  const handleIngestOpenStackJson = async (e: React.FormEvent) => {
    e.preventDefault();
    setOsLoading(true);
    setOsMsg(null);
    try {
      const parsed = JSON.parse(osJsonInput);
      const eventsArray = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed?.events)
          ? parsed.events
          : [parsed];
      const res = await api.ingestOpenStackEvents({
        events: eventsArray,
        source_mode: osSourceMode,
        source_name:
          osSourceMode === 'fixture'
            ? 'OpenStack Manual Fixture Input'
            : 'OpenStack Private Cloud Audit Ingestion',
      });
      await refreshOpenStackTelemetry();
      setOsJsonInput('');
      setOsMsg(
        `OpenStack ingest (${res.summary.source_mode}): imported=${res.summary.imported_count}, skipped=${res.summary.skipped_count}, rejected=${res.summary.rejected_count}.`,
      );
    } catch (err) {
      setOsMsg(err instanceof Error ? err.message : 'Invalid JSON or ingestion error.');
    } finally {
      setOsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleDatasetChange = (nextDatasetId: string) => {
    setSelectedFaasDatasetId(nextDatasetId);
    loadFaasTelemetry(nextDatasetId);
  };

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
              Serverless FaaS Telemetry (
              {faasTelemetry?.summary
                ? `${faasTelemetry.summary.unique_functions} Real · ${lambdaMetrics.length} Seeded`
                : lambdaMetrics.length}
              )
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('openstack')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                activeTab === 'openstack' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              OpenStack Telemetry ({osTelemetry?.event_counts.total_events ?? 0})
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
        ) : activeTab === 'serverless' ? (
          <div className="space-y-6">
            <SurfacePanel
              title="Real CloudTrail Serverless (AWS Lambda) Telemetry"
              subtitle="Extracted via Python ML service (/faas/telemetry) from Lambda Invoke, AssumeRole (invokedBy), and inScopeOf downstream execution records — zero ground-truth label leakage"
              rightSlot={
                <div className="flex items-center gap-2 text-xs">
                  <Database className="w-3.5 h-3.5 text-indigo-400" />
                  <select
                    aria-label="Select CloudTrail dataset for FaaS telemetry"
                    value={selectedFaasDatasetId}
                    onChange={(e) => handleDatasetChange(e.target.value)}
                    className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-indigo-500"
                  >
                    {(faasTelemetry?.available_datasets || []).map((ds) => (
                      <option key={ds.dataset_id} value={ds.dataset_id}>
                        {ds.name} ({ds.total_events.toLocaleString()} events · {ds.faas_related_hint.toLocaleString()} FaaS)
                      </option>
                    ))}
                  </select>
                </div>
              }
            >
              <div className="mb-4 p-3 rounded-lg border border-sky-500/30 bg-sky-950/20 text-xs text-sky-200 flex items-start gap-2.5">
                <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold">CloudTrail Telemetry Boundary:</span>{' '}
                  {faasTelemetry?.missing_telemetry_notice ||
                    'Execution duration, allocated memory, and cold-start counts are not emitted in CloudTrail audit logs and are displayed as Unavailable.'}
                </div>
              </div>

              {faasLoading ? (
                <div className="py-8 text-center text-xs text-slate-400">
                  Extracting CloudTrail FaaS telemetry via Python ML microservice...
                </div>
              ) : faasError || !faasTelemetry?.telemetry_available ? (
                <div className="p-4 rounded-lg border border-amber-500/30 bg-amber-950/20 text-xs text-amber-200 space-y-1">
                  <div className="font-semibold flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    Real CloudTrail FaaS Telemetry Unavailable
                  </div>
                  <p className="text-amber-300/90">
                    {faasError ||
                      faasTelemetry?.unavailable_reason ||
                      'Python ML service did not return FaaS telemetry.'}
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {faasTelemetry.summary && (
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                        <div className="text-[11px] text-slate-400">FaaS Events Detected</div>
                        <div className="text-lg font-semibold font-mono tabular-nums text-slate-100 mt-0.5">
                          {faasTelemetry.summary.faas_events_detected.toLocaleString()}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          of {faasTelemetry.summary.total_events_scanned.toLocaleString()} scanned ({faasTelemetry.summary.processing_ms} ms)
                        </div>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                        <div className="text-[11px] text-slate-400">Functions / Roles</div>
                        <div className="text-lg font-semibold font-mono tabular-nums text-indigo-300 mt-0.5">
                          {faasTelemetry.summary.unique_functions}
                        </div>
                        <div className="text-[10px] text-slate-500">Control-plane: {faasTelemetry.summary.control_plane_events}</div>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                        <div className="text-[11px] text-slate-400">Lambda Invoke</div>
                        <div className="text-lg font-semibold font-mono tabular-nums text-sky-300 mt-0.5">
                          {faasTelemetry.summary.invoke_events.toLocaleString()}
                        </div>
                        <div className="text-[10px] text-slate-500">lambda:Invoke / InvokeFunction</div>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                        <div className="text-[11px] text-slate-400">AssumeRole &amp; inScopeOf</div>
                        <div className="text-lg font-semibold font-mono tabular-nums text-emerald-300 mt-0.5">
                          {(faasTelemetry.summary.assume_role_events + faasTelemetry.summary.in_scope_downstream_events).toLocaleString()}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          {faasTelemetry.summary.assume_role_events} STS · {faasTelemetry.summary.in_scope_downstream_events} downstream
                        </div>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                        <div className="text-[11px] text-slate-400">Errors / AccessDenied</div>
                        <div className="text-lg font-semibold font-mono tabular-nums text-rose-300 mt-0.5">
                          {faasTelemetry.summary.total_errors.toLocaleString()}
                        </div>
                        <div className="text-[10px] text-slate-500">
                          {faasTelemetry.summary.total_access_denied.toLocaleString()} AccessDenied
                        </div>
                      </div>
                    </div>
                  )}

                  {faasTelemetry.functions.length === 0 ? (
                    <div className="py-6 text-center text-xs text-slate-400 border border-slate-800 rounded-lg">
                      No AWS Lambda or FaaS-scoped events found in this dataset selection.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2.5 pr-4 font-medium">Function / Role Identity</th>
                            <th className="py-2.5 pr-4 font-medium">Region</th>
                            <th className="py-2.5 pr-4 font-medium text-right">Total FaaS</th>
                            <th className="py-2.5 pr-4 font-medium text-right">Invoke / STS / inScope</th>
                            <th className="py-2.5 pr-4 font-medium text-right">Peak Burst (1m / 5m)</th>
                            <th className="py-2.5 pr-4 font-medium text-right">AccessDenied / Error %</th>
                            <th className="py-2.5 pr-4 font-medium">Downstream Breadth</th>
                            <th className="py-2.5 pr-4 font-medium">Sensitive Indicators</th>
                            <th className="py-2.5 pr-4 font-medium">Duration / Memory / Cold Start</th>
                            <th className="py-2.5 font-medium">Telemetry Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/70">
                          {faasTelemetry.functions.map((fn) => (
                            <tr key={fn.function_name} className="hover:bg-slate-800/40 align-top">
                              <td className="py-3 pr-4">
                                <div className="font-mono text-indigo-300 font-medium break-all max-w-xs">
                                  {fn.function_name}
                                </div>
                                {fn.function_arn && (
                                  <div className="text-[10px] font-mono text-slate-500 truncate max-w-xs" title={fn.function_arn}>
                                    {fn.function_arn}
                                  </div>
                                )}
                                <div className="text-[10px] text-slate-400 mt-0.5">Caller: {fn.last_caller}</div>
                              </td>
                              <td className="py-3 pr-4 text-slate-300 whitespace-nowrap font-mono">{fn.region}</td>
                              <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-100">
                                {fn.total_events.toLocaleString()}
                              </td>
                              <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                                {fn.invoke_count} / {fn.assume_role_count} / {fn.in_scope_downstream_count}
                              </td>
                              <td className="py-3 pr-4 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                                {fn.peak_burst_1m} / {fn.peak_burst_5m}
                              </td>
                              <td className="py-3 pr-4 text-right font-mono tabular-nums whitespace-nowrap">
                                <span className={fn.access_denied_count > 0 ? 'text-rose-400 font-medium' : 'text-slate-300'}>
                                  {fn.access_denied_count} ({fn.error_rate_pct.toFixed(2)}%)
                                </span>
                              </td>
                              <td className="py-3 pr-4">
                                {fn.downstream_services.length > 0 ? (
                                  <div className="flex flex-wrap gap-1 max-w-[180px]">
                                    <span className="text-[10px] font-mono text-slate-400 mr-1">
                                      ({fn.downstream_service_breadth})
                                    </span>
                                    {fn.downstream_services.map((svc) => (
                                      <span
                                        key={svc}
                                        className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] font-mono text-sky-300"
                                      >
                                        {svc}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <span className="text-slate-500">None</span>
                                )}
                              </td>
                              <td className="py-3 pr-4">
                                {fn.sensitive_action_count > 0 ? (
                                  <div className="space-y-0.5">
                                    <div className="font-mono text-amber-300 text-[11px]">
                                      {fn.sensitive_action_count.toLocaleString()} ops
                                    </div>
                                    <div className="text-[10px] font-mono text-slate-400 max-w-[160px] truncate" title={fn.sensitive_actions.join(', ')}>
                                      {fn.sensitive_actions.join(', ')}
                                    </div>
                                  </div>
                                ) : (
                                  <span className="text-slate-500">0</span>
                                )}
                              </td>
                              <td className="py-3 pr-4 whitespace-nowrap">
                                <span
                                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] text-slate-400"
                                  title={fn.telemetry_note}
                                >
                                  Unavailable (CloudTrail)
                                </span>
                              </td>
                              <td className="py-3 whitespace-nowrap">
                                {fn.anomaly_flag ? (
                                  <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                                    <AlertTriangle className="w-3.5 h-3.5" /> AccessDenied / Errors
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                                    <CheckCircle2 className="w-3.5 h-3.5" /> CloudTrail Verified
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </SurfacePanel>

            <SurfacePanel
              title="Seeded Simulated FaaS Baseline Scenarios (Demo Reference)"
              subtitle="Static simulated fixtures from SEEDED_LAMBDA_METRICS — kept separate from real CloudTrail telemetry above"
              rightSlot={
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-[11px] font-medium text-amber-300">
                  <Activity className="w-3.5 h-3.5" />
                  SIMULATED SEEDED DATA
                </span>
              }
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
                      <th className="py-2.5 pr-4 font-medium text-right">Avg Duration (Sim)</th>
                      <th className="py-2.5 pr-4 font-medium">Last Caller</th>
                      <th className="py-2.5 font-medium">FaaS Posture (Sim)</th>
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
          </div>
        ) : (
          <div className="space-y-6">
            <SurfacePanel
              title="OpenStack Private Cloud Audit Telemetry (Phase R4)"
              subtitle="Supports Keystone, Nova, Neutron, Glance, and Cinder CADF/audit ingestion with automatic credential redaction and evidence-based risk mapping"
              rightSlot={
                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium border ${
                    osTelemetry?.connectivity_status === 'Connected'
                      ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                      : osTelemetry?.connectivity_status === 'Fixture Mode'
                        ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                        : 'bg-slate-800 border-slate-700 text-slate-300'
                  }`}
                >
                  <Server className="w-3.5 h-3.5" />
                  Status: {osTelemetry?.connectivity_status || 'Not Connected'}
                </span>
              }
            >
              <div className="mb-4 p-3 rounded-lg border border-sky-500/30 bg-sky-950/20 text-xs text-sky-200 flex items-start gap-2.5">
                <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold">Honest Live Connectivity Check:</span>{' '}
                  {osTelemetry?.status_reason ||
                    'No OpenStack endpoint or read-only credentials configured on backend.'}{' '}
                  All tokens/passwords are stripped cleanly during ingestion.
                </div>
              </div>

              {osMsg && (
                <div className="mb-4 px-3 py-2 rounded border border-indigo-500/40 bg-slate-900 text-xs text-indigo-200">
                  {osMsg}
                </div>
              )}

              {osTelemetry && (
                <div className="space-y-5">
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                      <div className="text-[11px] text-slate-400">Total OpenStack Events</div>
                      <div className="text-lg font-semibold font-mono tabular-nums text-slate-100 mt-0.5">
                        {osTelemetry.event_counts.total_events}
                      </div>
                      <div className="text-[10px] text-slate-400">
                        Real: {osTelemetry.event_counts.real_events} · Fixture: {osTelemetry.event_counts.fixture_events}
                      </div>
                    </div>
                    <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                      <div className="text-[11px] text-slate-400">Services Detected</div>
                      <div className="text-lg font-semibold font-mono tabular-nums text-indigo-300 mt-0.5">
                        {osTelemetry.services_detected.length}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate">
                        {osTelemetry.services_detected.map((s) => s.service).join(', ') || 'None'}
                      </div>
                    </div>
                    <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                      <div className="text-[11px] text-slate-400">User / Project Pairs</div>
                      <div className="text-lg font-semibold font-mono tabular-nums text-sky-300 mt-0.5">
                        {osTelemetry.user_project_activity.length}
                      </div>
                      <div className="text-[10px] text-slate-500">Identity-scoped telemetry</div>
                    </div>
                    <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                      <div className="text-[11px] text-slate-400">Failed / Denied</div>
                      <div className="text-lg font-semibold font-mono tabular-nums text-amber-300 mt-0.5">
                        {osTelemetry.event_counts.failed_or_denied_events}
                      </div>
                      <div className="text-[10px] text-slate-500">HTTP 401/403 or Failed</div>
                    </div>
                    <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-3">
                      <div className="text-[11px] text-slate-400">Suspicious Events</div>
                      <div className="text-lg font-semibold font-mono tabular-nums text-rose-300 mt-0.5">
                        {osTelemetry.event_counts.suspicious_events}
                      </div>
                      <div className="text-[10px] text-slate-500">Risk-rule flagged</div>
                    </div>
                  </div>

                  {/* Services + Security Categories */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                    <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                      <div className="font-semibold text-slate-200">Detected OpenStack Services &amp; Provenance</div>
                      {osTelemetry.services_detected.length === 0 ? (
                        <p className="text-slate-400">No OpenStack events stored yet.</p>
                      ) : (
                        <div className="space-y-1.5">
                          {osTelemetry.services_detected.map((svc) => (
                            <div key={svc.service} className="flex items-center justify-between py-1 border-b border-slate-800/60 last:border-0">
                              <span className="font-mono text-indigo-300">{svc.provider}</span>
                              <span className="font-mono text-slate-300">
                                {svc.event_count} events ({svc.real_count} Real · {svc.fixture_count} Fixture)
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                      <div className="font-semibold text-slate-200">Mapped Security Event Categories</div>
                      {osTelemetry.category_breakdown.length === 0 ? (
                        <p className="text-slate-400">No mapped categories yet.</p>
                      ) : (
                        <div className="space-y-1.5">
                          {osTelemetry.category_breakdown.map((cat) => (
                            <div key={cat.category} className="flex items-center justify-between py-1 border-b border-slate-800/60 last:border-0">
                              <span className="text-slate-200">{cat.category}</span>
                              <span className="font-mono text-sky-300">{cat.count}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Ingest Controls */}
                  <div className="p-4 bg-slate-950/70 border border-slate-800 rounded-lg space-y-3 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="font-semibold text-slate-100">OpenStack Audit Ingestion &amp; Fixture Controls</div>
                        <div className="text-slate-400">
                          Load verified multi-service synthetic fixtures (`tests/fixtures/openstack/openstack_audit_sample.json`) or ingest custom JSON exports.
                        </div>
                      </div>
                      <button
                        type="button"
                        disabled={osLoading || currentUser.role === 'Viewer'}
                        onClick={handleLoadOsFixtures}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-amber-600/90 hover:bg-amber-500 disabled:opacity-50 text-white font-medium rounded"
                      >
                        <Upload className="w-3.5 h-3.5" />
                        {osLoading ? 'Loading...' : 'Load Synthetic OpenStack Fixtures'}
                      </button>
                    </div>

                    <form onSubmit={handleIngestOpenStackJson} className="space-y-2 pt-2 border-t border-slate-800">
                      <div className="flex flex-wrap items-center gap-3">
                        <label className="text-slate-300">Data Origin Tag:</label>
                        <select
                          aria-label="OpenStack Ingestion Source Mode"
                          value={osSourceMode}
                          onChange={(e) => setOsSourceMode(e.target.value as 'fixture' | 'real')}
                          className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-slate-200"
                        >
                          <option value="fixture">Synthetic Fixture (is_simulated=true)</option>
                          <option value="real">Real OpenStack Export (is_simulated=false)</option>
                        </select>
                      </div>
                      <textarea
                        rows={3}
                        value={osJsonInput}
                        onChange={(e) => setOsJsonInput(e.target.value)}
                        placeholder='Paste OpenStack JSON array or {"events": [...]} payload...'
                        className="w-full bg-slate-900 border border-slate-700 rounded p-2 font-mono text-[11px] text-slate-200"
                      />
                      <button
                        type="submit"
                        disabled={osLoading || !osJsonInput.trim() || currentUser.role === 'Viewer'}
                        className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded"
                      >
                        Ingest &amp; Redact OpenStack Events
                      </button>
                    </form>
                  </div>

                  {/* User / Project Activity & Suspicious Summary */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs">
                    <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                      <div className="font-semibold text-slate-200">User &amp; Project Activity</div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left border-collapse">
                          <thead>
                            <tr className="border-b border-slate-800 text-slate-400">
                              <th className="py-1.5 pr-3">User / Project</th>
                              <th className="py-1.5 pr-3 text-right">Events</th>
                              <th className="py-1.5 pr-3 text-right">Failed</th>
                              <th className="py-1.5 text-right">Max Risk</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono tabular-nums">
                            {osTelemetry.user_project_activity.map((u) => (
                              <tr key={`${u.cloud_user_id}-${u.project_id}`}>
                                <td className="py-1.5 pr-3 font-sans">
                                  <div className="text-slate-100">{u.cloud_user_id}</div>
                                  <div className="text-[10px] font-mono text-slate-400">
                                    project: {u.project_id} · {u.source_origins.join(', ')}
                                  </div>
                                </td>
                                <td className="py-1.5 pr-3 text-right">{u.event_count}</td>
                                <td className="py-1.5 pr-3 text-right text-amber-300">{u.failed_or_denied}</td>
                                <td className={`py-1.5 text-right font-semibold ${u.max_risk_score >= 65 ? 'text-rose-400' : 'text-emerald-400'}`}>
                                  {u.max_risk_score}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    <div className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-2">
                      <div className="font-semibold text-slate-200">Suspicious Event Summary (Evidence-Based)</div>
                      {osTelemetry.suspicious_events.length === 0 ? (
                        <p className="text-slate-400">No suspicious OpenStack events flagged.</p>
                      ) : (
                        <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                          {osTelemetry.suspicious_events.map((s) => (
                            <div key={s.event_id} className="p-2.5 bg-slate-900/70 border border-slate-800 rounded space-y-1">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-mono text-indigo-300">{s.provider} · {s.action}</span>
                                <span className="font-mono text-rose-400 font-semibold">
                                  {s.risk_level} ({s.risk_score})
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-300">{s.explanation}</div>
                              <div className="text-[10px] font-mono text-slate-400">
                                {s.cloud_user_id} ({s.project_id}) · Origin: {s.is_simulated ? 'Synthetic Fixture' : 'Real OpenStack'}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Latest Normalized OpenStack Records */}
                  <div className="overflow-x-auto">
                    <div className="text-xs font-semibold text-slate-200 mb-2">Latest OpenStack Event Records</div>
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 pr-3 font-medium">Event / Time</th>
                          <th className="py-2 pr-3 font-medium">Service</th>
                          <th className="py-2 pr-3 font-medium">User / Project</th>
                          <th className="py-2 pr-3 font-medium">Action &amp; Category</th>
                          <th className="py-2 pr-3 font-medium">Status</th>
                          <th className="py-2 font-medium">Provenance</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {osTelemetry.latest_events.map((ev) => (
                          <tr key={ev.event_id} className="hover:bg-slate-800/30">
                            <td className="py-2 pr-3 font-mono text-[11px]">
                              <div className="text-slate-200">{ev.event_id}</div>
                              <div className="text-slate-500">{ev.event_time.replace('T', ' ').slice(0, 19)}</div>
                            </td>
                            <td className="py-2 pr-3 text-indigo-300 whitespace-nowrap">{ev.provider}</td>
                            <td className="py-2 pr-3">
                              <div className="text-slate-200">{ev.cloud_user_id}</div>
                              <div className="text-[10px] font-mono text-slate-400">
                                {ev.project_id} · {ev.source_ip}
                              </div>
                            </td>
                            <td className="py-2 pr-3">
                              <div className="font-mono text-slate-200">{ev.action}</div>
                              <div className="text-[10px] text-slate-400">{ev.security_category}</div>
                            </td>
                            <td className="py-2 pr-3 font-mono">
                              <span className={ev.status === 'Success' ? 'text-emerald-400' : 'text-rose-400'}>
                                {ev.status}
                              </span>
                            </td>
                            <td className="py-2 whitespace-nowrap">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-medium border ${
                                  ev.is_simulated
                                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                                }`}
                              >
                                {ev.is_simulated ? 'Synthetic Fixture' : 'Real OpenStack'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </SurfacePanel>
          </div>
        )}
      </DataStateWrapper>
    </div>
  );
}
