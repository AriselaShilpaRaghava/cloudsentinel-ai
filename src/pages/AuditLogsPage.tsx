import React, { useEffect, useState } from 'react';
import { Database, FileUp, Search, Server, Upload, X } from 'lucide-react';
import { api } from '../services/api';
import type {
  AuthUser,
  DatasetRecord,
  IngestionSummary,
  LocalDatasetFileInfo,
  NormalizedAuditEvent,
} from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';

const SAMPLE_AWS_JSON = JSON.stringify(
  {
    Records: [
      {
        eventID: 'aws-ct-9012',
        eventSource: 'iam.amazonaws.com',
        eventTime: '2026-11-15T04:12:00Z',
        userIdentity: { userName: 'd.kline@corp.internal' },
        eventName: 'PutUserPolicy',
        resources: ['arn:aws:iam::904812:user/d.kline'],
        sourceIPAddress: '198.51.100.204',
        status: 'Success',
      },
      {
        eventID: 'aws-ct-9013',
        eventSource: 's3.amazonaws.com',
        eventTime: '2026-11-15T04:15:30Z',
        userIdentity: { userName: 'd.kline@corp.internal' },
        eventName: 'BulkGetObject',
        resources: ['s3://prod-finance-ledger-vault/salaries-2026.csv'],
        sourceIPAddress: '198.51.100.204',
        bytesTransferredMB: 920,
        status: 'Success',
      },
    ],
  },
  null,
  2,
);

const SAMPLE_OPENSTACK_CSV = `event_id,provider,event_time,cloud_user_id,action,resource,source_ip,status,ground_truth_label
os-nova-710,OpenStack Keystone,2026-11-15T03:45:00Z,k.sato@corp.internal,KeystoneAuthenticate,openstack:project/prod-core-infra,185.220.101.88,Failed,1
os-nova-711,OpenStack Nova,2026-11-15T03:48:10Z,k.sato@corp.internal,NovaDeleteServer,nova:regionOne/prod-core-infra/db-replica-02,185.220.101.88,Success,1`;

export function AuditLogsPage({ currentUser }: { currentUser: AuthUser }) {
  const [events, setEvents] = useState<NormalizedAuditEvent[]>([]);
  const [datasets, setDatasets] = useState<DatasetRecord[]>([]);
  const [localFiles, setLocalFiles] = useState<LocalDatasetFileInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [datasetFilter, setDatasetFilter] = useState('ALL');
  const [providerFilter, setProviderFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<NormalizedAuditEvent | null>(null);
  const [activeTab, setActiveTab] = useState<'logs' | 'upload' | 'datasets'>('logs');

  // Upload form state
  const [uploadFormat, setUploadFormat] = useState<'CSV' | 'JSON'>('JSON');
  const [uploadSource, setUploadSource] = useState('Manual Audit Batch');
  const [uploadContent, setUploadContent] = useState(SAMPLE_AWS_JSON);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadSummary, setUploadSummary] = useState<IngestionSummary | null>(null);
  const [uploadResult, setUploadResult] = useState<string | null>(null);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [ingestingFile, setIngestingFile] = useState<string | null>(null);

  const LARGE_FILE_THRESHOLD_BYTES = 1_000_000;

  const loadEvents = async (targetPage = page) => {
    setLoading(true);
    setError(null);
    try {
      const [evRes, dsRes, localRes] = await Promise.all([
        api.getEvents({
          provider: providerFilter,
          status: statusFilter,
          dataset_id: datasetFilter,
          search,
          page: targetPage,
          pageSize: 12,
        }),
        api.getDatasets(),
        api.getLocalDatasets(),
      ]);
      setEvents(evRes.items);
      setTotal(evRes.total);
      setTotalPages(evRes.totalPages);
      setDatasets(dsRes.datasets);
      setLocalFiles(localRes.files);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit events.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents(page);
  }, [page, providerFilter, statusFilter, datasetFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadEvents(1);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.name.toLowerCase().endsWith('.csv')) setUploadFormat('CSV');
    else if (file.name.toLowerCase().endsWith('.json')) setUploadFormat('JSON');
    setUploadSource(file.name);
    setUploadSummary(null);
    setUploadResult(null);
    setUploadErr(null);

    if (file.size > LARGE_FILE_THRESHOLD_BYTES) {
      setSelectedFile(file);
      return;
    }

    setSelectedFile(null);
    const reader = new FileReader();
    reader.onload = () => {
      setUploadContent(String(reader.result || ''));
    };
    reader.readAsText(file);
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setUploading(true);
    setUploadResult(null);
    setUploadSummary(null);
    setUploadErr(null);
    try {
      const res = selectedFile
        ? await api.uploadAuditLogFile(selectedFile, {
            format: uploadFormat,
            source_name: uploadSource,
          })
        : await api.uploadAuditLogs({
            content: uploadContent,
            format: uploadFormat,
            source_name: uploadSource,
          });
      setUploadSummary(res.summary);
      setUploadResult(res.message);
      setPage(1);
      await loadEvents(1);
    } catch (err) {
      setUploadErr(err instanceof Error ? err.message : 'Upload validation failed.');
    } finally {
      setUploading(false);
    }
  };

  const handleIngestLocal = async (file: LocalDatasetFileInfo) => {
    setIngestingFile(file.filename);
    setUploadResult(null);
    setUploadSummary(null);
    setUploadErr(null);
    try {
      const res = await api.ingestLocalDataset({
        filename: file.filename,
        dataset_role: file.suggested_role,
      });
      setUploadSummary(res.summary);
      setUploadResult(
        res.already_registered
          ? `Dataset '${res.dataset.name}' already registered (0 new events imported; ${res.summary.skipped_rows} skipped).`
          : `Ingested '${res.dataset.name}' (${res.summary.imported_rows} imported, ${res.summary.benign_count} benign, ${res.summary.attack_count} attack).`,
      );
      setPage(1);
      await loadEvents(1);
    } catch (err) {
      setUploadErr(err instanceof Error ? err.message : 'Server-side dataset ingestion failed.');
    } finally {
      setIngestingFile(null);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Audit Log Monitoring & Normalization"
        description="Unified normalized audit schema (event_id, provider, event_time, cloud_user_id, action, resource, source_ip, status, raw_event) supporting AWS, OpenStack, and CERT-mapped CSV/JSON uploads."
        actions={
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            {[
              { id: 'logs', label: `Audit Stream (${total})` },
              { id: 'upload', label: 'Upload CSV / JSON' },
              { id: 'datasets', label: `Datasets & Provenance (${datasets.length})` },
            ].map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setActiveTab(t.id as typeof activeTab)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  activeTab === t.id ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        }
      />

      {activeTab === 'logs' && (
        <>
          <SurfacePanel>
            <form onSubmit={handleSearchSubmit} className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[220px]">
                <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" aria-hidden="true" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search user, action, resource, IP, or event_id..."
                  className="w-full bg-slate-950 border border-slate-700 rounded pl-9 pr-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <select
                value={datasetFilter}
                onChange={(e) => {
                  setDatasetFilter(e.target.value);
                  setPage(1);
                }}
                aria-label="Filter by dataset"
                className="bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 max-w-[220px]"
              >
                <option value="ALL">All Datasets</option>
                {datasets.map((ds) => (
                  <option key={ds.dataset_id} value={ds.dataset_id}>
                    {ds.name} ({ds.imported_rows ?? ds.valid_rows})
                  </option>
                ))}
              </select>
              <select
                value={providerFilter}
                onChange={(e) => {
                  setProviderFilter(e.target.value);
                  setPage(1);
                }}
                aria-label="Filter by cloud provider"
                className="bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Providers</option>
                <option value="AWS CloudTrail">AWS CloudTrail</option>
                <option value="AWS Lambda">AWS Lambda</option>
                <option value="AWS IAM">AWS IAM</option>
                <option value="OpenStack Keystone">OpenStack Keystone</option>
                <option value="OpenStack Nova">OpenStack Nova</option>
                <option value="CERT Mapped">CERT Mapped</option>
              </select>
              <select
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value);
                  setPage(1);
                }}
                aria-label="Filter by event status"
                className="bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="Success">Success</option>
                <option value="Failed">Failed</option>
                <option value="Denied">Denied</option>
              </select>
              <button
                type="submit"
                className="px-4 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded transition-colors whitespace-nowrap"
              >
                Apply Filters
              </button>
            </form>
          </SurfacePanel>

          <DataStateWrapper
            loading={loading}
            error={error}
            isEmpty={events.length === 0}
            emptyTitle="No audit events match the active filters"
            emptyDescription="Adjust provider/status filters or upload a CSV/JSON audit batch."
            onRetry={() => loadEvents(page)}
          >
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
              <SurfacePanel className={selectedEvent ? 'xl:col-span-2' : 'xl:col-span-3'}>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 pr-3 font-medium">Event ID</th>
                        <th className="py-2.5 pr-3 font-medium">Timestamp (UTC)</th>
                        <th className="py-2.5 pr-3 font-medium">Provider</th>
                        <th className="py-2.5 pr-3 font-medium">Cloud User</th>
                        <th className="py-2.5 pr-3 font-medium">Action</th>
                        <th className="py-2.5 pr-3 font-medium">Resource</th>
                        <th className="py-2.5 pr-3 font-medium">Source IP</th>
                        <th className="py-2.5 font-medium">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {events.map((ev) => (
                        <tr
                          key={ev.event_id}
                          onClick={() => setSelectedEvent(ev)}
                          className={`cursor-pointer transition-colors ${
                            selectedEvent?.event_id === ev.event_id ? 'bg-indigo-950/30' : 'hover:bg-slate-800/40'
                          }`}
                        >
                          <td className="py-2.5 pr-3 font-mono text-slate-300 whitespace-nowrap">{ev.event_id}</td>
                          <td className="py-2.5 pr-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                            {ev.event_time.replace('T', ' ').slice(0, 19)}
                          </td>
                          <td className="py-2.5 pr-3 text-slate-300 whitespace-nowrap">{ev.provider}</td>
                          <td className="py-2.5 pr-3 font-mono text-slate-100 whitespace-nowrap">{ev.cloud_user_id}</td>
                          <td className="py-2.5 pr-3 font-mono text-indigo-300 whitespace-nowrap">{ev.action}</td>
                          <td className="py-2.5 pr-3 font-mono text-slate-400 max-w-[200px] truncate">{ev.resource}</td>
                          <td className="py-2.5 pr-3 font-mono tabular-nums text-slate-300 whitespace-nowrap">
                            {ev.source_ip}
                          </td>
                          <td className="py-2.5">
                            <StatusText status={ev.status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                  <span className="font-mono tabular-nums">
                    Showing page {page} of {totalPages} ({total} total normalized events)
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={page <= 1}
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      className="px-3 py-1 bg-slate-900 border border-slate-700 rounded disabled:opacity-40 hover:bg-slate-800 text-slate-200"
                    >
                      Previous
                    </button>
                    <button
                      type="button"
                      disabled={page >= totalPages}
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      className="px-3 py-1 bg-slate-900 border border-slate-700 rounded disabled:opacity-40 hover:bg-slate-800 text-slate-200"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </SurfacePanel>

              {selectedEvent && (
                <SurfacePanel
                  title={`Event Inspector · ${selectedEvent.event_id}`}
                  subtitle={selectedEvent.dataset_source}
                  rightSlot={
                    <button
                      type="button"
                      onClick={() => setSelectedEvent(null)}
                      className="text-xs text-slate-400 hover:text-slate-200"
                    >
                      Close
                    </button>
                  }
                >
                  <div className="space-y-3 text-xs">
                    <div className="grid grid-cols-2 gap-2 border-b border-slate-800 pb-3">
                      <div>
                        <span className="text-slate-500 block">Provider</span>
                        <span className="text-slate-200">{selectedEvent.provider}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block">Identity Type / Provenance</span>
                        <span className="text-slate-200">
                          {selectedEvent.identity_type || 'Standard'} ·{' '}
                          {selectedEvent.is_simulated ? 'Simulated' : 'Ingested'}
                        </span>
                      </div>
                      {selectedEvent.ground_truth_label !== undefined && (
                        <div>
                          <span className="text-slate-500 block">Ground Truth (Eval Only)</span>
                          <span className={selectedEvent.ground_truth_label === 1 ? 'text-rose-400 font-medium' : 'text-emerald-400 font-medium'}>
                            {selectedEvent.ground_truth_label === 1 ? 'Attack' : 'Benign'}
                            {selectedEvent.attack_name ? ` (${selectedEvent.attack_name})` : ''}
                          </span>
                        </div>
                      )}
                      {selectedEvent.dataset_id && (
                        <div>
                          <span className="text-slate-500 block">Dataset ID</span>
                          <span className="font-mono text-slate-300">{selectedEvent.dataset_id}</span>
                        </div>
                      )}
                    </div>
                    <div>
                      <span className="text-slate-400 block mb-1">Normalized Schema & Raw Payload</span>
                      <pre className="bg-slate-950 border border-slate-800 rounded p-3 font-mono text-[11px] text-slate-300 overflow-x-auto max-h-80">
                        {JSON.stringify(selectedEvent, null, 2)}
                      </pre>
                    </div>
                  </div>
                </SurfacePanel>
              )}
            </div>
          </DataStateWrapper>
        </>
      )}

      {activeTab === 'upload' && (
        <SurfacePanel
          title="Upload & Normalize Audit Logs (CSV or JSON)"
          subtitle="Supports AWS CloudTrail { Records: [...] }, OpenStack Nova/Keystone CSV, or normalized schema"
        >
          <form onSubmit={handleUploadSubmit} className="space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-slate-300 mb-1">Upload Local File (.csv or .json)</label>
                <label className="flex items-center justify-center gap-2 px-3 py-2 bg-slate-950 border border-dashed border-slate-700 hover:border-indigo-500 rounded cursor-pointer text-slate-300">
                  <FileUp className="w-4 h-4 text-indigo-400" />
                  <span>Choose CSV or JSON File</span>
                  <input type="file" accept=".csv,.json,text/csv,application/json" onChange={handleFileChange} className="hidden" />
                </label>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Format</label>
                <select
                  value={uploadFormat}
                  onChange={(e) => setUploadFormat(e.target.value as 'CSV' | 'JSON')}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                >
                  <option value="JSON">JSON (CloudTrail / Normalized)</option>
                  <option value="CSV">CSV (OpenStack / CERT / Tabular)</option>
                </select>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Batch Source Label</label>
                <input
                  type="text"
                  required
                  value={uploadSource}
                  onChange={(e) => setUploadSource(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-slate-400">Load Quick Template:</span>
              <button
                type="button"
                onClick={() => {
                  setUploadFormat('JSON');
                  setUploadSource('Sample AWS CloudTrail Batch');
                  setUploadContent(SAMPLE_AWS_JSON);
                }}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
              >
                AWS CloudTrail JSON
              </button>
              <button
                type="button"
                onClick={() => {
                  setUploadFormat('CSV');
                  setUploadSource('Sample OpenStack Nova/Keystone CSV');
                  setUploadContent(SAMPLE_OPENSTACK_CSV);
                }}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
              >
                OpenStack CSV
              </button>
            </div>

            <div>
              <label className="block text-slate-300 mb-1">
                {selectedFile ? 'Direct Stream File Selected (Bypassing Browser Textarea)' : 'Raw CSV / JSON Payload'}
              </label>
              {selectedFile ? (
                <div className="p-4 bg-slate-950 border border-indigo-500/40 rounded flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="font-mono text-slate-100 font-medium">{selectedFile.name}</div>
                    <div className="text-slate-400">
                      {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB · Streaming directly to server-side CloudTrail normalizer
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedFile(null)}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
                  >
                    <X className="w-3.5 h-3.5" /> Clear File
                  </button>
                </div>
              ) : (
                <textarea
                  rows={10}
                  required
                  value={uploadContent}
                  onChange={(e) => setUploadContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded p-3 font-mono text-[11px] text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              )}
            </div>

            <div className="flex items-center justify-between gap-4">
              <button
                type="submit"
                disabled={uploading || currentUser.role === 'Viewer'}
                className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
              >
                <Upload className="w-3.5 h-3.5" />
                {uploading ? 'Validating & Normalizing...' : 'Validate, Normalize & Ingest'}
              </button>
              {currentUser.role === 'Viewer' && (
                <span className="text-amber-400">Viewer role is read-only; switch to Security Analyst or Admin to upload logs.</span>
              )}
            </div>

            {uploadResult && (
              <div className="p-3 bg-emerald-950/30 border border-emerald-500/30 rounded text-emerald-200 space-y-2">
                <div>{uploadResult}</div>
                {uploadSummary && (
                  <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 pt-2 border-t border-emerald-500/20 font-mono text-[11px]">
                    <div>Source: {uploadSummary.total_rows}</div>
                    <div>Normalized: {uploadSummary.normalized_rows}</div>
                    <div>Imported: {uploadSummary.imported_rows}</div>
                    <div>Rejected: {uploadSummary.rejected_rows}</div>
                    <div>Skipped: {uploadSummary.skipped_rows}</div>
                    <div>
                      Labels: {uploadSummary.benign_count}B / {uploadSummary.attack_count}A
                    </div>
                  </div>
                )}
                {uploadSummary && (uploadSummary.skip_reasons.length > 0 || uploadSummary.rejection_reasons.length > 0) && (
                  <div className="text-[11px] text-slate-300 space-y-0.5">
                    {uploadSummary.skip_reasons.map((r, i) => (
                      <div key={`skip-${i}`}>Skipped reason: {r}</div>
                    ))}
                    {uploadSummary.rejection_reasons.map((r, i) => (
                      <div key={`rej-${i}`} className="text-amber-300">Rejected reason: {r}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {uploadErr && (
              <div className="p-3 bg-rose-950/30 border border-rose-500/30 rounded text-rose-200">{uploadErr}</div>
            )}
          </form>
        </SurfacePanel>
      )}

      {activeTab === 'datasets' && (
        <div className="space-y-4">
          {localFiles.length > 0 && (
            <SurfacePanel
              title="Server-Side Workspace Datasets (Safe Local Ingestion)"
              subtitle="Ingest large CloudTrail datasets directly on the backend without loading 50 MB JSON into the browser"
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {localFiles.map((lf) => (
                  <div
                    key={lf.filename}
                    className="p-3.5 bg-slate-950/70 border border-slate-800 rounded-lg flex items-center justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 font-mono text-slate-100 font-medium truncate">
                        <Server className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                        <span className="truncate">{lf.filename}</span>
                      </div>
                      <div className="text-slate-400 mt-1 flex items-center gap-2">
                        <span>{(lf.size_bytes / (1024 * 1024)).toFixed(2)} MB</span>
                        <span aria-hidden="true">·</span>
                        <span>{lf.format}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-indigo-300 uppercase font-mono text-[10px]">{lf.suggested_role}</span>
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={ingestingFile !== null || currentUser.role === 'Viewer' || lf.already_registered}
                      onClick={() => handleIngestLocal(lf)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded whitespace-nowrap shrink-0"
                    >
                      <Database className="w-3.5 h-3.5" />
                      {lf.already_registered
                        ? 'Ingested'
                        : ingestingFile === lf.filename
                          ? 'Ingesting...'
                          : 'Ingest on Server'}
                    </button>
                  </div>
                ))}
              </div>
              {uploadResult && (
                <div className="mt-3 p-3 bg-emerald-950/30 border border-emerald-500/30 rounded text-xs text-emerald-200">
                  {uploadResult}
                </div>
              )}
              {uploadErr && (
                <div className="mt-3 p-3 bg-rose-950/30 border border-rose-500/30 rounded text-xs text-rose-200">
                  {uploadErr}
                </div>
              )}
            </SurfacePanel>
          )}

          {datasets.map((ds) => (
            <SurfacePanel
              key={ds.dataset_id}
              title={ds.name}
              subtitle={`${ds.provenance}${ds.dataset_role ? ` · Role: ${ds.dataset_role}` : ''}`}
              rightSlot={<StatusText status={ds.preprocessed ? 'Preprocessed' : 'Raw'} />}
            >
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4 text-xs border-b border-slate-800 pb-4">
                <div>
                  <span className="text-slate-400 block">Dataset ID / Format</span>
                  <span className="font-mono text-slate-100">{ds.dataset_id} · {ds.source_type}</span>
                </div>
                <div>
                  <span className="text-slate-400 block">Imported / Normalized / Total</span>
                  <span className="font-mono tabular-nums text-slate-100">
                    {ds.imported_rows ?? ds.valid_rows} / {ds.normalized_rows ?? ds.valid_rows} / {ds.total_rows}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Rejected / Skipped</span>
                  <span className="font-mono tabular-nums text-slate-100">
                    {ds.rejected_rows ?? 0} rej · {ds.skipped_rows ?? ds.duplicate_count} skip
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Labels (Benign / Attack)</span>
                  <span className="font-mono tabular-nums text-slate-100">
                    {ds.benign_count ?? 0} B · {ds.attack_count ?? 0} A
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Original vs Adapted FaaS</span>
                  <span className="font-mono tabular-nums text-slate-100">
                    {ds.original_records_count} orig · {ds.adapted_faas_count} FaaS
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Train / Val / Test</span>
                  <span className="font-mono tabular-nums text-indigo-300">
                    {Math.round(ds.split_ratio.train * 100)}/{Math.round(ds.split_ratio.val * 100)}/
                    {Math.round(ds.split_ratio.test * 100)}
                  </span>
                </div>
              </div>
              {(ds.skip_reasons?.length || ds.rejection_reasons?.length) ? (
                <div className="pt-2.5 text-[11px] text-slate-400 space-y-0.5 border-b border-slate-800/70 pb-2.5">
                  {ds.skip_reasons?.map((r, i) => (
                    <div key={`ds-skip-${i}`}>Skipped: {r}</div>
                  ))}
                  {ds.rejection_reasons?.map((r, i) => (
                    <div key={`ds-rej-${i}`} className="text-amber-300">Rejected: {r}</div>
                  ))}
                </div>
              ) : null}
              <div className="pt-3 text-xs text-slate-400">
                Extracted Feature Vector ({ds.features_extracted.length}):{' '}
                <span className="font-mono text-slate-300">{ds.features_extracted.join(', ')}</span>
              </div>
            </SurfacePanel>
          ))}
        </div>
      )}
    </div>
  );
}
