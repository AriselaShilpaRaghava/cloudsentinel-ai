import React, { useState, useEffect, useRef } from 'react';
import { AuditLog } from '../types';
import { api } from '../services/api';
import {
  UploadCloud,
  Search,
  Filter,
  CheckCircle2,
  AlertCircle,
  FileText,
  Eye,
  X,
  Download
} from 'lucide-react';

interface AuditLogsProps {
  onRefreshDashboard: () => void;
}

export const AuditLogs: React.FC<AuditLogsProps> = ({ onRefreshDashboard }) => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchUser, setSearchUser] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [page, setPage] = useState(0);
  const pageSize = 15;

  // Upload state
  const [uploading, setUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Detail Modal
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const data = await api.getLogs({ limit: 500 });
      setLogs(data);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.name.endsWith('.csv')) {
      setUploadMessage({ type: 'error', text: 'Invalid file format. Please upload a standard CSV file.' });
      return;
    }

    try {
      setUploading(true);
      setUploadMessage(null);
      const res = await api.uploadLogs(file);
      setUploadMessage({
        type: 'success',
        text: `Ingestion complete: ${res.logs_imported} logs stored. (${res.duplicates_skipped} duplicates skipped).`
      });
      fetchLogs();
      onRefreshDashboard();
    } catch (err: any) {
      setUploadMessage({ type: 'error', text: err.message || 'CSV upload failed.' });
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Filter logs
  const filteredLogs = logs.filter((log) => {
    const matchesUser = searchUser === '' || log.user_id.toLowerCase().includes(searchUser.toLowerCase()) || log.resource.toLowerCase().includes(searchUser.toLowerCase());
    const matchesAction = filterAction === 'all' || log.action === filterAction;
    const matchesStatus = filterStatus === 'all' || log.status.toLowerCase() === filterStatus.toLowerCase();
    return matchesUser && matchesAction && matchesStatus;
  });

  const paginatedLogs = filteredLogs.slice(page * pageSize, (page + 1) * pageSize);
  const totalPages = Math.ceil(filteredLogs.length / pageSize) || 1;

  // Extract distinct actions for filter dropdown
  const uniqueActions = Array.from(new Set(logs.map((l) => l.action))).sort();

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Upload & Validation Banner */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-[#F8FAFC]">
            Cloud Audit Log Ingestion (CSV)
          </h3>
          <p className="text-xs text-[#94A3B8] mt-0.5">
            Expected schema: <span className="font-mono text-[#22D3EE]">timestamp, user_id, action, resource, source_ip, status</span>
          </p>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept=".csv"
            className="hidden"
            id="audit-csv-upload"
          />
          <label
            htmlFor="audit-csv-upload"
            className={`px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors cursor-pointer flex items-center gap-2 whitespace-nowrap ${
              uploading ? 'opacity-50 pointer-events-none' : ''
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>{uploading ? 'Validating & Uploading...' : 'Upload Audit CSV'}</span>
          </label>
        </div>
      </div>

      {/* Upload Feedback */}
      {uploadMessage && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
            uploadMessage.type === 'success'
              ? 'bg-[#22C55E]/10 border-[#22C55E]/30 text-[#22C55E]'
              : 'bg-[#EF4444]/10 border-[#EF4444]/30 text-[#EF4444]'
          }`}
        >
          {uploadMessage.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 shrink-0" />
          )}
          <span>{uploadMessage.text}</span>
          <button
            onClick={() => setUploadMessage(null)}
            className="ml-auto text-[#94A3B8] hover:text-[#F8FAFC]"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Controls Bar: Search & Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl text-xs">
        <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-md bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5">
          <Search className="w-3.5 h-3.5 text-[#94A3B8]" />
          <input
            type="text"
            placeholder="Search by user ID or resource..."
            value={searchUser}
            onChange={(e) => {
              setSearchUser(e.target.value);
              setPage(0);
            }}
            className="bg-transparent text-[#F8FAFC] placeholder-[#64748B] focus:outline-none w-full text-xs"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Action Filter */}
          <div className="flex items-center gap-1.5 bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-2 py-1">
            <Filter className="w-3 h-3 text-[#94A3B8]" />
            <select
              value={filterAction}
              onChange={(e) => {
                setFilterAction(e.target.value);
                setPage(0);
              }}
              className="bg-transparent text-[#F8FAFC] text-xs focus:outline-none"
            >
              <option value="all" className="bg-[#111C2E]">All Actions</option>
              {uniqueActions.map((act) => (
                <option key={act} value={act} className="bg-[#111C2E]">
                  {act}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-2 py-1">
            <select
              value={filterStatus}
              onChange={(e) => {
                setFilterStatus(e.target.value);
                setPage(0);
              }}
              className="bg-transparent text-[#F8FAFC] text-xs focus:outline-none"
            >
              <option value="all" className="bg-[#111C2E]">All Statuses</option>
              <option value="success" className="bg-[#111C2E]">Success</option>
              <option value="failure" className="bg-[#111C2E]">Failure</option>
            </select>
          </div>

          <div className="text-[#94A3B8] font-mono pl-2">
            Showing {filteredLogs.length} logs
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#111C2E] border-b border-[#1E2D4A] text-[#94A3B8]">
                <th className="py-2.5 px-4 font-medium">Log ID</th>
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium">User ID</th>
                <th className="py-2.5 px-4 font-medium">Action</th>
                <th className="py-2.5 px-4 font-medium">Resource</th>
                <th className="py-2.5 px-4 font-medium">Source IP</th>
                <th className="py-2.5 px-4 font-medium">Status</th>
                <th className="py-2.5 px-4 font-medium text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#94A3B8]">
                    Loading audit records...
                  </td>
                </tr>
              ) : paginatedLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#94A3B8]">
                    No audit records match the current filters.
                  </td>
                </tr>
              ) : (
                paginatedLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#1E2F4C] transition-colors">
                    <td className="py-2.5 px-4 font-mono text-[#64748B]">#{log.id}</td>
                    <td className="py-2.5 px-4 font-mono text-[#94A3B8] whitespace-nowrap">
                      {log.timestamp}
                    </td>
                    <td className="py-2.5 px-4 font-medium text-[#F8FAFC]">
                      {log.user_id}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[#22D3EE]">
                      {log.action}
                    </td>
                    <td className="py-2.5 px-4 text-[#94A3B8] truncate max-w-[160px]">
                      {log.resource}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[#94A3B8]">
                      {log.source_ip}
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`font-semibold ${
                          log.status.toLowerCase() === 'success'
                            ? 'text-[#22C55E]'
                            : 'text-[#EF4444]'
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="p-1 text-[#94A3B8] hover:text-[#22D3EE] transition-colors"
                        title="View Full JSON Record"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="flex items-center justify-between p-3 border-t border-[#1E2D4A] text-xs text-[#94A3B8]">
          <div>
            Page <span className="font-mono text-[#F8FAFC]">{page + 1}</span> of{' '}
            <span className="font-mono text-[#F8FAFC]">{totalPages}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-2.5 py-1 bg-[#111C2E] border border-[#1E2D4A] rounded hover:bg-[#1E2F4C] text-[#F8FAFC] disabled:opacity-40"
            >
              Previous
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-2.5 py-1 bg-[#111C2E] border border-[#1E2D4A] rounded hover:bg-[#1E2F4C] text-[#F8FAFC] disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-lg w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-[#22D3EE]" />
                <h3 className="text-sm font-semibold text-[#F8FAFC]">
                  Audit Log #{selectedLog.id} Metadata
                </h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <div className="grid grid-cols-3 gap-1 py-1 border-b border-[#1E2D4A]">
                <span className="text-[#94A3B8]">Timestamp</span>
                <span className="col-span-2 font-mono text-[#F8FAFC]">{selectedLog.timestamp}</span>
              </div>
              <div className="grid grid-cols-3 gap-1 py-1 border-b border-[#1E2D4A]">
                <span className="text-[#94A3B8]">User ID</span>
                <span className="col-span-2 font-medium text-[#F8FAFC]">{selectedLog.user_id}</span>
              </div>
              <div className="grid grid-cols-3 gap-1 py-1 border-b border-[#1E2D4A]">
                <span className="text-[#94A3B8]">Action</span>
                <span className="col-span-2 font-mono text-[#22D3EE]">{selectedLog.action}</span>
              </div>
              <div className="grid grid-cols-3 gap-1 py-1 border-b border-[#1E2D4A]">
                <span className="text-[#94A3B8]">Resource</span>
                <span className="col-span-2 text-[#F8FAFC]">{selectedLog.resource}</span>
              </div>
              <div className="grid grid-cols-3 gap-1 py-1 border-b border-[#1E2D4A]">
                <span className="text-[#94A3B8]">Source IP</span>
                <span className="col-span-2 font-mono text-[#F8FAFC]">{selectedLog.source_ip}</span>
              </div>
              <div className="grid grid-cols-3 gap-1 py-1 border-b border-[#1E2D4A]">
                <span className="text-[#94A3B8]">Status</span>
                <span className="col-span-2 font-semibold text-[#22C55E]">{selectedLog.status}</span>
              </div>
              <div className="grid grid-cols-3 gap-1 py-1">
                <span className="text-[#94A3B8]">Batch ID</span>
                <span className="col-span-2 font-mono text-[#64748B]">{selectedLog.upload_batch_id || 'manual'}</span>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 bg-[#111C2E] hover:bg-[#1E2F4C] text-xs font-medium text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
