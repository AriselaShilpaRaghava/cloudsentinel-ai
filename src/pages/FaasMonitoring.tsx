import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { FaasEvent } from '../types';
import {
  Zap,
  Clock,
  Key,
  ShieldAlert,
  PlusCircle,
  CheckCircle2,
  AlertTriangle,
  Play,
  Layers,
  Server
} from 'lucide-react';

export const FaasMonitoring: React.FC = () => {
  const [events, setEvents] = useState<FaasEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // New simulated event form state
  const [fnName, setFnName] = useState('fn_data_migrator');
  const [userId, setUserId] = useState('usr_ops_eve');
  const [duration, setDuration] = useState(4920);
  const [permission, setPermission] = useState('kms:*');
  const [resource, setResource] = useState('kms_keystone');
  const [eventType, setEventType] = useState('CRON_TRIGGER');

  const fetchEvents = async () => {
    try {
      setLoading(true);
      const data = await api.getFaasEvents();
      setEvents(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  const handleSimulateInvocation = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSubmitting(true);
      await api.recordFaasEvent({
        function_name: fnName,
        function_id: `fn-${Date.now().toString().slice(-4)}`,
        user_id: userId,
        request_id: `req-${Date.now().toString().slice(-6)}`,
        event_type: eventType,
        execution_duration_ms: Number(duration),
        permission: permission,
        resource: resource,
        timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
        status: 'SUCCESS',
      });
      setModalOpen(false);
      await fetchEvents();
    } catch (e) {
      console.error(e);
    } finally {
      setSubmitting(false);
    }
  };

  const totalInvocations = events.length;
  const anomalousCount = events.filter((e) => e.is_anomalous).length;
  const avgDuration = events.length > 0
    ? Math.round(events.reduce((sum, e) => sum + e.execution_duration_ms, 0) / events.length)
    : 0;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Overview Banner */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-[#FBBF24]" />
            <h3 className="text-sm font-semibold text-[#F8FAFC]">
              Serverless (FaaS) Application Telemetry Monitor
            </h3>
          </div>
          <p className="text-xs text-[#94A3B8] mt-1">
            Real-time audit log analysis applied to function invocations, execution duration P99 spikes, and IAM permission scopes.
          </p>
        </div>

        <button
          onClick={() => setModalOpen(true)}
          className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>Simulate Function Invocation</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
          <span className="text-xs text-[#94A3B8]">Total Function Invocations</span>
          <div className="mt-1 text-2xl font-bold font-mono text-[#F8FAFC]">
            {totalInvocations}
          </div>
          <span className="text-[11px] text-[#94A3B8] mt-1 font-mono">
            Simulated & Ingested
          </span>
        </div>

        <div className="p-4 bg-[#17243A] border border-[#EF4444]/30 rounded-xl">
          <span className="text-xs text-[#94A3B8]">Anomalous Executions</span>
          <div className="mt-1 text-2xl font-bold font-mono text-[#EF4444]">
            {anomalousCount}
          </div>
          <span className="text-[11px] text-[#EF4444] mt-1">
            Over-privileged or execution spike
          </span>
        </div>

        <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
          <span className="text-xs text-[#94A3B8]">Mean Execution Duration</span>
          <div className="mt-1 text-2xl font-bold font-mono text-[#22D3EE]">
            {avgDuration} ms
          </div>
          <span className="text-[11px] text-[#94A3B8] mt-1">
            P99 baseline: 4000 ms
          </span>
        </div>

        <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl">
          <span className="text-xs text-[#94A3B8]">Adapter Architecture</span>
          <div className="mt-1 text-base font-semibold text-[#F8FAFC] flex items-center gap-1.5">
            <Server className="w-4 h-4 text-[#38BDF8]" />
            <span>OpenStack / FaaS Ready</span>
          </div>
          <span className="text-[11px] text-[#22C55E] mt-1">
            Audit Stream Consumer Active
          </span>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 bg-[#111C2E] border-b border-[#1E2D4A] flex items-center justify-between">
          <h4 className="text-xs font-semibold text-[#F8FAFC]">
            Monitored Serverless Function Invocations
          </h4>
          <span className="text-xs font-mono text-[#94A3B8]">
            Environment: Simulated Testbed FaaS
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-[#111C2E]/60 border-b border-[#1E2D4A] text-[#94A3B8]">
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium">Function Name</th>
                <th className="py-2.5 px-4 font-medium">Invoking User</th>
                <th className="py-2.5 px-4 font-medium">Trigger Type</th>
                <th className="py-2.5 px-4 font-medium">Requested Permission</th>
                <th className="py-2.5 px-4 font-medium text-right">Duration</th>
                <th className="py-2.5 px-4 font-medium text-right">Anomaly Flag</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D4A]">
              {loading ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#94A3B8]">
                    Loading serverless telemetry...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-[#94A3B8]">
                    No FaaS events recorded yet. Click "Simulate Function Invocation" to test.
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-[#1E2F4C] transition-colors">
                    <td className="py-2.5 px-4 font-mono text-[#94A3B8] whitespace-nowrap">
                      {evt.timestamp}
                    </td>
                    <td className="py-2.5 px-4 font-mono font-medium text-[#22D3EE]">
                      {evt.function_name}
                    </td>
                    <td className="py-2.5 px-4 font-medium text-[#F8FAFC]">
                      {evt.user_id}
                    </td>
                    <td className="py-2.5 px-4 text-[#94A3B8]">
                      {evt.event_type}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-[#F59E0B]">
                      {evt.permission}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-right text-[#F8FAFC]">
                      {evt.execution_duration_ms} ms
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      {evt.is_anomalous ? (
                        <div className="flex items-center justify-end gap-1.5 text-[#EF4444] font-semibold">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          <span>Anomalous</span>
                        </div>
                      ) : (
                        <div className="flex items-center justify-end gap-1.5 text-[#22C55E]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Nominal</span>
                        </div>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Simulation Modal */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <form
            onSubmit={handleSimulateInvocation}
            className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-md w-full p-5 space-y-4 shadow-xl"
          >
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#FBBF24]" />
                <h3 className="text-sm font-semibold text-[#F8FAFC]">
                  Simulate FaaS Function Execution
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-[#94A3B8] font-medium block mb-1">
                  Function Name
                </label>
                <input
                  type="text"
                  value={fnName}
                  onChange={(e) => setFnName(e.target.value)}
                  className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 text-[#F8FAFC] text-xs focus:outline-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    User Identity
                  </label>
                  <input
                    type="text"
                    value={userId}
                    onChange={(e) => setUserId(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 text-[#F8FAFC] text-xs focus:outline-none"
                    required
                  />
                </div>
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Event Trigger
                  </label>
                  <select
                    value={eventType}
                    onChange={(e) => setEventType(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 text-[#F8FAFC] text-xs focus:outline-none"
                  >
                    <option value="CRON_TRIGGER">CRON_TRIGGER</option>
                    <option value="HTTP_TRIGGER">HTTP_TRIGGER</option>
                    <option value="S3_EVENT">S3_EVENT</option>
                    <option value="AUTH_WEBHOOK">AUTH_WEBHOOK</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Execution Duration (ms)
                  </label>
                  <input
                    type="number"
                    value={duration}
                    onChange={(e) => setDuration(Number(e.target.value))}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 text-[#F8FAFC] text-xs focus:outline-none font-mono"
                    required
                  />
                </div>
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Requested Permission
                  </label>
                  <input
                    type="text"
                    value={permission}
                    onChange={(e) => setPermission(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 text-[#F8FAFC] text-xs focus:outline-none font-mono"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-[#94A3B8] font-medium block mb-1">
                  Target Resource
                </label>
                <input
                  type="text"
                  value={resource}
                  onChange={(e) => setResource(e.target.value)}
                  className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 text-[#F8FAFC] text-xs focus:outline-none"
                  required
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-3 py-1.5 bg-[#111C2E] hover:bg-[#1E2F4C] text-xs font-medium text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-xs font-medium text-white rounded-lg transition-colors disabled:opacity-50"
                >
                  {submitting ? 'Triggering...' : 'Emit Event'}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
