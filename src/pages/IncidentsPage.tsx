import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { AuthUser, IncidentStatus, SecurityIncident } from '../types/security';
import {
  DataStateWrapper,
  SectionHeader,
  SeverityText,
  StatusText,
  SurfacePanel,
} from '../components/ui/SocPrimitives';

export function IncidentsPage({ currentUser }: { currentUser: AuthUser }) {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [selected, setSelected] = useState<SecurityIncident | null>(null);
  const [statusFilter, setStatusFilter] = useState<'ALL' | IncidentStatus>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [noteInput, setNoteInput] = useState('');
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const loadIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getIncidents();
      setIncidents(res.incidents);
      setSelected((prev) =>
        prev ? res.incidents.find((i) => i.incident_id === prev.incident_id) || res.incidents[0] || null : res.incidents[0] || null,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load incidents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  const handleUpdateStatus = async (status: IncidentStatus) => {
    if (!selected) return;
    setSaving(true);
    setFeedback(null);
    try {
      const res = await api.updateIncident(selected.incident_id, { status });
      setIncidents((prev) => prev.map((i) => (i.incident_id === selected.incident_id ? res.incident : i)));
      setSelected(res.incident);
      setFeedback(`Incident ${selected.incident_id} transitioned to ${status}.`);
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Failed to update status.');
    } finally {
      setSaving(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected || !noteInput.trim()) return;
    setSaving(true);
    setFeedback(null);
    try {
      const res = await api.updateIncident(selected.incident_id, { note: noteInput.trim() });
      setIncidents((prev) => prev.map((i) => (i.incident_id === selected.incident_id ? res.incident : i)));
      setSelected(res.incident);
      setNoteInput('');
      setFeedback('Investigation note recorded.');
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Failed to add note.');
    } finally {
      setSaving(false);
    }
  };

  const filtered = incidents.filter((i) => statusFilter === 'ALL' || i.status === statusFilter);

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Incident Management & Investigation"
        description="Track security incidents generated from AI anomaly detections through Open, Investigating, and Resolved triage stages."
        actions={
          <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
            {(['ALL', 'Open', 'Investigating', 'Resolved'] as const).map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  statusFilter === st ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st === 'ALL' ? `All (${incidents.length})` : st}
              </button>
            ))}
          </div>
        }
      />

      {feedback && (
        <div className="px-4 py-2 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200">
          {feedback}
        </div>
      )}

      <DataStateWrapper
        loading={loading}
        error={error}
        isEmpty={filtered.length === 0}
        emptyTitle="No incidents in this status queue"
        onRetry={loadIncidents}
      >
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <div className="xl:col-span-2 space-y-3">
            {filtered.map((inc) => (
              <button
                key={inc.incident_id}
                type="button"
                onClick={() => setSelected(inc)}
                className={`w-full text-left bg-[#0F172A] border rounded-lg p-4 transition-colors ${
                  selected?.incident_id === inc.incident_id
                    ? 'border-indigo-500/70 bg-indigo-950/20'
                    : 'border-slate-800/90 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="text-sm font-semibold text-slate-100">{inc.title}</div>
                    <div className="text-xs text-slate-400 mt-1 flex flex-wrap items-center gap-2 font-mono">
                      <span>{inc.incident_id}</span>
                      <span aria-hidden="true">·</span>
                      <span>{inc.affected_user}</span>
                      <span aria-hidden="true">·</span>
                      <span>{inc.provider}</span>
                      <span aria-hidden="true">·</span>
                      <span>Risk {inc.risk_score}/100</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <SeverityText level={inc.severity} />
                    <StatusText status={inc.status} />
                  </div>
                </div>
                <p className="mt-2.5 text-xs text-slate-300 line-clamp-2">{inc.summary}</p>
              </button>
            ))}
          </div>

          {selected && (
            <SurfacePanel
              title={selected.incident_id}
              subtitle={`Assigned to: ${selected.assigned_to} · Created ${selected.created_at.replace('T', ' ').slice(0, 19)} UTC`}
            >
              <div className="space-y-4 text-xs">
                <div>
                  <div className="text-slate-400 mb-1.5">Triage Workflow Status</div>
                  <div className="grid grid-cols-3 gap-1.5">
                    {(['Open', 'Investigating', 'Resolved'] as IncidentStatus[]).map((st) => (
                      <button
                        key={st}
                        type="button"
                        disabled={saving || currentUser.role === 'Viewer'}
                        onClick={() => handleUpdateStatus(st)}
                        className={`py-1.5 px-2 rounded font-medium border transition-colors ${
                          selected.status === st
                            ? 'bg-indigo-600 border-indigo-500 text-white'
                            : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
                        } disabled:opacity-50`}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="text-slate-400 mb-1">Recommended Containment Actions</div>
                  <ul className="space-y-1.5 text-slate-200 list-disc list-inside">
                    {selected.recommended_actions.map((act, idx) => (
                      <li key={idx}>{act}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <div className="text-slate-400 mb-1.5">
                    Corroborating Event Evidence ({selected.evidence_events.length})
                  </div>
                  <div className="space-y-1.5 max-h-44 overflow-y-auto pr-1">
                    {selected.evidence_events.map((ev) => (
                      <div key={ev.event_id} className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-[11px]">
                        <div className="flex justify-between text-indigo-300">
                          <span>{ev.action}</span>
                          <span className="text-slate-500">{ev.event_id}</span>
                        </div>
                        <div className="text-slate-400 truncate">{ev.resource} · {ev.source_ip}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800">
                  <div className="text-slate-400 mb-2">Analyst Investigation Notes</div>
                  <form onSubmit={handleAddNote} className="space-y-2 mb-3">
                    <textarea
                      rows={2}
                      value={noteInput}
                      onChange={(e) => setNoteInput(e.target.value)}
                      disabled={currentUser.role === 'Viewer'}
                      placeholder={
                        currentUser.role === 'Viewer'
                          ? 'Viewer role cannot post investigation notes'
                          : 'Document triage findings, ticket references, or containment actions...'
                      }
                      className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                    />
                    <button
                      type="submit"
                      disabled={saving || !noteInput.trim() || currentUser.role === 'Viewer'}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 font-medium rounded"
                    >
                      Save Investigation Note
                    </button>
                  </form>

                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {selected.analyst_notes.length === 0 ? (
                      <p className="text-slate-500 italic">No analyst notes logged yet.</p>
                    ) : (
                      selected.analyst_notes.map((n) => (
                        <div key={n.note_id} className="p-2.5 bg-slate-900/70 border border-slate-800 rounded">
                          <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                            <span className="font-medium text-slate-200">{n.author}</span>
                            <span className="font-mono">{n.timestamp.replace('T', ' ').slice(0, 19)}</span>
                          </div>
                          <p className="text-slate-300">{n.content}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </SurfacePanel>
          )}
        </div>
      </DataStateWrapper>
    </div>
  );
}
