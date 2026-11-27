import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Incident } from '../types';
import {
  Activity,
  PlusCircle,
  AlertTriangle,
  Clock,
  User,
  CheckCircle2,
  MessageSquare,
  Filter,
  Send,
  X
} from 'lucide-react';

export const IncidentManagement: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [statusFilter, setStatusFilter] = useState('all');

  // New incident modal
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState('High');
  const [userId, setUserId] = useState('');

  // Add note state
  const [newNote, setNewNote] = useState('');
  const [authorName, setAuthorName] = useState('Tier-1 SOC Analyst');
  const [addingNote, setAddingNote] = useState(false);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const data = await api.getIncidents();
      setIncidents(data);
      if (data.length > 0 && !selectedIncident) {
        setSelectedIncident(data[0]);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await api.createIncident({
        title,
        description,
        severity,
        related_user_id: userId || 'usr_unknown',
      });
      setCreateModalOpen(false);
      setTitle('');
      setDescription('');
      await fetchIncidents();
      setSelectedIncident(created);
    } catch (e) {
      console.error(e);
    }
  };

  const handleUpdateStatus = async (status: string) => {
    if (!selectedIncident) return;
    try {
      const updated = await api.updateIncident(selectedIncident.id, { status });
      setSelectedIncident(updated);
      await fetchIncidents();
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident || !newNote.trim()) return;
    try {
      setAddingNote(true);
      await api.addIncidentNote(selectedIncident.id, newNote, authorName);
      setNewNote('');
      const updatedIncidents = await api.getIncidents();
      setIncidents(updatedIncidents);
      const refreshed = updatedIncidents.find((i) => i.id === selectedIncident.id);
      if (refreshed) setSelectedIncident(refreshed);
    } catch (e) {
      console.error(e);
    } finally {
      setAddingNote(false);
    }
  };

  const filteredIncidents = incidents.filter((i) => {
    if (statusFilter === 'all') return true;
    return i.status === statusFilter;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Incident Header */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#A855F7]" />
            <h3 className="text-sm font-semibold text-[#F8FAFC]">
              SOC Incident Case Management & Triage
            </h3>
          </div>
          <p className="text-xs text-[#94A3B8] mt-1">
            Persisted SQLite incident registry. Track forensic investigation notes, severity tiers, and remediation workflows.
          </p>
        </div>

        <button
          onClick={() => setCreateModalOpen(true)}
          className="px-4 py-2 text-xs font-medium text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>New Incident Ticket</span>
        </button>
      </div>

      {/* Two Column Layout: List on Left, Inspector on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Incidents List */}
        <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
            <h4 className="text-xs font-semibold text-[#F8FAFC]">
              Incident Queue ({filteredIncidents.length})
            </h4>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#111C2E] text-[#F8FAFC] border border-[#1E2D4A] rounded-lg px-2 py-1 text-xs focus:outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
              <option value="Closed">Closed</option>
            </select>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {loading ? (
              <div className="py-8 text-center text-xs text-[#94A3B8]">
                Loading incidents...
              </div>
            ) : filteredIncidents.length === 0 ? (
              <div className="py-8 text-center text-xs text-[#94A3B8]">
                No incidents in this status queue.
              </div>
            ) : (
              filteredIncidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id;
                return (
                  <div
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`p-3 rounded-lg border text-xs cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-[#1E2F4C] border-[#2563EB]'
                        : 'bg-[#111C2E] border-[#1E2D4A] hover:bg-[#1E2F4C]/50'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[#64748B]">#{inc.id}</span>
                      <span
                        className={`font-semibold ${
                          inc.severity === 'Critical'
                            ? 'text-[#EF4444]'
                            : inc.severity === 'High'
                            ? 'text-[#F59E0B]'
                            : 'text-[#38BDF8]'
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </div>

                    <h5 className="font-medium text-[#F8FAFC] mt-1 line-clamp-2">
                      {inc.title}
                    </h5>

                    <div className="flex items-center justify-between mt-2 pt-2 border-t border-[#1E2D4A] text-[11px] text-[#94A3B8]">
                      <span>{inc.status}</span>
                      <span className="font-mono">{inc.notes?.length || 0} notes</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Active Incident Details & Notes */}
        <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl lg:col-span-2 space-y-4 flex flex-col justify-between">
          {selectedIncident ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="flex flex-wrap items-start justify-between gap-3 pb-3 border-b border-[#1E2D4A]">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-[#64748B]">Case #{selectedIncident.id}</span>
                    <span
                      className={`text-xs font-semibold px-2 py-0.5 rounded border ${
                        selectedIncident.severity === 'Critical'
                          ? 'bg-[#EF4444]/15 border-[#EF4444]/30 text-[#EF4444]'
                          : selectedIncident.severity === 'High'
                          ? 'bg-[#F59E0B]/15 border-[#F59E0B]/30 text-[#F59E0B]'
                          : 'bg-[#38BDF8]/15 border-[#38BDF8]/30 text-[#38BDF8]'
                      }`}
                    >
                      {selectedIncident.severity} Severity
                    </span>
                  </div>
                  <h4 className="text-base font-bold text-[#F8FAFC] mt-1">
                    {selectedIncident.title}
                  </h4>
                </div>

                {/* Status Switcher */}
                <div className="flex items-center gap-1.5 text-xs">
                  <span className="text-[#94A3B8]">Status:</span>
                  <select
                    value={selectedIncident.status}
                    onChange={(e) => handleUpdateStatus(e.target.value)}
                    className="bg-[#111C2E] text-[#F8FAFC] border border-[#1E2D4A] rounded-lg px-2.5 py-1 text-xs focus:outline-none font-medium"
                  >
                    <option value="Open">Open</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Resolved">Resolved</option>
                    <option value="Closed">Closed</option>
                  </select>
                </div>
              </div>

              {/* Case Metadata Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                <div className="p-2.5 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                  <span className="text-[11px] text-[#94A3B8]">Target User</span>
                  <div className="font-semibold text-[#22D3EE] font-mono mt-0.5">
                    {selectedIncident.related_user_id}
                  </div>
                </div>
                <div className="p-2.5 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                  <span className="text-[11px] text-[#94A3B8]">Assigned Analyst</span>
                  <div className="font-semibold text-[#F8FAFC] mt-0.5">
                    {selectedIncident.assigned_to}
                  </div>
                </div>
                <div className="p-2.5 bg-[#111C2E] border border-[#1E2D4A] rounded-lg col-span-2 sm:col-span-1">
                  <span className="text-[11px] text-[#94A3B8]">Opened At</span>
                  <div className="font-mono text-[#94A3B8] text-[11px] mt-0.5 truncate">
                    {selectedIncident.created_at}
                  </div>
                </div>
              </div>

              {/* Case Description */}
              <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg text-xs space-y-1">
                <span className="text-[11px] text-[#94A3B8] font-medium">Incident Summary & Evidence</span>
                <p className="text-[#F8FAFC] leading-relaxed whitespace-pre-line">
                  {selectedIncident.description}
                </p>
              </div>

              {/* Investigation Notes Timeline */}
              <div className="space-y-3 pt-2">
                <div className="flex items-center gap-2">
                  <MessageSquare className="w-4 h-4 text-[#38BDF8]" />
                  <h5 className="text-xs font-semibold text-[#F8FAFC]">
                    Forensic Investigation Timeline ({selectedIncident.notes?.length || 0})
                  </h5>
                </div>

                <div className="space-y-2 max-h-[220px] overflow-y-auto pr-1">
                  {!selectedIncident.notes || selectedIncident.notes.length === 0 ? (
                    <div className="p-3 text-center text-xs text-[#94A3B8] bg-[#111C2E] rounded-lg border border-[#1E2D4A]">
                      No notes recorded yet. Add an analyst observation below.
                    </div>
                  ) : (
                    selectedIncident.notes.map((note) => (
                      <div
                        key={note.id}
                        className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg space-y-1 text-xs"
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-semibold text-[#22D3EE]">{note.author}</span>
                          <span className="font-mono text-[#64748B]">{note.created_at}</span>
                        </div>
                        <p className="text-[#F8FAFC]">{note.note}</p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleAddNote} className="space-y-2 pt-1">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Add investigation observation or IOC notes..."
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      className="flex-1 bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none focus:border-[#2563EB]"
                    />
                    <button
                      type="submit"
                      disabled={addingNote || !newNote.trim()}
                      className="px-3.5 py-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-medium rounded-lg transition-colors flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Log Note</span>
                    </button>
                  </div>
                </form>
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-xs text-[#94A3B8]">
              Select an incident from the queue to view forensic details and notes.
            </div>
          )}
        </div>
      </div>

      {/* Create Incident Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <form
            onSubmit={handleCreateIncident}
            className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-lg w-full p-5 space-y-4 shadow-xl"
          >
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#A855F7]" />
                <h3 className="text-sm font-semibold text-[#F8FAFC]">
                  Create Manual Incident Ticket
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-[#94A3B8] font-medium block mb-1">
                  Incident Title
                </label>
                <input
                  type="text"
                  placeholder="E.g. Off-hours bulk data download on customer PII"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Severity
                  </label>
                  <select
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Target User ID
                  </label>
                  <input
                    type="text"
                    placeholder="E.g. usr_dev_dave"
                    value={userId}
                    onChange={(e) => setUserId(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none font-mono"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-[#94A3B8] font-medium block mb-1">
                  Incident Description & Hypothesis
                </label>
                <textarea
                  rows={4}
                  placeholder="Detail observed malicious or anomalous activities..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none"
                  required
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setCreateModalOpen(false)}
                  className="px-3 py-1.5 bg-[#111C2E] hover:bg-[#1E2F4C] text-xs font-medium text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-xs font-medium text-white rounded-lg transition-colors"
                >
                  Save Incident
                </button>
              </div>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
