import React, { useState, useEffect } from 'react';
import { DetectionResult } from '../types';
import { api } from '../services/api';
import { PageId } from '../components/Navigation';
import {
  AlertTriangle,
  Clock,
  Database,
  ShieldAlert,
  Flame,
  PlusCircle,
  Scale,
  Search,
  Filter,
  Info,
  CheckCircle2
} from 'lucide-react';

interface InsiderThreatsProps {
  selectedEvent: DetectionResult | null;
  onNavigate: (page: PageId) => void;
  onIncidentCreated: () => void;
}

export const InsiderThreats: React.FC<InsiderThreatsProps> = ({
  selectedEvent,
  onNavigate,
  onIncidentCreated,
}) => {
  const [threats, setThreats] = useState<DetectionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchUser, setSearchUser] = useState('');
  const [activeTab, setActiveTab] = useState<'all' | 'high' | 'medium'>('all');

  // Incident Creation Modal
  const [incidentModalOpen, setIncidentModalOpen] = useState(false);
  const [targetEvent, setTargetEvent] = useState<DetectionResult | null>(null);
  const [incidentTitle, setIncidentTitle] = useState('');
  const [incidentDesc, setIncidentDesc] = useState('');
  const [incidentSeverity, setIncidentSeverity] = useState('High');
  const [creatingIncident, setCreatingIncident] = useState(false);
  const [createdSuccess, setCreatedSuccess] = useState<string | null>(null);

  const fetchThreats = async () => {
    try {
      setLoading(true);
      const data = await api.getDetectionResults({ limit: 100 });
      // Filter only Medium and High risk events
      const filtered = data.filter((d) => d.risk_level !== 'Normal');
      setThreats(filtered);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, []);

  useEffect(() => {
    if (selectedEvent) {
      setTargetEvent(selectedEvent);
      setIncidentTitle(`Investigate suspicious ${selectedEvent.action} on ${selectedEvent.resource} (${selectedEvent.user_id})`);
      setIncidentDesc(selectedEvent.flag_reason);
      setIncidentSeverity(selectedEvent.risk_level === 'High Risk' ? 'Critical' : 'Medium');
    }
  }, [selectedEvent]);

  const handleOpenIncidentModal = (event: DetectionResult) => {
    setTargetEvent(event);
    setIncidentTitle(`Suspicious ${event.action} by ${event.user_id} on ${event.resource}`);
    setIncidentDesc(`Detected by ${event.model_used} with score ${event.anomaly_score.toFixed(2)}.\nReason: ${event.flag_reason}\nRecommendation: ${event.recommended_action}`);
    setIncidentSeverity(event.risk_level === 'High Risk' ? 'Critical' : 'Medium');
    setIncidentModalOpen(true);
  };

  const handleCreateIncident = async () => {
    if (!targetEvent || !incidentTitle) return;
    try {
      setCreatingIncident(true);
      await api.createIncident({
        title: incidentTitle,
        description: incidentDesc,
        severity: incidentSeverity,
        related_user_id: targetEvent.user_id,
        related_event_ids: String(targetEvent.id),
      });
      setCreatedSuccess('Incident created successfully in SQLite store.');
      setTimeout(() => {
        setIncidentModalOpen(false);
        setCreatedSuccess(null);
        onIncidentCreated();
        onNavigate('incidents');
      }, 1000);
    } catch (e) {
      console.error(e);
    } finally {
      setCreatingIncident(false);
    }
  };

  const displayedThreats = threats.filter((t) => {
    const matchesUser = searchUser === '' || t.user_id.toLowerCase().includes(searchUser.toLowerCase()) || t.resource.toLowerCase().includes(searchUser.toLowerCase());
    if (activeTab === 'high') return matchesUser && t.risk_level === 'High Risk';
    if (activeTab === 'medium') return matchesUser && t.risk_level === 'Medium Risk';
    return matchesUser;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Notice Banner */}
      <div className="p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl flex items-start gap-3">
        <Info className="w-4 h-4 text-[#22D3EE] shrink-0 mt-0.5" />
        <div className="text-xs">
          <span className="font-semibold text-[#F8FAFC]">SOC Investigation Principle:</span>
          <span className="text-[#94A3B8] ml-1">
            An anomaly is a mathematical deviation from learned baselines, not definitive proof of malicious intent.
            All flagged activities represent potential insider risks requiring context verification and human security triage.
          </span>
        </div>
      </div>

      {/* Tabs & Search Filter */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl text-xs">
        {/* Segmented Filter Buttons */}
        <div className="flex items-center gap-1 p-1 bg-[#111C2E] rounded-lg border border-[#1E2D4A]">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'all'
                ? 'bg-[#2563EB] text-white'
                : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            All Flagged ({threats.length})
          </button>
          <button
            onClick={() => setActiveTab('high')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'high'
                ? 'bg-[#EF4444] text-white'
                : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            High Risk ({threats.filter((t) => t.risk_level === 'High Risk').length})
          </button>
          <button
            onClick={() => setActiveTab('medium')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              activeTab === 'medium'
                ? 'bg-[#F59E0B] text-white'
                : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            Medium Risk ({threats.filter((t) => t.risk_level === 'Medium Risk').length})
          </button>
        </div>

        {/* Search Input */}
        <div className="flex items-center gap-2 bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-1.5 min-w-[220px]">
          <Search className="w-3.5 h-3.5 text-[#94A3B8]" />
          <input
            type="text"
            placeholder="Filter by user or resource..."
            value={searchUser}
            onChange={(e) => setSearchUser(e.target.value)}
            className="bg-transparent text-[#F8FAFC] placeholder-[#64748B] focus:outline-none w-full text-xs"
          />
        </div>
      </div>

      {/* Threats Detailed Cards Grid */}
      {loading ? (
        <div className="py-12 text-center text-xs text-[#94A3B8]">
          Scanning insider threat vectors...
        </div>
      ) : displayedThreats.length === 0 ? (
        <div className="py-12 text-center text-xs text-[#94A3B8] bg-[#17243A] rounded-xl border border-[#1E2D4A]">
          No flagged insider threat events matching criteria.
        </div>
      ) : (
        <div className="space-y-4">
          {displayedThreats.map((threat) => (
            <div
              key={threat.id}
              className={`p-5 bg-[#17243A] border rounded-xl space-y-3 transition-colors ${
                threat.risk_level === 'High Risk'
                  ? 'border-[#EF4444]/40 hover:border-[#EF4444]'
                  : 'border-[#F59E0B]/40 hover:border-[#F59E0B]'
              }`}
            >
              {/* Card Header */}
              <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-[#1E2D4A]">
                <div className="flex items-center gap-2.5">
                  {threat.risk_level === 'High Risk' ? (
                    <Flame className="w-4 h-4 text-[#EF4444]" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-[#F59E0B]" />
                  )}
                  <span className="font-semibold text-sm text-[#F8FAFC]">
                    {threat.user_id}
                  </span>
                  <span className="text-[#64748B]">·</span>
                  <span className="font-mono text-xs text-[#22D3EE]">
                    {threat.action}
                  </span>
                  <span className="text-[#64748B]">·</span>
                  <span className="text-xs text-[#94A3B8]">
                    Target: <strong className="text-[#F8FAFC]">{threat.resource}</strong>
                  </span>
                </div>

                <div className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-[#94A3B8]">{threat.timestamp}</span>
                  <span
                    className={`font-semibold ${
                      threat.risk_level === 'High Risk' ? 'text-[#EF4444]' : 'text-[#F59E0B]'
                    }`}
                  >
                    {threat.risk_level}
                  </span>
                  <span className="font-mono tabular-nums px-2 py-0.5 bg-[#111C2E] border border-[#1E2D4A] rounded text-[#F8FAFC]">
                    Score: {threat.anomaly_score.toFixed(2)}
                  </span>
                </div>
              </div>

              {/* Diagnostic Reasons & Context */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="md:col-span-2 space-y-2">
                  <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                    <span className="text-[11px] font-medium text-[#94A3B8] block mb-1">
                      Flag Reason & Behavioral Diagnosis:
                    </span>
                    <p className="text-[#F8FAFC] leading-relaxed">
                      {threat.flag_reason}
                    </p>
                  </div>

                  <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                    <span className="text-[11px] font-medium text-[#38BDF8] block mb-1">
                      Recommended Next Action:
                    </span>
                    <p className="text-[#94A3B8] leading-relaxed">
                      {threat.recommended_action}
                    </p>
                  </div>
                </div>

                {/* Metadata & Quick Escalation Box */}
                <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg flex flex-col justify-between space-y-3">
                  <div className="space-y-1.5 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-[#94A3B8]">Source IP:</span>
                      <span className="font-mono text-[#F8FAFC]">{threat.source_ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#94A3B8]">Status:</span>
                      <span className="font-semibold text-[#22C55E]">{threat.status}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#94A3B8]">Engine:</span>
                      <span className="font-mono text-[#38BDF8]">{threat.model_used}</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-[#1E2D4A] flex items-center gap-2">
                    <button
                      onClick={() => handleOpenIncidentModal(threat)}
                      className="flex-1 py-1.5 px-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-xs font-medium rounded transition-colors flex items-center justify-center gap-1.5"
                    >
                      <PlusCircle className="w-3.5 h-3.5" />
                      <span>Create Incident</span>
                    </button>

                    <button
                      onClick={() => onNavigate('policies')}
                      title="View Policy Recommendation"
                      className="p-1.5 bg-[#17243A] hover:bg-[#1E2F4C] border border-[#1E2D4A] rounded text-[#22D3EE] transition-colors"
                    >
                      <Scale className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Incident Creation Modal */}
      {incidentModalOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-lg w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#1E2D4A]">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#EF4444]" />
                <h3 className="text-sm font-semibold text-[#F8FAFC]">
                  Create SOC Incident Ticket
                </h3>
              </div>
              <button
                onClick={() => setIncidentModalOpen(false)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                ✕
              </button>
            </div>

            {createdSuccess ? (
              <div className="p-4 text-center text-xs text-[#22C55E] flex items-center justify-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>{createdSuccess}</span>
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Incident Title
                  </label>
                  <input
                    type="text"
                    value={incidentTitle}
                    onChange={(e) => setIncidentTitle(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none focus:border-[#2563EB]"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[#94A3B8] font-medium block mb-1">
                      Severity Level
                    </label>
                    <select
                      value={incidentSeverity}
                      onChange={(e) => setIncidentSeverity(e.target.value)}
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
                      Related User Identity
                    </label>
                    <input
                      type="text"
                      disabled
                      value={targetEvent?.user_id || ''}
                      className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#94A3B8] text-xs opacity-75"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[#94A3B8] font-medium block mb-1">
                    Investigation Description & Evidence
                  </label>
                  <textarea
                    rows={4}
                    value={incidentDesc}
                    onChange={(e) => setIncidentDesc(e.target.value)}
                    className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none focus:border-[#2563EB]"
                  />
                </div>

                <div className="pt-2 flex justify-end gap-2">
                  <button
                    onClick={() => setIncidentModalOpen(false)}
                    className="px-3 py-1.5 bg-[#111C2E] hover:bg-[#1E2F4C] text-xs font-medium text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreateIncident}
                    disabled={creatingIncident}
                    className="px-4 py-1.5 bg-[#2563EB] hover:bg-[#1D4ED8] text-xs font-medium text-white rounded-lg transition-colors disabled:opacity-50"
                  >
                    {creatingIncident ? 'Saving Incident...' : 'Commit Incident Ticket'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
