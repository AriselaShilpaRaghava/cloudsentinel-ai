import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { PolicyRecommendation } from '../types';
import {
  Scale,
  DollarSign,
  Shield,
  Activity,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Clock,
  Sparkles,
  Info
} from 'lucide-react';

export const PolicyOptimization: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyRecommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [decidingId, setDecidingId] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [notesModal, setNotesModal] = useState<{ id: number; action: 'Approved' | 'Rejected' } | null>(null);
  const [decisionNotes, setDecisionNotes] = useState('');

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const data = await api.getPolicies();
      setPolicies(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleExecuteDecision = async () => {
    if (!notesModal) return;
    try {
      setDecidingId(notesModal.id);
      await api.decidePolicy(notesModal.id, notesModal.action, decisionNotes);
      setNotesModal(null);
      setDecisionNotes('');
      await fetchPolicies();
    } catch (e) {
      console.error(e);
    } finally {
      setDecidingId(null);
    }
  };

  const filtered = policies.filter((p) => {
    if (statusFilter === 'all') return true;
    return p.status === statusFilter;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Optimization Architecture & Objective Function Banner */}
      <div className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
          <div className="flex items-center gap-2">
            <Scale className="w-4 h-4 text-[#22D3EE]" />
            <h3 className="text-xs font-semibold text-[#F8FAFC] tracking-tight">
              Cost-Aware Adaptive Security Policy Optimization Model
            </h3>
          </div>
          <span className="text-[11px] font-mono text-[#38BDF8]">
            Multi-Objective Utility Formulation
          </span>
        </div>

        <p className="text-xs text-[#94A3B8] leading-relaxed">
          Traditional security mechanisms blindly enforce heavy restrictions, causing high operational overhead and user friction.
          CloudSentinel AI balances <span className="text-[#22C55E] font-medium">Security Benefit</span> against{' '}
          <span className="text-[#F59E0B] font-medium">Estimated Operational Cost ($)</span> and{' '}
          <span className="text-[#22D3EE] font-medium">Performance Overhead (%)</span> using an objective utility function.
        </p>

        <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg font-mono text-xs text-[#22D3EE] overflow-x-auto">
          Utility(P) = (0.50 × SecurityBenefit) - (0.20 × CostUSD) - (0.15 × OverheadPct) - (0.15 × |RiskScore - PolicyCapability|)
        </div>

        <div className="flex items-center gap-2 text-[11px] text-[#94A3B8]">
          <Info className="w-3.5 h-3.5 text-[#38BDF8] shrink-0" />
          <span>Recommendations require authorized human confirmation before enforcement. Disabling accounts or deleting data is strictly prohibited without operator approval.</span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center justify-between p-4 bg-[#17243A] border border-[#1E2D4A] rounded-xl text-xs">
        <div className="flex items-center gap-1 p-1 bg-[#111C2E] rounded-lg border border-[#1E2D4A]">
          <button
            onClick={() => setStatusFilter('all')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              statusFilter === 'all' ? 'bg-[#2563EB] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            All Recommendations ({policies.length})
          </button>
          <button
            onClick={() => setStatusFilter('Pending')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              statusFilter === 'Pending' ? 'bg-[#F59E0B] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            Pending Review ({policies.filter((p) => p.status === 'Pending').length})
          </button>
          <button
            onClick={() => setStatusFilter('Approved')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              statusFilter === 'Approved' ? 'bg-[#22C55E] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            Enforced & Approved ({policies.filter((p) => p.status === 'Approved').length})
          </button>
          <button
            onClick={() => setStatusFilter('Rejected')}
            className={`px-3 py-1.5 rounded-md font-medium transition-colors ${
              statusFilter === 'Rejected' ? 'bg-[#EF4444] text-white' : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            Rejected ({policies.filter((p) => p.status === 'Rejected').length})
          </button>
        </div>

        <span className="text-[#94A3B8] font-mono">
          Showing {filtered.length} policies
        </span>
      </div>

      {/* Policy Recommendations List */}
      {loading ? (
        <div className="py-12 text-center text-xs text-[#94A3B8]">
          Evaluating optimal adaptive security policies...
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-12 text-center text-xs text-[#94A3B8] bg-[#17243A] rounded-xl border border-[#1E2D4A]">
          No policy recommendations matching current filter.
        </div>
      ) : (
        <div className="space-y-4">
          {filtered.map((policy) => {
            const isPending = policy.status === 'Pending';
            return (
              <div
                key={policy.id}
                className="p-5 bg-[#17243A] border border-[#1E2D4A] rounded-xl space-y-4 shadow-sm"
              >
                {/* Header Row */}
                <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#1E2D4A]">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-[#2563EB]/20 border border-[#2563EB]/30 flex items-center justify-center text-[#22D3EE]">
                      <Scale className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold text-[#F8FAFC]">
                        {policy.recommended_policy}
                      </h4>
                      <p className="text-xs text-[#94A3B8] mt-0.5">
                        Target User Identity: <span className="font-mono text-[#22D3EE]">{policy.user_id}</span> · Assessed Risk:{' '}
                        <span className="font-mono text-[#EF4444] font-semibold">{policy.current_risk_score.toFixed(2)}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`text-xs font-semibold px-2.5 py-1 rounded-md border ${
                        policy.status === 'Approved'
                          ? 'bg-[#22C55E]/15 border-[#22C55E]/30 text-[#22C55E]'
                          : policy.status === 'Rejected'
                          ? 'bg-[#EF4444]/15 border-[#EF4444]/30 text-[#EF4444]'
                          : 'bg-[#F59E0B]/15 border-[#F59E0B]/30 text-[#F59E0B]'
                      }`}
                    >
                      {policy.status === 'Approved' ? 'Enforced in Policy Store' : policy.status}
                    </span>
                  </div>
                </div>

                {/* Metrics Comparison Row */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                    <span className="text-[11px] text-[#94A3B8] block mb-1">Expected Security Benefit</span>
                    <p className="font-semibold text-[#22C55E]">
                      {policy.security_benefit}
                    </p>
                  </div>

                  <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                    <span className="text-[11px] text-[#94A3B8] block mb-1">Estimated Operational Cost</span>
                    <p className="font-semibold text-[#FBBF24] font-mono text-base">
                      ${policy.estimated_cost_usd.toFixed(2)} <span className="text-xs text-[#94A3B8] font-normal">USD / trigger</span>
                    </p>
                  </div>

                  <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg">
                    <span className="text-[11px] text-[#94A3B8] block mb-1">Estimated Performance Overhead</span>
                    <p className="font-semibold text-[#38BDF8] font-mono text-base">
                      {policy.performance_overhead_pct.toFixed(1)}% <span className="text-xs text-[#94A3B8] font-normal">latency delta</span>
                    </p>
                  </div>
                </div>

                {/* Optimization Reasoning Box */}
                <div className="p-3 bg-[#111C2E] border border-[#1E2D4A] rounded-lg text-xs space-y-1">
                  <span className="text-[11px] font-medium text-[#22D3EE]">Mathematical Optimization Rationale:</span>
                  <p className="text-[#F8FAFC] leading-relaxed">
                    {policy.reason}
                  </p>
                  {policy.decided_at && (
                    <div className="text-[11px] text-[#94A3B8] pt-1 border-t border-[#1E2D4A] font-mono">
                      Decision recorded at {policy.decided_at} {policy.decision_notes ? `· Note: ${policy.decision_notes}` : ''}
                    </div>
                  )}
                </div>

                {/* Operator Decision Actions */}
                {isPending && (
                  <div className="pt-2 flex items-center justify-end gap-3">
                    <button
                      onClick={() => setNotesModal({ id: policy.id, action: 'Rejected' })}
                      className="px-3.5 py-1.5 text-xs font-medium text-[#EF4444] bg-[#EF4444]/10 hover:bg-[#EF4444]/20 border border-[#EF4444]/30 rounded-lg transition-colors flex items-center gap-1.5"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Reject Policy</span>
                    </button>

                    <button
                      onClick={() => setNotesModal({ id: policy.id, action: 'Approved' })}
                      className="px-4 py-1.5 text-xs font-medium text-white bg-[#22C55E] hover:bg-[#16A34A] rounded-lg transition-colors flex items-center gap-1.5 shadow-sm shadow-[#22C55E]/30"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Authorize & Enforce</span>
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Decision Confirmation Modal */}
      {notesModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-[#17243A] border border-[#1E2D4A] rounded-xl max-w-md w-full p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-2 border-b border-[#1E2D4A]">
              <h3 className="text-sm font-semibold text-[#F8FAFC]">
                {notesModal.action === 'Approved' ? 'Authorize Policy Enforcement' : 'Reject Policy Recommendation'}
              </h3>
              <button
                onClick={() => setNotesModal(null)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-[#94A3B8]">
              {notesModal.action === 'Approved'
                ? 'Confirming will enforce this adaptive policy in the policy repository. User workflows will adapt with measured friction.'
                : 'Confirming will decline the automated recommendation. No policy changes will be enacted.'}
            </p>

            <div>
              <label className="text-xs text-[#94A3B8] font-medium block mb-1">
                Security Officer Notes (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="E.g. Approved during off-hours maintenance window triage..."
                value={decisionNotes}
                onChange={(e) => setDecisionNotes(e.target.value)}
                className="w-full bg-[#111C2E] border border-[#1E2D4A] rounded-lg px-3 py-2 text-[#F8FAFC] text-xs focus:outline-none focus:border-[#2563EB]"
              />
            </div>

            <div className="pt-2 flex justify-end gap-2 text-xs">
              <button
                onClick={() => setNotesModal(null)}
                className="px-3 py-1.5 bg-[#111C2E] hover:bg-[#1E2F4C] text-[#F8FAFC] rounded-lg border border-[#1E2D4A]"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteDecision}
                disabled={decidingId !== null}
                className={`px-4 py-1.5 font-medium text-white rounded-lg transition-colors ${
                  notesModal.action === 'Approved'
                    ? 'bg-[#22C55E] hover:bg-[#16A34A]'
                    : 'bg-[#EF4444] hover:bg-[#DC2626]'
                }`}
              >
                {decidingId !== null ? 'Saving...' : `Confirm ${notesModal.action}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
