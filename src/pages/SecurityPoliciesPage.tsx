import React, { useEffect, useState } from 'react';
import { Check, ShieldCheck, X } from 'lucide-react';
import { api } from '../services/api';
import type { AuthUser, PolicyRecommendation, RiskEngineWeights } from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';

export function SecurityPoliciesPage({ currentUser }: { currentUser: AuthUser }) {
  const [policies, setPolicies] = useState<PolicyRecommendation[]>([]);
  const [riskWeights, setRiskWeights] = useState<RiskEngineWeights | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [savingWeights, setSavingWeights] = useState(false);

  const loadPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getPolicies();
      setPolicies(res.policies);
      setRiskWeights(res.riskWeights);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security policy recommendations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPolicies();
  }, []);

  const handleDecision = async (id: string, approve: boolean) => {
    setFeedback(null);
    try {
      const res = approve ? await api.approvePolicy(id) : await api.rejectPolicy(id);
      setPolicies((prev) => prev.map((p) => (p.policy_id === id ? res.policy : p)));
      setFeedback(
        `Policy ${id} ${approve ? 'approved' : 'rejected'} by ${currentUser.full_name} and recorded in administrative audit trail.`,
      );
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Policy decision failed.');
    }
  };

  const handleSaveRiskWeights = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!riskWeights) return;
    setSavingWeights(true);
    setFeedback(null);
    try {
      const res = await api.updateWeights({ riskWeights });
      setRiskWeights(res.riskWeights);
      setFeedback('Risk Assessment Engine weights updated and logged.');
    } catch (err) {
      setFeedback(err instanceof Error ? err.message : 'Failed to update weights.');
    } finally {
      setSavingWeights(false);
    }
  };

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Adaptive Security Policy Recommendations"
        description="Evidence-backed least-privilege, MFA, FaaS rate-limit, and quarantine recommendations. Production policies are never changed automatically and require explicit Admin approval."
      />

      {feedback && (
        <div className="px-4 py-2.5 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200">
          {feedback}
        </div>
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadPolicies}>
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <div className="xl:col-span-2 space-y-4">
            {policies.map((pol) => (
              <SurfacePanel key={pol.policy_id}>
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span className="font-mono text-indigo-300">{pol.policy_id}</span>
                      <span aria-hidden="true">·</span>
                      <span>{pol.category}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono text-slate-300">{pol.target_user_id}</span>
                    </div>
                    <h3 className="text-sm font-semibold text-slate-100">{pol.title}</h3>
                    <p className="text-xs text-slate-300 leading-relaxed">{pol.description}</p>
                    <div className="text-[11px] font-mono text-slate-400">
                      Target: {pol.target_resource} · Evidence: {pol.supporting_evidence.join(', ')}
                    </div>
                  </div>
                  <div className="shrink-0 flex flex-col items-end gap-2">
                    <StatusText status={pol.approval_status} />
                    {pol.approved_by && (
                      <span className="text-[11px] text-slate-500">By {pol.approved_by}</span>
                    )}
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4 text-xs">
                  <div className="flex flex-wrap items-center gap-5 font-mono tabular-nums">
                    <div>
                      <span className="text-slate-500 block font-sans">Risk Reduction</span>
                      <span className="text-emerald-400 font-medium">
                        {pol.residual_risk_before} → {pol.residual_risk_after} (+{pol.security_improvement_pct}%)
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block font-sans">Monthly Cost</span>
                      <span className="text-slate-200">
                        ${pol.operational_cost_before_usd} → ${pol.operational_cost_after_usd}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block font-sans">Perf Overhead</span>
                      <span className="text-slate-300">+{pol.performance_overhead_pct}%</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block font-sans">Optimizer Score</span>
                      <span className="text-indigo-300 font-semibold">{pol.optimizer_score.toFixed(2)}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={currentUser.role !== 'Admin' || pol.approval_status === 'Approved'}
                      onClick={() => handleDecision(pol.policy_id, true)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-white font-medium rounded transition-colors"
                    >
                      <Check className="w-3.5 h-3.5" />
                      Approve Policy
                    </button>
                    <button
                      type="button"
                      disabled={currentUser.role !== 'Admin' || pol.approval_status === 'Rejected'}
                      onClick={() => handleDecision(pol.policy_id, false)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 font-medium rounded border border-slate-700 transition-colors"
                    >
                      <X className="w-3.5 h-3.5" />
                      Reject
                    </button>
                  </div>
                </div>
              </SurfacePanel>
            ))}
          </div>

          {riskWeights && (
            <SurfacePanel
              title="Risk Assessment Engine Weights"
              subtitle="Configurable scoring factor weights (Admin RBAC enforced)"
            >
              <form onSubmit={handleSaveRiskWeights} className="space-y-3 text-xs">
                {[
                  { key: 'w_anomaly', label: 'Anomaly Score Weight' },
                  { key: 'w_privilege', label: 'User Privilege Weight' },
                  { key: 'w_resource', label: 'Resource Sensitivity Weight' },
                  { key: 'w_action', label: 'Action Criticality Weight' },
                  { key: 'w_frequency', label: 'Event Frequency Weight' },
                  { key: 'w_evidence', label: 'Evidence Strength Weight' },
                  { key: 'confidence_threshold', label: 'Confidence Alert Gate (0.30-0.95)' },
                ].map((field) => (
                  <div key={field.key}>
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span>{field.label}</span>
                      <span className="font-mono tabular-nums text-indigo-300">
                        {riskWeights[field.key as keyof RiskEngineWeights].toFixed(2)}
                      </span>
                    </div>
                    <input
                      type="range"
                      min={field.key === 'confidence_threshold' ? 0.3 : 0.02}
                      max={field.key === 'confidence_threshold' ? 0.95 : 0.6}
                      step={0.02}
                      disabled={currentUser.role !== 'Admin'}
                      value={riskWeights[field.key as keyof RiskEngineWeights]}
                      onChange={(e) =>
                        setRiskWeights({ ...riskWeights, [field.key]: Number(e.target.value) })
                      }
                      className="w-full accent-indigo-500"
                    />
                  </div>
                ))}

                <div className="pt-2 flex items-center gap-2 text-[11px] text-slate-400">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>Current Role: {currentUser.role}. Only Admin can approve policies or adjust weights.</span>
                </div>

                <button
                  type="submit"
                  disabled={savingWeights || currentUser.role !== 'Admin'}
                  className="w-full py-2 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
                >
                  {savingWeights ? 'Saving Weights...' : 'Save Risk Engine Weights'}
                </button>
              </form>
            </SurfacePanel>
          )}
        </div>
      </DataStateWrapper>
    </div>
  );
}
