import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import type { AuthUser, CostOptimizerWeights, PolicyRecommendation } from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';
import { BeforeAfterComparisonChart } from '../components/charts/SocCharts';

export function CostOptimizationPage({ currentUser }: { currentUser: AuthUser }) {
  const [policies, setPolicies] = useState<PolicyRecommendation[]>([]);
  const [weights, setWeights] = useState<CostOptimizerWeights | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getPolicies();
      setPolicies(res.policies);
      setWeights(res.costWeights);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cost optimization analysis.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRecalculate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!weights) return;
    setSaving(true);
    setMsg(null);
    try {
      const res = await api.updateWeights({ costWeights: weights });
      setPolicies(res.policies);
      setWeights(res.costWeights);
      setMsg('Recalculated rule-based weighted policy optimization scores under updated constraints.');
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to update optimizer weights.');
    } finally {
      setSaving(false);
    }
  };

  const totalBeforeCost = policies.reduce((s, p) => s + p.operational_cost_before_usd, 0);
  const totalAfterCost = policies.reduce((s, p) => s + p.operational_cost_after_usd, 0);
  const avgRiskBefore = Math.round(policies.reduce((s, p) => s + p.residual_risk_before, 0) / Math.max(1, policies.length));
  const avgRiskAfter = Math.round(policies.reduce((s, p) => s + p.residual_risk_after, 0) / Math.max(1, policies.length));
  const avgPerf = (policies.reduce((s, p) => s + p.performance_overhead_pct, 0) / Math.max(1, policies.length)).toFixed(1);

  return (
    <div className="space-y-6">
      <SectionHeader
        title="Cost-Aware Adaptive Security Policy Optimizer"
        description="Transparent rule-based weighted multi-objective evaluation balancing residual security risk, monthly operational cost, performance latency, and monitoring overhead (Reinforcement Learning documented as future extension)."
      />

      {msg && (
        <div className="px-4 py-2 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200">{msg}</div>
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadData}>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <SurfacePanel>
            <div className="text-xs text-slate-400">Residual Security Risk</div>
            <div className="mt-1 text-xl font-mono tabular-nums font-semibold text-emerald-400">
              {avgRiskBefore}% → {avgRiskAfter}%
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Net risk reduction: -{avgRiskBefore - avgRiskAfter} pts</div>
          </SurfacePanel>
          <SurfacePanel>
            <div className="text-xs text-slate-400">Monthly Operational Cost</div>
            <div className="mt-1 text-xl font-mono tabular-nums font-semibold text-slate-100">
              ${totalBeforeCost} → ${totalAfterCost}
            </div>
            <div className="text-[11px] text-emerald-400 mt-1">
              Net delta: {totalAfterCost - totalBeforeCost <= 0 ? `-$${totalBeforeCost - totalAfterCost}/mo saved` : `+$${totalAfterCost - totalBeforeCost}/mo`}
            </div>
          </SurfacePanel>
          <SurfacePanel>
            <div className="text-xs text-slate-400">Avg Performance Impact</div>
            <div className="mt-1 text-xl font-mono tabular-nums font-semibold text-sky-300">+{avgPerf}%</div>
            <div className="text-[11px] text-slate-500 mt-1">Latency / Auth evaluation overhead</div>
          </SurfacePanel>
          <SurfacePanel>
            <div className="text-xs text-slate-400">Optimization Method</div>
            <div className="mt-1 text-sm font-semibold text-indigo-300">Weighted Rule Engine</div>
            <div className="text-[11px] text-slate-500 mt-1">RL policy agent reserved for future work</div>
          </SurfacePanel>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <SurfacePanel
            title="Before vs After Security & Cost Comparison"
            subtitle="Comparing baseline posture against recommended adaptive policies"
            className="xl:col-span-2"
          >
            <BeforeAfterComparisonChart
              items={policies.map((p) => ({
                label: `${p.policy_id}: ${p.title}`,
                beforeRisk: p.residual_risk_before,
                afterRisk: p.residual_risk_after,
                beforeCost: p.operational_cost_before_usd,
                afterCost: p.operational_cost_after_usd,
              }))}
            />
          </SurfacePanel>

          {weights && (
            <SurfacePanel
              title="Optimizer Weights & Constraints"
              subtitle="Adjust objective weights to re-rank policy recommendations"
            >
              <form onSubmit={handleRecalculate} className="space-y-3 text-xs">
                {[
                  { key: 'w_security_gain', label: 'Security Risk Reduction Weight' },
                  { key: 'w_operational_cost', label: 'Operational Cost Weight' },
                  { key: 'w_performance_overhead', label: 'Performance Latency Weight' },
                  { key: 'w_monitoring_overhead', label: 'Monitoring Overhead Weight' },
                ].map((f) => (
                  <div key={f.key}>
                    <div className="flex justify-between text-slate-300 mb-1">
                      <span>{f.label}</span>
                      <span className="font-mono tabular-nums text-indigo-300">
                        {Number(weights[f.key as keyof CostOptimizerWeights]).toFixed(2)}
                      </span>
                    </div>
                    <input
                      type="range"
                      min={0.05}
                      max={0.75}
                      step={0.05}
                      disabled={currentUser.role !== 'Admin'}
                      value={weights[f.key as keyof CostOptimizerWeights]}
                      onChange={(e) => setWeights({ ...weights, [f.key]: Number(e.target.value) })}
                      className="w-full accent-indigo-500"
                    />
                  </div>
                ))}

                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div>
                    <label className="block text-slate-400 mb-1">Max Budget ($/mo)</label>
                    <input
                      type="number"
                      min={100}
                      max={10000}
                      disabled={currentUser.role !== 'Admin'}
                      value={weights.max_budget_usd}
                      onChange={(e) => setWeights({ ...weights, max_budget_usd: Number(e.target.value) })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1">Max Latency (%)</label>
                    <input
                      type="number"
                      step={0.5}
                      min={1}
                      max={25}
                      disabled={currentUser.role !== 'Admin'}
                      value={weights.max_latency_overhead_pct}
                      onChange={(e) => setWeights({ ...weights, max_latency_overhead_pct: Number(e.target.value) })}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={saving || currentUser.role !== 'Admin'}
                  className="w-full py-2 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded transition-colors"
                >
                  {saving ? 'Recalculating...' : 'Recalculate Policy Rankings'}
                </button>
                {currentUser.role !== 'Admin' && (
                  <p className="text-[11px] text-amber-400">Admin role required to modify optimization weights.</p>
                )}
              </form>
            </SurfacePanel>
          )}
        </div>

        <SurfacePanel title="Ranked Policy Trade-Off Matrix" subtitle="Ordered by weighted security-to-cost efficiency score">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 pr-3 font-medium">Policy</th>
                  <th className="py-2.5 pr-3 font-medium text-right">Security Gain</th>
                  <th className="py-2.5 pr-3 font-medium text-right">Cost Delta</th>
                  <th className="py-2.5 pr-3 font-medium text-right">Perf Overhead</th>
                  <th className="py-2.5 pr-3 font-medium text-right">Monitoring Overhead</th>
                  <th className="py-2.5 pr-3 font-medium text-right">Optimizer Score</th>
                  <th className="py-2.5 font-medium">Approval State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {policies
                  .slice()
                  .sort((a, b) => b.optimizer_score - a.optimizer_score)
                  .map((p) => {
                    const delta = p.operational_cost_after_usd - p.operational_cost_before_usd;
                    return (
                      <tr key={p.policy_id} className="hover:bg-slate-800/40">
                        <td className="py-2.5 pr-3">
                          <div className="font-medium text-slate-100">{p.title}</div>
                          <div className="font-mono text-[11px] text-slate-400">
                            {p.policy_id} · {p.target_user_id}
                          </div>
                        </td>
                        <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-emerald-400">
                          +{p.security_improvement_pct}%
                        </td>
                        <td
                          className={`py-2.5 pr-3 text-right font-mono tabular-nums ${
                            delta <= 0 ? 'text-emerald-400' : 'text-amber-300'
                          }`}
                        >
                          {delta <= 0 ? `-$${Math.abs(delta)}` : `+$${delta}`}/mo
                        </td>
                        <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-300">
                          +{p.performance_overhead_pct}%
                        </td>
                        <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-300">
                          +{p.monitoring_overhead_pct}%
                        </td>
                        <td className="py-2.5 pr-3 text-right font-mono tabular-nums font-semibold text-indigo-300">
                          {p.optimizer_score.toFixed(2)}
                        </td>
                        <td className="py-2.5">
                          <StatusText status={p.approval_status} />
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </SurfacePanel>
      </DataStateWrapper>
    </div>
  );
}
