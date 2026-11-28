import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, DollarSign, Info, Play, Send, Shield } from 'lucide-react';
import { api } from '../services/api';
import type {
  AuthUser,
  CostAwareOptimizationResult,
  CostOptimizerWeights,
  OptimizerConstraints,
  OptimizerObjectiveWeights,
  OptimizerScenarioInput,
  PolicyOptimizerOverviewResponse,
  PolicyRecommendation,
} from '../types/security';
import { DataStateWrapper, SectionHeader, StatusText, SurfacePanel } from '../components/ui/SocPrimitives';
import { BeforeAfterComparisonChart } from '../components/charts/SocCharts';

const SCENARIO_PRESETS: Array<{
  label: string;
  risk_score: number;
  confidence: number;
  false_positive_likelihood: number;
  identity_type: NonNullable<OptimizerScenarioInput['identity_type']>;
  asset_criticality: NonNullable<OptimizerScenarioInput['asset_criticality']>;
  max_cost: number;
  max_impact: number;
}> = [
  {
    label: 'Low Risk (18)',
    risk_score: 18,
    confidence: 0.65,
    false_positive_likelihood: 0.35,
    identity_type: 'IAMUser',
    asset_criticality: 'Low',
    max_cost: 180,
    max_impact: 70,
  },
  {
    label: 'Medium Risk (48)',
    risk_score: 48,
    confidence: 0.75,
    false_positive_likelihood: 0.25,
    identity_type: 'IAMUser',
    asset_criticality: 'Medium',
    max_cost: 180,
    max_impact: 70,
  },
  {
    label: 'High Risk (76)',
    risk_score: 76,
    confidence: 0.85,
    false_positive_likelihood: 0.15,
    identity_type: 'AssumedRole',
    asset_criticality: 'High',
    max_cost: 180,
    max_impact: 70,
  },
  {
    label: 'Critical (95 · Budget Constrained)',
    risk_score: 95,
    confidence: 0.94,
    false_positive_likelihood: 0.06,
    identity_type: 'IAMUser',
    asset_criticality: 'Critical',
    max_cost: 180,
    max_impact: 70,
  },
  {
    label: 'Critical (95 · Full Isolation Cap)',
    risk_score: 95,
    confidence: 0.96,
    false_positive_likelihood: 0.04,
    identity_type: 'IAMUser',
    asset_criticality: 'Critical',
    max_cost: 300,
    max_impact: 95,
  },
];

export function CostOptimizationPage({ currentUser }: { currentUser: AuthUser }) {
  const [policies, setPolicies] = useState<PolicyRecommendation[]>([]);
  const [weights, setWeights] = useState<CostOptimizerWeights | null>(null);
  const [optimizerOverview, setOptimizerOverview] = useState<PolicyOptimizerOverviewResponse | null>(null);
  const [activeOptimization, setActiveOptimization] = useState<CostAwareOptimizationResult | null>(null);

  // Interactive Adaptive Optimizer Scenario State
  const [riskScore, setRiskScore] = useState<number>(76);
  const [confidence, setConfidence] = useState<number>(0.85);
  const [fpLikelihood, setFpLikelihood] = useState<number>(0.15);
  const [identityType, setIdentityType] =
    useState<NonNullable<OptimizerScenarioInput['identity_type']>>('IAMUser');
  const [assetCriticality, setAssetCriticality] =
    useState<NonNullable<OptimizerScenarioInput['asset_criticality']>>('High');
  const [scenarioName, setScenarioName] = useState<string>('High-Risk S3 / STS Anomaly Triage');
  const [targetUser, setTargetUser] = useState<string>('m.chen@corp.internal');
  const [constraints, setConstraints] = useState<OptimizerConstraints>({
    max_enforcement_cost_usd: 180,
    max_operational_impact: 70,
    max_response_latency_sec: 30,
  });
  const [objWeights, setObjWeights] = useState<OptimizerObjectiveWeights>({
    w_risk_reduction: 0.54,
    w_enforcement_cost: 0.16,
    w_operational_impact: 0.14,
    w_response_latency: 0.04,
    w_fp_friction: 0.12,
  });
  const [optimizing, setOptimizing] = useState(false);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [polRes, optRes] = await Promise.all([
        api.getPolicies(),
        api.getPolicyOptimizer(),
      ]);
      setPolicies(polRes.policies);
      setWeights(polRes.costWeights);
      setOptimizerOverview(optRes);
      setConstraints(optRes.default_constraints);
      setObjWeights(optRes.default_weights);
      setActiveOptimization((prev) => {
        if (prev) return prev;
        if (optRes.history.length > 0) return optRes.history[0];
        if (optRes.application_evaluations.length > 0) return optRes.application_evaluations[0];
        return null;
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cost optimization analysis.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const applyPreset = (preset: (typeof SCENARIO_PRESETS)[number]) => {
    setRiskScore(preset.risk_score);
    setConfidence(preset.confidence);
    setFpLikelihood(preset.false_positive_likelihood);
    setIdentityType(preset.identity_type);
    setAssetCriticality(preset.asset_criticality);
    setScenarioName(preset.label);
    setConstraints((prev) => ({
      ...prev,
      max_enforcement_cost_usd: preset.max_cost,
      max_operational_impact: preset.max_impact,
    }));
  };

  const applyApplicationScenario = (opt: CostAwareOptimizationResult) => {
    setActiveOptimization(opt);
    setRiskScore(opt.input.risk_score);
    setConfidence(opt.input.confidence ?? 0.8);
    setFpLikelihood(opt.input.false_positive_likelihood ?? 0.2);
    if (opt.input.identity_type) setIdentityType(opt.input.identity_type);
    if (opt.input.asset_criticality) setAssetCriticality(opt.input.asset_criticality);
    if (opt.input.scenario_name) setScenarioName(opt.input.scenario_name);
    if (opt.input.target_user_id) setTargetUser(opt.input.target_user_id);
  };

  const handleRunOptimization = async (createProposal: boolean) => {
    setOptimizing(true);
    setMsg(null);
    try {
      const res = await api.evaluatePolicyOptimizer({
        risk_score: riskScore,
        confidence,
        false_positive_likelihood: fpLikelihood,
        identity_type: identityType,
        asset_criticality: assetCriticality,
        scenario_name: scenarioName,
        target_user_id: targetUser,
        scenario_source: 'manual_simulation',
        constraints,
        weights: objWeights,
        create_proposal: createProposal,
      });
      setActiveOptimization(res.optimization);
      setOptimizerOverview((prev) =>
        prev
          ? { ...prev, history: [res.optimization, ...prev.history].slice(0, 50) }
          : prev,
      );
      if (res.created_policy) {
        const created = res.created_policy;
        setPolicies((prev) => [created, ...prev]);
        setMsg(
          `Created Pending Approval policy proposal ${created.policy_id} ('${created.title}') — requires explicit Admin approval in Security Policies (never auto-executed).`,
        );
      } else {
        setMsg(
          `Optimized response '${res.optimization.recommended_action.action_label}' (utility=${res.optimization.recommended_action.utility_score.toFixed(3)}, estimated cost=$${res.optimization.recommended_action.estimated_enforcement_cost_usd}).`,
        );
      }
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Cost-aware optimization request failed.');
    } finally {
      setOptimizing(false);
    }
  };

  const handleRecalculate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!weights) return;
    setSaving(true);
    setMsg(null);
    try {
      const res = await api.updateWeights({ costWeights: weights });
      setPolicies(res.policies);
      setWeights(res.costWeights);
      setMsg('Recalculated baseline policy trade-off rankings under updated weights.');
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
        description="Explainable constraint-aware security action optimization balancing threat risk reduction, estimated enforcement cost, operational disruption, response latency, and false-positive friction."
      />

      <div className="p-3 rounded-lg border border-sky-500/30 bg-sky-950/20 text-xs text-sky-200 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold">Estimated Cost &amp; Human-in-the-Loop Guarantee:</span>{' '}
          {optimizerOverview?.cost_assumptions ||
            'All USD enforcement costs, latencies, and operational impact scores are configurable model estimates rather than AWS billing data. Recommended controls remain proposals requiring Admin approval and are never executed automatically.'}
        </div>
      </div>

      {msg && (
        <div className="px-4 py-2 bg-slate-900 border border-indigo-500/40 rounded text-xs text-indigo-200">{msg}</div>
      )}

      <DataStateWrapper loading={loading} error={error} onRetry={loadData}>
        {/* Interactive Cost-Aware Adaptive Policy Optimization Console */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <SurfacePanel
            title="Adaptive Response Scenario & Constraints"
            subtitle="Configure threat signal parameters and hard cost / operational limits"
          >
            <div className="space-y-3 text-xs">
              <div>
                <div className="text-slate-400 mb-1.5">Deterministic Benchmark Presets (Simulated)</div>
                <div className="flex flex-wrap gap-1.5">
                  {SCENARIO_PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      type="button"
                      onClick={() => applyPreset(preset)}
                      className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[11px] text-slate-200"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </div>

              {optimizerOverview && optimizerOverview.application_evaluations.length > 0 && (
                <div>
                  <div className="text-slate-400 mb-1.5">Active Application Risk Signals</div>
                  <div className="space-y-1">
                    {optimizerOverview.application_evaluations.map((appOpt) => (
                      <button
                        key={appOpt.optimization_id}
                        type="button"
                        onClick={() => applyApplicationScenario(appOpt)}
                        className="w-full text-left px-2.5 py-1.5 rounded bg-slate-950/80 hover:bg-slate-800/70 border border-slate-800 flex items-center justify-between gap-2"
                      >
                        <span className="truncate text-slate-200">{appOpt.input.scenario_name}</span>
                        <span className="font-mono text-indigo-300 shrink-0">
                          Risk {appOpt.input.risk_score}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2.5 pt-1">
                <div>
                  <label htmlFor="opt-risk-score" className="block text-slate-300 mb-1">
                    Risk Score (0–100)
                  </label>
                  <input
                    id="opt-risk-score"
                    type="number"
                    min={0}
                    max={100}
                    value={riskScore}
                    onChange={(e) => setRiskScore(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="opt-fp-likelihood" className="block text-slate-300 mb-1">
                    FP Likelihood (0–1)
                  </label>
                  <input
                    id="opt-fp-likelihood"
                    type="number"
                    step={0.05}
                    min={0}
                    max={1}
                    value={fpLikelihood}
                    onChange={(e) => setFpLikelihood(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="opt-max-cost" className="block text-slate-300 mb-1">
                    Max Est. Cost ($ USD)
                  </label>
                  <input
                    id="opt-max-cost"
                    type="number"
                    min={0}
                    max={1000}
                    value={constraints.max_enforcement_cost_usd}
                    onChange={(e) =>
                      setConstraints({ ...constraints, max_enforcement_cost_usd: Number(e.target.value) })
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="opt-max-impact" className="block text-slate-300 mb-1">
                    Max Op Impact (0–100)
                  </label>
                  <input
                    id="opt-max-impact"
                    type="number"
                    min={0}
                    max={100}
                    value={constraints.max_operational_impact}
                    onChange={(e) =>
                      setConstraints({ ...constraints, max_operational_impact: Number(e.target.value) })
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="opt-identity-type" className="block text-slate-300 mb-1">
                    Identity Type
                  </label>
                  <select
                    id="opt-identity-type"
                    value={identityType}
                    onChange={(e) =>
                      setIdentityType(e.target.value as NonNullable<OptimizerScenarioInput['identity_type']>)
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-slate-100"
                  >
                    <option value="IAMUser">IAMUser</option>
                    <option value="AssumedRole">AssumedRole</option>
                    <option value="AWSService">AWSService</option>
                    <option value="ServicePrincipal">ServicePrincipal</option>
                    <option value="AWSAccount">AWSAccount</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="opt-asset-crit" className="block text-slate-300 mb-1">
                    Asset Criticality
                  </label>
                  <select
                    id="opt-asset-crit"
                    value={assetCriticality}
                    onChange={(e) =>
                      setAssetCriticality(e.target.value as NonNullable<OptimizerScenarioInput['asset_criticality']>)
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-slate-100"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>

              <div className="pt-1 flex flex-col gap-2">
                <button
                  type="button"
                  disabled={optimizing || currentUser.role === 'Viewer'}
                  onClick={() => handleRunOptimization(false)}
                  className="w-full inline-flex items-center justify-center gap-2 py-2 px-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium rounded"
                >
                  <Play className="w-3.5 h-3.5" />
                  {optimizing ? 'Optimizing...' : 'Run Cost-Aware Optimization'}
                </button>
                <button
                  type="button"
                  disabled={optimizing || currentUser.role === 'Viewer'}
                  onClick={() => handleRunOptimization(true)}
                  className="w-full inline-flex items-center justify-center gap-2 py-1.5 px-3 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-100 font-medium rounded border border-slate-700"
                >
                  <Send className="w-3.5 h-3.5 text-emerald-400" />
                  Submit Action as Pending Policy Proposal
                </button>
                {currentUser.role === 'Viewer' && (
                  <p className="text-[11px] text-amber-400">
                    Viewer role is read-only; Admin or Security Analyst role required to run optimizations.
                  </p>
                )}
              </div>
            </div>
          </SurfacePanel>

          {/* Active Optimization Output + Static vs Optimized Comparison */}
          <div className="xl:col-span-2 space-y-5">
            {activeOptimization ? (
              <SurfacePanel
                title={`Recommended Action: ${activeOptimization.recommended_action.action_label}`}
                subtitle={`${activeOptimization.data_origin_label} · ID ${activeOptimization.optimization_id}`}
                rightSlot={
                  <span
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium border ${
                      activeOptimization.feasible_action_found
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                        : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                    }`}
                  >
                    {activeOptimization.feasible_action_found ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5" />
                    )}
                    {activeOptimization.constraint_status}
                  </span>
                }
              >
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 pb-4 border-b border-slate-800 text-xs">
                  <div className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                    <div className="text-slate-400 text-[11px]">Effective Risk</div>
                    <div className="text-base font-mono tabular-nums font-semibold text-slate-100 mt-0.5">
                      {activeOptimization.effective_risk_score} → {activeOptimization.recommended_action.expected_residual_risk}
                    </div>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                    <div className="text-slate-400 text-[11px]">Risk Reduction</div>
                    <div className="text-base font-mono tabular-nums font-semibold text-emerald-400 mt-0.5">
                      -{activeOptimization.recommended_action.risk_reduction} ({activeOptimization.recommended_action.risk_reduction_pct}%)
                    </div>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                    <div className="text-slate-400 text-[11px]">Est. Cost (Sim)</div>
                    <div className="text-base font-mono tabular-nums font-semibold text-amber-300 mt-0.5">
                      ${activeOptimization.recommended_action.estimated_enforcement_cost_usd}
                    </div>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                    <div className="text-slate-400 text-[11px]">Op Impact</div>
                    <div className="text-base font-mono tabular-nums font-semibold text-slate-100 mt-0.5">
                      {activeOptimization.recommended_action.operational_impact}/100
                    </div>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                    <div className="text-slate-400 text-[11px]">Latency (Est)</div>
                    <div className="text-base font-mono tabular-nums font-semibold text-sky-300 mt-0.5">
                      {activeOptimization.recommended_action.response_latency_sec}s
                    </div>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800 rounded p-2.5">
                    <div className="text-slate-400 text-[11px]">Utility Score</div>
                    <div className="text-base font-mono tabular-nums font-semibold text-indigo-300 mt-0.5">
                      {activeOptimization.recommended_action.utility_score.toFixed(4)}
                    </div>
                  </div>
                </div>

                {/* Explanation + Approval / Execution Status */}
                <div className="py-3 border-b border-slate-800 text-xs space-y-2">
                  <div className="text-slate-200 leading-relaxed">
                    <strong className="text-indigo-300">Decision Rationale:</strong> {activeOptimization.explanation}
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <span className="inline-flex items-center gap-1.5 text-slate-400">
                      <Shield className="w-3.5 h-3.5 text-emerald-400" />
                      {activeOptimization.execution_notice}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-slate-200">
                      Approval Status: {activeOptimization.approval_status}
                      {activeOptimization.linked_policy_id ? ` (${activeOptimization.linked_policy_id})` : ''}
                    </span>
                  </div>
                </div>

                {/* Static Baseline vs Cost-Aware Optimized Policy Comparison */}
                <div className="py-3 border-b border-slate-800 text-xs space-y-2">
                  <div className="font-medium text-slate-100 flex items-center justify-between">
                    <span>Static Baseline Rule vs. Cost-Aware Optimized Action</span>
                    <span className="font-mono text-[11px] text-slate-400">
                      Cost delta:{' '}
                      {activeOptimization.comparison_summary.cost_delta_vs_static_usd <= 0
                        ? `-$${Math.abs(activeOptimization.comparison_summary.cost_delta_vs_static_usd)}`
                        : `+$${activeOptimization.comparison_summary.cost_delta_vs_static_usd}`}{' '}
                      · Utility delta:{' '}
                      {activeOptimization.comparison_summary.utility_delta_vs_static >= 0 ? '+' : ''}
                      {activeOptimization.comparison_summary.utility_delta_vs_static.toFixed(4)}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="p-3 rounded border border-indigo-500/35 bg-indigo-950/20">
                      <div className="text-[11px] text-indigo-300 font-semibold uppercase">Cost-Aware Optimized</div>
                      <div className="text-sm font-medium text-slate-100 mt-0.5">
                        {activeOptimization.recommended_action.action_label}
                      </div>
                      <div className="mt-1.5 font-mono text-[11px] text-slate-300">
                        Residual {activeOptimization.recommended_action.expected_residual_risk} · Est. ${activeOptimization.recommended_action.estimated_enforcement_cost_usd} · Impact {activeOptimization.recommended_action.operational_impact}/100 · Utility {activeOptimization.recommended_action.utility_score.toFixed(3)}
                      </div>
                    </div>
                    <div className="p-3 rounded border border-slate-700 bg-slate-950/60">
                      <div className="text-[11px] text-slate-400 font-semibold uppercase">
                        Static Severity Rule Baseline {activeOptimization.static_baseline.feasible ? '(Feasible)' : '(Violates Constraints)'}
                      </div>
                      <div className="text-sm font-medium text-slate-200 mt-0.5">
                        {activeOptimization.static_baseline.action_label}
                      </div>
                      <div className="mt-1.5 font-mono text-[11px] text-slate-400">
                        Residual {activeOptimization.static_baseline.expected_residual_risk} · Est. ${activeOptimization.static_baseline.estimated_enforcement_cost_usd} · Impact {activeOptimization.static_baseline.operational_impact}/100 · Utility {activeOptimization.static_baseline.utility_score.toFixed(3)}
                      </div>
                    </div>
                  </div>
                </div>

                {/* All 5 Candidate Actions Table */}
                <div className="pt-3 overflow-x-auto">
                  <div className="text-xs font-medium text-slate-200 mb-2">Candidate Action Trade-Off Evaluation (Estimated Units)</div>
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-3 font-medium">Candidate Action</th>
                        <th className="py-2 pr-3 font-medium text-right">Residual</th>
                        <th className="py-2 pr-3 font-medium text-right">Reduction</th>
                        <th className="py-2 pr-3 font-medium text-right">Est. Cost ($)</th>
                        <th className="py-2 pr-3 font-medium text-right">Op Impact</th>
                        <th className="py-2 pr-3 font-medium text-right">Latency</th>
                        <th className="py-2 pr-3 font-medium text-right">FP Friction</th>
                        <th className="py-2 pr-3 font-medium text-right">Utility</th>
                        <th className="py-2 font-medium">Constraints</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono tabular-nums">
                      {activeOptimization.candidates.map((cand) => {
                        const isWinner = cand.action_id === activeOptimization.recommended_action.action_id;
                        return (
                          <tr key={cand.action_id} className={isWinner ? 'bg-indigo-950/30' : 'hover:bg-slate-800/30'}>
                            <td className="py-2 pr-3 font-sans">
                              <div className="font-medium text-slate-100">
                                {cand.action_label}
                                {isWinner && (
                                  <span className="ml-2 px-1.5 py-0.5 rounded bg-indigo-600/30 text-indigo-200 text-[10px]">
                                    Selected
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="py-2 pr-3 text-right">{cand.expected_residual_risk}</td>
                            <td className="py-2 pr-3 text-right text-emerald-400">-{cand.risk_reduction}</td>
                            <td className="py-2 pr-3 text-right">${cand.estimated_enforcement_cost_usd}</td>
                            <td className="py-2 pr-3 text-right">{cand.operational_impact}/100</td>
                            <td className="py-2 pr-3 text-right">{cand.response_latency_sec}s</td>
                            <td className="py-2 pr-3 text-right">{cand.false_positive_friction}</td>
                            <td className="py-2 pr-3 text-right text-indigo-300 font-semibold">{cand.utility_score.toFixed(4)}</td>
                            <td className="py-2 font-sans text-[11px]">
                              {cand.feasible ? (
                                <span className="text-emerald-400">Feasible</span>
                              ) : (
                                <span className="text-rose-400" title={cand.constraint_violations.join(' ')}>
                                  Infeasible
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
            ) : (
              <SurfacePanel title="Adaptive Policy Optimizer Ready" subtitle="Run an optimization scenario on the left">
                <p className="text-xs text-slate-400">Select a risk preset or active incident signal to compare all 5 response controls.</p>
              </SurfacePanel>
            )}
          </div>
        </div>

        {/* Preserved Policy Portfolio Summary & Trade-Off Matrix */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <SurfacePanel>
            <div className="text-xs text-slate-400">Portfolio Residual Risk (Seeded Baseline)</div>
            <div className="mt-1 text-xl font-mono tabular-nums font-semibold text-emerald-400">
              {avgRiskBefore}% → {avgRiskAfter}%
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Net risk reduction: -{avgRiskBefore - avgRiskAfter} pts</div>
          </SurfacePanel>
          <SurfacePanel>
            <div className="text-xs text-slate-400">Estimated Monthly Policy Cost</div>
            <div className="mt-1 text-xl font-mono tabular-nums font-semibold text-slate-100">
              ${totalBeforeCost} → ${totalAfterCost}
            </div>
            <div className="text-[11px] text-emerald-400 mt-1">
              Net delta: {totalAfterCost - totalBeforeCost <= 0 ? `-$${totalBeforeCost - totalAfterCost}/mo saved` : `+$${totalAfterCost - totalBeforeCost}/mo`} (Est.)
            </div>
          </SurfacePanel>
          <SurfacePanel>
            <div className="text-xs text-slate-400">Avg Performance Impact</div>
            <div className="mt-1 text-xl font-mono tabular-nums font-semibold text-sky-300">+{avgPerf}%</div>
            <div className="text-[11px] text-slate-500 mt-1">Estimated auth / boundary overhead</div>
          </SurfacePanel>
          <SurfacePanel>
            <div className="text-xs text-slate-400">Optimization Method</div>
            <div className="mt-1 text-sm font-semibold text-indigo-300 flex items-center gap-1.5">
              <DollarSign className="w-4 h-4" /> Multi-Objective Constraint Utility
            </div>
            <div className="text-[11px] text-slate-500 mt-1">Deterministic scoring · Human approval required</div>
          </SurfacePanel>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
          <SurfacePanel
            title="Before vs After Security & Cost Comparison"
            subtitle="Comparing baseline posture against recommended adaptive policies (Estimated USD)"
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
              title="Portfolio Weights & Constraints"
              subtitle="Adjust objective weights to re-rank policy proposals"
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
                  <p className="text-[11px] text-amber-400">Admin role required to modify portfolio weights.</p>
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
