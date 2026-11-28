import type {
  ApprovalStatus,
  CostAwareOptimizationResult,
  OptimizerActionEvaluation,
  OptimizerCandidateActionConfig,
  OptimizerConstraints,
  OptimizerInputValidationResult,
  OptimizerObjectiveWeights,
  OptimizerScenarioInput,
  PolicyActionId,
  PolicyRecommendation,
} from '../types/security.ts';

export const COST_ESTIMATION_ASSUMPTIONS =
  'All enforcement costs (USD per incident-response window), response latencies (seconds), and operational impact scores (0-100 disruption index) are configurable model estimates, not live AWS billing metrics or automated cloud executions.';

export const CANDIDATE_ACTION_CATALOG: OptimizerCandidateActionConfig[] = [
  {
    action_id: 'monitor_and_alert',
    action_label: 'Monitor and alert',
    category: 'Monitoring & Alerting',
    base_effectiveness: 0.22,
    estimated_enforcement_cost_usd: 18,
    base_operational_impact: 5,
    estimated_response_latency_sec: 1.5,
    fp_friction_factor: 0.05,
    description:
      'Retains active sessions untouched while elevating SIEM alerting priority and capturing granular API audit telemetry for SOC analyst triage.',
  },
  {
    action_id: 'require_additional_mfa',
    action_label: 'Require additional MFA',
    category: 'MFA Enforcement',
    base_effectiveness: 0.56,
    estimated_enforcement_cost_usd: 45,
    base_operational_impact: 22,
    estimated_response_latency_sec: 4.0,
    fp_friction_factor: 0.25,
    description:
      'Challenges the identity with step-up multi-factor authentication on privileged or sensitive API calls prior to permitting execution.',
  },
  {
    action_id: 'temporarily_restrict_permissions',
    action_label: 'Temporarily restrict permissions',
    category: 'Temporary Restriction',
    base_effectiveness: 0.74,
    estimated_enforcement_cost_usd: 95,
    base_operational_impact: 48,
    estimated_response_latency_sec: 12.0,
    fp_friction_factor: 0.45,
    description:
      'Attaches a time-bounded least-privilege permission boundary blocking destructive write, IAM, and bulk export APIs while keeping read-only diagnostics available.',
  },
  {
    action_id: 'revoke_suspicious_session',
    action_label: 'Revoke suspicious session',
    category: 'Session Hardening',
    base_effectiveness: 0.85,
    estimated_enforcement_cost_usd: 140,
    base_operational_impact: 64,
    estimated_response_latency_sec: 3.5,
    fp_friction_factor: 0.65,
    description:
      'Invalidates active temporary STS tokens and interactive console sessions to halt active lateral movement or exfiltration while allowing clean re-authentication.',
  },
  {
    action_id: 'isolate_account_and_escalate',
    action_label: 'Isolate account and escalate to administrator',
    category: 'Least Privilege',
    base_effectiveness: 0.94,
    estimated_enforcement_cost_usd: 260,
    base_operational_impact: 88,
    estimated_response_latency_sec: 8.0,
    fp_friction_factor: 0.9,
    description:
      'Applies full explicit-deny quarantine to the principal and raises a high-priority administrator incident ticket requiring manual credential rotation.',
  },
];

export const DEFAULT_OPTIMIZER_CONSTRAINTS: OptimizerConstraints = {
  max_enforcement_cost_usd: 180,
  max_operational_impact: 70,
  max_response_latency_sec: 30,
};

export const DEFAULT_OPTIMIZER_WEIGHTS: OptimizerObjectiveWeights = {
  w_risk_reduction: 0.54,
  w_enforcement_cost: 0.16,
  w_operational_impact: 0.14,
  w_response_latency: 0.04,
  w_fp_friction: 0.12,
};

function clamp(val: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, val));
}

function round(val: number, digits = 3): number {
  const factor = 10 ** digits;
  return Math.round(val * factor) / factor;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Validate optimization scenario parameters, rejecting NaN, out-of-range, or malformed inputs
 * cleanly instead of silently coercing invalid numbers.
 */
export function validateOptimizerInput(rawInput: unknown): OptimizerInputValidationResult {
  if (!rawInput || typeof rawInput !== 'object' || Array.isArray(rawInput)) {
    return { valid: false, errors: ['Request payload must be a JSON object.'] };
  }

  const input = rawInput as Record<string, unknown>;
  const errors: string[] = [];

  if (!isFiniteNumber(input.risk_score) || input.risk_score < 0 || input.risk_score > 100) {
    errors.push('risk_score is required and must be a finite number between 0 and 100.');
  }

  let confidence = 0.75;
  if (input.confidence !== undefined) {
    if (!isFiniteNumber(input.confidence) || input.confidence < 0 || input.confidence > 1) {
      errors.push('confidence must be a finite number between 0 and 1.');
    } else {
      confidence = input.confidence;
    }
  }

  let fpLikelihood = clamp(round(1 - confidence, 3), 0.05, 0.85);
  if (input.false_positive_likelihood !== undefined) {
    if (
      !isFiniteNumber(input.false_positive_likelihood) ||
      input.false_positive_likelihood < 0 ||
      input.false_positive_likelihood > 1
    ) {
      errors.push('false_positive_likelihood must be a finite number between 0 and 1.');
    } else {
      fpLikelihood = input.false_positive_likelihood;
    }
  }

  const allowedIdentities = new Set([
    'IAMUser',
    'AssumedRole',
    'AWSService',
    'AWSAccount',
    'ServicePrincipal',
    'Unknown',
  ]);
  const identityType =
    typeof input.identity_type === 'string' && input.identity_type.trim()
      ? input.identity_type.trim()
      : 'IAMUser';
  if (!allowedIdentities.has(identityType)) {
    errors.push(
      'identity_type must be one of IAMUser, AssumedRole, AWSService, AWSAccount, ServicePrincipal, or Unknown.',
    );
  }

  const allowedCriticality = new Set(['Low', 'Medium', 'High', 'Critical']);
  const assetCriticality =
    typeof input.asset_criticality === 'string' && input.asset_criticality.trim()
      ? input.asset_criticality.trim()
      : 'Medium';
  if (!allowedCriticality.has(assetCriticality)) {
    errors.push('asset_criticality must be one of Low, Medium, High, or Critical.');
  }

  const constraintsRaw =
    input.constraints && typeof input.constraints === 'object' && !Array.isArray(input.constraints)
      ? (input.constraints as Record<string, unknown>)
      : {};
  if (input.constraints !== undefined && (typeof input.constraints !== 'object' || Array.isArray(input.constraints))) {
    errors.push('constraints must be an object when provided.');
  }

  let maxCost = DEFAULT_OPTIMIZER_CONSTRAINTS.max_enforcement_cost_usd;
  if (constraintsRaw.max_enforcement_cost_usd !== undefined) {
    if (
      !isFiniteNumber(constraintsRaw.max_enforcement_cost_usd) ||
      constraintsRaw.max_enforcement_cost_usd < 0
    ) {
      errors.push('constraints.max_enforcement_cost_usd must be a non-negative finite number.');
    } else {
      maxCost = constraintsRaw.max_enforcement_cost_usd;
    }
  }

  let maxImpact = DEFAULT_OPTIMIZER_CONSTRAINTS.max_operational_impact;
  if (constraintsRaw.max_operational_impact !== undefined) {
    if (
      !isFiniteNumber(constraintsRaw.max_operational_impact) ||
      constraintsRaw.max_operational_impact < 0 ||
      constraintsRaw.max_operational_impact > 100
    ) {
      errors.push('constraints.max_operational_impact must be a finite number between 0 and 100.');
    } else {
      maxImpact = constraintsRaw.max_operational_impact;
    }
  }

  let maxLatency = DEFAULT_OPTIMIZER_CONSTRAINTS.max_response_latency_sec;
  if (constraintsRaw.max_response_latency_sec !== undefined) {
    if (
      !isFiniteNumber(constraintsRaw.max_response_latency_sec) ||
      constraintsRaw.max_response_latency_sec <= 0
    ) {
      errors.push('constraints.max_response_latency_sec must be a positive finite number.');
    } else {
      maxLatency = constraintsRaw.max_response_latency_sec;
    }
  }

  const weightsRaw =
    input.weights && typeof input.weights === 'object' && !Array.isArray(input.weights)
      ? (input.weights as Record<string, unknown>)
      : {};
  if (input.weights !== undefined && (typeof input.weights !== 'object' || Array.isArray(input.weights))) {
    errors.push('weights must be an object when provided.');
  }

  const weights: OptimizerObjectiveWeights = { ...DEFAULT_OPTIMIZER_WEIGHTS };
  for (const key of Object.keys(DEFAULT_OPTIMIZER_WEIGHTS) as Array<keyof OptimizerObjectiveWeights>) {
    if (weightsRaw[key] !== undefined) {
      if (!isFiniteNumber(weightsRaw[key]) || (weightsRaw[key] as number) < 0) {
        errors.push(`weights.${key} must be a non-negative finite number.`);
      } else {
        weights[key] = weightsRaw[key] as number;
      }
    }
  }
  const weightSum =
    weights.w_risk_reduction +
    weights.w_enforcement_cost +
    weights.w_operational_impact +
    weights.w_response_latency +
    weights.w_fp_friction;
  if (weightSum <= 0) {
    errors.push('At least one optimizer objective weight must be greater than zero.');
  }

  const scenarioSource =
    input.scenario_source === 'application_prediction' ||
    input.scenario_source === 'incident' ||
    input.scenario_source === 'manual_simulation'
      ? input.scenario_source
      : 'manual_simulation';

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const normalized: OptimizerScenarioInput = {
    risk_score: Number(input.risk_score),
    confidence,
    false_positive_likelihood: fpLikelihood,
    identity_type: identityType as OptimizerScenarioInput['identity_type'],
    asset_criticality: assetCriticality as OptimizerScenarioInput['asset_criticality'],
    target_user_id:
      typeof input.target_user_id === 'string' && input.target_user_id.trim()
        ? input.target_user_id.trim()
        : 'unspecified-principal',
    target_resource:
      typeof input.target_resource === 'string' && input.target_resource.trim()
        ? input.target_resource.trim()
        : 'cloud-environment-scope',
    scenario_name:
      typeof input.scenario_name === 'string' && input.scenario_name.trim()
        ? input.scenario_name.trim()
        : 'Adaptive Risk Response Scenario',
    scenario_source: scenarioSource,
    prediction_id: typeof input.prediction_id === 'string' ? input.prediction_id : undefined,
    incident_id: typeof input.incident_id === 'string' ? input.incident_id : undefined,
    constraints: {
      max_enforcement_cost_usd: maxCost,
      max_operational_impact: maxImpact,
      max_response_latency_sec: maxLatency,
    },
    weights,
  };

  return { valid: true, errors: [], normalized };
}

/**
 * Legacy static rule-based severity mapping used strictly as the non-adaptive baseline comparison.
 * Ignores enforcement cost, operational impact limits, identity compatibility, and FP friction.
 */
export function selectStaticBaselineActionId(riskScore: number): PolicyActionId {
  if (riskScore >= 85) return 'isolate_account_and_escalate';
  if (riskScore >= 60) return 'temporarily_restrict_permissions';
  if (riskScore >= 30) return 'require_additional_mfa';
  return 'monitor_and_alert';
}

function normalizeWeights(w: OptimizerObjectiveWeights): OptimizerObjectiveWeights {
  const sum =
    w.w_risk_reduction +
    w.w_enforcement_cost +
    w.w_operational_impact +
    w.w_response_latency +
    w.w_fp_friction || 1;
  return {
    w_risk_reduction: w.w_risk_reduction / sum,
    w_enforcement_cost: w.w_enforcement_cost / sum,
    w_operational_impact: w.w_operational_impact / sum,
    w_response_latency: w.w_response_latency / sum,
    w_fp_friction: w.w_fp_friction / sum,
  };
}

/**
 * Evaluate all 5 candidate actions under risk, cost, operational impact, latency,
 * false-positive friction, and hard feasibility constraints.
 */
export function optimizeSecurityPolicy(
  rawInput: OptimizerScenarioInput,
  options?: {
    catalogOverrides?: Partial<Record<PolicyActionId, Partial<OptimizerCandidateActionConfig>>>;
    linkedPolicy?: PolicyRecommendation | null;
  },
): CostAwareOptimizationResult {
  const validation = validateOptimizerInput(rawInput);
  if (!validation.valid || !validation.normalized) {
    throw new Error(`Invalid optimizer input: ${validation.errors.join(' ')}`);
  }

  const input = validation.normalized;
  const constraints: OptimizerConstraints = {
    ...DEFAULT_OPTIMIZER_CONSTRAINTS,
    ...input.constraints,
  };
  const wNorm = normalizeWeights({
    ...DEFAULT_OPTIMIZER_WEIGHTS,
    ...input.weights,
  });

  const criticalityMultiplier: Record<NonNullable<OptimizerScenarioInput['asset_criticality']>, number> = {
    Low: 0.9,
    Medium: 1.0,
    High: 1.12,
    Critical: 1.22,
  };
  const assetMult = criticalityMultiplier[input.asset_criticality || 'Medium'];
  const effectiveRisk = clamp(round(input.risk_score * assetMult, 2), 0, 100);
  const fpProb = input.false_positive_likelihood ?? 0.25;
  const isAutomatedIdentity =
    input.identity_type === 'AWSService' || input.identity_type === 'ServicePrincipal';

  const maxCatalogCost = Math.max(
    ...CANDIDATE_ACTION_CATALOG.map((c) => {
      const ov = options?.catalogOverrides?.[c.action_id];
      return ov?.estimated_enforcement_cost_usd ?? c.estimated_enforcement_cost_usd;
    }),
    1,
  );
  const maxCatalogLatency = Math.max(
    ...CANDIDATE_ACTION_CATALOG.map((c) => {
      const ov = options?.catalogOverrides?.[c.action_id];
      return ov?.estimated_response_latency_sec ?? c.estimated_response_latency_sec;
    }),
    1,
  );

  const evaluations: OptimizerActionEvaluation[] = CANDIDATE_ACTION_CATALOG.map((baseCfg) => {
    const ov = options?.catalogOverrides?.[baseCfg.action_id];
    const cfg: OptimizerCandidateActionConfig = { ...baseCfg, ...(ov || {}) };

    let effectiveEfficiency = cfg.base_effectiveness * (0.85 + 0.15 * (input.confidence ?? 0.75));
    let operationalImpact = cfg.base_operational_impact;

    // Account-type adaptation: interactive MFA cannot directly challenge automated non-interactive roles
    if (cfg.action_id === 'require_additional_mfa' && isAutomatedIdentity) {
      effectiveEfficiency = Math.max(0.2, effectiveEfficiency - 0.22);
      operationalImpact = Math.min(100, operationalImpact + 14);
    }
    if (cfg.action_id === 'isolate_account_and_escalate' && isAutomatedIdentity) {
      operationalImpact = Math.min(100, operationalImpact + 8);
    }

    effectiveEfficiency = clamp(effectiveEfficiency, 0.05, 0.98);
    const riskReduction = round(effectiveRisk * effectiveEfficiency, 2);
    const expectedResidualRisk = round(Math.max(0, effectiveRisk - riskReduction), 2);
    const riskReductionPct = round((riskReduction / Math.max(1, effectiveRisk)) * 100, 1);

    // False-positive friction scales up when risk is moderate/low and false_positive_likelihood is elevated
    const fpFriction = round(
      clamp(100 * cfg.fp_friction_factor * fpProb * (1.2 - 0.35 * (effectiveRisk / 100)), 0, 100),
      2,
    );

    const costRef = Math.max(maxCatalogCost, 260);
    const latencyRef = Math.max(constraints.max_response_latency_sec, maxCatalogLatency, 30);
    const costNorm = clamp(cfg.estimated_enforcement_cost_usd / costRef, 0, 1);
    const impactNorm = clamp(operationalImpact / 100, 0, 1);
    const latencyNorm = clamp(cfg.estimated_response_latency_sec / latencyRef, 0, 1);
    const fpNorm = clamp(fpFriction / 100, 0, 1);
    const riskBenefitNorm = clamp(riskReduction / 100, 0, 1);

    // Weighted multi-objective utility: linear risk-reduction reward minus convex disruption/cost/FP penalty
    const convexDisruptionCost =
      wNorm.w_enforcement_cost * (costNorm ** 1.15) +
      wNorm.w_operational_impact * (impactNorm ** 1.45) +
      wNorm.w_response_latency * latencyNorm +
      wNorm.w_fp_friction * (fpNorm ** 1.1);
    const rawUtility = 1.32 * wNorm.w_risk_reduction * riskBenefitNorm - convexDisruptionCost;
    const utilityScore = round(clamp((rawUtility + 1.0) / 2.32, 0, 1), 4);

    const violations: string[] = [];
    if (cfg.estimated_enforcement_cost_usd > constraints.max_enforcement_cost_usd) {
      violations.push(
        `Estimated enforcement cost ($${cfg.estimated_enforcement_cost_usd}) exceeds max_enforcement_cost_usd ($${constraints.max_enforcement_cost_usd}).`,
      );
    }
    if (operationalImpact > constraints.max_operational_impact) {
      violations.push(
        `Operational impact (${operationalImpact}/100) exceeds max_operational_impact (${constraints.max_operational_impact}/100).`,
      );
    }
    if (cfg.estimated_response_latency_sec > constraints.max_response_latency_sec) {
      violations.push(
        `Response latency (${cfg.estimated_response_latency_sec}s) exceeds max_response_latency_sec (${constraints.max_response_latency_sec}s).`,
      );
    }

    return {
      action_id: cfg.action_id,
      action_label: cfg.action_label,
      category: cfg.category,
      description: cfg.description,
      expected_residual_risk: expectedResidualRisk,
      risk_reduction: riskReduction,
      risk_reduction_pct: riskReductionPct,
      estimated_enforcement_cost_usd: cfg.estimated_enforcement_cost_usd,
      operational_impact: operationalImpact,
      response_latency_sec: cfg.estimated_response_latency_sec,
      false_positive_friction: fpFriction,
      utility_score: utilityScore,
      feasible: violations.length === 0,
      constraint_violations: violations,
    };
  });

  const ranked = evaluations
    .slice()
    .sort((a, b) => {
      if (a.feasible !== b.feasible) return a.feasible ? -1 : 1;
      if (Math.abs(b.utility_score - a.utility_score) > 1e-9) {
        return b.utility_score - a.utility_score;
      }
      return a.estimated_enforcement_cost_usd - b.estimated_enforcement_cost_usd;
    });

  const feasibleList = ranked.filter((item) => item.feasible);
  const feasibleFound = feasibleList.length > 0;
  // If strict constraints eliminate every option (including Monitor & Alert), fall back to lowest-impact option and surface constraint_status honestly
  const recommended = feasibleFound
    ? feasibleList[0]
    : evaluations
        .slice()
        .sort((a, b) => a.estimated_enforcement_cost_usd - b.estimated_enforcement_cost_usd)[0];

  const staticBaselineId = selectStaticBaselineActionId(input.risk_score);
  const staticBaseline = evaluations.find((e) => e.action_id === staticBaselineId) || evaluations[0];

  const staticViolatedNote = staticBaseline.feasible
    ? 'satisfies configured constraints'
    : `violates constraints (${staticBaseline.constraint_violations.join(' ')})`;

  const explanationParts: string[] = [];
  if (!feasibleFound) {
    explanationParts.push(
      `No candidate satisfied all constraints (cost <= $${constraints.max_enforcement_cost_usd}, impact <= ${constraints.max_operational_impact}/100, latency <= ${constraints.max_response_latency_sec}s); surfaced least-intrusive fallback '${recommended.action_label}' requiring constraint adjustment or manual triage.`,
    );
  } else {
    explanationParts.push(
      `Selected '${recommended.action_label}' (utility ${recommended.utility_score.toFixed(3)}) for risk_score=${input.risk_score} (effective=${effectiveRisk}, FP likelihood=${round(fpProb * 100, 1)}%, identity=${input.identity_type}).`,
    );
    explanationParts.push(
      `Reduces expected residual risk from ${effectiveRisk} to ${recommended.expected_residual_risk} (-${recommended.risk_reduction} pts / -${recommended.risk_reduction_pct}%) at an estimated cost of $${recommended.estimated_enforcement_cost_usd}, operational impact ${recommended.operational_impact}/100, latency ${recommended.response_latency_sec}s, and FP friction ${recommended.false_positive_friction}/100.`,
    );
  }

  if (recommended.action_id !== staticBaseline.action_id) {
    explanationParts.push(
      `Differs from static rule baseline '${staticBaseline.action_label}' (utility ${staticBaseline.utility_score.toFixed(3)}, $${staticBaseline.estimated_enforcement_cost_usd}, impact ${staticBaseline.operational_impact}/100), which ${staticViolatedNote}.`,
    );
  } else {
    explanationParts.push(
      `Aligns with static rule baseline '${staticBaseline.action_label}' while verifying feasibility under cost ($${constraints.max_enforcement_cost_usd}) and impact (${constraints.max_operational_impact}/100) limits.`,
    );
  }

  const isRealAppData =
    input.scenario_source === 'application_prediction' || input.scenario_source === 'incident';
  const approvalStatus: ApprovalStatus | 'Proposal Only (Not Submitted)' = options?.linkedPolicy
    ? options.linkedPolicy.approval_status
    : 'Proposal Only (Not Submitted)';

  return {
    optimization_id: `OPT-${Date.now().toString(36).toUpperCase()}-${Math.round(effectiveRisk * 10)}`,
    evaluated_at: new Date().toISOString(),
    data_origin: isRealAppData ? 'application_data' : 'simulated_scenario',
    data_origin_label: isRealAppData
      ? 'Real Application Risk Signal (Estimated Cost/Impact Parameters)'
      : 'Simulated Benchmark Scenario (Estimated Cost/Impact Parameters)',
    is_estimated_cost: true,
    auto_executed: false,
    execution_notice:
      'Proposal only: no AWS IAM, STS, Lambda, or OpenStack enforcement action was executed automatically. Human administrator approval is required.',
    cost_assumptions: COST_ESTIMATION_ASSUMPTIONS,
    input,
    effective_risk_score: effectiveRisk,
    feasible_action_found: feasibleFound,
    constraint_status: feasibleFound
      ? `Feasible (${feasibleList.length}/${evaluations.length} actions within constraints)`
      : 'No Feasible Action Under Strict Constraints',
    recommended_action: recommended,
    static_baseline: staticBaseline,
    comparison_summary: {
      same_as_static_baseline: recommended.action_id === staticBaseline.action_id,
      cost_delta_vs_static_usd: round(
        recommended.estimated_enforcement_cost_usd - staticBaseline.estimated_enforcement_cost_usd,
        2,
      ),
      impact_delta_vs_static: round(
        recommended.operational_impact - staticBaseline.operational_impact,
        2,
      ),
      utility_delta_vs_static: round(recommended.utility_score - staticBaseline.utility_score, 4),
      static_baseline_feasible: staticBaseline.feasible,
    },
    explanation: explanationParts.join(' '),
    approval_status: approvalStatus,
    linked_policy_id: options?.linkedPolicy?.policy_id,
    candidates: ranked,
  };
}

export function buildPolicyProposalFromOptimization(
  opt: CostAwareOptimizationResult,
): PolicyRecommendation {
  const act = opt.recommended_action;
  const suffix = opt.optimization_id.replace(/^OPT-/, '').slice(-6);
  const policyId = `POL-OPT-${suffix}`;
  const riskBefore = Math.round(opt.effective_risk_score);
  const riskAfter = Math.round(act.expected_residual_risk);
  const improvementPct = Number(act.risk_reduction_pct.toFixed(1));

  return {
    policy_id: policyId,
    target_user_id: opt.input.target_user_id || 'unspecified-principal',
    target_resource: opt.input.target_resource || 'cloud-environment-scope',
    category:
      act.category === 'Monitoring & Alerting'
        ? 'Session Hardening'
        : (act.category as PolicyRecommendation['category']),
    title: `[Cost-Aware Proposal] ${act.action_label} (${opt.input.scenario_name || opt.optimization_id})`,
    description: `${opt.explanation} [Estimated operational enforcement cost=$${act.estimated_enforcement_cost_usd}; impact=${act.operational_impact}/100; latency=${act.response_latency_sec}s; non-binding proposal requiring Admin approval].`,
    supporting_evidence: [
      ...(opt.input.prediction_id ? [opt.input.prediction_id] : []),
      ...(opt.input.incident_id ? [opt.input.incident_id] : []),
      opt.optimization_id,
    ],
    security_improvement_pct: improvementPct,
    residual_risk_before: riskBefore,
    residual_risk_after: riskAfter,
    operational_cost_before_usd: 0,
    operational_cost_after_usd: act.estimated_enforcement_cost_usd,
    performance_overhead_pct: Number((act.operational_impact * 0.1).toFixed(1)),
    monitoring_overhead_pct: Number((act.response_latency_sec * 0.25).toFixed(1)),
    optimizer_score: Number(act.utility_score.toFixed(2)),
    approval_status: 'Pending Approval',
    requires_admin_approval: true,
  };
}
