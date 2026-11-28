import assert from 'node:assert/strict';
import {
  CANDIDATE_ACTION_CATALOG,
  buildPolicyProposalFromOptimization,
  optimizeSecurityPolicy,
  selectStaticBaselineActionId,
  validateOptimizerInput,
} from '../src/server/policyOptimizer.ts';
import type { OptimizerScenarioInput } from '../src/types/security.ts';

function runUnitTests(): void {
  console.log('Running Cost-Aware Adaptive Policy Optimizer deterministic unit tests...');

  // 1. Catalog completeness (5 candidate actions)
  assert.equal(CANDIDATE_ACTION_CATALOG.length, 5);

  // 2. Deterministic risk tiers: Low, Medium, High, Critical
  const low = optimizeSecurityPolicy({
    risk_score: 18,
    confidence: 0.65,
    asset_criticality: 'Low',
    constraints: { max_enforcement_cost_usd: 180, max_operational_impact: 70 },
  });
  assert.equal(low.recommended_action.action_id, 'monitor_and_alert');
  assert.equal(low.auto_executed, false);
  assert.equal(low.is_estimated_cost, true);
  assert.ok(low.recommended_action.expected_residual_risk < low.effective_risk_score);
  assert.ok(low.explanation.length > 20);

  const medium = optimizeSecurityPolicy({
    risk_score: 48,
    confidence: 0.75,
    asset_criticality: 'Medium',
    constraints: { max_enforcement_cost_usd: 180, max_operational_impact: 70 },
  });
  assert.equal(medium.recommended_action.action_id, 'require_additional_mfa');
  assert.equal(medium.feasible_action_found, true);

  const high = optimizeSecurityPolicy({
    risk_score: 76,
    confidence: 0.85,
    asset_criticality: 'High',
    constraints: { max_enforcement_cost_usd: 180, max_operational_impact: 70 },
  });
  assert.equal(high.feasible_action_found, true);
  assert.ok(
    ['temporarily_restrict_permissions', 'revoke_suspicious_session'].includes(
      high.recommended_action.action_id,
    ),
  );
  assert.equal(high.static_baseline.action_id, 'temporarily_restrict_permissions');

  // Critical risk under standard operational constraints vs. high-urgency containment weights
  const criticalConstrained = optimizeSecurityPolicy({
    risk_score: 95,
    confidence: 0.94,
    asset_criticality: 'Critical',
    constraints: { max_enforcement_cost_usd: 180, max_operational_impact: 70 },
  });
  assert.equal(criticalConstrained.static_baseline.action_id, 'isolate_account_and_escalate');
  assert.equal(criticalConstrained.static_baseline.feasible, false);
  assert.equal(criticalConstrained.comparison_summary.static_baseline_feasible, false);
  assert.equal(criticalConstrained.recommended_action.action_id, 'revoke_suspicious_session');
  assert.equal(criticalConstrained.recommended_action.feasible, true);

  const criticalFullCapUrgent = optimizeSecurityPolicy({
    risk_score: 98,
    confidence: 0.98,
    false_positive_likelihood: 0.02,
    asset_criticality: 'Critical',
    constraints: { max_enforcement_cost_usd: 300, max_operational_impact: 95 },
    weights: {
      w_risk_reduction: 0.82,
      w_enforcement_cost: 0.05,
      w_operational_impact: 0.05,
      w_response_latency: 0.02,
      w_fp_friction: 0.06,
    },
  });
  assert.equal(criticalFullCapUrgent.recommended_action.action_id, 'isolate_account_and_escalate');
  assert.equal(criticalFullCapUrgent.recommended_action.feasible, true);

  // 3. Cost constraint enforcement
  const costCapped = optimizeSecurityPolicy({
    risk_score: 90,
    confidence: 0.9,
    constraints: { max_enforcement_cost_usd: 100, max_operational_impact: 100 },
  });
  assert.ok(costCapped.recommended_action.estimated_enforcement_cost_usd <= 100);
  const revokeCand = costCapped.candidates.find((c) => c.action_id === 'revoke_suspicious_session');
  assert.equal(revokeCand?.feasible, false);

  // Impossible budget -> explicit infeasible flag, no silent fake pass
  const impossibleBudget = optimizeSecurityPolicy({
    risk_score: 80,
    constraints: { max_enforcement_cost_usd: 5, max_operational_impact: 100 },
  });
  assert.equal(impossibleBudget.feasible_action_found, false);
  assert.match(impossibleBudget.constraint_status, /No Feasible Action/i);

  // 4. Operational-impact constraint enforcement
  const impactCapped = optimizeSecurityPolicy({
    risk_score: 92,
    confidence: 0.9,
    constraints: { max_enforcement_cost_usd: 500, max_operational_impact: 50 },
  });
  assert.ok(impactCapped.recommended_action.operational_impact <= 50);
  assert.equal(impactCapped.recommended_action.action_id, 'temporarily_restrict_permissions');

  // 5. High false-positive likelihood friction penalty
  const noisyHighFp = optimizeSecurityPolicy({
    risk_score: 65,
    confidence: 0.3,
    false_positive_likelihood: 0.85,
    constraints: { max_enforcement_cost_usd: 300, max_operational_impact: 95 },
  });
  assert.notEqual(noisyHighFp.recommended_action.action_id, 'isolate_account_and_escalate');

  // 6. Missing optional values handled safely via documented defaults
  const minimalInput = validateOptimizerInput({ risk_score: 55 });
  assert.equal(minimalInput.valid, true);
  assert.equal(minimalInput.normalized?.confidence, 0.75);
  assert.equal(minimalInput.normalized?.constraints?.max_enforcement_cost_usd, 180);

  // 7. Invalid inputs rejected cleanly
  for (const bad of [
    null,
    [],
    {},
    { risk_score: -1 },
    { risk_score: 101 },
    { risk_score: Number.NaN },
    { risk_score: 50, confidence: 1.5 },
    { risk_score: 50, false_positive_likelihood: -0.2 },
    { risk_score: 50, identity_type: 'RootSuperFake' },
    { risk_score: 50, constraints: { max_enforcement_cost_usd: -10 } },
    { risk_score: 50, constraints: { max_operational_impact: 150 } },
    { risk_score: 50, constraints: { max_response_latency_sec: 0 } },
    {
      risk_score: 50,
      weights: {
        w_risk_reduction: 0,
        w_enforcement_cost: 0,
        w_operational_impact: 0,
        w_response_latency: 0,
        w_fp_friction: 0,
      },
    },
  ]) {
    const v = validateOptimizerInput(bad);
    assert.equal(v.valid, false, `Expected invalid for ${JSON.stringify(bad)}`);
    assert.ok(v.errors.length > 0);
  }

  // 8. Consistency / determinism
  const scenario: OptimizerScenarioInput = {
    risk_score: 79,
    confidence: 0.82,
    false_positive_likelihood: 0.18,
    identity_type: 'AWSService',
    asset_criticality: 'High',
  };
  const run1 = optimizeSecurityPolicy(scenario);
  const run2 = optimizeSecurityPolicy(scenario);
  assert.equal(run1.recommended_action.action_id, run2.recommended_action.action_id);
  assert.equal(run1.recommended_action.utility_score, run2.recommended_action.utility_score);
  assert.deepEqual(
    run1.candidates.map((c) => [c.action_id, c.utility_score, c.feasible]),
    run2.candidates.map((c) => [c.action_id, c.utility_score, c.feasible]),
  );

  // 9. Proposal builder enforces Pending Approval & Admin approval requirement
  const proposal = buildPolicyProposalFromOptimization(criticalConstrained);
  assert.equal(proposal.approval_status, 'Pending Approval');
  assert.equal(proposal.requires_admin_approval, true);
  assert.equal(selectStaticBaselineActionId(85), 'isolate_account_and_escalate');

  console.log('PASS: All 9 deterministic Policy Optimizer unit test groups passed.');
}

async function runLiveApiTests(): Promise<void> {
  const baseUrl = process.env.API_BASE_URL || 'http://127.0.0.1:3000';
  const mlUrl = process.env.ML_BASE_URL || 'http://127.0.0.1:8001';
  console.log(`Running live HTTP API, RBAC, and regression tests against ${baseUrl} and ${mlUrl}...`);

  const dirResp = await fetch(`${baseUrl}/api/auth/users-directory`);
  assert.equal(dirResp.status, 200);
  const { users } = (await dirResp.json()) as { users: Array<{ user_id: string; role: string }> };
  const admin = users.find((u) => u.role === 'Admin')!;
  const analyst = users.find((u) => u.role === 'Security Analyst')!;
  const viewer = users.find((u) => u.role === 'Viewer')!;
  assert.ok(admin && analyst && viewer);

  // GET /api/policies/optimizer
  const optOverviewResp = await fetch(`${baseUrl}/api/policies/optimizer`);
  assert.equal(optOverviewResp.status, 200);
  const optOverview = (await optOverviewResp.json()) as {
    candidate_catalog: unknown[];
    application_evaluations: Array<{ data_origin: string; auto_executed: boolean; is_estimated_cost: boolean }>;
  };
  assert.equal(optOverview.candidate_catalog.length, 5);
  assert.ok(optOverview.application_evaluations.length >= 1);
  assert.equal(optOverview.application_evaluations[0].data_origin, 'application_data');
  assert.equal(optOverview.application_evaluations[0].auto_executed, false);
  assert.equal(optOverview.application_evaluations[0].is_estimated_cost, true);

  // RBAC: Viewer denied POST /api/policies/optimize (403)
  const viewerResp = await fetch(`${baseUrl}/api/policies/optimize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CloudSentinel-UserId': viewer.user_id,
      'X-CloudSentinel-Role': viewer.role,
    },
    body: JSON.stringify({ risk_score: 75 }),
  });
  assert.equal(viewerResp.status, 403);

  // Invalid input -> 400
  const invalidResp = await fetch(`${baseUrl}/api/policies/optimize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CloudSentinel-UserId': analyst.user_id,
      'X-CloudSentinel-Role': analyst.role,
    },
    body: JSON.stringify({ risk_score: 999 }),
  });
  assert.equal(invalidResp.status, 400);

  // Analyst creates proposal -> Pending Approval (201)
  const analystCreateResp = await fetch(`${baseUrl}/api/policies/optimize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CloudSentinel-UserId': analyst.user_id,
      'X-CloudSentinel-Role': analyst.role,
    },
    body: JSON.stringify({
      risk_score: 91,
      confidence: 0.92,
      scenario_name: 'API Integration Critical Test',
      target_user_id: 'api-test-user',
      constraints: { max_enforcement_cost_usd: 180, max_operational_impact: 70 },
      create_proposal: true,
    }),
  });
  assert.equal(analystCreateResp.status, 201);
  const createdBody = (await analystCreateResp.json()) as {
    optimization: { recommended_action: { action_id: string }; approval_status: string };
    created_policy: { policy_id: string; approval_status: string };
  };
  assert.equal(createdBody.optimization.recommended_action.action_id, 'revoke_suspicious_session');
  assert.equal(createdBody.created_policy.approval_status, 'Pending Approval');

  // RBAC: Analyst cannot approve policy (403); Admin approves (200)
  const analystApproveResp = await fetch(
    `${baseUrl}/api/policies/${createdBody.created_policy.policy_id}/approve`,
    {
      method: 'POST',
      headers: {
        'X-CloudSentinel-UserId': analyst.user_id,
        'X-CloudSentinel-Role': analyst.role,
      },
    },
  );
  assert.equal(analystApproveResp.status, 403);

  const adminApproveResp = await fetch(
    `${baseUrl}/api/policies/${createdBody.created_policy.policy_id}/approve`,
    {
      method: 'POST',
      headers: {
        'X-CloudSentinel-UserId': admin.user_id,
        'X-CloudSentinel-Role': admin.role,
      },
    },
  );
  assert.equal(adminApproveResp.status, 200);
  const approvedPol = (await adminApproveResp.json()) as { policy: { approval_status: string } };
  assert.equal(approvedPol.policy.approval_status, 'Approved');

  // Existing policy, ML health, FaaS, and ML experiments regression checks
  const polResp = await fetch(`${baseUrl}/api/policies`);
  assert.equal(polResp.status, 200);
  const faasResp = await fetch(`${baseUrl}/api/faas/telemetry?dataset_id=ds-cloudtrail-train`);
  assert.equal(faasResp.status, 200);
  const mlHealthResp = await fetch(`${mlUrl}/health`);
  assert.equal(mlHealthResp.status, 200);
  const mlHealth = (await mlHealthResp.json()) as { feature_count: number; model_file: string };
  assert.equal(mlHealth.feature_count, 8);
  assert.equal(mlHealth.model_file, 'isolation_forest_cloudtrail.joblib');

  console.log('PASS: All live API, RBAC, proposal approval, and IF/FaaS regression checks passed.');
}

async function main(): Promise<void> {
  runUnitTests();
  if (process.env.RUN_LIVE_API_TESTS === '1') {
    await runLiveApiTests();
  }
}

main().catch((err) => {
  console.error('TEST FAILURE:', err);
  process.exit(1);
});
