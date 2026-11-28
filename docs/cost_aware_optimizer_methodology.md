# Cost-Aware Adaptive Security Policy Optimization Methodology

**Module:** `src/server/policyOptimizer.ts`  
**API Endpoints:** `GET /api/policies/optimizer`, `POST /api/policies/optimize` (with human-in-the-loop approval via `/api/policies/:id/approve` and `/api/policies/:id/reject`)

---

## 1. Objective & Design Principles

Traditional cloud alerting pipelines map threat severity directly to rigid controls (for example, quarantining any account above risk score 85), ignoring enforcement cost, operational disruption, response latency, identity compatibility, and false-positive friction. In **CloudSentinel AI**, the **Cost-Aware Adaptive Security Policy Optimizer** selects an explainable response **proposal** among five configurable candidate controls subject to hard feasibility constraints.

Key safeguards enforced by design:
- **Zero Automatic Cloud Execution:** `auto_executed` is unconditionally `false`. No AWS IAM, STS, Lambda, or OpenStack resource is modified automatically; converting an optimization into a policy entry generates a `Pending Approval` proposal requiring explicit Administrator approval.
- **Estimated Units Disclosure:** Every dollar cost, disruption score, and latency figure is explicitly marked as a configurable model estimate (`is_estimated_cost = true`), not live AWS billing telemetry.
- **Data Origin Separation:** Evaluations triggered from live Express `state.incidents` or detection predictions are labeled `application_data`, whereas synthetic or preset test cases are labeled `simulated_scenario`.

---

## 2. Candidate Action Catalog & Configurable Units

| Action ID | Action Label | Base Effectiveness ($\eta_a$) | Est. Enforcement Cost ($C_a$, USD / incident-window) | Base Operational Impact ($I_a$, 0–100) | Est. Response Latency ($L_a$, sec) | FP Friction Factor ($\phi_a$) |
|---|---|---:|---:|---:|---:|---:|
| `monitor_and_alert` | Monitor and alert | `0.22` | `$18` | `5` | `1.5` | `0.05` |
| `require_additional_mfa` | Require additional MFA | `0.56` | `$45` | `22` | `4.0` | `0.25` |
| `temporarily_restrict_permissions` | Temporarily restrict permissions | `0.74` | `$95` | `48` | `12.0` | `0.45` |
| `revoke_suspicious_session` | Revoke suspicious session | `0.85` | `$140` | `64` | `3.5` | `0.65` |
| `isolate_account_and_escalate` | Isolate account and escalate to administrator | `0.94` | `$260` | `88` | `8.0` | `0.90` |

### Unit Assumptions
1. **Estimated Enforcement Cost (`$ USD / incident-window`):** Estimated engineering/operational compute and triage effort per incident containment window (SIEM log elevation `$18`, IdP challenge `$45`, temporary IAM scope policy lifecycle `$95`, active token revocation and job replay `$140`, full account quarantine & administrator incident recovery `$260`). Not live AWS Billing / Cost Explorer data.
2. **Operational Impact (`0–100`):** Normalized workflow disruption scale (`0` = zero interruption; `100` = complete service halt).
3. **Response Latency (`seconds`):** Estimated control-plane propagation delay from policy approval/trigger to enforcement readiness (`1.5s` alerting pipeline up to `12.0s` scoped IAM policy propagation).

---

## 3. Mathematical Formulation

Given a validated scenario input:
- Base threat risk score $R_0 \in [0, 100]$, prediction confidence $c \in [0, 1]$ (default `0.75`), false-positive likelihood $p_{\text{fp}} \in [0, 1]$ (default $\text{clamp}(1 - c, 0.05, 0.85)$), identity type, asset criticality multiplier $m_{\text{asset}} \in \{0.90, 1.00, 1.12, 1.22\}$ (`Low`, `Medium`, `High`, `Critical`), hard constraints $(C_{\max}, I_{\max}, L_{\max})$, and nonnegative objective weights normalized to sum to 1:
  $$w = (w_{\text{risk}} = 0.54,\; w_{\text{cost}} = 0.16,\; w_{\text{impact}} = 0.14,\; w_{\text{latency}} = 0.04,\; w_{\text{fp}} = 0.12)$$

### 3.1 Effective Risk, Risk Reduction & Residual Risk
$$R_{\text{eff}} = \min(100, R_0 \cdot m_{\text{asset}})$$
$$\eta_a^{\text{eff}} = \eta_a \cdot (0.85 + 0.15 c) + \delta_{\text{identity}}(a, \text{identity})$$
where non-interactive service identities (`AWSService`, `ServicePrincipal`) incur an automated-identity MFA applicability reduction ($\delta = -0.22$ effectiveness and $+14$ operational impact on `require_additional_mfa`, and $+8$ operational impact on `isolate_account_and_escalate`).

$$\Delta R_a = R_{\text{eff}} \cdot \eta_a^{\text{eff}}, \qquad R^{\text{res}}_a = \max(0, R_{\text{eff}} - \Delta R_a)$$

### 3.2 False-Positive Friction
$$F_a = \text{clamp}\left(100 \cdot \phi_a \cdot p_{\text{fp}} \cdot \left(1.2 - 0.35 \cdot \frac{R_{\text{eff}}}{100}\right),\; 0,\; 100\right)$$
Intrusive controls incur steep friction penalties whenever detection confidence is low or $p_{\text{fp}}$ is high, avoiding lockouts on noisy moderate-risk alerts.

### 3.3 Hard Constraint Feasibility
An action $a$ is marked **feasible** if and only if:
$$C_a \le C_{\max}, \quad I_a \le I_{\max}, \quad L_a \le L_{\max}$$
Any violated constraint is recorded verbatim in `constraint_violations`. If zero candidates satisfy strict constraints (`feasible_action_found = false`), the optimizer surfaces the lowest-cost passive fallback (`monitor_and_alert`) with `constraint_status = "No Feasible Action Under Strict Constraints"` rather than hiding the violation.

### 3.4 Multi-Objective Utility Score
Normalizing cost against $C_{\text{ref}} = \max(\max_a C_a, 260)$, latency against $L_{\text{ref}} = \max(L_{\max}, \max_a L_a, 30)$, and disruption/friction against `100`, convex disruption cost is subtracted from scaled risk reduction:
$$D_a = w_{\text{cost}}\left(\frac{C_a}{C_{\text{ref}}}\right)^{1.15} + w_{\text{impact}}\left(\frac{I_a}{100}\right)^{1.45} + w_{\text{latency}}\left(\frac{L_a}{L_{\text{ref}}}\right) + w_{\text{fp}}\left(\frac{F_a}{100}\right)^{1.1}$$
$$U_a = \text{clamp}\left(\frac{1.32\,w_{\text{risk}}\,(\Delta R_a / 100) - D_a + 1.0}{2.32},\; 0,\; 1\right)$$

The optimizer selects the **feasible action maximizing $U_a$** (breaking exact ties by lower estimated enforcement cost).

---

## 4. Comparison Against Static Severity Baseline

For every evaluated scenario, the optimizer computes the legacy static rule-based selection (`selectStaticBaselineActionId`):
- `risk_score < 30` $\rightarrow$ `monitor_and_alert`
- `30 <= risk_score < 60` $\rightarrow$ `require_additional_mfa`
- `60 <= risk_score < 85` $\rightarrow$ `temporarily_restrict_permissions`
- `risk_score >= 85` $\rightarrow$ `isolate_account_and_escalate`

Because the static rule ignores cost ceilings, operational impact bounds, service-account MFA compatibility, and false-positive probability, it frequently proposes infeasible or unnecessarily disruptive actions (e.g., `$260` full isolation with `88/100` impact under a `$180` cost cap and `70/100` impact cap), which the side-by-side comparison table highlights explicitly.

---

## 5. Input Validation & RBAC Safeguards

- `validateOptimizerInput()` enforces `risk_score` $\in [0, 100]$, finite numeric ranges for `confidence` and `false_positive_likelihood` $\in [0, 1]$, non-negative `max_enforcement_cost_usd`, `max_operational_impact` $\in [0, 100]$, positive `max_response_latency_sec`, valid `identity_type` and `asset_criticality` enums, and positive sum of objective weights—returning HTTP `400` on invalid input.
- `POST /api/policies/optimize` is gated by `requireRole(['Admin', 'Security Analyst'])` (`Viewer` receives HTTP `403`), while policy proposal approval (`/api/policies/:id/approve`) remains restricted exclusively to `Admin`.
