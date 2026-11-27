"""
Cost-Aware Adaptive Security Policy Optimization Engine.
Evaluates candidate security policies against risk levels, balancing:
- Security Benefit (risk reduction capability)
- Estimated Financial/Operational Cost ($ USD)
- Performance & Latency Overhead (%)
- User Friction / Workflow Disruption

Objective Function:
Utility = (Weight_Security * SecurityBenefit) - (Weight_Cost * CostPenalty) - (Weight_Perf * OverheadPenalty) - (Weight_Alignment * DistanceToRisk)
"""

from typing import Dict, Any, List

CANDIDATE_POLICIES = [
    {
        "id": "POL_ALERT",
        "name": "Generate SOC Advisory Alert",
        "target_risk_range": (0.0, 0.45),
        "security_benefit_score": 0.40,
        "security_benefit_desc": "Maintains visibility and creates SIEM log record without blocking user.",
        "estimated_cost_usd": 0.05,
        "performance_overhead_pct": 0.5,
        "action_type": "Advisory",
        "recommended_for": "Low to Mild Risk"
    },
    {
        "id": "POL_STEPUP_MFA",
        "name": "Require Step-Up MFA Challenge",
        "target_risk_range": (0.45, 0.70),
        "security_benefit_score": 0.75,
        "security_benefit_desc": "Confirms user identity before proceeding; prevents credential-hijacking.",
        "estimated_cost_usd": 0.20,
        "performance_overhead_pct": 3.0,
        "action_type": "Identity Challenge",
        "recommended_for": "Medium Risk"
    },
    {
        "id": "POL_IAM_AUDIT",
        "name": "Initiate Least-Privilege IAM Audit",
        "target_risk_range": (0.55, 0.80),
        "security_benefit_score": 0.82,
        "security_benefit_desc": "Queues IAM role permissions and token scopes for automated security compliance check.",
        "estimated_cost_usd": 0.65,
        "performance_overhead_pct": 6.5,
        "action_type": "Access Review",
        "recommended_for": "Medium to High Risk"
    },
    {
        "id": "POL_TEMP_RESTRICT",
        "name": "Temporarily Restrict Sensitive Operation",
        "target_risk_range": (0.70, 0.90),
        "security_benefit_score": 0.92,
        "security_benefit_desc": "Selectively locks only the target sensitive API method (e.g., bulk download / export keys) while preserving normal work.",
        "estimated_cost_usd": 1.20,
        "performance_overhead_pct": 10.0,
        "action_type": "Selective Containment",
        "recommended_for": "High Risk"
    },
    {
        "id": "POL_SOC_ESCALATE",
        "name": "Escalate Priority Incident to SecOps Lead",
        "target_risk_range": (0.85, 1.00),
        "security_benefit_score": 0.98,
        "security_benefit_desc": "Dispatches high-urgency ticket to senior on-call engineer and triggers forensic snapshot.",
        "estimated_cost_usd": 3.50,
        "performance_overhead_pct": 18.0,
        "action_type": "Incident Escalation",
        "recommended_for": "Critical Risk"
    }
]

class PolicyOptimizer:
    def __init__(
        self,
        weight_security: float = 0.50,
        weight_cost: float = 0.20,
        weight_perf: float = 0.15,
        weight_alignment: float = 0.15
    ):
        self.w_sec = weight_security
        self.w_cost = weight_cost
        self.w_perf = weight_perf
        self.w_align = weight_alignment

    def optimize(self, current_risk: float, user_id: str, flag_reason: str) -> Dict[str, Any]:
        """
        Calculates utility scores for each candidate policy and selects the optimal trade-off.
        """
        scored_options = []
        for policy in CANDIDATE_POLICIES:
            # Normalized cost (scale $0 to $5)
            norm_cost = min(policy["estimated_cost_usd"] / 5.0, 1.0)
            # Normalized overhead (scale 0% to 25%)
            norm_overhead = min(policy["performance_overhead_pct"] / 25.0, 1.0)

            # Alignment distance between current risk and policy security capability
            alignment_distance = abs(current_risk - policy["security_benefit_score"])

            # Utility calculation
            utility = (
                self.w_sec * policy["security_benefit_score"]
                - self.w_cost * norm_cost
                - self.w_perf * norm_overhead
                - self.w_align * alignment_distance
            )

            scored_options.append({
                "policy_id": policy["id"],
                "policy_name": policy["name"],
                "security_benefit": policy["security_benefit_desc"],
                "security_benefit_score": policy["security_benefit_score"],
                "estimated_cost_usd": policy["estimated_cost_usd"],
                "performance_overhead_pct": policy["performance_overhead_pct"],
                "action_type": policy["action_type"],
                "score": round(float(utility), 4)
            })

        # Sort descending by utility
        scored_options.sort(key=lambda x: x["score"], reverse=True)
        recommended = scored_options[0]

        reason_text = (
            f"Based on evaluated risk score ({current_risk:.2f}), '{recommended['policy_name']}' provides "
            f"the optimal equilibrium between security risk reduction ({recommended['security_benefit_score']*100:.0f}%), "
            f"minimal operational cost (${recommended['estimated_cost_usd']:.2f} USD), and non-disruptive performance overhead "
            f"({recommended['performance_overhead_pct']:.1f}%). Requires human security operator approval prior to enforcement."
        )

        return {
            "user_id": user_id,
            "current_risk_score": current_risk,
            "recommended_policy": recommended["policy_name"],
            "security_benefit": recommended["security_benefit"],
            "estimated_cost_usd": recommended["estimated_cost_usd"],
            "performance_overhead_pct": recommended["performance_overhead_pct"],
            "reason": reason_text,
            "candidate_options": scored_options
        }
