"""
Risk Assessment Engine for Cloud Audit Log Events.
Combines ML anomaly scores with domain heuristics:
- Off-hours penalty
- Resource sensitivity
- High-risk administrative actions
- Repeated authentication or permission failures
"""

from typing import Dict, Any, Tuple

class RiskEngine:
    """
    Transparent risk scoring formula:
    RiskScore = 0.40 * ML_Score + 0.25 * ActionRisk + 0.20 * ResourceSensitivity + 0.10 * OffHours + 0.05 * Failure
    """

    @staticmethod
    def calculate_risk(
        ml_score: float,
        action_risk: float,
        resource_sensitivity: float,
        is_off_hours: bool,
        is_failure: bool,
        action_name: str,
        resource_name: str,
        timestamp_str: str
    ) -> Tuple[float, str, str, str]:
        off_hours_val = 1.0 if is_off_hours else 0.0
        failure_val = 1.0 if is_failure else 0.0

        raw_score = (
            0.40 * ml_score +
            0.25 * action_risk +
            0.20 * resource_sensitivity +
            0.10 * off_hours_val +
            0.05 * failure_val
        )
        final_risk = round(float(min(max(raw_score, 0.0), 1.0)), 3)

        # Risk Classification
        if final_risk >= 0.70:
            risk_level = "High Risk"
        elif final_risk >= 0.40:
            risk_level = "Medium Risk"
        else:
            risk_level = "Normal"

        # Generate transparent diagnostic reasoning
        reasons = []
        if ml_score > 0.65:
            reasons.append(f"Elevated ML anomaly score ({ml_score:.2f}) deviates significantly from learned user baseline")
        if is_off_hours:
            reasons.append(f"Accessed outside designated corporate working hours ({timestamp_str})")
        if action_risk >= 0.80:
            reasons.append(f"High-impact administrative/data operation '{action_name}' executed")
        if resource_sensitivity >= 0.80:
            reasons.append(f"Target resource '{resource_name}' is classified as critical enterprise tier")
        if is_failure:
            reasons.append("Unsuccessful operation or permission denial triggered")

        if not reasons:
            flag_reason = "Nominal operational telemetry consistent with role profile."
        else:
            flag_reason = " | ".join(reasons)

        # Recommended immediate security posture action
        if risk_level == "High Risk":
            recommended_action = "Escalate to SOC Tier-2, initiate step-up MFA, and review IAM policy bindings."
        elif risk_level == "Medium Risk":
            recommended_action = "Generate security warning event, log anomaly in audit register, and monitor session."
        else:
            recommended_action = "Standard telemetry archive. No intervention required."

        return final_risk, risk_level, flag_reason, recommended_action
