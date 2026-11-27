import { jsPDF } from 'jspdf';
import type {
  DashboardSummary,
  MLExperimentResult,
  PolicyRecommendation,
  SecurityIncident,
  ThreatPrediction,
  UserBehaviorProfile,
} from '../types/security';

export interface ReportPayload {
  summary: DashboardSummary;
  predictions: ThreatPrediction[];
  profiles: UserBehaviorProfile[];
  incidents: SecurityIncident[];
  policies: PolicyRecommendation[];
  experiments: MLExperimentResult[];
}

export function downloadSecurityPdfReport(data: ReportPayload): void {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  let y = 48;

  const addLine = (text: string, size = 10, bold = false, color: [number, number, number] = [30, 41, 59]) => {
    if (y > 760) {
      doc.addPage();
      y = 48;
    }
    doc.setFont('helvetica', bold ? 'bold' : 'normal');
    doc.setFontSize(size);
    doc.setTextColor(color[0], color[1], color[2]);
    const lines = doc.splitTextToSize(text, 500);
    doc.text(lines, 48, y);
    y += lines.length * (size * 1.35) + 4;
  };

  addLine('CloudSentinel AI — Security & Cost-Aware Adaptive Policy Report', 16, true, [15, 23, 42]);
  addLine(`Generated: ${new Date().toISOString()} | ML Mode: ${data.summary.ml_service_label}`, 9, false, [100, 116, 139]);
  y += 8;

  addLine('1. Audit Log & Threat Overview', 12, true, [67, 56, 202]);
  addLine(
    `Total Events: ${data.summary.total_cloud_events} | Suspicious Activities: ${data.summary.suspicious_activities} | Critical Alerts: ${data.summary.critical_security_alerts} | High-Risk Users: ${data.summary.high_risk_users} | Active Incidents: ${data.summary.active_incidents}`,
  );
  y += 6;

  addLine('2. Top Detected Anomalies & Confidence Assessment', 12, true, [67, 56, 202]);
  data.predictions
    .filter((p) => p.investigation_status !== 'Normal Baseline')
    .slice(0, 8)
    .forEach((p) => {
      addLine(
        `[${p.risk_level}] ${p.cloud_user_id} — ${p.scenario} | Anomaly: ${p.anomaly_score.toFixed(
          2,
        )} | Confidence: ${p.prediction_confidence.toFixed(2)} | Risk: ${p.risk_score}/100 | Status: ${
          p.investigation_status
        }`,
        9,
      );
    });
  y += 6;

  addLine('3. User Risk Assessment Summary', 12, true, [67, 56, 202]);
  data.profiles.slice(0, 6).forEach((u) => {
    addLine(
      `${u.display_name} (${u.user_id}) — Privilege: ${u.privilege_level} | Risk Score: ${u.current_risk_score}/100 (${u.risk_level}) | Anomalies: ${u.anomaly_count}`,
      9,
    );
  });
  y += 6;

  addLine('4. Security Incidents', 12, true, [67, 56, 202]);
  data.incidents.forEach((inc) => {
    addLine(
      `${inc.incident_id} [${inc.severity} / ${inc.status}] ${inc.title} — Assigned: ${inc.assigned_to}`,
      9,
    );
  });
  y += 6;

  addLine('5. Model Evaluation Results (Actual Executed Experiments)', 12, true, [67, 56, 202]);
  data.experiments.slice(0, 4).forEach((exp) => {
    addLine(
      `${exp.model_type} (${exp.model_version}) on ${exp.dataset_name} | Accuracy: ${exp.metrics.accuracy} | Precision: ${exp.metrics.precision} | Recall: ${exp.metrics.recall} | F1: ${exp.metrics.f1_score} | FPR: ${exp.metrics.false_positive_rate} | Latency: ${exp.system_metrics.latency_ms}ms`,
      9,
    );
  });
  y += 6;

  addLine('6. Security vs Operational Cost Comparison', 12, true, [67, 56, 202]);
  addLine(
    `Current Monthly Cost: $${data.summary.cost_overview.current_monthly_cost_usd} | Recommended Cost: $${data.summary.cost_overview.recommended_monthly_cost_usd} | Residual Risk Before: ${data.summary.cost_overview.current_residual_risk} -> After: ${data.summary.cost_overview.recommended_residual_risk}`,
    9,
  );
  data.policies.forEach((pol) => {
    addLine(
      `${pol.policy_id} [${pol.approval_status}] ${pol.title} | Security Gain: +${pol.security_improvement_pct}% | Cost: $${pol.operational_cost_before_usd} -> $${pol.operational_cost_after_usd}/mo | Perf Overhead: +${pol.performance_overhead_pct}%`,
      9,
    );
  });

  doc.save(`cloudsentinel-report-${new Date().toISOString().slice(0, 10)}.pdf`);
}

export function downloadFullCsvSummary(data: ReportPayload): void {
  const rows: string[][] = [
    ['Section', 'ID', 'Identity/Model', 'Metric_Or_Scenario', 'Score_Or_Status', 'Cost_Or_Confidence', 'Notes'],
  ];

  for (const p of data.predictions) {
    rows.push([
      'AnomalyDetection',
      p.prediction_id,
      p.cloud_user_id,
      p.scenario,
      `Risk=${p.risk_score} (${p.risk_level})`,
      `Anomaly=${p.anomaly_score} / Conf=${p.prediction_confidence}`,
      p.investigation_status,
    ]);
  }
  for (const inc of data.incidents) {
    rows.push([
      'Incident',
      inc.incident_id,
      inc.affected_user,
      inc.title,
      `${inc.severity} / ${inc.status}`,
      `Risk=${inc.risk_score}`,
      inc.assigned_to,
    ]);
  }
  for (const exp of data.experiments) {
    rows.push([
      'ModelEvaluation',
      exp.experiment_id,
      exp.model_type,
      exp.dataset_name,
      `F1=${exp.metrics.f1_score} Acc=${exp.metrics.accuracy}`,
      `FPR=${exp.metrics.false_positive_rate}`,
      exp.execution_mode,
    ]);
  }
  for (const pol of data.policies) {
    rows.push([
      'PolicyOptimization',
      pol.policy_id,
      pol.target_user_id,
      pol.title,
      pol.approval_status,
      `$${pol.operational_cost_before_usd} -> $${pol.operational_cost_after_usd}`,
      `SecurityGain=+${pol.security_improvement_pct}%`,
    ]);
  }

  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `cloudsentinel-comprehensive-${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
