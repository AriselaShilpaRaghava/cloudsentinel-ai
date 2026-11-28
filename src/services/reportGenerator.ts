import { jsPDF } from 'jspdf';
import type {
  DashboardSummary,
  DatasetRecord,
  MLExperimentResult,
  PolicyRecommendation,
  SecurityIncident,
  ThreatPrediction,
  UserBehaviorProfile,
} from '../types/security.ts';

export interface ReportPayload {
  summary: DashboardSummary;
  predictions: ThreatPrediction[];
  profiles: UserBehaviorProfile[];
  incidents: SecurityIncident[];
  policies: PolicyRecommendation[];
  experiments: MLExperimentResult[];
  datasets?: DatasetRecord[];
}

export function buildSecurityPdfArrayBuffer(data: ReportPayload): ArrayBuffer {
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  let y = 48;

  const addLine = (
    text: string,
    size = 10,
    bold = false,
    color: [number, number, number] = [30, 41, 59],
  ) => {
    if (y > 760) {
      doc.addPage();
      y = 48;
    }
    doc.setFont('helvetica', bold ? 'bold' : 'normal');
    doc.setFontSize(size);
    doc.setTextColor(color[0], color[1], color[2]);
    const lines = doc.splitTextToSize(text, 500) as string[];
    doc.text(lines, 48, y);
    y += lines.length * (size * 1.35) + 4;
  };

  addLine('CloudSentinel AI - Security & Cost-Aware Adaptive Policy Report', 16, true, [15, 23, 42]);
  addLine(
    `Generated: ${new Date().toISOString()} | ML Mode: ${data.summary.ml_service_label}`,
    9,
    false,
    [100, 116, 139],
  );
  y += 8;

  addLine('1. Audit Log & Threat Overview', 12, true, [67, 56, 202]);
  addLine(
    `Total Events: ${data.summary.total_cloud_events} | Suspicious Activities: ${data.summary.suspicious_activities} | Critical Alerts: ${data.summary.critical_security_alerts} | High-Risk Users: ${data.summary.high_risk_users} | Active Incidents: ${data.summary.active_incidents} | Pending Policy Approvals: ${data.summary.pending_policy_approvals}`,
  );
  y += 6;

  if (data.datasets && data.datasets.length > 0) {
    addLine('2. Registered Datasets', 12, true, [67, 56, 202]);
    data.datasets.forEach((ds) => {
      const roleStr = ds.dataset_role ? ` [${ds.dataset_role}]` : '';
      const labelStr =
        ds.benign_count !== undefined && ds.attack_count !== undefined
          ? ` | Labels: ${ds.benign_count} benign, ${ds.attack_count} attack`
          : '';
      addLine(
        `${ds.name}${roleStr} (${ds.dataset_id}) - Normalized: ${ds.normalized_rows ?? ds.valid_rows}/${ds.total_rows} | Skipped: ${ds.skipped_rows ?? ds.duplicate_count}${labelStr}`,
        9,
      );
    });
    y += 6;
  }

  addLine('3. Top Detected Anomalies & Confidence Assessment', 12, true, [67, 56, 202]);
  const flagged = data.predictions.filter((p) => p.investigation_status !== 'Normal Baseline');
  if (flagged.length === 0) {
    addLine('No anomalous events currently flagged.', 9);
  } else {
    flagged.slice(0, 10).forEach((p) => {
      addLine(
        `[${p.risk_level}] ${p.cloud_user_id} - ${p.scenario} | Anomaly: ${p.anomaly_score.toFixed(
          2,
        )} | Confidence: ${p.prediction_confidence.toFixed(2)} | Risk: ${p.risk_score}/100 | Status: ${
          p.investigation_status
        }`,
        9,
      );
    });
  }
  y += 6;

  addLine('4. User Risk Assessment Summary', 12, true, [67, 56, 202]);
  data.profiles.slice(0, 8).forEach((u) => {
    addLine(
      `${u.display_name} (${u.user_id}) - Privilege: ${u.privilege_level} | Risk Score: ${u.current_risk_score}/100 (${u.risk_level}) | Anomalies: ${u.anomaly_count}`,
      9,
    );
  });
  y += 6;

  addLine('5. Security Incidents', 12, true, [67, 56, 202]);
  if (data.incidents.length === 0) {
    addLine('No security incidents recorded.', 9);
  } else {
    data.incidents.forEach((inc) => {
      addLine(
        `${inc.incident_id} [${inc.severity} / ${inc.status}] ${inc.title} - Assigned: ${inc.assigned_to} | Risk: ${inc.risk_score}/100`,
        9,
      );
      if (inc.summary) {
        addLine(`Summary: ${inc.summary}`, 8, false, [71, 85, 105]);
      }
    });
  }
  y += 6;

  addLine('6. Model Evaluation Results (Executed Experiments)', 12, true, [67, 56, 202]);
  if (data.experiments.length === 0) {
    addLine('No model evaluation experiments executed yet.', 9);
  } else {
    data.experiments.slice(0, 5).forEach((exp) => {
      const gtLabel = exp.has_ground_truth === false ? 'N/A (unlabeled)' : null;
      const accStr = gtLabel ?? `${(exp.metrics.accuracy * 100).toFixed(1)}%`;
      const precStr = gtLabel ?? `${(exp.metrics.precision * 100).toFixed(1)}%`;
      const recStr = gtLabel ?? `${(exp.metrics.recall * 100).toFixed(1)}%`;
      const f1Str = gtLabel ?? `${(exp.metrics.f1_score * 100).toFixed(1)}%`;
      const aucStr = gtLabel ?? `${(exp.metrics.roc_auc * 100).toFixed(1)}%`;
      const simTag = exp.is_simulated ? ' [SIMULATED FALLBACK]' : '';
      addLine(
        `${exp.model_type} (${exp.model_version})${simTag} on ${exp.dataset_name} (Train=${exp.train_size}, Test=${exp.test_size}) | Acc: ${accStr} | Prec: ${precStr} | Rec: ${recStr} | F1: ${f1Str} | FPR: ${(exp.metrics.false_positive_rate * 100).toFixed(1)}% | ROC AUC: ${aucStr} | CM(TP/FP/TN/FN): ${exp.confusion_matrix.tp}/${exp.confusion_matrix.fp}/${exp.confusion_matrix.tn}/${exp.confusion_matrix.fn} | Latency: ${exp.system_metrics.latency_ms}ms`,
        9,
      );
    });
  }
  y += 6;

  addLine('7. Security vs Operational Cost Comparison', 12, true, [67, 56, 202]);
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

  return doc.output('arraybuffer');
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
