import type { CloudProvider, NormalizedAuditEvent } from '../types/security.ts';

export interface NormalizationResult {
  events: NormalizedAuditEvent[];
  total_rows: number;
  valid_rows: number;
  missing_value_count: number;
  duplicate_count: number;
  adapted_faas_count: number;
  original_records_count: number;
  errors: string[];
}

function normalizeProvider(rawProvider: string | undefined, rawObj: Record<string, unknown>): CloudProvider {
  const p = String(rawProvider || rawObj.eventSource || rawObj.service || '').toLowerCase();
  if (p.includes('lambda') || p.includes('faas')) return 'AWS Lambda';
  if (p.includes('iam')) return 'AWS IAM';
  if (p.includes('keystone')) return 'OpenStack Keystone';
  if (p.includes('nova')) return 'OpenStack Nova';
  if (p.includes('cert')) return 'CERT Mapped';
  return 'AWS CloudTrail';
}

function normalizeStatus(rawStatus: unknown): 'Success' | 'Failed' | 'Denied' {
  const s = String(rawStatus || 'Success').toLowerCase();
  if (s.includes('fail') || s.includes('error')) return 'Failed';
  if (s.includes('deny') || s.includes('denied') || s.includes('forbid')) return 'Denied';
  return 'Success';
}

function parseCsvRows(csvText: string): Array<Record<string, string>> {
  const lines = csvText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length < 2) return [];

  const splitLine = (line: string): string[] => {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        inQuotes = !inQuotes;
      } else if (ch === ',' && !inQuotes) {
        result.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    result.push(current.trim());
    return result;
  };

  const headers = splitLine(lines[0]).map((h) => h.replace(/^"|"$/g, '').trim());
  const rows: Array<Record<string, string>> = [];

  for (let i = 1; i < lines.length; i++) {
    const vals = splitLine(lines[i]);
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = (vals[idx] ?? '').replace(/^"|"$/g, '').trim();
    });
    rows.push(row);
  }
  return rows;
}

export function validateAndNormalizeUpload(
  content: string,
  format: 'CSV' | 'JSON',
  sourceLabel: string,
  existingIds: Set<string>,
): NormalizationResult {
  let rawRecords: Array<Record<string, unknown>> = [];
  const errors: string[] = [];

  if (format === 'JSON') {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed)) {
      rawRecords = parsed;
    } else if (parsed && Array.isArray(parsed.Records)) {
      // AWS CloudTrail native export format
      rawRecords = parsed.Records;
    } else if (parsed && Array.isArray(parsed.events)) {
      rawRecords = parsed.events;
    } else if (parsed && typeof parsed === 'object') {
      rawRecords = [parsed];
    } else {
      throw new Error('JSON upload must be an array of audit objects or CloudTrail { Records: [...] }');
    }
  } else {
    rawRecords = parseCsvRows(content);
    if (rawRecords.length === 0) {
      throw new Error('CSV upload requires a header row and at least one data row.');
    }
  }

  let missing_value_count = 0;
  let duplicate_count = 0;
  let adapted_faas_count = 0;
  let original_records_count = 0;
  const seenInBatch = new Set<string>();
  const events: NormalizedAuditEvent[] = [];

  rawRecords.forEach((rec, index) => {
    // Support both normalized schema and AWS CloudTrail / OpenStack native field names
    const userIdentity = rec.userIdentity as Record<string, unknown> | undefined;
    const event_id = String(
      rec.event_id || rec.eventID || rec.id || `upl-${Date.now().toString(36)}-${index + 1}`,
    ).trim();

    if (existingIds.has(event_id) || seenInBatch.has(event_id)) {
      duplicate_count += 1;
      return;
    }
    seenInBatch.add(event_id);

    const cloud_user_id = String(
      rec.cloud_user_id ||
        rec.user ||
        rec.username ||
        userIdentity?.userName ||
        userIdentity?.arn ||
        rec.actor_id ||
        '',
    ).trim();

    const action = String(rec.action || rec.eventName || rec.method || rec.activity || '').trim();
    const resource = String(
      rec.resource ||
        rec.target ||
        rec.resourceName ||
        (Array.isArray(rec.resources) && rec.resources[0] ? JSON.stringify(rec.resources[0]) : '') ||
        '',
    ).trim();

    const source_ip = String(rec.source_ip || rec.sourceIPAddress || rec.ip || rec.client_ip || '').trim();
    const event_time = String(rec.event_time || rec.eventTime || rec.timestamp || rec.date || '').trim();

    let rowMissing = 0;
    if (!cloud_user_id) rowMissing += 1;
    if (!action) rowMissing += 1;
    if (!resource) rowMissing += 1;
    if (!source_ip) rowMissing += 1;
    if (!event_time) rowMissing += 1;

    missing_value_count += rowMissing;

    if (!cloud_user_id || !action) {
      errors.push(`Row ${index + 1} skipped: missing required user or action field.`);
      return;
    }

    const parsedDate = event_time ? new Date(event_time) : new Date();
    const isoTime = Number.isNaN(parsedDate.getTime()) ? new Date().toISOString() : parsedDate.toISOString();

    const provider = normalizeProvider(rec.provider as string | undefined, rec);
    if (provider === 'AWS Lambda') adapted_faas_count += 1;
    else original_records_count += 1;

    const gtRaw = rec.ground_truth_label ?? rec.is_insider ?? rec.label;
    const ground_truth_label =
      gtRaw === 1 || gtRaw === '1' || gtRaw === true || String(gtRaw).toLowerCase() === 'anomaly'
        ? (1 as const)
        : gtRaw === 0 || gtRaw === '0' || gtRaw === false || String(gtRaw).toLowerCase() === 'normal'
          ? (0 as const)
          : undefined;

    events.push({
      event_id,
      provider,
      event_time: isoTime,
      cloud_user_id,
      action,
      resource: resource || 'unspecified-resource',
      source_ip: source_ip || '0.0.0.0',
      status: normalizeStatus(rec.status || rec.outcome || rec.errorCode),
      raw_event: rec,
      is_simulated: Boolean(rec.is_simulated ?? false),
      dataset_source: sourceLabel,
      ground_truth_label,
    });
  });

  return {
    events,
    total_rows: rawRecords.length,
    valid_rows: events.length,
    missing_value_count,
    duplicate_count,
    adapted_faas_count,
    original_records_count,
    errors,
  };
}
