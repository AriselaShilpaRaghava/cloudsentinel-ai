import type { CloudProvider, IngestionSummary, NormalizedAuditEvent } from '../types/security.ts';

export interface NormalizationResult extends IngestionSummary {
  events: NormalizedAuditEvent[];
}

export interface NormalizationOptions {
  datasetId?: string;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function firstNonEmptyString(...values: unknown[]): string {
  for (const v of values) {
    if (typeof v === 'string' && v.trim()) return v.trim();
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  }
  return '';
}

function normalizeProvider(rawProvider: string | undefined, rawObj: Record<string, unknown>): CloudProvider {
  const p = String(rawProvider || rawObj.eventSource || rawObj.service || '').toLowerCase();
  if (p.includes('lambda') || p.includes('faas')) return 'AWS Lambda';
  if (p.includes('iam')) return 'AWS IAM';
  if (p.includes('keystone')) return 'OpenStack Keystone';
  if (p.includes('nova')) return 'OpenStack Nova';
  if (p.includes('neutron')) return 'OpenStack Neutron';
  if (p.includes('glance')) return 'OpenStack Glance';
  if (p.includes('cinder')) return 'OpenStack Cinder';
  if (p.includes('openstack')) return 'OpenStack Audit';
  if (p.includes('cert')) return 'CERT Mapped';
  return 'AWS CloudTrail';
}

function normalizeStatus(rawStatus: unknown, rawObj: Record<string, unknown>): 'Success' | 'Failed' | 'Denied' {
  const explicit = firstNonEmptyString(rawStatus);
  if (explicit) {
    const s = explicit.toLowerCase();
    if (s.includes('deny') || s.includes('denied') || s.includes('forbid') || s.includes('unauth')) {
      return 'Denied';
    }
    if (s.includes('fail') || s.includes('error')) {
      return 'Failed';
    }
    return 'Success';
  }

  const errorCode = firstNonEmptyString(rawObj.errorCode);
  const errorMessage = firstNonEmptyString(rawObj.errorMessage);
  const combinedError = `${errorCode} ${errorMessage}`.toLowerCase();
  if (
    combinedError.includes('accessdenied') ||
    combinedError.includes('unauthorized') ||
    combinedError.includes('forbidden') ||
    combinedError.includes('denied')
  ) {
    return 'Denied';
  }
  if (errorCode || errorMessage) {
    return 'Failed';
  }
  return 'Success';
}

function extractCloudTrailIdentity(
  rec: Record<string, unknown>,
  userIdentity: Record<string, unknown> | undefined,
): { cloud_user_id: string; identity_type: string; hadExplicitIdentityField: boolean } {
  const flatUser = firstNonEmptyString(
    rec.cloud_user_id,
    rec.user,
    rec.username,
    rec.actor_id,
    rec.user_id,
  );
  if (flatUser) {
    return {
      cloud_user_id: flatUser,
      identity_type: firstNonEmptyString(rec.identity_type, userIdentity?.type) || 'Explicit',
      hadExplicitIdentityField: true,
    };
  }

  const isCloudTrailLike = Boolean(
    rec.eventVersion !== undefined ||
      rec.eventSource !== undefined ||
      rec.awsRegion !== undefined ||
      rec.eventName !== undefined ||
      userIdentity !== undefined,
  );

  if (userIdentity) {
    const rawType = firstNonEmptyString(userIdentity.type);
    const sessionContext = asRecord(userIdentity.sessionContext);
    const sessionIssuer = asRecord(sessionContext?.sessionIssuer);

    const resolved = firstNonEmptyString(
      userIdentity.userName,
      userIdentity.arn,
      sessionIssuer?.userName,
      sessionIssuer?.arn,
      userIdentity.invokedBy,
      userIdentity.principalId,
    );

    if (resolved) {
      const inferredType =
        rawType ||
        (userIdentity.invokedBy ? 'AWSService' : userIdentity.accountId ? 'AWSAccount' : 'Unknown');
      return {
        cloud_user_id: resolved,
        identity_type: inferredType,
        hadExplicitIdentityField: true,
      };
    }

    const accountId = firstNonEmptyString(userIdentity.accountId);
    if (accountId) {
      return {
        cloud_user_id: `aws-account:${accountId}`,
        identity_type: rawType || 'AWSAccount',
        hadExplicitIdentityField: true,
      };
    }

    if (isCloudTrailLike) {
      return {
        cloud_user_id: 'anonymous-caller',
        identity_type: rawType || 'Anonymous',
        hadExplicitIdentityField: false,
      };
    }
  }

  if (isCloudTrailLike) {
    return {
      cloud_user_id: 'anonymous-caller',
      identity_type: 'Anonymous',
      hadExplicitIdentityField: false,
    };
  }

  return {
    cloud_user_id: '',
    identity_type: 'Missing',
    hadExplicitIdentityField: false,
  };
}

function extractResource(rec: Record<string, unknown>): string {
  const direct = firstNonEmptyString(rec.resource, rec.target, rec.resourceName);
  if (direct) return direct;

  if (Array.isArray(rec.resources) && rec.resources.length > 0) {
    const parts: string[] = [];
    for (const item of rec.resources) {
      if (typeof item === 'string' && item.trim()) {
        parts.push(item.trim());
      } else {
        const obj = asRecord(item);
        const arnOrType = firstNonEmptyString(obj?.ARN, obj?.arn, obj?.type, obj?.accountId);
        if (arnOrType) parts.push(arnOrType);
      }
    }
    if (parts.length > 0) return parts.join(' | ');
  }

  const reqParams = asRecord(rec.requestParameters);
  if (reqParams) {
    const bucket = firstNonEmptyString(reqParams.bucketName);
    const key = firstNonEmptyString(reqParams.key);
    if (bucket && key) return `arn:aws:s3:::${bucket}/${key}`;
    if (bucket) return `arn:aws:s3:::${bucket}`;

    const paramResource = firstNonEmptyString(
      reqParams.roleArn,
      reqParams.functionName,
      reqParams.userName,
      reqParams.policyArn,
      reqParams.instanceId,
      reqParams.groupId,
      reqParams.tableName,
    );
    if (paramResource) return paramResource;
  }

  const eventSource = firstNonEmptyString(rec.eventSource);
  if (eventSource) return eventSource;

  return '';
}

function extractGroundTruthLabel(rec: Record<string, unknown>): 0 | 1 | undefined {
  const gtRaw =
    rec.ground_truth_label ?? rec.is_insider ?? rec.label ?? rec.should_sample;
  if (gtRaw === undefined || gtRaw === null || gtRaw === '') return undefined;

  if (gtRaw === 1 || gtRaw === '1' || gtRaw === true) return 1;
  if (gtRaw === 0 || gtRaw === '0' || gtRaw === false) return 0;

  const str = String(gtRaw).trim().toLowerCase();
  if (str === 'true' || str === 'anomaly' || str === 'attack' || str === 'malicious') return 1;
  if (str === 'false' || str === 'normal' || str === 'benign') return 0;
  return undefined;
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

function parseJsonRecords(content: string): unknown[] {
  const trimmed = content.trim();
  if (!trimmed) {
    throw new Error('JSON upload is empty.');
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed;
    const obj = asRecord(parsed);
    if (obj && Array.isArray(obj.Records)) return obj.Records;
    if (obj && Array.isArray(obj.events)) return obj.events;
    if (obj) return [obj];
  } catch (err) {
    // Support newline-delimited JSON (NDJSON) when single JSON.parse fails
    const lines = trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (lines.length > 1) {
      const ndjsonRecords: unknown[] = [];
      let ndjsonOk = true;
      for (const line of lines) {
        try {
          ndjsonRecords.push(JSON.parse(line));
        } catch {
          ndjsonOk = false;
          break;
        }
      }
      if (ndjsonOk && ndjsonRecords.length > 0) return ndjsonRecords;
    }
    throw err;
  }

  throw new Error('JSON upload must be an array of audit objects or CloudTrail { Records: [...] }');
}

export function validateAndNormalizeUpload(
  content: string,
  format: 'CSV' | 'JSON',
  sourceLabel: string,
  existingIds: Set<string>,
  options: NormalizationOptions = {},
): NormalizationResult {
  let rawRecords: unknown[] = [];
  const errors: string[] = [];

  if (format === 'JSON') {
    rawRecords = parseJsonRecords(content);
  } else {
    rawRecords = parseCsvRows(content);
    if (rawRecords.length === 0) {
      throw new Error('CSV upload requires a header row and at least one data row.');
    }
  }

  let missing_value_count = 0;
  let duplicate_count = 0;
  let already_exists_count = 0;
  let rejected_rows = 0;
  let adapted_faas_count = 0;
  let original_records_count = 0;

  let benign_count = 0;
  let attack_count = 0;
  let unlabeled_count = 0;
  let raw_benign_count = 0;
  let raw_attack_count = 0;
  let raw_unlabeled_count = 0;

  const rejectionReasonCounts = new Map<string, number>();
  const skipReasonCounts = new Map<string, number>();

  const bumpReason = (map: Map<string, number>, reason: string) => {
    map.set(reason, (map.get(reason) || 0) + 1);
  };

  const seenInBatch = new Set<string>();
  const events: NormalizedAuditEvent[] = [];
  const batchSeed = Date.now().toString(36);

  rawRecords.forEach((rawItem, index) => {
    const rec = asRecord(rawItem);
    if (!rec) {
      rejected_rows += 1;
      bumpReason(rejectionReasonCounts, 'Non-object record payload');
      if (errors.length < 25) {
        errors.push(`Row ${index + 1} rejected: record is not a JSON/CSV object.`);
      }
      return;
    }

    const rawLabel = extractGroundTruthLabel(rec);
    if (rawLabel === 1) raw_attack_count += 1;
    else if (rawLabel === 0) raw_benign_count += 1;
    else raw_unlabeled_count += 1;

    const event_id = firstNonEmptyString(
      rec.event_id,
      rec.eventID,
      rec.id,
      `upl-${batchSeed}-${index + 1}`,
    );

    if (seenInBatch.has(event_id)) {
      duplicate_count += 1;
      bumpReason(skipReasonCounts, 'Duplicate event_id/eventID within source batch');
      return;
    }
    if (existingIds.has(event_id)) {
      already_exists_count += 1;
      bumpReason(skipReasonCounts, 'Event ID already exists in stored event pool');
      return;
    }
    seenInBatch.add(event_id);

    const userIdentity = asRecord(rec.userIdentity);
    const identity = extractCloudTrailIdentity(rec, userIdentity);
    const action = firstNonEmptyString(rec.action, rec.eventName, rec.method, rec.activity);
    const resource = extractResource(rec);
    const source_ip = firstNonEmptyString(rec.source_ip, rec.sourceIPAddress, rec.ip, rec.client_ip);
    const event_time = firstNonEmptyString(rec.event_time, rec.eventTime, rec.timestamp, rec.date);

    let rowMissing = 0;
    if (!identity.hadExplicitIdentityField) rowMissing += 1;
    if (!action) rowMissing += 1;
    if (!resource) rowMissing += 1;
    if (!source_ip) rowMissing += 1;
    if (!event_time) rowMissing += 1;
    missing_value_count += rowMissing;

    if (!identity.cloud_user_id) {
      rejected_rows += 1;
      bumpReason(rejectionReasonCounts, 'Missing required user identity field');
      if (errors.length < 25) {
        errors.push(`Row ${index + 1} rejected: missing required user identity field.`);
      }
      return;
    }

    if (!action) {
      rejected_rows += 1;
      bumpReason(rejectionReasonCounts, 'Missing required action/eventName field');
      if (errors.length < 25) {
        errors.push(`Row ${index + 1} rejected: missing required action or eventName field.`);
      }
      return;
    }

    const parsedDate = event_time ? new Date(event_time) : new Date();
    const isoTime = Number.isNaN(parsedDate.getTime()) ? new Date().toISOString() : parsedDate.toISOString();

    const provider = normalizeProvider(
      typeof rec.provider === 'string' ? rec.provider : undefined,
      rec,
    );
    if (provider === 'AWS Lambda') adapted_faas_count += 1;
    else original_records_count += 1;

    if (rawLabel === 1) attack_count += 1;
    else if (rawLabel === 0) benign_count += 1;
    else unlabeled_count += 1;

    const attack_name = firstNonEmptyString(rec.attack_name) || undefined;

    events.push({
      event_id,
      ...(options.datasetId ? { dataset_id: options.datasetId } : {}),
      provider,
      event_time: isoTime,
      cloud_user_id: identity.cloud_user_id,
      identity_type: identity.identity_type,
      action,
      resource: resource || 'unspecified-resource',
      source_ip: source_ip || '0.0.0.0',
      status: normalizeStatus(rec.status ?? rec.outcome, rec),
      raw_event: rec,
      is_simulated: Boolean(rec.is_simulated ?? false),
      dataset_source: sourceLabel,
      ...(rawLabel !== undefined ? { ground_truth_label: rawLabel } : {}),
      ...(attack_name ? { attack_name } : {}),
    });
  });

  const skipped_rows = duplicate_count + already_exists_count;
  const rejection_reasons = Array.from(rejectionReasonCounts.entries()).map(
    ([reason, count]) => `${reason} (${count})`,
  );
  const skip_reasons = Array.from(skipReasonCounts.entries()).map(
    ([reason, count]) => `${reason} (${count})`,
  );

  return {
    events,
    total_rows: rawRecords.length,
    valid_rows: events.length,
    normalized_rows: events.length,
    imported_rows: events.length,
    rejected_rows,
    skipped_rows,
    missing_value_count,
    duplicate_count,
    already_exists_count,
    adapted_faas_count,
    original_records_count,
    benign_count,
    attack_count,
    unlabeled_count,
    raw_benign_count,
    raw_attack_count,
    raw_unlabeled_count,
    rejection_reasons,
    skip_reasons,
    errors,
  };
}
