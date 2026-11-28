import type {
  CloudProvider,
  DatasetRecord,
  NormalizedAuditEvent,
  OpenStackConnectivityStatus,
  OpenStackIngestResult,
  OpenStackSecurityCategory,
  OpenStackServiceName,
} from '../types/security.ts';

export const OPENSTACK_REAL_DATASET_ID = 'ds-openstack-audit';
export const OPENSTACK_FIXTURE_DATASET_ID = 'ds-openstack-fixture';

const SENSITIVE_KEY_PATTERN =
  /(password|passwd|secret|token|x-auth-token|x_auth_token|x-subject-token|x_subject_token|authorization|bearer|credential|private_key|api_key|apikey)/i;

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function firstString(...values: unknown[]): string {
  for (const val of values) {
    if (typeof val === 'string' && val.trim()) return val.trim();
    if (typeof val === 'number' && Number.isFinite(val)) return String(val);
  }
  return '';
}

/**
 * Recursively redact passwords, auth tokens, application credential secrets,
 * and bearer headers before persistence or API emission.
 */
export function redactOpenStackSecrets(input: unknown, depth = 0): unknown {
  if (depth > 8 || input === null || input === undefined) return input;
  if (Array.isArray(input)) {
    return input.map((item) => redactOpenStackSecrets(item, depth + 1));
  }
  if (typeof input === 'string') {
    if (/^(Bearer\s+|gAAAAA)[A-Za-z0-9._\-+/=]{8,}$/i.test(input.trim())) {
      return '[REDACTED]';
    }
    return input;
  }
  if (typeof input !== 'object') return input;

  const obj = input as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEY_PATTERN.test(k)) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = redactOpenStackSecrets(v, depth + 1);
    }
  }
  return out;
}

export function normalizeOpenStackService(rawService: string, action: string, targetType = ''): {
  service: OpenStackServiceName;
  provider: CloudProvider;
} {
  const combined = `${rawService} ${action} ${targetType}`.toLowerCase();
  if (combined.includes('keystone') || combined.includes('identity') || combined.includes('service/security/account')) {
    return { service: 'keystone', provider: 'OpenStack Keystone' };
  }
  if (combined.includes('nova') || combined.includes('compute') || combined.includes('server')) {
    return { service: 'nova', provider: 'OpenStack Nova' };
  }
  if (
    combined.includes('neutron') ||
    combined.includes('network') ||
    combined.includes('security_group') ||
    combined.includes('floatingip') ||
    combined.includes('router') ||
    combined.includes('subnet')
  ) {
    return { service: 'neutron', provider: 'OpenStack Neutron' };
  }
  if (combined.includes('glance') || combined.includes('image')) {
    return { service: 'glance', provider: 'OpenStack Glance' };
  }
  if (
    combined.includes('cinder') ||
    combined.includes('volume') ||
    combined.includes('block-storage') ||
    combined.includes('snapshot')
  ) {
    return { service: 'cinder', provider: 'OpenStack Cinder' };
  }
  return { service: 'unknown', provider: 'OpenStack Audit' };
}

export function classifyOpenStackSecurityCategory(
  service: OpenStackServiceName,
  action: string,
  status: 'Success' | 'Failed' | 'Denied',
  raw: Record<string, unknown>,
): OpenStackSecurityCategory {
  const a = action.toLowerCase();

  if (
    (service === 'keystone' || a.includes('auth') || a.includes('login') || a.includes('token')) &&
    (status === 'Failed' || status === 'Denied')
  ) {
    return 'Authentication Failures';
  }

  if (
    a.includes('role_assignment') ||
    a.includes('grant') ||
    a.includes('revoke_role') ||
    a.includes('policy') ||
    a.includes('trust') ||
    a.includes('create_user') ||
    a.includes('delete_user') ||
    a.includes('application_credential')
  ) {
    return 'Privilege and Role Changes';
  }

  if (
    service === 'nova' &&
    (a.includes('create') || a.includes('delete') || a.includes('terminate') || a.includes('rebuild') || a.includes('rescue'))
  ) {
    return 'Instance Creation/Deletion';
  }

  if (
    service === 'neutron' ||
    a.includes('security_group') ||
    a.includes('firewall') ||
    a.includes('router') ||
    a.includes('port') ||
    a.includes('floatingip') ||
    a.includes('network')
  ) {
    return 'Security Group and Network Changes';
  }

  if (
    service === 'glance' ||
    service === 'cinder' ||
    a.includes('image') ||
    a.includes('volume') ||
    a.includes('snapshot')
  ) {
    return 'Image and Volume Access';
  }

  if (
    a.includes('delete') ||
    a.includes('burst') ||
    a.includes('disable') ||
    a.includes('purge') ||
    a.includes('admin') ||
    Boolean(raw.administrativeOverride) ||
    status === 'Denied'
  ) {
    return 'Unusual Administrative Operations';
  }

  return 'Routine Operational Activity';
}

function normalizeOpenStackStatus(rec: Record<string, unknown>): 'Success' | 'Failed' | 'Denied' {
  const explicit = firstString(rec.status, rec.outcome).toLowerCase();
  const httpStatus = Number(rec.http_status ?? rec.status_code ?? rec.code);

  if (explicit.includes('deny') || explicit.includes('denied') || explicit.includes('forbid') || explicit.includes('unauth')) {
    return 'Denied';
  }
  if (explicit.includes('fail') || explicit.includes('error')) {
    return 'Failed';
  }
  if (Number.isFinite(httpStatus)) {
    if (httpStatus === 401 || httpStatus === 403) return 'Denied';
    if (httpStatus >= 400) return 'Failed';
  }
  return 'Success';
}

/**
 * Ingest and normalize raw OpenStack CADF or simplified JSON audit records into
 * CloudSentinel's NormalizedAuditEvent schema with secret redaction and validation.
 */
export function normalizeOpenStackEvents(
  rawRecords: unknown[],
  existingIds: Set<string>,
  options: {
    sourceMode: 'real' | 'fixture';
    sourceName?: string;
    datasetId?: string;
  },
): {
  events: NormalizedAuditEvent[];
  result: OpenStackIngestResult;
} {
  const isFixture = options.sourceMode === 'fixture';
  const datasetId =
    options.datasetId || (isFixture ? OPENSTACK_FIXTURE_DATASET_ID : OPENSTACK_REAL_DATASET_ID);
  const datasetSource =
    options.sourceName?.trim() ||
    (isFixture ? 'OpenStack Synthetic Test Fixture' : 'OpenStack Private Cloud Audit Ingestion');

  const seenBatch = new Set<string>();
  const rejectionCounts = new Map<string, number>();
  const skipCounts = new Map<string, number>();
  const errors: string[] = [];

  const bump = (m: Map<string, number>, reason: string) => {
    m.set(reason, (m.get(reason) || 0) + 1);
  };

  let missingFieldCount = 0;
  let duplicateCount = 0;
  let skippedCount = 0;
  let rejectedCount = 0;
  const servicesDetected = new Set<OpenStackServiceName>();
  const events: NormalizedAuditEvent[] = [];
  const batchSeed = Date.now().toString(36);

  rawRecords.forEach((item, index) => {
    const rec = asRecord(item);
    if (!rec) {
      rejectedCount += 1;
      bump(rejectionCounts, 'Non-object OpenStack audit entry');
      if (errors.length < 25) {
        errors.push(`Record ${index + 1} rejected: entry is not a JSON object.`);
      }
      return;
    }

    const initiator = asRecord(rec.initiator);
    const target = asRecord(rec.target);
    const initiatorHost = asRecord(initiator?.host);
    const extra = asRecord(rec.extra);

    const rawEventId = firstString(rec.event_id, rec.id, rec.cadf_id, rec.audit_id);
    const eventId = rawEventId || `os-${batchSeed}-${index + 1}`;

    if (seenBatch.has(eventId)) {
      duplicateCount += 1;
      skippedCount += 1;
      bump(skipCounts, 'Duplicate event_id within batch');
      return;
    }
    if (existingIds.has(eventId)) {
      skippedCount += 1;
      bump(skipCounts, 'Event ID already ingested in stored event pool');
      return;
    }

    const rawService = firstString(rec.service, rec.service_name, rec.component, target?.service);
    const action = firstString(rec.action, rec.event_type, rec.eventName, rec.method);
    const userId = firstString(
      rec.user_name,
      rec.username,
      rec.user_id,
      rec.cloud_user_id,
      initiator?.name,
      initiator?.id,
    );

    if (!action) {
      rejectedCount += 1;
      bump(rejectionCounts, 'Missing required OpenStack action/event_type field');
      if (errors.length < 25) {
        errors.push(`Record ${index + 1} rejected: missing action or event_type.`);
      }
      return;
    }

    if (!rawService && !userId) {
      rejectedCount += 1;
      bump(rejectionCounts, 'Missing both service and user identity fields');
      if (errors.length < 25) {
        errors.push(`Record ${index + 1} rejected: missing service and user identity.`);
      }
      return;
    }

    seenBatch.add(eventId);

    const rawTime = firstString(rec.event_time, rec.eventTime, rec.timestamp, rec.generated_at, rec.created_at);
    const parsedDt = rawTime ? new Date(rawTime) : new Date();
    const validIsoTime = !Number.isNaN(parsedDt.getTime());
    const isoTime = validIsoTime ? parsedDt.toISOString() : new Date().toISOString();

    const projectId = firstString(
      rec.project_name,
      rec.project_id,
      rec.tenant_id,
      rec.domain_id,
      initiator?.project_id,
      target?.project_id,
      'default-project',
    );
    const resourceId = firstString(rec.resource_id, rec.resource, target?.id, 'unspecified-resource');
    const resourceType = firstString(rec.resource_type, target?.typeURI, 'openstack:resource');
    const sourceIp = firstString(
      rec.source_ip,
      rec.client_ip,
      rec.ip,
      initiatorHost?.address,
      '0.0.0.0',
    );
    const requestId = firstString(rec.request_id, rec.req_id, rec.global_request_id, `req-${eventId}`);
    const region = firstString(rec.region, rec.region_name, 'RegionOne');

    if (!userId) missingFieldCount += 1;
    if (!rawTime || !validIsoTime) missingFieldCount += 1;
    if (!firstString(rec.source_ip, rec.client_ip, rec.ip, initiatorHost?.address)) missingFieldCount += 1;
    if (!firstString(rec.resource_id, rec.resource, target?.id)) missingFieldCount += 1;

    const { service, provider } = normalizeOpenStackService(rawService, action, resourceType);
    servicesDetected.add(service);

    const status = normalizeOpenStackStatus(rec);
    const redactedRaw = redactOpenStackSecrets(rec) as Record<string, unknown>;
    const securityCategory = classifyOpenStackSecurityCategory(service, action, status, redactedRaw);

    const resourceDisplay = resourceId.startsWith('openstack:')
      ? resourceId
      : `openstack:${service}/${region}/${projectId}/${resourceType}:${resourceId}`;

    const normalizedRaw: Record<string, unknown> = {
      ...redactedRaw,
      openstack_service: service,
      project_id: projectId,
      region,
      request_id: requestId,
      resource_type: resourceType,
      resource_id: resourceId,
      security_category: securityCategory,
      ...(extra ? { extra: redactOpenStackSecrets(extra) } : {}),
    };

    const gt =
      rec.ground_truth_label === 1 || rec.ground_truth_label === 0
        ? (rec.ground_truth_label as 0 | 1)
        : undefined;

    events.push({
      event_id: eventId,
      dataset_id: datasetId,
      provider,
      event_time: isoTime,
      cloud_user_id: userId || `anonymous:${projectId}`,
      identity_type: firstString(rec.identity_type, initiator?.typeURI) || (userId ? 'KeystoneUser' : 'Missing'),
      action,
      resource: resourceDisplay,
      source_ip: sourceIp,
      status,
      raw_event: normalizedRaw,
      is_simulated: isFixture || Boolean(rec.is_simulated),
      dataset_source: datasetSource,
      source_origin: isFixture || Boolean(rec.is_simulated) ? 'synthetic_fixture' : 'real_openstack',
      security_category: securityCategory,
      ...(gt !== undefined ? { ground_truth_label: gt } : {}),
    });
  });

  return {
    events,
    result: {
      dataset_id: datasetId,
      source_mode: isFixture ? 'fixture' : 'real',
      source_name: datasetSource,
      total_received: rawRecords.length,
      imported_count: events.length,
      normalized_count: events.length,
      rejected_count: rejectedCount,
      skipped_count: skippedCount,
      duplicate_count: duplicateCount,
      missing_field_count: missingFieldCount,
      services_detected: Array.from(servicesDetected),
      rejection_reasons: Array.from(rejectionCounts.entries()).map(([r, c]) => `${r} (${c})`),
      skip_reasons: Array.from(skipCounts.entries()).map(([r, c]) => `${r} (${c})`),
      errors,
    },
  };
}

export function buildOpenStackDatasetRecord(
  events: NormalizedAuditEvent[],
  summary: OpenStackIngestResult,
): DatasetRecord {
  const benign = events.filter((e) => e.ground_truth_label === 0).length;
  const attack = events.filter((e) => e.ground_truth_label === 1).length;
  return {
    dataset_id: summary.dataset_id,
    name: summary.source_name,
    source_type: 'JSON',
    provenance:
      summary.source_mode === 'fixture'
        ? 'Synthetic OpenStack Private Cloud Test Fixtures (Keystone/Nova/Neutron/Glance/Cinder)'
        : 'User-Ingested OpenStack Audit Telemetry Export',
    dataset_role: 'audit',
    is_cert_mapped: false,
    total_rows: summary.total_received,
    valid_rows: summary.imported_count,
    normalized_rows: summary.normalized_count,
    imported_rows: summary.imported_count,
    rejected_rows: summary.rejected_count,
    skipped_rows: summary.skipped_count,
    missing_value_count: summary.missing_field_count,
    duplicate_count: summary.duplicate_count,
    benign_count: benign,
    attack_count: attack,
    unlabeled_count: Math.max(0, summary.imported_count - benign - attack),
    rejection_reasons: summary.rejection_reasons,
    skip_reasons: summary.skip_reasons,
    original_records_count: summary.imported_count,
    adapted_faas_count: 0,
    split_ratio: { train: 0.6, val: 0.2, test: 0.2 },
    preprocessed: true,
    features_extracted: ['is_after_hours', 'is_unusual_ip', 'is_failed_auth', 'action_criticality', 'resource_sensitivity'],
    created_at: new Date().toISOString(),
    sample_preview: events.slice(0, 5),
  };
}

export function getOpenStackEnvironmentStatus(): {
  auth_url_configured: boolean;
  credentials_configured: boolean;
  endpoint_hint: string | null;
  auth_mode: string;
} {
  const authUrl = (process.env.OPENSTACK_AUTH_URL || process.env.OPENSTACK_KEYSTONE_URL || '').trim();
  const hasToken = Boolean(process.env.OPENSTACK_TOKEN?.trim());
  const hasAppCred = Boolean(
    process.env.OPENSTACK_APPLICATION_CREDENTIAL_ID?.trim() &&
      process.env.OPENSTACK_APPLICATION_CREDENTIAL_SECRET?.trim(),
  );
  const hasUserPass = Boolean(
    process.env.OPENSTACK_USERNAME?.trim() && process.env.OPENSTACK_PASSWORD?.trim(),
  );

  let maskedEndpoint: string | null = null;
  if (authUrl) {
    try {
      const parsed = new URL(authUrl);
      maskedEndpoint = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    } catch {
      maskedEndpoint = 'invalid-url-format';
    }
  }

  return {
    auth_url_configured: Boolean(authUrl),
    credentials_configured: hasToken || hasAppCred || hasUserPass,
    endpoint_hint: maskedEndpoint,
    auth_mode: hasAppCred
      ? 'Keystone Application Credential (Read-Only)'
      : hasToken
        ? 'Keystone Scoped Token'
        : hasUserPass
          ? 'Keystone Password Auth'
          : 'Unconfigured',
  };
}

/**
 * Perform a non-destructive read-only connectivity probe ONLY if endpoint and credentials are configured.
 * Never logs or returns tokens/passwords, and never simulates a 'Connected' status when offline.
 */
export async function probeOpenStackConnectivity(
  fixtureEventsCount: number,
  realOpenStackEventsCount: number,
): Promise<{
  connectivity_status: OpenStackConnectivityStatus;
  status_reason: string;
  env_status: ReturnType<typeof getOpenStackEnvironmentStatus>;
}> {
  const env = getOpenStackEnvironmentStatus();

  if (!env.auth_url_configured || !env.credentials_configured) {
    const inFixtureMode = fixtureEventsCount > 0 && realOpenStackEventsCount === 0;
    return {
      connectivity_status: inFixtureMode ? 'Fixture Mode' : 'Not Connected',
      status_reason: inFixtureMode
        ? 'No live OpenStack Keystone endpoint or credentials configured on backend; displaying ingested synthetic OpenStack fixtures.'
        : 'Live OpenStack environment not configured (OPENSTACK_AUTH_URL and read-only credentials/token are absent).',
      env_status: env,
    };
  }

  const rawUrl = (process.env.OPENSTACK_AUTH_URL || process.env.OPENSTACK_KEYSTONE_URL || '').trim();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (process.env.OPENSTACK_TOKEN?.trim()) {
      headers['X-Auth-Token'] = process.env.OPENSTACK_TOKEN.trim();
    }
    const resp = await fetch(rawUrl, { method: 'GET', headers, signal: controller.signal });
    if (resp.ok || resp.status === 300) {
      return {
        connectivity_status: 'Connected',
        status_reason: `Read-only discovery probe against ${env.endpoint_hint} succeeded (HTTP ${resp.status}).`,
        env_status: env,
      };
    }
    return {
      connectivity_status: fixtureEventsCount > 0 && realOpenStackEventsCount === 0 ? 'Fixture Mode' : 'Not Connected',
      status_reason: `OpenStack endpoint ${env.endpoint_hint} returned HTTP ${resp.status}; live retrieval unavailable.`,
      env_status: env,
    };
  } catch (err) {
    return {
      connectivity_status: fixtureEventsCount > 0 && realOpenStackEventsCount === 0 ? 'Fixture Mode' : 'Not Connected',
      status_reason: `OpenStack endpoint probe failed (${err instanceof Error ? err.message : 'network error'}).`,
      env_status: env,
    };
  } finally {
    clearTimeout(timer);
  }
}
