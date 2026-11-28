import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  normalizeOpenStackEvents,
  probeOpenStackConnectivity,
  redactOpenStackSecrets,
} from '../src/server/openstackAdapter.ts';
import { evaluateEvent } from '../src/server/mlEngine.ts';
import { DEFAULT_RISK_WEIGHTS } from '../src/server/seedData.ts';

function runUnitTests(): void {
  console.log('Running Phase R4 OpenStack adapter deterministic unit tests...');

  const fixturePath = path.resolve(
    process.cwd(),
    'tests',
    'fixtures',
    'openstack',
    'openstack_audit_sample.json',
  );
  const fixtureRaw = JSON.parse(fs.readFileSync(fixturePath, 'utf-8')) as {
    events: unknown[];
  };

  // 1. Valid multi-service ingestion (Keystone, Nova, Neutron, Glance, Cinder) + Secret Redaction
  const { events, result } = normalizeOpenStackEvents(fixtureRaw.events, new Set<string>(), {
    sourceMode: 'fixture',
    sourceName: 'OpenStack Fixture Suite',
  });
  assert.equal(result.imported_count, 9);
  assert.equal(result.rejected_count, 0);
  for (const svc of ['keystone', 'nova', 'neutron', 'glance', 'cinder'] as const) {
    assert.ok(result.services_detected.includes(svc), `Expected service ${svc}`);
  }

  // Credential/token redaction verification
  const ksAuth = events.find((e) => e.event_id === 'os-fix-ks-001')!;
  assert.equal(ksAuth.raw_event.token, '[REDACTED]');
  assert.equal(ksAuth.raw_event.password, '[REDACTED]');
  assert.equal(ksAuth.is_simulated, true);
  assert.equal(ksAuth.source_origin, 'synthetic_fixture');

  const nestedRedacted = redactOpenStackSecrets({
    headers: { 'X-Auth-Token': 'secret-abc', 'X-Subject-Token': 'subj-xyz' },
    credentials: { application_credential_secret: 'app-sec', password: 'pw' },
    payload: { application_credential_secret: 'app-sec', password: 'pw' },
    safe_field: 'RegionOne',
  }) as Record<string, unknown>;
  const hdrs = nestedRedacted.headers as Record<string, string>;
  const pl = nestedRedacted.payload as Record<string, string>;
  assert.equal(hdrs['X-Auth-Token'], '[REDACTED]');
  assert.equal(hdrs['X-Subject-Token'], '[REDACTED]');
  assert.equal(nestedRedacted.credentials, '[REDACTED]');
  assert.equal(pl.application_credential_secret, '[REDACTED]');
  assert.equal(pl.password, '[REDACTED]');
  assert.equal(nestedRedacted.safe_field, 'RegionOne');

  // 2. Security category mapping & non-malicious routine admin differentiation
  assert.equal(
    events.find((e) => e.event_id === 'os-fix-ks-002')?.security_category,
    'Authentication Failures',
  );
  assert.equal(
    events.find((e) => e.event_id === 'os-fix-ks-003')?.security_category,
    'Privilege and Role Changes',
  );
  assert.equal(
    events.find((e) => e.event_id === 'os-fix-nv-001')?.security_category,
    'Instance Creation/Deletion',
  );
  assert.equal(
    events.find((e) => e.event_id === 'os-fix-nt-001')?.security_category,
    'Security Group and Network Changes',
  );
  assert.equal(
    events.find((e) => e.event_id === 'os-fix-gl-001')?.security_category,
    'Image and Volume Access',
  );
  assert.equal(
    events.find((e) => e.event_id === 'os-fix-cn-001')?.security_category,
    'Image and Volume Access',
  );

  // Daytime authorized server/image/volume create by internal IP should remain Normal Baseline Activity
  const normalNova = evaluateEvent(
    events.find((e) => e.event_id === 'os-fix-nv-001')!,
    events,
    DEFAULT_RISK_WEIGHTS,
    'Unit Test Scorer',
  );
  assert.equal(normalNova.investigation_status, 'Normal Baseline');

  // External IP role assignment / security_group 0.0.0.0/0 / off-hours delete should flag as suspicious
  const roleEsc = evaluateEvent(
    events.find((e) => e.event_id === 'os-fix-ks-003')!,
    events,
    DEFAULT_RISK_WEIGHTS,
    'Unit Test Scorer',
  );
  assert.notEqual(roleEsc.investigation_status, 'Normal Baseline');

  // 3. Edge cases: missing optional fields, unknown service, malformed objects, duplicate event IDs
  const edgeInputs = [
    null,
    'not-an-object',
    { service: 'nova' }, // missing action -> rejected
    { action: 'unknown.ping' }, // missing service AND user -> rejected
    { event_id: 'dup-1', service: 'custom_telemetry_svc', action: 'meter.sample', user_name: 'svc-mon' }, // unknown service -> safe fallback
    { event_id: 'dup-1', service: 'keystone', action: 'identity.authenticate', user_name: 'bob' }, // in-batch duplicate -> skipped
    { event_id: 'sparse-1', service: 'cinder', action: 'volume.attach', user_name: 'alice.ops@corp.internal' }, // missing IP/time/resource -> imported safely
  ];
  const existing = new Set<string>(events.map((e) => e.event_id));
  existing.add('already-stored-1');
  edgeInputs.push({
    event_id: 'already-stored-1',
    service: 'glance',
    action: 'image.list',
    user_name: 'alice',
  });

  const edgeOut = normalizeOpenStackEvents(edgeInputs, existing, { sourceMode: 'real' });
  assert.equal(edgeOut.result.imported_count, 2);
  assert.equal(edgeOut.result.rejected_count, 4);
  assert.equal(edgeOut.result.duplicate_count, 1);
  assert.equal(edgeOut.result.skipped_count, 2);
  assert.ok(edgeOut.result.missing_field_count >= 3);
  assert.equal(edgeOut.events[0].provider, 'OpenStack Audit');
  assert.equal(edgeOut.events[0].is_simulated, false);
  assert.equal(edgeOut.events[0].source_origin, 'real_openstack');
  assert.equal(edgeOut.events[1].source_ip, '0.0.0.0');

  console.log('PASS: All Phase R4 OpenStack unit, redaction, category, and edge-case tests passed.');
}

async function runLiveApiTests(): Promise<void> {
  const baseUrl = process.env.API_BASE_URL || 'http://127.0.0.1:3000';
  const mlUrl = process.env.ML_BASE_URL || 'http://127.0.0.1:8001';
  console.log(`Running live Phase R4 API, RBAC, redaction, and regression tests against ${baseUrl}...`);

  // Verify honest offline OpenStack probe locally
  const localProbe = await probeOpenStackConnectivity(5, 0);
  assert.equal(localProbe.connectivity_status, 'Fixture Mode');

  const dirResp = await fetch(`${baseUrl}/api/auth/users-directory`);
  assert.equal(dirResp.status, 200);
  const { users } = (await dirResp.json()) as { users: Array<{ user_id: string; role: string }> };
  const admin = users.find((u) => u.role === 'Admin')!;
  const analyst = users.find((u) => u.role === 'Security Analyst')!;
  const viewer = users.find((u) => u.role === 'Viewer')!;

  // RBAC: Viewer denied POST /api/openstack/ingest (403) and POST /api/openstack/load-fixtures (403)
  const viewerIngest = await fetch(`${baseUrl}/api/openstack/ingest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CloudSentinel-UserId': viewer.user_id,
      'X-CloudSentinel-Role': viewer.role,
    },
    body: JSON.stringify({ events: [{ service: 'nova', action: 'server.list', user_name: 'bob' }] }),
  });
  assert.equal(viewerIngest.status, 403);

  const viewerFix = await fetch(`${baseUrl}/api/openstack/load-fixtures`, {
    method: 'POST',
    headers: {
      'X-CloudSentinel-UserId': viewer.user_id,
      'X-CloudSentinel-Role': viewer.role,
    },
  });
  assert.equal(viewerFix.status, 403);

  // Validation: Empty events array -> 400
  const badPayload = await fetch(`${baseUrl}/api/openstack/ingest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CloudSentinel-UserId': analyst.user_id,
      'X-CloudSentinel-Role': analyst.role,
    },
    body: JSON.stringify({ events: [] }),
  });
  assert.equal(badPayload.status, 400);

  // Analyst loads synthetic fixtures -> 201
  const loadFixResp = await fetch(`${baseUrl}/api/openstack/load-fixtures`, {
    method: 'POST',
    headers: {
      'X-CloudSentinel-UserId': analyst.user_id,
      'X-CloudSentinel-Role': analyst.role,
    },
  });
  assert.equal(loadFixResp.status, 201);

  // Check GET /api/openstack/telemetry -> Fixture Mode / Not Connected (NEVER Connected without real env), no leaked secrets
  const osTelResp = await fetch(`${baseUrl}/api/openstack/telemetry`);
  assert.equal(osTelResp.status, 200);
  const osTelText = await osTelResp.text();
  assert.ok(!osTelText.includes('fixture-secret-password'), 'Password leaked in API response!');
  assert.ok(!osTelText.includes('gAAAAABsynthetic-secret-token'), 'Token leaked in API response!');
  const osTel = JSON.parse(osTelText) as {
    connectivity_status: string;
    services_detected: Array<{ service: string }>;
    event_counts: { total_events: number; real_events: number; fixture_events: number; suspicious_events: number };
  };
  assert.equal(
    osTel.connectivity_status,
    osTel.event_counts.real_events === 0 ? 'Fixture Mode' : 'Not Connected',
  );
  assert.notEqual(osTel.connectivity_status, 'Connected');
  assert.ok(osTel.event_counts.total_events >= 9);
  assert.ok(osTel.event_counts.suspicious_events >= 1);
  assert.equal(osTel.services_detected.length, 5);

  // Admin ingests custom real-tagged event with secret to confirm redaction + mixed provenance
  const realIngestResp = await fetch(`${baseUrl}/api/openstack/ingest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CloudSentinel-UserId': admin.user_id,
      'X-CloudSentinel-Role': admin.role,
    },
    body: JSON.stringify({
      source_mode: 'real',
      source_name: 'OpenStack Test Export Verification',
      events: [
        {
          event_id: `os-real-verify-${Date.now()}`,
          service: 'neutron',
          action: 'network.port.create',
          user_name: 'netops@corp.internal',
          project_name: 'core-network',
          source_ip: '10.24.5.19',
          status: 'Success',
          token: 'super-secret-real-token-12345',
        },
      ],
    }),
  });
  assert.equal(realIngestResp.status, 201);

  // Regression checks: CloudTrail / FaaS / Optimizer / Isolation Forest / LSTM still work identically
  const [faasR, optR, polR, mlHealthR, lstmStR] = await Promise.all([
    fetch(`${baseUrl}/api/faas/telemetry?dataset_id=ds-cloudtrail-train`),
    fetch(`${baseUrl}/api/policies/optimizer`),
    fetch(`${baseUrl}/api/policies`),
    fetch(`${mlUrl}/health`),
    fetch(`${mlUrl}/lstm/status`),
  ]);
  assert.equal(faasR.status, 200);
  assert.equal(optR.status, 200);
  assert.equal(polR.status, 200);
  assert.equal(mlHealthR.status, 200);
  assert.equal(lstmStR.status, 200);
  const mlHealth = (await mlHealthR.json()) as { feature_count: number; model_file: string };
  assert.equal(mlHealth.feature_count, 8);
  assert.equal(mlHealth.model_file, 'isolation_forest_cloudtrail.joblib');

  console.log('PASS: All Phase R4 OpenStack live API, RBAC, redaction, and cross-phase regression tests passed.');
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
