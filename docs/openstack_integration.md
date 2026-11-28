# OpenStack Private Cloud Integration (Phase R4)

**Adapter Module:** `src/server/openstackAdapter.ts`  
**Express Endpoints:** `GET /api/openstack/telemetry`, `POST /api/openstack/ingest`, `POST /api/openstack/load-fixtures`  
**Synthetic Fixtures:** `tests/fixtures/openstack/openstack_audit_sample.json`

---

## 1. Architecture Overview

CloudSentinel AI integrates OpenStack private-cloud telemetry as an additive normalization and monitoring pipeline alongside existing AWS CloudTrail, Lambda FaaS, and adaptive policy components.

1. **Ingestion & Normalization (`src/server/openstackAdapter.ts`):**
   - Accepts CADF or flattened OpenStack JSON audit payloads spanning five OpenStack services: **Keystone** (Identity), **Nova** (Compute), **Neutron** (Networking), **Glance** (Image), and **Cinder** (Block Storage).
   - Maps unknown or third-party OpenStack components safely into `OpenStack Audit` without throwing or dropping non-empty audit items.
   - Deduplicates by `event_id` within batches and against existing stored events, tracking imported, normalized, skipped, duplicate, rejected, and missing-field counts separately.
2. **Secret & Token Redaction:**
   - Recursively scrubs keys matching `password`, `token`, `x-auth-token`, `x-subject-token`, `secret`, `credential`, `authorization`, `bearer`, `private_key`, and `api_key` into `[REDACTED]` before persisting events or returning API responses.
   - Passwords and Keystone tokens are never logged in audit trail descriptions or transmitted back to React clients.
3. **Security Event Mapping & Risk Evaluation:**
   - Maps OpenStack activity into normalized categories (`Authentication Failures`, `Privilege and Role Changes`, `Instance Creation/Deletion`, `Security Group and Network Changes`, `Image and Volume Access`, `Unusual Administrative Operations`, and `Routine Operational Activity`).
   - Preserves distinction between normal daytime administrative operations from known internal subnets (`Normal Baseline Activity`) and suspicious patterns (external IP authentication failures, privilege grants, `0.0.0.0/0` ingress rules, off-hours instance deletions, bulk snapshot exports).
4. **Strict Separation of Real Data vs. Synthetic Fixtures:**
   - Real OpenStack exports (`source_mode: "real"`) register under `ds-openstack-audit` (`source_origin: "real_openstack"`, `is_simulated: false`).
   - Synthetic test fixtures (`source_mode: "fixture"`) register under `ds-openstack-fixture` (`source_origin: "synthetic_fixture"`, `is_simulated: true`) and are badged distinctly in all API payloads and UI tables.

---

## 2. Live OpenStack Connectivity Status & Prerequisites

- **Current Host Status:** **Not Connected / Fixture Mode** (unless `OPENSTACK_AUTH_URL` and credentials are injected into backend environment variables).
- **Honesty Guarantee:** `probeOpenStackConnectivity()` never reports `Connected` without both an endpoint URL (`OPENSTACK_AUTH_URL` or `OPENSTACK_KEYSTONE_URL`) and read-only credentials (`OPENSTACK_TOKEN`, `OPENSTACK_APPLICATION_CREDENTIAL_ID` + `OPENSTACK_APPLICATION_CREDENTIAL_SECRET`, or `OPENSTACK_USERNAME` + `OPENSTACK_PASSWORD`) passing a live `GET` probe against the Keystone v3 endpoint.

### Prerequisites for Future Live Private-Cloud Testing
1. A reachable OpenStack deployment (e.g., DevStack or MicroStack / Kolla-Ansible) exposing Keystone Identity v3 (`https://<openstack-host>:5000/v3`) and RabbitMQ / Ceilometer / CADF audit log exporter.
2. A dedicated **read-only (`reader`)** Keystone Application Credential or scoped project token.
3. Backend environment variables configured in `.env` (never committed):
   - `OPENSTACK_AUTH_URL=https://<keystone-host>:5000/v3`
   - `OPENSTACK_APPLICATION_CREDENTIAL_ID=<id>`
   - `OPENSTACK_APPLICATION_CREDENTIAL_SECRET=<secret>` (or `OPENSTACK_TOKEN=<scoped-read-only-token>`)
4. Forwarding sanitized CADF audit events from OpenStack syslog/Ceilometer middleware into `POST /api/openstack/ingest` with `source_mode: "real"`.
