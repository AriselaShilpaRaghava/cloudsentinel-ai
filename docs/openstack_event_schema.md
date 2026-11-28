# OpenStack Audit Event JSON Schema & Security Mapping

**Endpoint:** `POST /api/openstack/ingest` (RBAC: `Admin` or `Security Analyst`; `Viewer` denied with `HTTP 403`)

---

## 1. JSON Request Payload Contract

```json
{
  "source_mode": "real | fixture",
  "source_name": "Optional human-readable feed or dataset label",
  "dataset_id": "Optional custom dataset identifier (defaults to ds-openstack-audit or ds-openstack-fixture)",
  "events": [
    {
      "event_id": "Optional unique event ID (auto-generated if omitted)",
      "event_time": "ISO-8601 UTC timestamp (also accepts eventTime, timestamp, generated_at, created_at)",
      "service": "keystone | nova | neutron | glance | cinder | custom-service",
      "action": "Required event action (also accepts event_type, eventName, method)",
      "user_name": "Initiating user or role name (also accepts username, user_id, initiator.name, initiator.id)",
      "project_name": "OpenStack project/tenant (also accepts project_id, tenant_id, domain_id)",
      "resource_type": "CADF target typeURI or short resource type",
      "resource_id": "Target resource UUID/name (also accepts resource, target.id)",
      "source_ip": "Client IPv4/IPv6 (also accepts client_ip, ip, initiator.host.address; defaults to 0.0.0.0)",
      "request_id": "OpenStack request ID (also accepts req_id, global_request_id)",
      "region": "OpenStack region (also accepts region_name; defaults to RegionOne)",
      "status": "Success | Failed | Denied (also accepts outcome or numeric http_status)"
    }
  ]
}
```

### Validation & Safe Fallback Behavior
- `events` must be a non-empty array (`HTTP 400` otherwise).
- Individual records that are not JSON objects, lack both `action`/`event_type` AND `service`/`user`, are rejected and itemized in `rejection_reasons`.
- Missing optional fields (`user_id`, valid timestamp, `source_ip`, `resource_id`) increment `missing_field_count` cleanly with deterministic fallbacks rather than crashing or corrupting state.
- Any credential keys (`password`, `token`, `x-auth-token`, `secret`, `bearer`, etc.) anywhere inside an ingested record are replaced with `"[REDACTED]"` prior to storage.

---

## 2. Service & Provider Normalization Table

| Input `service` / Keywords | Normalized `provider` | Internal `service` |
|---|---|---|
| `keystone`, `identity`, `service/security/account` | `OpenStack Keystone` | `keystone` |
| `nova`, `compute`, `server` | `OpenStack Nova` | `nova` |
| `neutron`, `network`, `security_group`, `router`, `subnet`, `floatingip` | `OpenStack Neutron` | `neutron` |
| `glance`, `image` | `OpenStack Glance` | `glance` |
| `cinder`, `volume`, `block-storage`, `snapshot` | `OpenStack Cinder` | `cinder` |
| Unrecognized / custom service | `OpenStack Audit` | `unknown` |

---

## 3. Security Event Category Mapping

| Category | Triggering Event Signals |
|---|---|
| `Authentication Failures` | Auth/login/token calls with `Failed` or `Denied` outcome (`401`/`403`) |
| `Privilege and Role Changes` | `role_assignment`, role grant/revoke, policy/trust/user/app-credential changes |
| `Instance Creation/Deletion` | Nova server lifecycle actions (`create`, `delete`, `terminate`, `rebuild`, `rescue`) |
| `Security Group and Network Changes` | Neutron operations (`security_group`, `firewall`, `router`, `port`, `floatingip`, `network`) |
| `Image and Volume Access` | Glance `image.*` and Cinder `volume.*` / `snapshot.*` / `backup.*` events |
| `Unusual Administrative Operations` | Destructive/burst/override administrative calls or denied operations outside above scopes |
| `Routine Operational Activity` | Baseline non-destructive reads/authorized operations |
