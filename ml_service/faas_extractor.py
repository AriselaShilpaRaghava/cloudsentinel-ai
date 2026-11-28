"""
Leak-free AWS Lambda / Serverless FaaS telemetry and behavioral feature extraction
for CloudTrail and normalized multi-cloud audit events.

Strictly excludes all ground-truth labels (`should_sample`, `attack_name`,
`ground_truth_label`, `is_insider`, `label`) from feature computation and
telemetry aggregation. Missing CloudWatch/runtime fields (duration, memory,
cold-start rate) are always returned as `None` (never fabricated).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
import math
import time

import numpy as np

from cloudtrail_pipeline import SENSITIVE_ACTIONS, parse_time

FAAS_FEATURES: List[str] = [
    "is_lambda_invoke",
    "is_lambda_assume_role",
    "is_lambda_in_scope",
    "is_lambda_control_plane",
    "failed_or_denied_flag",
    "sensitive_faas_action_flag",
    "log_burst_1m",
    "log_burst_5m",
    "log_downstream_service_breadth_5m",
    "access_denied_ratio_5m",
]

FAAS_SENSITIVE_ACTIONS: Set[str] = set(SENSITIVE_ACTIONS) | {
    "decrypt",
    "generate_data_key",
    "generatedatakey",
    "transactwriteitems",
    "putitem",
    "batchwriteitem",
    "putobject",
    "deleteobject",
    "putbucketpolicy",
    "updatefunctioncode",
    "updatefunctioncode20150331v2",
    "updatefunctionconfiguration",
    "updatefunctionconfiguration20150331v2",
    "addpermission",
    "addpermission20150331v2",
    "createeventsourcemapping",
}


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _get_raw(event: Dict[str, Any]) -> Dict[str, Any]:
    return _as_dict(event.get("raw_event"))


def _extract_source(event: Dict[str, Any], raw: Dict[str, Any]) -> str:
    return str(
        event.get("eventSource")
        or event.get("event_source")
        or raw.get("eventSource")
        or raw.get("event_source")
        or ""
    ).strip().lower()


def _extract_action(event: Dict[str, Any], raw: Dict[str, Any]) -> str:
    return str(
        event.get("action")
        or event.get("eventName")
        or raw.get("eventName")
        or ""
    ).strip()


def _extract_region(event: Dict[str, Any], raw: Dict[str, Any], arn: str = "") -> str:
    if arn.startswith("arn:aws:"):
        parts = arn.split(":")
        if len(parts) >= 4 and parts[3]:
            return parts[3]
    region = event.get("awsRegion") or raw.get("awsRegion") or event.get("region")
    return str(region).strip() if region else "unknown"


def _extract_error_info(event: Dict[str, Any], raw: Dict[str, Any]) -> Tuple[bool, bool]:
    status = str(event.get("status") or "").strip().lower()
    err_code = str(event.get("errorCode") or raw.get("errorCode") or "").strip().lower()
    err_msg = str(event.get("errorMessage") or raw.get("errorMessage") or "").strip().lower()
    is_denied = (
        status == "denied"
        or "accessdenied" in err_code
        or "unauthorized" in err_code
        or "forbidden" in err_code
        or "accessdenied" in err_msg
    )
    is_failed = is_denied or status in ("failed", "failure", "error") or bool(err_code or err_msg)
    return is_failed, is_denied


def _function_name_from_arn(arn_or_name: str) -> str:
    s = arn_or_name.strip()
    if ":function:" in s:
        tail = s.split(":function:", 1)[1]
        return tail.split(":", 1)[0]
    return s


def classify_faas_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify whether an event belongs to AWS Lambda / FaaS execution without reading labels.

    Covers:
    1. Direct Lambda Invoke / InvokeFunction & Lambda control-plane events (`lambda.amazonaws.com` or provider `AWS Lambda`)
    2. Lambda STS AssumeRole events (`userIdentity.invokedBy == 'lambda.amazonaws.com'` or `awslambda_` roleSessionName)
    3. Downstream execution events performed by Lambda roles (`userIdentity.inScopeOf.issuerType == 'AWS::Lambda::Function'`)
    """
    raw = _get_raw(event)
    provider = str(event.get("provider") or "").strip().lower()
    source = _extract_source(event, raw)
    action = _extract_action(event, raw)
    action_lower = action.lower()
    resource = str(event.get("resource") or "")

    ui = _as_dict(event.get("userIdentity") or raw.get("userIdentity"))
    in_scope = _as_dict(ui.get("inScopeOf"))
    rp = _as_dict(event.get("requestParameters") or raw.get("requestParameters"))

    issuer_type = str(in_scope.get("issuerType") or "").strip()
    invoked_by = str(ui.get("invokedBy") or "").strip().lower()
    role_session_name = str(rp.get("roleSessionName") or "").strip().lower()

    if issuer_type == "AWS::Lambda::Function":
        return {"is_faas": True, "category": "in_scope_downstream"}

    if "lambda.amazonaws.com" in source or "lambda" in provider or "faas" in provider:
        if action_lower in ("invoke", "invokefunction", "invoke_function"):
            return {"is_faas": True, "category": "invoke"}
        return {"is_faas": True, "category": "control_plane"}

    if action_lower in ("invokefunction", "invoke_function") or resource.lower().startswith(("fn_", "fn-")):
        return {"is_faas": True, "category": "invoke"}

    if (
        invoked_by == "lambda.amazonaws.com"
        or ("lambda" in invoked_by and "sts" in source)
        or (source == "sts.amazonaws.com" and role_session_name.startswith("awslambda_"))
    ):
        return {"is_faas": True, "category": "assume_role"}

    return {"is_faas": False, "category": "non_faas"}


def resolve_faas_identity(event: Dict[str, Any], category: str) -> Tuple[str, Optional[str], str, str]:
    """
    Resolve canonical (function_name, function_arn, caller_label, region) for a FaaS event.
    """
    raw = _get_raw(event)
    ui = _as_dict(event.get("userIdentity") or raw.get("userIdentity"))
    in_scope = _as_dict(ui.get("inScopeOf"))
    rp = _as_dict(event.get("requestParameters") or raw.get("requestParameters"))
    resources = event.get("resources") if isinstance(event.get("resources"), list) else raw.get("resources")

    issued_to = str(in_scope.get("credentialsIssuedTo") or "").strip()
    if issued_to:
        fn_name = _function_name_from_arn(issued_to)
        region = _extract_region(event, raw, issued_to)
        caller = str(event.get("cloud_user_id") or ui.get("invokedBy") or ui.get("arn") or fn_name)
        return fn_name, issued_to, caller, region

    fn_param = str(rp.get("functionName") or "").strip()
    if fn_param:
        fn_name = _function_name_from_arn(fn_param)
        fn_arn = fn_param if fn_param.startswith("arn:aws:") else None
        region = _extract_region(event, raw, fn_param)
        caller = str(event.get("cloud_user_id") or ui.get("invokedBy") or ui.get("userName") or "lambda.amazonaws.com")
        return fn_name, fn_arn, caller, region

    if isinstance(resources, list):
        for item in resources:
            if isinstance(item, dict) and item.get("type") == "AWS::Lambda::Function":
                arn = str(item.get("ARN") or item.get("arn") or "").strip()
                if arn:
                    fn_name = _function_name_from_arn(arn)
                    region = _extract_region(event, raw, arn)
                    caller = str(event.get("cloud_user_id") or ui.get("invokedBy") or "lambda.amazonaws.com")
                    return fn_name, arn, caller, region

    res_str = str(event.get("resource") or "").strip()
    if ":function:" in res_str or res_str.lower().startswith(("fn_", "fn-")):
        first_token = res_str.split(" | ")[0].strip()
        fn_name = _function_name_from_arn(first_token)
        fn_arn = first_token if first_token.startswith("arn:aws:") else None
        region = _extract_region(event, raw, first_token)
        caller = str(event.get("cloud_user_id") or ui.get("invokedBy") or "lambda.amazonaws.com")
        return fn_name, fn_arn, caller, region

    log_group = str(rp.get("logGroupName") or "").strip()
    if log_group.startswith("/aws/lambda/"):
        fn_name = log_group[len("/aws/lambda/"):].strip()
        region = _extract_region(event, raw)
        caller = str(event.get("cloud_user_id") or "lambda.amazonaws.com")
        return fn_name, None, caller, region

    if category == "assume_role":
        role_arn = str(rp.get("roleArn") or "").strip()
        if not role_arn and isinstance(resources, list):
            for item in resources:
                if isinstance(item, dict) and item.get("type") == "AWS::IAM::Role":
                    role_arn = str(item.get("ARN") or item.get("arn") or "").strip()
                    if role_arn:
                        break
        role_label = role_arn.split("/")[-1] if "/" in role_arn else (role_arn or "lambda-execution-role")
        region = _extract_region(event, raw, role_arn)
        caller = str(ui.get("invokedBy") or event.get("cloud_user_id") or "lambda.amazonaws.com")
        return f"lambda-role:{role_label}", role_arn or None, caller, region

    caller = str(event.get("cloud_user_id") or ui.get("invokedBy") or ui.get("arn") or "aws-service")
    region = _extract_region(event, raw)
    return "lambda-control-plane", None, caller, region


def extract_faas_telemetry(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Inspect events, extract chronological FaaS feature vectors, and aggregate
    per-function telemetry strictly from observed CloudTrail/normalized event metadata.
    """
    t_start = time.perf_counter()

    classified: List[Tuple[int, Dict[str, Any], Optional[datetime], str, str, Optional[str], str, str]] = []
    for idx, ev in enumerate(events):
        cls = classify_faas_event(ev)
        if not cls["is_faas"]:
            continue
        raw = _get_raw(ev)
        dt = parse_time(ev.get("event_time") or ev.get("eventTime") or ev.get("timestamp"))
        fn_name, fn_arn, caller, region = resolve_faas_identity(ev, cls["category"])
        classified.append((idx, ev, dt, cls["category"], fn_name, fn_arn, caller, region))

    # Chronological sort per canonical function identity for rolling burst features
    classified.sort(key=lambda item: (item[4], item[2] or datetime.min.replace(tzinfo=timezone.utc)))

    win_1m: Dict[str, deque] = defaultdict(deque)
    win_5m: Dict[str, deque] = defaultdict(deque)
    agg: Dict[str, Dict[str, Any]] = {}
    feature_rows: List[List[float]] = []

    category_totals = {
        "invoke": 0,
        "assume_role": 0,
        "in_scope_downstream": 0,
        "control_plane": 0,
    }
    total_errors = 0
    total_access_denied = 0

    for _, ev, dt, category, fn_name, fn_arn, caller, region in classified:
        raw = _get_raw(ev)
        source = _extract_source(ev, raw) or str(ev.get("provider") or "unknown").lower()
        action = _extract_action(ev, raw)
        action_lower = action.lower()
        is_failed, is_denied = _extract_error_info(ev, raw)

        category_totals[category] = category_totals.get(category, 0) + 1
        if is_failed:
            total_errors += 1
        if is_denied:
            total_access_denied += 1

        is_sensitive = action_lower in FAAS_SENSITIVE_ACTIONS
        if isinstance(raw, dict) and raw.get("bytesTransferredMB") is not None:
            try:
                if float(raw["bytesTransferredMB"]) >= 500:
                    is_sensitive = True
            except (TypeError, ValueError):
                pass

        if dt is not None:
            ts = dt.timestamp()
            q1 = win_1m[fn_name]
            q1.append(ts)
            while q1 and ts - q1[0] > 60.0:
                q1.popleft()

            q5 = win_5m[fn_name]
            q5.append((ts, source, is_denied or is_failed))
            while q5 and ts - q5[0][0] > 300.0:
                q5.popleft()

            burst_1m = len(q1)
            burst_5m = len(q5)
            service_breadth_5m = len({svc for _, svc, _ in q5 if svc})
            denied_5m = sum(1 for _, _, err in q5 if err)
            denied_ratio_5m = denied_5m / max(1, burst_5m)
        else:
            burst_1m = 1
            burst_5m = 1
            service_breadth_5m = 1
            denied_ratio_5m = 1.0 if (is_denied or is_failed) else 0.0

        feature_rows.append([
            1.0 if category == "invoke" else 0.0,
            1.0 if category == "assume_role" else 0.0,
            1.0 if category == "in_scope_downstream" else 0.0,
            1.0 if category == "control_plane" else 0.0,
            1.0 if is_failed else 0.0,
            1.0 if is_sensitive else 0.0,
            math.log1p(burst_1m),
            math.log1p(burst_5m),
            math.log1p(service_breadth_5m),
            round(denied_ratio_5m, 6),
        ])

        entry = agg.get(fn_name)
        dt_iso = dt.isoformat().replace("+00:00", "Z") if dt is not None else str(ev.get("event_time") or "")
        if entry is None:
            entry = {
                "function_name": fn_name,
                "function_arn": fn_arn,
                "region": region,
                "telemetry_source": "cloudtrail",
                "invoke_count": 0,
                "assume_role_count": 0,
                "in_scope_downstream_count": 0,
                "control_plane_count": 0,
                "total_events": 0,
                "peak_burst_1m": 0,
                "peak_burst_5m": 0,
                "error_count": 0,
                "access_denied_count": 0,
                "downstream_services": set(),
                "sensitive_action_count": 0,
                "sensitive_actions": set(),
                "invocation_types": set(),
                "last_caller": caller,
                "first_seen": dt_iso,
                "last_invoked": dt_iso,
            }
            agg[fn_name] = entry

        if fn_arn and not entry["function_arn"]:
            entry["function_arn"] = fn_arn
        if region != "unknown" and entry["region"] == "unknown":
            entry["region"] = region

        entry["total_events"] += 1
        if category == "invoke":
            entry["invoke_count"] += 1
        elif category == "assume_role":
            entry["assume_role_count"] += 1
        elif category == "in_scope_downstream":
            entry["in_scope_downstream_count"] += 1
            entry["downstream_services"].add(source.replace(".amazonaws.com", ""))
        elif category == "control_plane":
            entry["control_plane_count"] += 1

        if burst_1m > entry["peak_burst_1m"]:
            entry["peak_burst_1m"] = burst_1m
        if burst_5m > entry["peak_burst_5m"]:
            entry["peak_burst_5m"] = burst_5m

        if is_failed:
            entry["error_count"] += 1
        if is_denied:
            entry["access_denied_count"] += 1
        if is_sensitive:
            entry["sensitive_action_count"] += 1
            entry["sensitive_actions"].add(action)

        rp = _as_dict(ev.get("requestParameters") or raw.get("requestParameters"))
        inv_type = str(rp.get("invocationType") or "").strip()
        if inv_type:
            entry["invocation_types"].add(inv_type)

        if dt_iso and (not entry["first_seen"] or dt_iso < entry["first_seen"]):
            entry["first_seen"] = dt_iso
        if dt_iso and (not entry["last_invoked"] or dt_iso >= entry["last_invoked"]):
            entry["last_invoked"] = dt_iso
            entry["last_caller"] = caller

    functions: List[Dict[str, Any]] = []
    for entry in agg.values():
        total_ev = entry["total_events"]
        err_rate = round((entry["error_count"] / max(1, total_ev)) * 100.0, 2)
        downstream_list = sorted(entry["downstream_services"])
        anomaly_flag = bool(entry["access_denied_count"] > 0 or err_rate >= 5.0)
        functions.append({
            "function_name": entry["function_name"],
            "function_arn": entry["function_arn"],
            "region": entry["region"],
            "telemetry_source": "cloudtrail",
            "invoke_count": entry["invoke_count"],
            "assume_role_count": entry["assume_role_count"],
            "in_scope_downstream_count": entry["in_scope_downstream_count"],
            "control_plane_count": entry["control_plane_count"],
            "total_events": total_ev,
            "peak_burst_1m": entry["peak_burst_1m"],
            "peak_burst_5m": entry["peak_burst_5m"],
            "error_count": entry["error_count"],
            "access_denied_count": entry["access_denied_count"],
            "error_rate_pct": err_rate,
            "downstream_services": downstream_list,
            "downstream_service_breadth": len(downstream_list),
            "sensitive_action_count": entry["sensitive_action_count"],
            "sensitive_actions": sorted(entry["sensitive_actions"])[:10],
            "invocation_types": sorted(entry["invocation_types"]),
            "last_caller": entry["last_caller"],
            "first_seen": entry["first_seen"],
            "last_invoked": entry["last_invoked"],
            "anomaly_flag": anomaly_flag,
            "avg_duration_ms": None,
            "memory_mb": None,
            "cold_start_rate": None,
            "missing_telemetry_fields": ["avg_duration_ms", "memory_mb", "cold_start_rate"],
            "telemetry_note": "Unavailable in CloudTrail: execution duration, memory allocation, and cold-start rate require CloudWatch Logs / Lambda configuration APIs.",
        })

    functions.sort(key=lambda item: (-item["total_events"], item["function_name"]))
    elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

    return {
        "features_extracted": FAAS_FEATURES,
        "feature_matrix_shape": [len(feature_rows), len(FAAS_FEATURES)],
        "summary": {
            "total_events_scanned": len(events),
            "faas_events_detected": len(classified),
            "invoke_events": category_totals["invoke"],
            "assume_role_events": category_totals["assume_role"],
            "in_scope_downstream_events": category_totals["in_scope_downstream"],
            "control_plane_events": category_totals["control_plane"],
            "unique_functions": len(functions),
            "total_errors": total_errors,
            "total_access_denied": total_access_denied,
            "processing_ms": elapsed_ms,
        },
        "functions": functions,
    }
