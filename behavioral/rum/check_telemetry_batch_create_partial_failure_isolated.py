"""telemetry-batch-create-partial-failure-isolated."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "telemetry-batch-create-partial-failure-isolated"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A mixed-validity BatchCreate applies the valid definition and reports a per-item
    error for the invalid one, with no all-or-nothing rollback."""
    rum = ctx.client("rum")
    name = _create_app_monitor(ctx)
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    )
    _wait_for_destination(rum, name)

    valid_namespace = ctx.unique_name("sim2real-behav-ns-valid-")
    event_pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    valid_definition = {
        "Name": "ValidCustomMetric",
        "Namespace": valid_namespace,
        "EventPattern": event_pattern,
    }
    # ValueKey must reference one of RUM's fixed first-level event fields (event_details,
    # metadata, user_details, ...); "not_a_real_field" is never valid, so this is a per-item
    # validation failure, not a whole-request rejection.
    invalid_namespace = ctx.unique_name("sim2real-behav-ns-invalid-")
    invalid_definition = {
        "Name": "InvalidCustomMetric",
        "Namespace": invalid_namespace,
        "ValueKey": "not_a_real_field.value",
        "EventPattern": event_pattern,
    }

    created, errors = _create_with_retry(rum, name, [valid_definition, invalid_definition])
    created, errors = _reconcile_missing(
        rum, name, [valid_definition, invalid_definition], created, errors
    )
    diag = _diag(created, errors)
    assert len(created) == 1, diag
    assert created[0]["Name"] == "ValidCustomMetric", (
        f"expected the sole created definition to be ValidCustomMetric, got {created[0]['Name']!r}"
    )
    metric_id = created[0]["MetricDefinitionId"]
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
        )
    )

    assert len(errors) == 1, f"expected exactly one per-item error, got {errors}"
    assert errors[0]["MetricDefinition"]["Name"] == "InvalidCustomMetric", (
        f"expected the sole per-item error to name InvalidCustomMetric, "
        f"got {errors[0]['MetricDefinition'].get('Name')!r}"
    )

    got = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    names = {d["Name"] for d in got["MetricDefinitions"]}
    assert "ValidCustomMetric" in names, "the valid definition did not persist"
    assert "InvalidCustomMetric" not in names, "the invalid definition should never have persisted"


def _diag(created: list, errs: list) -> str:
    if errs:
        e0 = errs[0]
        return f"n={len(created)}/{len(errs)} code={e0.get('ErrorCode')} msg={e0.get('ErrorMessage', '')[:50]}"
    return f"n={len(created)}/{len(errs)}"


def _wait_for_destination(rum, name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """PutRumMetricsDestination can lag before ListRumMetricsDestinations reflects it, and
    BatchCreateRumMetricDefinitions silently no-ops (empty MetricDefinitions/Errors) if the
    destination isn't visible yet -- so poll for it before creating definitions."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        dests = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
        if any(d["Destination"] == "CloudWatch" for d in dests):
            return
        time.sleep(interval_s)
    raise AssertionError(f"destination for {name} never became visible within {timeout_s}s")


def _create_with_retry(rum, name: str, definitions: list, timeout_s: float = 30.0, interval_s: float = 2.0):
    """A single BatchCreate call can transiently return empty MetricDefinitions/Errors right
    after the destination is created (not yet fully applied) -- poll (without resending the
    write) until the backend actually reports created/errored items, then resolve any
    retry-induced conflicts."""
    deadline = time.monotonic() + timeout_s
    raw_created: list = []
    raw_errs: list = []
    while time.monotonic() < deadline:
        resp = rum.batch_create_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitions=definitions
        )
        raw_created = resp.get("MetricDefinitions", [])
        raw_errs = resp.get("Errors", [])
        if raw_created or raw_errs:
            return _resolve_conflicts(rum, name, raw_created, raw_errs)
        time.sleep(interval_s)
    return raw_created, raw_errs


def _resolve_conflicts(rum, name: str, created: list, errs: list) -> tuple:
    """The SDK's own transparent retry-on-throttle can resend an already-applied
    BatchCreate, so a definition can come back as a ConflictException even though it was
    truly created by an earlier (unobserved) attempt. Treat 'already exists' as success by
    looking the definition up via BatchGet, and only keep genuine validation errors."""
    resolved_created = list(created)
    resolved_errs = []
    for e in errs:
        if e.get("ErrorCode") == "ConflictException":
            d = e.get("MetricDefinition", {}) or {}
            got = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
            match = next(
                (
                    g
                    for g in got["MetricDefinitions"]
                    if g["Name"] == d.get("Name") and g.get("Namespace") == d.get("Namespace")
                ),
                None,
            )
            if match is not None:
                resolved_created.append(match)
                continue
        resolved_errs.append(e)
    return resolved_created, resolved_errs


def _reconcile_missing(
    rum, name: str, definitions: list, created: list, errs: list, timeout_s: float = 30.0, interval_s: float = 2.0
) -> tuple:
    """In a multi-item BatchCreate, the immediate response can omit an item that actually
    succeeded (neither in MetricDefinitions nor in Errors) if its application lags behind
    the response -- poll BatchGet for any item unaccounted for by either list before
    concluding it was dropped."""

    def key(d):
        return (d.get("Name"), d.get("Namespace"))

    accounted = {key(c) for c in created} | {key(e.get("MetricDefinition", {}) or {}) for e in errs}
    missing = [d for d in definitions if key(d) not in accounted]
    if not missing:
        return created, errs
    resolved_created = list(created)
    still_missing = list(missing)
    deadline = time.monotonic() + timeout_s
    while still_missing and time.monotonic() < deadline:
        got = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")["MetricDefinitions"]
        found_now = [d for d in still_missing if any(key(g) == key(d) for g in got)]
        for d in found_now:
            match = next(g for g in got if key(g) == key(d))
            resolved_created.append(match)
            still_missing.remove(d)
        if still_missing:
            time.sleep(interval_s)
    return resolved_created, errs


def _create_app_monitor(ctx, domain: str = "example.com") -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(Name=name, Domain=domain)
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))
    return name


def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

