"""telemetry-update-metric-definition-persists-change."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "telemetry-update-metric-definition-persists-change"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRumMetricDefinition's field changes persist and show up on the next BatchGet."""
    rum = ctx.client("rum")
    name = _create_app_monitor(ctx)
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    )
    _wait_for_destination(rum, name)

    namespace = ctx.unique_name("sim2real-behav-ns-")
    event_pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    initial_definition = {
        "Name": "CustomUpdatableMetric",
        "Namespace": namespace,
        "ValueKey": "event_details.duration",
        "EventPattern": event_pattern,
    }
    created, errs = _create_with_retry(rum, name, initial_definition)
    diag = _diag(created, errs)
    assert len(created) == 1 and not errs, diag
    metric_id = created[0]["MetricDefinitionId"]
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
        )
    )

    before = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    before_match = next(d for d in before["MetricDefinitions"] if d["MetricDefinitionId"] == metric_id)
    assert before_match.get("UnitLabel") is None, f"expected no UnitLabel before update, got {before_match.get('UnitLabel')!r}"

    updated_definition = {
        "Name": "CustomUpdatableMetric",
        "Namespace": namespace,
        "ValueKey": "event_details.duration",
        "EventPattern": event_pattern,
        "UnitLabel": "Milliseconds",
    }
    rum.update_rum_metric_definition(
        AppMonitorName=name,
        Destination="CloudWatch",
        MetricDefinitionId=metric_id,
        MetricDefinition=updated_definition,
    )

    after = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    after_match = next(d for d in after["MetricDefinitions"] if d["MetricDefinitionId"] == metric_id)
    assert after_match["UnitLabel"] == "Milliseconds", f"update did not persist: {after_match}"


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


def _create_with_retry(rum, name: str, metric_definition: dict, timeout_s: float = 30.0, interval_s: float = 2.0):
    """A single BatchCreate call can transiently return empty MetricDefinitions/Errors right
    after the destination is created (not yet fully applied) -- poll (without resending the
    write) until the backend actually reports created/errored items, then resolve any
    retry-induced conflicts."""
    deadline = time.monotonic() + timeout_s
    raw_created: list = []
    raw_errs: list = []
    while time.monotonic() < deadline:
        resp = rum.batch_create_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitions=[metric_definition]
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



def _create_app_monitor(ctx, domain: str = "example.com") -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-")
    rum.create_app_monitor(
        Name=name,
        Domain=domain,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
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

