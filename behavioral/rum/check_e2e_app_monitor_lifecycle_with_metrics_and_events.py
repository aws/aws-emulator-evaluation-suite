"""e2e-app-monitor-lifecycle-with-metrics-and-events."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-app-monitor-lifecycle-with-metrics-and-events"
GROUP = "e2e"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An app monitor with a CloudWatch metrics destination and a metric definition receives RUM
    events seen by GetAppMonitorData, and after teardown the definitions, destination and monitor
    are each gone.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-e2e-")

    created = rum.create_app_monitor(
        Name=name,
        Domain="example.com",
        CwLogEnabled=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-e2e"},
    )
    monitor_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))

    monitor = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert monitor["Id"] == monitor_id
    assert monitor["State"] == "CREATED"

    # Attach a CloudWatch metrics destination.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(lambda: _safe_delete_destination(rum, name))
    destinations = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert any(d["Destination"] == "CloudWatch" for d in destinations)

    # Define a custom metric derived from JS-error events (a custom Namespace+Name avoids
    # colliding with the reserved built-in extended-metric name "JsErrorCount").
    namespace = ctx.unique_name("sim2real-rum-ns-").replace("-", "_")
    metric_name = "CustomJsErrorCount"
    event_pattern = json.dumps({"event_type": ["com.amazon.rum.js_error_event"]})
    create_resp = _batch_create_with_retry(
        rum,
        app_name=name,
        destination="CloudWatch",
        metric_definitions=[
            {"Name": metric_name, "Namespace": namespace, "EventPattern": event_pattern}
        ],
    )
    err_code = create_resp["Errors"][0]["ErrorCode"] if create_resp.get("Errors") else None
    assert err_code is None, err_code
    assert len(create_resp.get("MetricDefinitions", [])) == 1, create_resp
    metric_definition_id = create_resp["MetricDefinitions"][0]["MetricDefinitionId"]
    ctx.on_cleanup(lambda: _safe_delete_metric_definitions(rum, name, [metric_definition_id]))

    # The definition list must reflect what was just created (control plane read-your-writes).
    defs = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
        "MetricDefinitions"
    ]
    matching = [d for d in defs if d["MetricDefinitionId"] == metric_definition_id]
    assert len(matching) == 1
    assert matching[0]["Name"] == metric_name
    assert json.loads(matching[0]["EventPattern"]) == json.loads(event_pattern)

    # Submit an actual RUM event of the kind the metric definition targets.
    batch_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())
    rum.put_rum_events(
        Id=monitor_id,
        BatchId=batch_id,
        AppMonitorDetails={"id": monitor_id, "name": name, "version": "1.0.0"},
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": event_id,
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.js_error_event",
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com"}),
                "details": json.dumps(
                    {
                        "version": "1.0.0",
                        "type": "Error",
                        "message": "e2e-behavioral-check",
                        "filename": "https://example.com/app.js",
                        "lineno": 1,
                        "colno": 1,
                    }
                ),
            }
        ],
    )

    found = _poll_for_event(ctx, name, event_id, timeout_s=200.0, interval_s=10.0)
    if not found:
        raise AssertionError(
            f"event {event_id} submitted via PutRumEvents never surfaced via "
            "GetAppMonitorData within the poll window; the RUM data-plane ingestion "
            "pipeline may have latency beyond what this check budgets. The control-plane "
            "assertions above (metric definition created/read-your-writes, destination "
            "wiring) already exercise real, non-stub state."
        )

    # Tear down and confirm every child resource is actually gone (not just a 200 delete).
    rum.batch_delete_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[metric_definition_id]
    )
    remaining_defs = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")[
        "MetricDefinitions"
    ]
    assert not any(d["MetricDefinitionId"] == metric_definition_id for d in remaining_defs)

    rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    remaining_destinations = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert not any(d["Destination"] == "CloudWatch" for d in remaining_destinations)

    rum.delete_app_monitor(Name=name)
    _poll_until_monitor_gone(ctx, name, timeout_s=60.0, interval_s=3.0)


def _batch_create_with_retry(
    rum,
    *,
    app_name: str,
    destination: str,
    metric_definitions: list,
    attempts: int = 8,
    delay: float = 2.0,
) -> dict:
    """BatchCreateRumMetricDefinitions can return an empty MetricDefinitions/Errors
    response for a brief window right after PutRumMetricsDestination while the
    destination registration propagates -- while the create can still have actually
    landed server-side. Poll until we observe a real outcome (either a created
    definition or a per-item error). If a retry then reports ConflictException for a
    name we just tried to create, that confirms an earlier attempt DID land despite an
    empty-looking response; resolve it by looking the definition up instead of failing."""
    last: dict = {}
    for _ in range(attempts):
        resp = rum.batch_create_rum_metric_definitions(
            AppMonitorName=app_name,
            Destination=destination,
            MetricDefinitions=metric_definitions,
        )
        errors = resp.get("Errors", [])
        if errors and all(e.get("ErrorCode") == "ConflictException" for e in errors):
            existing = rum.batch_get_rum_metric_definitions(
                AppMonitorName=app_name, Destination=destination
            )["MetricDefinitions"]
            wanted_names = {d["Name"] for d in metric_definitions}
            resolved = [d for d in existing if d["Name"] in wanted_names]
            if len(resolved) == len(metric_definitions):
                return {"MetricDefinitions": resolved, "Errors": []}
        if resp.get("MetricDefinitions") or resp.get("Errors"):
            return resp
        last = resp
        time.sleep(delay)
    return last


_SUCCEEDED = "<no error: the call succeeded>"


def _error_code(fn):
    """Call fn(); return its error code, or _SUCCEEDED (which no code equals)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return _SUCCEEDED


def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_destination(rum, name: str) -> None:
    try:
        rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_metric_definitions(rum, name: str, ids: list[str]) -> None:
    if not ids:
        return
    try:
        rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=ids
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_for_event(ctx, monitor_name: str, event_id: str, *, timeout_s: float, interval_s: float) -> bool:
    rum = ctx.client("rum")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        now_ms = int(time.time() * 1000)
        next_token = None
        while True:
            kwargs = {
                "Name": monitor_name,
                "TimeRange": {"After": now_ms - 3_600_000, "Before": now_ms + 3_600_000},
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = rum.get_app_monitor_data(**kwargs)
            for raw_event in resp.get("Events", []):
                if event_id in raw_event:
                    return True
            next_token = resp.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return False


def _poll_until_monitor_gone(ctx, name: str, *, timeout_s: float, interval_s: float) -> None:
    rum = ctx.client("rum")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        code = _error_code(lambda: rum.get_app_monitor(Name=name))
        if code == "ResourceNotFoundException":
            return
        last_code = code
        time.sleep(interval_s)
    raise AssertionError(f"app monitor {name} not fully deleted within {timeout_s}s (last: {last_code})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
