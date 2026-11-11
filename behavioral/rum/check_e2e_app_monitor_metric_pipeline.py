"""e2e-app-monitor-metric-pipeline."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "e2e-app-monitor-metric-pipeline"
GROUP = "e2e"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An app monitor ingests an event and carries a live custom metric definition and destination,
    which are gone after their deletes, and the monitor itself is gone after DeleteAppMonitor.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-e2e-")
    app_monitor_id = rum.create_app_monitor(Name=name, Domain="localhost")["Id"]
    deleted = {"value": False}
    ctx.on_cleanup(
        lambda: _safe(lambda: rum.delete_app_monitor(Name=name)) if not deleted["value"] else None
    )

    # 1. Ingest a real data-plane event.
    rum.put_rum_events(
        Id=app_monitor_id,
        BatchId=str(uuid.uuid4()),
        AppMonitorDetails={"id": app_monitor_id, "name": name, "version": "1.0.0"},
        UserDetails={"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        RumEvents=[
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.custom_event",
                "details": json.dumps({"message": "sim2real-e2e"}),
                "metadata": json.dumps({"version": "1.0.0", "domain": "localhost"}),
            }
        ],
    )

    # 2. Wire a metrics destination.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    destinations = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert any(d["Destination"] == "CloudWatch" for d in destinations), destinations

    # 3. Define a custom extracted metric routed to that destination.
    namespace = ctx.unique_name("Sim2RealPipelineNS")
    event_pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    metric_definition = {
        "Name": "sim2realPipelineMetric",
        "Namespace": namespace,
        "EventPattern": event_pattern,
    }
    create_resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=name,
        Destination="CloudWatch",
        MetricDefinitions=[metric_definition],
    )
    metric_id = _resolve_metric_id(
        rum,
        create_resp,
        app_monitor_name=name,
        destination="CloudWatch",
        expected_name="sim2realPipelineMetric",
        expected_namespace=namespace,
    )

    # 4. Observe the definition is live via the read path.
    get_resp = rum.batch_get_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch"
    )
    found = [
        d for d in get_resp["MetricDefinitions"] if d["MetricDefinitionId"] == metric_id
    ]
    assert len(found) == 1, get_resp["MetricDefinitions"]
    assert found[0]["Namespace"] == namespace, (metric_id, namespace, found[0])

    # 5. Tear the app monitor down, asserting each child resource is actually gone
    # (not just a 200 delete) before confirming the monitor itself is removed.
    rum.batch_delete_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
    )
    remaining_defs = rum.batch_get_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch"
    )["MetricDefinitions"]
    assert not any(d["MetricDefinitionId"] == metric_id for d in remaining_defs), remaining_defs

    rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    remaining_dests = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert not any(d["Destination"] == "CloudWatch" for d in remaining_dests), remaining_dests

    rum.delete_app_monitor(Name=name)
    deleted["value"] = True

    code, message = _poll_for_error(
        lambda: rum.get_app_monitor(Name=name), timeout_s=60.0, interval_s=3.0
    )
    assert code == "ResourceNotFoundException", (
        f"app monitor was never fully removed after DeleteAppMonitor, got {code!r}"
    )
    assert message == f"Resource not found {name}", message


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_for_error(fn, *, timeout_s: float, interval_s: float):
    """Poll until fn() is refused; return the (code, message). A success keeps polling until the
    deadline, then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _client_error(fn)
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(f"call was not refused within {timeout_s}s: {exc}") from None
        time.sleep(interval_s)


def _resolve_metric_id(rum, create_resp, *, app_monitor_name, destination, expected_name, expected_namespace):
    """BatchCreateRumMetricDefinitions has been observed to (a) return the created
    MetricDefinition directly, (b) report a ConflictException 'already exists' for the
    very definition it just (successfully) created, or (c) return empty
    MetricDefinitions/Errors lists for a create that nonetheless took effect. Resolve the
    id robustly via the read path (BatchGetRumMetricDefinitions) instead of assuming any
    one of those response shapes."""
    metric_defs = create_resp.get("MetricDefinitions") or []
    if metric_defs:
        return metric_defs[0]["MetricDefinitionId"]

    errors = create_resp.get("Errors") or []
    non_conflict = [e for e in errors if e.get("ErrorCode") != "ConflictException"]
    assert not non_conflict, f"BatchCreateRumMetricDefinitions reported errors: {non_conflict!r}"

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        get_resp = rum.batch_get_rum_metric_definitions(
            AppMonitorName=app_monitor_name, Destination=destination
        )
        for d in get_resp.get("MetricDefinitions", []):
            if d["Name"] == expected_name and d.get("Namespace") == expected_namespace:
                return d["MetricDefinitionId"]
        time.sleep(3.0)
    raise AssertionError(
        f"Metric definition {expected_name!r}/{expected_namespace!r} was not observable via "
        f"BatchGetRumMetricDefinitions after BatchCreateRumMetricDefinitions returned {create_resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
