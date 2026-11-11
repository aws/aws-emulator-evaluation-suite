"""batch-delete-metric-definition-removes-it."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "batch-delete-metric-definition-removes-it"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After BatchDeleteRumMetricDefinitions, the deleted definition no longer appears in
    BatchGetRumMetricDefinitions results, while a sibling definition created in the same
    batch remains untouched.
    """
    rum = ctx.client("rum")
    app_name = _create_app_monitor(ctx)
    rum.put_rum_metrics_destination(AppMonitorName=app_name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(
            AppMonitorName=app_name, Destination="CloudWatch"
        )
    )

    namespace = ctx.unique_name("sim2real-rum-ns-").replace("-", "_")
    keep_def = {
        "Name": "KeepMetric",
        "Namespace": namespace,
        "EventPattern": json.dumps({"event_type": ["com.amazon.rum.js_error_event"]}),
    }
    drop_def = {
        "Name": "DropMetric",
        "Namespace": namespace,
        "EventPattern": json.dumps({"event_type": ["com.amazon.rum.http_event"]}),
    }
    created = _batch_create_and_resolve(
        rum, app_name=app_name, destination="CloudWatch", metric_definitions=[keep_def, drop_def]
    )
    errs = created.get("Errors", [])
    assert errs == [], f"codes={[e.get('ErrorCode') for e in errs]!r} msgs={[e.get('ErrorMessage') for e in errs]!r}"
    ids_by_name = {d["Name"]: d["MetricDefinitionId"] for d in created["MetricDefinitions"]}
    keep_id = ids_by_name["KeepMetric"]
    drop_id = ids_by_name["DropMetric"]

    deleted = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=app_name,
        Destination="CloudWatch",
        MetricDefinitionIds=[drop_id],
    )
    assert deleted.get("Errors", []) == [], f"unexpected errors: {deleted.get('Errors')}"

    fetched = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app_name, Destination="CloudWatch"
    )
    remaining_ids = {d["MetricDefinitionId"] for d in fetched["MetricDefinitions"]}
    assert drop_id not in remaining_ids, "deleted metric definition still present"
    assert keep_id in remaining_ids, "sibling metric definition was incorrectly removed"

    redelete = rum.batch_delete_rum_metric_definitions(
        AppMonitorName=app_name,
        Destination="CloudWatch",
        MetricDefinitionIds=[drop_id],
    )
    redelete_errs = redelete.get("Errors", [])
    assert len(redelete_errs) == 1 and redelete_errs[0].get("MetricDefinitionId") == drop_id, (
        f"deleting the already-gone id should report it, got {redelete_errs!r}"
    )
    assert redelete_errs[0].get("ErrorCode") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the dead id, got {redelete_errs[0]!r}"
    )
    assert redelete_errs[0].get("ErrorMessage") == "Resource not found", (
        f"expected ErrorMessage 'Resource not found' for the dead id, got {redelete_errs[0]!r}"
    )


def _create_app_monitor(ctx: Any) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-app-")
    rum.create_app_monitor(
        Name=name,
        Domain="sim2real.example.com",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-app"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    return name


def _batch_create_and_resolve(
    rum: Any,
    *,
    app_name: str,
    destination: str,
    metric_definitions: list,
    attempts: int = 10,
    delay: float = 2.0,
) -> dict:
    """BatchCreateRumMetricDefinitions can return an empty MetricDefinitions/Errors
    response for a brief window right after PutRumMetricsDestination while the
    destination registration propagates -- even though the definition IS created
    server-side (re-issuing the same create afterwards yields ConflictException,
    proving it landed). So: issue the create exactly once, and if the immediate
    response is inconclusive (no MetricDefinitions, no Errors), poll
    BatchGetRumMetricDefinitions for the named definitions instead of re-creating.
    """
    import time

    resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app_name,
        Destination=destination,
        MetricDefinitions=metric_definitions,
    )
    if resp.get("MetricDefinitions") or resp.get("Errors"):
        return resp

    wanted_names = {d["Name"] for d in metric_definitions}
    for _ in range(attempts):
        time.sleep(delay)
        fetched = rum.batch_get_rum_metric_definitions(
            AppMonitorName=app_name, Destination=destination
        )
        found = [d for d in fetched.get("MetricDefinitions", []) if d["Name"] in wanted_names]
        if len(found) == len(wanted_names):
            return {"MetricDefinitions": found, "Errors": []}
    return {"MetricDefinitions": [], "Errors": []}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
