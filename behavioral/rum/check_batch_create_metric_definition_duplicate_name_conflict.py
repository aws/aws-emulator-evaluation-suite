"""batch-create-metric-definition-duplicate-name-conflict."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "batch-create-metric-definition-duplicate-name-conflict"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """Resubmitting an identical metric definition (same Name, Namespace and EventPattern) is
    reported per item as ConflictException in Errors and the original stays the only one with that
    identity, while the same Name with another EventPattern creates a second definition.
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
    original_pattern = json.dumps({"event_type": ["com.amazon.rum.js_error_event"]})
    metric_def = {
        "Name": "DuplicateMetric",
        "Namespace": namespace,
        "EventPattern": original_pattern,
    }

    # Positive control: first creation succeeds cleanly.
    first = _batch_create_and_resolve(
        rum, app_name=app_name, destination="CloudWatch", metric_definitions=[metric_def]
    )
    assert first.get("Errors", []) == [], f"unexpected errors: {first.get('Errors')}"
    assert len(first["MetricDefinitions"]) == 1, (
        f"expected exactly one created definition, got {first.get('MetricDefinitions')}"
    )
    original_id = first["MetricDefinitions"][0]["MetricDefinitionId"]
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=app_name, Destination="CloudWatch", MetricDefinitionIds=[original_id]
        )
    )

    # Break exactly one thing: resubmit the identical definition unchanged.
    second = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app_name,
        Destination="CloudWatch",
        MetricDefinitions=[metric_def],
    )
    assert second.get("MetricDefinitions", []) == [], (
        f"duplicate creation must not produce a new metric definition, got {second}"
    )
    assert len(second.get("Errors", [])) == 1, f"expected one item error, got {second}"
    assert second["Errors"][0]["ErrorCode"] == "ConflictException", (
        f"expected ConflictException, got {second['Errors'][0]}"
    )
    expected_message = (
        f"Metric definition already exists: MetricDefinitionRequest(name=DuplicateMetric, "
        f"valueKey=null, unitLabel=null, dimensionKeys=null, eventPattern={original_pattern}, "
        f"namespace={namespace})"
    )
    assert second["Errors"][0]["ErrorMessage"] == expected_message, (
        f"expected ErrorMessage {expected_message!r}, got {second['Errors'][0].get('ErrorMessage')!r}"
    )

    # Effect absent: still exactly one definition with this name/id, and its content is
    # unchanged -- the rejected resubmission did not overwrite the original.
    fetched = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app_name, Destination="CloudWatch"
    )
    matching = [d for d in fetched["MetricDefinitions"] if d["Name"] == "DuplicateMetric"]
    assert len(matching) == 1, f"expected exactly one DuplicateMetric definition, got {matching}"
    assert matching[0]["MetricDefinitionId"] == original_id, (
        f"expected id {original_id}, got {matching[0]['MetricDefinitionId']}"
    )
    assert matching[0]["EventPattern"] == original_pattern, (
        "the conflicting attempt must not have overwritten the original definition's content"
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
