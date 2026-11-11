"""update-metric-definition-changes-filter-persists."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags

CHECK = "update-metric-definition-changes-filter-persists"
GROUP = "telemetry"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRumMetricDefinition mutates the definition's EventPattern (filter) and
    DimensionKeys, and the change is visible on the next BatchGetRumMetricDefinitions.
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
    original_pattern = {"event_type": ["com.amazon.rum.js_error_event"]}
    created = _batch_create_and_resolve(
        rum,
        app_name=app_name,
        destination="CloudWatch",
        metric_definitions=[
            {
                "Name": "MutableMetric",
                "Namespace": namespace,
                "EventPattern": json.dumps(original_pattern),
            }
        ],
    )
    assert created.get("Errors", []) == [], f"unexpected errors: {created.get('Errors')}"
    definition_id = created["MetricDefinitions"][0]["MetricDefinitionId"]

    updated_pattern = {
        "event_type": ["com.amazon.rum.http_event"],
        "metadata": {"browserName": ["Chrome"]},
    }
    rum.update_rum_metric_definition(
        AppMonitorName=app_name,
        Destination="CloudWatch",
        MetricDefinitionId=definition_id,
        MetricDefinition={
            "Name": "MutableMetric",
            "Namespace": namespace,
            "EventPattern": json.dumps(updated_pattern),
            "DimensionKeys": {"metadata.browserName": "Browser"},
        },
    )

    fetched = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app_name, Destination="CloudWatch"
    )
    matches = [
        d for d in fetched["MetricDefinitions"] if d["MetricDefinitionId"] == definition_id
    ]
    assert len(matches) == 1, (
        f"expected exactly one definition {definition_id} in BatchGet, "
        f"got {[d['MetricDefinitionId'] for d in fetched['MetricDefinitions']]}"
    )
    got = matches[0]
    assert json.loads(got["EventPattern"]) == updated_pattern, (
        f"EventPattern did not persist: expected {updated_pattern}, "
        f"got {json.loads(got['EventPattern'])}"
    )
    assert got.get("DimensionKeys") == {"metadata.browserName": "Browser"}, (
        f"DimensionKeys did not persist: expected "
        f"{{'metadata.browserName': 'Browser'}}, got {got.get('DimensionKeys')}"
    )


def _create_app_monitor(ctx: Any) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-app-")
    rum.create_app_monitor(Name=name, Domain="sim2real.example.com", Tags={"Team": "rum-fidelity"})
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
    raise AssertionError(
        f"BatchCreate for {wanted_names} in {app_name}/{destination} was still "
        f"inconclusive (no MetricDefinitions/Errors) and never became visible via "
        f"BatchGet within {attempts * delay}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
