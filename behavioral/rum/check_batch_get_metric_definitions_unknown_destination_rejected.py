"""batch-get-metric-definitions-unknown-destination-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-get-metric-definitions-unknown-destination-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetRumMetricDefinitions against a non-existent app monitor name raises
    ResourceNotFoundException, while the same call against a real app monitor with a
    real destination and metric definition continues to succeed (positive control).
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
    created = _batch_create_and_resolve(
        rum,
        app_name=app_name,
        destination="CloudWatch",
        metric_definitions=[
            {
                "Name": "ControlMetric",
                "Namespace": namespace,
                "EventPattern": json.dumps({"event_type": ["com.amazon.rum.js_error_event"]}),
            }
        ],
    )
    assert created.get("Errors", []) == [], f"unexpected errors: {created.get('Errors')}"
    definition_id = created["MetricDefinitions"][0]["MetricDefinitionId"]

    bogus_app_name = ctx.unique_name("sim2real-rum-nonexistent-")
    code, message = _client_error(
        lambda: rum.batch_get_rum_metric_definitions(
            AppMonitorName=bogus_app_name, Destination="CloudWatch"
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Resource not found {bogus_app_name}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the real app monitor / destination pair is unaffected.
    fetched = rum.batch_get_rum_metric_definitions(
        AppMonitorName=app_name, Destination="CloudWatch"
    )
    ids = {d["MetricDefinitionId"] for d in fetched["MetricDefinitions"]}
    assert definition_id in ids, (
        f"expected {definition_id!r} in {ids!r} after the rejected call against a "
        "nonexistent app monitor"
    )


def _create_app_monitor(ctx: Any) -> str:
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-app-")
    rum.create_app_monitor(
        Name=name, Domain="sim2real.example.com", Tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    return name


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


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
