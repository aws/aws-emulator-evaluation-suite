"""batch-create-metric-definitions-malformed-namespace-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "batch-create-metric-definitions-malformed-namespace-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchCreateRumMetricDefinitions with a custom metric in the reserved AWS/RUM namespace is
    refused as a whole with ValidationException, while a valid definition in its own call is created
    and persists.
    """
    from botocore.exceptions import ClientError

    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-metrics-")
    rum.create_app_monitor(
        Name=name,
        Domain="localhost",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-metrics"},
    )
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))

    # A metrics destination must exist before any metric definitions can be
    # created against this app monitor.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch"))

    good_name = "GoodCustomMetric"
    bad_name = "BadCustomMetric"
    good_pattern = json.dumps({"event_type": ["com.amazon.rum.js_error_event"]})

    bad_definition = {
        "Name": bad_name,
        # Custom metrics must NOT use the reserved AWS/RUM namespace -- that
        # namespace is reserved for extended (built-in) metrics with a fixed
        # set of recognized metric names, so this whole request is rejected.
        "Namespace": "AWS/RUM",
        "EventPattern": good_pattern,
    }
    good_definition = {
        "Name": good_name,
        "Namespace": "sim2real/CustomNamespace",
        "EventPattern": good_pattern,
    }

    # Negative: the malformed namespace usage is rejected for the whole call.
    try:
        result = rum.batch_create_rum_metric_definitions(
            AppMonitorName=name,
            Destination="CloudWatch",
            MetricDefinitions=[bad_definition],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"expected a ValidationException, but the call succeeded: {result!r}")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f"Metric value {bad_name} is not valid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absence: nothing was persisted from the rejected request.
    persisted = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    persisted_names = {d["Name"] for d in persisted["MetricDefinitions"]}
    assert bad_name not in persisted_names, f"rejected definition {bad_name!r} was persisted: {persisted_names}"

    # Positive control: the same shape of request, but with a valid custom
    # namespace, succeeds and is (eventually) persisted. Creation is
    # asynchronous: the create call itself can return with neither an entry
    # in MetricDefinitions nor in Errors (an empty ack), so confirm the
    # effect by polling BatchGetRumMetricDefinitions with bounded retries
    # instead of retrying the create call (which would otherwise collide
    # with the already-in-flight create and surface a spurious
    # ConflictException).
    import time

    resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=name,
        Destination="CloudWatch",
        MetricDefinitions=[good_definition],
    )
    assert resp["Errors"] == [], repr([e.get("ErrorCode") for e in resp["Errors"]])

    match = None
    for d in resp["MetricDefinitions"]:
        if d["Name"] == good_name:
            match = d
    if match is None:
        for _ in range(6):
            fetched = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
            match = next((d for d in fetched["MetricDefinitions"] if d["Name"] == good_name), None)
            if match is not None:
                break
            time.sleep(5)
    assert match is not None, "GoodCustomMetric never appeared after create"
    metric_id = match["MetricDefinitionId"]
    ctx.on_cleanup(
        lambda: rum.batch_delete_rum_metric_definitions(
            AppMonitorName=name, Destination="CloudWatch", MetricDefinitionIds=[metric_id]
        )
    )

    persisted = rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    persisted_names = {d["Name"] for d in persisted["MetricDefinitions"]}
    assert good_name in persisted_names, f"valid definition {good_name!r} never persisted: {persisted_names}"
    assert bad_name not in persisted_names, f"rejected definition {bad_name!r} was persisted: {persisted_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
