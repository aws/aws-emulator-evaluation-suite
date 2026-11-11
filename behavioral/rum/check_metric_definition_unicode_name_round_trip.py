"""metric-definition-unicode-name-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metric-definition-unicode-name-round-trip"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom metric definition with unicode in its name and dimension mapping is
    returned unchanged by BatchGetRumMetricDefinitions."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(
        Name=name,
        Domain="localhost",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-rum-"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: rum.delete_app_monitor(Name=name)))

    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: _safe(
            lambda: rum.delete_rum_metrics_destination(
                AppMonitorName=name, Destination="CloudWatch"
            )
        )
    )

    metric_name = "自定義指標☂-Custom"
    namespace = ctx.unique_name("Sim2RealCustomNS")
    dimension_value = "自定義維度🔖"
    event_pattern = json.dumps(
        {
            "event_type": ["com.amazon.rum.custom_event"],
            "metadata": {"custom_tag": ["v"]},
        }
    )
    metric_definition = {
        "Name": metric_name,
        "Namespace": namespace,
        "EventPattern": event_pattern,
        "DimensionKeys": {"metadata.custom_tag": dimension_value},
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
        expected_name=metric_name,
        expected_namespace=namespace,
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: rum.batch_delete_rum_metric_definitions(
                AppMonitorName=name,
                Destination="CloudWatch",
                MetricDefinitionIds=[metric_id],
            )
        )
    )

    get_resp = rum.batch_get_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch"
    )
    found = next(
        (d for d in get_resp["MetricDefinitions"] if d["MetricDefinitionId"] == metric_id),
        None,
    )
    assert found is not None, (
        f"metric definition {metric_id} not found in BatchGetRumMetricDefinitions "
        f"result {get_resp['MetricDefinitions']!r}"
    )
    assert found["Name"] == metric_name, f"expected Name={metric_name!r}, got {found['Name']!r}"
    assert found["Namespace"] == namespace, f"expected Namespace={namespace!r}, got {found['Namespace']!r}"
    assert found["DimensionKeys"] == {"metadata.custom_tag": dimension_value}, (
        f"expected DimensionKeys={{'metadata.custom_tag': {dimension_value!r}}}, "
        f"got {found['DimensionKeys']!r}"
    )
    assert found["EventPattern"] == event_pattern, (
        f"expected EventPattern={event_pattern!r}, got {found['EventPattern']!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _resolve_metric_id(rum, create_resp, *, app_monitor_name, destination, expected_name, expected_namespace):
    """BatchCreateRumMetricDefinitions has been observed to (a) return the created
    MetricDefinition directly, (b) report a ConflictException 'already exists' for the
    very definition it just (successfully) created, or (c) return empty
    MetricDefinitions/Errors lists for a create that nonetheless took effect. Resolve the
    id robustly via the read path (BatchGetRumMetricDefinitions) instead of assuming any
    one of those response shapes."""
    import time

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
