"""delete-app-monitor-with-active-metric-destination-cleans-up."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-app-monitor-with-active-metric-destination-cleans-up"
GROUP = "overly-permissive"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRumMetricsDestinations and BatchGetRumMetricDefinitions return the configured destination
    and definition, and after DeleteAppMonitor both answer ResourceNotFoundException ("Resource not
    found <name>") rather than stale configuration.
    """
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(
        Name=name,
        Domain="example.com",
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    destinations = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert any(d["Destination"] == "CloudWatch" for d in destinations), (
        f"expected a CloudWatch destination to be listed for {name!r} before deletion, "
        f"got {destinations!r}"
    )

    pattern = json.dumps({"event_type": ["com.amazon.rum.custom_event"]})
    definition_id = _create_metric_definition_and_resolve_id(
        rum,
        app_monitor_name=name,
        destination="CloudWatch",
        metric_definition={
            "Name": "OrphanCheckMetric",
            "Namespace": "SimparityBehavioral",
            "EventPattern": pattern,
        },
    )
    live_definitions = rum.batch_get_rum_metric_definitions(
        AppMonitorName=name, Destination="CloudWatch"
    )["MetricDefinitions"]
    assert any(d["MetricDefinitionId"] == definition_id for d in live_definitions), (
        f"expected metric definition {definition_id!r} to be readable for {name!r} before "
        f"deletion, got {[d['MetricDefinitionId'] for d in live_definitions]!r}"
    )

    rum.delete_app_monitor(Name=name)

    _wait_not_found(rum, name, timeout_s=60.0)

    expected_message = f"Resource not found {name}"
    dest_code, dest_message = _client_error(lambda: rum.list_rum_metrics_destinations(AppMonitorName=name))
    assert dest_code == "ResourceNotFoundException", (
        f"metrics destinations for a deleted app monitor must not be queryable, got {dest_code}"
    )
    assert dest_message == expected_message, f"expected message {expected_message!r}, got {dest_message!r}"
    metrics_code, metrics_message = _client_error(
        lambda: rum.batch_get_rum_metric_definitions(AppMonitorName=name, Destination="CloudWatch")
    )
    assert metrics_code == "ResourceNotFoundException", (
        f"metric definitions for a deleted app monitor must not be queryable, got {metrics_code}"
    )
    assert metrics_message == expected_message, (
        f"expected message {expected_message!r}, got {metrics_message!r}"
    )


def _create_metric_definition_and_resolve_id(
    rum, *, app_monitor_name: str, destination: str, metric_definition: dict
) -> str:
    """BatchCreateRumMetricDefinitions can return an empty MetricDefinitions/Errors response
    for a brief window right after PutRumMetricsDestination while the destination registration
    propagates, even though the definition IS created server-side. Issue the create exactly
    once, then poll BatchGetRumMetricDefinitions for the named definition if the immediate
    response was inconclusive."""
    resp = rum.batch_create_rum_metric_definitions(
        AppMonitorName=app_monitor_name,
        Destination=destination,
        MetricDefinitions=[metric_definition],
    )
    created = resp.get("MetricDefinitions", [])
    if created:
        return created[0]["MetricDefinitionId"]
    assert not resp.get("Errors"), f"unexpected errors creating metric definition: {resp['Errors']}"

    def _find() -> str | None:
        fetched = rum.batch_get_rum_metric_definitions(
            AppMonitorName=app_monitor_name, Destination=destination
        )
        for d in fetched["MetricDefinitions"]:
            if d["Name"] == metric_definition["Name"]:
                return d["MetricDefinitionId"]
        return None

    found = _poll_until(_find, lambda v: v is not None, timeout_s=30.0)
    return found


def _safe_delete_app_monitor(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _wait_not_found(rum, name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    """Poll GetAppMonitor until it raises ResourceNotFoundException; a timeout raises."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rum.get_app_monitor(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"app monitor {name!r} still readable after {timeout_s}s")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
