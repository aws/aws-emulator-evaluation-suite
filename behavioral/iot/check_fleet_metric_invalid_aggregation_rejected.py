"""fleet-metric-invalid-aggregation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "fleet-metric-invalid-aggregation-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreateFleetMetric with Statistics over the string field thingName fails with
    InvalidRequestException and its exact message and creates nothing, while the same
    aggregation over connectivity.timestamp succeeds."""
    iot = ctx.client("iot")
    _ensure_thing_indexing_active(ctx)

    bad_metric_name = ctx.unique_name("sim2real-fleetmetric-bad-")
    code, message = _error_code(
        lambda: iot.create_fleet_metric(
            metricName=bad_metric_name,
            queryString="thingName:*",
            aggregationType={"name": "Statistics", "values": ["average"]},
            period=300,
            aggregationField="thingName",
            indexName="AWS_Things",
        )
    )
    assert code == "InvalidRequestException", f"unexpected code: {code!r}"
    expected_message = (
        "Invalid values [average] for Statistics aggregation on String field. "
        "Supported values are [count]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(
        lambda: iot.describe_fleet_metric(metricName=bad_metric_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code!r}"
    )
    expected_not_found = (
        "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric "
        f"operation: FleetMetric {ctx.account}:{bad_metric_name} not found."
    )
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    good_metric_name = ctx.unique_name("sim2real-fleetmetric-good-")
    iot.create_fleet_metric(
        metricName=good_metric_name,
        queryString="thingName:*",
        aggregationType={"name": "Statistics", "values": ["average"]},
        period=300,
        aggregationField="connectivity.timestamp",
        indexName="AWS_Things",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_fleet_metric_quiet(ctx, good_metric_name))
    described = iot.describe_fleet_metric(metricName=good_metric_name)
    assert described["metricName"] == good_metric_name, (
        f"expected metricName {good_metric_name!r}, got {described.get('metricName')!r}"
    )
    assert described["aggregationField"] == "connectivity.timestamp", (
        f"expected aggregationField 'connectivity.timestamp', got {described.get('aggregationField')!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_fleet_metric_quiet(ctx, metric_name):
    iot = ctx.client("iot")
    iot.delete_fleet_metric(metricName=metric_name)


def _ensure_thing_indexing_active(ctx, timeout_s=120.0, interval_s=3.0):
    iot = ctx.client("iot")
    current = iot.get_indexing_configuration()
    thing_cfg = current.get("thingIndexingConfiguration", {})
    mode = thing_cfg.get("thingIndexingMode", "OFF")
    connectivity_mode = thing_cfg.get("thingConnectivityIndexingMode", "OFF")
    if mode != "REGISTRY_AND_SHADOW" or connectivity_mode != "STATUS":
        new_cfg = {
            "thingIndexingMode": "REGISTRY_AND_SHADOW",
            "thingConnectivityIndexingMode": "STATUS",
        }
        if thing_cfg.get("namedShadowIndexingMode"):
            new_cfg["namedShadowIndexingMode"] = thing_cfg["namedShadowIndexingMode"]
        if thing_cfg.get("filter"):
            new_cfg["filter"] = thing_cfg["filter"]
        if thing_cfg.get("customFields"):
            new_cfg["customFields"] = thing_cfg["customFields"]
        ctx.on_cleanup(_restore_thing_indexing(iot, thing_cfg))
        iot.update_indexing_configuration(thingIndexingConfiguration=new_cfg)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError("AWS_Things index never reached ACTIVE within timeout")


def _restore_thing_indexing(iot, prior):
    """Teardown for the account-wide thing indexing configuration: put back exactly the
    configuration read before this check changed it. managedFields is derived by the service
    from the modes, so it is not sent back."""
    import copy

    original = {k: v for k, v in copy.deepcopy(prior).items() if k != "managedFields"}
    original.setdefault("thingIndexingMode", "OFF")
    return lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
