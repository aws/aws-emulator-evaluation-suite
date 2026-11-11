"""fleet-metric-lifecycle-and-query."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "fleet-metric-lifecycle-and-query"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreateFleetMetric's aggregation config persists through Describe/Update/List and
    is gone after Delete."""
    iot = ctx.client("iot")
    _ensure_thing_indexing_active(ctx)

    metric_name = ctx.unique_name("sim2real-fleetmetric-")
    iot.create_fleet_metric(
        metricName=metric_name,
        queryString="thingName:*",
        aggregationType={"name": "Statistics", "values": ["average"]},
        period=300,
        aggregationField="connectivity.timestamp",
        indexName="AWS_Things",
        description="initial description",
        tags=[{"Key": "sim2real", "Value": "fleet-metric-lifecycle-and-query"}],
    )
    ctx.on_cleanup(lambda: _delete_fleet_metric_quiet(ctx, metric_name))

    described = iot.describe_fleet_metric(metricName=metric_name)
    assert described["queryString"] == "thingName:*", described["queryString"]
    assert described["aggregationType"]["name"] == "Statistics", described["aggregationType"]
    assert described["period"] == 300, described["period"]
    assert described["aggregationField"] == "connectivity.timestamp", described["aggregationField"]
    assert described["description"] == "initial description", described["description"]

    iot.update_fleet_metric(
        metricName=metric_name,
        indexName="AWS_Things",
        period=3600,
        description="updated description",
    )

    described_after_update = iot.describe_fleet_metric(metricName=metric_name)
    assert described_after_update["period"] == 3600, described_after_update["period"]
    assert described_after_update["description"] == "updated description", (
        described_after_update["description"]
    )
    # Untouched fields must survive the partial update: confirmed against real AWS, not assumed.
    assert described_after_update["aggregationField"] == "connectivity.timestamp", (
        described_after_update["aggregationField"]
    )
    assert described_after_update["queryString"] == "thingName:*", described_after_update["queryString"]
    assert described_after_update["aggregationType"]["name"] == "Statistics", (
        described_after_update["aggregationType"]
    )

    found = False
    next_token = None
    for _ in range(20):
        kwargs = {"maxResults": 250}
        if next_token:
            kwargs["nextToken"] = next_token
        page = iot.list_fleet_metrics(**kwargs)
        if any(m["metricName"] == metric_name for m in page.get("fleetMetrics", [])):
            found = True
            break
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert found, f"{metric_name} not present in ListFleetMetrics"

    iot.delete_fleet_metric(metricName=metric_name)

    code, message = _error_code(lambda: iot.describe_fleet_metric(metricName=metric_name))
    assert code == "ResourceNotFoundException", code
    expected_describe = (
        "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric "
        f"operation: FleetMetric {ctx.account}:{metric_name} not found."
    )
    assert message == expected_describe, f"expected message {expected_describe!r}, got {message!r}"

    # The dead id must also reject a mutation, not just a read.
    update_code, update_message = _error_code(
        lambda: iot.update_fleet_metric(
            metricName=metric_name, indexName="AWS_Things", period=3600
        )
    )
    assert update_code == "ResourceNotFoundException", update_code
    expected_update = f"FleetMetric {metric_name} doesn't exist"
    assert update_message == expected_update, f"expected message {expected_update!r}, got {update_message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _delete_fleet_metric_quiet(ctx, metric_name):
    iot = ctx.client("iot")
    iot.delete_fleet_metric(metricName=metric_name)


def _ensure_thing_indexing_active(ctx, timeout_s=120.0, interval_s=3.0):
    """Enable REGISTRY_AND_SHADOW thing indexing plus connectivity indexing
    (idempotent) and poll until AWS_Things reaches ACTIVE -- fleet metrics require an
    active index to validate aggregation fields."""
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
        iot.update_indexing_configuration(thingIndexingConfiguration=new_cfg)
        restore_cfg = thing_cfg if thing_cfg else {"thingIndexingMode": "OFF"}
        ctx.on_cleanup(
            lambda: iot.update_indexing_configuration(thingIndexingConfiguration=restore_cfg)
        )
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError("AWS_Things index never reached ACTIVE within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
