"""telemetry-fleet-metric-lifecycle-and-aggregation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-fleet-metric-lifecycle-and-aggregation"
GROUP = "telemetry"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """A fleet metric's aggregation type/field can be updated post-creation,
    DescribeFleetMetric immediately reflects the new definition, and Delete
    removes it from both an independent Describe and ListFleetMetrics."""
    iot = ctx.client("iot")

    # Fleet metrics require an ACTIVE fleet index over the registry fields they
    # aggregate. Capture the account's current indexing config so we can restore
    # it, then turn on REGISTRY indexing and wait for the index to become ACTIVE.
    prev_cfg = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )

    def _restore_indexing():
        iot.update_indexing_configuration(thingIndexingConfiguration=prev_cfg)

    ctx.on_cleanup(_restore_indexing)
    iot.update_indexing_configuration(
        thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"}
    )
    _wait_index_active(iot)

    metric_name = ctx.unique_name("sim2real-fleetmetric").replace("_", "-")
    iot.create_fleet_metric(
        metricName=metric_name,
        queryString="thingName:*",
        aggregationType={"name": "Cardinality"},
        period=300,
        aggregationField="registry.thingTypeName",
        description="initial definition",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_fleet_metric_idempotent(iot, metric_name))

    described = iot.describe_fleet_metric(metricName=metric_name)
    assert described["aggregationField"] == "registry.thingTypeName", described
    assert described["period"] == 300, described
    assert described["aggregationType"]["name"] == "Cardinality", described

    # Update the aggregation field and period; per the API this requires
    # re-specifying indexName explicitly.
    iot.update_fleet_metric(
        metricName=metric_name,
        indexName=described["indexName"],
        queryString="thingName:*",
        aggregationType={"name": "Cardinality"},
        period=600,
        aggregationField="registry.thingGroupNames",
    )

    updated = iot.describe_fleet_metric(metricName=metric_name)
    assert updated["aggregationField"] == "registry.thingGroupNames", updated
    assert updated["period"] == 600, updated
    assert updated["aggregationType"]["name"] == "Cardinality", updated

    names = [m["metricName"] for m in iot.list_fleet_metrics().get("fleetMetrics", [])]
    assert metric_name in names, (metric_name, names)

    # The cleanup delete is a free negative assertion: prove the metric is both
    # gone from an independent read and gone from the listing surface.
    iot.delete_fleet_metric(metricName=metric_name)
    gone_code, gone_message = _error(lambda: iot.describe_fleet_metric(metricName=metric_name))
    assert gone_code == "ResourceNotFoundException", (
        f"deleted fleet metric is still describable, got {gone_code!r}"
    )
    assert gone_message == f"An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: FleetMetric {ctx.account}:{metric_name} not found.", (
        f"expected the exact {gone_code} message, got {gone_message!r}"
    )
    names_after_delete = [
        m["metricName"] for m in iot.list_fleet_metrics().get("fleetMetrics", [])
    ]
    assert metric_name not in names_after_delete, (
        "deleted fleet metric still appears in ListFleetMetrics",
        metric_name,
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_fleet_metric_idempotent(iot, metric_name: str) -> None:
    try:
        iot.delete_fleet_metric(metricName=metric_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_index_active(iot, index_name: str = "AWS_Things", timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = iot.describe_index(indexName=index_name)
            if resp.get("indexStatus") == "ACTIVE":
                return
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(3)
    raise AssertionError(f"index {index_name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
