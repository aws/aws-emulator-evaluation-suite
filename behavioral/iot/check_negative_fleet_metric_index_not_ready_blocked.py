"""negative-fleet-metric-index-not-ready-blocked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "negative-fleet-metric-index-not-ready-blocked"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """With thing indexing OFF, CreateFleetMetric and GetBucketsAggregation fail with
    ResourceNotFoundException naming the missing AWS_Things index and create no metric; the same
    calls succeed once the index is ACTIVE, and a deleted metric is gone."""
    iot = ctx.client("iot")

    prev_cfg = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )

    def _restore_indexing():
        iot.update_indexing_configuration(thingIndexingConfiguration=prev_cfg)

    ctx.on_cleanup(_restore_indexing)

    # wait for OFF to take effect so the index is guaranteed absent
    iot.update_indexing_configuration(thingIndexingConfiguration={"thingIndexingMode": "OFF"})
    _poll_until(
        lambda: iot.get_indexing_configuration()
        .get("thingIndexingConfiguration", {})
        .get("thingIndexingMode")
        == "OFF",
        timeout_s=30.0,
        desc="thingIndexingMode to report OFF",
    )

    metric_name = ctx.unique_name("sim2real-notready-metric").replace("_", "-")
    create_code, create_message = _error(
        lambda: iot.create_fleet_metric(
            metricName=metric_name,
            queryString="thingName:*",
            aggregationType={"name": "Cardinality"},
            period=300,
            aggregationField="registry.thingTypeName",
        )
    )
    assert create_code == "ResourceNotFoundException", create_code
    assert create_message == "Index AWS_Things does not exist. Please enable index by calling UpdateIndexingConfiguration", create_message

    bucket_code, bucket_message = _error(
        lambda: iot.get_buckets_aggregation(
            queryString="thingName:*",
            aggregationField="registry.thingTypeName",
            bucketsAggregationType={"termsAggregation": {"maxBuckets": 10}},
        )
    )
    assert bucket_code == "ResourceNotFoundException", bucket_code
    assert bucket_message == "Index AWS_Things does not exist. Please enable index by calling UpdateIndexingConfiguration", bucket_message

    describe_code, describe_message = _error(lambda: iot.describe_fleet_metric(metricName=metric_name))
    assert describe_code == "ResourceNotFoundException", describe_code
    assert describe_message == (
        "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: "
        f"FleetMetric {ctx.account}:{metric_name} not found."
    ), describe_message

    iot.update_indexing_configuration(thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"})
    _wait_index_active(iot)

    iot.create_fleet_metric(
        metricName=metric_name,
        queryString="thingName:*",
        aggregationType={"name": "Cardinality"},
        period=300,
        aggregationField="registry.thingTypeName",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_fleet_metric(metricName=metric_name))
    described = iot.describe_fleet_metric(metricName=metric_name)
    assert described["metricName"] == metric_name, described

    result = iot.get_buckets_aggregation(
        queryString="thingName:*",
        aggregationField="registry.thingTypeName",
        bucketsAggregationType={"termsAggregation": {"maxBuckets": 10}},
    )
    assert "totalCount" in result, result

    iot.delete_fleet_metric(metricName=metric_name)
    post_delete_code, post_delete_message = _error(lambda: iot.describe_fleet_metric(metricName=metric_name))
    assert post_delete_code == "ResourceNotFoundException", post_delete_code
    assert post_delete_message == (
        "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: "
        f"FleetMetric {ctx.account}:{metric_name} not found."
    ), post_delete_message


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


def _poll_until(predicate, *, timeout_s: float, interval_s: float = 1.0, desc: str = "condition") -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for: {desc}")


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
