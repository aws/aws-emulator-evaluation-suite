"""create-fleet-metric-invalid-aggregation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-fleet-metric-invalid-aggregation-rejected"
GROUP = "negative-classes"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreateFleetMetric with Percentiles on the string field registry.thingTypeName
    fails with InvalidRequestException and its exact message and creates nothing, while
    Cardinality on the same field succeeds."""
    iot = ctx.client("iot")

    restore = _ensure_registry_indexing_active(ctx)
    if restore is not None:
        ctx.on_cleanup(restore)

    bad_metric = ctx.unique_name("sim2real-fm-bad-")
    good_metric = ctx.unique_name("sim2real-fm-good-")

    err = _error(
        lambda: iot.create_fleet_metric(
            metricName=bad_metric,
            queryString="*",
            aggregationField="registry.thingTypeName",
            aggregationType={"name": "Percentiles", "values": ["50", "90", "99"]},
            period=300,
        )
    )
    assert err == ("InvalidRequestException", (
        "Invalid dataType String for field registry.thingTypeName. "
        "Only Number dataType is allowed for Percentiles aggregation"
    )), err

    # effect absent: the bad metric must not have been created
    names = _list_fleet_metric_names(iot)
    assert bad_metric not in names

    # positive control: same field, a type-compatible aggregation, succeeds
    iot.create_fleet_metric(
        metricName=good_metric,
        queryString="*",
        aggregationField="registry.thingTypeName",
        aggregationType={"name": "Cardinality"},
        period=300,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iot.delete_fleet_metric(metricName=good_metric))
    names_after = _list_fleet_metric_names(iot)
    assert good_metric in names_after


def _error(fn):
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _list_fleet_metric_names(iot) -> set:
    names = set()
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = iot.list_fleet_metrics(**kwargs)
        for m in resp.get("fleetMetrics", []):
            names.add(m["metricName"])
        token = resp.get("nextToken")
        if not token:
            break
    return names


def _ensure_registry_indexing_active(ctx):
    """Enable AWS_Things registry indexing if not already on; wait for ACTIVE.

    Returns a zero-arg restore callback to revert to the prior configuration, or
    None if indexing was already active and nothing needs to change.
    """
    iot = ctx.client("iot")
    current = iot.get_indexing_configuration()
    prior_mode = current.get("thingIndexingConfiguration", {}).get("thingIndexingMode", "OFF")

    if prior_mode == "OFF":
        iot.update_indexing_configuration(
            thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"}
        )

        def restore():
            iot.update_indexing_configuration(
                thingIndexingConfiguration={"thingIndexingMode": "OFF"}
            )
    else:
        restore = None

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return restore
        time.sleep(2)
    raise AssertionError("AWS_Things index never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
