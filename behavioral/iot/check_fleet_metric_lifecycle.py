"""fleet-metric-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fleet-metric-lifecycle"
GROUP = "telemetry"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """A fleet metric is created as set, updated to period 600 with a higher version,
    listed, and after delete is unlisted while Describe and Update fail with
    ResourceNotFoundException and their exact messages."""
    iot = ctx.client("iot")
    _ensure_thing_indexing_active(ctx)

    metric_name = ctx.unique_name("sim2real-fleetmetric-")
    iot.create_fleet_metric(
        metricName=metric_name,
        queryString="thingName:*",
        aggregationType={"name": "Statistics", "values": ["average"]},
        period=300,
        aggregationField="registry.version",
        indexName="AWS_Things",
        description="initial",
        tags=[{"Key": "sim2real", "Value": "fleet-metric-lifecycle"}],
    )

    def _cleanup_delete() -> None:
        try:
            iot.delete_fleet_metric(metricName=metric_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_delete)

    initial = iot.describe_fleet_metric(metricName=metric_name)
    assert initial["metricName"] == metric_name
    assert initial["period"] == 300
    assert initial["aggregationField"] == "registry.version"
    assert initial["queryString"] == "thingName:*"
    initial_version = initial["version"]

    iot.update_fleet_metric(
        metricName=metric_name,
        indexName="AWS_Things",
        period=600,
        description="updated",
        aggregationField="registry.version",
        aggregationType={"name": "Statistics", "values": ["average"]},
    )

    updated = iot.describe_fleet_metric(metricName=metric_name)
    assert updated["period"] == 600
    assert updated["description"] == "updated"
    assert updated["version"] > initial_version

    listed_names = _list_all_fleet_metric_names(iot)
    assert metric_name in listed_names

    iot.delete_fleet_metric(metricName=metric_name)

    deadline = time.monotonic() + 60
    still_listed = True
    while time.monotonic() < deadline:
        still_listed = metric_name in _list_all_fleet_metric_names(iot)
        if not still_listed:
            break
        time.sleep(3)
    assert not still_listed, "deleted fleet metric still appears in ListFleetMetrics"

    code, message = _error_code(lambda: iot.describe_fleet_metric(metricName=metric_name))
    assert code == "ResourceNotFoundException", code
    expected_describe = (
        "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric "
        f"operation: FleetMetric {ctx.account}:{metric_name} not found."
    )
    assert message == expected_describe, f"expected message {expected_describe!r}, got {message!r}"
    code, message = _error_code(
        lambda: iot.update_fleet_metric(
            metricName=metric_name,
            indexName="AWS_Things",
            period=900,
            aggregationField="registry.version",
            aggregationType={"name": "Statistics", "values": ["average"]},
        )
    )
    assert code == "ResourceNotFoundException", "update on a deleted fleet metric must not succeed"
    expected_update = f"FleetMetric {metric_name} doesn't exist"
    assert message == expected_update, f"expected message {expected_update!r}, got {message!r}"


def _error_code(fn) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _list_all_fleet_metric_names(iot: Any) -> set[str]:
    names: set[str] = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = iot.list_fleet_metrics(**kwargs)
        names.update(m["metricName"] for m in resp.get("fleetMetrics", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return names


def _ensure_thing_indexing_active(ctx) -> None:
    iot = ctx.client("iot")
    current = iot.get_indexing_configuration()
    thing_cfg = current.get("thingIndexingConfiguration") or {}
    if thing_cfg.get("thingIndexingMode", "OFF") == "OFF":
        iot.update_indexing_configuration(
            thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"}
        )

        def _restore() -> None:
            iot.update_indexing_configuration(
                thingIndexingConfiguration={"thingIndexingMode": "OFF"}
            )

        ctx.on_cleanup(_restore)

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = iot.describe_index(indexName="AWS_Things")["indexStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError("AWS_Things fleet index never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
