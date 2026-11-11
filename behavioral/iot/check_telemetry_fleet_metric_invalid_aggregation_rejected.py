"""telemetry-fleet-metric-invalid-aggregation-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "telemetry-fleet-metric-invalid-aggregation-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """CreateFleetMetric with a Statistics aggregation over a String custom field fails InvalidRequestException
    with AWS's exact message and the metric never exists, while a Cardinality aggregation on that field succeeds."""
    iot = ctx.client("iot")

    prev_cfg = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )

    def _restore_indexing():
        iot.update_indexing_configuration(thingIndexingConfiguration=prev_cfg)

    ctx.on_cleanup(_restore_indexing)
    custom_field_name = ctx.unique_name("s2rStrField").replace("-", "").replace("_", "")
    aggregation_field = f"attributes.{custom_field_name}"
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "customFields": [{"name": aggregation_field, "type": "String"}],
        }
    )
    _wait_index_active(iot)


    bad_metric_name = ctx.unique_name("sim2real-badmetric").replace("_", "-")
    code, code_message = _error(
        lambda: iot.create_fleet_metric(
            metricName=bad_metric_name,
            queryString="thingName:*",
            # aggregation_field is declared type String in the indexing
            # config; averaging it is not a valid numeric aggregation.
            aggregationType={"name": "Statistics", "values": ["average"]},
            period=300,
            aggregationField=aggregation_field,
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert code_message == "Invalid values [average] for Statistics aggregation on String field. Supported values are [count]", (
        f"expected the exact {code} message, got {code_message!r}"
    )


    # The rejected metric must not have been created.
    not_found_code, not_found_code_message = _error(lambda: iot.describe_fleet_metric(metricName=bad_metric_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code!r}"
    )
    assert not_found_code_message == f"An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: FleetMetric {ctx.account}:{bad_metric_name} not found.", (
        f"expected the exact {not_found_code} message, got {not_found_code_message!r}"
    )
    names = [m["metricName"] for m in iot.list_fleet_metrics().get("fleetMetrics", [])]
    assert bad_metric_name not in names, f"{bad_metric_name} present in list_fleet_metrics after rejection"

    # Positive control: the exact same field with a compatible aggregation
    # type (Cardinality, which just counts distinct values) succeeds.
    good_metric_name = ctx.unique_name("sim2real-goodmetric").replace("_", "-")
    iot.create_fleet_metric(
        metricName=good_metric_name,
        queryString="thingName:*",
        aggregationType={"name": "Cardinality"},
        period=300,
        aggregationField=aggregation_field,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )


    ctx.on_cleanup(lambda: iot.delete_fleet_metric(metricName=good_metric_name))
    described = iot.describe_fleet_metric(metricName=good_metric_name)
    assert described["metricName"] == good_metric_name, described
    assert described["aggregationType"]["name"] == "Cardinality", described
    assert described["aggregationField"] == aggregation_field, described


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
