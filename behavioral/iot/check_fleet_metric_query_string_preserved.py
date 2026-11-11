"""fleet-metric-query-string-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fleet-metric-query-string-preserved"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """A complex fleet-indexing query string set on CreateFleetMetric is returned
    character-for-character (including quoting, parens, wildcards and boolean operators) by
    DescribeFleetMetric."""
    iot = ctx.client("iot")

    original_thing_cfg = iot.get_indexing_configuration().get(
        "thingIndexingConfiguration", {"thingIndexingMode": "OFF"}
    )
    if original_thing_cfg.get("thingIndexingMode", "OFF") == "OFF":
        iot.update_indexing_configuration(thingIndexingConfiguration={"thingIndexingMode": "REGISTRY"})
        ctx.on_cleanup(
            lambda: iot.update_indexing_configuration(thingIndexingConfiguration=original_thing_cfg)
        )

    metric_name = ctx.unique_name("sim2realfm").replace("-", "")[:60]
    query_string = (
        'thingTypeName:"sim2real-sensor" AND '
        '(attributes.firmware:"2.1.0" OR attributes.firmware:"2.2.0") '
        'AND NOT thingName:"excluded-*"'
    )
    aggregation_type = {"name": "Statistics", "values": ["sum"]}

    _create_fleet_metric_with_retry(
        iot,
        metric_name=metric_name,
        query_string=query_string,
        aggregation_type=aggregation_type,
        aggregation_field="registry.version",
        period=300,
        index_name="AWS_Things",
        timeout_s=90.0,
    )
    ctx.on_cleanup(lambda: _delete_fleet_metric_quiet(iot, metric_name))

    described = iot.describe_fleet_metric(metricName=metric_name)
    assert described["queryString"] == query_string, (described["queryString"], query_string)
    assert described["aggregationField"] == "registry.version", described["aggregationField"]
    assert described["aggregationType"] == aggregation_type, described["aggregationType"]

    iot.delete_fleet_metric(metricName=metric_name)

    code, message = _error(lambda: iot.describe_fleet_metric(metricName=metric_name))
    assert code == "ResourceNotFoundException", code
    assert message == (
        "An error occurred (ResourceNotFoundException) when calling the DescribeFleetMetric operation: "
        f"FleetMetric {ctx.account}:{metric_name} not found."
    ), message

    update_code, update_message = _error(
        lambda: iot.update_fleet_metric(metricName=metric_name, indexName="AWS_Things", period=600)
    )
    assert update_code == "ResourceNotFoundException", update_code
    assert update_message == f"FleetMetric {metric_name} doesn't exist", update_message


def _create_fleet_metric_with_retry(
    iot, *, metric_name, query_string, aggregation_type, aggregation_field, period, index_name, timeout_s
):
    """The fleet index takes a short time to build after being enabled; retry past the
    documented IndexNotReadyException instead of asserting on the very first attempt."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            iot.create_fleet_metric(
                metricName=metric_name,
                queryString=query_string,
                aggregationType=aggregation_type,
                period=period,
                aggregationField=aggregation_field,
                indexName=index_name,
                tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "IndexNotReadyException":
                raise
            last_error = exc
            time.sleep(5.0)
    raise AssertionError(f"fleet index never became ready: {last_error!r}")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _delete_fleet_metric_quiet(iot, metric_name):
    iot.delete_fleet_metric(metricName=metric_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
