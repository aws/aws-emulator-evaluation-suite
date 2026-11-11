"""get-metric-data-multi-query-response-preserves-request-order."""
from __future__ import annotations

import datetime
import time

from behavioral_harness import tags

CHECK = "get-metric-data-multi-query-response-preserves-request-order"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData returns MetricDataResults in the same order the MetricDataQueries
    were submitted in the request, independent of the lexical order of the query Ids
    or of the metric names they reference."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-gmd-ns-")
    dim_value = ctx.unique_name("dim-")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    metric_names = ["MetricAlpha", "MetricBeta", "MetricGamma"]
    expected_values = {name: float(10 * (i + 1)) for i, name in enumerate(metric_names)}
    for metric_name, value in expected_values.items():
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{
                "MetricName": metric_name,
                "Dimensions": [{"Name": "Case", "Value": dim_value}],
                "Timestamp": now,
                "Value": value,
                "Unit": "Count",
            }],
        )

    # Ids intentionally NOT in alphabetical order, and not in the order the metrics
    # were published in either -- only the request order should determine the
    # response order.
    query_order = [
        ("q_zulu", "MetricGamma"),
        ("q_alpha", "MetricAlpha"),
        ("q_mike", "MetricBeta"),
    ]
    queries = [
        {
            "Id": qid,
            "MetricStat": {
                "Metric": {
                    "Namespace": namespace,
                    "MetricName": metric_name,
                    "Dimensions": [{"Name": "Case", "Value": dim_value}],
                },
                "Period": 60,
                "Stat": "Average",
            },
            "ReturnData": True,
        }
        for qid, metric_name in query_order
    ]

    results = _poll_until(
        lambda: cw.get_metric_data(
            MetricDataQueries=queries,
            StartTime=now - datetime.timedelta(minutes=5),
            EndTime=now + datetime.timedelta(minutes=5),
        )["MetricDataResults"],
        lambda rs: all(r.get("Values") for r in rs),
        timeout_s=60,
        interval_s=3,
    )

    returned_ids = [r["Id"] for r in results]
    expected_ids = [qid for qid, _ in query_order]
    assert returned_ids == expected_ids, (
        f"GetMetricData did not preserve request order: requested {expected_ids}, got {returned_ids}"
    )

    id_to_metric = dict(query_order)
    for result in results:
        metric_name = id_to_metric[result["Id"]]
        expected_value = expected_values[metric_name]
        actual_value = result["Values"][0]
        assert actual_value == expected_value, (
            f"query {result['Id']} for {metric_name} returned value {actual_value}, "
            f"expected {expected_value} (order-correct Id must also carry its own metric's data)"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
