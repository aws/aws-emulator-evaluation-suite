"""deep-cwlogs-semantics-metric-filter-dimensions-with-default-value-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cwlogs-semantics-metric-filter-dimensions-with-default-value-rejected"
GROUP = "metric-filters"
SERVICES = ["cloudwatch", "logs"]


@tags("axis:rejection", "cap:c2", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """PutMetricFilter refuses dimensions together with defaultValue (InvalidParameterException) and
    persists nothing; the same filter without defaultValue is accepted and publishes a dimensioned
    Sum, after which CloudWatch still holds no datapoint for the refused metric."""
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")
    group = ctx.unique_name("sim2real-behav-lg-dimdef-")
    namespace = ctx.unique_name("sim2real-behav-dimdef-ns-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = "events"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    pattern = '{ $.status = "fail" }'
    dims = {"Service": "$.service"}
    refused_name = "dimdef-refused"
    err = _error(lambda: logs.put_metric_filter(
        logGroupName=group, filterName=refused_name, filterPattern=pattern,
        metricTransformations=[{"metricName": "Refused", "metricNamespace": namespace,
                                "metricValue": "1", "defaultValue": 0.0, "dimensions": dims}],
    ))
    expected = ("InvalidParameterException",
                "Invalid metric transformation: dimensions and default value are mutually "
                "exclusive properties")
    assert err == expected, (
        f"PutMetricFilter with both dimensions and defaultValue returned {err!r}, expected "
        f"{expected!r}"
    )

    control_name = "dimdef-control"
    logs.put_metric_filter(
        logGroupName=group, filterName=control_name, filterPattern=pattern,
        metricTransformations=[{"metricName": "Control", "metricNamespace": namespace,
                                "metricValue": "1", "dimensions": dims}],
    )
    ctx.on_cleanup(lambda: logs.delete_metric_filter(logGroupName=group, filterName=control_name))

    names = sorted(f["filterName"] for f in logs.describe_metric_filters(logGroupName=group)["metricFilters"])
    assert names == [control_name], (
        f"only the accepted control filter may exist on the group; DescribeMetricFilters lists {names!r}"
    )

    base = int(time.time() * 1000) - 3000
    events = [json.dumps({"service": "checkout", "status": "fail", "n": i}) for i in range(3)]
    resp = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(events)],
    )
    assert "rejectedLogEventsInfo" not in resp, f"the fixture batch was partially rejected: {resp!r}"

    def _sum(metric, dimensions):
        end = datetime.now(timezone.utc) + timedelta(minutes=5)
        start = end - timedelta(minutes=20)
        points = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dimensions,
            StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
        ).get("Datapoints", [])
        return sum(p.get("Sum", 0.0) for p in points)

    service_dim = [{"Name": "Service", "Value": "checkout"}]
    control_sum = _poll_until(
        lambda: _sum("Control", service_dim), lambda s: s >= 3.0,
        timeout_s=210.0, interval_s=10.0,
        description=f"the control metric {namespace}/Control{{Service=checkout}} to reach Sum 3",
    )
    assert control_sum == 3.0, (
        f"the accepted control filter must publish exactly 3 (one per matching event) under "
        f"Service=checkout; got Sum={control_sum!r}"
    )

    # The control's arrival is the barrier, so the absence below is not publication lag.
    refused_dimensioned = _sum("Refused", service_dim)
    refused_bare = _sum("Refused", [])
    assert refused_dimensioned == 0.0 and refused_bare == 0.0, (
        "the refused metric filter must publish nothing, but CloudWatch holds "
        f"Refused{{Service=checkout}} Sum={refused_dimensioned!r} and Refused{{}} Sum={refused_bare!r} "
        "after the control's datapoints arrived"
    )


def _error(fn) -> tuple[str, str]:
    """Return the (code, message) of the AWS error; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
