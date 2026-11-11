"""cw-put-metric-data-oversized-batch-rejected-and-no-partial-ingestion."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cw-put-metric-data-oversized-batch-rejected-and-no-partial-ingestion"
GROUP = "metric-data-rejected"
SERVICES = ["cloudwatch"]


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An over-limit PutMetricData batch is rejected whole: not even a prefix is ingested.

    A positive control of the same 1000 data acts as a barrier before the 1001st name is read.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html
    """
    # No cleanup: CloudWatch has no DeleteMetric API; the namespace is unique per run.
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDepthBatchNs")
    t = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    limit = 1000

    # Distinct metric names so each datum is observable; Batch1000 exists only in the rejected
    # request, so it is the orphan probe.
    data = [
        {"MetricName": f"Batch{i}", "Timestamp": t, "Value": 1.0, "Unit": "Count"}
        for i in range(limit + 1)
    ]
    assert len(data) == limit + 1, f"built {len(data)!r} data, expected {limit + 1!r}"

    error = _error(lambda: cw.put_metric_data(Namespace=namespace, MetricData=data))
    assert error is not None, (
        f"PutMetricData accepted {len(data)} MetricData; real CloudWatch refuses anything over "
        f"{limit}. An acceptance here is over-permissiveness, and the {limit + 1}th datum is now "
        f"in the store"
    )
    code = error.get("Code")
    message = error.get("Message") or ""
    assert code == "InvalidParameterValue", (
        f"the over-limit batch was refused with {code!r}, expected 'InvalidParameterValue'; "
        f"message was {message!r}"
    )
    assert error.get("HTTPStatusCode") == 400, (
        f"the over-limit batch was refused with HTTP {error.get('HTTPStatusCode')!r}, expected 400"
    )
    expected_message = "The collection MetricData must not have a size greater than 1000."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # Positive control, issued after the rejected write: once its data are queryable the store
    # has caught up past the rejection.
    control = cw.put_metric_data(Namespace=namespace, MetricData=data[:limit])
    assert control["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the positive control at exactly {limit} data was rejected: {control!r}"
    )

    def _points(metric_name: str) -> list[dict]:
        return cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=t,
            EndTime=t + timedelta(seconds=60),
            Period=60,
            Statistics=["Sum", "SampleCount"],
        )["Datapoints"]

    sampled_names = ["Batch0", f"Batch{limit // 2}", f"Batch{limit - 1}"]
    sampled = _poll_until(
        lambda: {n: _points(n) for n in sampled_names},
        lambda got: all(len(v) == 1 for v in got.values()),
        timeout_s=180.0,
        interval_s=5.0,
        description=(
            f"all three sampled metrics from the accepted {limit}-datum batch became queryable "
            f"({sampled_names!r})"
        ),
    )
    assert sum(len(v) for v in sampled.values()) == 3, (
        f"expected one datapoint per sampled accepted metric, got "
        f"{ {n: len(v) for n, v in sampled.items()} !r}"
    )
    for name, points in sampled.items():
        assert points[0]["Sum"] == 1.0, f"accepted metric {name!r} read back as {points[0]!r}"

    orphan = _points(f"Batch{limit}")
    assert orphan == [], (
        f"the rejected {limit + 1}-datum batch was PARTIALLY ingested: Batch{limit} -- which "
        f"appears in no accepted request -- has datapoints {orphan!r}. The refusal must be "
        f"all-or-nothing"
    )


def _error(fn):
    """Return the botocore Error dict plus HTTPStatusCode for a ClientError, or None on success."""
    try:
        fn()
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return dict(exc.response.get("Error", {}), HTTPStatusCode=status)
    return None


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
