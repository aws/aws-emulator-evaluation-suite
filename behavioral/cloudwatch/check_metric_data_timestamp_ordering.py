"""metric-data-timestamp-ordering."""
from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-data-timestamp-ordering"
GROUP = 'metric-data'
SERVICES = ['cloudwatch']

_NAMESPACE = "SimParityProbe/Behavioral"


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData returns five datapoints published in scrambled order sorted by Timestamp, with Values
    tracking them (0-4) for TimestampAscending and exactly reversed for TimestampDescending, and rejects
    an unknown ScanBy server-side with ValidationError and its exact message."""
    cw = ctx.client("cloudwatch")
    metric_name = ctx.unique_name("sim2real-behav-cwprobe-metric-order-")
    base = (datetime.datetime.utcnow() - datetime.timedelta(minutes=20)).replace(
        second=0, microsecond=0
    )
    offsets = [0, 1, 2, 3, 4]
    timestamps = [base + datetime.timedelta(minutes=o) for o in offsets]
    # Value encodes the offset so we can verify Values track Timestamps after sorting.
    values = [float(o) for o in offsets]

    submission_order = [3, 0, 4, 1, 2]  # deliberately not temporal order
    for idx in submission_order:
        cw.put_metric_data(
            Namespace=_NAMESPACE,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": timestamps[idx],
                    "Value": values[idx],
                    "Unit": "Count",
                }
            ],
        )

    query = dict(
        MetricDataQueries=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": _NAMESPACE, "MetricName": metric_name},
                    "Period": 60,
                    "Stat": "Maximum",
                },
                "ReturnData": True,
            }
        ],
        StartTime=base,
        EndTime=base + datetime.timedelta(minutes=5),
    )

    def probe_ascending():
        resp = cw.get_metric_data(ScanBy="TimestampAscending", **query)
        return resp["MetricDataResults"][0]

    result = _poll_until(
        probe_ascending, lambda r: len(r.get("Timestamps", [])) >= len(offsets),
        timeout_s=90, interval_s=5, description="all 5 datapoints visible via GetMetricData",
    )

    got_timestamps = result["Timestamps"]
    got_values = result["Values"]
    assert got_timestamps == sorted(got_timestamps), (
        f"TimestampAscending must return strictly increasing timestamps, got {got_timestamps}"
    )
    # Values must track the ascending timestamp order (0,1,2,3,4), independent
    # of the scrambled [3,0,4,1,2] submission order above.
    assert got_values == sorted(offsets, key=float), (
        f"expected values in ascending-timestamp order {sorted(offsets)}, got {got_values}"
    )

    def probe_descending():
        resp = cw.get_metric_data(ScanBy="TimestampDescending", **query)
        return resp["MetricDataResults"][0]

    result_desc = _poll_until(
        probe_descending, lambda r: len(r.get("Timestamps", [])) >= len(offsets),
        timeout_s=30, interval_s=3, description="descending scan also returns all 5 datapoints",
    )
    assert result_desc["Timestamps"] == list(reversed(got_timestamps)), (
        "TimestampDescending must be the exact reverse of TimestampAscending"
    )

    # Overly-permissive check: a ScanBy value outside the documented enum
    # (TimestampAscending/TimestampDescending) must be rejected server-side with
    # the specific ValidationError -- a ParamValidationError raised locally by
    # botocore would never reach the target at all, so it cannot count here.
    try:
        cw.get_metric_data(ScanBy="NotARealScanByValue", **query)
    except ClientError as exc:
        error = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError("an invalid ScanBy value must be rejected, not silently accepted")
    assert error == ("ValidationError", (
        "1 validation error detected: Value at 'scanBy' failed to satisfy constraint: Member "
        "must satisfy enum value set: [TimestampAscending, TimestampDescending]"
    )), (
        f"expected the ValidationError for invalid ScanBy, got {error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
