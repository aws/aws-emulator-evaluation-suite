"""get-metric-data-duplicate-query-id-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-duplicate-query-id-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData with two MetricDataQueries sharing the same Id is rejected
    with a specific validation error, rather than silently returning only one
    of the two results."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-cw-dup-")
    metric_name = "DupIdCheckMetric"

    now = datetime.now(timezone.utc)
    # Publish a real datapoint so the positive control below round-trips actual data,
    # not just an empty/Complete-with-no-values response.
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 42.0, "Unit": "Count", "Timestamp": now}],
    )

    start = now - timedelta(minutes=10)
    end = now + timedelta(minutes=1)

    def _query(id_a: str, id_b: str) -> list[dict]:
        return [
            {
                "Id": id_a,
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": metric_name},
                    "Period": 60,
                    "Stat": "Sum",
                },
                "ReturnData": True,
            },
            {
                "Id": id_b,
                "MetricStat": {
                    "Metric": {"Namespace": namespace, "MetricName": metric_name},
                    "Period": 60,
                    "Stat": "SampleCount",
                },
                "ReturnData": True,
            },
        ]

    # --- Negative: duplicate Id across the two queries must be rejected outright.
    code, message = _error(
        lambda: cw.get_metric_data(MetricDataQueries=_query("dup", "dup"), StartTime=start, EndTime=end)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = "The values for parameter id in MetricDataQueries are not unique.\n"
    assert message == expected, f"expected the exact message {expected!r}, got {message!r}"

    # --- Positive control: same shape of request but with unique Ids must succeed,
    # and the call must have had no effect from the earlier rejected request (no
    # cached/partial result keyed by the reused Id "dup" leaking through).
    resp = _poll_until_complete(cw, _query("m1", "m2"), start, end)
    ids = {r["Id"] for r in resp["MetricDataResults"]}
    assert ids == {"m1", "m2"}, f"expected exactly ids m1,m2, got {ids}"
    for result in resp["MetricDataResults"]:
        assert result["StatusCode"] == "Complete", result
    sum_result = next(r for r in resp["MetricDataResults"] if r["Id"] == "m1")
    assert any(v == 42.0 for v in sum_result["Values"]), sum_result


def _error(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_complete(cw, queries, start, end, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
        last = resp
        results = {r["Id"]: r for r in resp["MetricDataResults"]}
        m1 = results.get("m1")
        if m1 and m1.get("Values"):
            return resp
        time.sleep(interval_s)
    last_statuses = (
        {r["Id"]: r.get("StatusCode") for r in last["MetricDataResults"]} if last is not None else None
    )
    raise AssertionError(
        f"GetMetricData never returned Values for query 'm1' within {timeout_s}s "
        f"(last statuses: {last_statuses!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
