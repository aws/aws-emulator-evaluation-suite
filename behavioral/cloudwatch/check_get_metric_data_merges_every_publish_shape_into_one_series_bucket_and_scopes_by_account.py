"""get-metric-data-merges-every-publish-shape-into-one-series-bucket-and-scopes-by-account."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-merges-every-publish-shape-into-one-series-bucket-and-scopes-by-account"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

#: A documentation account id that is not linked to the caller's account.
_FOREIGN_ACCOUNT = "111122223333"
_FORBIDDEN = [{
    "Code": "Forbidden",
    "Value": "Access denied when getting data - please check that this account and the requested metric account are linked",
}]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) holds; raise on timeout (TimeoutError if the run budget ended it)."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended the wait. Last result: {last!r}")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMetricData resolves a query to one series by namespace, name, dimension set and account:
    raw values, statistic sets and value/count arrays in one minute merge into one bucket, a repeated
    datum counts twice, dimension order is irrelevant, and an unlinked AccountId yields Forbidden."""
    cw = ctx.client("cloudwatch")
    account = ctx.account
    assert account != _FOREIGN_ACCOUNT, "test account collides with the fixed foreign account id"
    # A custom namespace cannot be deleted (no DeleteMetric API); it ages out.
    namespace = ctx.unique_name("sim2real-cw-gmd-merge-")
    written = datetime.now(timezone.utc).replace(microsecond=0)
    bucket = written.replace(second=0)
    dims = [{"Name": "A", "Value": "1"}, {"Name": "B", "Value": "2"}]

    merge = {"MetricName": "Merge", "Dimensions": dims, "Timestamp": written}
    cw.put_metric_data(Namespace=namespace, MetricData=[
        {**merge, "Value": 10.0},
        {**merge, "StatisticValues": {"SampleCount": 4.0, "Sum": 20.0, "Minimum": 1.0, "Maximum": 9.0}},
        {**merge, "Values": [1.0, 2.0], "Counts": [1.0, 3.0]},
    ])
    for _ in range(2):
        cw.put_metric_data(Namespace=namespace, MetricData=[{"MetricName": "Dup", "Timestamp": written, "Value": 5.0}])

    def query(qid, stat, metric_name="Merge", dimensions=dims, **extra):
        metric = {"Namespace": namespace, "MetricName": metric_name, "Dimensions": dimensions}
        return {"Id": qid, "MetricStat": {"Metric": metric, "Period": 60, "Stat": stat}, "ReturnData": True, **extra}

    def read(*queries):
        resp = cw.get_metric_data(
            MetricDataQueries=list(queries), StartTime=bucket - timedelta(minutes=5), EndTime=bucket + timedelta(minutes=5)
        )
        return {r["Id"]: r for r in resp["MetricDataResults"]}

    merged = _poll_until(
        ctx,
        lambda: read(
            query("n", "SampleCount"), query("s", "Sum"), query("lo", "Minimum"), query("hi", "Maximum"),
            query("dn", "SampleCount", "Dup", []), query("ds", "Sum", "Dup", []),
        ),
        lambda r: r["n"]["Values"] == [9.0] and r["dn"]["Values"] == [2.0],
        timeout_s=60.0, description="all merged and duplicated datapoints counted",
    )
    stats = {qid: merged[qid]["Values"] for qid in ("s", "lo", "hi", "ds")}
    assert stats == {"s": [37.0], "lo": [1.0], "hi": [10.0], "ds": [10.0]}, (
        f"expected Merge Sum 37 / Min 1 / Max 10 and Dup Sum 10 in one bucket each, got {stats!r}"
    )
    assert merged["s"]["Timestamps"] == [bucket], f"expected the single bucket {bucket!r}, got {merged['s']['Timestamps']!r}"

    scoped = read(query("rev", "Sum", dimensions=dims[::-1]), query("own", "Sum", AccountId=account))
    for qid in ("rev", "own"):
        got = (scoped[qid]["Values"], scoped[qid]["StatusCode"])
        assert got == ([37.0], "Complete"), f"{qid}: expected the same series ([37.0], Complete), got {got!r}"

    foreign = read(query("far", "Sum", AccountId=_FOREIGN_ACCOUNT))["far"]
    got = (foreign["StatusCode"], foreign["Values"], foreign.get("Messages"))
    assert got == ("Forbidden", [], _FORBIDDEN), (
        f"expected an unlinked AccountId to yield a Forbidden result with no values, got {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
