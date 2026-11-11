"""get-metric-data-pagination-budgets-time-slots-and-binds-the-token-to-the-query."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-data-pagination-budgets-time-slots-and-binds-the-token-to-the-query"
GROUP = "metric-data"
SERVICES = ["cloudwatch"]

_INVALID_TOKEN = ("InvalidNextToken", "")


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
    """GetMetricData's MaxDatapoints budgets the Period slots of the window, empty slots included,
    a query that has completed drops out of later pages, and a NextToken is honoured only for the
    same queries and window while a changed MaxDatapoints is allowed."""
    cw = ctx.client("cloudwatch")
    # A custom namespace cannot be deleted (no DeleteMetric API); it ages out.
    namespace = ctx.unique_name("sim2real-cw-gmd-page-")
    minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {"MetricName": "Page", "Timestamp": minute - timedelta(minutes=i), "Value": float(i)} for i in range(1, 7)
        ],
    )

    def query(qid="a", stat="Sum"):
        metric = {"Namespace": namespace, "MetricName": "Page"}
        return {"Id": qid, "MetricStat": {"Metric": metric, "Period": 60, "Stat": stat}, "ReturnData": True}

    base = {
        "MetricDataQueries": [query()],
        "StartTime": minute - timedelta(minutes=10),
        "EndTime": minute + timedelta(minutes=1),
        "ScanBy": "TimestampDescending",
    }

    def pages(**overrides):
        kwargs = {**base, **overrides}
        out = []
        while True:
            resp = cw.get_metric_data(**kwargs)
            out.append(resp)
            if "NextToken" not in resp:
                return out
            assert len(out) < 20, f"expected pagination to finish within 20 pages, still has a NextToken after {out!r}"
            kwargs["NextToken"] = resp["NextToken"]

    baseline = _poll_until(
        ctx,
        lambda: cw.get_metric_data(**base)["MetricDataResults"][0]["Values"],
        lambda values: values == [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
        timeout_s=60.0, description="all six back-dated Page points readable unpaginated",
    )

    two = pages(MaxDatapoints=2)
    per_page = [p["MetricDataResults"][0]["Values"] for p in two]
    assert per_page == [[1.0], [2.0, 3.0], [4.0, 5.0], [6.0], [], []], (
        f"expected MaxDatapoints=2 to budget the 11 minute slots (empty ones included), got pages {per_page!r}"
    )
    statuses = [p["MetricDataResults"][0]["StatusCode"] for p in two]
    assert statuses == ["PartialData"] * 5 + ["Complete"], f"expected PartialData on every page but the last, got {statuses!r}"
    assert sum(per_page, []) == baseline, f"expected the pages to reassemble the baseline {baseline!r}, got {per_page!r}"

    walk = pages(MetricDataQueries=[query(), query("b", "SampleCount")], MaxDatapoints=3)
    seen = [{r["Id"]: r["StatusCode"] for r in p["MetricDataResults"]} for p in walk]
    early = [(i, qid) for i, ids in enumerate(seen[:-1]) for qid, status in ids.items() if status == "Complete"]
    assert early, f"expected one query to complete while the other still pages, got per-page statuses {seen!r}"
    for i, qid in early:
        later = [ids for ids in seen[i + 1:] if qid in ids]
        assert not later, f"expected {qid!r}, Complete on page {i + 1}, to be absent from later pages, got {seen!r}"
    values = {"a": [], "b": []}
    for page in walk:
        for result in page["MetricDataResults"]:
            values[result["Id"]] += result["Values"]
    completed = {qid for ids in seen for qid, status in ids.items() if status == "Complete"}
    assert completed == {"a", "b"}, f"expected both queries to reach Complete, got per-page statuses {seen!r}"
    assert values == {"a": baseline, "b": [1.0] * 6}, f"expected each query to reassemble its series, got {values!r}"

    token = two[0]["NextToken"]
    replay = cw.get_metric_data(**base, MaxDatapoints=2, NextToken=token)["MetricDataResults"][0]["Values"]
    assert replay == [2.0, 3.0], f"expected an identical replay to return page 2 [2,3], got {replay!r}"
    wider = cw.get_metric_data(**base, MaxDatapoints=3, NextToken=token)["MetricDataResults"][0]["Values"]
    assert wider == [2.0, 3.0, 4.0], f"expected a replay with MaxDatapoints=3 to return [2,3,4], got {wider!r}"

    for label, change in [
        ("changed StartTime", {"StartTime": base["StartTime"] - timedelta(minutes=1)}),
        ("changed Stat", {"MetricDataQueries": [query(stat="Maximum")]}),
        ("added query", {"MetricDataQueries": [query(), query("b")]}),
    ]:
        expect_error(
            lambda change=change: cw.get_metric_data(**{**base, **change}, MaxDatapoints=2, NextToken=token),
            *_INVALID_TOKEN, label=label,
        )


def expect_error(fn, code, message, label="call"):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message", ""))
        assert got == (code, message), f"{label}: expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"{label}: expected {(code, message)!r}, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
