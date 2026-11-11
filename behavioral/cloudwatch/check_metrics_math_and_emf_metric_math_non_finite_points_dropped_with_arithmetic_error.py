"""metrics-math-and-emf-metric-math-non-finite-points-dropped-with-arithmetic-error."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "metrics-math-and-emf-metric-math-non-finite-points-dropped-with-arithmetic-error"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

_A = [1.0, 3.0, 6.0, 10.0, 15.0]
_B = [5.0, 1.0, 4.0, 2.0, 3.0]  # B-1 is zero ONLY at index 1
_ARITH_DROPPED = (
    "One or more data-points have been dropped due to non-numeric values (NaN, -Infinite, +Infinite)"
)


@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """m1/(m2-1) omits only the divide-by-zero point (Values and Timestamps) with an ArithmeticError
    message and StatusCode Complete; m1/0 drops every point; the control m1/m2 keeps all five.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-mme-nan/")
    t0 = (datetime.now(timezone.utc) - timedelta(minutes=8)).replace(second=0, microsecond=0)
    stamps = [t0 + timedelta(minutes=i) for i in range(5)]
    cw.put_metric_data(Namespace=namespace, MetricData=(
        [{"MetricName": "A", "Timestamp": t, "Value": v} for t, v in zip(stamps, _A)]
        + [{"MetricName": "B", "Timestamp": t, "Value": v} for t, v in zip(stamps, _B)]
    ))
    queries = [
        {"Id": "m1", "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": "A"}, "Period": 60, "Stat": "Sum"}},
        {"Id": "m2", "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": "B"}, "Period": 60, "Stat": "Sum"}},
        {"Id": "ctl", "Expression": "m1/m2"},
        {"Id": "gap", "Expression": "m1/(m2-1)"},
        {"Id": "none", "Expression": "m1/0"},
    ]
    want_ctl = [a / b for a, b in zip(_A, _B)]
    res = _poll(lambda: _read(cw, queries, t0, t0 + timedelta(minutes=5)),
                lambda r: r["ctl"]["values"] == want_ctl)

    ctl = res["ctl"]
    assert ctl["values"] == want_ctl and ctl["timestamps"] == stamps, f"control m1/m2 was {ctl!r}"
    assert ctl["messages"] == [] and ctl["status"] == "Complete", f"control carried {ctl!r}"

    gap = res["gap"]
    keep = [i for i in range(5) if _B[i] - 1 != 0]
    assert keep == [0, 2, 3, 4], f"test data invariant broken: {keep!r}"
    assert gap["values"] == [_A[i] / (_B[i] - 1) for i in keep], (
        f"m1/(m2-1) values {gap['values']!r}; expected the four finite quotients"
    )
    assert gap["timestamps"] == [stamps[i] for i in keep], (
        f"m1/(m2-1) timestamps {gap['timestamps']!r}; the divide-by-zero point must be omitted"
    )
    assert gap["status"] == "Complete", f"m1/(m2-1) StatusCode was {gap['status']!r}"
    assert gap["messages"] == [{"Code": "ArithmeticError", "Value": _ARITH_DROPPED}], (
        f"m1/(m2-1) messages were {gap['messages']!r}; expected exactly one ArithmeticError"
    )

    none = res["none"]
    assert none["values"] == [] and none["timestamps"] == [], f"m1/0 returned {none!r}"
    assert none["messages"] == [{"Code": "ArithmeticError", "Value": _ARITH_DROPPED}], (
        f"m1/0 messages were {none['messages']!r}; expected exactly one ArithmeticError"
    )


def _read(cw, queries, start, end):
    out = {}
    token = None
    while True:
        kw = dict(MetricDataQueries=queries, StartTime=start, EndTime=end,
                  ScanBy="TimestampAscending")
        if token:
            kw["NextToken"] = token
        resp = cw.get_metric_data(**kw)
        for r in resp["MetricDataResults"]:
            slot = out.setdefault(r["Id"], {"values": [], "timestamps": [], "messages": []})
            slot["values"].extend(r["Values"])
            slot["timestamps"].extend(t.astimezone(timezone.utc) for t in r["Timestamps"])
            slot["messages"].extend(r.get("Messages") or [])
            slot["status"] = r["StatusCode"]
        token = resp.get("NextToken")
        if not token:
            return out


def _poll(fn, ready, timeout_s=300, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if ready(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"published series never became fully readable; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
